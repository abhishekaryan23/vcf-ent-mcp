# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Loopback-only credential page used by MCP URL-mode elicitation.

Passwords and API keys must never pass through the MCP client or the model
(MCP 2026-07-28 elicitation: servers MUST use URL mode for sensitive data).
The guided setup issues a one-time ticket and sends the user a URL to this page;
the user types the secret into their own browser and it goes straight into the
configured secret store. The model only ever learns that the credential was saved.

Controls:
- binds to 127.0.0.1 on an ephemeral port, so only the local user can reach it
  (remote deployments use the `credentials add` CLI on the server host instead);
- tickets are 256-bit random, single-use, expire after 10 minutes and are bound
  to the principal, component and storage reference chosen by the server;
- Host header must be the loopback address (DNS-rebinding defence), the form
  carries a per-ticket CSRF token, bodies are capped at 8 KiB;
- the page shows a verification code that also appears in the assistant's
  message, so the user can check the link belongs to their own setup;
- request bodies are never logged; responses are no-store with a strict CSP.

The same page server also serves PERSONAL-MODE APPROVAL pages (/approve/<ticket>): the plan, Approve / Reject buttons and, for
destructive or security-sensitive changes, a field where the person types the target name or plan code. A ticket is a 256-bit
random URL token, expires with the plan, takes exactly one decision and has a per-ticket CSRF token. The page only records the
person's decision in the spool; the MCP server records the signed approval when it next sees the ticket.

MCP clients that restart the stdio server between turns (LM Studio does) would kill an
in-process page before the user opens it. In stdio mode the server therefore uses
DetachedPortal: tickets (never secrets) are written to an owner-only spool directory and a
small background process (setup/portal_service.py) serves the pages and exits once nothing
is pending. A restarted server reads ticket status from the same spool.
"""

from __future__ import annotations

import html
import json
import os
import secrets
import subprocess
import sys
import threading
import time
import urllib.parse
from dataclasses import asdict, dataclass, field
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Dict, Optional

from vcf_enterprise_mcp.secrets.models import SecretValue

TICKET_TTL_SECONDS = 600
MAX_BODY_BYTES = 8192

# store(reference, secret, tenant_id, environment_id, description) -> None
SecretSink = Callable[[str, SecretValue, str, str, str], None]


@dataclass
class CredentialTicket:
    ticket_id: str
    principal_id: str
    component: str
    component_title: str
    endpoint_host: str
    username: str
    reference: str
    tenant_id: str
    environment_id: str
    verification_code: str
    csrf_token: str
    expires_at: float
    status: str = "PENDING"  # PENDING | STORED | EXPIRED | FAILED
    error: Optional[str] = None
    stored_at: Optional[float] = field(default=None)

    def effective_status(self) -> str:
        if self.status == "PENDING" and time.time() > self.expires_at:
            self.status = "EXPIRED"
        return self.status


@dataclass
class ApprovalTicket:
    """One personal-mode approval page: what the person is shown and what they decided. Holds no secrets."""
    ticket_id: str
    plan_id: str
    tenant_id: str
    environment_id: str
    initiator_id: str
    approver_id: str
    tool_id: str
    risk_class: str
    target: str
    plan_hash: str
    short_code: str
    lines: list
    requires_text: bool
    expected_text: str
    text_prompt: str
    csrf_token: str
    expires_at: float
    status: str = "PENDING"  # PENDING | APPROVED | REJECTED | RECORDED | EXPIRED
    attempts: int = 0
    decided_at: Optional[float] = None
    approval_id: Optional[str] = None

    def effective_status(self) -> str:
        if self.status == "PENDING" and time.time() > self.expires_at:
            self.status = "EXPIRED"
        return self.status


MAX_CONFIRM_ATTEMPTS = 5

_PAGE_CSS = (
    "body{font-family:-apple-system,Segoe UI,sans-serif;max-width:520px;margin:48px auto;padding:0 16px;"
    "color:#1d1d1f;background:#f7f7f8}main{background:#fff;border:1px solid #e3e3e6;border-radius:12px;padding:28px}"
    "h1{font-size:20px;margin:0 0 8px}p{line-height:1.5}code{background:#f0f0f2;padding:2px 6px;border-radius:4px}"
    ".code{font-size:22px;letter-spacing:3px;font-weight:600}label{display:block;margin:16px 0 6px;font-weight:600}"
    "input{width:100%;padding:10px;border:1px solid #c8c8cc;border-radius:8px;font-size:15px;box-sizing:border-box}"
    "input[readonly]{background:#f3f3f5}button{margin-top:20px;width:100%;padding:12px;border:0;border-radius:8px;"
    "background:#0b57d0;color:#fff;font-size:15px;font-weight:600;cursor:pointer}.note{font-size:13px;color:#5f5f66}"
    ".row{display:flex;gap:12px}.row button{flex:1}button.no{background:#6b6b73}ul{padding-left:20px}li{margin:4px 0;word-break:break-word}"
    ".err{color:#b3261e;font-weight:600}"
    "@media (prefers-color-scheme:dark){body{background:#1b1b1d;color:#ececf0}main{background:#242427;border-color:#3a3a3f}"
    "code{background:#333338}input{background:#2c2c30;color:#ececf0;border-color:#4a4a50}input[readonly]{background:#333338}}"
)


def _page(title: str, body: str) -> bytes:
    return (
        "<!doctype html><html lang=en><head><meta charset=utf-8>"
        "<meta name=viewport content='width=device-width,initial-scale=1'>"
        f"<title>{html.escape(title)}</title><style>{_PAGE_CSS}</style></head>"
        f"<body><main>{body}</main></body></html>"
    ).encode("utf-8")


class CredentialPortal:
    def __init__(self, sink: SecretSink, host: str = "127.0.0.1", spool_dir: Optional[Path] = None):
        if host not in ("127.0.0.1", "::1", "localhost"):
            raise ValueError("The credential portal only binds to loopback.")
        self._sink = sink
        self._spool = Path(spool_dir) if spool_dir else None
        self._host = "127.0.0.1" if host == "localhost" else host
        self._tickets: Dict[str, CredentialTicket] = {}
        self._lock = threading.Lock()
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    # ---- lifecycle ---------------------------------------------------------------

    @property
    def port(self) -> int:
        self._ensure_started()
        return self._server.server_address[1]

    def _ensure_started(self) -> None:
        if self._server is not None:
            return
        portal = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "vcf-mcp-setup"
            sys_version = ""

            def log_message(self, format, *args):  # noqa: A002 - never log requests (bodies hold secrets)
                return

            def do_GET(self):
                portal._handle_get(self)

            def do_POST(self):
                portal._handle_post(self)

        self._server = ThreadingHTTPServer((self._host, 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, name="vcf-mcp-credential-portal", daemon=True)
        self._thread.start()

    def shutdown(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    # ---- tickets -----------------------------------------------------------------

    def issue(self, *, principal_id: str, component: str, component_title: str, endpoint_host: str,
              username: str, reference: str, tenant_id: str, environment_id: str) -> CredentialTicket:
        self._ensure_started()
        ticket = CredentialTicket(
            ticket_id=secrets.token_urlsafe(32),
            principal_id=principal_id,
            component=component,
            component_title=component_title,
            endpoint_host=endpoint_host,
            username=username,
            reference=reference,
            tenant_id=tenant_id,
            environment_id=environment_id,
            verification_code=f"{secrets.randbelow(10**6):06d}",
            csrf_token=secrets.token_urlsafe(24),
            expires_at=time.time() + TICKET_TTL_SECONDS,
        )
        with self._lock:
            self._tickets[ticket.ticket_id] = ticket
        return ticket

    def url_for(self, ticket: CredentialTicket) -> str:
        return f"http://{self._host}:{self.port}/credential/{ticket.ticket_id}"

    @property
    def spool_dir(self) -> Optional[Path]:
        return self._spool

    def issue_approval(self, ticket: ApprovalTicket) -> ApprovalTicket:
        if self._spool is None:
            raise ValueError("Approval pages need a spool directory.")
        self._ensure_started()
        write_approval_ticket(self._spool, ticket)
        return ticket

    def url_for_approval(self, ticket: ApprovalTicket) -> str:
        return f"http://{self._host}:{self.port}/approve/{ticket.ticket_id}"

    def get(self, ticket_id: str, principal_id: str) -> Optional[CredentialTicket]:
        with self._lock:
            ticket = self._tickets.get(ticket_id)
        if ticket is None or ticket.principal_id != principal_id:
            return None
        ticket.effective_status()
        return ticket

    # ---- HTTP handlers -------------------------------------------------------------

    def _send(self, handler: BaseHTTPRequestHandler, status: int, body: bytes) -> None:
        handler.send_response(status)
        handler.send_header("Content-Type", "text/html; charset=utf-8")
        handler.send_header("Content-Length", str(len(body)))
        handler.send_header("Cache-Control", "no-store")
        handler.send_header("Pragma", "no-cache")
        # same-origin (not no-referrer): under no-referrer browsers send "Origin: null" on the form POST,
        # which the strict Origin check below would reject. Nothing leaks cross-origin either way.
        handler.send_header("Referrer-Policy", "same-origin")
        handler.send_header("X-Content-Type-Options", "nosniff")
        handler.send_header("X-Frame-Options", "DENY")
        handler.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
        )
        handler.end_headers()
        handler.wfile.write(body)

    def _host_ok(self, handler: BaseHTTPRequestHandler) -> bool:
        expected = {f"{self._host}:{self.port}"}
        if self._host == "127.0.0.1":
            expected.add(f"localhost:{self.port}")
        return handler.headers.get("Host", "") in expected

    def _ticket_from_path(self, path: str) -> Optional[CredentialTicket]:
        parts = urllib.parse.urlsplit(path).path.strip("/").split("/")
        if len(parts) != 2 or parts[0] != "credential":
            return None
        with self._lock:
            ticket = self._tickets.get(parts[1]) or self._load(parts[1])
        if ticket is None:
            return None
        ticket.effective_status()
        return ticket

    # ---- spool (detached mode) ---------------------------------------------------------

    def _load(self, ticket_id: str) -> Optional[CredentialTicket]:
        if self._spool is None or not ticket_id.replace("-", "").replace("_", "").isalnum():
            return None
        ticket = read_ticket(self._spool, ticket_id)
        if ticket is not None:
            self._tickets[ticket_id] = ticket
        return ticket

    def _persist(self, ticket: CredentialTicket) -> None:
        if self._spool is not None:
            write_ticket(self._spool, ticket)

    # ---- approval pages (personal access mode) -------------------------------------------

    def _approval_from_path(self, path: str) -> Optional[ApprovalTicket]:
        parts = urllib.parse.urlsplit(path).path.strip("/").split("/")
        if len(parts) != 2 or parts[0] != "approve" or self._spool is None:
            return None
        ticket = read_approval_ticket(self._spool, parts[1])
        if ticket is not None:
            ticket.effective_status()
        return ticket

    def _approval_form(self, ticket: ApprovalTicket, error: str = "") -> bytes:
        e = html.escape
        items = "".join(f"<li>{e(str(line))}</li>" for line in ticket.lines)
        confirm = ""
        if ticket.requires_text:
            confirm = (f"<label for=c>{e(ticket.text_prompt)}</label>"
                       "<input id=c name=confirm autocomplete=off autocapitalize=off spellcheck=false>")
        body = (
            "<h1>Approve this change?</h1>"
            f"<p>Your assistant asked VCF Enterprise MCP to run <code>{e(ticket.tool_id)}</code> on <code>{e(ticket.target)}</code>. "
            f"Risk: <code>{e(ticket.risk_class)}</code>. You are approving as <code>{e(ticket.approver_id)}</code>.</p>"
            f"<ul>{items}</ul>"
            f"<p class=note>Plan code <span class=code>{e(ticket.short_code)}</span> (the terminal shows the same code if you approve there instead).</p>"
            + (f"<p class=err>{e(error)}</p>" if error else "")
            + f"<form method=post action='/approve/{e(ticket.ticket_id)}' autocomplete=off>"
            f"<input type=hidden name=csrf value='{e(ticket.csrf_token)}'>{confirm}"
            "<div class=row><button type=submit name=decision value=approve>Approve</button>"
            "<button class=no type=submit name=decision value=reject>Reject</button></div></form>"
            "<p class=note>This link works once and expires with the plan. Nothing runs until you approve here "
            "and your assistant then asks for the plan to be executed.</p>"
        )
        return _page("Approve a change", body)

    def _approval_get(self, handler: BaseHTTPRequestHandler) -> None:
        ticket = self._approval_from_path(handler.path)
        if ticket is None:
            return self._send(handler, 404, _page("Link not valid", "<h1>This approval link is not valid</h1><p>Ask your assistant for the plan again.</p>"))
        if ticket.status != "PENDING":
            msg = {"EXPIRED": "This approval link has expired.", "REJECTED": "You rejected this change."}.get(ticket.status, "This change was already decided.")
            return self._send(handler, 410, _page("Link used", f"<h1>{msg}</h1><p>Return to your assistant.</p>"))
        self._send(handler, 200, self._approval_form(ticket))

    def _approval_post(self, handler: BaseHTTPRequestHandler) -> None:
        ticket = self._approval_from_path(handler.path)
        if ticket is None or ticket.status != "PENDING":
            return self._send(handler, 410, _page("Link used", "<h1>This approval link is no longer valid</h1><p>Return to your assistant.</p>"))
        length = int(handler.headers.get("Content-Length") or 0)
        if length <= 0 or length > MAX_BODY_BYTES:
            return self._send(handler, 413, _page("Rejected", "<h1>Request rejected</h1>"))
        form = urllib.parse.parse_qs(handler.rfile.read(length).decode("utf-8", errors="replace"), max_num_fields=6)
        if not secrets.compare_digest((form.get("csrf") or [""])[0], ticket.csrf_token):
            return self._send(handler, 403, _page("Rejected", "<h1>Request rejected</h1>"))
        decision = (form.get("decision") or [""])[0]
        if decision not in ("approve", "reject"):
            return self._send(handler, 400, _page("Missing", "<h1>Choose Approve or Reject</h1>"))
        with self._lock:  # one decision per ticket, even under concurrent submits
            ticket = read_approval_ticket(self._spool, ticket.ticket_id) or ticket
            if ticket.effective_status() != "PENDING":
                return self._send(handler, 410, _page("Link used", "<h1>This approval link is no longer valid</h1>"))
            if decision == "reject":
                ticket.status, ticket.decided_at = "REJECTED", time.time()
                write_approval_ticket(self._spool, ticket)
                return self._send(handler, 200, _page("Rejected", "<h1>Rejected</h1><p>Nothing was changed. Return to your assistant.</p>"))
            if ticket.requires_text:
                typed = (form.get("confirm") or [""])[0].strip()
                if not secrets.compare_digest(typed.casefold().encode(), ticket.expected_text.strip().casefold().encode()):
                    ticket.attempts += 1
                    if ticket.attempts >= MAX_CONFIRM_ATTEMPTS:
                        ticket.status, ticket.decided_at = "REJECTED", time.time()
                        write_approval_ticket(self._spool, ticket)
                        return self._send(handler, 403, _page("Locked", "<h1>Too many wrong confirmations</h1><p>This change was rejected. Ask for a new plan.</p>"))
                    write_approval_ticket(self._spool, ticket)
                    return self._send(handler, 400, self._approval_form(ticket, "That did not match. Nothing was approved."))
            ticket.status, ticket.decided_at = "APPROVED", time.time()
            write_approval_ticket(self._spool, ticket)
        self._send(handler, 200, _page("Approved", "<h1>Approved</h1><p>Return to your assistant and tell it to carry on. "
                                                    "It only needs to call the tool again with the plan id.</p>"))

    def _handle_get(self, handler: BaseHTTPRequestHandler) -> None:
        if not self._host_ok(handler):
            return self._send(handler, 421, _page("Wrong host", "<h1>Wrong host</h1>"))
        if urllib.parse.urlsplit(handler.path).path.startswith("/approve/"):
            return self._approval_get(handler)
        ticket = self._ticket_from_path(handler.path)
        if ticket is None:
            return self._send(handler, 404, _page("Link not valid", "<h1>This setup link is not valid</h1><p>Ask your assistant to restart credential setup.</p>"))
        if ticket.status != "PENDING":
            msg = "This credential was already saved." if ticket.status == "STORED" else "This link has expired."
            return self._send(handler, 410, _page("Link used", f"<h1>{msg}</h1><p>Return to your assistant.</p>"))
        e = html.escape
        body = (
            f"<h1>Connect {e(ticket.component_title)}</h1>"
            f"<p>VCF Enterprise MCP needs the password for <code>{e(ticket.username)}</code> on <code>{e(ticket.endpoint_host)}</code>.</p>"
            f"<p>Check this code matches the one your assistant showed you:</p><p class=code>{e(ticket.verification_code)}</p>"
            f"<form method=post action='/credential/{e(ticket.ticket_id)}' autocomplete=off>"
            f"<input type=hidden name=csrf value='{e(ticket.csrf_token)}'>"
            f"<label for=u>Username</label><input id=u value='{e(ticket.username)}' readonly>"
            "<label for=p>Password or API key</label><input id=p name=secret type=password required autofocus>"
            "<button type=submit>Save securely</button></form>"
            f"<p class=note>The secret goes straight to the configured secret store (<code>{e(ticket.reference.split('://', 1)[0])}://</code>). "
            "It is never shown to the assistant, the MCP client or the model. This link works once and expires in 10 minutes.</p>"
        )
        self._send(handler, 200, _page(f"Connect {ticket.component_title}", body))

    def _handle_post(self, handler: BaseHTTPRequestHandler) -> None:
        if not self._host_ok(handler):
            return self._send(handler, 421, _page("Wrong host", "<h1>Wrong host</h1>"))
        origin = handler.headers.get("Origin")
        if origin and origin not in (f"http://{self._host}:{self.port}", f"http://localhost:{self.port}"):
            return self._send(handler, 403, _page("Rejected", "<h1>Cross-origin request rejected</h1>"))
        if urllib.parse.urlsplit(handler.path).path.startswith("/approve/"):
            return self._approval_post(handler)
        ticket = self._ticket_from_path(handler.path)
        if ticket is None or ticket.status != "PENDING":
            return self._send(handler, 410, _page("Link used", "<h1>This link is no longer valid</h1><p>Return to your assistant.</p>"))
        length = int(handler.headers.get("Content-Length") or 0)
        if length <= 0 or length > MAX_BODY_BYTES:
            return self._send(handler, 413, _page("Rejected", "<h1>Request rejected</h1>"))
        form = urllib.parse.parse_qs(handler.rfile.read(length).decode("utf-8", errors="replace"), max_num_fields=4)
        if not secrets.compare_digest((form.get("csrf") or [""])[0], ticket.csrf_token):
            return self._send(handler, 403, _page("Rejected", "<h1>Request rejected</h1>"))
        secret_text = (form.get("secret") or [""])[0]
        if not secret_text:
            return self._send(handler, 400, _page("Missing", "<h1>No password entered</h1>"))

        with self._lock:
            if ticket.status != "PENDING":  # single use, even under concurrent submits
                return self._send(handler, 410, _page("Link used", "<h1>This link is no longer valid</h1>"))
            ticket.status = "STORING"
        try:
            self._sink(ticket.reference, SecretValue(secret_text), ticket.tenant_id, ticket.environment_id,
                       f"VCF MCP {ticket.component} credential for {ticket.username}")
        except Exception as exc:  # report type only; never echo input
            ticket.status, ticket.error = "FAILED", type(exc).__name__
            self._persist(ticket)
            return self._send(handler, 500, _page("Not saved", "<h1>The credential could not be saved</h1><p>Return to your assistant for next steps.</p>"))
        finally:
            secret_text = ""  # noqa: F841 - drop the reference promptly
            form.clear()
        ticket.status, ticket.stored_at = "STORED", time.time()
        self._persist(ticket)
        self._send(handler, 200, _page("Saved", f"<h1>{html.escape(ticket.component_title)} credential saved</h1><p>You can close this tab and return to your assistant.</p>"))


# ---- detached portal (stdio servers) ---------------------------------------------------------------

def _private_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path, 0o700)
    return path


def write_ticket(spool: Path, ticket: CredentialTicket) -> None:
    d = _private_dir(spool / "tickets")
    tmp = d / f".{ticket.ticket_id}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(asdict(ticket), fh)
    os.replace(tmp, d / f"{ticket.ticket_id}.json")


def read_ticket(spool: Path, ticket_id: str) -> Optional[CredentialTicket]:
    try:
        data = json.loads((spool / "tickets" / f"{ticket_id}.json").read_text(encoding="utf-8"))
        return CredentialTicket(**data)
    except (OSError, ValueError, TypeError):
        return None


def _approvals_dir(spool: Path) -> Path:
    return _private_dir(Path(spool) / "approvals")


def write_approval_ticket(spool: Path, ticket: ApprovalTicket) -> None:
    d = _approvals_dir(spool)
    tmp = d / f".{ticket.ticket_id}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(asdict(ticket), fh)
    os.replace(tmp, d / f"{ticket.ticket_id}.json")


def read_approval_ticket(spool: Path, ticket_id: str) -> Optional[ApprovalTicket]:
    if not ticket_id or not ticket_id.replace("-", "").replace("_", "").isalnum():
        return None
    try:
        data = json.loads((Path(spool) / "approvals" / f"{ticket_id}.json").read_text(encoding="utf-8"))
        return ApprovalTicket(**data)
    except (OSError, ValueError, TypeError):
        return None


def list_approval_tickets(spool: Path) -> list:
    out = []
    try:
        for f in sorted((Path(spool) / "approvals").glob("*.json")):
            t = read_approval_ticket(spool, f.stem)
            if t is not None:
                out.append(t)
    except OSError:
        pass
    return out


class DetachedPortal:
    """Same interface as CredentialPortal, but the page is served by a background process that
    outlives this server (see setup/portal_service.py)."""

    def __init__(self, spool_dir: Path):
        self._spool = _private_dir(Path(spool_dir))

    def _service_port(self) -> Optional[int]:
        try:
            pid = int((self._spool / "service.pid").read_text())
            os.kill(pid, 0)
            return int((self._spool / "service.port").read_text())
        except (OSError, ValueError):
            return None

    @property
    def port(self) -> int:
        port = self._service_port()
        if port:
            return port
        for name in ("service.port", "service.pid"):
            (self._spool / name).unlink(missing_ok=True)
        subprocess.Popen([sys.executable, "-m", "vcf_enterprise_mcp.setup.portal_service", str(self._spool)],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True, env=dict(os.environ))
        deadline = time.time() + 15
        while time.time() < deadline:
            port = self._service_port()
            if port:
                return port
            time.sleep(0.1)
        raise RuntimeError("The local credential page could not start; use the 'vcf-mcp credentials add' command instead.")

    def issue(self, *, principal_id: str, component: str, component_title: str, endpoint_host: str,
              username: str, reference: str, tenant_id: str, environment_id: str) -> CredentialTicket:
        ticket = CredentialTicket(
            ticket_id=secrets.token_urlsafe(32), principal_id=principal_id, component=component, component_title=component_title,
            endpoint_host=endpoint_host, username=username, reference=reference, tenant_id=tenant_id, environment_id=environment_id,
            verification_code=f"{secrets.randbelow(10**6):06d}", csrf_token=secrets.token_urlsafe(24),
            expires_at=time.time() + TICKET_TTL_SECONDS,
        )
        write_ticket(self._spool, ticket)
        _ = self.port  # make sure the page is being served
        return ticket

    def url_for(self, ticket: CredentialTicket) -> str:
        return f"http://127.0.0.1:{self.port}/credential/{ticket.ticket_id}"

    def get(self, ticket_id: str, principal_id: str) -> Optional[CredentialTicket]:
        ticket = read_ticket(self._spool, ticket_id)
        if ticket is None or ticket.principal_id != principal_id:
            return None
        ticket.effective_status()
        return ticket

    @property
    def spool_dir(self) -> Path:
        return self._spool

    def issue_approval(self, ticket: ApprovalTicket) -> ApprovalTicket:
        write_approval_ticket(self._spool, ticket)
        _ = self.port  # make sure the page is being served
        return ticket

    def url_for_approval(self, ticket: ApprovalTicket) -> str:
        return f"http://127.0.0.1:{self.port}/approve/{ticket.ticket_id}"

    def shutdown(self) -> None:
        return
