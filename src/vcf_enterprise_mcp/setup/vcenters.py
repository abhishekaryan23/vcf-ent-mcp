# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Attach more vCenters (for example one per workload domain) to the running server: vcf_add_vcenter in the chat, or
`vcf-mcp vcenter add` in a terminal.

A vCenter is attached either with its own service account (needed when its workload domain has an isolated SSO domain)
or with the main vCenter account. Its own password goes to the secret store through the private local page (or a
hidden terminal prompt), never through the chat. Reusing the main account sends that account's password to the new
vCenter, so the person confirms it in a client dialog (or the terminal); the assistant cannot confirm it for them.
Every vCenter is logged in to and checked before it is saved under vcf.vcenters.
"""

from __future__ import annotations

import json
import re
import time
import urllib.parse
from typing import Any, Callable, Dict, Optional, Tuple

from vcf_enterprise_mcp.adapter.connectivity import apply_endpoint_override, suffix_for_host
from vcf_enterprise_mcp.adapter.transport.vcf_sessions import VCenterSessionAuth
from vcf_enterprise_mcp.core.errors import InvalidArgumentException
from vcf_enterprise_mcp.setup.access_probe import AccessProbe

ADD_BINDING = "tools/call:vcf_add_vcenter"
TENANT = "tenant-default"  # the same secret-store scope as guided setup
ENVIRONMENT = "env-prod"


def vcenter_reference(host: str) -> str:
    """Secret-store reference for an attached vCenter's own account."""
    return f"local://{ENVIRONMENT}/vcf-mcp-vcenter-{re.sub(r'[^a-z0-9]+', '-', host.lower()).strip('-')}"


def parse_vcenter_url(url: str) -> Tuple[str, str]:
    """(host, https://host[:port]) from what the person typed; a bare host name means HTTPS."""
    text = (url or "").strip()
    if text and "://" not in text:
        text = "https://" + text
    parts = urllib.parse.urlsplit(text)
    if parts.scheme != "https" or not parts.hostname or parts.path not in ("", "/") or parts.query or parts.username:
        raise InvalidArgumentException(f"Give the vCenter as https://<host name>, for example https://vc-wld01.corp.example (got '{url}').")
    return parts.hostname.lower(), f"https://{parts.netloc.lower()}"


class VCenterAttacher:
    """Checks a vCenter with its account and saves it under vcf.vcenters. Uses the setup wizard's portal, secret store,
    transport and config writer, so it follows the same network, TLS and allowlist settings as guided setup."""

    def __init__(self, wizard: Any):
        self.w = wizard

    # ---- what is configured ---------------------------------------------------------

    def _main(self) -> Tuple[Optional[str], Optional[str], Optional[str], str]:
        """(host, url, username, credential reference) of the main vCenter account."""
        vcf = self.w._vcf()
        url = getattr(vcf, "vcenter_url", None)
        host = urllib.parse.urlsplit(url).hostname if url else None
        username = (getattr(vcf, "component_usernames", None) or {}).get("vcenter")
        ref = (getattr(vcf, "component_credential_refs", None) or {}).get("vcenter") or f"local://{ENVIRONMENT}/vcf-mcp-vcenter"
        return host, url, username, ref

    def attached(self) -> Dict[str, Any]:
        return dict(getattr(self.w._vcf(), "vcenters", None) or {})

    def _known(self, host: str) -> Optional[str]:
        main_host = self._main()[0]
        if main_host and main_host.lower() == host:
            return "the main vCenter"
        if any(h.lower() == host for h in self.attached()):
            return "already attached"
        return None

    # ---- check and save -------------------------------------------------------------

    def check(self, host: str, url: str, username: str, ref: str) -> Dict[str, Any]:
        """Logs in to the vCenter with the account whose password is under ref, and reads what it may do."""
        overrides = dict(getattr(self.w._vcf(), "endpoint_overrides", None) or {})
        target = apply_endpoint_override(url, overrides)
        transport = self.w.transport_factory([host, urllib.parse.urlsplit(target).hostname])

        def supplier():
            secret = self.w.secrets.resolve(ref, tenant_id=TENANT, environment_id=ENVIRONMENT)
            return username, secret.reveal_for_transport()
        probe = AccessProbe(transport, vcf_config=self.w._vcf())
        return probe.probe("vcenter", target, username, VCenterSessionAuth(target, transport, supplier)).to_dict()

    def save(self, host: str, url: str, username: Optional[str], ref: Optional[str], access: Dict[str, Any]) -> None:
        import yaml
        path = self.w.config_path
        data: Dict[str, Any] = (yaml.safe_load(path.read_text(encoding="utf-8")) or {}) if path.exists() else {}
        vcf = data.setdefault("vcf", {})
        entry: Dict[str, Any] = {"url": url}
        if username:
            entry.update(username=username, credential_ref=ref)
        vcf.setdefault("vcenters", {})[host] = entry
        # The person named this vCenter, so allow its DNS suffix (and the mapped address's) like guided setup does.
        target = apply_endpoint_override(url, vcf.get("endpoint_overrides") or {})
        hosts = [host, urllib.parse.urlsplit(target).hostname]
        suffixes = set(vcf.get("allowed_dns_suffixes") or []) | {s for s in (suffix_for_host(h) for h in hosts if h) if s}
        if suffixes:
            vcf["allowed_dns_suffixes"] = sorted(suffixes)
        self.w._atomic_write(path, yaml.safe_dump(data, sort_keys=False))
        report_path = self.w.home / "access_report.json"
        if report_path.exists():  # vcf_access_report shows what each attached vCenter's account may do
            report = json.loads(report_path.read_text(encoding="utf-8"))
            report.setdefault("attached_vcenters", {})[host] = access
            self.w._atomic_write(report_path, json.dumps(report, indent=2))
        self.w._reload_config()

    def remove(self, host: str) -> bool:
        import yaml
        host = host.strip().lower()
        path = self.w.config_path
        data: Dict[str, Any] = (yaml.safe_load(path.read_text(encoding="utf-8")) or {}) if path.exists() else {}
        vcenters = (data.get("vcf") or {}).get("vcenters") or {}
        name = next((h for h in vcenters if h.lower() == host), None)
        if name is None:
            return False
        entry = vcenters.pop(name)
        self.w._atomic_write(path, yaml.safe_dump(data, sort_keys=False))
        if isinstance(entry, dict) and entry.get("credential_ref"):
            try:
                self.w.secrets.delete(entry["credential_ref"], tenant_id=TENANT, environment_id=ENVIRONMENT)
            except Exception:
                pass
        self.w._reload_config()
        return True

    def attach(self, host: str, url: str, username: Optional[str]) -> Dict[str, Any]:
        """Checks and saves a vCenter whose password (own account) or confirmation (main account) is in place.
        Returns the result payload. A rejected login discards the password it used, if it was this vCenter's own."""
        main_host, _, main_user, main_ref = self._main()
        own = bool(username)
        user, ref = (username, vcenter_reference(host)) if own else (main_user, main_ref)
        if not user:
            return {"status": "NOT_POSSIBLE", "vcenter": host,
                    "message": "There is no main vCenter account to reuse. Attach the vCenter with its own service account (give a username)."}
        access = self.check(host, url, user, ref)
        self.w.audit("setup.vcenter_checked", {"vcenter": host, "identity": access.get("identity"), "roles": access.get("roles"),
                                                "authenticated": access.get("authenticated"), "own_account": own})
        if not access.get("authenticated"):
            discarded = own and bool(access.get("login_rejected"))
            if discarded:
                try:
                    self.w.secrets.delete(ref, tenant_id=TENANT, environment_id=ENVIRONMENT)
                except Exception:
                    pass
            problem = access.get("problem") or {}
            return {"status": "ACCESS_CHECK_FAILED", "vcenter": host, "account": user, "error": access.get("error"),
                    "problem": {k: problem.get(k) for k in ("cause", "summary", "config_key", "fix") if problem.get(k)},
                    "password_discarded": discarded,
                    "message": f"I could not log in to {host} as '{user}': {access.get('error')} Nothing was saved."
                               + (" Enter the password again when you retry." if discarded else "")}
        self.save(host, url, username if own else None, ref if own else None, access)
        self.w.audit("setup.vcenter_attached", {"vcenter": host, "account": user, "own_account": own})
        warnings = list(access.get("findings") or [])
        if access.get("over_permissive") or access.get("local_admin"):
            warnings.insert(0, f"'{user}' has more access on {host} than this MCP needs; use a scoped service account.")
        return {"status": "COMPLETE", "vcenter": host, "url": url, "account": user,
                "account_kind": "its own service account" if own else f"the main vCenter account (from {main_host})",
                "identity": access.get("identity"), "roles": access.get("roles"), "warnings": warnings,
                "message": f"{host} is attached. Inventory tools now include it, and VM changes for its VMs go to it."}

    # ---- the vcf_add_vcenter tool ---------------------------------------------------

    def run(self, principal: Any, arguments: Dict[str, Any], meta: Dict[str, Any]) -> Dict[str, Any]:
        from vcf_enterprise_mcp.setup.wizard import _contains_secret_keys
        w = self.w
        arguments = dict(arguments or {})
        responses = meta.get("inputResponses") or {}
        submitted = [r.get("content") for r in responses.values() if isinstance(r, dict)]
        secret_keys = _contains_secret_keys(arguments) + _contains_secret_keys(submitted)
        if secret_keys:
            raise InvalidArgumentException(
                "Never send passwords, API keys or tokens through chat or tool arguments "
                f"(rejected field(s): {', '.join(sorted(set(secret_keys)))}). The password goes on a private local page.")
        caps = (meta.get("clientCapabilities") or {}).get("elicitation")
        w.form_ok = caps is not None and (caps == {} or "form" in caps)
        w.url_ok = caps is not None and "url" in caps
        w.principal_id = principal.user_id or principal.principal_id
        w._reload_config()
        token = meta.get("requestState") or arguments.pop("resume", None)
        state = w.codec.decode(token, w.principal_id, ADD_BINDING) if token else {}

        def encode() -> str:
            return w.codec.encode(w.principal_id, ADD_BINDING, state)

        def result(payload: Dict[str, Any]) -> Dict[str, Any]:
            return {"structured": payload}

        if "host" not in state:
            if not arguments.get("url"):
                raise InvalidArgumentException("Give the vCenter's address in 'url', for example https://vc-wld01.corp.example.")
            state["host"], state["url"] = parse_vcenter_url(arguments["url"])
            state["username"] = (arguments.get("username") or "").strip() or None
        host, url, username = state["host"], state["url"], state.get("username")
        known = self._known(host)
        if known:
            return result({"status": "ALREADY_ATTACHED", "vcenter": host,
                           "message": f"{host} is {known}; nothing to add. Remove it with 'vcf-mcp vcenter remove {host}' to attach it again."})
        if not (self._main()[1] or self.attached() or getattr(w._vcf(), "sddc_manager_url", None)):
            return result({"status": "SETUP_FIRST", "message": "Run guided setup (vcf_setup) first; then attach more vCenters."})

        if username:  # its own account: the password goes on the private page
            ref = vcenter_reference(host)
            action, _ = w._accepted(responses, "login_vcenter")
            if action in ("decline", "cancel"):
                return result({"status": "CANCELLED", "message": "Nothing was changed."})
            if not self._password_ready(ref, state):
                return self._ask_password(state, host, username, ref, encode, result)
        else:  # the main account: only the person may agree to send its password to this vCenter
            action, content = w._accepted(responses, "confirm_main_account")
            if action in ("decline", "cancel") or (action == "accept" and not content.get("use_main_account")):
                return result({"status": "CANCELLED", "message": "Nothing was changed. To use a different account, call vcf_add_vcenter with its username."})
            if action != "accept":
                main_host, _, main_user, _ = self._main()
                question = (f"Attach {host} with the main vCenter account '{main_user}'? Its password will be sent to {host} to log in. "
                            "Choose this only if this vCenter shares the main SSO domain; otherwise cancel and give its own account.")
                if not w.form_ok:
                    return result({"status": "NEEDS_CONFIRMATION", "vcenter": host,
                                   "message": "Reusing the main vCenter account needs the user's own confirmation, which this client "
                                              "cannot show. Ask the user to run this in their terminal:",
                                   "command": f"vcf-mcp vcenter add {url}"})
                return {"resultType": "input_required", "requestState": encode(), "inputRequests": {"confirm_main_account": {
                    "method": "elicitation/create", "params": {"mode": "form", "message": question, "requestedSchema": {
                        "type": "object", "required": ["use_main_account"], "properties": {"use_main_account": {
                            "type": "boolean", "title": f"Use '{main_user}' on {host}", "default": False}}}}}}}
        return result(self.attach(host, url, username))

    def _password_ready(self, ref: str, state: Dict[str, Any]) -> bool:
        """True once the private page has stored the password (waits briefly while the page is open)."""
        w = self.w
        deadline = time.time() + (w.wait_seconds if state.get("ticket") else 0)
        while True:
            try:
                if w.secrets.resolve(ref, tenant_id=TENANT, environment_id=ENVIRONMENT).reveal_for_transport():
                    return True
            except Exception:
                pass
            ticket = w.portal.get(state["ticket"], w.principal_id) if state.get("ticket") else None
            if ticket is None or ticket.effective_status() in ("EXPIRED", "FAILED") or time.time() >= deadline:
                return False
            time.sleep(0.5)

    def _ask_password(self, state: Dict[str, Any], host: str, username: str, ref: str,
                      encode: Callable[[], str], result: Callable[[Dict[str, Any]], Dict[str, Any]]) -> Dict[str, Any]:
        w = self.w
        ticket = w.portal.get(state["ticket"], w.principal_id) if state.get("ticket") else None
        if ticket is None or ticket.effective_status() in ("EXPIRED", "FAILED"):
            ticket = w.portal.issue(principal_id=w.principal_id, component="vcenter", component_title=f"vCenter {host}",
                                    endpoint_host=host, username=username, reference=ref, tenant_id=TENANT, environment_id=ENVIRONMENT)
            state["ticket"] = ticket.ticket_id
        page = w.portal.url_for(ticket)
        # Clients may show only the first line of a message, so the code and the ask come first.
        message = (f"Code {ticket.verification_code}: vCenter {host} password for '{username}'. Open the private page on this "
                   "computer, check it shows the same code, and enter the password there. It goes straight to the secret store "
                   "and is never shown to the assistant.")
        if w.url_ok:
            return {"resultType": "input_required", "requestState": encode(), "inputRequests": {
                "login_vcenter": {"method": "elicitation/create", "params": {"mode": "url", "url": page, "message": message}}}}
        return result({"status": "NEEDS_CREDENTIALS", "vcenter": host,
                       "message": "The password must be entered outside the chat. Give the user this private local link, wait until "
                                  "they say they are done, then call vcf_add_vcenter again with 'resume'.",
                       "credential_page": {"url": page, "verification_code": ticket.verification_code},
                       "cli_alternative": f"vcf-mcp vcenter add {state['url']} --username {username}",
                       "resume": encode()})
