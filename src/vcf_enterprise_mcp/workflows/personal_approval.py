# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Approvals in personal access mode (see auth/personal.py): the person who asked is the person who approves.

One explicit human confirmation per plan, through one of three channels the model cannot answer itself:
  in_client  MCP elicitation form in the chat window (clients that declare the elicitation capability);
  page       a one-time local page on 127.0.0.1 (setup/credential_portal.py);
  cli        `vcf-mcp plans approve <plan_id>` typed in the person's own interactive terminal.
For DESTRUCTIVE and SECURITY_SENSITIVE changes the person also types the target name (or the plan code when there is no
single target). Every approval is recorded with approver, channel, mode and plan hash in the audit chain.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import shlex
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from vcf_enterprise_mcp.auth.identity import Principal
from vcf_enterprise_mcp.core.errors import AuthorizationDeniedException
from vcf_enterprise_mcp.setup.access_guide import TOOL_IMPACT

# True while a tools/call from a client that declared the elicitation capability is being handled.
CLIENT_ELICITS: ContextVar[bool] = ContextVar("vcf_mcp_client_elicits", default=False)

SENSITIVE_RISKS = ("DESTRUCTIVE", "SECURITY_SENSITIVE")
CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"  # no 0/O/1/I/L
APPROVAL_KEY = "approve_plan"
_HIDE = {"canonical_plan_hash", "risk_class", "target_resource_ids", "approvals_required", "approval_required", "requires_approval",
         "how_to_approve", "next_step", "plan_id", "status", "dry_run", "allowed", "instructions", "impact_plan",
         "permission_epoch", "resource_revisions", "approval_id", "nonce"}


def _clip(value: Any, limit: int = 160) -> str:
    text = " ".join(str(value).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _line(key: str, value: Any) -> Optional[str]:
    if value is None or value == "" or value == [] or value == {}:
        return None
    if isinstance(value, dict):
        value = ", ".join(f"{k}={_clip(v, 60)}" for k, v in list(value.items())[:6])
    elif isinstance(value, (list, tuple)):
        value = ", ".join(_clip(v, 60) for v in value[:8]) + (" …" if len(value) > 8 else "")
    return f"{key}: {_clip(value)}"


@dataclass
class PlanInfo:
    plan_id: str
    tool: str
    risk: str
    targets: List[str]
    target: str
    requires_text: bool
    expected_text: str
    text_prompt: str
    short_code: str
    plan_hash: str
    expires_at: float
    initiator: str
    tenant_id: str
    environment_id: str
    lines: List[str] = field(default_factory=list)


class PersonalApproval:
    def __init__(self, durable: Any, user_id: str, home: Path, plan_manager: Any = None, portal: Any = None,
                 db_path: Optional[str] = None):
        self.durable = durable
        self.user_id = user_id
        self.home = Path(home)
        self.mgr = plan_manager
        self._portal = portal
        self.db_path = db_path if db_path is not None else getattr(durable, "db_path", None)

    # ---- identity and codes -----------------------------------------------------------------

    def approver_principal(self, plan: Dict[str, Any]) -> Principal:
        return Principal(user_id=self.user_id, tenant_id=plan["tenant_id"], environment_ids=(plan["environment_id"],),
                         corporate_groups=["personal-local-approver"], roles=("VCF_PLATFORM_ADMIN",),
                         allowed_domains=["*"], allowed_clusters=["*"], token_id="personal-approver")

    def _code_key(self) -> bytes:
        """Per-install secret so the plan code cannot be worked out from a tool result alone."""
        path = self.home / "plan_code.key"
        try:
            self.home.mkdir(parents=True, exist_ok=True, mode=0o700)
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                key = path.read_bytes()
                return key if len(key) == 32 else b""
            key = os.urandom(32)
            with os.fdopen(fd, "wb") as fh:
                fh.write(key)
            return key
        except OSError:
            return b""

    def short_code(self, plan_id: str, plan_hash: str = "") -> str:
        digest = hmac.new(self._code_key() or b"vcf-mcp-plan-code", f"{plan_id}:{plan_hash}".encode(), hashlib.sha256).digest()
        return "".join(CODE_ALPHABET[b % len(CODE_ALPHABET)] for b in digest[:6])

    # ---- what the person is shown -------------------------------------------------------------

    def info(self, plan: Dict[str, Any]) -> PlanInfo:
        impact = plan.get("impact_summary", {}) or {}
        risk = str(impact.get("risk_class", "HIGH_IMPACT"))
        tool = plan["tool_id"]
        targets = [str(t) for t in (impact.get("target_resource_ids") or list((plan.get("resource_revisions") or {}).keys()))]
        single = targets[0] if len(targets) == 1 and targets[0] != tool else ""
        impact_level = TOOL_IMPACT[tool].level if tool in TOOL_IMPACT else ""
        requires_text = risk in SENSITIVE_RISKS or impact_level == "DESTRUCTIVE"
        plan_hash = impact.get("canonical_plan_hash", "")
        code = self.short_code(plan["plan_id"], plan_hash)
        if single:
            expected, prompt = single, f"Type the target name ({single}) to confirm"
        else:
            expected, prompt = code, f"Type the plan code ({code}) to confirm"
        lines = [ln for k, v in impact.items() if k not in _HIDE for ln in [_line(k, v)] if ln][:12]
        lines += [ln for k, v in list((plan.get("normalized_args") or {}).items())[:10] for ln in [_line("argument " + k, v)] if ln]
        return PlanInfo(plan_id=plan["plan_id"], tool=tool, risk=risk, targets=targets,
                        target=single or (", ".join(targets) if targets else tool), requires_text=requires_text,
                        expected_text=expected, text_prompt=prompt, short_code=code, plan_hash=plan_hash,
                        expires_at=plan["expires_at"], initiator=plan["principal_id"], tenant_id=plan["tenant_id"],
                        environment_id=plan["environment_id"], lines=lines)

    @staticmethod
    def confirmation_ok(info: PlanInfo, typed: Optional[str]) -> bool:
        if not info.requires_text:
            return True
        return secrets.compare_digest((typed or "").strip().casefold().encode(), info.expected_text.strip().casefold().encode())

    def render(self, info: PlanInfo) -> str:
        head = (f"Approve {info.tool} on {info.target}? Risk: {info.risk}. Requested by the assistant for {self.user_id}.")
        return head + "\n" + "\n".join(f"  - {ln}" for ln in info.lines) + f"\nPlan code: {info.short_code}"

    # ---- elicitation (MRTR form) ---------------------------------------------------------------

    def elicitation_request(self, info: PlanInfo, error: str = "") -> Dict[str, Any]:
        props: Dict[str, Any] = {
            "decision": {"type": "string", "title": "Approve this change?", "default": "reject",
                         "oneOf": [{"const": "approve", "title": "Approve"}, {"const": "reject", "title": "Reject"}]},
        }
        required = ["decision"]
        if info.requires_text:
            props["confirm"] = {"type": "string", "title": info.text_prompt,
                                "description": "Only needed to approve. Anything else cancels the approval."}
        message = (error + "\n" if error else "") + self.render(info)
        return {"method": "elicitation/create",
                "params": {"mode": "form", "message": message, "requestedSchema": {"type": "object", "properties": props, "required": required}}}

    # ---- page tickets ----------------------------------------------------------------------------

    @property
    def portal(self) -> Any:
        if self._portal is None:
            from vcf_enterprise_mcp.setup.credential_portal import DetachedPortal
            self._portal = DetachedPortal(self.home / "portal")
        return self._portal

    def ticket_for(self, plan: Dict[str, Any]) -> Any:
        """The approval page ticket for this plan: the existing pending one, else a new one that expires with the plan."""
        import time
        from vcf_enterprise_mcp.setup.credential_portal import ApprovalTicket, list_approval_tickets
        info = self.info(plan)
        for t in list_approval_tickets(self.portal.spool_dir):
            if t.plan_id == info.plan_id and t.effective_status() == "PENDING" and t.plan_hash == info.plan_hash and t.approver_id == self.user_id:
                self.portal.issue_approval(t)  # make sure the page is being served
                return t
        ticket = ApprovalTicket(
            ticket_id=secrets.token_urlsafe(32), plan_id=info.plan_id, tenant_id=info.tenant_id, environment_id=info.environment_id,
            initiator_id=info.initiator, approver_id=self.user_id, tool_id=info.tool, risk_class=info.risk, target=info.target,
            plan_hash=info.plan_hash, short_code=info.short_code, lines=info.lines, requires_text=info.requires_text,
            expected_text=info.expected_text, text_prompt=info.text_prompt, csrf_token=secrets.token_urlsafe(24),
            expires_at=min(info.expires_at, time.time() + 86400))
        return self.portal.issue_approval(ticket)

    def approval_url(self, plan: Dict[str, Any]) -> str:
        return self.portal.url_for_approval(self.ticket_for(plan))

    def sync_page_decision(self, plan: Dict[str, Any]) -> Optional[str]:
        """Records the signed approval for a plan the person approved on the page. Returns APPROVED / REJECTED / None."""
        import time
        from vcf_enterprise_mcp.setup.credential_portal import list_approval_tickets, write_approval_ticket
        spool = self.portal.spool_dir
        info = self.info(plan)
        outcome = None
        for t in list_approval_tickets(spool):
            if t.plan_id != info.plan_id or t.tenant_id != info.tenant_id or t.plan_hash != info.plan_hash:
                continue
            if t.status == "REJECTED":
                outcome = outcome or "REJECTED"
            elif t.status == "APPROVED" and t.decided_at and t.decided_at <= t.expires_at:
                try:
                    signed = self.mgr.approve_plan(info.plan_id, self.approver_principal(plan), channel="page")
                    t.approval_id = signed.approval_id
                except AuthorizationDeniedException:
                    pass  # this person already approved the plan (duplicate): nothing more to record
                t.status = "RECORDED"
                write_approval_ticket(spool, t)
                outcome = "APPROVED"
            elif t.status == "RECORDED":
                outcome = outcome or "APPROVED"
        return outcome

    def rejected_on_page(self, plan: Dict[str, Any]) -> bool:
        from vcf_enterprise_mcp.setup.credential_portal import list_approval_tickets
        info = self.info(plan)
        return any(t.plan_id == info.plan_id and t.plan_hash == info.plan_hash and t.status == "REJECTED"
                   for t in list_approval_tickets(self.portal.spool_dir))

    # ---- hand-off text for the model -----------------------------------------------------------------

    def command(self, plan_id: str) -> str:
        return f"vcf-mcp plans approve {plan_id}" + (f" --db {shlex.quote(self.db_path)}" if self.db_path and self.db_path != ":memory:" else "")

    def how_to_approve(self, plan_id: str, tenant_id: str, env_id: str) -> Dict[str, Any]:
        plan = self.durable.get_execution_plan(tenant_id, env_id, plan_id)
        info = self.info(plan) if plan else None
        out: Dict[str, Any] = {
            "mode": "personal",
            "approvals_required": 1,
            "approver": self.user_id,
            "command": self.command(plan_id),
            "needs_typed_confirmation": bool(info and info.requires_text),
        }
        if info and info.requires_text:
            out["confirm_by_typing"] = "the target name" if info.expected_text == info.target else "the plan code shown on the person's screen"
        if CLIENT_ELICITS.get():
            out["steps"] = [
                "The person who asked approves this change themselves. Call this tool again with the SAME arguments plus plan_id (nothing else).",
                "A confirmation prompt then appears in the chat window for the person; you cannot answer it. Approve runs the change in that same call.",
                f"If they would rather approve in their own terminal: {out['command']}, then call again with plan_id only.",
            ]
            return out
        url = None
        try:
            if plan:
                url = self.approval_url(plan)
        except Exception as exc:  # the page could not start: the terminal command still works
            out["approval_url_error"] = f"The local approval page could not start ({type(exc).__name__}); use the command instead."
        if url:
            out["approval_url"] = url
        out["steps"] = [
            "The person who asked approves this change themselves; you cannot approve it for them.",
            (f"Ask them to open {url} in their browser (local page, one use)" if url else "Ask them")
            + f" or to run this in their OWN terminal: {out['command']} (they type the plan code shown there"
            + (" and the target name" if out["needs_typed_confirmation"] else "") + ").",
            "When they tell you they approved, call this tool again with the SAME arguments plus plan_id only: no approval_id or nonce is needed.",
        ]
        return out

    # ---- status for vcf_get_plan ------------------------------------------------------------------------

    def refusal_after_reject(self, plan_id: str) -> AuthorizationDeniedException:
        return AuthorizationDeniedException(f"The person rejected plan '{plan_id}' on the approval page, so it will not run. Make a new dry run if the change is still wanted.")
