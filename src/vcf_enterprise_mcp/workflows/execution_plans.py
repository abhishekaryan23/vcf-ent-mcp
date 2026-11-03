# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Execution Plan & TOCTOU-Guarded Approval Service for Enterprise VCF MCP Control Plane.
Implements the full lifecycle:
DRY RUN -> Execution Plan -> Plan ID -> N-Person Approvals -> KMS-Signed Execution Authorization -> EXECUTE.
Binds principal, tenant, environment, canonical plan hash, resource revisions, fine-grained permission epoch,
single-use nonces, rotatable signing keys, and detects TOCTOU state changes prior to execution.
"""

from __future__ import annotations
import hashlib
import json
import os
import shlex
import time
import secrets
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from vcf_enterprise_mcp.auth.identity import Principal
from vcf_enterprise_mcp.state.durable_store import DurableStore
from vcf_enterprise_mcp.adapter.platform import PlatformClient
from vcf_enterprise_mcp.policy.models import RiskClass, ApprovalPolicy, CapabilityRole
from vcf_enterprise_mcp.auth.kms import KMSKeyManager, get_kms_manager
from vcf_enterprise_mcp.core.errors import (
    PlanStaleException,
    AuthorizationDeniedException,
    VCFEnterpriseException,
    ApprovalRequiredException,
)


def compute_normalized_sha256(data: Dict[str, Any]) -> str:
    """Computes deterministic SHA256 of sorted canonical JSON arguments."""
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def compute_canonical_plan_hash(
    tenant_id: str,
    environment_id: str,
    principal_id: str,
    tool_id: str,
    target_resource_ids: List[str],
    normalized_arguments: Dict[str, Any],
    resource_revisions: Dict[str, Any],
    permission_epoch: int,
    risk_class: str,
    expires_at: float,
) -> str:
    """
    Computes standard canonical hash binding:
    SHA256( canonical_json( tenant, environment, principal, tool, resources, normalized_arguments,
                           resource_revisions, permission_epoch, risk, expiry ) )
    """
    canonical_dict = {
        "tenant": tenant_id,
        "environment": environment_id,
        "principal": principal_id,
        "tool": tool_id,
        "resources": sorted(target_resource_ids),
        "arguments": normalized_arguments,
        "resource_revisions": {k: str(resource_revisions[k]) for k in sorted(resource_revisions.keys())},
        "permission_epoch": permission_epoch,
        "risk": risk_class,
        "expires_at": round(expires_at, 2),
    }
    canonical_str = json.dumps(canonical_dict, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()


@dataclass
class SignedExecutionAuthorization:
    approval_id: str
    plan_id: str
    approver: str
    nonce: str
    issued_at: float
    expires_at: float
    permission_epoch: int
    tenant_id: str = "tenant-default"
    environment_id: str = "env-prod"
    canonical_plan_hash: str = ""
    signature: str = ""
    key_id: str = ""
    algorithm: str = "RS256"
    signature_version: str = "v1"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "plan_id": self.plan_id,
            "approver": self.approver,
            "tenant_id": self.tenant_id,
            "environment_id": self.environment_id,
            "nonce": self.nonce,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "permission_epoch": self.permission_epoch,
            "canonical_plan_hash": self.canonical_plan_hash,
            "signature": self.signature,
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "signature_version": self.signature_version,
        }


# Roles allowed to approve plans (the enterprise/plans/approve RPC and `vcf-mcp plans approve` apply the same gate);
# on top of this, ApprovalPolicy.required_approver_roles may require specific groups for riskier changes.
PLAN_APPROVER_ROLES = (
    CapabilityRole.VCF_PLATFORM_ADMIN,
    CapabilityRole.SECURITY_ADMIN,
    CapabilityRole.COMPUTE_ADMIN,
    CapabilityRole.NETWORK_ADMIN,
    CapabilityRole.LIFECYCLE_ADMIN,
)


def personal_approval_policy() -> ApprovalPolicy:
    """Personal mode: ONE explicit human confirmation per plan for every change; the person who asked is the person
    who approves, so separation of duties and the approver-role/group rules do not apply (see auth/personal.py)."""
    return ApprovalPolicy(
        required_approvals=1,
        allow_initiator=True,
        disallow_self_approval=False,
        approvals_required={
            RiskClass.READ: 0, RiskClass.SAFE_WRITE: 1, RiskClass.CHANGE: 1, RiskClass.HIGH_IMPACT: 1,
            RiskClass.DESTRUCTIVE: 1, RiskClass.SECURITY_SENSITIVE: 1,
        },
        required_approver_roles={},
    )


def how_to_approve(plan_id: str, risk_class: RiskClass, initiator_id: str, db_path: Optional[str] = None,
                   policy: Optional[ApprovalPolicy] = None) -> Dict[str, Any]:
    """What a human must do to approve this plan, in words a model can relay verbatim."""
    policy = policy or ApprovalPolicy()
    needed = policy.get_required_approvals(risk_class)
    groups = list(policy.required_approver_roles.get(risk_class, []))
    command = f"vcf-mcp plans approve {plan_id}" + (f" --db {shlex.quote(db_path)}" if db_path and db_path != ":memory:" else "")
    steps = [
        f"A human administrator (not {initiator_id}) runs, in a terminal on the MCP host: {command}",
        "The command reads the approver's OWN access token from --approver-token, --approver-token-file or the VCF_MCP_APPROVER_TOKEN "
        "environment variable (your identity provider's token; in a lab: vcf-mcp token mint --role VCF_PLATFORM_ADMIN --user <you> --raw).",
    ]
    if needed > 1:
        steps.append(f"This change needs {needed} DIFFERENT approvers: each runs the same command with their own token.")
    steps.append("When the required approvals are in, the command prints approval_id and nonce. The user pastes those two values into "
                 "this chat; then call the tool again with the same arguments plus plan_id, approval_id and nonce.")
    return {
        "command": command,
        "approvals_required": needed,
        "approver_roles_any_of": [r.value for r in PLAN_APPROVER_ROLES],
        "approver_groups_any_of": groups,
        "approver_must_differ_from": initiator_id,
        "steps": steps,
    }


class ExecutionPlanManager:
    """Manages creation, review, rotatable signing, N-person approvals, and TOCTOU validation of execution plans."""

    def __init__(
        self,
        durable_store: DurableStore,
        platform_client: Optional[PlatformClient] = None,
        tenant_id: str = "tenant-default",
        environment_id: str = "env-prod",
        kms_manager: Optional[KMSKeyManager] = None,
        approval_policy: Optional[ApprovalPolicy] = None,
    ):
        self.durable = durable_store
        self.platform = platform_client or PlatformClient()
        self.tenant_id = tenant_id
        self.environment_id = environment_id
        self.kms = kms_manager or get_kms_manager()
        self.approval_policy = approval_policy or ApprovalPolicy()
        self.personal = None  # PersonalApproval, set by enable_personal() in personal access mode

    def enable_personal(self, personal: Any) -> None:
        """Switches this manager to personal access mode (one confirmation by the local person, no second approver)."""
        self.personal = personal
        self.approval_policy = personal_approval_policy()

    def how_to_approve_for(self, plan_id: str, risk_class: RiskClass, principal: Principal) -> Dict[str, Any]:
        """The hand-off instructions for a plan: personal (chat prompt / local page / own terminal) or team (approver token)."""
        if self.personal is not None:
            tenant_id, env_id = self._get_effective_coords(principal)
            return self.personal.how_to_approve(plan_id, tenant_id, env_id)
        return how_to_approve(plan_id, risk_class, principal.user_id, getattr(self.durable, "db_path", None), self.approval_policy)

    def _get_effective_coords(self, principal: Optional[Principal]) -> Tuple[str, str]:
        if not principal:
            return (self.tenant_id, self.environment_id)
        tenant_id = principal.tenant_id if principal.tenant_id != "tenant-default" else self.tenant_id
        if principal.environment_ids and principal.environment_ids not in [("env-prod",), ("env-default",)]:
            env_id = principal.environment_ids[0]
        else:
            env_id = self.environment_id
        return (tenant_id, env_id)

    def create_dry_run_plan(
        self,
        principal: Principal,
        tool_id: str,
        arguments: Dict[str, Any],
        impact_summary: Dict[str, Any],
        target_resource_ids: List[str],
        risk_class: RiskClass = RiskClass.HIGH_IMPACT,
        ttl_seconds: float = 900.0,
    ) -> Dict[str, Any]:
        """
        Generates an immutable Execution Plan during dry-run.
        Captures current resource revisions to prevent TOCTOU bugs upon execution.
        """
        tenant_id, env_id = self._get_effective_coords(principal)

        ignored_keys = ["dry_run", "approval_token", "plan_id", "approval_id", "nonce", "approved"]
        clean_args = {k: v for k, v in arguments.items() if k not in ignored_keys}
        args_hash = compute_normalized_sha256(clean_args)

        resource_revisions = {
            rid: str(self.platform.get_resource_revision(rid))
            for rid in target_resource_ids
        }
        current_epoch = self.durable.get_permission_epoch(tenant_id, env_id)
        now = time.time()
        expires_at = now + ttl_seconds
        plan_id = f"plan_{secrets.token_urlsafe(16)}"

        canonical_hash = compute_canonical_plan_hash(
            tenant_id=tenant_id,
            environment_id=env_id,
            principal_id=principal.user_id,
            tool_id=tool_id,
            target_resource_ids=target_resource_ids,
            normalized_arguments=clean_args,
            resource_revisions=resource_revisions,
            permission_epoch=current_epoch,
            risk_class=risk_class.value,
            expires_at=expires_at,
        )

        impact_summary["canonical_plan_hash"] = canonical_hash
        impact_summary["risk_class"] = risk_class.value
        impact_summary["target_resource_ids"] = target_resource_ids
        approvals_needed = self.approval_policy.get_required_approvals(risk_class)
        impact_summary["approvals_required"] = approvals_needed

        self.durable.save_execution_plan(
            plan_id=plan_id,
            tenant_id=tenant_id,
            environment_id=env_id,
            principal_id=principal.user_id,
            tool_id=tool_id,
            args_sha256=args_hash,
            normalized_args=clean_args,
            resource_revisions=resource_revisions,
            impact_summary=impact_summary,
            permission_epoch=current_epoch,
            status="PENDING_APPROVAL",
            ttl_seconds=ttl_seconds,
            expires_at=expires_at,
        )

        res = {
            "dry_run": True,
            "allowed": True,
            "approval_required": approvals_needed > 0,
            "requires_approval": approvals_needed > 0,
            "plan_id": plan_id,
            "status": "PENDING_APPROVAL",
            "impact_summary": impact_summary,
            "impact_plan": impact_summary,
            "target_resource_ids": target_resource_ids,
            "resource_revisions": resource_revisions,
            "permission_epoch": current_epoch,
            "canonical_plan_hash": canonical_hash,
            "approvals_required": approvals_needed,
            "instructions": f"Submit plan_id '{plan_id}' to authorized approver(s) to obtain a SignedExecutionAuthorization.",
        }
        if approvals_needed > 0:
            res["how_to_approve"] = self.how_to_approve_for(plan_id, risk_class, principal)
            if self.personal is not None:
                res["instructions"] = (f"The person confirms plan '{plan_id}' themselves (see how_to_approve); then call the tool again "
                                       "with the same arguments plus plan_id.")

        lab_auto_approve = (
            os.environ.get("VCF_LAB_AUTO_APPROVE", "").lower() in ("true", "1", "yes")
            and os.environ.get("VCF_MCP_ENV", "development").lower() != "production"
        )
        if lab_auto_approve:
            signature, key_id, algorithm, signature_version = self.kms.sign_digest(canonical_hash)
            approval_id = f"appr_{secrets.token_urlsafe(16)}"
            nonce = secrets.token_hex(16)
            self.durable.save_approval(
                approval_id=approval_id,
                plan_id=plan_id,
                tenant_id=tenant_id,
                environment_id=env_id,
                approver_id="lab-auto-approver@local",
                nonce=nonce,
                approver_roles=["VCF-Platform-Admins", "VCF-Security-Approvers"],
                permission_epoch=current_epoch,
                signature=signature,
                key_id=key_id,
                algorithm=algorithm,
                ttl_seconds=ttl_seconds,
            )
            res["status"] = "APPROVED"
            res["approval_id"] = approval_id
            res["nonce"] = nonce
            res["instructions"] = (
                f"Lab auto-approval enabled: Execute with plan_id='{plan_id}', approval_id='{approval_id}', nonce='{nonce}'."
            )

        return res

    def list_plans(
        self,
        caller: Principal,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Lists execution plans within the caller's tenant and environment."""
        tenant_id, env_id = self._get_effective_coords(caller)
        if not hasattr(self.durable, "list_execution_plans"):
            return []
        plans = self.durable.list_execution_plans(tenant_id, env_id, status=status)
        now = time.time()
        results: List[Dict[str, Any]] = []
        for p in plans:
            is_expired = now > p.get("expires_at", 0)
            eff_status = "EXPIRED" if is_expired and p.get("status") == "PENDING_APPROVAL" else p.get("status", "PENDING_APPROVAL")
            if status and eff_status != status:
                continue
            valid_approvals = self.durable.list_valid_approvals(tenant_id, env_id, p["plan_id"])
            req_approvals = p.get("impact_summary", {}).get("approvals_required", 1)
            results.append({
                "plan_id": p["plan_id"],
                "tool_id": p["tool_id"],
                "principal_id": p["principal_id"],
                "tenant_id": p["tenant_id"],
                "environment_id": p["environment_id"],
                "status": "APPROVED" if len(valid_approvals) >= req_approvals else eff_status,
                "risk_class": p.get("impact_summary", {}).get("risk_class", "CHANGE"),
                "target_resource_ids": p.get("impact_summary", {}).get("target_resource_ids", []),
                "normalized_args": p.get("normalized_args", {}),
                "approvals_recorded": len(valid_approvals),
                "approvals_required": req_approvals,
                "created_at": p.get("created_at"),
                "expires_at": p.get("expires_at"),
            })
        return results

    def get_plan(
        self,
        plan_id: str,
        caller: Principal,
    ) -> Dict[str, Any]:
        """
        Retrieves full details of an execution plan.
        If the caller is the plan initiator and the plan has met its approval threshold,
        returns the unconsumed approval_id and single-use nonce for live execution handback.
        """
        tenant_id, env_id = self._get_effective_coords(caller)
        plan = self.durable.get_execution_plan(tenant_id, env_id, plan_id)
        if not plan:
            raise VCFEnterpriseException(
                f"Execution plan '{plan_id}' not found in tenant '{tenant_id}'.",
                error_code=-32012,
            )
        valid_approvals = self.durable.list_valid_approvals(tenant_id, env_id, plan_id)
        req_approvals = plan.get("impact_summary", {}).get("approvals_required", 1)
        is_ready = len(valid_approvals) >= req_approvals and time.time() <= plan.get("expires_at", 0)
        eff_status = "APPROVED" if is_ready else ("EXPIRED" if time.time() > plan.get("expires_at", 0) else plan.get("status", "PENDING_APPROVAL"))

        response: Dict[str, Any] = {
            "plan_id": plan["plan_id"],
            "tool_id": plan["tool_id"],
            "principal_id": plan["principal_id"],
            "tenant_id": plan["tenant_id"],
            "environment_id": plan["environment_id"],
            "status": eff_status,
            "ready_to_execute": is_ready,
            "normalized_args": plan.get("normalized_args", {}),
            "resource_revisions": plan.get("resource_revisions", {}),
            "impact_summary": plan.get("impact_summary", {}),
            "permission_epoch": plan.get("permission_epoch"),
            "approvals_recorded": len(valid_approvals),
            "approvals_required": req_approvals,
            "approvers": [a["approver_id"] for a in valid_approvals],
            "created_at": plan.get("created_at"),
            "expires_at": plan.get("expires_at"),
        }
        # Initiator handback: only the plan initiator receives the single-use nonce
        if is_ready and valid_approvals and caller.user_id == plan["principal_id"]:
            latest = valid_approvals[-1]
            response["approval_id"] = latest["approval_id"]
            response["nonce"] = latest["nonce"]
        return response

    def approve_plan(
        self,
        plan_id: str,
        approver: Principal,
        ttl_seconds: Optional[float] = None,
        channel: str = "token",
    ) -> SignedExecutionAuthorization:
        """
        Approves an execution plan using configurable N-person approval policy
        and mints a KMS-signed, non-replayable authorization token.
        Enforces tenant isolation, separation of duties, and distinct approver uniqueness.
        """
        tenant_id, env_id = self._get_effective_coords(approver)

        plan = self.durable.get_execution_plan(tenant_id, env_id, plan_id)
        if not plan:
            raise VCFEnterpriseException(
                f"Execution plan '{plan_id}' not found in tenant '{tenant_id}'.",
                error_code=-32012,
            )

        now = time.time()
        if now > plan["expires_at"]:
            raise VCFEnterpriseException(f"Execution plan '{plan_id}' has expired.", error_code=-32013)
        if ttl_seconds is None:
            # Team: 10 minutes. Personal: the approval lives as long as the plan, so a person who approves on a page or in a
            # terminal has the plan's whole lifetime to tell the assistant to carry on.
            ttl_seconds = max(60.0, plan["expires_at"] - now) if self.personal is not None else 600.0

        risk_val = plan.get("impact_summary", {}).get("risk_class", RiskClass.HIGH_IMPACT.value)
        try:
            risk = RiskClass(risk_val)
        except ValueError:
            risk = RiskClass.HIGH_IMPACT

        # Check if permission epoch has drifted
        current_epoch = self.durable.get_permission_epoch(tenant_id, env_id)
        if current_epoch != plan["permission_epoch"]:
            raise VCFEnterpriseException(
                f"Plan invalid: Permission epoch changed from {plan['permission_epoch']} to {current_epoch} (revocation occurred).",
                error_code=-32014,
            )

        # Validate approver against ApprovalPolicy
        is_ok, reason = self.approval_policy.validate_approver(
            initiator_id=plan["principal_id"],
            approver_id=approver.user_id,
            approver_groups=approver.corporate_groups,
            risk_class=risk,
        )
        if not is_ok:
            raise AuthorizationDeniedException(reason)

        # Check distinct approvers constraint: Cannot approve the same plan twice
        existing_approvals = self.durable.list_valid_approvals(tenant_id, env_id, plan_id)
        if any(a["approver_id"] == approver.user_id for a in existing_approvals):
            raise AuthorizationDeniedException(
                f"Duplicate approval: Approver '{approver.user_id}' has already approved plan '{plan_id}'."
            )

        # Cryptographically sign canonical plan hash using KMS
        canonical_hash = plan.get("impact_summary", {}).get("canonical_plan_hash", "")
        if not canonical_hash:
            canonical_hash = compute_canonical_plan_hash(
                tenant_id=tenant_id,
                environment_id=env_id,
                principal_id=plan["principal_id"],
                tool_id=plan["tool_id"],
                target_resource_ids=plan.get("impact_summary", {}).get("target_resource_ids", []),
                normalized_arguments=plan["normalized_args"],
                resource_revisions=plan["resource_revisions"],
                permission_epoch=current_epoch,
                risk_class=risk.value,
                expires_at=plan["expires_at"],
            )

        signature, key_id, algorithm, signature_version = self.kms.sign_digest(canonical_hash)

        approval_id = f"appr_{secrets.token_urlsafe(16)}"
        nonce = secrets.token_hex(16)
        self.durable.save_approval(
            approval_id=approval_id,
            plan_id=plan_id,
            tenant_id=tenant_id,
            environment_id=env_id,
            approver_id=approver.user_id,
            nonce=nonce,
            approver_roles=approver.corporate_groups,
            permission_epoch=current_epoch,
            signature=signature,
            key_id=key_id,
            algorithm=algorithm,
            ttl_seconds=ttl_seconds,
        )
        self.audit_approval(plan, approver.user_id, channel, "APPROVED", canonical_hash, approval_id)

        return SignedExecutionAuthorization(
            approval_id=approval_id,
            plan_id=plan_id,
            approver=approver.user_id,
            tenant_id=tenant_id,
            environment_id=env_id,
            nonce=nonce,
            issued_at=now,
            expires_at=now + ttl_seconds,
            permission_epoch=current_epoch,
            canonical_plan_hash=canonical_hash,
            signature=signature,
            key_id=key_id,
            algorithm=algorithm,
            signature_version=signature_version,
        )

    def audit_approval(self, plan: Dict[str, Any], approver_id: str, channel: str, outcome: str,
                       plan_hash: str = "", approval_id: str = "") -> None:
        """Hash-chained audit record of a human decision: approver, channel (in_client | page | cli | token), mode, plan hash."""
        try:
            from vcf_enterprise_mcp.audit.recorder import AuditRecord
            import uuid
            mode = "personal" if self.personal is not None else "team"
            impact = plan.get("impact_summary", {}) or {}
            plan_hash = plan_hash or impact.get("canonical_plan_hash", "")
            rec = AuditRecord(
                request_id=f"req-{uuid.uuid4().hex[:12]}", timestamp=time.time(),
                actor={"principal_id": approver_id, "user_id": approver_id, "tenant_id": plan["tenant_id"]},
                agent={"client": "plan-approval", "channel": channel},
                tool="plan_approval", resource={"plan_id": plan["plan_id"], "tool": plan["tool_id"]},
                action_type=str(impact.get("risk_class", "")),
                arguments={"plan_id": plan["plan_id"], "approver": approver_id, "channel": channel, "mode": mode,
                           "plan_hash": plan_hash, "outcome": outcome, "approval_id": approval_id,
                           "initiator": plan["principal_id"]},
                before_state=None, authorization={"allow": outcome == "APPROVED", "reason": f"plan {outcome.lower()} via {channel} ({mode} mode)"},
                dry_run=False, tenant_id=plan["tenant_id"], environment_id=plan["environment_id"],
                result_status="SUCCESS", response_summary=f"Plan {plan['plan_id']} {outcome.lower()} by {approver_id} via {channel} ({mode} mode)")
            self.durable.record_audit_event_chained(tenant_id=rec.tenant_id, environment_id=rec.environment_id,
                                                    event_id=rec.request_id, record_payload=rec.to_dict())
        except Exception:  # never let bookkeeping block or fake an approval
            import logging
            logging.getLogger(__name__).exception("Could not write the approval audit record")

    def plan_for_gate(self, plan_id: str, tool_id: str, arguments: Dict[str, Any], caller: Principal) -> Dict[str, Any]:
        """Checks a plan can still be approved for exactly this call (before a human is asked); returns the stored plan."""
        tenant_id, env_id = self._get_effective_coords(caller)
        plan = self.durable.get_execution_plan(tenant_id, env_id, plan_id)
        if not plan:
            raise VCFEnterpriseException(f"Execution plan '{plan_id}' not found in tenant '{tenant_id}'.", error_code=-32012)
        if time.time() > plan["expires_at"]:
            raise AuthorizationDeniedException("Execution plan has expired. Make a new dry run.")
        if caller.user_id != plan["principal_id"]:
            raise AuthorizationDeniedException(f"Caller '{caller.user_id}' does not match plan initiator '{plan['principal_id']}'.")
        if plan.get("tool_id") != tool_id:
            raise AuthorizationDeniedException(
                f"Tool mismatch: Plan was generated for tool '{plan.get('tool_id')}', but attempted execution with tool '{tool_id}'.")
        if self.durable.get_permission_epoch(tenant_id, env_id) != plan["permission_epoch"]:
            raise AuthorizationDeniedException("Authorization stale: permissions changed since the dry run. Make a new dry run.")
        ignored_keys = ["dry_run", "approval_token", "plan_id", "approval_id", "nonce", "approved"]
        clean_args = {k: v for k, v in arguments.items() if k not in ignored_keys}
        # The tool adds the resolved cluster_id / domain_id to a VM call before it checks the plan hash, so those two may be missing here.
        planned = plan.get("normalized_args") or {}
        resolved = ("cluster_id", "domain_id")
        if any(planned.get(k) != v for k, v in clean_args.items() if k not in resolved) or \
                any(k not in clean_args and k not in resolved for k in planned) or \
                any(k in clean_args and k in planned and planned[k] != clean_args[k] for k in resolved):
            raise AuthorizationDeniedException("The arguments differ from the dry run this plan was made for. Repeat the SAME arguments plus plan_id.")
        return plan

    def approvals_for_plan(self, plan: Dict[str, Any]) -> List[Dict[str, Any]]:
        epoch = self.durable.get_permission_epoch(plan["tenant_id"], plan["environment_id"])
        return [a for a in self.durable.list_valid_approvals(plan["tenant_id"], plan["environment_id"], plan["plan_id"])
                if a.get("permission_epoch") == epoch]

    def find_unused_approval(self, plan: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        unused = [a for a in self.approvals_for_plan(plan) if not a.get("used")]
        return unused[-1] if unused else None

    def has_used_approval(self, plan: Dict[str, Any]) -> bool:
        return any(a.get("used") for a in self.approvals_for_plan(plan))

    def describe_plan(self, plan_id: str, caller: Principal) -> Dict[str, Any]:
        """Status of a plan for `vcf_get_plan`: risk, approvals, whether it can run now, and how a human approves it."""
        tenant_id, env_id = self._get_effective_coords(caller)
        plan = self.durable.get_execution_plan(tenant_id, env_id, plan_id)
        if not plan:
            raise VCFEnterpriseException(f"Execution plan '{plan_id}' not found in tenant '{tenant_id}'.", error_code=-32012)
        impact = plan.get("impact_summary", {}) or {}
        risk = impact.get("risk_class", "CHANGE")
        expired = time.time() > plan["expires_at"]
        out: Dict[str, Any] = {
            "plan_id": plan_id, "tool": plan["tool_id"], "risk_class": risk,
            "target_resource_ids": impact.get("target_resource_ids", []),
            "initiator": plan["principal_id"], "expires_at": plan["expires_at"], "expired": expired,
            "approval_mode": "personal" if self.personal is not None else "team",
        }
        if self.personal is not None:
            decision = None if expired else self.personal.sync_page_decision(plan)
            approvals = self.approvals_for_plan(plan)
            unused = [a for a in approvals if not a.get("used")]
            required = 1
            ready = bool(unused) and not expired
            if decision == "REJECTED" or (not ready and not expired and self.personal.rejected_on_page(plan)):
                status = "REJECTED"
            elif expired:
                status = "EXPIRED"
            elif ready:
                status = "APPROVED"
            elif any(a.get("used") for a in approvals):
                status = "EXECUTED"
            else:
                status = "PENDING_APPROVAL"
            out.update(status=status, approvals_recorded=len(approvals), approvals_required=required, ready_to_execute=ready,
                       approvers=[a["approver_id"] for a in approvals])
            if status == "PENDING_APPROVAL":
                out["how_to_approve"] = self.personal.how_to_approve(plan_id, tenant_id, env_id)
            elif ready:
                out["next_step"] = "Call the tool again with the SAME arguments plus plan_id only; the recorded approval is used once."
            elif status == "EXECUTED":
                out["next_step"] = "This plan's approval was already used. Make a new dry run for another execution."
            elif status == "REJECTED":
                out["next_step"] = "The person rejected this plan. Make a new dry run if the change is still wanted."
            return out
        details = self.get_plan(plan_id, caller)
        out.update(status=details["status"], approvals_recorded=details["approvals_recorded"],
                   approvals_required=details["approvals_required"], ready_to_execute=details["ready_to_execute"],
                   approvers=details["approvers"])
        if details["ready_to_execute"]:
            if "approval_id" in details:  # only the initiator receives the single-use hand-back
                out.update(approval_id=details["approval_id"], nonce=details["nonce"])
                out["next_step"] = "Call the tool again with the SAME arguments plus plan_id, approval_id and nonce."
        elif not expired:
            out["how_to_approve"] = how_to_approve(plan_id, RiskClass(risk) if risk in RiskClass._value2member_map_ else RiskClass.HIGH_IMPACT,
                                                  plan["principal_id"], getattr(self.durable, "db_path", None), self.approval_policy)
        return out

    def validate_plan_for_execution(
        self,
        plan_id: str,
        approval_id: str,
        nonce: str,
        current_arguments: Dict[str, Any],
        caller: Principal,
        signed_auth: Optional[SignedExecutionAuthorization] = None,
        expected_tool_id: Optional[str] = None,
        target_resource_ids: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Validates authorization, consumes single-use nonce, unconditionally verifies
        KMS signature against canonical plan hash, verifies N-person approvals requirement,
        and performs TOCTOU revision check.
        Raises PlanStaleException if any affected resource state changed since dry-run!
        """
        if not plan_id:
            raise VCFEnterpriseException("Execution plan ID is required.", error_code=-32012)
        if not approval_id:
            raise AuthorizationDeniedException("Missing approval_id for execution validation.")
        if not nonce:
            raise AuthorizationDeniedException("Missing nonce for execution validation.")

        tenant_id, env_id = self._get_effective_coords(caller)

        plan = self.durable.get_execution_plan(tenant_id, env_id, plan_id)
        if not plan:
            raise VCFEnterpriseException(
                f"Execution plan '{plan_id}' not found in tenant '{tenant_id}'.",
                error_code=-32012,
            )

        if time.time() > plan["expires_at"]:
            raise AuthorizationDeniedException("Execution plan has expired.")

        # 1. Tenant boundary validation
        caller_tid = caller.tenant_id if caller.tenant_id != "tenant-default" else tenant_id
        if caller_tid != plan["tenant_id"]:
            raise AuthorizationDeniedException("Cross-tenant execution plan access denied.")

        # 2. Caller identity must match plan initiator
        if caller.user_id != plan["principal_id"]:
            raise AuthorizationDeniedException(
                f"Caller '{caller.user_id}' does not match plan initiator '{plan['principal_id']}'."
            )

        # Tool and resource binding validation
        if expected_tool_id and plan.get("tool_id") != expected_tool_id:
            raise AuthorizationDeniedException(
                f"Tool mismatch: Plan was generated for tool '{plan.get('tool_id')}', but attempted execution with tool '{expected_tool_id}'."
            )

        if target_resource_ids:
            plan_targets = plan.get("impact_summary", {}).get("target_resource_ids", []) or list(plan.get("resource_revisions", {}).keys())
            for tr in target_resource_ids:
                if plan_targets and tr not in plan_targets:
                    raise AuthorizationDeniedException(
                        f"Resource mismatch: Plan targets {plan_targets}, but execution targets '{tr}'."
                    )

        # 3. Freshness check against permission epoch
        current_epoch = self.durable.get_permission_epoch(tenant_id, env_id)
        if current_epoch != plan["permission_epoch"]:
            raise AuthorizationDeniedException(
                f"Authorization stale: Permission epoch changed from {plan['permission_epoch']} to {current_epoch}."
            )

        # 4. Load and unconditionally verify cryptographic execution authorization presented by caller
        approval_record = self.durable.get_approval(tenant_id, env_id, approval_id)
        if not approval_record and not signed_auth:
            raise AuthorizationDeniedException(
                f"Approval authorization '{approval_id}' not found in tenant '{tenant_id}'."
            )

        sig = signed_auth.signature if (signed_auth and signed_auth.signature) else (approval_record.get("signature") if approval_record else "")
        key_id = signed_auth.key_id if (signed_auth and signed_auth.key_id) else (approval_record.get("key_id") if approval_record else "")
        algo = signed_auth.algorithm if (signed_auth and signed_auth.algorithm) else (approval_record.get("algorithm", "HMAC-SHA256") if approval_record else "HMAC-SHA256")
        sig_version = getattr(signed_auth, "signature_version", "v1") if signed_auth else (approval_record.get("signature_version", "v1") if approval_record else "v1")
        expires_at = signed_auth.expires_at if signed_auth else (approval_record.get("expires_at", 0) if approval_record else 0)
        auth_epoch = signed_auth.permission_epoch if signed_auth else (approval_record.get("permission_epoch") if approval_record else None)
        auth_plan_id = signed_auth.plan_id if signed_auth else (approval_record.get("plan_id") if approval_record else "")
        auth_nonce = signed_auth.nonce if signed_auth else (approval_record.get("nonce") if approval_record else "")

        if not sig or not str(sig).strip():
            raise AuthorizationDeniedException("Cryptographic signature is missing on execution authorization.")

        if not key_id or not str(key_id).strip():
            raise AuthorizationDeniedException("KMS key ID is missing on execution authorization.")

        if expires_at and time.time() > expires_at:
            raise AuthorizationDeniedException(f"Approval authorization '{approval_id}' has expired.")

        if auth_epoch is not None and auth_epoch != current_epoch:
            raise AuthorizationDeniedException(
                f"Authorization stale: Permission epoch changed from {auth_epoch} to {current_epoch}."
            )

        if auth_plan_id and auth_plan_id != plan_id:
            raise AuthorizationDeniedException(
                f"Authorization plan mismatch: Authorization is for plan '{auth_plan_id}', but executing plan '{plan_id}'."
            )

        if auth_nonce and auth_nonce != nonce:
            raise AuthorizationDeniedException("Authorization nonce mismatch: Provided nonce does not match approval record.")

        if signed_auth and approval_record:
            if signed_auth.signature != approval_record.get("signature"):
                raise AuthorizationDeniedException("Tampering detected: Provided signature does not match stored approval signature.")

        # Always recompute KMS digest against current stored plan row data (F11)
        target_res = (
            plan.get("impact_summary", {}).get("target_resource_ids", [])
            or list(plan.get("resource_revisions", {}).keys())
        )
        risk_val = plan.get("impact_summary", {}).get("risk_class", RiskClass.HIGH_IMPACT.value)
        try:
            risk = RiskClass(risk_val)
        except ValueError:
            risk = RiskClass.HIGH_IMPACT

        canonical_hash = compute_canonical_plan_hash(
            tenant_id=plan["tenant_id"],
            environment_id=plan["environment_id"],
            principal_id=plan["principal_id"],
            tool_id=plan["tool_id"],
            target_resource_ids=target_res,
            normalized_arguments=plan["normalized_args"],
            resource_revisions=plan["resource_revisions"],
            permission_epoch=plan["permission_epoch"],
            risk_class=risk.value,
            expires_at=plan["expires_at"],
        )

        if not self.kms.verify_signature(
            digest=canonical_hash,
            signature=sig,
            key_id=key_id,
            signature_version=sig_version,
        ):
            raise AuthorizationDeniedException("Cryptographic signature verification failed on execution authorization.")

        # 5. N-Person Approvals Validation (multi-party authorization)
        required_approvals = plan.get("impact_summary", {}).get("approvals_required", 1)
        policy_required = self.approval_policy.get_required_approvals(risk)
        total_required = max(required_approvals, policy_required)

        valid_approvals = self.durable.list_valid_approvals(tenant_id, env_id, plan_id)
        # Filter approvals for matching permission epoch
        epoch_valid_approvals = [
            a for a in valid_approvals
            if a["permission_epoch"] == current_epoch
        ]

        # Extract distinct approver principal IDs
        lab_self_approve = (
            os.environ.get("VCF_LAB_SELF_APPROVE", "").lower() in ("true", "1", "yes")
            and os.environ.get("VCF_MCP_ENV", "development").lower() != "production"
        )
        lab_auto_approve = (
            os.environ.get("VCF_LAB_AUTO_APPROVE", "").lower() in ("true", "1", "yes")
            and os.environ.get("VCF_MCP_ENV", "development").lower() != "production"
        )
        approvers_set = set()
        for a in epoch_valid_approvals:
            approver_principal = a["approver_id"]
            # Exclude initiator unless explicitly allowed by policy or lab self-approve mode
            if not (self.approval_policy.allow_initiator or lab_self_approve) and approver_principal == plan["principal_id"]:
                continue
            approvers_set.add(approver_principal)

        effective_required = 1 if (lab_self_approve or lab_auto_approve) and total_required > 1 else total_required
        if len(approvers_set) < effective_required:
            raise AuthorizationDeniedException(
                f"Insufficient approvals: Plan requires {effective_required} distinct approver(s), but only {len(approvers_set)} valid approval(s) were recorded."
            )

        # 6. Argument tampering check
        ignored_keys = ["dry_run", "approval_token", "plan_id", "approval_id", "nonce", "approved"]
        clean_args = {k: v for k, v in current_arguments.items() if k not in ignored_keys}
        current_hash = compute_normalized_sha256(clean_args)
        if current_hash != plan["args_sha256"]:
            raise AuthorizationDeniedException(
                f"Tampering detected: Execution arguments hash '{current_hash}' != approved plan hash '{plan['args_sha256']}'"
            )

        # 7. TOCTOU (Time of Check to Time of Use) Revision Verification
        for rid, recorded_rev in plan["resource_revisions"].items():
            current_rev = self.platform.get_resource_revision(rid)
            if str(current_rev) != str(recorded_rev):
                raise PlanStaleException(
                    f"TOCTOU violation: Resource '{rid}' revision changed from '{recorded_rev}' to '{current_rev}' since dry-run. Plan is stale. A new dry-run plan is required.",
                    details={"resource_id": rid, "dry_run_revision": recorded_rev, "current_revision": current_rev},
                )

        # 8. Replay & single-use nonce consumption
        valid, msg = self.durable.consume_approval(tenant_id, env_id, approval_id, nonce)
        if not valid:
            raise AuthorizationDeniedException(f"Invalid approval authorization: {msg}")

        return plan
