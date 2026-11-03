# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Enterprise Policy Decision Point (PDP).
Evaluates the core intersection formula:
Effective Permission = Corporate Identity ∩ Native VCF entitlement ∩ MCP policy ∩ Resource scope ∩ Tool risk policy ∩ Operational conditions.
Tracks permission freshness via permission epochs and checks change control windows.
"""

from __future__ import annotations
import time
from typing import Dict, Any, List, Set, Optional
from vcf_enterprise_mcp.auth.identity import Principal
from vcf_enterprise_mcp.policy.models import (
    RiskClass,
    CapabilityRole,
    NormalizedCapability,
    ROLE_PRESET_CAPABILITIES,
    ChangeControlContext,
    ResourceScope,
    PolicyDecision,
)
from vcf_enterprise_mcp.config.settings import PolicyConfig
from vcf_enterprise_mcp.state.durable_store import DurableStore


GROUP_TO_CAPABILITY_ROLES: Dict[str, List[CapabilityRole]] = {
    "VCF-Platform-Admins": [
        CapabilityRole.VCF_PLATFORM_ADMIN,
        CapabilityRole.COMPUTE_ADMIN,
        CapabilityRole.NETWORK_ADMIN,
        CapabilityRole.STORAGE_ADMIN,
        CapabilityRole.DR_ADMIN,
        CapabilityRole.LIFECYCLE_ADMIN,
        CapabilityRole.SECURITY_ADMIN,
        CapabilityRole.VCF_VIEWER,
    ],
    "corp-cloud-admins": [
        CapabilityRole.VCF_PLATFORM_ADMIN,
        CapabilityRole.COMPUTE_ADMIN,
        CapabilityRole.NETWORK_ADMIN,
        CapabilityRole.STORAGE_ADMIN,
        CapabilityRole.DR_ADMIN,
        CapabilityRole.LIFECYCLE_ADMIN,
        CapabilityRole.SECURITY_ADMIN,
        CapabilityRole.VCF_VIEWER,
    ],
    "VCF-Compute-Operators": [
        CapabilityRole.COMPUTE_OPERATOR,
        CapabilityRole.VCF_VIEWER,
    ],
    "vcf-compute-operators": [
        CapabilityRole.COMPUTE_OPERATOR,
        CapabilityRole.VCF_VIEWER,
    ],
    "VCF-Compute-Admins": [
        CapabilityRole.COMPUTE_ADMIN,
        CapabilityRole.COMPUTE_OPERATOR,
        CapabilityRole.VCF_VIEWER,
    ],
    "VCF-Network-Operators": [
        CapabilityRole.NETWORK_OPERATOR,
        CapabilityRole.VCF_VIEWER,
    ],
    "vcf-network-operators": [
        CapabilityRole.NETWORK_OPERATOR,
        CapabilityRole.VCF_VIEWER,
    ],
    "VCF-Network-Admins": [
        CapabilityRole.NETWORK_ADMIN,
        CapabilityRole.NETWORK_OPERATOR,
        CapabilityRole.VCF_VIEWER,
    ],
    "VCF-Storage-Operators": [
        CapabilityRole.STORAGE_OPERATOR,
        CapabilityRole.VCF_VIEWER,
    ],
    "vcf-storage-operators": [
        CapabilityRole.STORAGE_OPERATOR,
        CapabilityRole.VCF_VIEWER,
    ],
    "VCF-Storage-Admins": [
        CapabilityRole.STORAGE_ADMIN,
        CapabilityRole.STORAGE_OPERATOR,
        CapabilityRole.VCF_VIEWER,
    ],
    "VCF-Lifecycle-Operators": [
        CapabilityRole.LIFECYCLE_OPERATOR,
        CapabilityRole.VCF_VIEWER,
    ],
    "VCF-Lifecycle-Admins": [
        CapabilityRole.LIFECYCLE_ADMIN,
        CapabilityRole.LIFECYCLE_OPERATOR,
        CapabilityRole.VCF_VIEWER,
    ],
    "VCF-Automation-Operators": [
        CapabilityRole.AUTOMATION_OPERATOR,
        CapabilityRole.VCF_VIEWER,
    ],
    "VCF-MCP-Admins": [
        CapabilityRole.MCP_ADMIN,
        CapabilityRole.VCF_VIEWER,
    ],
    "VCF-DR-Operators": [
        CapabilityRole.DR_OPERATOR,
        CapabilityRole.VCF_VIEWER,
    ],
    "VCF-DR-Admins": [
        CapabilityRole.DR_ADMIN,
        CapabilityRole.DR_OPERATOR,
        CapabilityRole.VCF_VIEWER,
    ],
    "VCF-Security-Admins": [
        CapabilityRole.SECURITY_ADMIN,
        CapabilityRole.VCF_AUDITOR,
        CapabilityRole.VCF_VIEWER,
    ],
    "VCF-Auditors": [
        CapabilityRole.VCF_AUDITOR,
        CapabilityRole.VCF_VIEWER,
    ],
    "VCF-Prod-ReadOnly": [
        CapabilityRole.VCF_VIEWER,
    ],
    "VCF-Users-ReadOnly": [
        CapabilityRole.VCF_VIEWER,
    ],
    "VCF-Guest-ReadOnly": [
        CapabilityRole.VCF_VIEWER,
    ],
}

ROLE_MAX_RISK: Dict[CapabilityRole, RiskClass] = {
    CapabilityRole.VCF_VIEWER: RiskClass.READ,
    CapabilityRole.VCF_AUDITOR: RiskClass.READ,
    CapabilityRole.COMPUTE_OPERATOR: RiskClass.CHANGE,
    CapabilityRole.COMPUTE_ADMIN: RiskClass.HIGH_IMPACT,
    CapabilityRole.NETWORK_OPERATOR: RiskClass.READ,
    CapabilityRole.NETWORK_ADMIN: RiskClass.HIGH_IMPACT,
    CapabilityRole.STORAGE_OPERATOR: RiskClass.READ,
    CapabilityRole.STORAGE_ADMIN: RiskClass.HIGH_IMPACT,
    CapabilityRole.AUTOMATION_OPERATOR: RiskClass.CHANGE,
    CapabilityRole.DR_OPERATOR: RiskClass.SAFE_WRITE,
    CapabilityRole.DR_ADMIN: RiskClass.HIGH_IMPACT,
    CapabilityRole.LIFECYCLE_OPERATOR: RiskClass.READ,
    CapabilityRole.LIFECYCLE_ADMIN: RiskClass.HIGH_IMPACT,
    CapabilityRole.SECURITY_ADMIN: RiskClass.SECURITY_SENSITIVE,
    CapabilityRole.VCF_PLATFORM_ADMIN: RiskClass.DESTRUCTIVE,
    CapabilityRole.MCP_ADMIN: RiskClass.SAFE_WRITE,
}


class PolicyDecisionPoint:
    """Evaluates multi-factor authorization requests against restrictive enterprise policies."""

    def __init__(
        self,
        config: Optional[PolicyConfig] = None,
        durable_store: Optional[DurableStore] = None,
        tenant_id: str = "tenant-default",
        environment_id: str = "env-prod",
    ):
        self.config = config or PolicyConfig()
        self.durable = durable_store or DurableStore()
        self.tenant_id = tenant_id
        self.environment_id = environment_id

    def get_effective_roles_for_principal(self, principal: Principal) -> Set[CapabilityRole]:
        """Maps principal corporate groups and explicitly assigned roles into a union of capability roles."""
        roles: Set[CapabilityRole] = set()
        for grp in principal.corporate_groups:
            if grp in GROUP_TO_CAPABILITY_ROLES:
                roles.update(GROUP_TO_CAPABILITY_ROLES[grp])
        if hasattr(principal, "roles") and principal.roles:
            for r in principal.roles:
                if isinstance(r, CapabilityRole):
                    roles.add(r)
                elif isinstance(r, str):
                    matched = False
                    for cr in CapabilityRole:
                        if cr.value.lower() == r.lower() or cr.name.lower() == r.lower():
                            roles.add(cr)
                            matched = True
                            break
                    if not matched:
                        # Strict role mapping: unmapped/unknown roles must NEVER escalate to admin
                        roles.add(CapabilityRole.VCF_VIEWER)
        if not roles:
            roles.add(CapabilityRole.VCF_VIEWER)
        return roles

    def get_effective_capabilities_for_principal(self, principal: Principal) -> Set[NormalizedCapability]:
        """Calculates union of normalized capabilities derived from mapped roles and custom grants."""
        roles = self.get_effective_roles_for_principal(principal)
        caps: Set[NormalizedCapability] = set()
        for r in roles:
            if r in ROLE_PRESET_CAPABILITIES:
                caps.update(ROLE_PRESET_CAPABILITIES[r])
        return caps

    def get_current_epoch(self) -> int:
        return self.durable.get_permission_epoch(self.tenant_id, self.environment_id)

    def bump_epoch_on_permission_change(self) -> int:
        """Called when an administrator alters privileges or revokes user access."""
        return self.durable.bump_permission_epoch(self.tenant_id, self.environment_id)

    def evaluate_request(
        self,
        principal: Principal,
        tool_name: str,
        risk_class: RiskClass,
        required_roles: List[CapabilityRole],
        required_capability: Optional[NormalizedCapability] = None,
        target_resource: Optional[Dict[str, Any]] = None,
        change_context: Optional[ChangeControlContext] = None,
        dry_run: bool = False,
        vcf_version: str = "9.1.1",
    ) -> PolicyDecision:
        now = time.time()
        tenant_id = principal.tenant_id or self.tenant_id
        env_id = principal.environment_ids[0] if principal.environment_ids else self.environment_id
        current_epoch = self.durable.get_permission_epoch(tenant_id, env_id)
        effective_roles = self.get_effective_roles_for_principal(principal)
        effective_caps = self.get_effective_capabilities_for_principal(principal)

        def _r_str(r: Any) -> str:
            return r.value if hasattr(r, "value") else str(r)

        target_res = target_resource or {}
        domain_id = target_res.get("domain_id")
        cluster_id = target_res.get("cluster_id")
        site_id = target_res.get("site_id")

        # 1. Operating Mode Guardrail (Emergency Stop & Read-Only / Disabled Enforcement)
        op_mode = (self.config.operating_mode or "UNKNOWN").upper()
        if op_mode == "DISABLED":
            return PolicyDecision(
                allow=False,
                reason="Action denied: Control Plane is in DISABLED mode (emergency stop). All operations blocked.",
                risk_class=risk_class,
                effective_roles=[_r_str(r) for r in effective_roles],
                effective_capabilities=effective_caps,
                permission_epoch=current_epoch,
                tenant_id=tenant_id,
                environment_id=env_id,
                decision_timestamp=now,
            )
        elif op_mode in ("READ_ONLY", "DISCOVERY_ONLY"):
            if risk_class != RiskClass.READ:
                return PolicyDecision(
                    allow=False,
                    reason=f"Action denied: Control Plane is in {op_mode} mode. Mutating operation '{tool_name}' ({risk_class.value}) is blocked.",
                    risk_class=risk_class,
                    effective_roles=[_r_str(r) for r in effective_roles],
                    effective_capabilities=effective_caps,
                    permission_epoch=current_epoch,
                    tenant_id=tenant_id,
                    environment_id=env_id,
                    decision_timestamp=now,
                )
        elif op_mode not in ("AUDITED_OPERATIONS", "FULL_ENFORCEMENT"):
            # Unknown / typo operating mode -> FAIL CLOSED
            return PolicyDecision(
                allow=False,
                reason=f"Action denied: Control Plane is in unrecognized operating mode '{op_mode}'. Fail-closed.",
                risk_class=risk_class,
                effective_roles=[_r_str(r) for r in effective_roles],
                effective_capabilities=effective_caps,
                permission_epoch=current_epoch,
                tenant_id=tenant_id,
                environment_id=env_id,
                decision_timestamp=now,
            )

        # 2. Capability & Role Matching
        # Either normalized capability matches OR role preset matches
        has_role = (
            CapabilityRole.VCF_PLATFORM_ADMIN in effective_roles
            or any(r in effective_roles for r in required_roles)
        )
        has_cap = (
            required_capability is None
            or required_capability in effective_caps
            or CapabilityRole.VCF_PLATFORM_ADMIN in effective_roles
        )
        if not (has_role and has_cap):
            req_role_names = [_r_str(r) for r in required_roles]
            return PolicyDecision(
                allow=False,
                reason=f"Action denied: Principal '{principal.user_id}' lacks required capability role ({', '.join(req_role_names)}). Granted: {[_r_str(r) for r in effective_roles]}.",
                risk_class=risk_class,
                effective_roles=[_r_str(r) for r in effective_roles],
                effective_capabilities=effective_caps,
                permission_epoch=current_epoch,
                tenant_id=tenant_id,
                environment_id=env_id,
                decision_timestamp=now,
            )

        # 3. Risk Class Ceiling Check
        risk_order = {
            RiskClass.READ: 0,
            RiskClass.SAFE_WRITE: 1,
            RiskClass.CHANGE: 2,
            RiskClass.HIGH_IMPACT: 3,
            RiskClass.DESTRUCTIVE: 4,
            RiskClass.SECURITY_SENSITIVE: 5,
        }
        requested_risk_lvl = risk_order[risk_class]
        allowed_by_risk = False
        for role in effective_roles:
            max_r = ROLE_MAX_RISK.get(role, RiskClass.READ)
            if risk_order[max_r] >= requested_risk_lvl:
                allowed_by_risk = True
                break

        if not allowed_by_risk and not dry_run:
            return PolicyDecision(
                allow=False,
                reason=f"Action denied: Risk ceiling exceeded. Tool '{tool_name}' carries risk '{risk_class.value}', which exceeds maximum authorized risk for roles {[_r_str(r) for r in effective_roles]}.",
                risk_class=risk_class,
                effective_roles=[_r_str(r) for r in effective_roles],
                effective_capabilities=effective_caps,
                permission_epoch=current_epoch,
                tenant_id=tenant_id,
                environment_id=env_id,
                decision_timestamp=now,
            )

        # 4. Resource Scope Enforcement
        if not principal.is_in_resource_scope(domain_id=domain_id, cluster_id=cluster_id):
            return PolicyDecision(
                allow=False,
                reason=f"Action denied: Resource scope violation. Target cluster '{cluster_id}' or domain '{domain_id}' is outside principal's permitted boundaries.",
                risk_class=risk_class,
                effective_roles=[_r_str(r) for r in effective_roles],
                effective_capabilities=effective_caps,
                permission_epoch=current_epoch,
                tenant_id=tenant_id,
                environment_id=env_id,
                decision_timestamp=now,
            )

        # 5. Change Control Window / Ticket Check (if not dry_run)
        if change_context and not dry_run:
            permitted, chg_reason = change_context.is_change_permitted(risk_class)
            if not permitted:
                return PolicyDecision(
                    allow=False,
                    reason=f"Action denied: Change control policy: {chg_reason}",
                    risk_class=risk_class,
                    effective_roles=[_r_str(r) for r in effective_roles],
                    effective_capabilities=effective_caps,
                    permission_epoch=current_epoch,
                    tenant_id=tenant_id,
                    environment_id=env_id,
                    decision_timestamp=now,
                )

        # 6. Approval Requirements for Mutating Operations
        needs_approval = False
        if not dry_run:
            if risk_class in (RiskClass.HIGH_IMPACT, RiskClass.DESTRUCTIVE, RiskClass.SECURITY_SENSITIVE):
                if self.config.require_approval_for_high_impact:
                    needs_approval = True
            elif risk_class == RiskClass.CHANGE:
                if self.config.operating_mode == "FULL_ENFORCEMENT" or getattr(self.config, "require_approval_for_change", False):
                    needs_approval = True

        approval_note = " (APPROVAL REQUIRED before live execution)" if needs_approval else ""
        return PolicyDecision(
            allow=True,
            reason=f"Authorized under policy intersection: roles={[_r_str(r) for r in effective_roles]}, scope=OK{approval_note}",
            approval_required=needs_approval,
            risk_class=risk_class,
            effective_roles=[_r_str(r) for r in effective_roles],
            effective_capabilities=effective_caps,
            permission_epoch=current_epoch,
            tenant_id=tenant_id,
            environment_id=env_id,
            decision_timestamp=now,
        )
