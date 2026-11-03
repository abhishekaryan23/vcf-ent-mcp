# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Enterprise Policy Enforcement Point (PEP).
Enforces two-stage authorization:
Stage 1: Pre-routing / Pre-discovery tool filtering (principal-sensitive tools/list with cacheScope=private)
Stage 2: Pre-execution validation of exact object, action, risk, and approval requirements.
"""

from __future__ import annotations
from typing import List, Dict, Any, Optional
from vcf_enterprise_mcp.auth.identity import Principal
from vcf_enterprise_mcp.policy.models import RiskClass, CapabilityRole, NormalizedCapability, PolicyDecision, ChangeControlContext
from vcf_enterprise_mcp.policy.engine import PolicyDecisionPoint
from vcf_enterprise_mcp.core.errors import AuthorizationDeniedException, ApprovalRequiredException


class PolicyEnforcementPoint:
    """Gateway enforcement point applying two-stage authorization policies."""

    def __init__(self, pdp: Optional[PolicyDecisionPoint] = None, safety_profile: Optional[Any] = None):
        self.pdp = pdp or PolicyDecisionPoint()
        # Operator safety profile (setup/safety_profile.py): tools switched off for this installation.
        self.safety_profile = safety_profile

    def filter_visible_tools(
        self,
        principal: Principal,
        tools: List[Dict[str, Any]],
        active_skill_allowed_tools: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Stage 1: Pre-discovery / Pre-routing authorization.
        Filters tools/list dynamically so the LLM agent only sees tools the user is entitled to use.
        When active_skill_allowed_tools is provided, further restricts visibility to the active
        single-task role skill's whitelist.
        """
        effective_roles = self.pdp.get_effective_roles_for_principal(principal)
        effective_caps = self.pdp.get_effective_capabilities_for_principal(principal)
        is_discovery_only = self.pdp.config.operating_mode == "DISCOVERY_ONLY"
        skill_whitelist = set(active_skill_allowed_tools) if active_skill_allowed_tools is not None else None

        visible: List[Dict[str, Any]] = []
        for tool in tools:
            if skill_whitelist is not None and tool.get("name") not in skill_whitelist:
                continue
            meta = tool.get("_enterprise_meta", {})
            risk_class = meta.get("risk_class", RiskClass.READ)
            required_roles = meta.get("required_roles", [CapabilityRole.VCF_VIEWER])
            required_cap = meta.get("required_capability")

            # In DISCOVERY_ONLY mode, only READ tools (and control-plane setup tools) are advertised
            if is_discovery_only and risk_class != RiskClass.READ and not meta.get("control_plane_setup"):
                continue

            if self.safety_profile is not None:
                name = tool.get("name", "")
                if meta.get("control_plane_setup"):
                    # Read-only mode must not hide the setup tools (they only ever tighten): only an explicit per-tool block does.
                    if name in self.safety_profile.disabled_tools:
                        continue
                elif self.safety_profile.is_tool_disabled(name, getattr(risk_class, "value", risk_class)):
                    continue

            # Role & capability check
            has_role = (
                CapabilityRole.VCF_PLATFORM_ADMIN in effective_roles
                or any(r in effective_roles for r in required_roles)
            )
            has_cap = (
                required_cap is None
                or required_cap in effective_caps
                or CapabilityRole.VCF_PLATFORM_ADMIN in effective_roles
            )
            if has_role and has_cap:
                clean_tool = {k: v for k, v in tool.items() if not k.startswith("_")}
                visible.append(clean_tool)

        return visible

    def authorize_execution(
        self,
        principal: Principal,
        tool_name: str,
        arguments: Dict[str, Any],
        tool_meta: Dict[str, Any],
        approved: bool = False,
        change_context: Optional[ChangeControlContext] = None,
    ) -> PolicyDecision:
        """
        Stage 2: Pre-execution authorization gate.
        Evaluates exact target object coordinates (VM, cluster, domain), checks dry-run,
        validates risk level, and enforces approval requirements.
        """
        risk_class = tool_meta.get("risk_class", RiskClass.READ)
        required_roles = tool_meta.get("required_roles", [CapabilityRole.VCF_VIEWER])
        required_cap = tool_meta.get("required_capability")
        dry_run = arguments.get("dry_run", False)

        target_resource = {
            "domain_id": arguments.get("domain_id"),
            "cluster_id": arguments.get("cluster_id") or arguments.get("cluster"),
            "vm_id": arguments.get("vm_id"),
            "site_id": arguments.get("datacenter_id") or arguments.get("site_id"),
        }

        if self.safety_profile is not None and self.safety_profile.is_tool_disabled(
            tool_name, getattr(risk_class, "value", risk_class)
        ):
            raise AuthorizationDeniedException(
                f"Tool '{tool_name}' is disabled by the operator safety profile "
                f"({self.safety_profile.disabled_reason(tool_name)}). Re-enable it locally with "
                f"'vcf-mcp safety enable {tool_name}'."
            )

        decision = self.pdp.evaluate_request(
            principal=principal,
            tool_name=tool_name,
            risk_class=risk_class,
            required_roles=required_roles,
            required_capability=required_cap,
            target_resource=target_resource,
            change_context=change_context,
            dry_run=dry_run,
        )

        if not decision.allow:
            raise AuthorizationDeniedException(
                f"PEP Authorization Denied: {decision.reason} [Principal: {principal.user_id}, Tool: {tool_name}]"
            )

        if decision.approval_required and not dry_run:
            # Caller-supplied 'approved: true' boolean flags have ZERO security trust.
            # Real live execution requires signed execution plan authorization credentials.
            has_auth = bool(arguments.get("plan_id") and arguments.get("approval_id") and arguments.get("nonce"))
            if not has_auth:
                raise ApprovalRequiredException(
                    f"PEP Approval Required: High-impact operation '{tool_name}' requires operational approval before execution. Run with dry_run=True to inspect impact plan first."
                )

        return decision
