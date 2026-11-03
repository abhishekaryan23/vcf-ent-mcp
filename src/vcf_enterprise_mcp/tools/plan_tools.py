# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""vcf_get_plan: status of a dry-run plan (risk, approvals, ready to execute, how a human approves it)."""

from __future__ import annotations

from typing import Any, Dict

from vcf_enterprise_mcp.auth.identity import Principal
from vcf_enterprise_mcp.core.errors import InvalidArgumentException
from vcf_enterprise_mcp.policy.models import CapabilityRole, RiskClass
from vcf_enterprise_mcp.tools.base import BaseEnterpriseTool


class VCFGetPlanTool(BaseEnterpriseTool):
    name = "vcf_get_plan"
    level = "L1_QUERY"
    risk_class = RiskClass.READ
    required_roles = list(CapabilityRole)
    required_capability = None
    subsystem = "control_plane"

    async def run_live(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        plan_id = str(arguments.get("plan_id") or "").strip()
        if not plan_id:
            raise InvalidArgumentException("plan_id is required (it comes from the dry run).")
        return self.plan_manager.describe_plan(plan_id, principal)
