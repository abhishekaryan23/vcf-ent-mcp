# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
VCF Automation tools (Assembler cloud templates, Orchestrator workflows) and the
application/network views of the troubleshooting engine. See automation/service.py and
diagnostics/service.py.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict

from vcf_enterprise_mcp.auth.identity import Principal
from vcf_enterprise_mcp.automation import service as auto
from vcf_enterprise_mcp.core.errors import InvalidArgumentException
from vcf_enterprise_mcp.diagnostics import service as diag
from vcf_enterprise_mcp.policy.models import CapabilityRole, NormalizedCapability, RiskClass
from vcf_enterprise_mcp.tools.base import BaseEnterpriseTool
from vcf_enterprise_mcp.tools.diagnostic_tools import DIAG_ROLES, _DiagTool

AUTO_READ_ROLES = [CapabilityRole.VCF_VIEWER, CapabilityRole.VCF_AUDITOR, CapabilityRole.AUTOMATION_OPERATOR]


class _AutoTool(BaseEnterpriseTool):
    level = "L1_QUERY"
    risk_class = RiskClass.READ
    required_roles = AUTO_READ_ROLES
    required_capability = NormalizedCapability.AUTOMATION_READ

    async def _call(self, fn, *args, **kwargs) -> Dict[str, Any]:
        try:
            return await asyncio.to_thread(fn, self.platform, *args, **kwargs)
        except auto.AutomationUnavailable as exc:
            return {"status": "UNAVAILABLE", "reason": str(exc)}

    @staticmethod
    def _need(arguments: Dict[str, Any], *names: str) -> None:
        missing = [n for n in names if not arguments.get(n)]
        if missing:
            raise InvalidArgumentException(f"Missing required argument(s): {', '.join(missing)}")


class VCFTraceApplicationTool(_DiagTool):
    name = "vcf_trace_application"
    required_roles = DIAG_ROLES

    async def run_live(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        if not arguments.get("application"):
            raise InvalidArgumentException("application is required (an Application tag such as 'CRM', a cluster/AG name, an AD forest or a VM name)")
        return await self._call(diag.trace_application, arguments["application"])


class VCFListNetworksTool(_DiagTool):
    name = "vcf_list_networks"

    async def run_live(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        return await self._call(diag.list_networks, arguments.get("domain"))


class VCFAutomationListTool(_AutoTool):
    name = "vcf_automation_list"

    async def run_live(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        kind = arguments.get("kind")
        if kind not in auto.KINDS:
            raise InvalidArgumentException(f"kind must be one of: {', '.join(auto.KINDS)}")
        return await self._call(auto.inventory, kind, arguments.get("project_id"))


class VCFAutomationGetTool(_AutoTool):
    name = "vcf_automation_get"

    async def run_live(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        self._need(arguments, "kind", "id")
        if arguments["kind"] == "template":
            return await self._call(auto.get_template, arguments["id"])
        raise InvalidArgumentException("kind must be 'template' (for Orchestrator workflows use vcf_orch_get)")


class VCFAutomationValidateTemplateTool(_AutoTool):
    name = "vcf_automation_validate_template"

    async def run_live(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        self._need(arguments, "project_id", "content")
        return await self._call(auto.validate_template, arguments["project_id"], arguments["content"])


class VCFAutomationCreateTemplateTool(_AutoTool):
    name = "vcf_automation_create_template"
    level = "L2_OPERATIONAL"
    risk_class = RiskClass.CHANGE
    required_roles = [CapabilityRole.AUTOMATION_OPERATOR]
    required_capability = NormalizedCapability.AUTOMATION_TEMPLATE_WRITE

    async def run_dry_run(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        self._need(arguments, "project_id", "name", "content")
        check = await self._call(auto.validate_template, arguments["project_id"], arguments["content"])
        return {"dry_run": True, "would_create": f"cloud template '{arguments['name']}' (DRAFT) in project {arguments['project_id']}",
                "validation": check, "allowed": bool(check.get("valid")),
                "next_step": "Get the plan approved by a human approver (vcf-mcp plans approve <plan_id>), then call again with the SAME arguments plus plan_id, approval_id and nonce (without dry_run)." if check.get("valid")
                else "Fix the validation errors, then dry-run again."}

    async def run_live(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        self._need(arguments, "project_id", "name", "content")
        return await self._call(auto.create_template, arguments["project_id"], arguments["name"], arguments["content"],
                                arguments.get("description", ""))
