# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
L1 troubleshooting tools: read-only root-cause analysis across SDDC Manager, every vCenter,
every NSX Manager cluster and VCF Operations (see diagnostics/engine.py).
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict

from vcf_enterprise_mcp.auth.identity import Principal
from vcf_enterprise_mcp.core.errors import InvalidArgumentException
from vcf_enterprise_mcp.diagnostics import service
from vcf_enterprise_mcp.policy.models import CapabilityRole, NormalizedCapability, RiskClass
from vcf_enterprise_mcp.tools.base import BaseEnterpriseTool

DIAG_ROLES = [CapabilityRole.VCF_VIEWER, CapabilityRole.VCF_AUDITOR, CapabilityRole.COMPUTE_OPERATOR,
              CapabilityRole.NETWORK_OPERATOR, CapabilityRole.STORAGE_OPERATOR, CapabilityRole.LIFECYCLE_OPERATOR]


class _DiagTool(BaseEnterpriseTool):
    level = "L1_QUERY"
    risk_class = RiskClass.READ
    required_roles = DIAG_ROLES
    required_capability = NormalizedCapability.LIFECYCLE_DOMAIN_READ

    async def _call(self, fn, *args, **kwargs) -> Dict[str, Any]:
        try:
            # Collection makes many sequential HTTPS calls; keep the event loop free.
            return await asyncio.to_thread(fn, self.platform, *args, **kwargs)
        except service.DiagnosticsUnavailable as exc:
            return {"status": "UNAVAILABLE", "reason": str(exc)}


class VCFDiagnoseTool(_DiagTool):
    name = "vcf_diagnose"

    async def run_live(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        return await self._call(service.diagnose, symptom=arguments.get("symptom", ""), domain=arguments.get("domain"))


class VCFCheckComponentTool(_DiagTool):
    name = "vcf_check_component"

    async def run_live(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        component = arguments.get("component")
        if component not in ("sddc_manager", "vcenter", "nsx", "vcf_operations"):
            raise InvalidArgumentException("component must be one of: sddc_manager, vcenter, nsx, vcf_operations")
        return await self._call(service.check_component, component, arguments.get("target"))


class VCFListFailedTasksTool(_DiagTool):
    name = "vcf_list_failed_tasks"

    async def run_live(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        return await self._call(service.list_failed_tasks)


class VCFListAlertsTool(_DiagTool):
    name = "vcf_list_alerts"

    async def run_live(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        return await self._call(service.list_alerts, bool(arguments.get("include_warnings", False)))
