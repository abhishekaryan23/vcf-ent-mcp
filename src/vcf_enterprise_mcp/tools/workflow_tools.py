# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
L3 Workflow Tools (Deterministic Multi-step Orchestration, HIGH_IMPACT).
Executes coordinated domain lifecycle upgrades and disaster recovery drills with MCP Tasks tracking,
execution plan binding, and compensation boundaries.
"""

from __future__ import annotations
from typing import Dict, Any, Optional
from vcf_enterprise_mcp.auth.identity import Principal
from vcf_enterprise_mcp.policy.models import RiskClass, CapabilityRole, NormalizedCapability
from vcf_enterprise_mcp.tools.base import BaseEnterpriseTool
from vcf_enterprise_mcp.workflows.engine import VCFWorkflowEngine


class VCFUpgradeDomainTool(BaseEnterpriseTool):
    name = "vcf_upgrade_domain"
    level = "L3_WORKFLOW"
    risk_class = RiskClass.HIGH_IMPACT
    required_roles = [CapabilityRole.LIFECYCLE_ADMIN, CapabilityRole.VCF_PLATFORM_ADMIN]
    required_capability = NormalizedCapability.LIFECYCLE_DOMAIN_UPGRADE

    def __init__(self, workflow_engine: Optional[VCFWorkflowEngine] = None, **kwargs):
        self.workflow_engine = workflow_engine or VCFWorkflowEngine()
        if "plan_manager" not in kwargs:
            kwargs["plan_manager"] = self.workflow_engine.plan_manager
        if "durable_store" not in kwargs:
            kwargs["durable_store"] = self.workflow_engine.task_store.durable
        super().__init__(**kwargs)

    async def run_dry_run(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        domain_id = arguments["domain_id"]
        target_ver = arguments.get("target_version", "9.1.1")
        return self.workflow_engine.plan_domain_upgrade(
            domain_id=domain_id,
            target_version=target_ver,
            principal=principal,
            dry_run=True,
            arguments=arguments,
        )

    async def run_live(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        domain_id = arguments["domain_id"]
        target_ver = arguments.get("target_version", "9.1.1")
        plan_id = arguments.get("plan_id")
        approval_id = arguments.get("approval_id")
        nonce = arguments.get("nonce")
        return self.workflow_engine.plan_domain_upgrade(
            domain_id=domain_id,
            target_version=target_ver,
            principal=principal,
            dry_run=False,
            approval_id=approval_id,
            nonce=nonce,
            plan_id=plan_id,
            arguments=arguments,
            plan_validated=True,
        )


class VCFRecoverSiteTool(BaseEnterpriseTool):
    name = "vcf_recover_site"
    level = "L3_WORKFLOW"
    risk_class = RiskClass.SAFE_WRITE  # Test drill mode is non-disruptive
    required_roles = [CapabilityRole.DR_OPERATOR, CapabilityRole.DR_ADMIN]
    required_capability = NormalizedCapability.DR_REPLICATION_READ

    def __init__(self, workflow_engine: Optional[VCFWorkflowEngine] = None, **kwargs):
        self.workflow_engine = workflow_engine or VCFWorkflowEngine()
        if "plan_manager" not in kwargs:
            kwargs["plan_manager"] = self.workflow_engine.plan_manager
        if "durable_store" not in kwargs:
            kwargs["durable_store"] = self.workflow_engine.task_store.durable
        super().__init__(**kwargs)

    async def run_dry_run(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        dr_plan_id = arguments.get("recovery_plan_id") or arguments.get("plan_id") or "rp-default"
        # Preserve recovery_plan_id in arguments before ExecutionPlanManager strips 'plan_id'
        if "recovery_plan_id" not in arguments and not str(dr_plan_id).startswith("plan_"):
            arguments["recovery_plan_id"] = dr_plan_id
        target_site = arguments.get("target_site", "dc2")
        return self.workflow_engine.plan_site_recovery_drill(
            plan_id=dr_plan_id,
            target_site=target_site,
            principal=principal,
            dry_run=True,
        )

    async def run_live(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        dr_plan_id = arguments.get("recovery_plan_id")
        if not dr_plan_id:
            raw_pid = arguments.get("plan_id", "rp-default")
            dr_plan_id = "rp-default" if str(raw_pid).startswith("plan_") else raw_pid
        target_site = arguments.get("target_site", "dc2")
        return self.workflow_engine.plan_site_recovery_drill(
            plan_id=dr_plan_id,
            target_site=target_site,
            principal=principal,
            dry_run=False,
        )
