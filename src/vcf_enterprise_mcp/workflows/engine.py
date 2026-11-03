# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Deterministic VCF Workflow Engine with Resumability and Compensation Boundaries.
Defines explicit step reversibility, rollback actions, and recovery from process crashes.
"""

from __future__ import annotations
import time
from typing import Dict, Any, List, Optional
from vcf_enterprise_mcp.auth.identity import Principal
from vcf_enterprise_mcp.workflows.task_store import TaskStore, MCPTask, WorkflowStep
from vcf_enterprise_mcp.adapter.platform import PlatformClient, PlatformMode
from vcf_enterprise_mcp.adapter.providers.sddc import SDDCManagerProvider
from vcf_enterprise_mcp.adapter.transport.errors import UpstreamPreconditionException
from vcf_enterprise_mcp.workflows.execution_plans import ExecutionPlanManager
from vcf_enterprise_mcp.core.errors import (
    ApprovalRequiredException,
    PlanStaleException,
    WorkflowExecutionException,
)


# Explicit compensation boundary steps for Workload Domain Upgrades
DOMAIN_UPGRADE_STEPS = [
    WorkflowStep(
        name="Precheck & manifest validation",
        is_reversible=True,
        rollback_action="Clear precheck locks",
        irreversible_after=False,
    ),
    WorkflowStep(
        name="Download & verify release bundles",
        is_reversible=True,
        rollback_action="Delete downloaded bundle cache",
        irreversible_after=False,
    ),
    WorkflowStep(
        name="Evacuate host workloads via DRS",
        is_reversible=True,
        rollback_action="Restore DRS VM placements",
        irreversible_after=False,
    ),
    WorkflowStep(
        name="ESXi host hypervisor upgrade",
        is_reversible=False,
        rollback_action="ESXi shift-R recovery partition boot",
        irreversible_after=False,
    ),
    WorkflowStep(
        name="Server hardware firmware & BIOS flash",
        is_reversible=False,
        rollback_action=None,  # Hardware flash is irreversible!
        irreversible_after=True,
    ),
    WorkflowStep(
        name="Post-upgrade validation & DRS unpause",
        is_reversible=True,
        rollback_action="Emit health alarm",
        irreversible_after=False,
    ),
]


class VCFWorkflowEngine:
    """Orchestrates deterministic multi-step infrastructure workflows with durable resumption."""

    def __init__(
        self,
        task_store: Optional[TaskStore] = None,
        platform_client: Optional[PlatformClient] = None,
        plan_manager: Optional[ExecutionPlanManager] = None,
    ):
        self.task_store = task_store or TaskStore()
        self.platform = platform_client or PlatformClient()
        self.plan_manager = plan_manager or ExecutionPlanManager(
            durable_store=self.task_store.durable,
            platform_client=self.platform,
        )

    def plan_domain_upgrade(
        self,
        domain_id: str,
        target_version: str,
        principal: Principal,
        dry_run: bool = True,
        approval_id: Optional[str] = None,
        nonce: Optional[str] = None,
        plan_id: Optional[str] = None,
        arguments: Optional[Dict[str, Any]] = None,
        plan_validated: bool = False,
    ) -> Dict[str, Any]:
        """
        Plans or executes a workload domain lifecycle upgrade.
        Dry-run: Creates an immutable ExecutionPlan with recorded resource revisions.
        Live: Validates approval, verifies TOCTOU resource revisions, and starts durable task.
        """
        bundle_id = (arguments or {}).get("bundle_id")
        if self._is_real_vcf():
            impact_summary = self._observed_upgrade_impact(domain_id, target_version, bundle_id)
        else:
            impact_summary = {
                "data_source": "SIMULATED",
                "domain_id": domain_id,
                "target_version": target_version,
                "affected_clusters": 2,
                "affected_hosts": 8,
                "affected_vms": 64,
                "estimated_duration_minutes": 90,
                "compensation_boundaries": [
                    {"step": s.name, "reversible": s.is_reversible, "irreversible_after": s.irreversible_after}
                    for s in DOMAIN_UPGRADE_STEPS
                ],
                "prechecks": "PASSED (14/14 checks verified)",
            }

        if dry_run:
            raw_args = arguments or {"domain_id": domain_id, "target_version": target_version}
            return self.plan_manager.create_dry_run_plan(
                principal=principal,
                tool_id="vcf_upgrade_domain",
                arguments=raw_args,
                impact_summary=impact_summary,
                target_resource_ids=[domain_id, "cluster-prod-a", "cluster-prod-b"],
            )

        # Live execution: Enforce signed plan authorization and TOCTOU verification
        if not (plan_id and approval_id and nonce):
            raise ApprovalRequiredException(
                "Live execution of 'vcf_upgrade_domain' requires 'plan_id', 'approval_id', and single-use 'nonce'. Run with dry_run=True first to generate an execution plan."
            )

        if not plan_validated:
            exec_args = arguments or {"domain_id": domain_id, "target_version": target_version}
            self.plan_manager.validate_plan_for_execution(
                plan_id=plan_id,
                approval_id=approval_id,
                nonce=nonce,
                current_arguments=exec_args,
                caller=principal,
            )

        # Real VCF: start the SDDC Manager upgrade and track its native task id.
        native_task_id = f"vcf-lcm-task-{domain_id}-911"
        if self._is_real_vcf():
            started = self.platform.upgrade_domain(domain_id, target_version, bundle_id=bundle_id)
            native_task_id = started["task_id"]

        # Create durable task with compensation steps
        task = self.task_store.create_task(
            tool_name="vcf_upgrade_domain",
            principal=principal,
            steps=DOMAIN_UPGRADE_STEPS,
            approval_status="APPROVED",
            impact_summary=impact_summary,
            native_task_id=native_task_id,
        )
        self.task_store.update_task_progress(
            task.task_id, 1, DOMAIN_UPGRADE_STEPS[0].name, "RUNNING", native_task_id=task.native_task_id
        )

        return {
            "dry_run": False,
            "task_id": task.task_id,
            "status": "RUNNING",
            "message": f"Upgrade workflow for domain '{domain_id}' initiated. Track progress via tasks/get (taskId: {task.task_id}).",
            "impact_plan": impact_summary,
        }

    def plan_site_recovery_drill(
        self,
        plan_id: str,
        target_site: str,
        principal: Principal,
        dry_run: bool = True,
    ) -> Dict[str, Any]:
        if self._is_real_vcf():
            raise UpstreamPreconditionException(
                "vcf_recover_site",
                "No VMware Live Recovery / Site Recovery provider is implemented; refusing to simulate a DR drill against real VCF.",
            )
        impact_plan = {
            "data_source": "SIMULATED",
            "plan_id": plan_id,
            "target_site": target_site,
            "mode": "TEST_BUBBLE",
            "isolated_network": f"seg-{plan_id}-test-bubble",
            "protected_vms_to_recover": 12,
            "production_traffic_impact": "ZERO (Isolated test network)",
        }

        if dry_run:
            return {
                "dry_run": True,
                "allowed": True,
                "approval_required": False,
                "risk_class": "SAFE_WRITE",
                "impact_plan": impact_plan,
            }

        steps = [
            WorkflowStep("Create test bubble isolated network", is_reversible=True, rollback_action="Delete test network"),
            WorkflowStep("Instantiate VM test replicas", is_reversible=True, rollback_action="Power off and delete test replicas"),
            WorkflowStep("Verify guest customization and connectivity", is_reversible=True),
        ]

        task = self.task_store.create_task(
            tool_name="vcf_recover_site",
            principal=principal,
            steps=steps,
            approval_status="APPROVED",
            impact_summary=impact_plan,
            native_task_id=f"srm-test-drill-{plan_id}",
        )
        self.task_store.update_task_progress(task.task_id, 1, steps[0].name, "RUNNING")
        return {
            "dry_run": False,
            "task_id": task.task_id,
            "status": "RUNNING",
            "message": f"Site recovery drill '{plan_id}' initiated on '{target_site}'. Monitor via tasks/get.",
            "impact_plan": impact_plan,
        }

    def resume_in_flight_workflows(self) -> List[Dict[str, Any]]:
        """
        Discovers uncompleted tasks after process restart, queries upstream native tasks,
        and advances workflow state.
        """
        resumable = self.task_store.durable.list_resumable_tasks()
        resumed = []
        if self._is_real_vcf():
            return self._resume_from_native_tasks(resumable)
        for task_row in resumable:
            task_id = task_row["task_id"]
            # Query simulated upstream native task status
            # Advance progress or complete
            progress = min(100.0, task_row["progress"] + 25.0)
            status = "COMPLETED" if progress >= 100.0 else "RUNNING"
            step_desc = "Resumed workflow after control plane reboot"
            if status == "COMPLETED":
                self.task_store.complete_task(task_id, {"status": "SUCCESS", "resumed": True})
            else:
                self.task_store.update_task_progress(task_id, 2, step_desc, status=status)
            resumed.append({"task_id": task_id, "status": status, "progress": progress})
        return resumed

    # -------------------------------------------------------------------------
    # Real VCF helpers: plans and progress come only from observed upstream state.
    # -------------------------------------------------------------------------

    def _is_real_vcf(self) -> bool:
        return getattr(self.platform, "mode", None) == PlatformMode.REAL_VCF

    def _sddc(self) -> SDDCManagerProvider:
        entry = self.platform.registry.resolve("domain.lifecycle")
        return SDDCManagerProvider(
            endpoint_url=entry.endpoint_url,
            transport=self.platform.transport,
            auth=self.platform._auth_for("sddc_manager"),
            api_version=entry.api_version,
        )

    def _observed_upgrade_impact(self, domain_id: str, target_version: str, bundle_id: Optional[str]) -> Dict[str, Any]:
        sddc = self._sddc()
        domain = sddc.get_domain(domain_id) or {}
        upgradables = sddc.get_upgradables(domain_id, target_version=target_version)
        bundles = [
            {"bundle_id": u.get("bundleId"), "bundle_type": u.get("bundleType"), "status": u.get("status"),
             "components": [c.get("type") or c.get("name") for c in (u.get("softwareComponents") or []) if isinstance(c, dict)]}
            for u in upgradables
        ]
        applicable = [b["bundle_id"] for b in bundles if b["status"] in ("AVAILABLE", None)]
        warnings = []
        if bundle_id and bundle_id not in [b["bundle_id"] for b in bundles]:
            warnings.append(f"bundle_id '{bundle_id}' is not listed as upgradable for domain '{domain_id}'.")
        if not bundle_id:
            warnings.append("No bundle_id selected; live execution requires one of the applicable bundles.")
        return {
            "data_source": "OBSERVED",
            "domain_id": domain_id,
            "domain_name": domain.get("name"),
            "domain_status": domain.get("status"),
            "upgrade_state": domain.get("upgradeState"),
            "cluster_count": len(domain.get("clusters") or []),
            "target_version": target_version,
            "selected_bundle_id": bundle_id,
            "upgradable_bundles": bundles,
            "applicable_bundle_ids": applicable,
            "prechecks": "NOT_RUN: run SDDC Manager upgrade prechecks (POST /v1/upgrades/{id}/prechecks) and review results before approval.",
            "upgrade_sequence_reference": "https://knowledge.broadcom.com/external/article/440630",
            "warnings": warnings,
        }

    def _resume_from_native_tasks(self, resumable: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Advances local tasks only from the SDDC Manager task state (GET /v1/tasks/{id})."""
        sddc = self._sddc()
        resumed = []
        for task_row in resumable:
            task_id = task_row["task_id"]
            native_id = task_row.get("native_task_id")
            if not native_id:
                resumed.append({"task_id": task_id, "status": "UNKNOWN", "reason": "no native task id"})
                continue
            try:
                native = sddc.get_task(native_id)
            except Exception as ex:
                resumed.append({"task_id": task_id, "status": "UNKNOWN", "reason": type(ex).__name__})
                continue
            status = native.get("status")
            scope = {"tenant_id": task_row.get("tenant_id"), "environment_id": task_row.get("environment_id")}
            if status in ("SUCCESSFUL", "COMPLETED_WITH_WARNING"):
                self.task_store.complete_task(task_id, {"status": "SUCCESS", "native_status": status, "native_task_id": native_id}, **scope)
                local = "COMPLETED"
            elif status in ("FAILED", "CANCELLED", "TIMED_OUT"):
                self.task_store.fail_task(task_id, f"SDDC Manager task {native_id} ended {status}", **scope)
                local = "FAILED"
            else:
                local = "RUNNING"
            resumed.append({"task_id": task_id, "status": local, "native_status": status, "native_task_id": native_id})
        return resumed
