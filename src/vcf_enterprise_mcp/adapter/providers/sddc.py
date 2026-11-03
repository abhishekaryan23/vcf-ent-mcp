# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
SDDC Manager / VCF Platform Provider.
Provides workload domain lifecycle management, LCM upgrades, pre-checks, and bundle management.
"""

from __future__ import annotations
from typing import Dict, Any, List, Optional
from vcf_enterprise_mcp.adapter.providers.base import BaseVCFProvider
from vcf_enterprise_mcp.adapter.transport.errors import UpstreamPreconditionException
from vcf_enterprise_mcp.adapter.models import (
    ResourceRevision,
    ReconciliationStatus,
    ReconciliationResult,
    ExecutionIntent,
)


class SDDCManagerProvider(BaseVCFProvider):
    """Integrates with VMware Cloud Foundation SDDC Manager APIs (/v1/*)."""

    def get_domains(self) -> List[Dict[str, Any]]:
        resp = self.request("GET", "/v1/domains")
        data = resp.json()
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return data.get("elements", data.get("domains", []))
        return []

    def get_domain(self, domain_id: str) -> Optional[Dict[str, Any]]:
        resp = self.request("GET", f"/v1/domains/{domain_id}")
        data = resp.json()
        if isinstance(data, dict):
            return data
        return None

    # SDDC Manager Task.status values that are terminal (normalized to upper snake case).
    TERMINAL_TASK_STATES = {"SUCCESSFUL", "FAILED", "CANCELLED", "COMPLETED_WITH_WARNING", "SKIPPED", "TIMED_OUT"}

    @staticmethod
    def _elements(data: Any) -> List[Dict[str, Any]]:
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return data.get("elements", [])
        return []

    def get_upgradables(self, domain_id: str, target_version: Optional[str] = None) -> List[Dict[str, Any]]:
        """GET /v1/upgradables/domains/{domainId}: bundles applicable to the domain (PageOfUpgradable)."""
        params = {"targetVersion": target_version} if target_version else None
        resp = self.request("GET", f"/v1/upgradables/domains/{domain_id}", params=params)
        return self._elements(resp.json())

    def upgrade_domain(self, domain_id: str, target_version: str, bundle_id: Optional[str] = None) -> Dict[str, Any]:
        """Starts a domain upgrade with POST /v1/upgrades (UpgradeSpec).

        UpgradeSpec requires bundleId, resourceType and resourceUpgradeSpecs. A target version is
        not part of the spec; the caller must pick a bundle from get_upgradables().
        """
        if not bundle_id:
            raise UpstreamPreconditionException(
                "upgrade_domain",
                "SDDC Manager upgrades are bundle-based: supply bundle_id from GET /v1/upgradables/domains/{domainId}.",
            )
        body = {
            "bundleId": bundle_id,
            "resourceType": "DOMAIN",
            "resourceUpgradeSpecs": [{"resourceId": domain_id, "upgradeNow": True}],
        }
        resp = self.request("POST", "/v1/upgrades", json_body=body)
        task = resp.json() if resp.is_success else None
        task_id = task.get("id") if isinstance(task, dict) else None
        if not task_id:
            raise UpstreamPreconditionException("upgrade_domain", "SDDC Manager did not return a task id; upgrade state is unknown.", {"http_status": resp.status_code})
        return {
            "domain_id": domain_id,
            "target_version": target_version,
            "bundle_id": bundle_id,
            "task_id": task_id,
            "status": self.normalize_task_status(task.get("status")),
        }

    @staticmethod
    def normalize_task_status(status: Any) -> str:
        """Task.status mixes forms ('IN_PROGRESS', 'In Progress'); normalize to upper snake case."""
        return str(status or "UNKNOWN").strip().upper().replace(" ", "_")

    def get_task(self, task_id: str) -> Dict[str, Any]:
        """GET /v1/tasks/{id}: authoritative progress for long-running SDDC Manager operations."""
        resp = self.request("GET", f"/v1/tasks/{task_id}")
        data = resp.json()
        if not isinstance(data, dict):
            return {"id": task_id, "status": "UNKNOWN"}
        data["status"] = self.normalize_task_status(data.get("status"))
        return data

    def get_system_health(self) -> Dict[str, Any]:
        """Domain lifecycle status from GET /v1/domains.

        SDDC Manager has no synchronous health endpoint (health-summary and check-sets are
        asynchronous runs), so this reports observed domain states only and never infers GREEN.
        """
        domains = self.get_domains()
        return {
            "source": "sddc-manager:GET /v1/domains",
            "domains": [{"id": d.get("id"), "name": d.get("name"), "status": d.get("status")} for d in domains],
        }

    def get_versions(self) -> Dict[str, Any]:
        """Observed component versions from SDDC Manager inventory (GET /v1/sddc-managers, /v1/vcenters)."""
        versions: Dict[str, Any] = {}
        managers = self._elements(self.request("GET", "/v1/sddc-managers").json())
        if managers:
            versions["sddc_manager"] = managers[0].get("version")
        vcenters = self._elements(self.request("GET", "/v1/vcenters").json())
        versions["vcenters"] = {vc.get("fqdn") or vc.get("id"): vc.get("version") for vc in vcenters}
        return versions

    def get_bundles(self) -> List[Dict[str, Any]]:
        resp = self.request("GET", "/v1/bundles")
        return self._elements(resp.json())

    async def reconcile_operation(
        self,
        intent: ExecutionIntent | Dict[str, Any],
    ) -> ReconciliationResult:
        """
        Reconciles SDDC Manager domain upgrade operations by querying domain status.
        Never blindly retries UNKNOWN.
        """
        target_res = intent.target_resource if isinstance(intent, ExecutionIntent) else intent.get("target_resource", "")
        op_id = intent.operation_id if isinstance(intent, ExecutionIntent) else intent.get("operation_id", "")
        desired = intent.desired_state if isinstance(intent, ExecutionIntent) else intent.get("desired_state", {})

        if op_id in ("upgrade_domain", "vcf_upgrade_domain"):
            native_task_id = desired.get("native_task_id") if isinstance(desired, dict) else None
            if native_task_id:
                try:
                    task = self.get_task(native_task_id)
                except Exception as ex:
                    return ReconciliationResult(status=ReconciliationStatus.UNKNOWN, details={"error": str(ex)})
                status = task.get("status")
                if status in ("SUCCESSFUL", "COMPLETED_WITH_WARNING"):
                    return ReconciliationResult(status=ReconciliationStatus.APPLIED, details={"task_id": native_task_id, "status": status})
                if status in ("FAILED", "CANCELLED", "TIMED_OUT", "SKIPPED"):
                    return ReconciliationResult(status=ReconciliationStatus.NOT_APPLIED, details={"task_id": native_task_id, "status": status})
                if status in ("PENDING", "IN_PROGRESS", "QUEUED"):
                    return ReconciliationResult(status=ReconciliationStatus.IN_PROGRESS, details={"task_id": native_task_id, "status": status})
                return ReconciliationResult(status=ReconciliationStatus.UNKNOWN, details={"task_id": native_task_id, "status": status})
            try:
                domain = self.get_domain(target_res)
                if not domain:
                    return ReconciliationResult(
                        status=ReconciliationStatus.UNKNOWN,
                        details={"error": f"Domain '{target_res}' not found during reconciliation."},
                    )
                target_ver = desired.get("target_version")
                actual_ver = domain.get("vcf_version", domain.get("version"))
                if target_ver and actual_ver == target_ver:
                    return ReconciliationResult(
                        status=ReconciliationStatus.APPLIED,
                        details={"domain_id": target_res, "version": actual_ver},
                        observed_revision=ResourceRevision("sddc-manager", f"rev-domain-{target_res}-{actual_ver}"),
                    )
                task_status = domain.get("status")
                if task_status == "UPGRADING":
                    return ReconciliationResult(
                        status=ReconciliationStatus.IN_PROGRESS,
                        details={"domain_id": target_res, "status": "UPGRADING"},
                    )
                return ReconciliationResult(
                    status=ReconciliationStatus.NOT_APPLIED,
                    details={"domain_id": target_res, "actual_version": actual_ver, "expected_version": target_ver},
                )
            except Exception as ex:
                return ReconciliationResult(
                    status=ReconciliationStatus.UNKNOWN,
                    details={"error": str(ex)},
                )

        return ReconciliationResult(
            status=ReconciliationStatus.UNKNOWN,
            details={"reason": f"No SDDC Manager reconciliation handler for operation '{op_id}'."},
        )
