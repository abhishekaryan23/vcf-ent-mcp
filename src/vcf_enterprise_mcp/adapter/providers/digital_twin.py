# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Digital Twin Provider.
Communicates with the local or testbed VCF Digital Twin mock server gateway
(e.g., http://127.0.0.1:9080 or http://127.0.0.1:9090).
"""

from __future__ import annotations
from typing import Dict, Any, List, Optional
from vcf_enterprise_mcp.adapter.providers.base import BaseVCFProvider
from vcf_enterprise_mcp.adapter.models import (
    ResourceRevision,
    ReconciliationStatus,
    ReconciliationResult,
    ExecutionIntent,
)


class DigitalTwinProvider(BaseVCFProvider):
    """Integrates with the VMware Cloud Foundation Digital Twin gateway."""

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
        return data if isinstance(data, dict) else None

    def get_clusters(self, domain_id: Optional[str] = None) -> List[Dict[str, Any]]:
        resp = self.request("GET", "/api/vcenter/cluster")
        data = resp.json()
        clusters = data if isinstance(data, list) else data.get("value", data.get("clusters", []))
        if domain_id:
            return [c for c in clusters if c.get("domain") == domain_id]
        return clusters

    def get_hosts(self, cluster_id: Optional[str] = None) -> List[Dict[str, Any]]:
        params = {"clusters": cluster_id} if cluster_id else None
        resp = self.request("GET", "/api/vcenter/host", params=params)
        data = resp.json()
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return data.get("value", data.get("hosts", []))
        return []

    def get_vms(self, cluster_id: Optional[str] = None) -> List[Dict[str, Any]]:
        params = {"clusters": cluster_id} if cluster_id else None
        resp = self.request("GET", "/api/vcenter/vm", params=params)
        data = resp.json()
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return data.get("value", data.get("vms", []))
        return []

    def get_vm(self, vm_id: str) -> Optional[Dict[str, Any]]:
        resp = self.request("GET", f"/api/vcenter/vm/{vm_id}")
        data = resp.json()
        return data if isinstance(data, dict) else None

    def power_vm(self, vm_id: str, action: str) -> Dict[str, Any]:
        resp = self.request("POST", f"/api/vcenter/vm/{vm_id}/power", params={"action": "reset" if action == "restart" else action})
        return {
            "vm_id": vm_id,
            "action": action,
            "status": "SUCCESS" if resp.is_success else "FAILED",
            "new_power_state": "POWERED_ON" if action in ("start", "reset", "restart") else ("SUSPENDED" if action == "suspend" else "POWERED_OFF"),
        }

    def resize_vm(self, vm_id: str, memory_gb: Optional[int] = None, cpu_cores: Optional[int] = None) -> Dict[str, Any]:
        if cpu_cores is not None:
            self.request("PATCH", f"/api/vcenter/vm/{vm_id}/hardware/cpu", json_body={"count": cpu_cores})
        if memory_gb is not None:
            self.request("PATCH", f"/api/vcenter/vm/{vm_id}/hardware/memory", json_body={"size_MiB": memory_gb * 1024})
        actual = self.get_vm(vm_id)
        matches = (memory_gb is None or actual.get("memory_size_MiB") == memory_gb * 1024) and (cpu_cores is None or actual.get("cpu_count") == cpu_cores)
        return {
            "vm_id": vm_id,
            "allocated_memory_gb": actual.get("memory_size_MiB", 0) / 1024,
            "allocated_cpu_cores": actual.get("cpu_count"),
            "status": "SUCCESS" if matches else "FAILED",
        }

    def create_snapshot(self, vm_id: str, snapshot_name: str) -> Dict[str, Any]:
        resp = self.request("POST", f"/api/vcenter/vm/{vm_id}/snapshots", json_body={"name": snapshot_name})
        return {
            "vm_id": vm_id,
            "snapshot_id": f"snap-{vm_id}-{snapshot_name}",
            "snapshot_name": snapshot_name,
            "status": "SUCCESS" if resp.is_success else "FAILED",
        }

    def create_segment(self, segment_name: str, gateway_id: str, cidr: str) -> Dict[str, Any]:
        resp = self.request("PUT", f"/policy/api/v1/infra/segments/{segment_name}", json_body={"gateway": gateway_id, "cidr": cidr})
        return {
            "segment_id": f"seg-{segment_name}",
            "segment_name": segment_name,
            "gateway": gateway_id,
            "cidr": cidr,
            "status": "SUCCESS" if resp.is_success else "FAILED",
        }

    def upgrade_domain(self, domain_id: str, target_version: str) -> Dict[str, Any]:
        resp = self.request("POST", "/v1/upgrades", json_body={"domainId": domain_id, "targetVersion": target_version})
        return {
            "domain_id": domain_id,
            "target_version": target_version,
            "task_id": f"vcf-lcm-task-{domain_id}-911",
            "status": "RUNNING" if resp.is_success else "FAILED",
        }

    def get_health(self) -> Dict[str, Any]:
        resp = self.request("GET", "/v1/system/health")
        data = resp.json()
        return data if isinstance(data, dict) else {"status": "HEALTHY"}

    def query_telemetry(self, entity_id: str, metrics: Optional[List[str]] = None) -> Dict[str, Any]:
        # The Twin exposes the batch stats route, distinct from native Operations.
        resp = self.request("GET", "/suite-api/api/resources/stats", params={"resourceId": entity_id, "statKey": metrics or []})
        data = resp.json()
        if not isinstance(data, dict) or not isinstance(data.get("resourceStats"), list):
            raise ValueError("Twin returned an invalid telemetry response")
        return {"entity_id": entity_id, "data_points": data["resourceStats"], "synthetic": True}

    async def reconcile_operation(
        self,
        intent: ExecutionIntent | Dict[str, Any],
    ) -> ReconciliationResult:
        """
        Reconciles Digital Twin operations. Never blindly retries UNKNOWN.
        """
        target_res = intent.target_resource if isinstance(intent, ExecutionIntent) else intent.get("target_resource", "")
        op_id = intent.operation_id if isinstance(intent, ExecutionIntent) else intent.get("operation_id", "")
        desired = intent.desired_state if isinstance(intent, ExecutionIntent) else intent.get("desired_state", {})

        try:
            if "vm" in op_id or target_res.startswith("vm-"):
                vm = self.get_vm(target_res)
                if vm and isinstance(vm, dict):
                    if "memory_gb" in desired:
                        mem = vm.get("memory_gb", vm.get("allocated_memory_gb"))
                        if mem == desired["memory_gb"]:
                            return ReconciliationResult(
                                status=ReconciliationStatus.APPLIED,
                                details={"vm_id": target_res, "memory_gb": mem},
                                observed_revision=ResourceRevision("digital_twin", f"rev-{target_res}-{mem}"),
                            )
                        return ReconciliationResult(
                            status=ReconciliationStatus.NOT_APPLIED,
                            details={"vm_id": target_res, "actual_memory_gb": mem, "expected": desired["memory_gb"]},
                        )
            elif "domain" in op_id or target_res.startswith("mgmt-domain") or "domain" in target_res:
                domain = self.get_domain(target_res)
                if domain and isinstance(domain, dict):
                    ver = domain.get("version", domain.get("vcf_version"))
                    if "target_version" in desired and ver == desired["target_version"]:
                        return ReconciliationResult(
                            status=ReconciliationStatus.APPLIED,
                            details={"domain_id": target_res, "version": ver},
                            observed_revision=ResourceRevision("digital_twin", f"rev-{target_res}-{ver}"),
                        )
                    return ReconciliationResult(
                        status=ReconciliationStatus.NOT_APPLIED,
                        details={"domain_id": target_res, "actual_version": ver, "expected": desired.get("target_version")},
                    )
        except Exception as ex:
            return ReconciliationResult(
                status=ReconciliationStatus.UNKNOWN,
                details={"error": str(ex)},
            )

        return ReconciliationResult(
            status=ReconciliationStatus.UNKNOWN,
            details={"message": f"Indeterminate state in Digital Twin for operation '{op_id}' on '{target_res}'."},
        )
