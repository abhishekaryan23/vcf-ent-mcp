# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
vCenter REST API Provider.
Provides inventory, power lifecycle, VM reconfiguration, snapshot creation, and cluster management.
"""

from __future__ import annotations
from typing import Dict, Any, List, Optional
from vcf_enterprise_mcp.adapter.providers.base import BaseVCFProvider
from vcf_enterprise_mcp.adapter.transport.errors import (
    TransportException,
    UpstreamPreconditionException,
    UpstreamResourceNotFoundException,
)
from vcf_enterprise_mcp.adapter.models import (
    ResourceRevision,
    ReconciliationStatus,
    ReconciliationResult,
    ExecutionIntent,
)


class VCenterProvider(BaseVCFProvider):
    """Integrates with VMware vCenter REST APIs (/api/vcenter/*)."""

    def get_vms(self, cluster_id: Optional[str] = None) -> List[Dict[str, Any]]:
        params = {"clusters": cluster_id} if cluster_id else None
        resp = self.request("GET", "/api/vcenter/vm", params=params)
        data = resp.json()
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return data.get("value", data.get("vms", []))
        return []

    def resolve_vm_identifier(self, vm_id_or_name: str) -> str:
        """Resolves a human-friendly VM name to its vSphere MOID (e.g. 'vm-101') when needed."""
        if not vm_id_or_name or vm_id_or_name.startswith("vm-"):
            return vm_id_or_name
        try:
            resp = self.request("GET", "/api/vcenter/vm", params={"names": vm_id_or_name})
            if resp and resp.is_success:
                items = self._unwrap(resp.json())
                if isinstance(items, list) and len(items) == 1 and isinstance(items[0], dict):
                    found = items[0].get("vm") or items[0].get("vm_id") or items[0].get("id")
                    if found:
                        return str(found)
        except Exception:
            pass
        return vm_id_or_name

    def get_vm(self, vm_id: str) -> Optional[Dict[str, Any]]:
        resolved_id = self.resolve_vm_identifier(vm_id)
        resp = self.request("GET", f"/api/vcenter/vm/{resolved_id}")
        data = resp.json()
        if isinstance(data, dict):
            val = data.get("value", data)
            if isinstance(val, dict):
                val.setdefault("vm_id", resolved_id)
                val.setdefault("id", resolved_id)
            return val
        return None

    def get_datastores(self) -> List[Dict[str, Any]]:
        """Lists vSphere datastores via GET /api/vcenter/datastore."""
        resp = self.request("GET", "/api/vcenter/datastore")
        data = resp.json()
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return data.get("value", data.get("datastores", []))
        return []

    # vCenter power actions (POST /api/vcenter/vm/{vm}/power?action=...).
    POWER_ACTIONS = {"start": "start", "stop": "stop", "reset": "reset", "restart": "reset", "suspend": "suspend"}

    @staticmethod
    def _unwrap(data: Any) -> Any:
        if isinstance(data, dict) and set(data.keys()) == {"value"}:
            return data["value"]
        return data

    def _get_json(self, path: str) -> Any:
        try:
            resp = self.request("GET", path)
        except UpstreamResourceNotFoundException:
            raise
        except TransportException:
            return None
        return self._unwrap(resp.json()) if resp.is_success else None

    def get_power_state(self, vm_id: str) -> Optional[str]:
        """Observed power state from GET /api/vcenter/vm/{vm}/power (Power.Info.state)."""
        info = self._get_json(f"/api/vcenter/vm/{vm_id}/power")
        if isinstance(info, dict):
            state = info.get("state") or info.get("power_state")
            if state in ("POWERED_ON", "POWERED_OFF", "SUSPENDED"):
                return state
        vm = self.get_vm(vm_id)
        state = vm.get("power_state") if isinstance(vm, dict) else None
        return state if state in ("POWERED_ON", "POWERED_OFF", "SUSPENDED") else None

    def power_vm(self, vm_id: str, action: str) -> Dict[str, Any]:
        """Powers a VM via the official action query operation, then reports the observed state."""
        vcenter_action = self.POWER_ACTIONS.get(action)
        if vcenter_action is None:
            raise UpstreamPreconditionException("power_vm", f"Unsupported power action '{action}'. Allowed: {sorted(self.POWER_ACTIONS)}")
        resp = self.request("POST", f"/api/vcenter/vm/{vm_id}/power", params={"action": vcenter_action})
        observed = self.get_power_state(vm_id) if resp.is_success else None
        return {
            "vm_id": vm_id,
            "action": action,
            "status": "SUCCESS" if resp.is_success else "FAILED",
            # Observed from vCenter after the call; never assumed from the request.
            "new_power_state": observed,
        }

    def resize_vm(
        self,
        vm_id: str,
        memory_gb: Optional[int] = None,
        cpu_cores: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Reconfigures vCPU count and memory via PATCH /hardware/cpu and /hardware/memory.

        Enforces the documented vSphere constraints before dispatch: a powered-on VM can only
        grow CPU/memory when hot-add is enabled, memory must respect the hot-add increment and
        limit, and CPU can only shrink while running when hot-remove is enabled.
        """
        power_state = self.get_power_state(vm_id)
        if power_state is None:
            raise UpstreamPreconditionException("resize_vm", f"Could not observe the power state of VM '{vm_id}'; refusing to reconfigure blind.")
        running = power_state != "POWERED_OFF"

        if cpu_cores is not None and running:
            cpu = self._get_json(f"/api/vcenter/vm/{vm_id}/hardware/cpu") or {}
            current = cpu.get("count")
            if not isinstance(current, int):
                raise UpstreamPreconditionException("resize_vm", "Could not read current vCPU configuration of the running VM.")
            if cpu_cores > current and not cpu.get("hot_add_enabled"):
                raise UpstreamPreconditionException("resize_vm", "VM is powered on and CPU hot-add is disabled; power it off first.")
            if cpu_cores < current and not cpu.get("hot_remove_enabled"):
                raise UpstreamPreconditionException("resize_vm", "VM is powered on and CPU hot-remove is disabled; power it off first.")

        if memory_gb is not None and running:
            mem = self._get_json(f"/api/vcenter/vm/{vm_id}/hardware/memory") or {}
            current_mib = mem.get("size_mib", mem.get("size_MiB"))
            target_mib = memory_gb * 1024
            if not isinstance(current_mib, int):
                raise UpstreamPreconditionException("resize_vm", "Could not read current memory configuration of the running VM.")
            if target_mib < current_mib:
                raise UpstreamPreconditionException("resize_vm", "Memory cannot be reduced while the VM is powered on.")
            if target_mib > current_mib:
                if not mem.get("hot_add_enabled"):
                    raise UpstreamPreconditionException("resize_vm", "VM is powered on and memory hot-add is disabled; power it off first.")
                limit = mem.get("hot_add_limit_mib", mem.get("hot_add_limit_MiB"))
                step = mem.get("hot_add_increment_size_mib", mem.get("hot_add_increment_size_MiB"))
                if isinstance(limit, int) and target_mib > limit:
                    raise UpstreamPreconditionException("resize_vm", f"Requested {target_mib} MiB exceeds the hot-add limit of {limit} MiB.")
                if isinstance(step, int) and step > 0 and (target_mib - current_mib) % step:
                    raise UpstreamPreconditionException("resize_vm", f"Memory increase must be a multiple of {step} MiB while powered on.")

        success = True
        if cpu_cores is not None:
            cpu_resp = self.request("PATCH", f"/api/vcenter/vm/{vm_id}/hardware/cpu", json_body={"count": cpu_cores})
            success = success and cpu_resp.is_success
        if memory_gb is not None:
            # VCF 9.x Vcenter.Vm.Hardware.Memory.UpdateSpec uses 'size_mib' (8.0.3 used 'size_MiB').
            mem_resp = self.request("PATCH", f"/api/vcenter/vm/{vm_id}/hardware/memory", json_body={"size_mib": memory_gb * 1024})
            success = success and mem_resp.is_success

        return {
            "vm_id": vm_id,
            "power_state_at_change": power_state,
            "allocated_memory_gb": memory_gb,
            "allocated_cpu_cores": cpu_cores,
            "status": "SUCCESS" if success else "FAILED",
        }

    def vi_json_release(self) -> str:
        """VI/JSON path release segment, e.g. API 9.1.1 -> '9.1.0.0'. Must match the vCenter's
        advertised VI/JSON release; verify against GET /sdk/vim25/release before enabling writes."""
        parts = (self.api_version.split(".") + ["0", "0"])[:2]
        return f"{parts[0]}.{parts[1]}.0.0"

    def create_snapshot(self, vm_id: str, snapshot_name: str, memory: bool = False, quiesce: bool = False) -> Dict[str, Any]:
        """Creates a VM snapshot through the VI/JSON API.

        The vSphere Automation REST API (/api/vcenter) has no VM snapshot operation in the
        9.0/9.1 specifications; the documented operation is
        POST /sdk/vim25/{release}/VirtualMachine/{moId}/CreateSnapshot_Task, which returns a Task
        managed-object reference. Authentication uses the vmware-api-session-id header.
        """
        body = {"name": snapshot_name, "description": "Snapshot taken by VCF MCP Control Plane", "memory": memory, "quiesce": quiesce}
        resp = self.request("POST", f"/sdk/vim25/{self.vi_json_release()}/VirtualMachine/{vm_id}/CreateSnapshot_Task", json_body=body)
        task = resp.json() if resp.is_success else None
        task_id = task.get("value") if isinstance(task, dict) else None
        return {
            "vm_id": vm_id,
            "snapshot_name": snapshot_name,
            # vCenter task moref; the snapshot moref is only known once the task completes.
            "native_task_id": task_id,
            "status": "SUBMITTED" if resp.is_success and task_id else "FAILED",
        }

    def get_hosts(self, cluster_id: Optional[str] = None) -> List[Dict[str, Any]]:
        params = {"clusters": cluster_id} if cluster_id else None
        resp = self.request("GET", "/api/vcenter/host", params=params)
        data = resp.json()
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return data.get("value", data.get("hosts", []))
        return []

    def get_clusters(self, domain_id: Optional[str] = None) -> List[Dict[str, Any]]:
        resp = self.request("GET", "/api/vcenter/cluster")
        data = resp.json()
        clusters = data if isinstance(data, list) else data.get("value", data.get("clusters", []))
        if domain_id:
            return [c for c in clusters if c.get("domain") == domain_id]
        return clusters

    async def reconcile_operation(
        self,
        intent: ExecutionIntent | Dict[str, Any],
    ) -> ReconciliationResult:
        """
        Reconciles vCenter operations by querying VM state.
        Never blindly retries UNKNOWN.
        """
        target_res = intent.target_resource if isinstance(intent, ExecutionIntent) else intent.get("target_resource", "")
        op_id = intent.operation_id if isinstance(intent, ExecutionIntent) else intent.get("operation_id", "")
        desired = intent.desired_state if isinstance(intent, ExecutionIntent) else intent.get("desired_state", {})

        if op_id in ("resize_vm", "reconfigure_vm", "power_vm"):
            try:
                vm = self.get_vm(target_res)
                if not vm:
                    return ReconciliationResult(
                        status=ReconciliationStatus.UNKNOWN,
                        details={"error": f"VM '{target_res}' not found during reconciliation."},
                    )
                if "memory_gb" in desired:
                    mem = vm.get("memory") if isinstance(vm.get("memory"), dict) else {}
                    actual_mib = mem.get("size_mib", mem.get("size_MiB", vm.get("memory_size_mib", vm.get("memory_size_MiB", 0))))
                    actual_mem = (actual_mib or 0) // 1024
                    if actual_mem == desired["memory_gb"]:
                        return ReconciliationResult(
                            status=ReconciliationStatus.APPLIED,
                            details={"vm_id": target_res, "memory_gb": actual_mem},
                            observed_revision=ResourceRevision("vcenter", f"rev-vm-{target_res}-{actual_mem}"),
                        )
                    else:
                        return ReconciliationResult(
                            status=ReconciliationStatus.NOT_APPLIED,
                            details={"vm_id": target_res, "actual_memory_gb": actual_mem, "expected": desired["memory_gb"]},
                        )
                if "power_state" in desired:
                    actual_power = vm.get("power_state")
                    if actual_power == desired["power_state"]:
                        return ReconciliationResult(
                            status=ReconciliationStatus.APPLIED,
                            details={"vm_id": target_res, "power_state": actual_power},
                        )
                    else:
                        return ReconciliationResult(
                            status=ReconciliationStatus.NOT_APPLIED,
                            details={"vm_id": target_res, "actual_power_state": actual_power},
                        )
            except Exception as ex:
                return ReconciliationResult(
                    status=ReconciliationStatus.UNKNOWN,
                    details={"error": str(ex)},
                )

        return ReconciliationResult(
            status=ReconciliationStatus.UNKNOWN,
            details={"reason": f"No vCenter reconciliation handler for operation '{op_id}'."},
        )
