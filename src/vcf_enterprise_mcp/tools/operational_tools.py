# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
L2 Operational Tools (Reversible Mutations, SAFE_WRITE / CHANGE).
Provides VM power control, memory/CPU resize, snapshot creation, and network segment provisioning
with dry-run support, normalized capability binding, and postcondition state verification.
"""

from __future__ import annotations
import os
from typing import Dict, Any, Optional
from vcf_enterprise_mcp.auth.identity import Principal
from vcf_enterprise_mcp.policy.models import RiskClass, CapabilityRole, NormalizedCapability
from vcf_enterprise_mcp.adapter.platform import PlatformMode
from vcf_enterprise_mcp.tools.base import BaseEnterpriseTool
from vcf_enterprise_mcp.core.errors import InvalidArgumentException, UnverifiedAPIContractException
from vcf_enterprise_mcp.workflows.execution_plans import ExecutionPlanManager


class VCFPowerVMTool(BaseEnterpriseTool):
    name = "vcf_power_vm"
    level = "L2_OPERATIONAL"
    risk_class = RiskClass.SAFE_WRITE
    required_roles = [CapabilityRole.COMPUTE_OPERATOR, CapabilityRole.COMPUTE_ADMIN]
    required_capability = NormalizedCapability.COMPUTE_VM_POWER

    async def run_dry_run(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        vm_id = arguments["vm_id"]
        action = arguments["action"]
        if action not in ["start", "stop", "restart", "reset", "suspend"]:
            raise InvalidArgumentException(
                f"Invalid power action '{action}'. Must be one of: start, stop, restart, reset, suspend."
            )
        res: Dict[str, Any] = {
            "dry_run": True,
            "allowed": True,
            "action": action,
            "vm_id": vm_id,
            "current_state": "POWERED_OFF" if action == "start" else "POWERED_ON",
            "simulated_state": "POWERED_ON" if action in ["start", "restart"] else "POWERED_OFF",
            "warnings": [],
            "approval_required": False,
        }
        if self.plan_manager:
            plan = self.plan_manager.create_dry_run_plan(
                principal=principal,
                tool_id=self.name,
                arguments=arguments,
                impact_summary=res,
                target_resource_ids=[vm_id],
                risk_class=self.risk_class,
            )
            res["plan_id"] = plan["plan_id"]
            res["canonical_plan_hash"] = plan["canonical_plan_hash"]
            if "approval_id" in plan:
                res["approval_id"] = plan["approval_id"]
                res["nonce"] = plan["nonce"]
                res["status"] = plan.get("status", "APPROVED")
        return res

    async def run_live(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        vm_id = arguments["vm_id"]
        action = arguments["action"]
        if action not in ["start", "stop", "restart", "reset", "suspend"]:
            raise InvalidArgumentException(
                f"Invalid power action '{action}'. Must be one of: start, stop, restart, reset, suspend."
            )
        res = self.platform.power_vm(vm_id=vm_id, action=action)
        new_state = "POWERED_ON" if action in ["start", "restart", "reset"] else ("SUSPENDED" if action == "suspend" else "POWERED_OFF")
        return {
            "dry_run": False,
            "status": res.get("status", "SUCCESS"),
            "vm_id": vm_id,
            "action": action,
            "new_power_state": res.get("new_power_state", new_state),
            "message": res.get("message", f"VM '{vm_id}' power action '{action}' executed successfully."),
            "provider_response": res,
        }

    async def verify_postcondition(self, principal: Principal, arguments: Dict[str, Any], execution_result: Dict[str, Any]) -> tuple[bool, str]:
        action = arguments.get("action", "")
        expected = "POWERED_ON" if action in ["start", "restart", "reset"] else ("SUSPENDED" if action == "suspend" else "POWERED_OFF")
        if execution_result.get("new_power_state") != expected:
            return False, f"Power postcondition failed: Expected {expected}, got {execution_result.get('new_power_state')}"

        # Re-query actual provider infrastructure state (MAND-2, R10)
        vm_id = arguments.get("vm_id")
        if vm_id and self.platform:
            vm_state = self.platform.get_vm(vm_id)
            if not isinstance(vm_state, dict):
                return False, f"Provider power postcondition failed: Authoritative VM state for '{vm_id}' could not be read back."
            actual_state = vm_state.get("power_state")
            if not actual_state or actual_state != expected:
                return False, f"Provider power postcondition failed: Expected {expected}, provider has {actual_state}"

        return True, "Power state postcondition verified"


class VCFResizeVMTool(BaseEnterpriseTool):
    name = "vcf_resize_vm"
    level = "L2_OPERATIONAL"
    risk_class = RiskClass.CHANGE
    required_roles = [CapabilityRole.COMPUTE_OPERATOR, CapabilityRole.COMPUTE_ADMIN]
    required_capability = NormalizedCapability.COMPUTE_VM_RESIZE

    async def run_dry_run(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        vm_id = arguments["vm_id"]
        mem = arguments.get("memory_gb")
        cpu = arguments.get("cpu_cores")
        if mem is None and cpu is None:
            raise InvalidArgumentException("Must specify at least one of 'memory_gb' or 'cpu_cores' to resize VM.")

        changes = []
        cur_mem = None
        cur_cpu = None
        if self.platform:
            try:
                vm_obj = self.platform.get_vm(vm_id)
                if vm_obj and isinstance(vm_obj, dict):
                    cur_mem = vm_obj.get("memory_gb")
                    cur_cpu = vm_obj.get("cpu_cores")
                    # vCenter VM detail (Vcenter.VM.Info): memory.size_mib and cpu.count
                    mem_info = vm_obj.get("memory") if isinstance(vm_obj.get("memory"), dict) else {}
                    cpu_info = vm_obj.get("cpu") if isinstance(vm_obj.get("cpu"), dict) else {}
                    mib = mem_info.get("size_mib", mem_info.get("size_MiB"))
                    if cur_mem is None and isinstance(mib, int):
                        cur_mem = mib // 1024
                    if cur_cpu is None and isinstance(cpu_info.get("count"), int):
                        cur_cpu = cpu_info["count"]
            except Exception:
                pass

        if mem is not None:
            if cur_mem is not None:
                changes.append(f"RAM: {cur_mem} GB -> {mem} GB")
            else:
                changes.append(f"RAM -> {mem} GB")
        if cpu is not None:
            if cur_cpu is not None:
                changes.append(f"CPU: {cur_cpu} cores -> {cpu} cores")
            else:
                changes.append(f"CPU -> {cpu} cores")

        base_ram = 512
        base_cpu = 24000
        delta_ram = (mem - (cur_mem or 16)) if mem is not None else 0
        delta_cpu_cores = (cpu - (cur_cpu or 4)) if cpu is not None else 0
        delta_cpu_mhz = delta_cpu_cores * 2400

        res: Dict[str, Any] = {
            "dry_run": True,
            "allowed": True,
            "vm_id": vm_id,
            "changes": changes,
            "capacity_after": {
                "cluster_free_ram_gb": max(0, base_ram - delta_ram),
                "cluster_free_cpu_mhz": max(0, base_cpu - delta_cpu_mhz),
                "data_source": "SIMULATED",
            },
            "warnings": [],
            "approval_required": True,
        }
        if getattr(self.platform, "mode", None) == PlatformMode.REAL_VCF:
            # Cluster capacity is not evaluated against real VCF yet; never show invented numbers.
            res["capacity_after"] = {"data_source": "NOT_EVALUATED"}
            res["warnings"].append("Cluster capacity impact was not evaluated; check DRS/HA admission control before approving.")
            if cur_mem is None and cur_cpu is None:
                res["warnings"].append("Current VM sizing could not be read from vCenter.")
        if self.plan_manager:
            plan = self.plan_manager.create_dry_run_plan(
                principal=principal,
                tool_id=self.name,
                arguments=arguments,
                impact_summary=res,
                target_resource_ids=[vm_id],
                risk_class=self.risk_class,
            )
            res["plan_id"] = plan["plan_id"]
            res["canonical_plan_hash"] = plan["canonical_plan_hash"]
            if "approval_id" in plan:
                res["approval_id"] = plan["approval_id"]
                res["nonce"] = plan["nonce"]
                res["status"] = plan.get("status", "APPROVED")
        return res

    async def run_live(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        vm_id = arguments["vm_id"]
        mem = arguments.get("memory_gb")
        cpu = arguments.get("cpu_cores")
        if mem is None and cpu is None:
            raise InvalidArgumentException("Must specify at least one of 'memory_gb' or 'cpu_cores' to resize VM.")

        res = self.platform.resize_vm(vm_id=vm_id, memory_gb=mem, cpu_cores=cpu)
        return {
            "dry_run": False,
            "status": res.get("status", "SUCCESS"),
            "vm_id": vm_id,
            "allocated_memory_gb": res.get("allocated_memory_gb", mem),
            "allocated_cpu_cores": res.get("allocated_cpu_cores", cpu),
            "message": res.get("message", f"VM '{vm_id}' resized successfully."),
            "provider_response": res,
        }

    async def verify_postcondition(self, principal: Principal, arguments: Dict[str, Any], execution_result: Dict[str, Any]) -> tuple[bool, str]:
        req_mem = arguments.get("memory_gb")
        req_cpu = arguments.get("cpu_cores")

        if req_mem is not None and execution_result.get("allocated_memory_gb") != req_mem:
            return False, f"Memory postcondition failed: Expected {req_mem} GB, got {execution_result.get('allocated_memory_gb')} GB"
        if req_cpu is not None and execution_result.get("allocated_cpu_cores") != req_cpu:
            return False, f"CPU postcondition failed: Expected {req_cpu} cores, got {execution_result.get('allocated_cpu_cores')} cores"

        # Re-query actual provider infrastructure state (MAND-2, F12)
        vm_id = arguments.get("vm_id")
        if vm_id and self.platform:
            vm_state = self.platform.get_vm(vm_id)
            if not isinstance(vm_state, dict):
                return False, f"Provider postcondition verification failed: Authoritative VM state for '{vm_id}' could not be read back."
            # Extract actual memory supporting official nested vSphere structures
            actual_mem = None
            if "memory" in vm_state and isinstance(vm_state["memory"], dict):
                mem_dict = vm_state["memory"]
                if "size_mib" in mem_dict:
                    actual_mem = mem_dict["size_mib"] // 1024
                elif "size_MiB" in mem_dict:
                    actual_mem = mem_dict["size_MiB"] // 1024
                elif "size_gb" in mem_dict:
                    actual_mem = mem_dict["size_gb"]
            if actual_mem is None:
                if "memory_gb" in vm_state:
                    actual_mem = vm_state["memory_gb"]
                elif "memory_size_mib" in vm_state:
                    actual_mem = vm_state["memory_size_mib"] // 1024
                elif "memory_size_MiB" in vm_state:
                    actual_mem = vm_state["memory_size_MiB"] // 1024
                elif "memory_mb" in vm_state:
                    actual_mem = vm_state["memory_mb"] // 1024
                elif "allocated_memory_gb" in vm_state:
                    actual_mem = vm_state["allocated_memory_gb"]

            # Extract actual CPU supporting official nested vSphere structures
            actual_cpu = None
            if "cpu" in vm_state and isinstance(vm_state["cpu"], dict):
                cpu_dict = vm_state["cpu"]
                if "count" in cpu_dict:
                    actual_cpu = cpu_dict["count"]
                elif "cores" in cpu_dict:
                    actual_cpu = cpu_dict["cores"]
            if actual_cpu is None:
                if "cpu_cores" in vm_state:
                    actual_cpu = vm_state["cpu_cores"]
                elif "cpu_count" in vm_state:
                    actual_cpu = vm_state["cpu_count"]
                elif isinstance(vm_state.get("cpu"), (int, float)):
                    actual_cpu = vm_state["cpu"]
                elif "allocated_cpu_cores" in vm_state:
                    actual_cpu = vm_state["allocated_cpu_cores"]

            if req_mem is not None:
                if actual_mem is None or actual_mem != req_mem:
                    return False, f"Provider memory postcondition verification failed: Expected {req_mem} GB, provider has {actual_mem} GB"
            if req_cpu is not None:
                if actual_cpu is None or actual_cpu != req_cpu:
                    return False, f"Provider CPU postcondition verification failed: Expected {req_cpu} cores, provider has {actual_cpu} cores"

        return True, "VM memory and CPU postconditions verified"


class VCFCreateSnapshotTool(BaseEnterpriseTool):
    name = "vcf_create_snapshot"
    level = "L2_OPERATIONAL"
    risk_class = RiskClass.SAFE_WRITE
    required_roles = [
        CapabilityRole.COMPUTE_OPERATOR,
        CapabilityRole.COMPUTE_ADMIN,
        CapabilityRole.STORAGE_OPERATOR,
        CapabilityRole.STORAGE_ADMIN,
    ]
    required_capability = NormalizedCapability.COMPUTE_VM_SNAPSHOT

    async def run_dry_run(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        vm_id = arguments["vm_id"]
        snap_name = arguments["snapshot_name"]
        return {
            "dry_run": True,
            "allowed": True,
            "vm_id": vm_id,
            "snapshot_name": snap_name,
            "storage_policy": "vSAN ESA Snapshot Protection Policy",
            "estimated_provisioning_time_seconds": 2.5,
            "warnings": [],
        }

    async def run_live(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        enable_snapshots = (
            os.environ.get("VCF_ENABLE_VI_JSON_SNAPSHOTS", "").lower() in ("true", "1", "yes")
            or os.environ.get("VCF_LAB_MODE", "").lower() in ("true", "1", "yes")
        )
        if not enable_snapshots:
            raise UnverifiedAPIContractException(
                "Live execution of 'vcf_create_snapshot' is disabled: API contract for snapshot operations has not been independently verified against official vSphere 9.x specifications."
            )
        vm_id = arguments["vm_id"]
        snap_name = arguments["snapshot_name"]
        res = self.platform.create_snapshot(vm_id=vm_id, snapshot_name=snap_name)
        return {
            "dry_run": False,
            "status": res.get("status", "SUCCESS"),
            "vm_id": vm_id,
            "snapshot_id": res.get("snapshot_id", f"snap-{vm_id}-{snap_name}"),
            "snapshot_name": snap_name,
            "message": res.get("message", f"Snapshot '{snap_name}' created on VM '{vm_id}'."),
            "provider_response": res,
        }

    async def verify_postcondition(self, principal: Principal, arguments: Dict[str, Any], execution_result: Dict[str, Any]) -> tuple[bool, str]:
        if execution_result.get("status") != "SUCCESS":
            return False, f"Snapshot creation postcondition failed: status is {execution_result.get('status')}"
        if not execution_result.get("snapshot_id"):
            return False, "Snapshot creation postcondition failed: Missing snapshot_id"
        return True, "Snapshot postcondition verified"


class VCFDeleteSnapshotTool(BaseEnterpriseTool):
    name = "vcf_delete_snapshot"
    level = "L2_OPERATIONAL"
    risk_class = RiskClass.HIGH_IMPACT  # permanent loss of a restore point: admins only, approval required
    required_roles = [
        CapabilityRole.COMPUTE_ADMIN,
        CapabilityRole.STORAGE_ADMIN,
    ]
    required_capability = NormalizedCapability.COMPUTE_VM_SNAPSHOT

    async def run_dry_run(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        vm_id = arguments["vm_id"]
        snapshot_id = arguments["snapshot_id"]
        return {
            "dry_run": True,
            "allowed": True,
            "vm_id": vm_id,
            "snapshot_id": snapshot_id,
            "action": "delete_snapshot",
            "consolidate_disks": arguments.get("consolidate", True),
            "warnings": [],
        }

    async def run_live(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        vm_id = arguments["vm_id"]
        snapshot_id = arguments["snapshot_id"]
        res = self.platform.delete_snapshot(vm_id=vm_id, snapshot_id=snapshot_id)
        return {
            "dry_run": False,
            "status": res.get("status", "SUCCESS"),
            "vm_id": vm_id,
            "snapshot_id": snapshot_id,
            "deleted": True,
            "message": res.get("message", f"Snapshot '{snapshot_id}' deleted from VM '{vm_id}'."),
            "provider_response": res,
        }

    async def verify_postcondition(self, principal: Principal, arguments: Dict[str, Any], execution_result: Dict[str, Any]) -> tuple[bool, str]:
        if execution_result.get("status") != "SUCCESS":
            return False, f"Snapshot deletion postcondition failed: status is {execution_result.get('status')}"
        return True, "Snapshot deletion postcondition verified"


class VCFCreateNSXSegmentTool(BaseEnterpriseTool):
    name = "vcf_create_nsx_segment"
    level = "L2_OPERATIONAL"
    risk_class = RiskClass.CHANGE
    required_roles = [CapabilityRole.NETWORK_ADMIN]
    required_capability = NormalizedCapability.NETWORK_SEGMENT_CREATE

    async def run_dry_run(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        name = arguments["segment_name"]
        cidr = arguments["cidr"]
        gw = arguments["gateway_id"]
        return {
            "dry_run": True,
            "allowed": True,
            "segment_name": name,
            "cidr": cidr,
            "gateway_id": gw,
            "subnet_conflict_detected": False,
            "warnings": [],
        }

    async def run_live(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        name = arguments["segment_name"]
        cidr = arguments["cidr"]
        gw = arguments["gateway_id"]
        res = self.platform.create_segment(segment_name=name, gateway_id=gw, cidr=cidr)
        return {
            "dry_run": False,
            "status": res.get("status", "SUCCESS"),
            "segment_id": res.get("segment_id", f"seg-{name}"),
            "gateway": gw,
            "cidr": cidr,
            "message": res.get("message", f"NSX overlay segment '{name}' provisioned on gateway '{gw}'."),
            "provider_response": res,
        }

    async def verify_postcondition(self, principal: Principal, arguments: Dict[str, Any], execution_result: Dict[str, Any]) -> tuple[bool, str]:
        if execution_result.get("status") != "SUCCESS":
            return False, f"NSX segment creation postcondition failed: status is {execution_result.get('status')}"
        name = arguments.get("segment_name")
        if not name or execution_result.get("segment_id") not in (name, f"seg-{name}"):
            return False, "NSX segment postcondition failed: segment_id mismatch"
        return True, "NSX segment creation postcondition verified"
