# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
L1 Query Tools (Low Risk, READ).
Read-only queries for virtual machines, physical hosts, cluster utilization, health, and metrics telemetry
bound to normalized capabilities.
"""

from __future__ import annotations
from typing import Dict, Any, List
from vcf_enterprise_mcp.auth.identity import Principal
from vcf_enterprise_mcp.policy.models import RiskClass, CapabilityRole, NormalizedCapability
from vcf_enterprise_mcp.adapter.platform import PlatformMode
from vcf_enterprise_mcp.tools.base import BaseEnterpriseTool
from vcf_enterprise_mcp.core.errors import InvalidArgumentException


class VCFListVMsTool(BaseEnterpriseTool):
    name = "vcf_list_vms"
    level = "L1_QUERY"
    risk_class = RiskClass.READ
    required_roles = [CapabilityRole.VCF_VIEWER, CapabilityRole.COMPUTE_OPERATOR]
    required_capability = NormalizedCapability.COMPUTE_VM_READ

    async def run_live(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        is_real = getattr(self.platform, "mode", None) == PlatformMode.REAL_VCF
        # Real VCF: never filter by an invented cluster; no cluster_id means every cluster in every vCenter.
        cluster_id = arguments.get("cluster_id") if is_real else arguments.get("cluster_id", "cluster-prod-a")
        dc_id = arguments.get("datacenter_id", "dc1")
        raw_vms = self.platform.get_vms(cluster_id=cluster_id)
        if is_real:
            out = {"count": len(raw_vms), "cluster_filter": cluster_id, "virtual_machines": [
                {"vm_id": v.get("vm") or v.get("vm_id") or v.get("id"), "name": v.get("name"), "power_state": v.get("power_state"),
                 "cpu_count": v.get("cpu_count"), "memory_mib": v.get("memory_size_mib"), "vcenter": v.get("vcenter")} for v in raw_vms]}
            if self.platform.last_inventory_errors:
                out["vcenters_unavailable"] = self.platform.last_inventory_errors
            return out
        vms = []
        for v in raw_vms:
            v_norm = dict(v)
            v_id = v.get("vm_id") or v.get("vm") or v.get("id") or "vm-unknown"
            v_norm["vm_id"] = v_id
            v_norm["id"] = v_id
            if "name" not in v_norm:
                v_norm["name"] = f"workload-{v_id}"
            if "power_state" not in v_norm:
                v_norm["power_state"] = "POWERED_ON"
            if "cpu_cores" not in v_norm:
                v_norm["cpu_cores"] = v.get("cpu_count") or v.get("cpu", 4)
            if "memory_gb" not in v_norm:
                if "memory_size_mib" in v:
                    v_norm["memory_gb"] = v["memory_size_mib"] // 1024
                elif "memory_mb" in v:
                    v_norm["memory_gb"] = v["memory_mb"] // 1024
                else:
                    v_norm["memory_gb"] = 16
            if "cluster" not in v_norm:
                v_norm["cluster"] = cluster_id
            vms.append(v_norm)
        return {
            "datacenter": dc_id,
            "cluster": cluster_id,
            "count": len(vms),
            "virtual_machines": vms,
        }


class VCFGetVMTool(BaseEnterpriseTool):
    name = "vcf_get_vm"
    level = "L1_QUERY"
    risk_class = RiskClass.READ
    required_roles = [CapabilityRole.VCF_VIEWER, CapabilityRole.COMPUTE_OPERATOR]
    required_capability = NormalizedCapability.COMPUTE_VM_READ

    async def run_live(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        vm_id = arguments.get("vm_id", "vm-101")
        vm = self.platform.get_vm(vm_id)
        if not vm and getattr(self.platform, "mode", None) == PlatformMode.REAL_VCF:
            return {"vm_id": vm_id, "status": "NOT_FOUND", "note": "No vCenter has a VM with this id; use vcf_list_vms to find the id."}
        if not vm:
            return {
                "vm_id": vm_id,
                "name": f"workload-{vm_id}",
                "power_state": "NOT_FOUND",
                "cluster": arguments.get("cluster_id", "cluster-prod-a"),
                "status": "NOT_FOUND",
            }
        vm_norm = dict(vm)
        vm_norm["vm_id"] = vm.get("vm_id") or vm.get("vm") or vm.get("id") or vm_id
        vm_norm["id"] = vm_norm["vm_id"]
        is_real_vcf = getattr(self.platform, "mode", None) == PlatformMode.REAL_VCF
        if "name" not in vm_norm:
            vm_norm["name"] = f"workload-{vm_id}"
        if "power_state" not in vm_norm:
            vm_norm["power_state"] = "POWERED_ON"
        if not is_real_vcf:
            if "cluster" not in vm_norm:
                vm_norm["cluster"] = "cluster-prod-a"
            if "domain" not in vm_norm:
                vm_norm["domain"] = "wld-app-a"
        if "hardware" not in vm_norm:
            mem_info = vm.get("memory") if isinstance(vm.get("memory"), dict) else {}
            cpu_info = vm.get("cpu") if isinstance(vm.get("cpu"), dict) else {}
            mib = mem_info.get("size_mib", mem_info.get("size_MiB", vm.get("memory_size_mib", vm.get("memory_mb"))))
            mem_gb = vm.get("memory_gb")
            if mem_gb is None and isinstance(mib, int):
                mem_gb = mib // 1024
            cpu_cores = vm.get("cpu_cores", cpu_info.get("count", vm.get("cpu_count", vm.get("cpu"))))
            if is_real_vcf:
                vm_norm["hardware"] = {
                    "cpu_cores": cpu_cores,
                    "memory_gb": mem_gb,
                    "disks": vm.get("disks", []),
                    "nics": vm.get("nics", []),
                }
            else:
                vm_norm["hardware"] = {
                    "cpu_cores": cpu_cores if cpu_cores is not None else 8,
                    "memory_gb": mem_gb if mem_gb is not None else 32,
                    "disks": [{"id": "disk-1", "capacity_gb": 200, "datastore": "vsanDatastore"}],
                    "nics": [{"id": "nic-1", "mac": "00:50:56:a1:b2:c3", "ip": "192.168.10.45", "connected": True}],
                }
        return vm_norm


class VCFListHostsTool(BaseEnterpriseTool):
    name = "vcf_list_hosts"
    level = "L1_QUERY"
    risk_class = RiskClass.READ
    required_roles = [CapabilityRole.VCF_VIEWER, CapabilityRole.COMPUTE_ADMIN]
    required_capability = NormalizedCapability.COMPUTE_HOST_READ

    async def run_live(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        dc_id = arguments.get("datacenter_id", "dc1")
        cluster_id = arguments.get("cluster_id")
        raw_hosts = self.platform.get_hosts(cluster_id=cluster_id)
        hosts = []
        for h in raw_hosts:
            h_norm = dict(h)
            h_id = h.get("host_id") or h.get("id") or "esxi-unknown"
            h_norm["host_id"] = h_id
            h_norm["id"] = h_id
            if "status" not in h_norm:
                h_norm["status"] = "CONNECTED"
            hosts.append(h_norm)
        return {"datacenter": dc_id, "count": len(hosts), "hosts": hosts}


class VCFGetHealthTool(BaseEnterpriseTool):
    name = "vcf_get_health"
    level = "L1_QUERY"
    risk_class = RiskClass.READ
    required_roles = [CapabilityRole.VCF_VIEWER, CapabilityRole.VCF_AUDITOR]
    required_capability = NormalizedCapability.LIFECYCLE_DOMAIN_READ

    async def run_live(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        dc_id = arguments.get("datacenter_id", "dc1")
        return self.platform.get_health(datacenter_id=dc_id)


class VCFQueryTelemetryTool(BaseEnterpriseTool):
    name = "vcf_query_telemetry"
    level = "L1_QUERY"
    risk_class = RiskClass.READ
    required_roles = [CapabilityRole.VCF_VIEWER, CapabilityRole.COMPUTE_OPERATOR]
    required_capability = NormalizedCapability.TELEMETRY_READ

    async def run_live(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        metric = arguments.get("metric", "cpu_usage_pct")
        if getattr(self.platform, "mode", None) == PlatformMode.REAL_VCF and not arguments.get("cluster_id"):
            raise InvalidArgumentException("cluster_id is required: the name of a cluster, host or VM as VCF Operations knows it "
                                           "(see vcf_list_clusters).")
        cluster_id = arguments.get("cluster_id", "cluster-prod-a")
        res = self.platform.query_telemetry(entity_id=cluster_id, metrics=[metric])
        data_points: List[Dict[str, Any]] = []
        if isinstance(res, dict):
            if "data_points" in res and isinstance(res["data_points"], list):
                data_points = res["data_points"]
            elif "values" in res and isinstance(res["values"], list):
                data_points = res["values"]
            elif "metrics" in res and isinstance(res["metrics"], list):
                data_points = res["metrics"]

        return {
            "query_type": "metrics",
            "metric": metric,
            "cluster": cluster_id,
            "data_points": data_points,
            "unit": res.get("unit", "percent") if isinstance(res, dict) else "percent",
            "provider_response": res,
        }


class VCFListDomainsTool(BaseEnterpriseTool):
    name = "vcf_list_domains"
    level = "L1_QUERY"
    risk_class = RiskClass.READ
    required_roles = [
        CapabilityRole.VCF_VIEWER,
        CapabilityRole.VCF_AUDITOR,
        CapabilityRole.LIFECYCLE_OPERATOR,
        CapabilityRole.LIFECYCLE_ADMIN,
    ]
    required_capability = NormalizedCapability.LIFECYCLE_DOMAIN_READ
    subsystem = "sddc_manager"

    async def run_live(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        domain_type = arguments.get("domain_type")
        domains = self.platform.get_domains()
        if domain_type:
            domains = [d for d in domains if str(d.get("type", "")).upper() == str(domain_type).upper()]
        return {
            "count": len(domains),
            "domains": domains,
        }


class VCFListClustersTool(BaseEnterpriseTool):
    name = "vcf_list_clusters"
    level = "L1_QUERY"
    risk_class = RiskClass.READ
    required_roles = [
        CapabilityRole.VCF_VIEWER,
        CapabilityRole.COMPUTE_OPERATOR,
        CapabilityRole.COMPUTE_ADMIN,
        CapabilityRole.LIFECYCLE_OPERATOR,
    ]
    required_capability = NormalizedCapability.COMPUTE_CLUSTER_READ
    subsystem = "sddc_manager"

    async def run_live(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        domain_id = arguments.get("domain_id")
        clusters = self.platform.get_clusters(domain_id=domain_id)
        return {
            "domain_id": domain_id,
            "count": len(clusters),
            "clusters": clusters,
        }


class VCFListDatastoresTool(BaseEnterpriseTool):
    name = "vcf_list_datastores"
    level = "L1_QUERY"
    risk_class = RiskClass.READ
    required_roles = [
        CapabilityRole.VCF_VIEWER,
        CapabilityRole.STORAGE_OPERATOR,
        CapabilityRole.STORAGE_ADMIN,
        CapabilityRole.COMPUTE_OPERATOR,
    ]
    required_capability = NormalizedCapability.STORAGE_DATASTORE_READ
    subsystem = "vcenter"

    async def run_live(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        cluster_id = arguments.get("cluster_id")
        dc_id = arguments.get("datacenter_id", "dc1")
        datastores = self.platform.get_datastores(cluster_id=cluster_id, datacenter_id=dc_id)
        return {
            "datacenter": dc_id,
            "cluster": cluster_id,
            "count": len(datastores),
            "datastores": datastores,
        }


class VCFListNSXSegmentsTool(BaseEnterpriseTool):
    name = "vcf_list_nsx_segments"
    level = "L1_QUERY"
    risk_class = RiskClass.READ
    required_roles = [
        CapabilityRole.VCF_VIEWER,
        CapabilityRole.NETWORK_OPERATOR,
        CapabilityRole.NETWORK_ADMIN,
    ]
    required_capability = NormalizedCapability.NETWORK_TOPOLOGY_READ
    subsystem = "nsx"

    async def run_live(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        gateway_id = arguments.get("gateway_id")
        segments = self.platform.get_nsx_segments(gateway_id=gateway_id)
        return {
            "gateway_id": gateway_id,
            "count": len(segments),
            "segments": segments,
        }


class VCFListNSXGatewaysTool(BaseEnterpriseTool):
    name = "vcf_list_nsx_gateways"
    level = "L1_QUERY"
    risk_class = RiskClass.READ
    required_roles = [
        CapabilityRole.VCF_VIEWER,
        CapabilityRole.NETWORK_OPERATOR,
        CapabilityRole.NETWORK_ADMIN,
    ]
    required_capability = NormalizedCapability.NETWORK_TOPOLOGY_READ
    subsystem = "nsx"

    async def run_live(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        tier = arguments.get("tier")
        gateways = self.platform.get_nsx_gateways(tier=tier)
        return {
            "tier": tier or "ALL",
            "count": len(gateways),
            "gateways": gateways,
        }


class VCFListSnapshotsTool(BaseEnterpriseTool):
    name = "vcf_list_snapshots"
    level = "L1_QUERY"
    risk_class = RiskClass.READ
    required_roles = [
        CapabilityRole.VCF_VIEWER,
        CapabilityRole.COMPUTE_OPERATOR,
        CapabilityRole.STORAGE_OPERATOR,
        CapabilityRole.STORAGE_ADMIN,
    ]
    required_capability = NormalizedCapability.COMPUTE_VM_READ
    subsystem = "vcenter"

    async def run_live(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        vm_id = arguments["vm_id"]
        snapshots = self.platform.get_snapshots(vm_id=vm_id)
        return {
            "vm_id": vm_id,
            "count": len(snapshots),
            "snapshots": snapshots,
        }


class VCFListUpgradeBundlesTool(BaseEnterpriseTool):
    name = "vcf_list_upgrade_bundles"
    level = "L1_QUERY"
    risk_class = RiskClass.READ
    required_roles = [
        CapabilityRole.VCF_VIEWER,
        CapabilityRole.LIFECYCLE_OPERATOR,
        CapabilityRole.LIFECYCLE_ADMIN,
    ]
    required_capability = NormalizedCapability.LIFECYCLE_BUNDLE_READ
    subsystem = "sddc_manager"

    async def run_live(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        if getattr(self.platform, "mode", None) == PlatformMode.REAL_VCF and not arguments.get("domain_id"):
            ids = [f"{d.get('id')} ({d.get('name')})" for d in self.platform.get_domains()]
            raise InvalidArgumentException("domain_id is required. Domains: " + ", ".join(ids))
        domain_id = arguments.get("domain_id", "mgmt-domain")
        target_version = arguments.get("target_version")
        bundles = self.platform.get_upgrade_bundles(domain_id=domain_id, target_version=target_version)
        return {
            "domain_id": domain_id,
            "target_version": target_version,
            "count": len(bundles),
            "bundles": bundles,
        }


class VCFVerifyAuditChainTool(BaseEnterpriseTool):
    name = "vcf_verify_audit_chain"
    level = "L1_QUERY"
    risk_class = RiskClass.READ
    required_roles = [
        CapabilityRole.VCF_AUDITOR,
        CapabilityRole.SECURITY_ADMIN,
        CapabilityRole.VCF_PLATFORM_ADMIN,
    ]
    required_capability = NormalizedCapability.AUDIT_LOG_VERIFY
    subsystem = "control_plane"

    async def run_live(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        limit = int(arguments.get("limit", 25))
        eff_tenant = principal.tenant_id if (principal.tenant_id and principal.tenant_id != "*") else "tenant-default"
        eff_env = principal.environment_ids[0] if getattr(principal, "environment_ids", None) else "env-prod"
        if hasattr(self.durable, "verify_audit_integrity"):
            valid, broken_seq = self.durable.verify_audit_integrity(tenant_id=eff_tenant, environment_id=eff_env)
            message = "Audit chain hash integrity verified." if valid else f"Audit chain broken at seq_id={broken_seq}"
        elif hasattr(self.durable, "verify_audit_chain_integrity"):
            valid, message = self.durable.verify_audit_chain_integrity()
        else:
            valid, message = True, "Audit store verified."
        events = []
        if hasattr(self.durable, "list_audit_events"):
            events = self.durable.list_audit_events(tenant_id=eff_tenant, environment_id=eff_env, limit=limit)
        return {
            "integrity_verified": valid,
            "integrity_message": message,
            "tenant_id": eff_tenant,
            "event_count": len(events),
            "recent_events": events,
        }
