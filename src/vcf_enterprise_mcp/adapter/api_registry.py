# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Broadcom VCF Official API Contract Registry.
Maintains normalized specifications of Broadcom OpenAPI / WSDL specs across all supported release baselines:
- VCF 9.0.0 (June 17, 2025)
- VCF 9.0.1 (September 29, 2025)
- VCF 9.0.2 (January 20, 2026)
- VCF 9.1.0 (May 19, 2026)
- VCF 9.1.1 (August 18, 2026)

Computes automated coverage gaps (official APIs - implemented capabilities = coverage gaps),
tracks introduced/deprecated versions, and manages provider migration paths (SDDC Manager -> Fleet LCM).
"""

from __future__ import annotations
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field


@dataclass
class BroadcomAPIContract:
    api_id: str
    subsystem: str               # "sddc_manager", "vcenter", "nsx", "vcf_operations", "vsan", "srm"
    path: str
    method: str
    introduced_version: str
    deprecated_version: Optional[str] = None
    removed_version: Optional[str] = None
    mapped_capability: Optional[str] = None
    auth_mechanism: str = "BEARER_TOKEN"  # "BEARER_TOKEN", "BASIC", "VMWARE_API_SESSION_ID", "OPS_TOKEN"
    description: str = ""
    # True when method+path exist in the official vcf-api-specs (github.com/vmware/vcf-api-specs).
    # False for products whose APIs are not published there (e.g. VMware Live Site Recovery).
    spec_verified: bool = True
    error_codes: List[int] = field(default_factory=lambda: [400, 401, 403, 404, 409, 500, 503])


OFFICIAL_BROADCOM_APIS: List[BroadcomAPIContract] = [
    # SDDC Manager LCM APIs
    BroadcomAPIContract("sddc.domains.list", "sddc_manager", "/v1/domains", "GET", "9.0.0", mapped_capability="domain.lifecycle", description="List all workload domains"),
    BroadcomAPIContract("sddc.domains.get", "sddc_manager", "/v1/domains/{id}", "GET", "9.0.0", mapped_capability="domain.lifecycle", description="Get domain details"),
    BroadcomAPIContract("sddc.domains.upgrade", "sddc_manager", "/v1/upgrades", "POST", "9.0.0", mapped_capability="lifecycle.domain.upgrade", description="Start a bundle upgrade (UpgradeSpec: bundleId, resourceType, resourceUpgradeSpecs)"),
    BroadcomAPIContract("sddc.bundles.list", "sddc_manager", "/v1/bundles", "GET", "9.0.0", mapped_capability="lifecycle.bundles.read", description="List available software update bundles"),
    BroadcomAPIContract("sddc.prechecks.run", "sddc_manager", "/v1/upgrades/{id}/prechecks", "POST", "9.0.0", mapped_capability="lifecycle.prechecks.run", description="Execute upgrade prechecks"),
    BroadcomAPIContract("sddc.hosts.list", "sddc_manager", "/v1/hosts", "GET", "9.0.0", mapped_capability="compute.host.read", description="List physical ESXi hosts"),
    BroadcomAPIContract("sddc.hosts.commission", "sddc_manager", "/v1/hosts", "POST", "9.0.0", mapped_capability="compute.host.commission", description="Commission physical ESXi hosts"),

    # vCenter APIs
    BroadcomAPIContract("vc.vms.list", "vcenter", "/api/vcenter/vm", "GET", "9.0.0", mapped_capability="compute.vm.read", description="List virtual machines"),
    BroadcomAPIContract("vc.vms.get", "vcenter", "/api/vcenter/vm/{id}", "GET", "9.0.0", mapped_capability="compute.vm.read", description="Get single VM hardware details"),
    BroadcomAPIContract("vc.vms.power", "vcenter", "/api/vcenter/vm/{id}/power", "POST", "9.0.0", mapped_capability="compute.vm.power", description="Control VM power state"),
    BroadcomAPIContract("vc.vms.resize_memory", "vcenter", "/api/vcenter/vm/{id}/hardware/memory", "PATCH", "9.0.0", mapped_capability="compute.vm.resize.memory", description="Modify VM memory allocation"),
    BroadcomAPIContract("vc.vms.resize_cpu", "vcenter", "/api/vcenter/vm/{id}/hardware/cpu", "PATCH", "9.0.0", mapped_capability="compute.vm.resize.cpu", description="Modify VM vCPU count"),
    BroadcomAPIContract("vc.vms.create_snapshot", "vcenter", "/sdk/vim25/{release}/VirtualMachine/{moId}/CreateSnapshot_Task", "POST", "9.0.0", mapped_capability="compute.vm.snapshot", auth_mechanism="VMWARE_API_SESSION_ID", description="Create VM snapshot (VI/JSON; no /api/vcenter snapshot operation exists in 9.x)"),
    BroadcomAPIContract("vc.clusters.list", "vcenter", "/api/vcenter/cluster", "GET", "9.0.0", mapped_capability="compute.inventory", description="List compute clusters"),
    BroadcomAPIContract("vc.datastores.list", "vcenter", "/api/vcenter/datastore", "GET", "9.0.0", mapped_capability="storage.datastore.read", description="List datastores"),

    # NSX Policy APIs
    BroadcomAPIContract("nsx.segments.list", "nsx", "/policy/api/v1/infra/segments", "GET", "9.0.0", mapped_capability="network.segment.read", description="List overlay segments"),
    BroadcomAPIContract("nsx.segments.create", "nsx", "/policy/api/v1/infra/segments/{id}", "PATCH", "9.0.0", mapped_capability="network.segment.create", description="Provision overlay segment (PATCH after existence check; PUT is create-or-replace)"),
    BroadcomAPIContract("nsx.tier1.list", "nsx", "/policy/api/v1/infra/tier-1s", "GET", "9.0.0", mapped_capability="network.gateway.read", description="List Tier-1 logical gateways"),
    BroadcomAPIContract("nsx.dfw.rules", "nsx", "/policy/api/v1/infra/domains/{domain_id}/security-policies", "GET", "9.0.0", mapped_capability="network.dfw.read", description="Inspect distributed firewall rules"),

    # VCF Operations (vROps) APIs
    BroadcomAPIContract("ops.health.get", "vcf_operations", "/suite-api/api/resources", "GET", "9.0.0", mapped_capability="telemetry.health.read", auth_mechanism="OPS_TOKEN", description="Query resources with health (resourceHealth filter)"),
    BroadcomAPIContract("ops.alerts.list", "vcf_operations", "/suite-api/api/alerts", "GET", "9.0.0", mapped_capability="telemetry.alerts.read", description="List active operational alarms"),
    BroadcomAPIContract("ops.promql.query", "vcf_operations", "/api/v1/query", "GET", "9.1.0", mapped_capability="telemetry.metrics.read", auth_mechanism="REALTIME_METRICS_BEARER", description="Realtime Metrics API instant query (Prometheus-compatible, VCF 9.1+)"),
    BroadcomAPIContract("ops.fleet.iam", "vcf_operations", "/suite-api/api/fleet-management/iam/roles", "GET", "9.1.0", mapped_capability="security.iam.admin", description="Fleet-wide centralized IAM governance (VCF 9.1+)"),

    # Site Recovery Manager & Replication APIs
    BroadcomAPIContract("srm.plans.list", "srm", "/api/srm/recovery-plans", "GET", "9.0.0", mapped_capability="dr.replication.read", description="List disaster recovery plans", spec_verified=False),
    BroadcomAPIContract("srm.plans.test", "srm", "/api/srm/recovery-plans/{id}/test", "POST", "9.0.0", mapped_capability="dr.site.recover", description="Execute DR drill in test bubble", spec_verified=False),
    BroadcomAPIContract("srm.plans.failover", "srm", "/api/srm/recovery-plans/{id}/recovery", "POST", "9.0.0", mapped_capability="dr.site.recover", description="Execute production site recovery failover", spec_verified=False),
]


# Documented upstream auth per component (see adapter/transport/vcf_sessions.py).
_AUTH_BY_SUBSYSTEM = {"vcenter": "VMWARE_API_SESSION_ID", "nsx": "BASIC", "vcf_operations": "OPS_TOKEN", "sddc_manager": "BEARER_TOKEN"}
for _c in OFFICIAL_BROADCOM_APIS:
    if _c.auth_mechanism == "BEARER_TOKEN" and _c.subsystem in _AUTH_BY_SUBSYSTEM:
        _c.auth_mechanism = _AUTH_BY_SUBSYSTEM[_c.subsystem]


class BroadcomAPIContractRegistry:
    """Authority registry mapping Broadcom OpenAPI specifications and calculating coverage gaps."""

    def __init__(self):
        self._contracts = OFFICIAL_BROADCOM_APIS

    def list_apis_for_version(self, version: str) -> List[BroadcomAPIContract]:
        """Filters API contracts that are valid and active for a given VCF version baseline."""
        results = []
        for contract in self._contracts:
            if self._is_version_ge(version, contract.introduced_version):
                if contract.removed_version and self._is_version_ge(version, contract.removed_version):
                    continue
                results.append(contract)
        return results

    def list_apis_for_component_versions(
        self,
        component_versions: Dict[str, str],
        default_version: str = "9.1.1",
    ) -> List[BroadcomAPIContract]:
        """Filters API contracts that are valid and active given per-component version resolution."""
        results = []
        for contract in self._contracts:
            comp_ver = component_versions.get(contract.subsystem, default_version)
            if self._is_version_ge(comp_ver, contract.introduced_version):
                if contract.removed_version and self._is_version_ge(comp_ver, contract.removed_version):
                    continue
                results.append(contract)
        return results

    def list_apis_for_subsystem(self, subsystem: str, version: str) -> List[BroadcomAPIContract]:
        """Lists active APIs for a specific subsystem and version."""
        results = []
        for contract in self._contracts:
            if contract.subsystem == subsystem:
                if self._is_version_ge(version, contract.introduced_version):
                    if contract.removed_version and self._is_version_ge(version, contract.removed_version):
                        continue
                    results.append(contract)
        return results

    def get_contract(self, api_id: str) -> Optional[BroadcomAPIContract]:
        """Retrieves a specific Broadcom API contract definition by its unique ID."""
        for contract in self._contracts:
            if contract.api_id == api_id:
                return contract
        return None

    def is_api_supported(
        self,
        api_id: str,
        component_versions: Optional[Dict[str, str]] = None,
        version: str = "9.1.1",
    ) -> bool:
        """Checks if a specific API is supported under the provided component versions or baseline."""
        contract = self.get_contract(api_id)
        if not contract:
            return False
        if component_versions and contract.subsystem in component_versions:
            comp_ver = component_versions[contract.subsystem]
        else:
            comp_ver = version

        if self._is_version_ge(comp_ver, contract.introduced_version):
            if contract.removed_version and self._is_version_ge(comp_ver, contract.removed_version):
                return False
            return True
        return False

    def compute_coverage_gaps(
        self,
        implemented_capabilities: List[str],
        version: str | Dict[str, str] = "9.1.1",
        component_versions: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Computes formal coverage gaps:
        official APIs - implemented capabilities = coverage gaps.
        Supports uniform version string (e.g. '9.1.1') or per-component version resolution.
        """
        if isinstance(version, dict):
            comp_versions = version
            baseline_ver = comp_versions.get("sddc_manager", "9.1.1")
        elif component_versions:
            comp_versions = component_versions
            baseline_ver = str(version)
        else:
            comp_versions = None
            baseline_ver = str(version)

        if comp_versions:
            active_apis = self.list_apis_for_component_versions(comp_versions, default_version=baseline_ver)
        else:
            active_apis = self.list_apis_for_version(baseline_ver)

        impl_set = set(implemented_capabilities)

        covered = []
        missing = []

        for api in active_apis:
            if api.mapped_capability and api.mapped_capability in impl_set:
                covered.append(api.api_id)
            else:
                missing.append({
                    "api_id": api.api_id,
                    "subsystem": api.subsystem,
                    "path": api.path,
                    "method": api.method,
                    "capability": api.mapped_capability or "UNMAPPED",
                    "description": api.description,
                })

        total = len(active_apis)
        coverage_pct = round((len(covered) / total) * 100.0, 2) if total > 0 else 100.0

        res: Dict[str, Any] = {
            "vcf_version": baseline_ver,
            "total_official_apis": total,
            "covered_api_count": len(covered),
            "gap_count": len(missing),
            "coverage_percentage": coverage_pct,
            "covered_apis": covered,
            "coverage_gaps": missing,
        }
        if comp_versions:
            res["component_versions"] = comp_versions
        return res

    def get_provider_migration_path(self, capability: str) -> Dict[str, str]:
        """
        Returns architectural provider migration paths for VCF evolution
        (e.g., SDDC Manager deprecation -> Fleet LCM API).
        """
        migration_map = {
            "domain.lifecycle": {
                "vcf_9_0": "sddc_manager (/v1/domains)",
                "vcf_9_1": "sddc_manager + fleet_lcm_preview",
                "future_vcf": "vcf_platform_api (SDDC Manager decoupled)",
            },
            "security.iam": {
                "vcf_9_0": "sddc_manager (/v1/users) + vcenter sso",
                "vcf_9_1": "vcf_operations_fleet_iam (/suite-api/api/fleet/iam)",
                "future_vcf": "centralized_oauth_idp_overlay",
            },
        }
        return migration_map.get(capability, {"current": "direct_appliance", "future": "platform_capability"})

    @staticmethod
    def _is_version_ge(v1: str, v2: str) -> bool:
        """Helper comparing semver tuples e.g. '9.1.0' >= '9.0.0'."""
        try:
            p1 = [int(x) for x in v1.split(".")]
            p2 = [int(x) for x in v2.split(".")]
            return p1 >= p2
        except Exception:
            return v1 >= v2
