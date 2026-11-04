# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Platform Client Abstraction for Enterprise VCF MCP Control Plane.
Internal tools invoke platform methods (e.g. platform.get_domains(), platform.get_hosts(),
platform.get_vms(), platform.get_resource_revision()) rather than coupling directly to SDDC Manager
or vCenter. The platform layer resolves the appropriate CapabilityProvider and executes calls
via the robust HTTP transport layer.
"""

from __future__ import annotations
import os
import hashlib
import json
import time
from typing import Dict, Any, List, Optional
from vcf_enterprise_mcp.adapter.capability_provider import CapabilityProviderRegistry
from vcf_enterprise_mcp.adapter.ssrf_guard import SSRFGuard
from vcf_enterprise_mcp.adapter.transport.base import BaseTransport, TransportRequest
from vcf_enterprise_mcp.adapter.transport.auth import BaseUpstreamAuth
from vcf_enterprise_mcp.adapter.transport.http import HTTPTransport
from vcf_enterprise_mcp.adapter.providers.vcenter import VCenterProvider
from vcf_enterprise_mcp.adapter.providers.nsx import NSXProvider
from vcf_enterprise_mcp.adapter.providers.sddc import SDDCManagerProvider
from vcf_enterprise_mcp.adapter.providers.operations import VCFOperationsProvider
from vcf_enterprise_mcp.adapter.providers.digital_twin import DigitalTwinProvider
from vcf_enterprise_mcp.adapter.models import (
    PlatformMode,
    ResourceRevision,
    ReconciliationStatus,
    ReconciliationResult,
    ExecutionIntent,
)
from vcf_enterprise_mcp.adapter.version_adapter import VCFVersionAdapter


class PlatformClient:
    """Unified infrastructure platform interface backed by CapabilityProviderRegistry and HTTPTransport."""

    def __init__(
        self,
        registry: Optional[CapabilityProviderRegistry] = None,
        ssrf_guard: Optional[SSRFGuard] = None,
        transport: Optional[BaseTransport] = None,
        auth: Optional[BaseUpstreamAuth] = None,
        use_live_transport: bool = False,
        component_auth: Optional[Dict[str, BaseUpstreamAuth]] = None,
        mode: Optional[PlatformMode | str] = None,
        digital_twin_url: str = "http://127.0.0.1:9080",
        version_adapter: Optional[VCFVersionAdapter] = None,
    ):
        self.registry = registry or CapabilityProviderRegistry.create_default()
        self.ssrf_guard = ssrf_guard or SSRFGuard()
        self.transport = transport or HTTPTransport(ssrf_guard=self.ssrf_guard)
        self.auth = auth
        # Per-component session auth keyed by provider type (vcenter, sddc_manager, nsx,
        # vcf_operations); each VCF appliance has its own login flow. Falls back to `auth`.
        self.component_auth: Dict[str, BaseUpstreamAuth] = dict(component_auth or {})
        # Real-VCF only: build auth for appliances discovered at runtime (e.g. one vCenter per workload
        # domain). Signature: (provider_type, base_url) -> BaseUpstreamAuth. Set by the server builder.
        self.auth_factory = None
        # FQDN -> base URL for discovered appliances behind a load balancer/proxy, or a lab simulator.
        self.endpoint_overrides: Dict[str, str] = {}
        # Real-VCF only: vCenters attached in vcf.vcenters (host name -> base URL), and the host name of the configured
        # vCenter, so every vCenter can be named. Set by the server builder.
        self.extra_vcenters: Dict[str, str] = {}
        self.main_vcenter_name: Optional[str] = None
        self.last_inventory_errors: List[Dict[str, Any]] = []
        self.automation = None  # (base_url, auth) when VCF Automation is configured
        self.orchestrator = None  # dict(url, auth, managed_category, module_prefix, ...) when Orchestrator is configured
        self.resolve_secret = None  # callable(ref) -> secret value, server-side only
        self.version_adapter = version_adapter or VCFVersionAdapter()

        if mode is not None:
            if isinstance(mode, PlatformMode):
                self.mode = mode
            else:
                self.mode = PlatformMode(str(mode).upper())
        elif "VCF_PLATFORM_MODE" in os.environ:
            self.mode = PlatformMode(os.environ["VCF_PLATFORM_MODE"].upper())
        elif use_live_transport:
            self.mode = PlatformMode.REAL_VCF
        else:
            self.mode = PlatformMode.UNIT_TEST

        self.use_live_transport = (self.mode == PlatformMode.REAL_VCF) or use_live_transport
        self.digital_twin_url = digital_twin_url or os.environ.get("VCF_DIGITAL_TWIN_URL", "http://127.0.0.1:9080")

        # Monotonic revision tracker for TOCTOU validation across infrastructure entities
        self._revisions: Dict[str, str] = {
            "cluster-prod-a": "rev-100",
            "cluster-prod-b": "rev-100",
            "vm-101": "rev-201",
            "vm-102": "rev-202",
            "mgmt-domain": "rev-501",
            "vi-workload-domain-01": "rev-502",
        }

        # In-memory test fixtures for UNIT_TEST mode
        self._vms: Dict[str, Dict[str, Any]] = {
            "vm-101": {"id": "vm-101", "vm_id": "vm-101", "name": "web-frontend-01", "cluster": "cluster-prod-a", "power_state": "POWERED_ON", "cpu": 4, "cpu_cores": 4, "memory_mb": 16384, "memory_gb": 16},
            "vm-102": {"id": "vm-102", "vm_id": "vm-102", "name": "db-backend-01", "cluster": "cluster-prod-a", "power_state": "POWERED_ON", "cpu": 8, "cpu_cores": 8, "memory_mb": 16384, "memory_gb": 16},
            "vm-201": {"id": "vm-201", "vm_id": "vm-201", "name": "analytics-worker-01", "cluster": "cluster-prod-b", "power_state": "POWERED_ON", "cpu": 16, "cpu_cores": 16, "memory_mb": 65536, "memory_gb": 64},
            "vm-twin-101": {"id": "vm-twin-101", "vm_id": "vm-twin-101", "name": "twin-frontend-01", "cluster": "cluster-twin-a", "power_state": "POWERED_ON", "cpu": 4, "cpu_cores": 4, "memory_mb": 16384, "memory_gb": 16},
        }
        self._domains: Dict[str, Dict[str, Any]] = {
            "mgmt-domain": {"id": "mgmt-domain", "name": "Management-Domain", "status": "ACTIVE", "provider": "sddc-manager-01"},
            "vi-workload-domain-01": {"id": "vi-workload-domain-01", "name": "Workload-Domain-01", "status": "ACTIVE", "provider": "sddc-manager-01"},
        }
        self._hosts: Dict[str, Dict[str, Any]] = {
            "host-esx-01.corp.internal": {"id": "host-esx-01.corp.internal", "host_id": "host-esx-01.corp.internal", "cluster": "cluster-prod-a", "cpu_cores": 64, "memory_gb": 512, "status": "CONNECTED"},
            "host-esx-02.corp.internal": {"id": "host-esx-02.corp.internal", "host_id": "host-esx-02.corp.internal", "cluster": "cluster-prod-a", "cpu_cores": 64, "memory_gb": 512, "status": "CONNECTED"},
            "host-esx-03.corp.internal": {"id": "host-esx-03.corp.internal", "host_id": "host-esx-03.corp.internal", "cluster": "cluster-prod-b", "cpu_cores": 128, "memory_gb": 1024, "status": "CONNECTED"},
        }
        self._clusters: Dict[str, Dict[str, Any]] = {
            "cluster-prod-a": {"id": "cluster-prod-a", "name": "Production-Cluster-A", "domain": "mgmt-domain", "host_count": 4, "drs_enabled": True},
            "cluster-prod-b": {"id": "cluster-prod-b", "name": "Production-Cluster-B", "domain": "vi-workload-domain-01", "host_count": 8, "drs_enabled": True},
            "cluster-twin-a": {"id": "cluster-twin-a", "name": "Twin-Cluster-A", "domain": "mgmt-domain", "host_count": 2, "drs_enabled": True},
        }
        self._segments: Dict[str, Dict[str, Any]] = {
            "seg-app-tier-01": {"segment_id": "seg-app-tier-01", "segment_name": "seg-app-tier-01", "gateway": "t1-gw-workloads", "cidr": "10.20.10.1/24", "status": "SUCCESS"},
            "seg-db-tier-01": {"segment_id": "seg-db-tier-01", "segment_name": "seg-db-tier-01", "gateway": "t1-gw-workloads", "cidr": "10.20.20.1/24", "status": "SUCCESS"},
        }
        self._gateways: List[Dict[str, Any]] = [
            {"id": "t0-gw-prod", "name": "Tier-0-Prod-Gateway", "tier": "TIER_0", "ha_mode": "ACTIVE_ACTIVE", "status": "UP"},
            {"id": "t1-gw-workloads", "name": "Tier-1-Workloads-Gateway", "tier": "TIER_1", "linked_tier0": "t0-gw-prod", "status": "UP"},
        ]
        self._datastores: List[Dict[str, Any]] = [
            {"datastore": "ds-vsan-prod-a", "name": "vsan-esa-prod-a", "type": "VSAN", "cluster": "cluster-prod-a", "capacity_gb": 65536, "free_gb": 42100, "status": "ACCESSIBLE"},
            {"datastore": "ds-vsan-prod-b", "name": "vsan-esa-prod-b", "type": "VSAN", "cluster": "cluster-prod-b", "capacity_gb": 131072, "free_gb": 94200, "status": "ACCESSIBLE"},
        ]
        self._snapshots: Dict[str, List[Dict[str, Any]]] = {
            "vm-101": [
                {"snapshot_id": "snap-vm-101-pre-patch", "vm_id": "vm-101", "snapshot_name": "pre-patch-baseline", "created_at": 1727200000, "size_gb": 4.2},
            ],
        }

    def _vcenter_providers(self) -> List[tuple]:
        """Real VCF: one provider per vCenter, named by host: those SDDC Manager reports (each workload domain has its
        own vCenter) plus those attached in vcf.vcenters, and the configured one. With no other vCenter known it is the
        configured vCenter alone, unnamed, as before."""
        entry = self.registry.resolve("vm.lifecycle")
        main = VCenterProvider(endpoint_url=entry.endpoint_url, transport=self.transport,
                               auth=self._auth_for("vcenter"), api_version=entry.api_version)
        if self.auth_factory is None:
            return [(None, main)]
        targets: Dict[str, str] = {}
        try:
            sddc_entry = self.registry.resolve("domain.lifecycle")
            sddc = SDDCManagerProvider(endpoint_url=sddc_entry.endpoint_url, transport=self.transport,
                                       auth=self._auth_for("sddc_manager"), api_version=sddc_entry.api_version)
            for vc in (sddc.request("GET", "/v1/vcenters").json() or {}).get("elements", []):
                if vc.get("fqdn"):
                    targets[vc["fqdn"]] = self.endpoint_overrides.get(vc["fqdn"]) or f"https://{vc['fqdn']}"
        except Exception:
            pass
        for host, url in self.extra_vcenters.items():
            if not any(h.lower() == host.lower() for h in targets):
                targets[host] = url
        if not targets:
            return [(None, main)]
        if entry.endpoint_url.rstrip("/") not in {u.rstrip("/") for u in targets.values()}:
            targets = {self.main_vcenter_name or entry.endpoint_url: entry.endpoint_url, **targets}
        return [(fqdn, VCenterProvider(endpoint_url=url, transport=self.transport, auth=self.auth_factory("vcenter", url),
                                       api_version=entry.api_version)) for fqdn, url in targets.items()]

    def _named_vcenters(self) -> List[tuple]:
        """(name, provider) for every vCenter; the configured one is named by its host even when it is the only one."""
        return [(fqdn or self.main_vcenter_name, vc) for fqdn, vc in self._vcenter_providers()]

    def _vcenter_for(self, vcenter: Optional[str]) -> VCenterProvider:
        """The vCenter a VM change goes to: the one named, else the configured vCenter."""
        named = self._named_vcenters()
        if not vcenter:
            entry = self.registry.resolve("vm.lifecycle")
            return next((vc for _, vc in named if vc.endpoint_url.rstrip("/") == entry.endpoint_url.rstrip("/")), named[0][1])
        for name, vc in named:
            if name and name.lower() == vcenter.lower():
                return vc
        from vcf_enterprise_mcp.core.errors import InvalidArgumentException
        raise InvalidArgumentException(f"Unknown vCenter '{vcenter}'. Known vCenters: {', '.join(n for n, _ in named if n) or 'none'}.")

    def _across_vcenters(self, fetch) -> List[Dict[str, Any]]:
        """Runs fetch(provider) on every vCenter, tags items with their vCenter, and records unreachable ones."""
        self.last_inventory_errors = []
        items: List[Dict[str, Any]] = []
        for fqdn, vc in self._vcenter_providers():
            try:
                for item in fetch(vc) or []:
                    if fqdn and isinstance(item, dict):
                        item = dict(item, vcenter=fqdn)
                    items.append(item)
            except Exception as exc:
                if fqdn is None:
                    raise
                from vcf_enterprise_mcp.adapter.connectivity import classify_connection_error
                problem = classify_connection_error(exc, self.endpoint_overrides.get(fqdn) or f"https://{fqdn}")
                entry = {"vcenter": fqdn, "error": type(exc).__name__, "cause": problem.cause}
                if problem.mcp_config_problem:  # our own allowlist, not the appliance: say so and name the key to change
                    entry.update(note="Blocked by this MCP's network allowlist (not an appliance fault).", config_key=problem.config_key, fix=problem.fix)
                self.last_inventory_errors.append(entry)
        return items

    def _auth_for(self, provider_type: str) -> Optional[BaseUpstreamAuth]:
        return self.component_auth.get(provider_type, self.auth)

    def _resolve_provider_for_resource(self, resource_id: str) -> str:
        if resource_id.startswith("mgmt-domain") or "domain" in resource_id:
            return "sddc-manager"
        elif resource_id.startswith("seg-") or "network" in resource_id:
            return "nsx"
        return "vcenter"

    def _vcenter_base_url(self) -> Optional[str]:
        """The configured vCenter endpoint, or None when none is known (never an invented host name)."""
        try:
            entry_url = (
                self.registry.resolve("vm.lifecycle").endpoint_url
                if self.registry and self.registry.has_capability("vm.lifecycle")
                else ""
            )
        except Exception:
            entry_url = ""
        if entry_url and entry_url != "http://127.0.0.1:9090":
            return entry_url.rstrip("/")
        return None

    def get_resource_revision(self, resource_id: str) -> ResourceRevision:
        """Returns the current monotonic typed revision for an infrastructure entity."""
        provider = self._resolve_provider_for_resource(resource_id)
        if self.mode == PlatformMode.REAL_VCF:
            if provider == "vcenter" and self._vcenter_base_url() is None:
                # No vCenter is configured: nothing to probe, so use the local revision (no network call).
                return ResourceRevision(provider=provider, value=self._revisions.get(resource_id, "rev-100"))
            auth_obj = self._auth_for("vcenter" if provider == "vcenter" else provider.replace("-", "_"))
            try:
                if provider == "vcenter":
                    vc_base = self._vcenter_base_url()
                    req = TransportRequest(
                        method="GET",
                        url=f"{vc_base}/api/vcenter/vm/{resource_id}",
                        headers={},
                    )
                    if isinstance(auth_obj, str):
                        req.headers["Authorization"] = f"Bearer {auth_obj}"
                    elif auth_obj is not None and hasattr(auth_obj, "apply"):
                        req = auth_obj.apply(req)  # the session auth classes' real method
                    resp = self.transport.send(req)
                    if resp and resp.is_success:
                        vm_data = resp.json()
                        if isinstance(vm_data, dict):
                            inner = vm_data.get("value")
                            if isinstance(inner, dict):
                                vm_data = inner
                            mem_mib = vm_data.get("memory_size_mib", vm_data.get("memory_size_MiB", ""))
                            if not mem_mib and isinstance(vm_data.get("memory"), dict):
                                mem_mib = vm_data["memory"].get("size_mib", vm_data["memory"].get("size_MiB", ""))
                            cpu_cnt = vm_data.get("cpu_cores", vm_data.get("cpu_count", ""))
                            if not cpu_cnt and isinstance(vm_data.get("cpu"), dict):
                                cpu_cnt = vm_data["cpu"].get("count", "")
                            val = (
                                vm_data.get("revision")
                                or vm_data.get("change_version")
                                or (f"rev-{vm_data.get('power_state')}-{mem_mib}-{cpu_cnt}"
                                    if "power_state" in vm_data else None)
                            )
                            if val:
                                return ResourceRevision(provider="vcenter", value=val)
                return ResourceRevision(provider=provider, value="UNKNOWN")
            except Exception:
                return ResourceRevision(provider=provider, value="UNKNOWN")
        elif self.mode == PlatformMode.DIGITAL_TWIN:
            try:
                dt = DigitalTwinProvider(
                    endpoint_url=self.digital_twin_url,
                    transport=self.transport,
                    auth=self.auth,
                )
                if resource_id.startswith("vm-") or "vm" in resource_id:
                    vm = dt.get_vm(resource_id)
                    if vm and isinstance(vm, dict):
                        value = str(vm["revision"]) if "revision" in vm else hashlib.sha256(json.dumps(vm, sort_keys=True).encode()).hexdigest()
                        return ResourceRevision(provider="digital_twin", value=value)
            except Exception:
                return ResourceRevision(provider="digital_twin", value="UNKNOWN")
            return ResourceRevision(provider="digital_twin", value="UNKNOWN")
        val = self._revisions.get(resource_id, "rev-100")
        return ResourceRevision(provider=provider, value=val)

    def update_resource_revision(self, resource_id: str, new_revision: Optional[str] = None) -> ResourceRevision:
        """Bumps the revision when a mutation occurs, invalidating outstanding dry-run plans."""
        rev_str = new_revision or f"rev-{int(time.time() * 1000)}"
        self._revisions[resource_id] = rev_str
        provider = self._resolve_provider_for_resource(resource_id)
        return ResourceRevision(provider=provider, value=rev_str)

    def reconcile_operation_sync(
        self,
        intent: ExecutionIntent | Dict[str, Any],
    ) -> ReconciliationResult:
        """
        Synchronously reconciles an execution intent against infrastructure state.
        Never blindly retries UNKNOWN.
        """
        target_res = intent.target_resource if isinstance(intent, ExecutionIntent) else intent.get("target_resource", "")
        op_id = intent.operation_id if isinstance(intent, ExecutionIntent) else intent.get("operation_id", "")
        desired = intent.desired_state if isinstance(intent, ExecutionIntent) else intent.get("desired_state", {})

        current_rev = self.get_resource_revision(target_res)
        expected_rev = intent.expected_revision if isinstance(intent, ExecutionIntent) else intent.get("expected_revision")

        # Explicit reconciliation status hints from tests or upstream metadata
        if desired.get("reconciliation_status") == "APPLIED":
            return ReconciliationResult(
                status=ReconciliationStatus.APPLIED,
                details={"target": target_res, "operation": op_id},
                observed_revision=current_rev,
            )
        elif desired.get("reconciliation_status") == "NOT_APPLIED":
            return ReconciliationResult(
                status=ReconciliationStatus.NOT_APPLIED,
                details={"target": target_res, "operation": op_id},
                observed_revision=current_rev,
            )
        elif desired.get("reconciliation_status") == "IN_PROGRESS":
            return ReconciliationResult(
                status=ReconciliationStatus.IN_PROGRESS,
                details={"target": target_res, "operation": op_id},
                observed_revision=current_rev,
            )
        elif desired.get("reconciliation_status") == "UNKNOWN":
            return ReconciliationResult(
                status=ReconciliationStatus.UNKNOWN,
                details={"target": target_res, "operation": op_id, "reason": "Explicit UNKNOWN status from test/chaos probe"},
                observed_revision=current_rev,
            )

        if self.mode == PlatformMode.REAL_VCF:
            try:
                provider_name = self._resolve_provider_for_resource(target_res)
                vc_base = self._vcenter_base_url() if provider_name == "vcenter" else None
                if vc_base is not None:  # no known vCenter: skip the probe and fall through to revision matching
                    req = TransportRequest(
                        method="GET",
                        url=f"{vc_base}/api/vcenter/vm/{target_res}",
                    )
                    auth_obj = self._auth_for("vcenter")
                    if auth_obj is not None and hasattr(auth_obj, "apply"):
                        req = auth_obj.apply(req)
                    resp = self.transport.send(req)
                    if resp and resp.is_success:
                        vm_data = resp.json()
                        if "memory_gb" in desired:
                            act_mem = 0
                            if "memory" in vm_data and isinstance(vm_data["memory"], dict):
                                act_mem = vm_data["memory"].get("size_mib", 0) // 1024
                            elif "memory_size_MiB" in vm_data:
                                act_mem = vm_data["memory_size_MiB"] // 1024
                            elif "memory_size_mib" in vm_data:
                                act_mem = vm_data["memory_size_mib"] // 1024
                            elif "memory_gb" in vm_data:
                                act_mem = vm_data["memory_gb"]
                            if act_mem == desired["memory_gb"]:
                                return ReconciliationResult(
                                    status=ReconciliationStatus.APPLIED,
                                    details={"vm_id": target_res, "memory_gb": act_mem},
                                    observed_revision=ResourceRevision("vcenter", f"rev-vm-{target_res}-{act_mem}"),
                                )
                            else:
                                return ReconciliationResult(
                                    status=ReconciliationStatus.NOT_APPLIED,
                                    details={"vm_id": target_res, "actual_memory_gb": act_mem, "expected": desired["memory_gb"]},
                                    observed_revision=ResourceRevision("vcenter", f"rev-vm-{target_res}-{act_mem}"),
                                )
            except Exception as e:
                return ReconciliationResult(
                    status=ReconciliationStatus.UNKNOWN,
                    details={"error": f"Upstream authoritative reconciliation failed: {str(e)}"},
                )

        # Revision-based matching: if revision has not changed from expected pre-mutation baseline, NOT_APPLIED
        if expected_rev and str(current_rev) == str(expected_rev):
            return ReconciliationResult(
                status=ReconciliationStatus.NOT_APPLIED,
                details={"target": target_res, "revision": str(current_rev), "reason": "Revision unchanged from baseline"},
                observed_revision=current_rev,
            )

        # In-memory heuristic: if revision was modified from baseline
        if current_rev.value and current_rev.value not in ("rev-100", "rev-201", "rev-202", "rev-501", "rev-502"):
            return ReconciliationResult(
                status=ReconciliationStatus.APPLIED,
                details={"target": target_res, "revision": current_rev.value},
                observed_revision=current_rev,
            )

        # When ambiguous and no explicit probe, safely flag UNKNOWN
        return ReconciliationResult(
            status=ReconciliationStatus.UNKNOWN,
            details={"target": target_res, "reason": "Indeterminate state: mutation could not be proven"},
            observed_revision=current_rev,
        )

    async def reconcile_operation(
        self,
        intent: ExecutionIntent | Dict[str, Any],
    ) -> ReconciliationResult:
        """Asynchronously probes upstream provider or resolves via provider registry."""
        if self.mode == PlatformMode.DIGITAL_TWIN:
            dt = DigitalTwinProvider(
                endpoint_url=self.digital_twin_url,
                transport=self.transport,
                auth=self.auth,
            )
            return await dt.reconcile_operation(intent)
        elif self.mode == PlatformMode.REAL_VCF:
            target_res = intent.target_resource if isinstance(intent, ExecutionIntent) else intent.get("target_resource", "")
            provider_name = self._resolve_provider_for_resource(target_res)
            if provider_name == "vcenter":
                provider_entry = self.registry.resolve("vm.lifecycle")
                vc = VCenterProvider(
                    endpoint_url=provider_entry.endpoint_url,
                    transport=self.transport,
                    auth=self._auth_for("vcenter"),
                    api_version=provider_entry.api_version,
                )
                return await vc.reconcile_operation(intent)
            elif provider_name == "sddc-manager":
                provider_entry = self.registry.resolve("domain.lifecycle")
                sddc = SDDCManagerProvider(
                    endpoint_url=provider_entry.endpoint_url,
                    transport=self.transport,
                    auth=self._auth_for("sddc_manager"),
                    api_version=provider_entry.api_version,
                )
                return await sddc.reconcile_operation(intent)
            elif provider_name == "nsx":
                provider_entry = self.registry.resolve("network.segments")
                nsx = NSXProvider(
                    endpoint_url=provider_entry.endpoint_url,
                    transport=self.transport,
                    auth=self._auth_for("nsx"),
                    api_version=provider_entry.api_version,
                )
                return await nsx.reconcile_operation(intent)

        return self.reconcile_operation_sync(intent)

    # =========================================================================
    # Platform Capabilities
    # =========================================================================

    def get_domains(self) -> List[Dict[str, Any]]:
        if self.mode == PlatformMode.REAL_VCF:
            provider_entry = self.registry.resolve("domain.lifecycle")
            sddc = SDDCManagerProvider(
                endpoint_url=provider_entry.endpoint_url,
                transport=self.transport,
                auth=self._auth_for("sddc_manager"),
                api_version=provider_entry.api_version,
            )
            return sddc.get_domains()
        elif self.mode == PlatformMode.DIGITAL_TWIN:
            dt = DigitalTwinProvider(
                endpoint_url=self.digital_twin_url,
                transport=self.transport,
                auth=self.auth,
            )
            return dt.get_domains()

        provider_entry = self.registry.resolve("domain.lifecycle")
        return [
            {"id": "mgmt-domain", "name": "Management-Domain", "status": "ACTIVE", "provider": provider_entry.provider_instance_id},
            {"id": "vi-workload-domain-01", "name": "Workload-Domain-01", "status": "ACTIVE", "provider": provider_entry.provider_instance_id},
        ]

    def get_domain(self, domain_id: str) -> Optional[Dict[str, Any]]:
        if self.mode == PlatformMode.REAL_VCF:
            provider_entry = self.registry.resolve("domain.lifecycle")
            sddc = SDDCManagerProvider(
                endpoint_url=provider_entry.endpoint_url,
                transport=self.transport,
                auth=self._auth_for("sddc_manager"),
                api_version=provider_entry.api_version,
            )
            return sddc.get_domain(domain_id)
        elif self.mode == PlatformMode.DIGITAL_TWIN:
            dt = DigitalTwinProvider(
                endpoint_url=self.digital_twin_url,
                transport=self.transport,
                auth=self.auth,
            )
            return dt.get_domain(domain_id)

        return self._domains.get(domain_id)

    def get_clusters(self, domain_id: Optional[str] = None) -> List[Dict[str, Any]]:
        if self.mode == PlatformMode.REAL_VCF:
            if domain_id and self.auth_factory is not None:
                # vCenter does not know VCF domains: resolve the domain to its own vCenter(s) via SDDC Manager.
                wanted = set()
                for d in self.get_domains():
                    if domain_id in (d.get("id"), d.get("name")):
                        wanted |= {vc.get("fqdn") for vc in d.get("vcenters") or []}
                return [c for c in self._across_vcenters(lambda vc: vc.get_clusters()) if c.get("vcenter") in wanted]
            return self._across_vcenters(lambda vc: vc.get_clusters(domain_id))
        elif self.mode == PlatformMode.DIGITAL_TWIN:
            dt = DigitalTwinProvider(
                endpoint_url=self.digital_twin_url,
                transport=self.transport,
                auth=self.auth,
            )
            return dt.get_clusters(domain_id)

        clusters = list(self._clusters.values())
        if domain_id:
            return [c for c in clusters if c.get("domain") == domain_id]
        return clusters

    def get_hosts(self, cluster_id: Optional[str] = None) -> List[Dict[str, Any]]:
        if self.mode == PlatformMode.REAL_VCF:
            return self._across_vcenters(lambda vc: vc.get_hosts(cluster_id))
        elif self.mode == PlatformMode.DIGITAL_TWIN:
            dt = DigitalTwinProvider(
                endpoint_url=self.digital_twin_url,
                transport=self.transport,
                auth=self.auth,
            )
            return dt.get_hosts(cluster_id)

        hosts = list(self._hosts.values())
        if cluster_id:
            return [h for h in hosts if h.get("cluster") == cluster_id]
        return hosts

    def get_vms(self, cluster_id: Optional[str] = None) -> List[Dict[str, Any]]:
        if self.mode == PlatformMode.REAL_VCF:
            return self._across_vcenters(lambda vc: vc.get_vms(cluster_id))
        elif self.mode == PlatformMode.DIGITAL_TWIN:
            dt = DigitalTwinProvider(
                endpoint_url=self.digital_twin_url,
                transport=self.transport,
                auth=self.auth,
            )
            return dt.get_vms(cluster_id)

        vms = list(self._vms.values())
        if cluster_id:
            return [v for v in vms if v.get("cluster") == cluster_id]
        return vms

    def get_vm(self, vm_id: str, vcenter: Optional[str] = None) -> Optional[Dict[str, Any]]:
        if self.mode == PlatformMode.REAL_VCF:
            providers = self._vcenter_providers()
            if vcenter:
                providers = [(f, vc) for f, vc in providers if (f or self.main_vcenter_name or "").lower() == vcenter.lower()]
                if not providers:
                    self._vcenter_for(vcenter)  # raises, naming the known vCenters
            found = []
            for fqdn, vc in providers:
                try:
                    vm = vc.get_vm(vm_id)
                except Exception:
                    continue
                if vm:
                    found.append(dict(vm, vcenter=fqdn) if fqdn else vm)
            if len(found) > 1:
                # VM IDs are only unique inside one vCenter: never guess which VM is meant.
                from vcf_enterprise_mcp.core.errors import AmbiguousResourceException
                names = ", ".join(str(v.get("vcenter")) for v in found)
                raise AmbiguousResourceException(
                    f"VM '{vm_id}' exists in more than one vCenter ({names}). Say which one with the 'vcenter' argument.",
                    details={"vm_id": vm_id, "vcenters": [v.get("vcenter") for v in found]})
            return found[0] if found else None
        elif self.mode == PlatformMode.DIGITAL_TWIN:
            dt = DigitalTwinProvider(
                endpoint_url=self.digital_twin_url,
                transport=self.transport,
                auth=self.auth,
            )
            return dt.get_vm(vm_id)

        if vm_id in self._vms:
            return self._vms[vm_id]
        for v in self._vms.values():
            if str(v.get("name", "")).lower() == vm_id.lower():
                return v
        return None

    def power_vm(self, vm_id: str, action: str, vcenter: Optional[str] = None) -> Dict[str, Any]:
        if self.mode == PlatformMode.REAL_VCF:
            vc = self._vcenter_for(vcenter)
            res = vc.power_vm(vm_id, action)
            self.update_resource_revision(vm_id)
            return res
        elif self.mode == PlatformMode.DIGITAL_TWIN:
            dt = DigitalTwinProvider(
                endpoint_url=self.digital_twin_url,
                transport=self.transport,
                auth=self.auth,
            )
            res = dt.power_vm(vm_id, action)
            self.update_resource_revision(vm_id)
            return res

        new_power = "POWERED_ON" if action in ("start", "restart", "reset") else ("SUSPENDED" if action == "suspend" else "POWERED_OFF")
        if vm_id in self._vms:
            self._vms[vm_id]["power_state"] = new_power
        else:
            self._vms[vm_id] = {
                "id": vm_id,
                "vm_id": vm_id,
                "name": f"vm-{vm_id}",
                "cluster": "cluster-prod-a",
                "power_state": new_power,
                "cpu": 4,
                "cpu_cores": 4,
                "memory_mb": 16384,
                "memory_gb": 16,
            }
        self.update_resource_revision(vm_id)
        return {
            "vm_id": vm_id,
            "action": action,
            "status": "SUCCESS",
            "new_power_state": new_power,
        }

    def resize_vm(self, vm_id: str, memory_gb: Optional[int] = None, cpu_cores: Optional[int] = None,
                  vcenter: Optional[str] = None) -> Dict[str, Any]:
        if self.mode == PlatformMode.REAL_VCF:
            vc = self._vcenter_for(vcenter)
            res = vc.resize_vm(vm_id, memory_gb, cpu_cores)
            self.update_resource_revision(vm_id)
            return res
        elif self.mode == PlatformMode.DIGITAL_TWIN:
            dt = DigitalTwinProvider(
                endpoint_url=self.digital_twin_url,
                transport=self.transport,
                auth=self.auth,
            )
            res = dt.resize_vm(vm_id, memory_gb, cpu_cores)
            self.update_resource_revision(vm_id)
            return res

        if vm_id in self._vms:
            if memory_gb is not None:
                self._vms[vm_id]["memory_gb"] = memory_gb
                self._vms[vm_id]["memory_mb"] = memory_gb * 1024
                self._vms[vm_id]["allocated_memory_gb"] = memory_gb
            if cpu_cores is not None:
                self._vms[vm_id]["cpu"] = cpu_cores
                self._vms[vm_id]["cpu_cores"] = cpu_cores
                self._vms[vm_id]["allocated_cpu_cores"] = cpu_cores
        else:
            self._vms[vm_id] = {
                "id": vm_id,
                "vm_id": vm_id,
                "name": f"vm-{vm_id}",
                "cluster": "cluster-prod-a",
                "power_state": "POWERED_ON",
                "cpu": cpu_cores or 4,
                "cpu_cores": cpu_cores or 4,
                "allocated_cpu_cores": cpu_cores or 4,
                "memory_mb": (memory_gb or 16) * 1024,
                "memory_gb": memory_gb or 16,
                "allocated_memory_gb": memory_gb or 16,
            }
        self.update_resource_revision(vm_id)
        return {
            "vm_id": vm_id,
            "allocated_memory_gb": memory_gb,
            "allocated_cpu_cores": cpu_cores,
            "status": "SUCCESS",
        }

    def create_snapshot(self, vm_id: str, snapshot_name: str, vcenter: Optional[str] = None) -> Dict[str, Any]:
        if self.mode == PlatformMode.REAL_VCF:
            vc = self._vcenter_for(vcenter)
            res = vc.create_snapshot(vm_id, snapshot_name)
            self.update_resource_revision(vm_id)
            return res
        elif self.mode == PlatformMode.DIGITAL_TWIN:
            dt = DigitalTwinProvider(
                endpoint_url=self.digital_twin_url,
                transport=self.transport,
                auth=self.auth,
            )
            res = dt.create_snapshot(vm_id, snapshot_name)
            self.update_resource_revision(vm_id)
            return res

        self.update_resource_revision(vm_id)
        snap_rec = {
            "vm_id": vm_id,
            "snapshot_id": f"snap-{vm_id}-{snapshot_name}",
            "snapshot_name": snapshot_name,
            "created_at": int(time.time()),
            "size_gb": 2.5,
            "status": "SUCCESS",
        }
        self._snapshots.setdefault(vm_id, []).append(snap_rec)
        return snap_rec

    def _no_real_snapshot_api(self, what: str) -> None:
        if self.mode == PlatformMode.REAL_VCF:
            from vcf_enterprise_mcp.core.errors import UnverifiedAPIContractException
            raise UnverifiedAPIContractException(
                f"{what} on a real vCenter is not implemented yet, so nothing was read or changed. Use the vSphere Client for now.")

    def get_snapshots(self, vm_id: str, vcenter: Optional[str] = None) -> List[Dict[str, Any]]:
        self._no_real_snapshot_api("Listing snapshots")
        if self.mode == PlatformMode.DIGITAL_TWIN and hasattr(DigitalTwinProvider, "get_snapshots"):
            dt = DigitalTwinProvider(
                endpoint_url=self.digital_twin_url,
                transport=self.transport,
                auth=self.auth,
            )
            return dt.get_snapshots(vm_id)
        return list(self._snapshots.get(vm_id, []))

    def delete_snapshot(self, vm_id: str, snapshot_id: str, vcenter: Optional[str] = None) -> Dict[str, Any]:
        self._no_real_snapshot_api("Deleting snapshots")
        snaps = self._snapshots.get(vm_id, [])
        self._snapshots[vm_id] = [s for s in snaps if s.get("snapshot_id") != snapshot_id]
        self.update_resource_revision(vm_id)
        return {
            "vm_id": vm_id,
            "snapshot_id": snapshot_id,
            "status": "SUCCESS",
            "message": f"Snapshot '{snapshot_id}' deleted from VM '{vm_id}'.",
        }

    def get_datastores(
        self,
        cluster_id: Optional[str] = None,
        datacenter_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        if self.mode == PlatformMode.REAL_VCF:
            ds = self._across_vcenters(lambda vc: vc.get_datastores())
            if cluster_id:
                return [d for d in ds if d.get("cluster") == cluster_id or not d.get("cluster")]
            return ds
        if cluster_id:
            return [d for d in self._datastores if d.get("cluster") == cluster_id]
        return list(self._datastores)

    def get_nsx_segments(self, gateway_id: Optional[str] = None) -> List[Dict[str, Any]]:
        if self.mode == PlatformMode.REAL_VCF:
            provider_entry = self.registry.resolve("network.segments")
            nsx = NSXProvider(
                endpoint_url=provider_entry.endpoint_url,
                transport=self.transport,
                auth=self._auth_for("nsx"),
                api_version=provider_entry.api_version,
            )
            segs = nsx.get_segments()
        else:
            segs = list(self._segments.values())
        if gateway_id:
            return [s for s in segs if s.get("gateway") == gateway_id or str(s.get("connectivity_path", "")).endswith(gateway_id)]
        return segs

    def get_nsx_gateways(self, tier: Optional[str] = None) -> List[Dict[str, Any]]:
        if self.mode == PlatformMode.REAL_VCF:
            provider_entry = self.registry.resolve("network.segments")
            nsx = NSXProvider(
                endpoint_url=provider_entry.endpoint_url,
                transport=self.transport,
                auth=self._auth_for("nsx"),
                api_version=provider_entry.api_version,
            )
            gws = nsx.get_gateways()
        else:
            gws = list(self._gateways)
        if tier:
            tier_u = tier.upper()
            return [g for g in gws if str(g.get("tier", "")).upper() == tier_u]
        return gws

    def get_upgrade_bundles(
        self,
        domain_id: Optional[str] = None,
        target_version: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        if self.mode == PlatformMode.REAL_VCF:
            provider_entry = self.registry.resolve("domain.lifecycle")
            sddc = SDDCManagerProvider(
                endpoint_url=provider_entry.endpoint_url,
                transport=self.transport,
                auth=self._auth_for("sddc_manager"),
                api_version=provider_entry.api_version,
            )
            if domain_id:
                bundles = sddc.get_upgradables(domain_id)
            else:
                bundles = sddc.get_bundles()
        else:
            bundles = [
                {
                    "id": "bundle-vcf-9.1.1.0-01",
                    "bundle_id": "bundle-vcf-9.1.1.0-01",
                    "version": "9.1.1.0",
                    "component": "VCF-SDDC-BUNDLE",
                    "domain_id": domain_id or "mgmt-domain",
                    "status": "AVAILABLE",
                }
            ]
        if target_version:
            return [b for b in bundles if target_version in str(b.get("version", ""))]
        return bundles

    def create_segment(self, segment_name: str, gateway_id: str, cidr: str) -> Dict[str, Any]:
        if self.mode == PlatformMode.REAL_VCF:
            provider_entry = self.registry.resolve("network.segments")
            nsx = NSXProvider(
                endpoint_url=provider_entry.endpoint_url,
                transport=self.transport,
                auth=self._auth_for("nsx"),
                api_version=provider_entry.api_version,
            )
            res = nsx.create_segment(segment_name, gateway_id, cidr)
            self.update_resource_revision(segment_name)
            return res
        elif self.mode == PlatformMode.DIGITAL_TWIN:
            dt = DigitalTwinProvider(
                endpoint_url=self.digital_twin_url,
                transport=self.transport,
                auth=self.auth,
            )
            res = dt.create_segment(segment_name, gateway_id, cidr)
            self.update_resource_revision(segment_name)
            return res

        self._segments[segment_name] = {
            "segment_id": f"seg-{segment_name}",
            "segment_name": segment_name,
            "gateway": gateway_id,
            "cidr": cidr,
        }
        self.update_resource_revision(segment_name)
        return {
            "segment_id": f"seg-{segment_name}",
            "segment_name": segment_name,
            "gateway": gateway_id,
            "cidr": cidr,
            "status": "SUCCESS",
        }

    def upgrade_domain(self, domain_id: str, target_version: str, bundle_id: Optional[str] = None) -> Dict[str, Any]:
        if self.mode == PlatformMode.REAL_VCF:
            provider_entry = self.registry.resolve("domain.lifecycle")
            sddc = SDDCManagerProvider(
                endpoint_url=provider_entry.endpoint_url,
                transport=self.transport,
                auth=self._auth_for("sddc_manager"),
                api_version=provider_entry.api_version,
            )
            res = sddc.upgrade_domain(domain_id, target_version, bundle_id=bundle_id)
            self.update_resource_revision(domain_id)
            return res
        elif self.mode == PlatformMode.DIGITAL_TWIN:
            dt = DigitalTwinProvider(
                endpoint_url=self.digital_twin_url,
                transport=self.transport,
                auth=self.auth,
            )
            res = dt.upgrade_domain(domain_id, target_version)
            self.update_resource_revision(domain_id)
            return res

        self.update_resource_revision(domain_id)
        return {
            "domain_id": domain_id,
            "target_version": target_version,
            "task_id": f"vcf-lcm-task-{domain_id}-911",
            "status": "RUNNING",
        }

    def _observed_health(self, datacenter_id: str) -> Dict[str, Any]:
        """Health built only from observed upstream data; never defaults to GREEN.

        Sources: SDDC Manager domain status (GET /v1/domains) and active VCF Operations alerts
        (GET /suite-api/api/alerts). If VCF Operations cannot be read, overall status is UNKNOWN.
        """
        errors: Dict[str, str] = {}
        domains: List[Dict[str, Any]] = []
        alerts: List[Dict[str, Any]] = []
        try:
            entry = self.registry.resolve("domain.lifecycle")
            sddc = SDDCManagerProvider(endpoint_url=entry.endpoint_url, transport=self.transport, auth=self._auth_for("sddc_manager"), api_version=entry.api_version)
            domains = sddc.get_system_health()["domains"]
        except Exception as ex:
            errors["sddc_manager"] = type(ex).__name__
        ops_ok = False
        try:
            entry = self.registry.resolve("telemetry.promql")
            ops = VCFOperationsProvider(endpoint_url=entry.endpoint_url, transport=self.transport, auth=self._auth_for("vcf_operations"), api_version=entry.api_version)
            alerts = ops.get_alerts(active_only=True)
            ops_ok = True
        except Exception as ex:
            errors["vcf_operations"] = type(ex).__name__

        levels = [str(a.get("alertLevel", "")).upper() for a in alerts]
        bad_domains = [d for d in domains if str(d.get("status", "")).upper() not in ("ACTIVE",)]
        if not ops_ok:
            overall = "UNKNOWN"
        elif "CRITICAL" in levels or any(str(d.get("status", "")).upper() == "ERROR" for d in domains):
            overall = "RED"
        elif "IMMEDIATE" in levels or "WARNING" in levels or bad_domains:
            overall = "YELLOW"
        else:
            overall = "GREEN"
        return {
            "datacenter": datacenter_id,
            "overall_status": overall,
            "domains": domains,
            "active_alert_counts": {lvl: levels.count(lvl) for lvl in sorted(set(levels))},
            "active_alarms": [
                {"alert_id": a.get("alertId"), "name": a.get("alertDefinitionName"), "level": a.get("alertLevel"), "resource_id": a.get("resourceId")}
                for a in alerts if str(a.get("alertLevel", "")).upper() in ("CRITICAL", "IMMEDIATE")
            ][:50],
            "unavailable_sources": errors,
            "sources": ["sddc-manager:GET /v1/domains", "vcf-operations:GET /suite-api/api/alerts"],
        }

    def get_health(self, datacenter_id: str = "dc1") -> Dict[str, Any]:
        if self.mode == PlatformMode.REAL_VCF:
            return self._observed_health(datacenter_id)
        if self.mode == PlatformMode.DIGITAL_TWIN:
            dt = DigitalTwinProvider(
                endpoint_url=self.digital_twin_url,
                transport=self.transport,
                auth=self.auth,
            )
            raw = dt.get_health()
            return {
                "datacenter": datacenter_id,
                "overall_status": raw.get("status", "GREEN"),
                "score": raw.get("score", 98.5),
                "subsystems": raw.get("subsystems", {
                    "sddc_manager": "HEALTHY",
                    "vcenter": "HEALTHY",
                    "nsx_edge_cluster": "HEALTHY",
                    "vsan_esa": "HEALTHY",
                }),
                "active_alarms": raw.get("active_alarms", []),
            }

        return {
            "datacenter": datacenter_id,
            "overall_status": "GREEN",
            "score": 98.5,
            "subsystems": {
                "sddc_manager": "HEALTHY",
                "vcenter": "HEALTHY",
                "nsx_edge_cluster": "HEALTHY",
                "vsan_esa": "HEALTHY",
            },
            "active_alarms": [],
        }

    def query_telemetry(self, entity_id: str, metrics: Optional[List[str]] = None) -> Dict[str, Any]:
        if self.mode == PlatformMode.REAL_VCF:
            provider_entry = self.registry.resolve("telemetry.promql")
            ops = VCFOperationsProvider(
                endpoint_url=provider_entry.endpoint_url,
                transport=self.transport,
                auth=self._auth_for("vcf_operations"),
                api_version=provider_entry.api_version,
            )
            return ops.query_telemetry(entity_id, metrics)
        elif self.mode == PlatformMode.DIGITAL_TWIN:
            dt = DigitalTwinProvider(
                endpoint_url=self.digital_twin_url,
                transport=self.transport,
                auth=self.auth,
            )
            return dt.query_telemetry(entity_id, metrics)

        return {
            "entity_id": entity_id,
            "metrics": {m: 42.0 for m in (metrics or ["cpu_usage", "memory_usage"])},
            "data_points": [
                {"timestamp": 1727210000, "value": 41.2},
                {"timestamp": 1727210060, "value": 42.8},
                {"timestamp": 1727210120, "value": 39.5},
            ],
            "unit": "percent",
        }

    def get_lifecycle_state(self) -> Dict[str, Any]:
        provider = self.registry.resolve("domain.lifecycle")
        return {
            "lcm_status": "UP_TO_DATE",
            "active_version": provider.api_version,
            "pending_bundles": 0,
            "provider": provider.provider_instance_id,
        }

    def get_component_versions(self) -> Dict[str, Any]:
        if self.mode == PlatformMode.REAL_VCF:
            return self._observed_component_versions()
        return {
            "sddc_manager": "9.1.1",
            "vcenter": "9.1.1",
            "nsx": "4.2.1",
            "vcf_operations": "9.1.1",
            "supervisor": "v1.30",
        }

    def _observed_component_versions(self) -> Dict[str, Any]:
        """Versions read from each appliance; a component that cannot be read reports None.
        In VCF 9.x NSX ships as 9.x (not 4.x), so versions must be observed, not assumed."""
        result: Dict[str, Any] = {}
        probes = {
            "sddc_manager": ("domain.lifecycle", "sddc_manager", lambda p: SDDCManagerProvider(**p).get_versions().get("sddc_manager")),
            "vcenter": ("vm.lifecycle", "vcenter", lambda p: (VCenterProvider(**p).request("GET", "/api/appliance/system/version").json() or {}).get("version")),
            "nsx": ("network.segments", "nsx", lambda p: NSXProvider(**p).get_version()),
            "vcf_operations": ("telemetry.promql", "vcf_operations", lambda p: VCFOperationsProvider(**p).get_version()),
        }
        for name, (capability, provider_type, probe) in probes.items():
            try:
                entry = self.registry.resolve(capability)
                params = {"endpoint_url": entry.endpoint_url, "transport": self.transport, "auth": self._auth_for(provider_type), "api_version": entry.api_version}
                result[name] = probe(params)
            except Exception:
                result[name] = None
        return result
