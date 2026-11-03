# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
VCF Real-World Certification Runner.
Enforces SDDC Manager Independence: verifies vCenter-direct, NSX-direct,
and SDDC-Manager-mediated operations independently against target profiles.
"""

from __future__ import annotations
import os
import time
import yaml
from pathlib import Path
from typing import Dict, Any, List, Optional

from vcf_enterprise_mcp.certification.models import (
    VerificationLevel,
    ComponentType,
    CertificationOperation,
    CertificationProfile,
    OperationResult,
    CertificationResult,
)
from vcf_enterprise_mcp.adapter.platform import PlatformClient, PlatformMode
from vcf_enterprise_mcp.auth.untrusted import sanitize_freeform_string


PROFILES_DIR = Path(__file__).parent / "profiles"


def load_profile(profile_name_or_path: str) -> CertificationProfile:
    """Loads a certification profile from yaml name or file path."""
    if os.path.exists(profile_name_or_path):
        path = Path(profile_name_or_path)
    else:
        candidates = [
            PROFILES_DIR / f"{profile_name_or_path}.yaml",
            PROFILES_DIR / f"{profile_name_or_path}.yml",
            PROFILES_DIR / profile_name_or_path,
        ]
        path = next((c for c in candidates if c.exists()), None)
        if not path:
            raise FileNotFoundError(f"Certification profile '{profile_name_or_path}' not found in {PROFILES_DIR}")

    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    operations: List[CertificationOperation] = []
    for op_raw in data.get("operations", []):
        operations.append(
            CertificationOperation(
                name=op_raw["name"],
                component=ComponentType(op_raw["component"]),
                transport_route=op_raw.get("transport_route", "direct"),
                required_capabilities=op_raw.get("required_capabilities", []),
                description=op_raw.get("description", ""),
                is_destructive=op_raw.get("is_destructive", False),
                test_params=op_raw.get("test_params", {}),
            )
        )

    return CertificationProfile(
        profile_name=data.get("profile_name", path.stem),
        vcf_version=data.get("vcf_version", "unknown"),
        component_versions=data.get("component_versions", {}),
        operations=operations,
        metadata=data.get("metadata", {}),
    )


class CertificationRunner:
    """
    Executes a VCF interoperability certification suite against a target PlatformClient.
    Enforces independent evaluation of direct vs mediated component paths.
    """

    def __init__(
        self,
        platform_client: Optional[PlatformClient] = None,
        registry: Optional[Any] = None,
    ):
        self._injected_platform = platform_client is not None
        self.platform = platform_client or PlatformClient()
        self.registry = registry

    def run_profile(
        self,
        profile: CertificationProfile,
        verification_level: Optional[VerificationLevel] = None,
        skip_destructive: bool = False,
        target: Optional[str] = None,
    ) -> CertificationResult:
        """Executes all operations specified in the profile and compiles certification results."""
        if target not in (None, "digital_twin", "real_vcf"):
            raise ValueError("Unknown certification target")
        if target and not self._injected_platform:
            from vcf_enterprise_mcp.config.settings import get_enterprise_settings
            from vcf_enterprise_mcp.adapter.transport.http import HTTPTransport
            cfg = get_enterprise_settings()
            self.platform = PlatformClient(
                mode=PlatformMode.DIGITAL_TWIN if target == "digital_twin" else PlatformMode.REAL_VCF,
                transport=HTTPTransport(max_retries=0, verify_ssl=cfg.vcf.verify_ssl, ca_cert_path=cfg.vcf.ca_cert_path),
                digital_twin_url=cfg.vcf.gateway_url,
            )
        simulated = (self.platform.mode == PlatformMode.UNIT_TEST or
                     getattr(self.platform.transport, "mock_handler", None) is not None)
        verification_level = VerificationLevel.UNIT_TEST_ONLY if simulated else VerificationLevel.UNVERIFIED
        writes = {"power_vm", "resize_vm", "create_snapshot", "create_segment", "upgrade_domain"}

        results: List[OperationResult] = []

        for op in profile.operations:
            if (skip_destructive and op.is_destructive) or (not simulated and op.name in writes):
                results.append(
                    OperationResult(
                        operation_name=op.name,
                        component=op.component,
                        transport_route=op.transport_route,
                        verification_level=verification_level,
                        status="SKIPPED",
                        latency_ms=0.0,
                        details={"reason": "Write operation excluded: use the signed-plan test-resource E2E harness"},
                    )
                )
                continue

            op_result = self._execute_operation(op, verification_level)
            results.append(op_result)

        executed = [r for r in results if r.status != "SKIPPED"]
        if not simulated and executed and all(r.status == "PASS" for r in executed):
            verification_level = (VerificationLevel.DIGITAL_TWIN_VERIFIED if self.platform.mode == PlatformMode.DIGITAL_TWIN
                                  else VerificationLevel.REAL_VCF_VERIFIED)

        return CertificationResult(
            profile_name=profile.profile_name,
            vcf_version=profile.vcf_version,
            verification_level=verification_level,
            timestamp=time.time(),
            operation_results=results,
        )

    def run_all_profiles(self, target: Optional[str] = None) -> List[CertificationResult]:
        """Executes all standard VCF certification profiles."""
        profiles = ["vcf_9_0_0", "vcf_9_1_0", "vcf_9_1_1"]
        results: List[CertificationResult] = []
        for p in profiles:
            try:
                prof = load_profile(p)
                results.append(self.run_profile(prof, target=target))
            except Exception:
                raise
        return results

    def _execute_operation(
        self,
        op: CertificationOperation,
        verification_level: VerificationLevel,
    ) -> OperationResult:
        """Executes a single certification operation and measures performance and accuracy."""
        start_time = time.perf_counter()
        params = op.test_params or {}
        before = getattr(self.platform.transport, "network_response_count", 0)

        try:
            res: Any = None
            if op.name == "get_domains":
                res = self.platform.get_domains()
            elif op.name == "get_system_health":
                dc_id = params.get("datacenter_id", "dc1")
                res = self.platform.get_health(datacenter_id=dc_id)
                unavailable = res.get("unavailable_sources", {}) if isinstance(res, dict) else {}
                if "sddc_manager" in unavailable:
                    raise ValueError(f"SDDC Manager health source unavailable: {unavailable['sddc_manager']}")
            elif op.name == "upgrade_domain":
                domain_id = params.get("domain_id", "mgmt-domain")
                target_ver = params.get("target_version", "9.1.1")
                res = self.platform.upgrade_domain(domain_id, target_ver, bundle_id=params.get("bundle_id"))
            elif op.name == "get_vms":
                cluster_id = params.get("cluster_id")
                res = self.platform.get_vms(cluster_id=cluster_id)
            elif op.name == "get_vm":
                vm_id = params.get("vm_id", "vm-twin-101")
                if self.platform.mode == PlatformMode.DIGITAL_TWIN and vm_id == "vm-twin-101":
                    inventory = self.platform.get_vms()
                    if not inventory:
                        raise ValueError("Twin inventory is empty")
                    vm_id = inventory[0].get("vm") or inventory[0].get("id") or inventory[0].get("vm_id")
                res = self.platform.get_vm(vm_id)
            elif op.name == "power_vm":
                vm_id = params.get("vm_id", "vm-twin-101")
                action = params.get("action", "start")
                res = self.platform.power_vm(vm_id, action)
            elif op.name == "resize_vm":
                vm_id = params.get("vm_id", "vm-twin-101")
                cpu = params.get("cpu_cores", 8)
                ram = params.get("memory_gb", 32)
                res = self.platform.resize_vm(vm_id, memory_gb=ram, cpu_cores=cpu)
            elif op.name == "create_snapshot":
                vm_id = params.get("vm_id", "vm-twin-101")
                snap_name = params.get("snapshot_name", "snap-cert")
                res = self.platform.create_snapshot(vm_id, snap_name)
            elif op.name == "get_hosts":
                cluster_id = params.get("cluster_id")
                res = self.platform.get_hosts(cluster_id=cluster_id)
            elif op.name == "get_clusters":
                res = self.platform.get_clusters()
            elif op.name == "create_segment":
                seg_name = params.get("segment_name", "seg-cert-auto")
                gw_id = params.get("gateway_id", "t1-gw-01")
                cidr = params.get("cidr", "172.28.10.1/24")
                res = self.platform.create_segment(seg_name, gw_id, cidr)
            elif op.name == "query_telemetry":
                entity_id = params.get("entity_id", "cluster-twin-a")
                if self.platform.mode == PlatformMode.DIGITAL_TWIN and entity_id == "cluster-twin-a":
                    clusters = self.platform.get_clusters()
                    if not clusters:
                        raise ValueError("Twin cluster inventory is empty")
                    entity_id = clusters[0].get("cluster") or clusters[0].get("id")
                metrics = params.get("metrics", ["cpu_utilization_pct"])
                res = self.platform.query_telemetry(entity_id, metrics)
            else:
                raise ValueError(f"Unknown certification operation '{op.name}'")

            elapsed_ms = (time.perf_counter() - start_time) * 1000.0

            # Verification of response payload
            if res is None:
                raise ValueError(f"Operation '{op.name}' returned None")

            responses = getattr(self.platform.transport, "network_response_count", 0) - before
            if verification_level != VerificationLevel.UNIT_TEST_ONLY:
                if responses <= 0:
                    raise ValueError("No real HTTP response observed for requested operation")
                verification_level = (VerificationLevel.DIGITAL_TWIN_VERIFIED if self.platform.mode == PlatformMode.DIGITAL_TWIN
                                      else VerificationLevel.REAL_VCF_VERIFIED)
            if isinstance(res, dict) and res.get("status") in ("FAILED", "ERROR"):
                raise ValueError("Provider reported operation failure")
            return OperationResult(
                operation_name=op.name,
                component=op.component,
                transport_route=op.transport_route,
                verification_level=verification_level,
                status="PASS",
                latency_ms=round(elapsed_ms, 2),
                details={"http_responses": responses, "platform_mode": self.platform.mode.value, "scope": "provider transport check; not full MCP certification"},
            )

        except Exception as ex:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return OperationResult(
                operation_name=op.name,
                component=op.component,
                transport_route=op.transport_route,
                verification_level=verification_level,
                status="FAIL",
                latency_ms=round(elapsed_ms, 2),
                error_message=sanitize_freeform_string(str(ex)),
                details={"exception_type": ex.__class__.__name__},
            )
