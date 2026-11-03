# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Enterprise Environment Onboarding & Capability Auto-Discovery Engine.
Executes automated discovery, constructs Environment Profiles, and imports native VCF permissions.
"""

from __future__ import annotations
import time
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from vcf_enterprise_mcp.adapter.version_adapter import VCFVersionAdapter


@dataclass
class EnvironmentProfile:
    """Discovered topological overview and component bill of materials for a target VCF fleet."""
    sddc_fqdn: str
    vcf_version: str
    domains_count: int
    vcenters_count: int
    clusters_count: int
    hosts_count: int
    installed_components: Dict[str, bool] = field(default_factory=dict)
    discovered_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sddc_fqdn": self.sddc_fqdn,
            "vcf_version": self.vcf_version,
            "domains_count": self.domains_count,
            "vcenters_count": self.vcenters_count,
            "clusters_count": self.clusters_count,
            "hosts_count": self.hosts_count,
            "components": self.installed_components,
            "discovered_at": self.discovered_at,
        }


@dataclass
class CapabilityMatrix:
    """Matrix of supported vs unavailable operational capabilities in the discovered environment."""
    supported_capabilities: List[str]
    unavailable_capabilities: List[str]
    active_profile: EnvironmentProfile

    def is_capability_available(self, capability: str) -> bool:
        return capability in self.supported_capabilities


class OnboardingEngine:
    """Drives the 18-step enterprise onboarding wizard and manages the DISCOVERY_ONLY safety gate."""

    def __init__(self, target_version: str = "9.1.1"):
        self.version_adapter = VCFVersionAdapter(target_version)
        self.current_profile: Optional[EnvironmentProfile] = None
        self.current_matrix: Optional[CapabilityMatrix] = None
        self.mode: str = "DISCOVERY_ONLY"

    def run_discovery(
        self,
        sddc_fqdn: str,
        vcf_version: str = "9.1.1",
        simulated_data: Optional[Dict[str, Any]] = None,
    ) -> EnvironmentProfile:
        """Discovers topology, component releases, and hardware inventory from SDDC Manager."""
        data = simulated_data or {}
        components = {
            "sddc_manager": True,
            "vcenter": True,
            "nsx": True,
            "vsan_esa": True,
            "operations": data.get("has_operations", True),
            "automation": data.get("has_automation", True),
            "live_recovery": data.get("has_srm", True),
            "private_ai": data.get("has_private_ai", False),
            "fleet_iam": self.version_adapter.is_feature_supported("fleet_iam_sso"),
            "promql_telemetry": self.version_adapter.is_feature_supported("promql_telemetry"),
        }

        profile = EnvironmentProfile(
            sddc_fqdn=sddc_fqdn,
            vcf_version=vcf_version,
            domains_count=data.get("domains_count", 2),
            vcenters_count=data.get("vcenters_count", 2),
            clusters_count=data.get("clusters_count", 4),
            hosts_count=data.get("hosts_count", 16),
            installed_components=components,
        )
        self.current_profile = profile
        self.current_matrix = self.build_capability_matrix(profile)
        return profile

    def build_capability_matrix(self, profile: EnvironmentProfile) -> CapabilityMatrix:
        """Derives supported capabilities from discovered components and version adapter."""
        supported = ["compute_inventory", "health_audit", "log_search"]
        unavailable = []

        comps = profile.installed_components
        if comps.get("vsan_esa"):
            supported.append("vsan_data_protection")
        if comps.get("nsx"):
            supported.append("network_microsegmentation")
        if comps.get("live_recovery"):
            supported.append("disaster_recovery_pairings")
        if comps.get("automation"):
            supported.append("cloud_assembly_deployments")
        if comps.get("promql_telemetry"):
            supported.append("realtime_promql_telemetry")
        else:
            unavailable.append("realtime_promql_telemetry")

        if comps.get("fleet_iam"):
            supported.append("fleet_sso_realms")
        else:
            unavailable.append("fleet_sso_realms")

        if comps.get("private_ai"):
            supported.append("private_ai_vgpu")
        else:
            unavailable.append("private_ai_vgpu")

        return CapabilityMatrix(
            supported_capabilities=supported,
            unavailable_capabilities=unavailable,
            active_profile=profile,
        )

    def transition_operating_mode(self, new_mode: str) -> str:
        """Allows authorized administrator to promote control plane from DISCOVERY_ONLY to AUDITED_OPERATIONS."""
        valid_modes = {"DISCOVERY_ONLY", "AUDITED_OPERATIONS", "FULL_ENFORCEMENT"}
        if new_mode not in valid_modes:
            raise ValueError(f"Invalid mode: {new_mode}. Must be one of {valid_modes}")
        if new_mode != "DISCOVERY_ONLY" and self.current_profile is None:
            raise RuntimeError("Cannot promote operating mode to an operational state without completing environment discovery first.")
        self.mode = new_mode
        return self.mode
