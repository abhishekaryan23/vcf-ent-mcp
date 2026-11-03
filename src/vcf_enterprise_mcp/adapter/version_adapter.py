# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
VCF Multi-Version Adapter Layer (9.0.0 through 9.1.1).
Decouples LLM tool schemas from underlying Broadcom API differences across releases.
"""

from __future__ import annotations
from typing import Dict, Any, Optional
from vcf_enterprise_mcp.core.errors import VersionMismatchException


class VCFVersionAdapter:
    """
    Translates generic operational requests into version-specific VCF REST endpoints.
    Supports both uniform VCF release baselines and heterogeneous per-component versions
    (sddc_manager, vcenter, nsx, vcf_operations, vsan, srm).
    """

    # Baseline feature and API availability matrix
    FEATURE_MATRIX = {
        "promql_telemetry": {"9.0.0": False, "9.0.1": False, "9.0.2": False, "9.1.0": True, "9.1.1": True},
        "fleet_iam_sso": {"9.0.0": False, "9.0.1": False, "9.0.2": False, "9.1.0": True, "9.1.1": True},
        "vsan_esa_snapshots": {"9.0.0": True, "9.0.1": True, "9.0.2": True, "9.1.0": True, "9.1.1": True},
        "relax_1g_nic_validation": {"9.0.0": False, "9.0.1": False, "9.0.2": True, "9.1.0": True, "9.1.1": True},
        "uppercase_fqdn_fix": {"9.0.0": False, "9.0.1": False, "9.0.2": False, "9.1.0": False, "9.1.1": True},
    }

    # Mapping of features to their governing subsystems
    FEATURE_SUBSYSTEM_MAP = {
        "promql_telemetry": "vcf_operations",
        "fleet_iam_sso": "vcf_operations",
        "vsan_esa_snapshots": "vcenter",
        "relax_1g_nic_validation": "sddc_manager",
        "uppercase_fqdn_fix": "sddc_manager",
    }

    # Minimum version thresholds for semver comparison
    FEATURE_MIN_VERSION = {
        "promql_telemetry": "9.1.0",
        "fleet_iam_sso": "9.1.0",
        "vsan_esa_snapshots": "9.0.0",
        "relax_1g_nic_validation": "9.0.2",
        "uppercase_fqdn_fix": "9.1.1",
    }

    KNOWN_SUBSYSTEMS = ("sddc_manager", "vcenter", "nsx", "vcf_operations", "vsan", "srm")

    def __init__(
        self,
        target_version: str | Dict[str, str] = "9.1.1",
        component_versions: Optional[Dict[str, str]] = None,
    ):
        if isinstance(target_version, dict):
            comp_dict = target_version
            baseline = comp_dict.get("sddc_manager", "9.1.1")
        else:
            comp_dict = component_versions or {}
            baseline = target_version

        self.target_version = self.normalize_version(baseline)
        self.component_versions: Dict[str, str] = {}

        # Initialize defaults from target baseline
        for sub in self.KNOWN_SUBSYSTEMS:
            self.component_versions[sub] = self.target_version

        # Apply specific overrides
        for sub, ver in comp_dict.items():
            self.component_versions[sub] = self.normalize_version(ver)

    @staticmethod
    def normalize_version(version: str) -> str:
        parts = version.split(".")
        if len(parts) >= 3:
            return ".".join(parts[:3])
        return version

    @staticmethod
    def _is_version_ge(v1: str, v2: str) -> bool:
        """Helper comparing semver tuples e.g. '9.1.0' >= '9.0.0'."""
        try:
            p1 = [int(x) for x in v1.split(".")]
            p2 = [int(x) for x in v2.split(".")]
            return p1 >= p2
        except Exception:
            return v1 >= v2

    def get_component_version(self, subsystem: str) -> str:
        """Returns the active version for a specific subsystem."""
        return self.component_versions.get(subsystem, self.target_version)

    def set_component_version(self, subsystem: str, version: str) -> None:
        """Updates the active version for a specific subsystem."""
        self.component_versions[subsystem] = self.normalize_version(version)

    def get_all_component_versions(self) -> Dict[str, str]:
        """Returns a snapshot of all component versions."""
        return dict(self.component_versions)

    def is_feature_supported(
        self,
        feature_key: str,
        subsystem: Optional[str] = None,
        version: Optional[str] = None,
    ) -> bool:
        """
        Determines if a feature is supported.
        If version is explicitly provided, evaluates against that version.
        Else, evaluates against the resolved component version for the subsystem
        associated with the feature (or the specified subsystem).
        """
        if version is not None:
            eval_version = self.normalize_version(version)
        else:
            target_subsystem = subsystem or self.FEATURE_SUBSYSTEM_MAP.get(feature_key)
            if target_subsystem:
                eval_version = self.get_component_version(target_subsystem)
            else:
                eval_version = self.target_version

        # 1. Exact matrix lookup
        matrix = self.FEATURE_MATRIX.get(feature_key)
        if matrix and eval_version in matrix:
            return matrix[eval_version]

        # 2. Semver fallback against minimum introduced version
        min_ver = self.FEATURE_MIN_VERSION.get(feature_key)
        if min_ver:
            return self._is_version_ge(eval_version, min_ver)

        return False

    def adapt_endpoint(self, generic_action: str) -> str:
        """Returns the appropriate subsystem REST path for the active version baseline."""
        if generic_action == "telemetry.query":
            comp_ver = self.get_component_version("vcf_operations")
            if not self.is_feature_supported("promql_telemetry", subsystem="vcf_operations"):
                ver_display = comp_ver if comp_ver == self.target_version else f"{self.target_version} (vcf_operations {comp_ver})"
                raise VersionMismatchException(
                    f"PromQL real-time telemetry is not supported in VCF {ver_display}. Requires VCF 9.1.0+."
                )
            return "/api/v1/telemetry/query"

        if generic_action == "fleet_iam.sso_realms":
            comp_ver = self.get_component_version("vcf_operations")
            if not self.is_feature_supported("fleet_iam_sso", subsystem="vcf_operations"):
                ver_display = comp_ver if comp_ver == self.target_version else f"{self.target_version} (vcf_operations {comp_ver})"
                raise VersionMismatchException(
                    f"Fleet IAM SSO Realm management is not supported in VCF {ver_display}. Requires VCF 9.1.0+."
                )
            return "/suite-api/api/fleet-management/iam/sso-realms"

        if generic_action == "compute.vms":
            return "/api/vcenter/vm"

        if generic_action == "sddc.domains":
            return "/v1/domains"

        if generic_action == "nsx.segments":
            return "/policy/api/v1/infra/segments"

        return f"/api/{generic_action.replace('.', '/')}"

    def get_supported_baselines(self) -> Dict[str, str]:
        return {
            "9.0.0": "Initial VCF 9.0 release baseline (June 2025)",
            "9.0.1": "Maintenance update 1 (September 2025)",
            "9.0.2": "Maintenance update 2 with relaxed NIC check (January 2026)",
            "9.1.0": "Major release with PromQL & Fleet IAM (May 2026)",
            "9.1.1": "Current release baseline with uppercase FQDN fix (August 2026)",
        }

    def is_supported_baseline(self, version: str) -> bool:
        """Validates that a version is an approved, supported VCF baseline (F07)."""
        norm = self.normalize_version(version)
        if norm in self.get_supported_baselines():
            return True
        return self._is_version_ge(norm, "9.0.0") and not norm.startswith("0.")

    def get_subsystem_default_versions(self, vcf_baseline: str = "9.1.1") -> Dict[str, str]:
        """Returns standard component versions associated with a given VCF release baseline."""
        norm = self.normalize_version(vcf_baseline)
        return {sub: norm for sub in self.KNOWN_SUBSYSTEMS}
