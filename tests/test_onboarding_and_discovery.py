# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Unit Tests for VCF Environment Onboarding, Capability Matrix Auto-Discovery, and Version Adapters.
Runs in-memory with zero external test runner dependencies (uses standard library unittest).
"""

from __future__ import annotations
import sys
import os
import unittest

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC_DIR = os.path.join(BASE_DIR, "src")
sys.path.insert(0, SRC_DIR)

from vcf_enterprise_mcp.adapter.version_adapter import VCFVersionAdapter
from vcf_enterprise_mcp.adapter.discovery import OnboardingEngine, EnvironmentProfile
from vcf_enterprise_mcp.core.errors import VersionMismatchException


class TestOnboardingAndVersionAdapters(unittest.TestCase):
    """Validates VCF auto-discovery, capability matrix generation, and multi-version abstraction."""

    def setUp(self):
        self.onboarding = OnboardingEngine(target_version="9.1.1")

    def test_environment_auto_discovery_and_profile_generation(self):
        """Simulates discovery scan against SDDC Manager FQDN."""
        profile = self.onboarding.run_discovery(
            sddc_fqdn="sddc-manager.corp.internal",
            vcf_version="9.1.1",
            simulated_data={
                "domains_count": 3,
                "vcenters_count": 3,
                "clusters_count": 8,
                "hosts_count": 48,
                "has_operations": True,
                "has_automation": True,
                "has_srm": True,
                "has_private_ai": False,
            },
        )
        self.assertEqual(profile.sddc_fqdn, "sddc-manager.corp.internal")
        self.assertEqual(profile.vcf_version, "9.1.1")
        self.assertEqual(profile.domains_count, 3)
        self.assertEqual(profile.hosts_count, 48)
        self.assertTrue(profile.installed_components["fleet_iam"])
        self.assertTrue(profile.installed_components["promql_telemetry"])
        self.assertFalse(profile.installed_components["private_ai"])

    def test_capability_matrix_derivation(self):
        """Ensures unavailable features (e.g. Private AI) are omitted from advertised capability matrix."""
        self.onboarding.run_discovery(
            sddc_fqdn="sddc-manager.corp.internal",
            vcf_version="9.1.1",
            simulated_data={"has_private_ai": False},
        )
        matrix = self.onboarding.current_matrix
        self.assertIsNotNone(matrix)
        self.assertTrue(matrix.is_capability_available("compute_inventory"))
        self.assertTrue(matrix.is_capability_available("network_microsegmentation"))
        self.assertTrue(matrix.is_capability_available("vsan_data_protection"))
        self.assertTrue(matrix.is_capability_available("realtime_promql_telemetry"))

        # Private AI was not installed
        self.assertFalse(matrix.is_capability_available("private_ai_vgpu"))
        self.assertIn("private_ai_vgpu", matrix.unavailable_capabilities)

    def test_version_adapter_gates_90_vs_91(self):
        """Verifies version adapter prevents PromQL and Fleet IAM on VCF 9.0.x baselines."""
        adapter_90 = VCFVersionAdapter("9.0.0")
        adapter_91 = VCFVersionAdapter("9.1.1")

        # PromQL
        self.assertFalse(adapter_90.is_feature_supported("promql_telemetry"))
        self.assertTrue(adapter_91.is_feature_supported("promql_telemetry"))

        # Fleet IAM
        self.assertFalse(adapter_90.is_feature_supported("fleet_iam_sso"))
        self.assertTrue(adapter_91.is_feature_supported("fleet_iam_sso"))

        # Endpoint adaptation
        self.assertEqual(adapter_91.adapt_endpoint("telemetry.query"), "/api/v1/telemetry/query")
        with self.assertRaises(VersionMismatchException):
            adapter_90.adapt_endpoint("telemetry.query")

    def test_onboarding_safety_mode_transitions(self):
        """Verifies starting in DISCOVERY_ONLY and transitioning to AUDITED_OPERATIONS."""
        self.assertEqual(self.onboarding.mode, "DISCOVERY_ONLY")

        # Must run discovery before promoting out of DISCOVERY_ONLY
        self.onboarding.run_discovery(sddc_fqdn="sddc-manager.corp.internal", vcf_version="9.1.1")

        # Promote mode
        new_mode = self.onboarding.transition_operating_mode("AUDITED_OPERATIONS")
        self.assertEqual(new_mode, "AUDITED_OPERATIONS")

        # Invalid mode throws error
        with self.assertRaises(ValueError):
            self.onboarding.transition_operating_mode("INVALID_SUPERUSER_MODE")


if __name__ == "__main__":
    unittest.main()
