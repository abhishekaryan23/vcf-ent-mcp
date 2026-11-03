# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Comprehensive test suite for per-component version resolution and Broadcom API registry.
Validates MAND-1 requirement from Re-Audit Remediation Directive.
"""

import unittest
from vcf_enterprise_mcp.adapter.version_adapter import VCFVersionAdapter
from vcf_enterprise_mcp.adapter.api_registry import BroadcomAPIContractRegistry
from vcf_enterprise_mcp.core.errors import VersionMismatchException


class TestPerComponentVersions(unittest.TestCase):
    """Tests per-component version adaptation and API contract filtering."""

    def test_default_baseline_sets_all_components(self):
        """Verifies uniform baseline initializes all subsystems uniformly."""
        adapter = VCFVersionAdapter("9.0.2")
        self.assertEqual(adapter.target_version, "9.0.2")
        self.assertEqual(adapter.get_component_version("sddc_manager"), "9.0.2")
        self.assertEqual(adapter.get_component_version("vcenter"), "9.0.2")
        self.assertEqual(adapter.get_component_version("nsx"), "9.0.2")
        self.assertEqual(adapter.get_component_version("vcf_operations"), "9.0.2")

        # 9.0.2 has relaxed NIC check, but NOT promql or fleet IAM
        self.assertTrue(adapter.is_feature_supported("relax_1g_nic_validation"))
        self.assertFalse(adapter.is_feature_supported("promql_telemetry"))
        self.assertFalse(adapter.is_feature_supported("fleet_iam_sso"))
        self.assertFalse(adapter.is_feature_supported("uppercase_fqdn_fix"))

    def test_heterogeneous_component_versions(self):
        """
        Verifies heterogeneous cluster:
        VCF baseline 9.1.1, but vcf_operations remains on 9.0.0 and sddc_manager on 9.0.1.
        """
        adapter = VCFVersionAdapter(
            target_version="9.1.1",
            component_versions={
                "vcf_operations": "9.0.0",
                "sddc_manager": "9.0.1",
                "vcenter": "9.1.1",
            }
        )

        self.assertEqual(adapter.get_component_version("vcf_operations"), "9.0.0")
        self.assertEqual(adapter.get_component_version("sddc_manager"), "9.0.1")
        self.assertEqual(adapter.get_component_version("vcenter"), "9.1.1")
        self.assertEqual(adapter.get_component_version("nsx"), "9.1.1")  # defaulted to baseline

        # vcf_operations is 9.0.0 -> promql and fleet IAM MUST be false
        self.assertFalse(adapter.is_feature_supported("promql_telemetry"))
        self.assertFalse(adapter.is_feature_supported("fleet_iam_sso"))

        # sddc_manager is 9.0.1 -> relax_1g_nic_validation (9.0.2+) and uppercase_fqdn_fix (9.1.1+) MUST be false
        self.assertFalse(adapter.is_feature_supported("relax_1g_nic_validation"))
        self.assertFalse(adapter.is_feature_supported("uppercase_fqdn_fix"))

        # vcenter is 9.1.1 -> vsan_esa_snapshots MUST be true
        self.assertTrue(adapter.is_feature_supported("vsan_esa_snapshots"))

        # Endpoint adaptation should raise for telemetry.query
        with self.assertRaises(VersionMismatchException) as ctx:
            adapter.adapt_endpoint("telemetry.query")
        self.assertIn("vcf_operations 9.0.0", str(ctx.exception))

        # Dynamic upgrade of vcf_operations subsystem
        adapter.set_component_version("vcf_operations", "9.1.0")
        self.assertTrue(adapter.is_feature_supported("promql_telemetry"))
        self.assertTrue(adapter.is_feature_supported("fleet_iam_sso"))
        self.assertEqual(adapter.adapt_endpoint("telemetry.query"), "/api/v1/telemetry/query")

    def test_dict_initialization_for_version_adapter(self):
        """Verifies passing dictionary as first argument initializes correctly."""
        comp_map = {
            "sddc_manager": "9.1.1",
            "vcenter": "9.1.0",
            "nsx": "9.1.1",
            "vcf_operations": "9.1.1",
        }
        adapter = VCFVersionAdapter(comp_map)
        self.assertEqual(adapter.target_version, "9.1.1")
        self.assertEqual(adapter.get_component_version("vcenter"), "9.1.0")
        self.assertEqual(adapter.get_all_component_versions()["vcenter"], "9.1.0")

    def test_api_contract_registry_component_version_filtering(self):
        """Verifies API registry resolves APIs based on individual subsystem versions."""
        registry = BroadcomAPIContractRegistry()

        # In pure 9.0.0, ops.promql.query (introduced in 9.1.0) is omitted
        apis_90 = registry.list_apis_for_version("9.0.0")
        api_ids_90 = {a.api_id for a in apis_90}
        self.assertNotIn("ops.promql.query", api_ids_90)
        self.assertNotIn("ops.fleet.iam", api_ids_90)
        self.assertIn("vc.vms.list", api_ids_90)
        self.assertIn("sddc.domains.list", api_ids_90)

        # Heterogeneous: vcenter 9.0.0, but vcf_operations 9.1.1
        comp_versions = {
            "vcenter": "9.0.0",
            "sddc_manager": "9.0.0",
            "nsx": "9.0.0",
            "vcf_operations": "9.1.1",
        }
        apis_hetero = registry.list_apis_for_component_versions(comp_versions)
        api_ids_hetero = {a.api_id for a in apis_hetero}
        self.assertIn("ops.promql.query", api_ids_hetero)
        self.assertIn("ops.fleet.iam", api_ids_hetero)
        self.assertIn("vc.vms.list", api_ids_hetero)

    def test_list_apis_for_subsystem(self):
        """Verifies filtering APIs by subsystem and version."""
        registry = BroadcomAPIContractRegistry()
        nsx_apis = registry.list_apis_for_subsystem("nsx", "9.1.1")
        self.assertTrue(all(a.subsystem == "nsx" for a in nsx_apis))
        self.assertGreater(len(nsx_apis), 0)

        vcenter_apis = registry.list_apis_for_subsystem("vcenter", "9.1.1")
        self.assertTrue(all(a.subsystem == "vcenter" for a in vcenter_apis))
        self.assertGreater(len(vcenter_apis), 0)

    def test_is_api_supported_with_components(self):
        """Verifies is_api_supported with per-component dictionary."""
        registry = BroadcomAPIContractRegistry()

        comp_versions = {
            "vcf_operations": "9.0.2",
            "vcenter": "9.1.1",
        }

        # ops.promql.query requires 9.1.0, but vcf_operations is 9.0.2
        self.assertFalse(registry.is_api_supported("ops.promql.query", component_versions=comp_versions))

        # vc.vms.create_snapshot requires 9.0.0, vcenter is 9.1.1
        self.assertTrue(registry.is_api_supported("vc.vms.create_snapshot", component_versions=comp_versions))

        # Upgrade vcf_operations in dict
        comp_versions["vcf_operations"] = "9.1.0"
        self.assertTrue(registry.is_api_supported("ops.promql.query", component_versions=comp_versions))

    def test_coverage_gaps_with_component_versions(self):
        """Verifies coverage gap calculation accounts for component versions."""
        registry = BroadcomAPIContractRegistry()

        implemented = ["compute.vm.read", "compute.vm.power", "telemetry.health.read"]

        # 1. With component_versions dict passed directly
        comp_versions = {
            "sddc_manager": "9.0.0",
            "vcenter": "9.1.1",
            "nsx": "9.0.0",
            "vcf_operations": "9.0.0",  # PromQL API not in active set
        }
        gaps_90_ops = registry.compute_coverage_gaps(implemented, component_versions=comp_versions)
        missing_ids_90 = {g["api_id"] for g in gaps_90_ops["coverage_gaps"]}
        self.assertNotIn("ops.promql.query", missing_ids_90)
        self.assertEqual(gaps_90_ops["component_versions"], comp_versions)

        # 2. With vcf_operations upgraded to 9.1.0, ops.promql.query enters active APIs and becomes a gap
        comp_versions["vcf_operations"] = "9.1.0"
        gaps_91_ops = registry.compute_coverage_gaps(implemented, component_versions=comp_versions)
        missing_ids_91 = {g["api_id"] for g in gaps_91_ops["coverage_gaps"]}
        self.assertIn("ops.promql.query", missing_ids_91)


if __name__ == "__main__":
    unittest.main()
