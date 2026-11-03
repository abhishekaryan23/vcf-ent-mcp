# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Tests for the VCF Interoperability Certification Framework (Phases 16-19).
Verifies:
- Profile loading for VCF 9.0.0, 9.1.0, and 9.1.1
- Runner execution and SDDC Manager Independence
- Resilience of vCenter/NSX operations when SDDC Manager is unavailable
- JSON and Markdown audit matrix report generation
"""

import json
import unittest
from pathlib import Path

from vcf_enterprise_mcp.certification.models import (
    VerificationLevel,
    ComponentType,
    CertificationProfile,
    CertificationResult,
)
from vcf_enterprise_mcp.certification.runner import (
    CertificationRunner,
    load_profile,
)
from vcf_enterprise_mcp.certification.report import (
    CertificationReportGenerator,
)
from vcf_enterprise_mcp.adapter.platform import PlatformClient, PlatformMode
from vcf_enterprise_mcp.adapter.capability_provider import CapabilityProviderRegistry
from vcf_enterprise_mcp.adapter.transport.http import (
    HTTPTransport,
    TransportRequest,
    TransportResponse,
)


class TestVCFCertificationFramework(unittest.TestCase):

    def setUp(self):
        # In-memory mock server returning response shapes from the official vcf-api-specs 9.1.1.0
        self.vms = {
            "vm-twin-101": {"name": "db-cert-primary", "power_state": "POWERED_ON",
                            "cpu": {"count": 4, "hot_add_enabled": True, "hot_remove_enabled": False},
                            "memory": {"size_mib": 16384, "hot_add_enabled": True, "hot_add_increment_size_mib": 1024, "hot_add_limit_mib": 131072}}
        }
        self.segments = {}
        self.sddc_available = True
        ops_cluster_uuid = "2d16d6ea-21cd-48e5-a8e8-936da75185b5"

        def vcf_gateway_handler(req: TransportRequest) -> TransportResponse:
            url = req.full_url if hasattr(req, "full_url") else req.get_full_url()
            path = url.split("?")[0]
            method = req.method

            # SDDC Manager
            if "sddc-manager" in url:
                if not self.sddc_available:
                    return TransportResponse(503, body=b'{"errorCode": "SDDC_MANAGER_UNAVAILABLE"}')
                if method == "GET" and path.endswith("/v1/domains"):
                    return TransportResponse(200, body=b'{"elements": [{"id": "mgmt-domain", "name": "Management-Domain", "status": "ACTIVE"}]}')
                if method == "POST" and path.endswith("/v1/upgrades"):
                    return TransportResponse(202, body=b'{"id": "upgrade-task-01", "name": "Upgrade", "status": "IN_PROGRESS", "creationTimestamp": "2026-10-10T00:00:00Z"}')

            # vCenter
            if "/api/vcenter/vm" in path:
                if method == "GET" and path.endswith("/api/vcenter/vm"):
                    summaries = [{"vm": k, "name": v["name"], "power_state": v["power_state"], "cpu_count": v["cpu"]["count"], "memory_size_mib": v["memory"]["size_mib"]} for k, v in self.vms.items()]
                    return TransportResponse(200, body=json.dumps(summaries).encode())
                vm_id = path.split("/api/vcenter/vm/")[1].split("/")[0]
                vm = self.vms.get(vm_id)
                if vm is None:
                    return TransportResponse(404, body=b"{}")
                if path.endswith("/power"):
                    if method == "GET":
                        return TransportResponse(200, body=json.dumps({"state": vm["power_state"]}).encode())
                    action = req.params.get("action")
                    vm["power_state"] = {"start": "POWERED_ON", "reset": "POWERED_ON", "stop": "POWERED_OFF", "suspend": "SUSPENDED"}[action]
                    return TransportResponse(204)
                if path.endswith("/hardware/cpu"):
                    if method == "PATCH":
                        vm["cpu"]["count"] = req.json_body["count"]
                        return TransportResponse(204)
                    return TransportResponse(200, body=json.dumps(vm["cpu"]).encode())
                if path.endswith("/hardware/memory"):
                    if method == "PATCH":
                        vm["memory"]["size_mib"] = req.json_body["size_mib"]
                        return TransportResponse(204)
                    return TransportResponse(200, body=json.dumps(vm["memory"]).encode())
                return TransportResponse(200, body=json.dumps(vm).encode())

            if method == "POST" and "/CreateSnapshot_Task" in path:
                return TransportResponse(200, body=b'{"_typeName": "ManagedObjectReference", "type": "Task", "value": "task-501"}')

            if method == "GET" and "/api/vcenter/host" in path:
                return TransportResponse(200, body=b'[{"host": "host-10", "name": "esx-01.corp", "connection_state": "CONNECTED"}]')

            if method == "GET" and "/api/vcenter/cluster" in path:
                return TransportResponse(200, body=b'[{"cluster": "domain-c8", "name": "cluster-twin-a"}]')

            # NSX Policy
            if "/policy/api/v1/infra/segments/" in path:
                seg_name = path.split("/segments/")[1]
                if method == "GET":
                    if seg_name not in self.segments:
                        return TransportResponse(404, body=b'{"error_code": 600}')
                    return TransportResponse(200, body=json.dumps(self.segments[seg_name]).encode())
                if method == "PATCH":
                    self.segments[seg_name] = {"id": seg_name, **req.json_body}
                    return TransportResponse(200)

            # VCF Operations
            if path.endswith("/suite-api/api/resources"):
                return TransportResponse(200, body=json.dumps({"resourceList": [{"identifier": ops_cluster_uuid, "resourceKey": {"name": "cluster-twin-a"}}]}).encode())
            if path.endswith(f"/suite-api/api/resources/{ops_cluster_uuid}/stats"):
                return TransportResponse(200, body=json.dumps({"values": [{"resourceId": ops_cluster_uuid, "stat-list": {"stat": [{"timestamps": [1788000000000], "statKey": {"key": "cpu|usage_average"}, "data": [32.5]}]}}]}).encode())
            if path.endswith("/suite-api/api/alerts"):
                return TransportResponse(200, body=b'{"alerts": []}')

            return TransportResponse(404, body=b"{}")

        self.transport = HTTPTransport(mock_handler=vcf_gateway_handler)
        self.registry = CapabilityProviderRegistry.create_default(
            sddc_url="http://sddc-manager.corp.internal:9080",
            vc_url="http://vcenter-01.corp.internal:9090",
            nsx_url="http://nsx-manager-01.corp.internal:9081",
            ops_url="http://vcf-ops.corp.internal:9082",
        )
        self.platform = PlatformClient(
            registry=self.registry,
            transport=self.transport,
            mode=PlatformMode.REAL_VCF,
        )
        self.runner = CertificationRunner(self.platform)

    def test_load_all_certification_profiles(self):
        """Verifies loading valid YAML profiles for 9.0.0, 9.1.0, and 9.1.1."""
        for version in ["vcf_9_0_0", "vcf_9_1_0", "vcf_9_1_1"]:
            profile = load_profile(version)
            self.assertIsInstance(profile, CertificationProfile)
            self.assertGreater(len(profile.operations), 4)
            self.assertIn("vcenter", profile.component_versions)

    def test_full_certification_run_vcf_9_1_1(self):
        """Runs the complete VCF 9.1.1 certification suite and verifies 100% pass."""
        profile = load_profile("vcf_9_1_1")
        result = self.runner.run_profile(
            profile=profile,
            verification_level=VerificationLevel.DIGITAL_TWIN_VERIFIED,
        )

        self.assertTrue(result.is_successful)
        self.assertEqual(result.failed_count, 0)
        self.assertGreaterEqual(result.passed_count, 10)
        self.assertTrue(result.direct_vcenter_success)
        self.assertTrue(result.direct_nsx_success)

    def test_sddc_manager_independence_under_sddc_failure(self):
        """
        Critical architectural verification:
        When SDDC Manager is completely offline/failing (503),
        vCenter-direct and NSX-direct operations MUST still succeed.
        """
        profile = load_profile("vcf_9_1_1")
        self.sddc_available = False

        result = self.runner.run_profile(
            profile=profile,
            verification_level=VerificationLevel.DIGITAL_TWIN_VERIFIED,
        )

        # SDDC Manager operations failed as expected
        sddc_ops = [r for r in result.operation_results if r.component == ComponentType.SDDC_MANAGER]
        self.assertTrue(all(r.status == "FAIL" for r in sddc_ops))

        # BUT vCenter-direct and NSX-direct operations still 100% SUCCEEDED!
        self.assertTrue(result.direct_vcenter_success)
        self.assertTrue(result.direct_nsx_success)

    def test_report_generation_json_and_markdown(self):
        """Verifies report generation into JSON and audit-grade Markdown."""
        profile = load_profile("vcf_9_1_1")
        result = self.runner.run_profile(
            profile=profile,
            verification_level=VerificationLevel.DIGITAL_TWIN_VERIFIED,
        )

        # JSON
        json_str = CertificationReportGenerator.to_json(result)
        parsed = json.loads(json_str)
        self.assertEqual(parsed["profile_name"], "vcf_9_1_1")
        self.assertEqual(parsed["summary"]["failed"], 0)

        # Markdown
        md_str = CertificationReportGenerator.to_markdown(result)
        self.assertIn("# VCF Interoperability Certification Report", md_str)
        self.assertIn("SDDC Manager Independence", md_str)
        self.assertIn("| `vcenter` | `power_vm` | `direct`", md_str)

        # Save to temporary matrix path
        import tempfile
        with tempfile.TemporaryDirectory() as tmp_dir:
            matrix_path = Path(tmp_dir) / "vcf_certification_matrix.md"
            CertificationReportGenerator.save_markdown(result, str(matrix_path))
            self.assertTrue(matrix_path.exists())
