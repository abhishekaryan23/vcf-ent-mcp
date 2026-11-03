# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Unit & Integration Tests for MCP Tool Provider Wiring, Digital Twin HTTP Transport, and Real Postconditions.
Verifies:
1. MCP Tools invoke PlatformClient and delegate to providers across REAL_VCF, DIGITAL_TWIN, and UNIT_TEST modes (P1-4).
2. Digital Twin mode exercises real HTTP transport matching production paths (MAND-3).
3. Real postcondition verification re-queries the provider and catches infrastructure drift (MAND-2).
"""

from __future__ import annotations
from tests.fixtures.authorized_execution import execute_authorized
import unittest
import asyncio
import json
from vcf_enterprise_mcp.auth.identity import Principal
from vcf_enterprise_mcp.state.durable_store import DurableStore
from vcf_enterprise_mcp.policy.enforcement import PolicyEnforcementPoint
from vcf_enterprise_mcp.policy.engine import PolicyDecisionPoint
from vcf_enterprise_mcp.config.settings import PolicyConfig
from vcf_enterprise_mcp.adapter.platform import PlatformClient
from vcf_enterprise_mcp.adapter.models import PlatformMode
from vcf_enterprise_mcp.adapter.transport.base import TransportRequest, TransportResponse
from vcf_enterprise_mcp.adapter.transport.http import HTTPTransport
from vcf_enterprise_mcp.core.errors import PostconditionFailedException
from vcf_enterprise_mcp.tools.query_tools import (
    VCFListVMsTool,
    VCFGetVMTool,
    VCFListHostsTool,
    VCFGetHealthTool,
    VCFQueryTelemetryTool,
)
from vcf_enterprise_mcp.tools.operational_tools import (
    VCFPowerVMTool,
    VCFResizeVMTool,
    VCFCreateSnapshotTool,
    VCFCreateNSXSegmentTool,
)


class TestToolProviderWiring(unittest.TestCase):

    def setUp(self):
        self.durable = DurableStore(":memory:")
        self.pdp = PolicyDecisionPoint(
            config=PolicyConfig(operating_mode="AUDITED_OPERATIONS"),
            durable_store=self.durable,
        )
        self.pep = PolicyEnforcementPoint(pdp=self.pdp)
        self.admin = Principal(
            user_id="admin@corp.com",
            corporate_groups=["VCF-Platform-Admins"],
            allowed_clusters=["*"],
        )
        self.operator = Principal(
            user_id="alice@corp.com",
            corporate_groups=["VCF-Compute-Operators"],
            allowed_clusters=["*"],
            allowed_domains=["*"],
        )
        self.net_admin = Principal(
            user_id="netadmin@corp.com",
            corporate_groups=["VCF-Network-Admins"],
            allowed_clusters=["*"],
        )

    def test_query_tools_in_unit_test_mode(self):
        """Query tools query PlatformClient in UNIT_TEST mode and return normalized attributes."""
        platform = PlatformClient(mode=PlatformMode.UNIT_TEST)
        list_vms_tool = VCFListVMsTool(pep=self.pep, durable_store=self.durable, platform_client=platform)
        get_vm_tool = VCFGetVMTool(pep=self.pep, durable_store=self.durable, platform_client=platform)
        list_hosts_tool = VCFListHostsTool(pep=self.pep, durable_store=self.durable, platform_client=platform)
        health_tool = VCFGetHealthTool(pep=self.pep, durable_store=self.durable, platform_client=platform)
        telemetry_tool = VCFQueryTelemetryTool(pep=self.pep, durable_store=self.durable, platform_client=platform)

        # 1. List VMs
        res_vms = asyncio.run(execute_authorized(list_vms_tool, self.operator, {"cluster_id": "cluster-prod-a"}))
        self.assertGreaterEqual(res_vms["count"], 2)
        self.assertIn("virtual_machines", res_vms)
        self.assertTrue(any(vm["vm_id"] == "vm-101" for vm in res_vms["virtual_machines"]))

        # 2. Get VM
        res_vm = asyncio.run(execute_authorized(get_vm_tool, self.operator, {"vm_id": "vm-101"}))
        self.assertEqual(res_vm["vm_id"], "vm-101")
        self.assertEqual(res_vm["power_state"], "POWERED_ON")
        self.assertIn("hardware", res_vm)

        # 3. List Hosts
        res_hosts = asyncio.run(execute_authorized(list_hosts_tool, self.admin, {"cluster_id": "cluster-prod-a"}))
        self.assertGreaterEqual(res_hosts["count"], 2)
        self.assertIn("hosts", res_hosts)

        # 4. Health
        res_health = asyncio.run(execute_authorized(health_tool, self.admin, {"datacenter_id": "dc1"}))
        self.assertEqual(res_health["overall_status"], "GREEN")
        self.assertEqual(res_health["subsystems"]["sddc_manager"], "HEALTHY")

        # 5. Telemetry
        res_telem = asyncio.run(execute_authorized(telemetry_tool, self.operator, {"cluster_id": "cluster-prod-a", "metric": "cpu_usage_pct"}))
        self.assertEqual(res_telem["query_type"], "metrics")
        self.assertIn("data_points", res_telem)

    def test_operational_tools_in_real_vcf_mode(self):
        """In REAL_VCF mode, mutating operations dispatch requests to vCenter and NSX over HTTP."""
        calls = []

        vm = {"power_state": "POWERED_OFF", "cpu": {"count": 4}, "memory": {"size_mib": 16384}}
        segments = {}

        def mock_upstream(req: TransportRequest) -> TransportResponse:
            calls.append((req.method, req.get_full_url(), req.json_body))
            path = req.url
            if path.endswith("/api/vcenter/vm/vm-101/power"):
                if req.method == "POST":
                    vm["power_state"] = "POWERED_ON" if req.params["action"] in ("start", "reset") else "POWERED_OFF"
                    return TransportResponse(204)
                return TransportResponse(200, body=json.dumps({"state": vm["power_state"]}).encode())
            if path.endswith("/api/vcenter/vm/vm-101/hardware/cpu"):
                if req.method == "PATCH":
                    vm["cpu"]["count"] = req.json_body["count"]
                    return TransportResponse(204)
                return TransportResponse(200, body=json.dumps({**vm["cpu"], "hot_add_enabled": True, "hot_remove_enabled": False}).encode())
            if path.endswith("/api/vcenter/vm/vm-101/hardware/memory"):
                if req.method == "PATCH":
                    vm["memory"]["size_mib"] = req.json_body["size_mib"]
                    return TransportResponse(204)
                return TransportResponse(200, body=json.dumps({**vm["memory"], "hot_add_enabled": True, "hot_add_increment_size_mib": 1024}).encode())
            if path.endswith("/api/vcenter/vm/vm-101"):
                return TransportResponse(200, body=json.dumps(vm).encode())
            if "/policy/api/v1/infra/segments/" in path:
                name = path.rsplit("/", 1)[-1]
                if req.method == "GET":
                    return TransportResponse(200, body=json.dumps(segments[name]).encode()) if name in segments else TransportResponse(404)
                segments[name] = {"id": name, **req.json_body}
                return TransportResponse(200)
            return TransportResponse(404)

        transport = HTTPTransport(mock_handler=mock_upstream)
        platform = PlatformClient(transport=transport, mode=PlatformMode.REAL_VCF)

        power_tool = VCFPowerVMTool(pep=self.pep, durable_store=self.durable, platform_client=platform)
        resize_tool = VCFResizeVMTool(pep=self.pep, durable_store=self.durable, platform_client=platform)
        nsx_tool = VCFCreateNSXSegmentTool(pep=self.pep, durable_store=self.durable, platform_client=platform)

        # 1. Power VM
        res_pwr = asyncio.run(execute_authorized(power_tool, self.operator, {"vm_id": "vm-101", "action": "start"}))
        self.assertEqual(res_pwr["status"], "SUCCESS")
        self.assertEqual(res_pwr["new_power_state"], "POWERED_ON")
        self.assertTrue(any("/api/vcenter/vm/vm-101/power" in c[1] for c in calls))

        # 2. Resize VM
        res_resize = asyncio.run(execute_authorized(resize_tool, self.operator, {"vm_id": "vm-101", "memory_gb": 32, "cpu_cores": 8}))
        self.assertEqual(res_resize["status"], "SUCCESS")
        self.assertEqual(res_resize["allocated_memory_gb"], 32)
        self.assertTrue(any("/api/vcenter/vm/vm-101/hardware" in c[1] for c in calls))

        # 3. Create NSX Segment
        res_nsx = asyncio.run(execute_authorized(nsx_tool, self.net_admin, {"segment_name": "seg-prod", "cidr": "192.168.50.1/24", "gateway_id": "t1-gw"}))
        self.assertEqual(res_nsx["status"], "SUCCESS")
        self.assertEqual(res_nsx["segment_id"], "seg-prod")
        self.assertTrue(any("/policy/api/v1/infra/segments/seg-prod" in c[1] for c in calls))

    def test_digital_twin_over_http_transport(self):
        """In DIGITAL_TWIN mode, operations route through DigitalTwinProvider over HTTP transport (MAND-3)."""
        http_requests = []

        def mock_twin_server(req: TransportRequest) -> TransportResponse:
            http_requests.append((req.method, req.url))
            if req.url.endswith("/api/vcenter/vm"):
                return TransportResponse(200, body=b'{"value": [{"id": "vm-twin-1", "name": "twin-web-01"}]}')
            elif "/api/vcenter/vm/vm-twin-1/power" in req.url:
                return TransportResponse(200, body=b'{"status": "SUCCESS"}')
            elif "/v1/system/health" in req.url:
                return TransportResponse(200, body=b'{"status": "HEALTHY", "score": 99.0}')
            elif "/api/vcenter/vm/vm-twin-1" in req.url:
                return TransportResponse(200, body=b'{"id": "vm-twin-1", "power_state": "POWERED_ON"}')
            return TransportResponse(200, body=b'{"status": "OK"}')

        transport = HTTPTransport(mock_handler=mock_twin_server)
        platform = PlatformClient(
            transport=transport,
            mode=PlatformMode.DIGITAL_TWIN,
            digital_twin_url="http://127.0.0.1:9080",
        )

        list_tool = VCFListVMsTool(pep=self.pep, durable_store=self.durable, platform_client=platform)
        power_tool = VCFPowerVMTool(pep=self.pep, durable_store=self.durable, platform_client=platform)
        health_tool = VCFGetHealthTool(pep=self.pep, durable_store=self.durable, platform_client=platform)

        # 1. List VMs routes through HTTP transport to twin gateway
        vms = asyncio.run(execute_authorized(list_tool, self.operator, {"cluster_id": "cluster-prod-a"}))
        self.assertEqual(len(vms["virtual_machines"]), 1)
        self.assertEqual(vms["virtual_machines"][0]["vm_id"], "vm-twin-1")
        self.assertTrue(any("127.0.0.1:9080/api/vcenter/vm" in u[1] for u in http_requests))

        # 2. Power VM routes to digital twin
        res_pwr = asyncio.run(execute_authorized(power_tool, self.operator, {"vm_id": "vm-twin-1", "action": "start"}))
        self.assertEqual(res_pwr["status"], "SUCCESS")
        self.assertTrue(any("127.0.0.1:9080/api/vcenter/vm/vm-twin-1/power" in u[1] for u in http_requests))

        # 3. Health routes to digital twin
        res_hlth = asyncio.run(execute_authorized(health_tool, self.admin, {"datacenter_id": "dc1"}))
        self.assertEqual(res_hlth["overall_status"], "HEALTHY")
        self.assertTrue(any("127.0.0.1:9080/v1/system/health" in u[1] for u in http_requests))

    def test_real_postcondition_catches_provider_drift(self):
        """Postcondition verification re-queries provider and fails if provider did not achieve state (MAND-2)."""
        def mock_stubborn_vm(req: TransportRequest) -> TransportResponse:
            # Upstream claims mutation succeeded
            if "/power/start" in req.url:
                return TransportResponse(200, body=b'{"status": "SUCCESS"}')
            # But subsequent query for actual VM state shows VM is still POWERED_OFF!
            if "/api/vcenter/vm/vm-101" in req.url:
                return TransportResponse(200, body=b'{"id": "vm-101", "power_state": "POWERED_OFF"}')
            return TransportResponse(200, body=b'{}')

        transport = HTTPTransport(mock_handler=mock_stubborn_vm)
        platform = PlatformClient(transport=transport, mode=PlatformMode.REAL_VCF)
        power_tool = VCFPowerVMTool(pep=self.pep, durable_store=self.durable, platform_client=platform)

        # Mutating start should fail postcondition verification because actual provider state is still POWERED_OFF
        with self.assertRaises(PostconditionFailedException) as ctx:
            asyncio.run(execute_authorized(power_tool, self.operator, {"vm_id": "vm-101", "action": "start"}))
        # The provider reports the observed state, so the postcondition catches the drift.
        self.assertIn("Expected POWERED_ON", str(ctx.exception))
        self.assertIn("POWERED_OFF", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
