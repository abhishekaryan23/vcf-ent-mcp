# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Per-component upstream session authentication and real-VCF truthfulness.

Covers the documented login flows (vCenter /api/session, SDDC Manager /v1/tokens,
VCF Operations token/acquire, NSX Basic), 401 re-login, and that REAL_VCF mode
never reports invented health, plans or workflow completion.
"""

import asyncio
import base64
import json
import time
import unittest

from vcf_enterprise_mcp.adapter.capability_provider import CapabilityProviderRegistry
from vcf_enterprise_mcp.adapter.platform import PlatformClient, PlatformMode
from vcf_enterprise_mcp.adapter.providers.vcenter import VCenterProvider
from vcf_enterprise_mcp.adapter.transport.base import TransportRequest, TransportResponse
from vcf_enterprise_mcp.adapter.transport.errors import UpstreamPreconditionException
from vcf_enterprise_mcp.adapter.transport.http import HTTPTransport
from vcf_enterprise_mcp.adapter.transport.vcf_sessions import (
    NSXBasicAuth,
    SDDCManagerTokenAuth,
    VCenterSessionAuth,
    VCFOperationsTokenAuth,
)

CREDS = lambda: ("svc-mcp@vsphere.local", "lab-only-test-value")  # noqa: E731

URLS = {
    "sddc_url": "http://sddc-manager.corp.internal",
    "vc_url": "http://vcenter.corp.internal",
    "nsx_url": "http://nsx.corp.internal",
    "ops_url": "http://vcf-ops.corp.internal",
}


class TestVCFSessionAuth(unittest.TestCase):

    def test_vcenter_session_login_reuse_and_relogin_on_401(self):
        logins = []
        issued = {"current": None}

        def handler(req: TransportRequest) -> TransportResponse:
            if req.url.endswith("/api/session") and req.method == "POST":
                expected = "Basic " + base64.b64encode(b"svc-mcp@vsphere.local:lab-only-test-value").decode()
                self.assertEqual(req.headers["Authorization"], expected)
                issued["current"] = f"sess-{len(logins) + 1}"
                logins.append(issued["current"])
                return TransportResponse(201, body=json.dumps(issued["current"]).encode())
            if req.headers.get("vmware-api-session-id") != issued["current"]:
                return TransportResponse(401, body=b'{"error_type": "UNAUTHENTICATED"}')
            return TransportResponse(200, body=b"[]")

        transport = HTTPTransport(mock_handler=handler)
        auth = VCenterSessionAuth("http://vcenter.corp.internal", transport, CREDS)
        vc = VCenterProvider("http://vcenter.corp.internal", transport, auth=auth)

        vc.get_vms()
        vc.get_vms()
        self.assertEqual(logins, ["sess-1"])  # session reused

        issued["current"] = "expired-server-side"
        vc.get_vms()  # 401 -> invalidate -> re-login -> resend
        self.assertEqual(logins, ["sess-1", "sess-2"])

    def test_sddc_manager_token_pair_and_refresh(self):
        seen = []

        def handler(req: TransportRequest) -> TransportResponse:
            seen.append((req.method, req.url, req.json_body))
            if req.url.endswith("/v1/tokens"):
                self.assertEqual(req.json_body, {"username": "svc-mcp@vsphere.local", "password": "lab-only-test-value"})
                return TransportResponse(200, body=b'{"accessToken": "acc-1", "refreshToken": {"id": "ref-1"}}')
            if req.url.endswith("/v1/tokens/access-token/refresh"):
                self.assertEqual(req.method, "PATCH")
                self.assertEqual(req.json_body, "ref-1")
                return TransportResponse(200, body=b'"acc-2"')
            raise AssertionError(req.url)

        auth = SDDCManagerTokenAuth("http://sddc-manager.corp.internal", HTTPTransport(mock_handler=handler), CREDS)
        self.assertEqual(auth.apply(TransportRequest("GET", "x")).headers["Authorization"], "Bearer acc-1")
        auth._expires_at = time.time()  # force refresh path
        self.assertEqual(auth.apply(TransportRequest("GET", "x")).headers["Authorization"], "Bearer acc-2")
        self.assertEqual([s[0] for s in seen], ["POST", "PATCH"])

    def test_vcf_operations_ops_token(self):
        validity_ms = int((time.time() + 3600) * 1000)

        def handler(req: TransportRequest) -> TransportResponse:
            self.assertTrue(req.url.endswith("/suite-api/api/auth/token/acquire"))
            self.assertEqual(req.json_body["authSource"], "vIDMAuthSource")
            return TransportResponse(200, body=json.dumps({"token": "ops-1", "validity": validity_ms}).encode())

        auth = VCFOperationsTokenAuth("http://vcf-ops.corp.internal", HTTPTransport(mock_handler=handler), CREDS, auth_source="vIDMAuthSource")
        self.assertEqual(auth.apply(TransportRequest("GET", "x")).headers["Authorization"], "OpsToken ops-1")
        self.assertAlmostEqual(auth._expires_at, validity_ms / 1000.0, delta=1)

    def test_nsx_basic_per_request(self):
        header = NSXBasicAuth(CREDS).apply(TransportRequest("GET", "x")).headers["Authorization"]
        self.assertTrue(header.startswith("Basic "))


class TestRealVCFTruthfulness(unittest.TestCase):

    def _platform(self, handler, **kwargs):
        registry = CapabilityProviderRegistry.create_default(**URLS)
        return PlatformClient(registry=registry, transport=HTTPTransport(mock_handler=handler, max_retries=0), mode=PlatformMode.REAL_VCF, **kwargs)

    def test_health_is_unknown_not_green_when_operations_unreachable(self):
        def handler(req):
            if req.url.endswith("/v1/domains"):
                return TransportResponse(200, body=b'{"elements": [{"id": "d1", "name": "mgmt", "status": "ACTIVE"}]}')
            return TransportResponse(503)

        health = self._platform(handler).get_health()
        self.assertEqual(health["overall_status"], "UNKNOWN")
        self.assertIn("vcf_operations", health["unavailable_sources"])
        self.assertNotIn("score", health)

    def test_health_red_on_critical_alert(self):
        def handler(req):
            if req.url.endswith("/v1/domains"):
                return TransportResponse(200, body=b'{"elements": [{"id": "d1", "status": "ACTIVE"}]}')
            if req.url.endswith("/suite-api/api/alerts"):
                return TransportResponse(200, body=b'{"alerts": [{"alertId": "a1", "alertLevel": "CRITICAL", "status": "ACTIVE"}, {"alertId": "a2", "alertLevel": "CRITICAL", "status": "CANCELED"}]}')
            return TransportResponse(404)

        health = self._platform(handler).get_health()
        self.assertEqual(health["overall_status"], "RED")
        self.assertEqual(health["active_alert_counts"], {"CRITICAL": 1})

    def test_component_versions_are_observed(self):
        def handler(req):
            path = req.url
            if path.endswith("/v1/sddc-managers"):
                return TransportResponse(200, body=b'{"elements": [{"version": "9.1.1.0-25714914"}]}')
            if path.endswith("/v1/vcenters"):
                return TransportResponse(200, body=b'{"elements": []}')
            if path.endswith("/api/appliance/system/version"):
                return TransportResponse(200, body=b'{"version": "9.1.1.0"}')
            if path.endswith("/api/v1/node/version"):
                return TransportResponse(200, body=b'{"node_version": "9.1.1.0.0.25700000"}')
            return TransportResponse(503)

        versions = self._platform(handler).get_component_versions()
        self.assertEqual(versions["sddc_manager"], "9.1.1.0-25714914")
        self.assertEqual(versions["vcenter"], "9.1.1.0")
        self.assertEqual(versions["nsx"], "9.1.1.0.0.25700000")
        self.assertIsNone(versions["vcf_operations"])  # unreachable reports None, not a guess

    def test_component_auth_routes_per_provider(self):
        headers = {}

        def handler(req):
            headers[req.url.split("/")[2]] = dict(req.headers)
            if req.url.endswith("/api/vcenter/vm"):
                return TransportResponse(200, body=b"[]")
            return TransportResponse(200, body=b'{"elements": []}')

        class Fixed:
            def __init__(self, name, value):
                self.name, self.value = name, value

            def apply(self, request):
                request.headers[self.name] = self.value
                return request

            def invalidate(self):
                pass

        platform = self._platform(handler, component_auth={
            "vcenter": Fixed("vmware-api-session-id", "vc-sess"),
            "sddc_manager": Fixed("Authorization", "Bearer sddc"),
        })
        platform.get_vms()
        platform.get_domains()
        self.assertEqual(headers["vcenter.corp.internal"]["vmware-api-session-id"], "vc-sess")
        self.assertEqual(headers["sddc-manager.corp.internal"]["Authorization"], "Bearer sddc")


class TestRealVCFWorkflows(unittest.TestCase):

    def setUp(self):
        from vcf_enterprise_mcp.state.sqlite_store import SQLiteDurableStore
        from vcf_enterprise_mcp.workflows.engine import VCFWorkflowEngine
        from vcf_enterprise_mcp.workflows.task_store import TaskStore
        from vcf_enterprise_mcp.auth.identity import Principal

        self.posts = []
        self.task_status = "IN_PROGRESS"

        def handler(req):
            if req.url.endswith("/v1/domains/wld-01"):
                return TransportResponse(200, body=b'{"id": "wld-01", "name": "wld-01", "status": "ACTIVE", "clusters": [{"id": "c1"}]}')
            if req.url.endswith("/v1/upgradables/domains/wld-01"):
                return TransportResponse(200, body=b'{"elements": [{"bundleId": "b-911", "bundleType": "VMWARE_SOFTWARE", "status": "AVAILABLE", "softwareComponents": [{"type": "VCENTER"}]}]}')
            if req.url.endswith("/v1/upgrades") and req.method == "POST":
                self.posts.append(req.json_body)
                return TransportResponse(202, body=b'{"id": "native-42", "status": "IN_PROGRESS"}')
            if req.url.endswith("/v1/tasks/native-42"):
                return TransportResponse(200, body=json.dumps({"id": "native-42", "status": self.task_status}).encode())
            return TransportResponse(404)

        registry = CapabilityProviderRegistry.create_default(**URLS)
        self.platform = PlatformClient(registry=registry, transport=HTTPTransport(mock_handler=handler, max_retries=0), mode=PlatformMode.REAL_VCF)
        import tempfile, os
        self.tmp = tempfile.TemporaryDirectory()
        store = SQLiteDurableStore(db_path=os.path.join(self.tmp.name, "wf.db"))
        self.engine = VCFWorkflowEngine(task_store=TaskStore(durable_store=store), platform_client=self.platform)
        self.principal = Principal(principal_id="lifecycle-admin", user_id="lifecycle-admin", tenant_id="tenant-default", environment_ids=("env-prod",))

    def tearDown(self):
        self.tmp.cleanup()

    def test_upgrade_dry_run_uses_observed_data(self):
        impact = self.engine._observed_upgrade_impact("wld-01", "9.1.1", None)
        self.assertEqual(impact["data_source"], "OBSERVED")
        self.assertEqual(impact["applicable_bundle_ids"], ["b-911"])
        self.assertTrue(impact["prechecks"].startswith("NOT_RUN"))
        self.assertNotIn("affected_vms", impact)
        self.assertEqual(self.posts, [])

    def test_dr_drill_refuses_in_real_mode(self):
        with self.assertRaises(UpstreamPreconditionException):
            self.engine.plan_site_recovery_drill("rp-1", "dc2", self.principal, dry_run=True)

    def test_resume_follows_native_task_not_a_timer(self):
        task = self.engine.task_store.create_task(
            tool_name="vcf_upgrade_domain", principal=self.principal, steps=[], approval_status="APPROVED",
            impact_summary={}, native_task_id="native-42",
        )
        self.engine.task_store.update_task_progress(task.task_id, 1, "start", "RUNNING", native_task_id="native-42")
        for _ in range(5):
            out = self.engine.resume_in_flight_workflows()
        self.assertEqual(out[0]["status"], "RUNNING")  # still running upstream: never auto-completed

        self.task_status = "Successful"
        out = self.engine.resume_in_flight_workflows()
        self.assertEqual(out[0]["status"], "COMPLETED")
        self.assertEqual(out[0]["native_status"], "SUCCESSFUL")


if __name__ == "__main__":
    unittest.main()


class TestRealVCFStartup(unittest.TestCase):

    def test_real_mode_requires_endpoints_and_pins_real_dns(self):
        from vcf_enterprise_mcp.config.settings import EnterpriseSettings
        from vcf_enterprise_mcp.core.server import _build_real_vcf_platform

        cfg = EnterpriseSettings()
        cfg.vcf.sddc_manager_fqdn = ""
        with self.assertRaises(ValueError):
            _build_real_vcf_platform(cfg)

        cfg.vcf.sddc_manager_url = "https://sddc-manager.corp.internal"
        cfg.vcf.vcenter_url = "https://vcenter.corp.internal"
        cfg.vcf.nsx_url = "https://nsx.corp.internal"
        cfg.vcf.operations_url = "https://vcf-ops.corp.internal"
        platform = _build_real_vcf_platform(cfg)
        self.assertEqual(platform.mode, PlatformMode.REAL_VCF)
        self.assertEqual(set(platform.component_auth), {"sddc_manager", "vcenter", "nsx", "vcf_operations"})
        self.assertEqual(platform.registry.resolve("vm.lifecycle").endpoint_url, "https://vcenter.corp.internal")
        guard = platform.transport.ssrf_guard
        self.assertEqual(guard.mock_dns, {})
        self.assertFalse(guard.allow_lab_dns_fallback)
        self.assertFalse(guard.allow_loopback)
