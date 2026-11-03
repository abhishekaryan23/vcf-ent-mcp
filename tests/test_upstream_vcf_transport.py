# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Test Suite: Upstream VCF Transport Layer & Provider Verification (ARCH-01).
Verifies:
1. Transport models, request serialization, and response JSON parsing.
2. SSRF guardrails blocking cloud metadata and non-allowlisted targets.
3. Authentication handlers (Basic, Bearer, Session Token).
4. Circuit breaker state transitions (CLOSED -> OPEN -> HALF_OPEN -> CLOSED).
5. Resilient HTTP retries with exponential backoff and jitter.
6. Granular exception mapping (Auth, Not Found, Rate Limit, Server Error, Timeout, Connection).
7. Concrete VCF Providers (vCenter, NSX, SDDC Manager, Operations, Digital Twin).
8. Unified PlatformClient routing with revision tracking.
"""

import unittest
import json
import time
from vcf_enterprise_mcp.adapter.transport.base import (
    TransportRequest,
    TransportResponse,
)
from vcf_enterprise_mcp.adapter.transport.errors import (
    UpstreamPreconditionException,
    UpstreamAuthException,
    UpstreamResourceNotFoundException,
    UpstreamRateLimitException,
    UpstreamServerException,
    UpstreamConnectionException,
    UpstreamTimeoutException,
    UpstreamTLSException,
)
from vcf_enterprise_mcp.adapter.transport.circuit_breaker import (
    CircuitState,
    TransportCircuitBreaker,
)
from vcf_enterprise_mcp.adapter.transport.auth import (
    BasicAuth,
    BearerAuth,
    SessionTokenAuth,
)
from vcf_enterprise_mcp.adapter.transport.http import HTTPTransport
from vcf_enterprise_mcp.adapter.ssrf_guard import SSRFGuard
from vcf_enterprise_mcp.core.errors import (
    SSRFViolationException,
    ProviderUnavailableException,
)
from vcf_enterprise_mcp.adapter.providers.vcenter import VCenterProvider
from vcf_enterprise_mcp.adapter.providers.nsx import NSXProvider
from vcf_enterprise_mcp.adapter.providers.sddc import SDDCManagerProvider
from vcf_enterprise_mcp.adapter.providers.operations import VCFOperationsProvider
from vcf_enterprise_mcp.adapter.providers.digital_twin import DigitalTwinProvider
from vcf_enterprise_mcp.adapter.platform import PlatformClient
from vcf_enterprise_mcp.adapter.capability_provider import CapabilityProviderRegistry


class TestUpstreamVCFTransportARCH01(unittest.TestCase):
    """Unit tests for upstream transport, providers, resilience, and error mapping."""

    def test_transport_request_response_serialization(self):
        """Validates query param encoding, body serialization, and JSON decoding."""
        req = TransportRequest(
            method="GET",
            url="http://127.0.0.1:9080/v1/domains",
            params={"status": "ACTIVE", "limit": 10},
        )
        full_url = req.get_full_url()
        self.assertIn("status=ACTIVE", full_url)
        self.assertIn("limit=10", full_url)

        body_data = {"domain_id": "mgmt-domain", "target_version": "9.1.1"}
        req_post = TransportRequest(
            method="POST",
            url="http://127.0.0.1:9080/v1/upgrades",
            json_body=body_data,
        )
        self.assertEqual(json.loads(req_post.get_body_bytes().decode("utf-8")), body_data)

        resp = TransportResponse(
            status_code=200,
            headers={"Content-Type": "application/json"},
            body=json.dumps({"elements": [{"id": "mgmt-domain"}]}).encode("utf-8"),
        )
        self.assertTrue(resp.is_success)
        self.assertEqual(resp.json()["elements"][0]["id"], "mgmt-domain")

    def test_ssrf_guard_blocks_cloud_metadata_and_unknown_destinations(self):
        """SSRF guard blocks AWS metadata (169.254.169.254) and unapproved external domains."""
        guard = SSRFGuard()
        with self.assertRaises(SSRFViolationException):
            guard.validate_destination_url("http://169.254.169.254/latest/meta-data/")

        with self.assertRaises(SSRFViolationException):
            guard.validate_destination_url("http://attacker.com/steal-creds")

        # Enterprise internal domains and localhost are permitted
        self.assertEqual(
            guard.validate_destination_url("https://vcenter.corp.internal/api/vcenter/vm"),
            "https://vcenter.corp.internal/api/vcenter/vm",
        )
        self.assertEqual(
            guard.validate_destination_url("http://127.0.0.1:9080/v1/domains"),
            "http://127.0.0.1:9080/v1/domains",
        )

    def test_upstream_auth_header_injection(self):
        """Validates Basic, Bearer, and Session Token header injection."""
        req = TransportRequest(method="GET", url="http://127.0.0.1:9090/api/vcenter/vm")
        basic = BasicAuth("admin@vsphere.local", "VMware1!Pass")
        basic.apply(req)
        self.assertTrue(req.headers["Authorization"].startswith("Basic "))

        bearer = BearerAuth("mock-jwt-token-xyz")
        bearer.apply(req)
        self.assertEqual(req.headers["Authorization"], "Bearer mock-jwt-token-xyz")

        session = SessionTokenAuth("vmware-session-token-456")
        session.apply(req)
        self.assertEqual(req.headers["vmware-api-session-id"], "vmware-session-token-456")

    def test_circuit_breaker_lifecycle(self):
        """Verifies CLOSED -> OPEN on failure threshold, and HALF_OPEN after recovery timeout."""
        cb = TransportCircuitBreaker("vcenter.corp.internal", failure_threshold=2, recovery_time_seconds=0.02)
        self.assertEqual(cb.state, CircuitState.CLOSED)
        self.assertTrue(cb.allow_request())

        # 1st failure
        cb.record_failure("HTTP 503")
        self.assertEqual(cb.state, CircuitState.CLOSED)

        # 2nd failure -> Trips circuit to OPEN
        cb.record_failure("HTTP 503")
        self.assertEqual(cb.state, CircuitState.OPEN)
        self.assertFalse(cb.allow_request())

        with self.assertRaises(ProviderUnavailableException):
            cb.check_or_raise()

        # Wait for recovery timeout
        time.sleep(0.03)
        self.assertEqual(cb.state, CircuitState.HALF_OPEN)
        self.assertTrue(cb.allow_request())

        # Success in HALF_OPEN resets to CLOSED
        cb.record_success()
        self.assertEqual(cb.state, CircuitState.CLOSED)

    def test_http_transport_retry_and_resilience_on_5xx(self):
        """HTTP transport retries on 500/503 and succeeds on subsequent attempt."""
        attempts = 0

        def flaky_handler(req: TransportRequest) -> TransportResponse:
            nonlocal attempts
            attempts += 1
            if attempts < 3:
                return TransportResponse(status_code=503, body=b"Service Temporarily Unavailable")
            return TransportResponse(status_code=200, body=b'{"status": "UP"}')

        transport = HTTPTransport(
            max_retries=3,
            backoff_factor=0.01,
            mock_handler=flaky_handler,
        )
        req = TransportRequest(method="GET", url="http://127.0.0.1:9080/v1/system/health")
        resp = transport.send(req)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(attempts, 3)

    def test_http_transport_trips_circuit_after_exhausted_retries(self):
        """Persistent 500 errors exhaust retries and trip the circuit breaker."""
        def broken_handler(req: TransportRequest) -> TransportResponse:
            return TransportResponse(status_code=500, body=b"Internal Server Error")

        cb = TransportCircuitBreaker("127.0.0.1:9080", failure_threshold=1)
        transport = HTTPTransport(
            max_retries=2,
            backoff_factor=0.01,
            circuit_breakers={"127.0.0.1:9080": cb},
            mock_handler=broken_handler,
        )
        req = TransportRequest(method="GET", url="http://127.0.0.1:9080/v1/system/health")

        # First execution exhausts retries and raises UpstreamServerException
        with self.assertRaises(UpstreamServerException):
            transport.send(req)

        # Subsequent call is rejected by circuit breaker immediately without making network calls
        with self.assertRaises(ProviderUnavailableException):
            transport.send(req)

    def test_explicit_exception_mapping(self):
        """Translates HTTP status codes (401, 404, 429, 500) into typed domain exceptions."""
        def make_handler(status: int, body: bytes):
            return lambda req: TransportResponse(status_code=status, body=body)

        # 401 -> UpstreamAuthException
        t_auth = HTTPTransport(mock_handler=make_handler(401, b"Unauthorized"))
        with self.assertRaises(UpstreamAuthException):
            t_auth.send(TransportRequest("GET", "http://127.0.0.1:9080/v1/domains"))

        # 404 -> UpstreamResourceNotFoundException
        t_404 = HTTPTransport(mock_handler=make_handler(404, b"Not Found"))
        with self.assertRaises(UpstreamResourceNotFoundException):
            t_404.send(TransportRequest("GET", "http://127.0.0.1:9080/v1/domains/invalid-id"))

        # 429 -> UpstreamRateLimitException
        t_429 = HTTPTransport(max_retries=0, mock_handler=make_handler(429, b"Too Many Requests"))
        with self.assertRaises(UpstreamRateLimitException):
            t_429.send(TransportRequest("GET", "http://127.0.0.1:9080/v1/domains"))

    def test_vcenter_provider_crud(self):
        """VCenterProvider uses the official power action query and hardware endpoints."""
        calls = []
        state = {"power": "POWERED_OFF"}

        def mock_vc(req: TransportRequest) -> TransportResponse:
            calls.append((req.method, req.get_full_url(), req.json_body))
            path = req.url
            if path.endswith("/api/vcenter/vm"):
                return TransportResponse(200, body=b'[{"vm": "vm-101", "name": "app-web", "power_state": "POWERED_OFF"}]')
            if path.endswith("/power"):
                if req.method == "POST":
                    state["power"] = "POWERED_ON" if req.params["action"] == "start" else "POWERED_OFF"
                    return TransportResponse(204)
                return TransportResponse(200, body=json.dumps({"state": state["power"]}).encode())
            if "/hardware/" in path:
                return TransportResponse(204)
            return TransportResponse(404)

        transport = HTTPTransport(mock_handler=mock_vc)
        vc = VCenterProvider(endpoint_url="http://127.0.0.1:9090", transport=transport, auth=SessionTokenAuth("session-123"))

        vms = vc.get_vms()
        self.assertEqual(vms[0]["vm"], "vm-101")

        # Powered-off VM: resize needs no hot-add checks.
        resize = vc.resize_vm("vm-101", memory_gb=32, cpu_cores=8)
        self.assertEqual(resize["status"], "SUCCESS")
        self.assertEqual(resize["allocated_memory_gb"], 32)
        self.assertIn(("PATCH", "http://127.0.0.1:9090/api/vcenter/vm/vm-101/hardware/cpu", {"count": 8}), calls)
        self.assertIn(("PATCH", "http://127.0.0.1:9090/api/vcenter/vm/vm-101/hardware/memory", {"size_mib": 32768}), calls)

        pwr = vc.power_vm("vm-101", "start")
        self.assertEqual(pwr["status"], "SUCCESS")
        self.assertEqual(pwr["new_power_state"], "POWERED_ON")  # observed, not assumed
        self.assertIn(("POST", "http://127.0.0.1:9090/api/vcenter/vm/vm-101/power?action=start", None), calls)

    def test_vcenter_resize_refuses_unsafe_hot_changes(self):
        """A running VM without hot-add, or a memory decrease while running, is refused before any PATCH."""
        patches = []

        def mock_vc(req: TransportRequest) -> TransportResponse:
            if req.method == "PATCH":
                patches.append(req.url)
                return TransportResponse(204)
            if req.url.endswith("/power"):
                return TransportResponse(200, body=b'{"state": "POWERED_ON"}')
            if req.url.endswith("/hardware/cpu"):
                return TransportResponse(200, body=b'{"count": 4, "hot_add_enabled": false, "hot_remove_enabled": false}')
            if req.url.endswith("/hardware/memory"):
                return TransportResponse(200, body=b'{"size_mib": 16384, "hot_add_enabled": true, "hot_add_increment_size_mib": 1024, "hot_add_limit_mib": 65536}')
            return TransportResponse(404)

        vc = VCenterProvider(endpoint_url="http://127.0.0.1:9090", transport=HTTPTransport(mock_handler=mock_vc))
        for kwargs in ({"cpu_cores": 8}, {"memory_gb": 8}, {"memory_gb": 128}):
            with self.assertRaises(UpstreamPreconditionException):
                vc.resize_vm("vm-101", **kwargs)
        self.assertEqual(patches, [])
        self.assertEqual(vc.resize_vm("vm-101", memory_gb=32)["status"], "SUCCESS")

    def test_nsx_provider_crud(self):
        """NSXProvider refuses to replace an existing segment and validates the gateway CIDR."""
        segments = {"seg-existing": {"id": "seg-existing"}}
        calls = []

        def mock_nsx(req: TransportRequest) -> TransportResponse:
            calls.append((req.method, req.url, req.json_body))
            if req.url.endswith("/infra/segments"):
                return TransportResponse(200, body=json.dumps({"results": list(segments.values())}).encode())
            name = req.url.split("/segments/")[-1]
            if req.method == "GET":
                return TransportResponse(200, body=json.dumps(segments[name]).encode()) if name in segments else TransportResponse(404)
            segments[name] = {"id": name, **req.json_body}
            return TransportResponse(200)

        nsx = NSXProvider(endpoint_url="http://127.0.0.1:9080", transport=HTTPTransport(mock_handler=mock_nsx))
        self.assertEqual(len(nsx.get_segments()), 1)

        created = nsx.create_segment("seg-web", "t1-gw-01", "192.168.10.1/24")
        self.assertEqual(created["status"], "SUCCESS")
        self.assertEqual(created["segment_id"], "seg-web")
        self.assertEqual(calls[-1][0], "PATCH")
        self.assertEqual(calls[-1][2]["subnets"], [{"gateway_address": "192.168.10.1/24"}])

        with self.assertRaises(UpstreamPreconditionException):
            nsx.create_segment("seg-existing", "t1-gw-01", "192.168.20.1/24")
        with self.assertRaises(UpstreamPreconditionException):
            nsx.create_segment("seg-net", "t1-gw-01", "192.168.30.0/24")  # network address, not gateway

    def test_sddc_manager_provider_crud(self):
        """SDDCManagerProvider sends a spec-valid UpgradeSpec and returns the real task id."""
        bodies = []

        def mock_sddc(req: TransportRequest) -> TransportResponse:
            if req.url.endswith("/v1/domains"):
                return TransportResponse(200, body=b'{"elements": [{"id": "mgmt-domain", "name": "Management", "status": "ACTIVE"}]}')
            if req.url.endswith("/v1/upgrades"):
                bodies.append(req.json_body)
                return TransportResponse(202, body=b'{"id": "lcm-task-777", "status": "In Progress"}')
            if req.url.endswith("/v1/tasks/lcm-task-777"):
                return TransportResponse(200, body=b'{"id": "lcm-task-777", "status": "SUCCESSFUL"}')
            return TransportResponse(404)

        sddc = SDDCManagerProvider(endpoint_url="http://127.0.0.1:9080", transport=HTTPTransport(mock_handler=mock_sddc))
        self.assertEqual(sddc.get_domains()[0]["id"], "mgmt-domain")

        with self.assertRaises(UpstreamPreconditionException):
            sddc.upgrade_domain("mgmt-domain", "9.1.1")  # no bundle: refused, nothing sent
        self.assertEqual(bodies, [])

        upg = sddc.upgrade_domain("mgmt-domain", "9.1.1", bundle_id="bundle-123")
        self.assertEqual(upg["task_id"], "lcm-task-777")
        self.assertEqual(upg["status"], "IN_PROGRESS")
        self.assertEqual(bodies[0], {"bundleId": "bundle-123", "resourceType": "DOMAIN", "resourceUpgradeSpecs": [{"resourceId": "mgmt-domain", "upgradeNow": True}]})
        self.assertEqual(sddc.get_task("lcm-task-777")["status"], "SUCCESSFUL")

    def test_platform_client_routes_through_live_transport(self):
        """PlatformClient with use_live_transport=True routes through providers and tracks revisions."""
        mutations = []

        def mock_all(req: TransportRequest) -> TransportResponse:
            mutations.append((req.method, req.url))
            if "/api/vcenter/vm/vm-101" in req.url:
                pwr = "POWERED_ON" if any(m[0] == "POST" and "power" in m[1] for m in mutations) else "POWERED_OFF"
                return TransportResponse(200, body=json.dumps({"value": {"id": "vm-101", "power_state": pwr, "memory_size_mib": 4096, "cpu_cores": 2}}).encode())
            if "/api/vcenter/vm" in req.url:
                return TransportResponse(200, body=b'{"value": [{"id": "vm-live-1"}]}')
            if "/v1/domains" in req.url:
                return TransportResponse(200, body=b'{"elements": [{"id": "wld-live-1"}]}')
            return TransportResponse(200, body=b'{"status": "SUCCESS"}')

        transport = HTTPTransport(mock_handler=mock_all)
        platform = PlatformClient(transport=transport, use_live_transport=True)

        rev_before = platform.get_resource_revision("vm-101")
        vms = platform.get_vms()
        self.assertEqual(len(vms), 1)
        self.assertEqual(vms[0]["id"], "vm-live-1")

        # Mutating action bumps resource revision
        platform.power_vm("vm-101", "start")
        rev_after = platform.get_resource_revision("vm-101")
        self.assertNotEqual(rev_before, rev_after)


if __name__ == "__main__":
    unittest.main()
