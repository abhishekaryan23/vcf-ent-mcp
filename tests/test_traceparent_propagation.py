# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Tests for W3C TraceContext and traceparent upstream propagation (P2-4).
Verifies that incoming MCP trace context is propagated across execution boundaries
to outgoing Broadcom appliance HTTP transport requests.
"""

import unittest
import asyncio
from typing import Dict, Any, List
from vcf_enterprise_mcp.core.headers import (
    TraceContext,
    validate_mcp_headers,
    get_current_trace_context,
    set_current_trace_context,
)
from vcf_enterprise_mcp.adapter.transport.base import TransportRequest, TransportResponse
from vcf_enterprise_mcp.adapter.transport.http import HTTPTransport
from vcf_enterprise_mcp.adapter.ssrf_guard import SSRFGuard
from vcf_enterprise_mcp.core.protocol import EnterpriseMCPProtocolEngine
from vcf_enterprise_mcp.auth.identity import Principal
from vcf_enterprise_mcp.auth.idp import EnterpriseIdPValidator
from vcf_enterprise_mcp.adapter.platform import PlatformClient, PlatformMode


class TestTraceparentPropagation(unittest.TestCase):
    """Test suite ensuring W3C traceparent headers are propagated upstream to VCF appliances."""

    def setUp(self):
        self.guard = SSRFGuard()
        self.captured_requests: List[TransportRequest] = []

        def mock_upstream(req: TransportRequest) -> TransportResponse:
            self.captured_requests.append(req)
            return TransportResponse(status_code=200, body=b'{"status": "OK"}')

        self.transport = HTTPTransport(
            ssrf_guard=self.guard,
            mock_handler=mock_upstream,
        )
        set_current_trace_context(None)

    def tearDown(self):
        set_current_trace_context(None)

    def test_direct_trace_contextvar_and_transport_injection(self):
        """Verifies HTTPTransport.send automatically injects traceparent from contextvar."""
        trace_id = "4bf92f3577b34da6a3ce929d0e0e4736"
        span_id = "00f067aa0ba902b7"
        ctx = TraceContext(trace_id=trace_id, span_id=span_id, trace_flags="01")
        set_current_trace_context(ctx)

        req = TransportRequest(method="GET", url="https://vcf.corp.internal/api/vcenter/vm")
        resp = self.transport.send(req)

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(self.captured_requests), 1)
        sent_headers = self.captured_requests[0].headers
        self.assertIn("traceparent", sent_headers)
        self.assertEqual(sent_headers["traceparent"], f"00-{trace_id}-{span_id}-01")

    def test_existing_traceparent_preserved(self):
        """Verifies if request already contains an explicit traceparent, it is not overwritten."""
        set_current_trace_context(TraceContext("11111111111111111111111111111111", "2222222222222222"))

        custom_traceparent = "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01"
        req = TransportRequest(
            method="GET",
            url="https://vcf.corp.internal/api/vcenter/vm",
            headers={"traceparent": custom_traceparent},
        )
        self.transport.send(req)

        self.assertEqual(len(self.captured_requests), 1)
        self.assertEqual(self.captured_requests[0].headers["traceparent"], custom_traceparent)

    def test_validate_mcp_headers_sets_trace_context(self):
        """Verifies validate_mcp_headers sets the contextvar from incoming HTTP headers."""
        incoming_headers = {
            "traceparent": "00-aabbccddeeff00112233445566778899-12345678abcdef01-01",
            "Mcp-Method": "tools/call",
            "Mcp-Name": "vcf_list_vms",
        }
        body = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "vcf_list_vms", "arguments": {}},
        }

        body["params"]["_meta"] = {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}
        incoming_headers["MCP-Protocol-Version"] = "2026-07-28"
        ctx = validate_mcp_headers(incoming_headers, body)
        self.assertEqual(ctx.trace_id, "aabbccddeeff00112233445566778899")
        self.assertEqual(ctx.span_id, "12345678abcdef01")

        active_ctx = get_current_trace_context()
        self.assertIsNotNone(active_ctx)
        self.assertEqual(active_ctx.trace_id, "aabbccddeeff00112233445566778899")

    def test_end_to_end_protocol_engine_traceparent_propagation(self):
        """
        Verifies end-to-end request through EnterpriseMCPProtocolEngine:
        Incoming traceparent is received, set into context, propagated through tool execution,
        and captured on the upstream HTTP request.
        """
        import json
        from tests.fixtures.jwt_factory import JWTTestFactory

        engine = EnterpriseMCPProtocolEngine(
            platform_client=PlatformClient(
                mode=PlatformMode.REAL_VCF,
                transport=self.transport,
            )
        )

        jwt_factory = JWTTestFactory()
        jwt_factory.register_with_jwks(engine.idp.jwks_manager)

        test_token = jwt_factory.create_token(
            user_id="alice-admin",
            groups=["VCF-Platform-Admins"],
            roles=["PlatformAdmin"],
            tenant_id="tenant-prod",
            allowed_clusters=["*"],
            extra_claims={"env_id": "env-prod"},
        )

        incoming_traceparent = "00-55555555555555555555555555555555-7777777777777777-01"
        incoming_headers = {
            "traceparent": incoming_traceparent,
            "Mcp-Method": "tools/call",
            "Mcp-Name": "vcf_list_vms",
        }
        rpc_request = {
            "jsonrpc": "2.0",
            "id": "req-trace-01",
            "method": "tools/call",
            "params": {
                "name": "vcf_list_vms",
                "arguments": {},
            },
        }

        # Mock platform response in captured handler
        def mock_vms(req: TransportRequest) -> TransportResponse:
            self.captured_requests.append(req)
            return TransportResponse(
                status_code=200,
                body=json.dumps({"value": [{"vm": "vm-101", "name": "app-web-01", "power_state": "POWERED_ON"}]}).encode("utf-8"),
            )
        self.transport.mock_handler = mock_vms

        rpc_request["params"]["_meta"] = {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}
        incoming_headers["MCP-Protocol-Version"] = "2026-07-28"
        response = asyncio.run(engine.handle_jsonrpc_request(
            request=rpc_request,
            headers=incoming_headers,
            auth_header=f"Bearer {test_token}",
            client_ip="127.0.0.1",
        ))

        self.assertNotIn("error", response)
        self.assertEqual(len(self.captured_requests), 1)
        sent_req = self.captured_requests[0]
        self.assertIn("traceparent", sent_req.headers)
        self.assertEqual(sent_req.headers["traceparent"], incoming_traceparent)

        # Ensure context was cleaned up after request execution
        self.assertIsNone(get_current_trace_context())


if __name__ == "__main__":
    unittest.main()
