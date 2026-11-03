# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Test Suite: SSRF and DNS Rebinding Protection (Finding P1-3).

Validates:
1. Direct IP blocking: AWS/Azure/GCP cloud metadata (169.254.169.254), CGNAT (100.64.0.0/10), IPv6 link-local (fe80::/10); IPv6 loopback (::1) is treated like 127.0.0.1 (allowed only when allow_loopback is on).
2. DNS Whitelist rejection: Hostnames that do not match allowed enterprise DNS suffixes.
3. DNS Rebinding detection: Hostname matches approved suffix, but DNS resolves to cloud metadata IP (169.254.169.254).
4. Loopback Rebinding detection: Hostname resolves to 127.0.0.1 when allow_loopback is False.
5. Outside CIDR Rebinding detection: Hostname resolves to public IP outside allowed enterprise CIDRs.
6. Multi-address inspection: Rejection if ANY resolved IP falls in a blocked range.
7. ResolvedDestination pinning: Valid enterprise host resolves to allowed IP with pinned destination.
8. HTTPS enforcement: Plaintext HTTP rejected when enforce_https is True.
9. HTTPTransport integration: Attempted request to rebinding host is blocked before dispatch.
"""

import unittest
from vcf_enterprise_mcp.adapter.ssrf_guard import SSRFGuard, ResolvedDestination
from vcf_enterprise_mcp.adapter.transport.http import HTTPTransport
from vcf_enterprise_mcp.adapter.transport.base import TransportRequest
from vcf_enterprise_mcp.core.errors import SSRFViolationException


class TestSSRFAndDNSRebinding(unittest.TestCase):

    def setUp(self):
        self.guard = SSRFGuard(
            allowed_dns_suffixes=[".corp.internal", ".corp.local", ".vmware.local"],
            allowed_cidrs=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
            allow_loopback=False,  # Enforce strict production-like loopback restriction
            enforce_https=False,
        )

    def test_direct_cloud_metadata_ip_blocked(self):
        """169.254.169.254 (IMDS) must be blocked directly."""
        with self.assertRaises(SSRFViolationException) as ctx:
            self.guard.resolve_destination("http://169.254.169.254/latest/meta-data")
        self.assertIn("blocked subnet", str(ctx.exception))

    def test_direct_cgnat_and_link_local_blocked(self):
        """CGNAT (100.64.0.1) and link-local ranges must be blocked."""
        with self.assertRaises(SSRFViolationException):
            self.guard.resolve_destination("http://100.64.0.1/status")

        with self.assertRaises(SSRFViolationException):
            self.guard.resolve_destination("http://169.254.10.20/api")

    def test_unauthorized_dns_suffix_rejected(self):
        """Hostnames outside enterprise whitelist must be rejected without DNS lookup."""
        with self.assertRaises(SSRFViolationException) as ctx:
            self.guard.resolve_destination("http://attacker.com/vcf-steal")
        self.assertIn("does not match allowed enterprise DNS suffixes", str(ctx.exception))

    def test_dns_rebinding_to_cloud_metadata_blocked(self):
        """Hostname matches .corp.local but DNS resolves to 169.254.169.254 (DNS Rebinding Attack)."""
        rebound_guard = SSRFGuard(
            allowed_dns_suffixes=[".corp.local"],
            allowed_cidrs=["10.0.0.0/8"],
            dns_resolver=lambda host, port: ["169.254.169.254"],
        )
        with self.assertRaises(SSRFViolationException) as ctx:
            rebound_guard.resolve_destination("http://vcenter.corp.local/api")
        self.assertIn("falls within blocked subnet", str(ctx.exception))
        self.assertIn("169.254.169.254", str(ctx.exception))

    def test_dns_rebinding_to_loopback_blocked(self):
        """Hostname matches .corp.internal but DNS resolves to 127.0.0.1 when allow_loopback=False."""
        rebound_guard = SSRFGuard(
            allowed_dns_suffixes=[".corp.internal"],
            allowed_cidrs=["10.0.0.0/8"],
            allow_loopback=False,
            dns_resolver=lambda host, port: ["127.0.0.1"],
        )
        with self.assertRaises(SSRFViolationException) as ctx:
            rebound_guard.resolve_destination("http://sddc.corp.internal/api")
        self.assertIn("Loopback 'sddc.corp.internal' is prohibited", str(ctx.exception))

    def test_dns_rebinding_to_public_ip_outside_allowed_cidrs_blocked(self):
        """Hostname matches .corp.internal but resolves to public IP 93.184.216.34 outside enterprise CIDRs."""
        rebound_guard = SSRFGuard(
            allowed_dns_suffixes=[".corp.internal"],
            allowed_cidrs=["10.0.0.0/8"],
            dns_resolver=lambda host, port: ["93.184.216.34"],
        )
        with self.assertRaises(SSRFViolationException) as ctx:
            rebound_guard.resolve_destination("http://mgmt.corp.internal/vcf")
        self.assertIn("not in allowed enterprise CIDRs", str(ctx.exception))

    def test_multi_ip_resolution_rejects_if_any_ip_is_blocked(self):
        """If DNS returns multiple IPs and one is malicious metadata, the request must be aborted."""
        rebound_guard = SSRFGuard(
            allowed_dns_suffixes=[".corp.local"],
            allowed_cidrs=["10.0.0.0/8"],
            dns_resolver=lambda host, port: ["10.0.0.15", "169.254.169.254"],
        )
        with self.assertRaises(SSRFViolationException) as ctx:
            rebound_guard.resolve_destination("http://vcenter.corp.local/api")
        self.assertIn("blocked subnet", str(ctx.exception))

    def test_valid_enterprise_resolution_and_pinning(self):
        """Legitimate destination resolves to allowed CIDR IP and returns pinned ResolvedDestination."""
        valid_guard = SSRFGuard(
            allowed_dns_suffixes=[".corp.internal"],
            allowed_cidrs=["10.0.0.0/8"],
            dns_resolver=lambda host, port: ["10.10.20.5"],
        )
        dest = valid_guard.resolve_destination("https://sddc-manager.corp.internal:8443/v1/domains")
        self.assertIsInstance(dest, ResolvedDestination)
        self.assertEqual(dest.hostname, "sddc-manager.corp.internal")
        self.assertEqual(dest.port, 8443)
        self.assertEqual(dest.pinned_ip, "10.10.20.5")
        self.assertEqual(dest.scheme, "https")
        self.assertEqual(dest.get_pinned_url(), "https://10.10.20.5:8443/v1/domains")

    def test_enforce_https_rejects_plain_http(self):
        """When enforce_https=True, plain HTTP URLs must be rejected."""
        https_guard = SSRFGuard(
            allowed_dns_suffixes=[".corp.internal"],
            allowed_cidrs=["10.0.0.0/8"],
            enforce_https=True,
            dns_resolver=lambda host, port: ["10.0.0.10"],
        )
        with self.assertRaises(SSRFViolationException) as ctx:
            https_guard.resolve_destination("http://sddc-manager.corp.internal/v1/domains")
        self.assertIn("HTTPS is enforced in production mode", str(ctx.exception))

    def test_http_transport_blocks_rebinding_before_network_dispatch(self):
        """HTTPTransport.send must abort with SSRFViolationException on rebinding targets."""
        rebound_guard = SSRFGuard(
            allowed_dns_suffixes=[".corp.local"],
            allowed_cidrs=["10.0.0.0/8"],
            dns_resolver=lambda host, port: ["169.254.169.254"],
        )
        transport = HTTPTransport(ssrf_guard=rebound_guard)
        req = TransportRequest(method="GET", url="http://vcenter.corp.local/api/vms")

        with self.assertRaises(SSRFViolationException):
            transport.send(req)


if __name__ == "__main__":
    unittest.main()


class TestIPv6LoopbackParity(unittest.TestCase):
    """'localhost' resolves to both 127.0.0.1 and ::1, so both loopbacks follow allow_loopback."""

    def test_ipv6_loopback_follows_allow_loopback(self):
        from vcf_enterprise_mcp.adapter.ssrf_guard import SSRFGuard
        from vcf_enterprise_mcp.core.errors import SSRFViolationException
        resolver = lambda host, port: ["127.0.0.1", "::1"]  # noqa: E731
        strict = SSRFGuard(allow_loopback=False, enforce_https=True, dns_resolver=resolver)
        with self.assertRaises(SSRFViolationException):
            strict.resolve_destination("https://localhost:9443/api/session")
        lab = SSRFGuard(allow_loopback=True, enforce_https=True, dns_resolver=resolver)
        self.assertTrue(lab.resolve_destination("https://localhost:9443/api/session"))


class TestValidatedAddressFallback(unittest.TestCase):
    """A host whose first resolved address is unreachable still works via its other validated address."""

    def _server(self):
        import http.server, threading
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), type("H", (http.server.BaseHTTPRequestHandler,), {
            "do_GET": lambda self: (self.send_response(200), self.send_header("Content-Length", "2"), self.end_headers(), self.wfile.write(b"ok")),
            "log_message": lambda self, *a: None,
        }))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        return srv.server_address[1]

    def test_falls_back_to_next_validated_address(self):
        from vcf_enterprise_mcp.adapter.transport.base import TransportRequest
        port = self._server()
        # ::1 is validated but nothing listens there; 127.0.0.1 answers.
        guard = SSRFGuard(allow_loopback=True, dns_resolver=lambda h, p: ["::1", "127.0.0.1"])
        resp = HTTPTransport(ssrf_guard=guard, max_retries=0).send(TransportRequest("GET", f"http://localhost:{port}/"))
        self.assertEqual(resp.status_code, 200)

    def test_all_unreachable_fails_and_unvalidated_ips_are_never_tried(self):
        from vcf_enterprise_mcp.adapter.transport.base import TransportRequest
        from vcf_enterprise_mcp.adapter.transport.errors import UpstreamConnectionException
        from vcf_enterprise_mcp.adapter.transport import http as http_mod
        guard = SSRFGuard(allow_loopback=True, dns_resolver=lambda h, p: ["::1", "127.0.0.1"])
        tried = []
        real = http_mod.socket.create_connection

        def spy(addr, *a, **k):
            tried.append(addr[0])
            return real(addr, *a, **k)
        http_mod.socket.create_connection = spy
        try:
            with self.assertRaises(UpstreamConnectionException):
                HTTPTransport(ssrf_guard=guard, max_retries=0).send(TransportRequest("POST", "http://localhost:9/", json_body={}))
        finally:
            http_mod.socket.create_connection = real
        self.assertEqual(tried, ["::1", "127.0.0.1"])  # each validated address once, nothing else
