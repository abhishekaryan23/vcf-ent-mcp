# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""Enterprise networking: CA bundles add to the system trust store; explicit HTTPS proxy support (review F8)."""

import socket
import ssl
import threading
from contextlib import contextmanager

import pytest

from tests.test_tls_verification_options import certs, tls_server  # noqa: F401  (fixtures)
from vcf_enterprise_mcp.adapter.ssrf_guard import SSRFGuard
from vcf_enterprise_mcp.adapter.transport.base import TransportRequest
from vcf_enterprise_mcp.adapter.transport.errors import UpstreamConnectionException
from vcf_enterprise_mcp.adapter.transport.http import (
    HTTPTransport, build_ssl_context, bypasses_proxy, parse_proxy, proxy_from_settings,
)
from vcf_enterprise_mcp.core.errors import SSRFViolationException


def test_configured_ca_is_added_to_the_system_trust_store_not_substituted(certs):
    baseline = ssl.create_default_context().cert_store_stats()["x509_ca"]
    ctx = build_ssl_context(True, str(certs / "ca.pem"))
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname
    assert ctx.cert_store_stats()["x509_ca"] == baseline + 1  # system roots kept, enterprise CA added
    assert build_ssl_context(True, None) is None              # stock verifying default
    assert build_ssl_context(False, None).verify_mode == ssl.CERT_NONE


class ConnectProxy:
    """Minimal HTTP CONNECT proxy that tunnels every request to one local port and records what it was asked for."""

    def __init__(self, backend_port, status="200 Connection established"):
        self.backend_port, self.status, self.requests = backend_port, status, []
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                client, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(client,), daemon=True).start()

    def _serve(self, client):
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = client.recv(4096)
            if not chunk:
                return
            data += chunk
        self.requests.append(data.decode("latin-1"))
        if not self.status.startswith("200"):
            client.sendall(f"HTTP/1.1 {self.status}\r\n\r\n".encode())
            client.close()
            return
        backend = socket.create_connection(("127.0.0.1", self.backend_port))
        client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")

        def pipe(src, dst):
            try:
                while True:
                    buf = src.recv(4096)
                    if not buf:
                        break
                    dst.sendall(buf)
            except OSError:
                pass
            finally:
                for s in (src, dst):
                    try:
                        s.close()
                    except OSError:
                        pass
        threading.Thread(target=pipe, args=(client, backend), daemon=True).start()
        threading.Thread(target=pipe, args=(backend, client), daemon=True).start()

    def close(self):
        self.sock.close()


@contextmanager
def proxy_for(url, **kw):
    port = int(url.split(":")[-1].rstrip("/"))
    proxy = ConnectProxy(port, **kw)
    try:
        yield proxy
    finally:
        proxy.close()


def test_requests_go_through_the_configured_proxy_and_the_guard_still_runs(certs):
    guard = SSRFGuard(dns_resolver=lambda host, port: ["127.0.0.1"])
    with tls_server(certs, "valid") as url, proxy_for(url) as proxy:
        transport = HTTPTransport(ssrf_guard=guard, max_retries=0, ca_cert_path=str(certs / "ca.pem"),
                                  proxy=parse_proxy(f"http://user:pw@127.0.0.1:{proxy.port}"))
        assert transport.send(TransportRequest(method="GET", url=url)).json() == {"ok": True}
        assert proxy.requests and proxy.requests[0].startswith(f"CONNECT localhost:{url.split(':')[-1].rstrip('/')} HTTP/1.1")
        assert "Proxy-Authorization: Basic " in proxy.requests[0]  # credentials in the proxy URL are used, never logged


def test_no_proxy_bypasses_the_proxy(certs):
    guard = SSRFGuard(dns_resolver=lambda host, port: ["127.0.0.1"])
    with tls_server(certs, "valid") as url, proxy_for(url) as proxy:
        transport = HTTPTransport(ssrf_guard=guard, max_retries=0, ca_cert_path=str(certs / "ca.pem"),
                                  proxy=parse_proxy(f"http://127.0.0.1:{proxy.port}", no_proxy="localhost"))
        assert transport.send(TransportRequest(method="GET", url=url)).json() == {"ok": True}
        assert proxy.requests == []


def test_the_ssrf_guard_checks_the_final_target_even_with_a_proxy():
    with proxy_for("https://x:1") as proxy:
        guard = SSRFGuard(allowed_dns_suffixes=[".corp.internal"], dns_resolver=lambda host, port: ["10.1.1.5"], enforce_https=True)
        transport = HTTPTransport(ssrf_guard=guard, max_retries=0, proxy=parse_proxy(f"http://127.0.0.1:{proxy.port}"))
        with pytest.raises(SSRFViolationException):
            transport.send(TransportRequest(method="GET", url="https://evil.example/"))
        with pytest.raises(SSRFViolationException):  # a metadata-service address is refused before any proxy contact
            transport.send(TransportRequest(method="GET", url="https://169.254.169.254/"))
        assert proxy.requests == []


def test_a_name_only_the_proxy_can_resolve_is_tolerated_but_not_without_a_proxy(certs):
    guard = SSRFGuard(allowed_dns_suffixes=[".test.invalid"], mock_dns={}, allow_lab_dns_fallback=False, enforce_https=True)
    with tls_server(certs, "valid") as url, proxy_for(url) as proxy:
        port = url.split(":")[-1].rstrip("/")
        target = f"https://vc.test.invalid:{port}/"
        viaproxy = HTTPTransport(ssrf_guard=guard, max_retries=0, verify_ssl=False, proxy=parse_proxy(f"http://127.0.0.1:{proxy.port}"))
        assert viaproxy.send(TransportRequest(method="GET", url=target)).json() == {"ok": True}
        assert proxy.requests[0].startswith(f"CONNECT vc.test.invalid:{port}")
        direct = HTTPTransport(ssrf_guard=guard, max_retries=0, verify_ssl=False)
        with pytest.raises(SSRFViolationException):
            direct.send(TransportRequest(method="GET", url=target))


def test_a_refused_tunnel_is_reported_as_a_proxy_problem():
    with proxy_for("https://x:1", status="403 Forbidden") as proxy:
        guard = SSRFGuard(dns_resolver=lambda host, port: ["127.0.0.1"])
        transport = HTTPTransport(ssrf_guard=guard, max_retries=0, proxy=parse_proxy(f"http://127.0.0.1:{proxy.port}"))
        with pytest.raises(UpstreamConnectionException) as err:
            transport.send(TransportRequest(method="GET", url="https://localhost:9/"))
        assert "proxy" in str(err.value).lower() and "403" in str(err.value)


def test_proxy_settings_and_no_proxy_semantics(monkeypatch):
    assert parse_proxy(None) is None
    with pytest.raises(ValueError):
        parse_proxy("https://proxy.example.internal:3128")
    monkeypatch.setenv("HTTPS_PROXY", "http://envproxy.example.internal:8080")
    monkeypatch.setenv("NO_PROXY", ".corp.internal,10.0.0.0/8")
    p = proxy_from_settings(None)
    assert (p.host, p.port) == ("envproxy.example.internal", 8080)
    assert bypasses_proxy("vc.corp.internal", p.no_proxy) and bypasses_proxy("10.2.3.4", p.no_proxy)
    assert not bypasses_proxy("vc.other.example", p.no_proxy) and not bypasses_proxy("192.168.1.1", p.no_proxy)
    assert bypasses_proxy("anything", "*")

    class Cfg:
        https_proxy = "http://cfgproxy.example.internal:3128"
        no_proxy = None
    assert proxy_from_settings(Cfg()).host == "cfgproxy.example.internal"  # config wins over the environment
