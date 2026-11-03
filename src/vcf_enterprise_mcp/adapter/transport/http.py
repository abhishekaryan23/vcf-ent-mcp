# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Production-Grade HTTP Transport for Upstream VMware Cloud Foundation (VCF) Endpoints.
Includes SSRF guardrails, exponential backoff retries with jitter, per-endpoint circuit breakers,
and explicit error translation to domain exceptions.
"""

from __future__ import annotations
import time
import random
import socket
import ssl
import logging
import http.client
import urllib.request
import urllib.error
import urllib.parse
import base64
import ipaddress
import os
from dataclasses import dataclass
from typing import Dict, Any, Optional, Callable, List
from vcf_enterprise_mcp.adapter.transport.base import (
    BaseTransport,
    TransportRequest,
    TransportResponse,
)
from vcf_enterprise_mcp.adapter.transport.errors import (
    TransportException,
    UpstreamCommunicationException,
    UpstreamConnectionException,
    UpstreamTimeoutException,
    UpstreamTLSException,
    UpstreamAuthException,
    UpstreamResourceNotFoundException,
    UpstreamRateLimitException,
    UpstreamServerException,
)
from vcf_enterprise_mcp.adapter.transport.circuit_breaker import (
    TransportCircuitBreaker,
)
from vcf_enterprise_mcp.adapter.ssrf_guard import SSRFGuard, ResolvedDestination, DNSResolutionError
from vcf_enterprise_mcp.core.headers import get_current_trace_context

logger = logging.getLogger(__name__)


def connect_validated(destination, timeout, source_address=None) -> socket.socket:
    """Opens a TCP connection to one of the destination's SSRF-validated addresses.

    The pinned address is tried first, then the other validated addresses in resolver order,
    and only when the connection itself fails (refused, unreachable, connect timeout). Nothing
    has been sent at that point, so falling back is safe for mutating requests too. Addresses
    the guard did not validate are never contacted.
    """
    ordered = [destination.pinned_ip] + [ip for ip in destination.resolved_ips if ip != destination.pinned_ip]
    last_error: Optional[OSError] = None
    for ip in ordered:
        try:
            return socket.create_connection((ip, destination.port), timeout, source_address)
        except OSError as exc:  # includes ConnectionRefusedError, socket.timeout, EHOSTUNREACH
            last_error = exc
    raise last_error or OSError(f"no validated address for {destination.hostname}")


def build_ssl_context(verify_ssl: bool = True, ca_cert_path: Optional[str] = None) -> Optional[ssl.SSLContext]:
    """TLS context for upstream VCF connections.

    A configured CA bundle is ADDED to the system trust store (a private CA file does not remove the public
    roots), so appliances signed by a public CA keep working next to ones signed by the enterprise CA.
    Returns None for the stock verifying default.
    """
    if not verify_ssl:
        return ssl._create_unverified_context()
    if ca_cert_path:
        ctx = ssl.create_default_context()           # system trust store (honours SSL_CERT_FILE / SSL_CERT_DIR)
        ctx.load_verify_locations(cafile=ca_cert_path)  # plus the configured CA(s)
        return ctx
    return None


@dataclass(frozen=True)
class ProxyConfig:
    host: str
    port: int
    authorization: Optional[str] = None   # "Basic ..." from user:password in the proxy URL; never logged
    no_proxy: str = ""


class ProxyConnectError(OSError):
    """The proxy refused or failed the CONNECT tunnel."""


def parse_proxy(proxy_url: Optional[str], no_proxy: Optional[str] = None) -> Optional[ProxyConfig]:
    """Parses http://[user:pass@]host:port. Only plain-HTTP proxies (CONNECT tunnels) are supported."""
    if not proxy_url:
        return None
    parts = urllib.parse.urlsplit(proxy_url if "://" in proxy_url else f"http://{proxy_url}")
    if parts.scheme != "http" or not parts.hostname:
        raise ValueError("vcf.https_proxy must look like http://proxy.example.internal:3128 (CONNECT tunnel to the proxy).")
    auth = None
    if parts.username:
        raw = f"{urllib.parse.unquote(parts.username)}:{urllib.parse.unquote(parts.password or '')}"
        auth = "Basic " + base64.b64encode(raw.encode("utf-8")).decode("ascii")
    return ProxyConfig(host=parts.hostname, port=parts.port or 3128, authorization=auth, no_proxy=no_proxy or "")


def proxy_from_settings(vcf_config: Any = None) -> Optional[ProxyConfig]:
    """vcf.https_proxy / vcf.no_proxy win; otherwise the standard HTTPS_PROXY / NO_PROXY environment variables."""
    url = getattr(vcf_config, "https_proxy", None) or os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
    no_proxy = getattr(vcf_config, "no_proxy", None) or os.environ.get("NO_PROXY") or os.environ.get("no_proxy") or ""
    return parse_proxy(url, no_proxy)


def bypasses_proxy(host: str, no_proxy: str) -> bool:
    """NO_PROXY semantics: '*' matches all; 'example.com' and '.example.com' match the domain and its subdomains;
    an address or CIDR matches literal IPs."""
    host = host.lower().strip("[]")
    for entry in (e.strip().lower() for e in (no_proxy or "").split(",")):
        if not entry:
            continue
        if entry == "*":
            return True
        entry = entry.rsplit(":", 1)[0] if entry.count(":") == 1 else entry
        try:
            if "/" in entry:
                if ipaddress.ip_address(host) in ipaddress.ip_network(entry, strict=False):
                    return True
                continue
            if ipaddress.ip_address(host) == ipaddress.ip_address(entry):
                return True
            continue
        except ValueError:
            pass
        bare = entry.lstrip("*").lstrip(".")
        if host == bare or host.endswith("." + bare):
            return True
    return False


def open_proxy_tunnel(proxy: ProxyConfig, host: str, port: int, timeout) -> socket.socket:
    """TCP to the proxy, then CONNECT host:port. Returns the tunnelled socket (TLS is layered on top by the caller)."""
    sock = socket.create_connection((proxy.host, proxy.port), timeout)
    try:
        target = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        lines = [f"CONNECT {target} HTTP/1.1", f"Host: {target}"]
        if proxy.authorization:
            lines.append(f"Proxy-Authorization: {proxy.authorization}")
        sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"))
        buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < 16384:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
        status_line = buf.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
        pieces = status_line.split(" ", 2)
        if len(pieces) < 2 or pieces[1] != "200":
            raise ProxyConnectError(f"proxy {proxy.host}:{proxy.port} refused CONNECT to {target}: {status_line or 'no response'}")
        return sock
    except BaseException:
        sock.close()
        raise


class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """
    SSRF-hardened redirect handler.
    Revalidates every redirect hop against SSRFGuard and strips sensitive credentials across origins (F04).
    """

    def __init__(self, ssrf_guard: SSRFGuard, via_proxy: bool = False):
        super().__init__()
        self.ssrf_guard = ssrf_guard
        self.via_proxy = via_proxy
        self.redirect_count = 0
        self.max_redirects = 5

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.redirect_count += 1
        if self.redirect_count > self.max_redirects:
            raise UpstreamCommunicationException(f"Too many redirects (exceeded limit of {self.max_redirects})")

        # Re-validate destination URL against SSRFGuard
        try:
            destination = self.ssrf_guard.resolve_destination(newurl, allow_unresolved=self.via_proxy)
        except Exception:
            # Deny redirect to destination that violates SSRF constraints
            return None

        # Check cross-origin redirect
        old_parsed = urllib.parse.urlsplit(req.full_url)
        new_parsed = urllib.parse.urlsplit(newurl)
        is_cross_origin = (
            old_parsed.scheme != new_parsed.scheme or
            old_parsed.netloc != new_parsed.netloc
        )

        new_req = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new_req is None:
            return None

        new_req._validated_destination = destination

        # Re-pin Host header to target destination host:port (Finding F04 / R04)
        new_host = new_parsed.netloc
        new_req.headers["Host"] = new_host
        new_req.unredirected_hdrs["Host"] = new_host

        # Strip authorization and session headers across origins case-insensitively (Finding F04 / R04)
        if is_cross_origin:
            sensitive_exact = {
                "authorization", "proxy-authorization", "cookie", "set-cookie",
                "vmware-api-session-id", "x-vcf-token", "x-api-key", "x-auth-token"
            }
            for d in (new_req.headers, new_req.unredirected_hdrs):
                for k in list(d.keys()):
                    kl = k.lower()
                    if kl in sensitive_exact or kl.startswith("x-vcf-"):
                        d.pop(k, None)

        return new_req


class HTTPTransport(BaseTransport):
    """
    Robust HTTP Transport connecting to upstream VMware SDDC Manager, vCenter, and NSX.
    Enforces SSRF validation, per-host circuit breaking, exponential backoff retries,
    and granular exception mapping.
    """

    def __init__(
        self,
        ssrf_guard: Optional[SSRFGuard] = None,
        max_retries: int = 3,
        backoff_factor: float = 0.2,
        circuit_breakers: Optional[Dict[str, TransportCircuitBreaker]] = None,
        mock_handler: Optional[Callable[[TransportRequest], TransportResponse]] = None,
        verify_ssl: bool = True,
        ca_cert_path: Optional[str] = None,
        proxy: Optional[ProxyConfig] = None,
    ):
        self.ssrf_guard = ssrf_guard or SSRFGuard()
        # Optional explicit HTTPS proxy (CONNECT). The SSRF guard still checks the final target (scheme, HTTPS,
        # DNS suffix, and every address it can resolve); a name only the proxy can resolve is tolerated.
        self.proxy = proxy
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.circuit_breakers = circuit_breakers if circuit_breakers is not None else {}
        self.mock_handler = mock_handler
        self.network_response_count = 0
        if not isinstance(verify_ssl, bool):
            raise ValueError("verify_ssl must be a boolean; use False explicitly to ignore certificates.")
        self.verify_ssl = verify_ssl
        self.ca_cert_path = ca_cert_path
        if not verify_ssl:
            logger.warning(
                "TLS certificate verification is DISABLED by explicit configuration for upstream VCF connections. "
                "Certificate trust, expiry and hostname checks are skipped; server identity is not verified. "
                "HTTPS encryption remains enabled. Remove --insecure or set vcf.verify_ssl=true to restore verification."
            )

    def _uses_proxy(self, url: str) -> bool:
        if self.proxy is None:
            return False
        parts = urllib.parse.urlsplit(url)
        return parts.scheme == "https" and bool(parts.hostname) and not bypasses_proxy(parts.hostname, self.proxy.no_proxy)

    def _get_circuit_breaker(self, host: str) -> TransportCircuitBreaker:
        if host not in self.circuit_breakers:
            self.circuit_breakers[host] = TransportCircuitBreaker(endpoint_id=host)
        return self.circuit_breakers[host]

    def send(self, request: TransportRequest) -> TransportResponse:
        """Executes HTTP request with SSRF validation, circuit breaker, retries, and error mapping."""
        # Upstream traceparent propagation (P2-4)
        trace_ctx = get_current_trace_context()
        if trace_ctx and not any(k.lower() == "traceparent" for k in request.headers):
            request.headers["traceparent"] = trace_ctx.to_header()

        # 1. SSRF Destination Guardrail & DNS Resolution Pinning (F04, P1-3)
        use_proxy = self._uses_proxy(request.url)
        resolved_dest = self.ssrf_guard.resolve_destination(request.url, allow_unresolved=use_proxy)

        parsed_url = urllib.parse.urlparse(request.url)
        host = parsed_url.netloc or parsed_url.hostname or "unknown"
        cb = self._get_circuit_breaker(host)

        # 2. Circuit Breaker Check
        cb.check_or_raise()

        # 3. In-Memory Mock Handler (for offline testing)
        if self.mock_handler is not None:
            return self._execute_mock(request, cb, host)

        # 4. Real HTTP Execution with Resilient Retries & Backoff
        return self._execute_http_with_retries(request, cb, host, resolved_dest)

    async def send_async(self, request: TransportRequest) -> TransportResponse:
        """Asynchronously executes HTTP request by delegating to thread pool."""
        import asyncio
        return await asyncio.to_thread(self.send, request)

    def _execute_mock(
        self,
        request: TransportRequest,
        cb: TransportCircuitBreaker,
        host: str,
    ) -> TransportResponse:
        attempt = 0
        is_mutating = request.method.upper() in ("POST", "PUT", "PATCH", "DELETE")
        while attempt <= self.max_retries:
            attempt += 1
            try:
                response = self.mock_handler(request)
                if response.status_code >= 500:
                    if not is_mutating and attempt <= self.max_retries:
                        time.sleep(self._calculate_backoff(attempt))
                        continue
                    cb.record_failure(f"HTTP {response.status_code}")
                    raise UpstreamServerException(request.url, response.status_code, response.text)
                if response.status_code == 404:
                    cb.record_success()
                    raise UpstreamResourceNotFoundException("Resource", request.url, request.url)
                if response.status_code in (401, 403):
                    cb.record_success()
                    raise UpstreamAuthException(request.url, response.status_code, response.text)
                if response.status_code == 429:
                    if attempt <= self.max_retries:
                        time.sleep(self._calculate_backoff(attempt))
                        continue
                    raise UpstreamRateLimitException(request.url)

                cb.record_success()
                return response
            except (UpstreamServerException, UpstreamConnectionException, UpstreamTimeoutException):
                if is_mutating or attempt > self.max_retries:
                    raise
                time.sleep(self._calculate_backoff(attempt))
            except Exception as e:
                cb.record_failure(str(e))
                raise

    def _execute_http_with_retries(
        self,
        request: TransportRequest,
        cb: TransportCircuitBreaker,
        host: str,
        resolved_dest: Optional[ResolvedDestination] = None,
    ) -> TransportResponse:
        full_url = request.get_full_url()
        body_bytes = request.get_body_bytes()
        is_mutating = request.method.upper() in ("POST", "PUT", "PATCH", "DELETE")

        # Keep the logical URL for redirects and Host/SNI; pin only the socket.
        via_proxy = self._uses_proxy(full_url)
        proxy = self.proxy
        destination = resolved_dest or self.ssrf_guard.resolve_destination(full_url, allow_unresolved=via_proxy)
        req_headers = {k: v for k, v in request.headers.items() if k.lower() != "host"}
        req_headers["Host"] = urllib.parse.urlsplit(full_url).netloc
        req = urllib.request.Request(full_url, data=body_bytes, headers=req_headers, method=request.method)
        req._validated_destination = destination

        ssl_ctx = build_ssl_context(self.verify_ssl, self.ca_cert_path)

        redirect_handler = SafeRedirectHandler(self.ssrf_guard, via_proxy=self.proxy is not None)
        handlers: list[Any] = [redirect_handler]

        class PinnedHTTPHandler(urllib.request.HTTPHandler):
            def http_open(self, r):
                destination = r._validated_destination
                class PinnedHTTPConnection(http.client.HTTPConnection):
                    def connect(self):
                        self.sock = connect_validated(destination, self.timeout, self.source_address)
                return self.do_open(PinnedHTTPConnection, r)

        class PinnedHTTPSHandler(urllib.request.HTTPSHandler):
            def https_open(self, r):
                destination = r._validated_destination
                class PinnedHTTPSConnection(http.client.HTTPSConnection):
                    def connect(self):
                        if proxy is not None and not bypasses_proxy(destination.hostname, proxy.no_proxy):
                            raw = open_proxy_tunnel(proxy, destination.hostname, destination.port, self.timeout)
                        else:
                            raw = connect_validated(destination, self.timeout, self.source_address)
                        try:
                            self.sock = self._context.wrap_socket(raw, server_hostname=destination.hostname)
                        except Exception:
                            raw.close()
                            raise
                return self.do_open(PinnedHTTPSConnection, r, context=self._context)

        # Never the ambient system proxy (it would bypass destination pinning): direct egress, or the explicit
        # vcf.https_proxy / HTTPS_PROXY tunnel configured above (whose target the SSRF guard has already checked).
        handlers.extend([urllib.request.ProxyHandler({}), PinnedHTTPHandler()])
        if ssl_ctx:
            handlers.append(PinnedHTTPSHandler(context=ssl_ctx))
        else:
            handlers.append(PinnedHTTPSHandler())

        opener = urllib.request.build_opener(*handlers)

        attempt = 0
        last_exception: Optional[Exception] = None

        while attempt <= self.max_retries:
            attempt += 1
            start_time = time.time()
            try:
                cm = opener.open(req, timeout=request.timeout_seconds)

                with cm as resp:
                    elapsed = time.time() - start_time
                    resp_body = resp.read()
                    status = resp.getcode()
                    self.network_response_count += 1
                    headers = dict(resp.headers)
                    cb.record_success()
                    return TransportResponse(
                        status_code=status,
                        headers=headers,
                        body=resp_body,
                        elapsed_seconds=elapsed,
                    )
            except urllib.error.HTTPError as he:
                elapsed = time.time() - start_time
                error_body = he.read()
                err_text = error_body.decode("utf-8", errors="replace")

                # Retriable server errors: only idempotent methods (GET/HEAD)
                # Mutating operations must never be blindly retried on 5xx (F05)
                if he.code in (500, 502, 503, 504):
                    if not is_mutating and attempt <= self.max_retries:
                        time.sleep(self._calculate_backoff(attempt))
                        continue
                    cb.record_failure(f"HTTP {he.code}")
                    raise UpstreamServerException(full_url, he.code, err_text)
                elif he.code in (401, 403):
                    cb.record_success()
                    raise UpstreamAuthException(full_url, he.code, err_text)
                elif he.code == 404:
                    cb.record_success()
                    raise UpstreamResourceNotFoundException("Resource", full_url, full_url)
                elif he.code == 429:
                    retry_after = float(he.headers.get("Retry-After", 1.0))
                    if attempt <= self.max_retries:
                        time.sleep(retry_after)
                        continue
                    raise UpstreamRateLimitException(full_url, retry_after=retry_after)
                else:
                    cb.record_success()
                    return TransportResponse(
                        status_code=he.code,
                        headers=dict(he.headers),
                        body=error_body,
                        elapsed_seconds=elapsed,
                    )
            except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError, OSError) as e:
                is_timeout = isinstance(e, (socket.timeout, TimeoutError)) or (
                    isinstance(e, urllib.error.URLError) and "timed out" in str(e).lower()
                )
                is_tls = isinstance(e, ssl.SSLError) or (
                    isinstance(e, urllib.error.URLError) and "certificate" in str(e).lower()
                )

                if is_timeout:
                    last_exception = UpstreamTimeoutException(full_url, request.timeout_seconds)
                    if is_mutating:
                        # Mutating methods (POST/PUT/PATCH/DELETE) must NOT blind retry on timeout (F05)
                        raise last_exception
                elif is_tls:
                    last_exception = UpstreamTLSException(full_url, str(e))
                else:
                    last_exception = UpstreamConnectionException(full_url, str(e))

                # TLS failures do not benefit from blind retries, nor do mutating methods (F05).
                if attempt <= self.max_retries and not is_mutating and not is_tls:
                    time.sleep(self._calculate_backoff(attempt))
                    continue
                # One failed request counts once, however many attempts it took, so a single tool call
                # cannot open the breaker by itself.
                cb.record_failure(str(e))
                raise last_exception

        if last_exception:
            raise last_exception
        raise UpstreamCommunicationException(f"Failed to communicate with '{full_url}' after {self.max_retries} retries.")

    def _calculate_backoff(self, attempt: int) -> float:
        """Calculates exponential backoff with full jitter to avoid thundering herd."""
        delay = self.backoff_factor * (2 ** (attempt - 1))
        # Add random jitter between 0 and 50% of delay
        jitter = random.uniform(0, 0.5 * delay)
        return delay + jitter
