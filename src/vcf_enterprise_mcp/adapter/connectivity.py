# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Turns a failed connection to a VCF appliance into a cause class plus the exact configuration key to change.

Used by guided setup (so a TLS or allowlist problem is not reported as a wrong password) and by the
troubleshooting engine (so the MCP's own network policy is never presented as an appliance fault).
"""

from __future__ import annotations

import ipaddress
import re
import urllib.parse
from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional

from vcf_enterprise_mcp.adapter.transport.errors import (
    UpstreamAuthException,
    UpstreamConnectionException,
    UpstreamTimeoutException,
    UpstreamTLSException,
)
from vcf_enterprise_mcp.core.errors import SSRFViolationException

DEFAULT_CIDRS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "::1/128"]


@dataclass
class ConnectionProblem:
    cause: str                      # auth_rejected | tls_certificate | dns | connection_refused | timeout | proxy |
                                    # mcp_allowlist_dns_suffix | mcp_allowlist_cidr | mcp_loopback_blocked |
                                    # mcp_blocked_range | mcp_https_required | unreachable | other
    summary: str
    config_key: Optional[str] = None
    fix: Optional[str] = None       # exact YAML to put in the MCP config file
    mcp_config_problem: bool = False  # True: this MCP's own policy blocked it; the appliance may be perfectly healthy
    host: Optional[str] = None
    change: Optional[Dict[str, Any]] = None  # machine-readable form of `fix` that setup can apply after the user agrees

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


def suffix_for_host(host: str) -> Optional[str]:
    """The DNS suffix to allow for a host: '.corp.example' for vc.corp.example, the name itself for a single label.
    None for IP literals (those belong in allowed_cidrs)."""
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return None
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass
    return "." + host.split(".", 1)[1] if "." in host else host


def apply_endpoint_override(url: Optional[str], overrides: Optional[Dict[str, str]]) -> Optional[str]:
    """Maps a configured appliance URL through vcf.endpoint_overrides (host name -> reachable URL), so a name that
    does not resolve from this machine can still be used. Unmapped URLs are returned unchanged."""
    if not url or not overrides:
        return url
    host = (urllib.parse.urlsplit(url).hostname or "").lower().rstrip(".")
    for name, target in overrides.items():
        if str(name).strip().lower().rstrip(".") == host and target:
            return str(target)
    return url


def _current_list(vcf_config: Any, attr: str) -> list:
    return list(getattr(vcf_config, attr, None) or [])


def classify_connection_error(exc: BaseException, url: str = "", vcf_config: Any = None) -> ConnectionProblem:
    """Classifies a transport/SSRF exception. `vcf_config` (the vcf section) lets the fix show the existing list plus the addition."""
    host = urllib.parse.urlsplit(url).hostname if url else None
    text = str(exc)

    if isinstance(exc, UpstreamAuthException):
        code = exc.details.get("status_code")
        return ConnectionProblem("auth_rejected", f"The appliance rejected the login (HTTP {code}): wrong or expired password, locked account, "
                                 "or the account lacks the role.", host=host)

    if isinstance(exc, SSRFViolationException):
        if "does not match allowed enterprise DNS suffixes" in text:
            m = re.search(r"Host '([^']+)'", text)
            blocked = m.group(1) if m else host
            suffix = suffix_for_host(blocked or "")
            current = _current_list(vcf_config, "allowed_dns_suffixes")
            wanted = current + ([suffix] if suffix and suffix not in current else [])
            fix = f"vcf:\n  allowed_dns_suffixes: {wanted!r}".replace("'", '"') if suffix else None
            return ConnectionProblem(
                "mcp_allowlist_dns_suffix",
                f"This MCP's network allowlist does not include '{blocked}'. This is an MCP configuration problem, not an appliance fault. "
                "If the name should not resolve from this machine, map it with vcf.endpoint_overrides instead.",
                "vcf.allowed_dns_suffixes", fix, True, blocked,
                {"key": "allowed_dns_suffixes", "add": suffix} if suffix else None)
        if "not in allowed enterprise CIDRs" in text:
            m = re.search(r"\(IP: ([^)]+)\)", text)
            ip = m.group(1) if m else None
            current = _current_list(vcf_config, "allowed_cidrs") or list(DEFAULT_CIDRS)
            wanted = current + ([f"{ip}/32"] if ip and f"{ip}/32" not in current else [])
            return ConnectionProblem(
                "mcp_allowlist_cidr",
                f"The appliance address {ip or ''} is outside the network ranges this MCP may contact (default: private RFC1918 and loopback). "
                "This is an MCP configuration problem, not an appliance fault.",
                "vcf.allowed_cidrs", f"vcf:\n  allowed_cidrs: {wanted!r}".replace("'", '"') if ip else None, True, host,
                {"key": "allowed_cidrs", "add": f"{ip}/32"} if ip else None)
        if "Loopback" in text:
            return ConnectionProblem(
                "mcp_loopback_blocked", "The appliance is on this machine's loopback address, which this MCP blocks unless you allow it for a lab.",
                "vcf.allow_loopback_targets", "vcf:\n  allow_loopback_targets: true   # lab only; refused in production mode", True, host,
                {"key": "allow_loopback_targets", "set": True})
        if "blocked subnet" in text:
            return ConnectionProblem(
                "mcp_blocked_range", "The appliance address is in a range this MCP never contacts (link-local, carrier-grade NAT or reserved). "
                "It cannot be allowed; use an address in your management network.", None, None, True, host)
        if "HTTPS is enforced" in text:
            return ConnectionProblem("mcp_https_required", "The URL must start with https://.", "vcf.*_url", None, True, host)
        if "DNS resolution failed" in text:
            return ConnectionProblem(
                "dns", f"The name '{host}' does not resolve from this machine. Check DNS, the VPN, or map the name to a reachable address "
                "with vcf.endpoint_overrides.", "vcf.endpoint_overrides",
                f'vcf:\n  endpoint_overrides:\n    "{host}": "https://<reachable-address>:443"' if host else None, False, host)
        return ConnectionProblem("mcp_allowlist_dns_suffix", "This MCP's network policy blocked the destination: " + text, "vcf.allowed_dns_suffixes",
                                 None, True, host)

    if isinstance(exc, UpstreamTLSException):
        reason = str(exc.details.get("reason") or text).lower()
        if "expired" in reason:
            summary = "The appliance's TLS certificate has expired. Renew it on the appliance."
            return ConnectionProblem("tls_certificate", summary, None, None, False, host)
        if "hostname" in reason or "doesn't match" in reason or "does not match" in reason:
            return ConnectionProblem("tls_certificate", "The certificate does not cover this name: use the FQDN in the certificate, or reissue it "
                                     "with the right Subject Alternative Names.", None, None, False, host)
        return ConnectionProblem(
            "tls_certificate",
            "The appliance's certificate is not trusted by this machine. Point the MCP at the CA chain that signed it; it is added to the "
            "system trust store (it does not replace it). For a throwaway lab only, vcf.verify_ssl: false also works.",
            "vcf.ca_cert_path", 'vcf:\n  ca_cert_path: "/path/to/enterprise-ca-chain.pem"', False, host)

    if isinstance(exc, UpstreamTimeoutException):
        return ConnectionProblem("timeout", "The appliance did not answer in time: check firewall, VPN or routing from this machine. If a proxy "
                                 "is required, set vcf.https_proxy (or HTTPS_PROXY).", "vcf.https_proxy", None, False, host)

    if isinstance(exc, UpstreamConnectionException):
        reason = str(exc.details.get("reason") or text).lower()
        if "proxy" in reason:
            return ConnectionProblem("proxy", "The proxy could not open a tunnel to the appliance: " + str(exc.details.get("reason") or text)[:200],
                                     "vcf.https_proxy", None, False, host)
        if "refused" in reason:
            return ConnectionProblem("connection_refused", "Connection refused: nothing is listening on that address and port. Check the URL "
                                     "(and port) and that the appliance is up.", None, None, False, host)
        if "name or service not known" in reason or "nodename nor servname" in reason or "getaddrinfo" in reason:
            return ConnectionProblem("dns", f"The name '{host}' does not resolve from this machine.", "vcf.endpoint_overrides", None, False, host)
        if "timed out" in reason:
            return ConnectionProblem("timeout", "The connection timed out: check firewall, VPN or routing. If a proxy is required, set "
                                     "vcf.https_proxy (or HTTPS_PROXY).", "vcf.https_proxy", None, False, host)
        return ConnectionProblem("unreachable", "Could not open a TCP connection: check the address, firewall and VPN. If a proxy is required, "
                                 "set vcf.https_proxy (or HTTPS_PROXY).", "vcf.https_proxy", None, False, host)

    return ConnectionProblem("other", f"{type(exc).__name__} while contacting the appliance.", None, None, False, host)
