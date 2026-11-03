# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
SSRF (Server-Side Request Forgery) Protection & Destination Validator.
Guarantees that discovery, onboarding, and upstream calls cannot probe cloud metadata services,
link-local addresses, loopback (in production), or arbitrary unapproved network destinations.
Enforces DNS resolution inspection and pinned connections against DNS rebinding (Finding P1-3).
"""

from __future__ import annotations
import os
import socket
import ipaddress
import urllib.parse
from dataclasses import dataclass
from typing import List, Optional, Dict, Tuple, Callable
from vcf_enterprise_mcp.core.errors import SSRFViolationException


BLOCKED_NETWORKS = [
    ipaddress.ip_network("169.254.0.0/16"),       # Link-local / AWS / Azure / GCP IMDS metadata
    ipaddress.ip_network("100.64.0.0/10"),        # Shared address space / CGNAT
    ipaddress.ip_network("0.0.0.0/8"),            # Current network
    ipaddress.ip_network("240.0.0.0/4"),          # Reserved
    ipaddress.ip_network("fe80::/10"),            # IPv6 link-local
    ipaddress.ip_network("fc00::/7"),             # IPv6 unique local (unless explicitly enabled)
]


class DNSResolutionError(SSRFViolationException):
    """The destination name did not resolve. Still an SSRF violation for direct connections; with an explicit
    proxy the proxy resolves it, so the guard can be asked to tolerate exactly this case."""


@dataclass(frozen=True)
class ResolvedDestination:
    """
    Cryptographically and topologically validated network destination.
    Contains DNS-resolved IP addresses and pinned address to eliminate TOCTOU DNS rebinding.
    """
    original_url: str
    scheme: str
    hostname: str
    port: int
    resolved_ips: Tuple[str, ...]
    pinned_ip: str

    def get_pinned_url(self) -> str:
        """Constructs URL with pinned IP replacing hostname to eliminate TOCTOU rebinding."""
        parsed = urllib.parse.urlsplit(self.original_url)
        # Format IPv6 addresses with brackets if needed
        ip_str = f"[{self.pinned_ip}]" if ":" in self.pinned_ip else self.pinned_ip
        netloc = f"{ip_str}:{self.port}" if self.port else ip_str
        return urllib.parse.urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))


class SSRFGuard:
    """
    Validates URLs against permitted enterprise suffixes and blocked IP ranges.
    Resolves DNS and performs multi-address inspection against metadata and CIDR bounds
    to prevent DNS rebinding and SSRF attacks (P1-3).
    """

    def __init__(
        self,
        allowed_dns_suffixes: Optional[List[str]] = None,
        allowed_cidrs: Optional[List[str]] = None,
        allow_loopback: bool = True,  # Allowed for local lab/mock testing
        enforce_https: bool = False,  # Enforced in production mode
        dns_resolver: Optional[Callable[[str, int], List[str]]] = None,
        mock_dns: Optional[Dict[str, List[str]]] = None,
        allow_lab_dns_fallback: bool = True,
    ):
        self.allowed_dns_suffixes = allowed_dns_suffixes or [
            ".corp.internal",
            ".corp.local",
            ".vmware.local",
            ".vcf.internal",
            "localhost",
            "127.0.0.1",
        ]
        self.allowed_cidrs = [
            ipaddress.ip_network(c)
            for c in (allowed_cidrs or ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "::1/128"])
        ]
        self.allow_loopback = allow_loopback
        self.enforce_https = enforce_https
        self.dns_resolver = dns_resolver
        # Real-VCF deployments pass mock_dns={} and allow_lab_dns_fallback=False so that hosts
        # resolve only through the system resolver and never to the lab placeholder addresses.
        self.allow_lab_dns_fallback = allow_lab_dns_fallback
        self.mock_dns = mock_dns if mock_dns is not None else {
            "sddc-manager.corp.internal": ["10.0.0.100"],
            "vcenter.corp.local": ["10.0.0.101"],
            "nsx-mgr.corp.internal": ["10.0.0.102"],
            "vcf-ops.corp.internal": ["10.0.0.103"],
        }

    def _resolve_host(self, host: str, port: int) -> List[str]:
        """Resolves host using custom resolver, mock DNS table, or system resolver."""
        if self.dns_resolver:
            return self.dns_resolver(host, port)
        if host in self.mock_dns:
            return self.mock_dns[host]

        try:
            infos = socket.getaddrinfo(host, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
            return list(dict.fromkeys(info[4][0] for info in infos))
        except socket.gaierror as e:
            if os.environ.get("VCF_MCP_ENV") == "production" or not self.allow_lab_dns_fallback:
                raise DNSResolutionError(f"DNS resolution failed for '{host}': {e}")
            # In test/lab environment, if domain has approved suffix, resolve to default lab IP
            if any(host == s or host.endswith(s) for s in self.allowed_dns_suffixes):
                return ["10.0.0.50"]
            raise DNSResolutionError(f"DNS resolution failed for '{host}': {e}")

    def _validate_ip_address(self, ip_str: str, host_context: str) -> None:
        """Validates that an IP address is not in blocked ranges and is in allowed CIDRs."""
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            raise SSRFViolationException(f"Invalid IP address format '{ip_str}' for host '{host_context}'.")

        # 1. Check blocked metadata & link-local ranges
        for blocked in BLOCKED_NETWORKS:
            if ip in blocked:
                raise SSRFViolationException(
                    f"SSRF violation: Host '{host_context}' falls within blocked subnet '{blocked}' (IP: {ip_str})."
                )

        # 2. Check loopback restrictions (IPv4 and IPv6 loopback alike; "localhost" resolves to both)
        if ip.is_loopback and not self.allow_loopback:
            raise SSRFViolationException(
                f"SSRF violation: Loopback '{host_context}' is prohibited in production mode (IP: {ip_str})."
            )

        # 3. Validate against allowed enterprise CIDRs
        in_allowed_cidr = any(ip in cidr for cidr in self.allowed_cidrs)
        if not in_allowed_cidr:
            raise SSRFViolationException(
                f"SSRF violation: Host '{host_context}' (IP: {ip_str}) is not in allowed enterprise CIDRs."
            )

    def resolve_destination(self, url: str, allow_unresolved: bool = False) -> ResolvedDestination:
        """
        Validates destination URL, resolves DNS, checks all resolved IPs,
        and returns a ResolvedDestination with pinned connection attributes (P1-3).

        allow_unresolved is for connections made through an explicit proxy: the scheme, HTTPS, DNS-suffix and
        every address check still apply, but a name that only the proxy can resolve is tolerated (the result
        then has no pinned address; the proxy opens the connection).
        """
        parsed = urllib.parse.urlparse(url)
        if not parsed.scheme or parsed.scheme not in ["http", "https"]:
            raise SSRFViolationException(f"Invalid URL scheme '{parsed.scheme}'. Only HTTP/HTTPS allowed.")

        if self.enforce_https and parsed.scheme != "https":
            raise SSRFViolationException(f"Destination '{url}' rejected: HTTPS is enforced in production mode.")

        host = parsed.hostname
        if not host:
            raise SSRFViolationException(f"Invalid destination URL: missing hostname in '{url}'.")

        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        # 1. Direct IP check
        try:
            ipaddress.ip_address(host)
            self._validate_ip_address(host, host)
            return ResolvedDestination(
                original_url=url,
                scheme=parsed.scheme,
                hostname=host,
                port=port,
                resolved_ips=(host,),
                pinned_ip=host,
            )
        except ValueError:
            # Host is a DNS name
            pass

        # 2. DNS Whitelist check
        is_allowed_dns = any(host == s or host.endswith(s) for s in self.allowed_dns_suffixes)
        if not is_allowed_dns:
            raise SSRFViolationException(
                f"SSRF violation: Host '{host}' does not match allowed enterprise DNS suffixes ({self.allowed_dns_suffixes})."
            )

        # 3. DNS Resolution & Rebinding Check
        try:
            resolved_ips = self._resolve_host(host, port)
        except DNSResolutionError:
            if not allow_unresolved:
                raise
            return ResolvedDestination(original_url=url, scheme=parsed.scheme, hostname=host, port=port, resolved_ips=(), pinned_ip="")
        if not resolved_ips:
            raise SSRFViolationException(f"SSRF violation: Host '{host}' returned no valid IP addresses.")

        # Validate EVERY resolved IP address against blocked networks and allowed CIDRs
        for resolved_ip in resolved_ips:
            self._validate_ip_address(resolved_ip, host)

        # Pin to first valid resolved IP
        pinned = resolved_ips[0]
        return ResolvedDestination(
            original_url=url,
            scheme=parsed.scheme,
            hostname=host,
            port=port,
            resolved_ips=tuple(resolved_ips),
            pinned_ip=pinned,
        )

    def validate_destination_url(self, url: str) -> str:
        """
        Validates destination URL. Raises SSRFViolationException on dangerous targets.
        Preserves string return value for backward compatibility.
        """
        self.resolve_destination(url)
        return url
