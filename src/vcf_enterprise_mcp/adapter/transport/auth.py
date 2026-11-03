# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Upstream VCF Authentication Providers.
Supports Basic Auth, Bearer Token, Session ID (vmware-api-session-id), and mTLS.
"""

from __future__ import annotations
import base64
from abc import ABC, abstractmethod
from typing import Optional
from vcf_enterprise_mcp.adapter.transport.base import TransportRequest


class BaseUpstreamAuth(ABC):
    """Abstract base class for upstream authentication strategies."""

    @abstractmethod
    def apply(self, request: TransportRequest) -> TransportRequest:
        """Injects authentication headers or credentials into the transport request."""
        raise NotImplementedError

    def invalidate(self) -> None:
        """Drops any cached upstream session so the next apply() logs in again."""
        return None


class BasicAuth(BaseUpstreamAuth):
    """HTTP Basic Authentication for initial session establishment on vCenter / SDDC Manager."""

    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password

    def apply(self, request: TransportRequest) -> TransportRequest:
        raw_cred = f"{self.username}:{self.password}".encode("utf-8")
        b64_cred = base64.b64encode(raw_cred).decode("ascii")
        request.headers["Authorization"] = f"Basic {b64_cred}"
        return request


class BearerAuth(BaseUpstreamAuth):
    """Bearer Token Authentication for OAuth2 / OIDC upstream endpoints."""

    def __init__(self, token: str):
        self.token = token

    def apply(self, request: TransportRequest) -> TransportRequest:
        request.headers["Authorization"] = f"Bearer {self.token}"
        return request


class SessionTokenAuth(BaseUpstreamAuth):
    """Header-based session token authentication (e.g. vmware-api-session-id)."""

    def __init__(self, session_token: str, header_name: str = "vmware-api-session-id"):
        self.session_token = session_token
        self.header_name = header_name

    def apply(self, request: TransportRequest) -> TransportRequest:
        request.headers[self.header_name] = self.session_token
        return request


class mTLSAuth(BaseUpstreamAuth):
    """Mutual TLS (mTLS) Authentication using client certificates and private keys."""

    def __init__(
        self,
        cert_file: str,
        key_file: str,
        ca_cert_file: Optional[str] = None,
        key_password: Optional[str] = None,
    ):
        self.cert_file = cert_file
        self.key_file = key_file
        self.ca_cert_file = ca_cert_file
        self.key_password = key_password

    def apply(self, request: TransportRequest) -> TransportRequest:
        # mTLS credentials are applied at TLS socket context during transport execution
        return request
