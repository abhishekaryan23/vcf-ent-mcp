# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Enterprise VCF Transport Layer.
Provides base transport interfaces, resilient HTTP client, circuit breakers, and upstream authentication.
"""

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
    CircuitState,
    TransportCircuitBreaker,
)
from vcf_enterprise_mcp.adapter.transport.auth import (
    BaseUpstreamAuth,
    BasicAuth,
    BearerAuth,
    SessionTokenAuth,
    mTLSAuth,
)
from vcf_enterprise_mcp.adapter.transport.http import HTTPTransport

__all__ = [
    "BaseTransport",
    "TransportRequest",
    "TransportResponse",
    "TransportException",
    "UpstreamCommunicationException",
    "UpstreamConnectionException",
    "UpstreamTimeoutException",
    "UpstreamTLSException",
    "UpstreamAuthException",
    "UpstreamResourceNotFoundException",
    "UpstreamRateLimitException",
    "UpstreamServerException",
    "CircuitState",
    "TransportCircuitBreaker",
    "BaseUpstreamAuth",
    "BasicAuth",
    "BearerAuth",
    "SessionTokenAuth",
    "mTLSAuth",
    "HTTPTransport",
]
