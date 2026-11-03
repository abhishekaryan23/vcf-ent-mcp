# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Transport and Upstream Communication Exceptions for Enterprise VCF MCP Control Plane.
Explicitly maps socket, TLS, HTTP, and upstream appliance errors to domain exceptions.
"""

from __future__ import annotations
from typing import Dict, Any, Optional
from vcf_enterprise_mcp.core.errors import VCFEnterpriseException


class TransportException(VCFEnterpriseException):
    """Base exception for all upstream VCF transport and network failures."""
    def __init__(self, message: str, error_code: int = -32020, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, error_code=error_code, details=details)


class UpstreamCommunicationException(TransportException):
    """Raised when communication with an upstream VCF appliance fails unexpectedly."""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, error_code=-32021, details=details)


class UpstreamConnectionException(TransportException):
    """Raised when unable to establish a TCP socket connection to upstream endpoint."""
    def __init__(self, endpoint: str, reason: str, details: Optional[Dict[str, Any]] = None):
        d = details or {}
        d.update({"endpoint": endpoint, "reason": reason})
        hint = ""
        if "refused" in reason.lower():
            hint = (" Nothing is accepting connections at that address: check that the appliance (or the Digital Twin) "
                    "is running and that the address and port are right.")
        super().__init__(f"Failed to connect to upstream VCF endpoint '{endpoint}': {reason}.{hint}", error_code=-32022, details=d)


class UpstreamTimeoutException(TransportException):
    """Raised when an upstream request times out."""
    def __init__(self, endpoint: str, timeout_seconds: float, details: Optional[Dict[str, Any]] = None):
        d = details or {}
        d.update({"endpoint": endpoint, "timeout_seconds": timeout_seconds})
        super().__init__(
            f"Upstream request to '{endpoint}' timed out after {timeout_seconds:.1f}s",
            error_code=-32023,
            details=d,
        )


class UpstreamTLSException(TransportException):
    """Raised when TLS handshake or certificate verification fails."""
    def __init__(self, endpoint: str, reason: str, details: Optional[Dict[str, Any]] = None):
        d = details or {}
        d.update({"endpoint": endpoint, "reason": reason})
        super().__init__(f"TLS certificate verification failed for '{endpoint}': {reason}", error_code=-32024, details=d)


class UpstreamAuthException(TransportException):
    """Raised when upstream returns HTTP 401 or 403 due to invalid appliance credentials."""
    def __init__(self, endpoint: str, status_code: int, message: str = "", details: Optional[Dict[str, Any]] = None):
        d = details or {}
        d.update({"endpoint": endpoint, "status_code": status_code, "upstream_message": message})
        super().__init__(
            f"Upstream authentication failed on '{endpoint}' (HTTP {status_code}): {message or 'Access Denied'}",
            error_code=-32025,
            details=d,
        )


class UpstreamResourceNotFoundException(TransportException):
    """Raised when an upstream VCF resource does not exist (HTTP 404)."""
    def __init__(self, resource_type: str, resource_id: str, endpoint: str = "", details: Optional[Dict[str, Any]] = None):
        d = details or {}
        d.update({"resource_type": resource_type, "resource_id": resource_id, "endpoint": endpoint})
        super().__init__(
            f"Upstream resource '{resource_type}' with ID '{resource_id}' not found on '{endpoint}'.",
            error_code=-32026,
            details=d,
        )


class UpstreamRateLimitException(TransportException):
    """Raised when upstream rate limits or throttles requests (HTTP 429)."""
    def __init__(self, endpoint: str, retry_after: Optional[float] = None, details: Optional[Dict[str, Any]] = None):
        d = details or {}
        d.update({"endpoint": endpoint, "retry_after": retry_after})
        super().__init__(
            f"Upstream endpoint '{endpoint}' rate limit exceeded. Retry after {retry_after or 'N/A'}s.",
            error_code=-32027,
            details=d,
        )


class UpstreamServerException(TransportException):
    """Raised when upstream appliance returns an internal server error (HTTP 5xx)."""
    def __init__(self, endpoint: str, status_code: int, message: str = "", details: Optional[Dict[str, Any]] = None):
        d = details or {}
        d.update({"endpoint": endpoint, "status_code": status_code, "upstream_message": message})
        super().__init__(
            f"Upstream VCF server error on '{endpoint}' (HTTP {status_code}): {message or 'Internal Server Error'}",
            error_code=-32028,
            details=d,
        )


class UpstreamPreconditionException(TransportException):
    """Raised before dispatch when observed upstream state makes a mutation unsafe or unsupported."""
    def __init__(self, operation: str, reason: str, details: Optional[Dict[str, Any]] = None):
        d = details or {}
        d.update({"operation": operation, "reason": reason})
        super().__init__(
            f"Precondition failed for '{operation}': {reason}",
            error_code=-32029,
            details=d,
        )
