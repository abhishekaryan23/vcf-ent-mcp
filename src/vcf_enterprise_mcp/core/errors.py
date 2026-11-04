# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Typed Exceptions for Enterprise VCF MCP Control Plane.
"""

from __future__ import annotations
from typing import Dict, Any, Optional


class VCFEnterpriseException(Exception):
    """Base exception for all enterprise control plane errors."""
    def __init__(self, message: str, error_code: int = -32603, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.details = details or {}

    def to_rpc_error(self) -> Dict[str, Any]:
        return {
            "code": self.error_code,
            "message": self.message,
            "data": self.details,
        }


class EnterpriseSecurityException(VCFEnterpriseException):
    """Base exception for all security, authentication, and authorization violations."""
    def __init__(self, message: str, error_code: int = -32001, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, error_code=error_code, details=details)


class AuthorizationDeniedException(VCFEnterpriseException):
    """Raised when an operation violates the enterprise policy intersection."""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, error_code=-32001, details=details)


class ApprovalRequiredException(VCFEnterpriseException):
    """Raised when a high-impact operation requires human approval."""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, error_code=-32002, details=details)


class VersionMismatchException(VCFEnterpriseException):
    """Raised when an API is called on an unsupported VCF version baseline."""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, error_code=-32003, details=details)


class WorkflowExecutionException(VCFEnterpriseException):
    """Raised when a step in a multi-step deterministic workflow fails."""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, error_code=-32004, details=details)


class SSRFViolationException(VCFEnterpriseException):
    """Raised when an unauthorized target IP or private metadata range is probed."""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, error_code=-32005, details=details)


class PlanStaleException(VCFEnterpriseException):
    """Raised when a dry-run execution plan is stale due to resource revision changes (TOCTOU)."""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, error_code=-32006, details=details)


class IdempotencyConflictException(VCFEnterpriseException):
    """Raised when an idempotency key is reused with different request arguments."""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, error_code=-32007, details=details)


class PostconditionFailedException(VCFEnterpriseException):
    """Raised when postcondition verification fails after mutation execution."""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, error_code=-32008, details=details)


class HeaderMismatchException(VCFEnterpriseException):
    """Raised when HTTP Mcp-* headers disagree with the JSON-RPC request body."""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, error_code=-32020, details=details)


class UnsupportedProtocolVersionException(HeaderMismatchException):
    def __init__(self, requested: str):
        super().__init__("Unsupported protocol version", {"supported": ["2026-07-28"], "requested": requested})
        self.error_code = -32022


class TaskNotFoundException(VCFEnterpriseException):
    """Raised when a task is not found or caller lacks ownership."""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, error_code=-32010, details=details)


class StaleFencingTokenException(VCFEnterpriseException):
    """Raised when a resource operation presents a superseded or expired fencing token."""
    def __init__(self, resource_id: str, current_token: int, presented_token: int, details: Optional[Dict[str, Any]] = None):
        d = details or {}
        d.update({"resource_id": resource_id, "current_fencing_token": current_token, "presented_token": presented_token})
        super().__init__(
            f"Fencing token rejection on '{resource_id}': presented token {presented_token} is stale (active is {current_token})",
            error_code=-32012,
            details=d,
        )


class ReconciliationRequiredException(VCFEnterpriseException):
    """Raised when the remote state of an executed operation is indeterminate and requires reconciliation."""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, error_code=-32013, details=details)


class ManualInterventionRequiredException(VCFEnterpriseException):
    """Raised when automated reconciliation cannot resolve divergence and requires human intervention."""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, error_code=-32014, details=details)


class ResourceLockException(VCFEnterpriseException):
    """Raised when a requested resource lease is held by another worker or process."""
    def __init__(self, resource_id: str, reason: str, details: Optional[Dict[str, Any]] = None):
        d = details or {}
        d.update({"resource_id": resource_id, "reason": reason, "http_status": 409})
        super().__init__(f"Conflict: Resource '{resource_id}' is locked: {reason}", error_code=-32015, details=d)


class ProviderUnavailableException(VCFEnterpriseException):
    """Raised when a downstream VCF provider circuit breaker is OPEN."""
    def __init__(self, provider: str, reason: str, details: Optional[Dict[str, Any]] = None):
        d = details or {}
        d.update({"provider": provider, "reason": reason, "http_status": 503})
        super().__init__(f"Provider '{provider}' unavailable: {reason}", error_code=-32016, details=d)


class RateLimitBudgetExceededException(VCFEnterpriseException):
    """Raised when an admission control concurrency or rate limit budget is exceeded."""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, error_code=-32017, details=details)


class ConfigurationException(VCFEnterpriseException):
    """Raised when server, IdP, or transport configuration is invalid or unsafe for production."""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, error_code=-32018, details=details)


class KnownIssueBlockedException(VCFEnterpriseException):
    """Raised when an operation is blocked by a confirmed vendor defect or known issue."""
    def __init__(self, issue_id: str, title: str, details: Optional[Dict[str, Any]] = None):
        d = details or {}
        d.update({"issue_id": issue_id, "title": title})
        super().__init__(
            f"Operation blocked by known vendor issue '{issue_id}': {title}",
            error_code=-32019,
            details=d,
        )


class InvalidArgumentException(VCFEnterpriseException):
    """Raised when request arguments fail strict schema validation, type checks, or range constraints."""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, error_code=-32602, details=details)


class ScopeViolationException(EnterpriseSecurityException):
    """Raised when an operation attempts to access resources outside allowed scopes or attempts scope forgery (Finding F02 / R02)."""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, error_code=-32001, details=details)


class AmbiguousResourceException(ScopeViolationException):
    """Raised when a resource ID matches in more than one vCenter and the caller did not say which one."""


class UnverifiedAPIContractException(VCFEnterpriseException):
    """Raised when a mutating operation targets an unverified vendor API contract in live mode (Finding F06 / R12)."""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, error_code=-32020, details=details)



