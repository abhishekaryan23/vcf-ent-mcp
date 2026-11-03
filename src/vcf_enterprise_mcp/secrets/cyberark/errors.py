# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Typed domain exceptions for CyberArk PAM Central Credential Provider (CCP) integration.
Maps CyberArk AIMWebService error codes (APPAP...) to explicit domain exceptions.
"""

from __future__ import annotations

from typing import Optional
from vcf_enterprise_mcp.secrets.base import SecretProviderException, MissingCredentialException


class CyberArkException(SecretProviderException):
    """Base exception for all CyberArk PAM integration errors."""
    def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        code: int = -32030,
    ):
        self.error_code = error_code
        prefix = f"[{error_code}] " if error_code else ""
        super().__init__(message=f"CyberArk PAM Error: {prefix}{message}", code=code)


class CyberArkConfigurationException(CyberArkException):
    """Raised when CyberArk configuration is missing or invalid."""
    def __init__(self, message: str):
        super().__init__(message=message, error_code="CONFIG_ERROR", code=-32031)


class CyberArkAuthenticationException(CyberArkException):
    """Raised when client authentication to CCP fails (AppID unauthorized, bad client cert, or IP not permitted)."""
    def __init__(self, message: str, error_code: Optional[str] = "APPAP133E"):
        super().__init__(message=message, error_code=error_code, code=-32032)


class CyberArkAccountNotFoundException(CyberArkException, MissingCredentialException):
    """Raised when requested privileged account or object does not exist in the specified Safe."""
    def __init__(self, message: str, error_code: Optional[str] = "APPAP004E"):
        CyberArkException.__init__(self, message=message, error_code=error_code, code=-32033)


class CyberArkSafeNotFoundException(CyberArkException):
    """Raised when the specified Safe does not exist or AppID lacks retrieve permissions on the Safe."""
    def __init__(self, message: str, error_code: Optional[str] = "APPAP272E"):
        super().__init__(message=message, error_code=error_code, code=-32034)


class CyberArkAccountLockedException(CyberArkException):
    """Raised when the privileged account is locked by CyberArk CPM or another administrative process."""
    def __init__(self, message: str, error_code: Optional[str] = "APPAP330E"):
        super().__init__(message=message, error_code=error_code, code=-32035)


class CyberArkRateLimitException(CyberArkException):
    """Raised when CCP or IIS throttles incoming requests."""
    def __init__(self, message: str, retry_after_seconds: float = 5.0):
        self.retry_after_seconds = retry_after_seconds
        super().__init__(message=message, error_code="RATE_LIMITED", code=-32036)


class CyberArkCommunicationException(CyberArkException):
    """Raised on connection timeout, TLS failure, or network disruption reaching CCP web service."""
    def __init__(self, message: str, original_cause: Optional[Exception] = None):
        self.original_cause = original_cause
        super().__init__(message=message, error_code="COMM_ERROR", code=-32037)
