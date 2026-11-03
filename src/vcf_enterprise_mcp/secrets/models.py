# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Data models and security contracts for Enterprise Secret Providers.
Enforces that secrets cannot be accidentally logged, serialized, or revealed.
"""

from __future__ import annotations

import hmac
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


class SecretValue:
    """
    Immutable wrapper for sensitive credentials.
    Prevents accidental leakage via __repr__, __str__, logging, audit, and exceptions.
    """

    sensitive: bool = True
    __slots__ = ("_value",)

    def __init__(self, value: str):
        if not isinstance(value, str):
            raise TypeError(f"SecretValue requires string value, got {type(value).__name__}")
        self._value: str = value

    def reveal_for_transport(self) -> str:
        """Explicit opt-in to reveal plaintext for transport-level authentication only."""
        return self._value

    def reveal(self) -> str:
        """Alias for reveal_for_transport for backward compatibility."""
        return self.reveal_for_transport()

    def __repr__(self) -> str:
        return "<SecretValue [REDACTED]>"

    def __str__(self) -> str:
        return "[REDACTED]"

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, SecretValue):
            return hmac.compare_digest(self._value, other._value)
        if isinstance(other, str):
            return hmac.compare_digest(self._value, other)
        return False

    def __bool__(self) -> bool:
        return bool(self._value)

    def __len__(self) -> int:
        return len(self._value)

    def __hash__(self) -> int:
        # Constant dummy hash to avoid leaking timing/structure in hash tables
        return hash("SecretValue[REDACTED]")


@dataclass
class SecretMaterial:
    """
    Encapsulates complete secret material (username, password, metadata) retrieved
    from enterprise providers like CyberArk PAM.
    """
    username: Optional[SecretValue] = None
    password: Optional[SecretValue] = None
    metadata: Optional["SecretMetadata"] = None

    def reveal_for_transport(self) -> str:
        """Reveals password (or username if password omitted) strictly for upstream transport."""
        if self.password is not None:
            return self.password.reveal_for_transport()
        if self.username is not None:
            return self.username.reveal_for_transport()
        return ""

    def reveal(self) -> str:
        return self.reveal_for_transport()

    def __repr__(self) -> str:
        return "<SecretMaterial [REDACTED]>"

    def __str__(self) -> str:
        return "[REDACTED]"

    def __eq__(self, other: Any) -> bool:
        if self.password is not None:
            return self.password == other
        return False

    def __bool__(self) -> bool:
        return bool(self.password or self.username)


@dataclass
class SecretReference:
    """Structured representation of a parsed credential reference URI."""
    uri: str
    scheme: str = ""
    safe_or_path: str = ""
    object_or_field: str = ""
    query_params: Dict[str, str] = field(default_factory=dict)
    tag: Optional[str] = None


@dataclass
class RequestContext:
    """Contextual metadata passed during credential resolution."""
    tenant_id: str = "tenant-default"
    environment_id: str = "env-prod"
    client_ip: Optional[str] = None
    trace_id: Optional[str] = None
    app_id: Optional[str] = None
    reason: Optional[str] = None


@dataclass
class SecretProviderHealth:
    """Health check outcome for a secret provider."""
    status: str = "HEALTHY"  # HEALTHY, DEGRADED, UNHEALTHY
    provider_name: str = "unknown"
    details: Dict[str, Any] = field(default_factory=dict)
    checked_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "provider_name": self.provider_name,
            "details": self.details,
            "checked_at": self.checked_at,
        }


@dataclass
class SecretMetadata:
    """Metadata describing a stored secret reference without revealing its value."""
    reference: str
    version: int = 1
    key_id: str = "default"
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    tenant_id: str = "tenant-default"
    environment_id: str = "env-prod"
    description: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "reference": self.reference,
            "version": self.version,
            "key_id": self.key_id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "tenant_id": self.tenant_id,
            "environment_id": self.environment_id,
            "description": self.description,
        }


@dataclass
class CredentialPolicy:
    """
    Enterprise policy governing allowed credential providers across environments.
    Strictly forbids insecure or unencrypted sources in production.
    """
    allow_environment_secrets: bool = False
    allow_local_encrypted: bool = True
    require_encrypted_storage: bool = True
    allow_enterprise_secret_manager: bool = True

    @classmethod
    def for_environment(cls, environment_name: str) -> "CredentialPolicy":
        """Factory creating calibrated credential policy per deployment tier."""
        env = (environment_name or "").lower().strip()
        if env in ("development", "dev", "unit_test"):
            return cls(
                allow_environment_secrets=True,
                allow_local_encrypted=True,
                require_encrypted_storage=False,
                allow_enterprise_secret_manager=True,
            )
        elif env in ("lab", "sandbox", "poc", "eval"):
            return cls(
                allow_environment_secrets=True,
                allow_local_encrypted=True,
                require_encrypted_storage=True,
                allow_enterprise_secret_manager=True,
            )
        elif env in ("pilot", "staging"):
            return cls(
                allow_environment_secrets=False,
                allow_local_encrypted=True,
                require_encrypted_storage=True,
                allow_enterprise_secret_manager=True,
            )
        else:  # production
            return cls(
                allow_environment_secrets=False,
                allow_local_encrypted=True,
                require_encrypted_storage=True,
                allow_enterprise_secret_manager=True,
            )

    def validate_reference_allowed(self, environment_name: str, reference: str) -> None:
        """
        Validates whether a credential reference URI scheme is permitted under this policy.
        Raises CredentialPolicyViolationException if disallowed.
        """
        from vcf_enterprise_mcp.secrets.base import CredentialPolicyViolationException

        ref_lower = (reference or "").lower()

        if ref_lower.startswith("env://"):
            if not self.allow_environment_secrets:
                raise CredentialPolicyViolationException(
                    f"Policy violation: Environment variable credentials ('{reference}') are strictly forbidden in '{environment_name}' environment."
                )

        if ref_lower.startswith("local://"):
            if not self.allow_local_encrypted:
                raise CredentialPolicyViolationException(
                    f"Policy violation: Local encrypted credentials ('{reference}') are not allowed in '{environment_name}' environment."
                )

        if any(ref_lower.startswith(p) for p in ("vault://", "azurekv://", "awssecrets://", "cyberark://", "conjur://")):
            if not self.allow_enterprise_secret_manager:
                raise CredentialPolicyViolationException(
                    f"Policy violation: External secret manager reference ('{reference}') is not enabled in '{environment_name}' environment."
                )
