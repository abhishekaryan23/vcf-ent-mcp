# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Base abstractions and protocol definitions for Secret Providers.
All secret providers must implement this contract.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Protocol, Union, runtime_checkable
from vcf_enterprise_mcp.core.errors import EnterpriseSecurityException
from vcf_enterprise_mcp.secrets.models import (
    SecretValue,
    SecretMaterial,
    SecretReference,
    RequestContext,
    SecretProviderHealth,
    SecretMetadata,
)


class SecretProviderException(EnterpriseSecurityException):
    """Base exception for all secret provider errors."""
    def __init__(self, message: str, code: int = -32025):
        super().__init__(message=message, error_code=code)


class MissingCredentialException(SecretProviderException):
    """Raised when a requested credential reference cannot be found."""
    def __init__(self, message: str, code: int = -32026, **kwargs: Any):
        super().__init__(message=message, code=code)


class CredentialPolicyViolationException(SecretProviderException):
    """Raised when credential resolution violates enterprise security policy."""
    def __init__(self, message: str, code: int = -32027, **kwargs: Any):
        super().__init__(message=message, code=code)


class CredentialDecryptionException(SecretProviderException):
    """Raised when encrypted credential cannot be decrypted or authentication tag fails."""
    def __init__(self, message: str, code: int = -32028, **kwargs: Any):
        super().__init__(message=message, code=code)


@runtime_checkable
class SecretProvider(Protocol):
    """
    Protocol contract for enterprise secret providers.
    Provides resolution, storage, deletion, metadata listing, and health checks.
    """

    provider_name: str

    def resolve(
        self,
        reference: Union[str, SecretReference],
        *,
        tenant_id: str = "tenant-default",
        environment_id: str = "env-prod",
        request_context: Optional[RequestContext] = None,
    ) -> Union[SecretValue, SecretMaterial]:
        """Resolves a standardized secret reference into an immutable SecretValue or SecretMaterial wrapper."""
        ...

    def resolve_material(
        self,
        reference: Union[str, SecretReference],
        *,
        tenant_id: str = "tenant-default",
        environment_id: str = "env-prod",
        request_context: Optional[RequestContext] = None,
    ) -> SecretMaterial:
        """Resolves a standardized secret reference into complete SecretMaterial (including optional username)."""
        ...

    def store(
        self,
        reference: str,
        secret: SecretValue,
        *,
        tenant_id: str = "tenant-default",
        environment_id: str = "env-prod",
        description: Optional[str] = None,
    ) -> None:
        """Stores a credential under the specified reference."""
        ...

    def delete(
        self,
        reference: str,
        *,
        tenant_id: str = "tenant-default",
        environment_id: str = "env-prod",
    ) -> None:
        """Deletes a credential by reference."""
        ...

    def list_references(
        self,
        *,
        tenant_id: str = "tenant-default",
        environment_id: str = "env-prod",
    ) -> List[SecretMetadata]:
        """Lists metadata of available credential references without revealing plain secret values."""
        ...

    def health_check(self) -> SecretProviderHealth:
        """Performs liveness and connectivity verification for the secret backend."""
        ...
