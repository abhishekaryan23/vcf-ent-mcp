# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Central Secret Provider Registry.
Coordinates credential resolution across local encrypted stores, environment variables,
and enterprise key management systems under strict policy enforcement.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from vcf_enterprise_mcp.secrets.base import (
    SecretProvider,
    SecretProviderException,
    MissingCredentialException,
    CredentialPolicyViolationException,
)
from vcf_enterprise_mcp.secrets.models import (
    SecretValue,
    SecretMaterial,
    SecretReference,
    RequestContext,
    SecretProviderHealth,
    SecretMetadata,
    CredentialPolicy,
)
from vcf_enterprise_mcp.secrets.environment import EnvironmentSecretProvider
from vcf_enterprise_mcp.secrets.local_encrypted import LocalEncryptedSecretProvider
from vcf_enterprise_mcp.secrets.vault import HashiCorpVaultSecretProvider
from vcf_enterprise_mcp.secrets.azure_keyvault import AzureKeyVaultSecretProvider
from vcf_enterprise_mcp.secrets.aws_secrets import AWSSecretsManagerProvider
from vcf_enterprise_mcp.secrets.cyberark import CyberArkCCPSecretProvider


class SecretProviderRegistry:
    """
    Central dispatcher and policy enforcement point for credential references.
    Maps URI schemes (env://, local://, vault://, azurekv://, awssecrets://, cyberark://) to providers.
    """

    def __init__(self, policy: Optional[CredentialPolicy] = None):
        self.policy = policy or CredentialPolicy()
        self._providers: Dict[str, SecretProvider] = {}
        self._init_default_providers()

    def _init_default_providers(self) -> None:
        """Initializes default built-in providers."""
        self.register_provider("env", EnvironmentSecretProvider())
        self.register_provider("local", LocalEncryptedSecretProvider())
        self.register_provider("vault", HashiCorpVaultSecretProvider())
        self.register_provider("azurekv", AzureKeyVaultSecretProvider())
        self.register_provider("awssecrets", AWSSecretsManagerProvider())
        self.register_provider("cyberark", CyberArkCCPSecretProvider())

    def register_provider(self, scheme: str, provider: SecretProvider) -> None:
        """Registers a provider for a specific URI scheme."""
        clean_scheme = scheme.lower().rstrip(":/")
        self._providers[clean_scheme] = provider

    def get_provider(self, scheme: str) -> SecretProvider:
        """Retrieves provider registered for the given scheme."""
        clean_scheme = scheme.lower().rstrip(":/")
        if clean_scheme not in self._providers:
            raise SecretProviderException(
                f"No secret provider registered for credential scheme '{clean_scheme}://'."
            )
        return self._providers[clean_scheme]

    def _extract_scheme(self, reference: str) -> str:
        if "://" not in reference:
            raise ValueError(f"Invalid reference URI format (missing '://'): {reference}")
        scheme = reference.split("://", 1)[0].lower().strip()
        return scheme

    def resolve(
        self,
        reference: Union[str, SecretReference],
        *,
        tenant_id: str = "tenant-default",
        environment_id: str = "env-prod",
        request_context: Optional[RequestContext] = None,
    ) -> Union[SecretValue, SecretMaterial]:
        """
        Resolves a credential reference into an immutable SecretValue or SecretMaterial wrapper.
        Enforces CredentialPolicy before delegating to the backend provider.
        """
        ref_str = reference.uri if isinstance(reference, SecretReference) else reference
        if not ref_str:
            raise MissingCredentialException("Empty or null credential reference provided.")

        scheme = self._extract_scheme(ref_str)

        # 1. Enforce Credential Policy
        self.policy.validate_reference_allowed(environment_id, ref_str)

        # 2. Delegate to appropriate provider
        provider = self.get_provider(scheme)
        return provider.resolve(
            reference,
            tenant_id=tenant_id,
            environment_id=environment_id,
            request_context=request_context,
        )

    def resolve_material(
        self,
        reference: Union[str, SecretReference],
        *,
        tenant_id: str = "tenant-default",
        environment_id: str = "env-prod",
        request_context: Optional[RequestContext] = None,
    ) -> SecretMaterial:
        """
        Resolves a credential reference into complete SecretMaterial (including optional username).
        """
        ref_str = reference.uri if isinstance(reference, SecretReference) else reference
        if not ref_str:
            raise MissingCredentialException("Empty or null credential reference provided.")

        scheme = self._extract_scheme(ref_str)
        self.policy.validate_reference_allowed(environment_id, ref_str)
        provider = self.get_provider(scheme)

        if hasattr(provider, "resolve_material"):
            return provider.resolve_material(
                reference,
                tenant_id=tenant_id,
                environment_id=environment_id,
                request_context=request_context,
            )

        # Fallback: resolve SecretValue and wrap in SecretMaterial
        secret_val = provider.resolve(
            ref_str,
            tenant_id=tenant_id,
            environment_id=environment_id,
        )
        metadata = SecretMetadata(
            reference=ref_str,
            tenant_id=tenant_id,
            environment_id=environment_id,
        )
        return SecretMaterial(password=secret_val, metadata=metadata)

    def store(
        self,
        reference: str,
        secret: SecretValue,
        *,
        tenant_id: str = "tenant-default",
        environment_id: str = "env-prod",
        description: Optional[str] = None,
    ) -> None:
        """Stores a secret via the matching provider."""
        scheme = self._extract_scheme(reference)
        provider = self.get_provider(scheme)
        provider.store(
            reference,
            secret,
            tenant_id=tenant_id,
            environment_id=environment_id,
            description=description,
        )

    def delete(
        self,
        reference: str,
        *,
        tenant_id: str = "tenant-default",
        environment_id: str = "env-prod",
    ) -> None:
        """Deletes a secret via the matching provider."""
        scheme = self._extract_scheme(reference)
        provider = self.get_provider(scheme)
        provider.delete(
            reference,
            tenant_id=tenant_id,
            environment_id=environment_id,
        )

    def list_references(
        self,
        *,
        tenant_id: str = "tenant-default",
        environment_id: str = "env-prod",
    ) -> List[SecretMetadata]:
        """Lists metadata of all secrets across all configured providers."""
        results: List[SecretMetadata] = []
        for provider in self._providers.values():
            try:
                results.extend(provider.list_references(tenant_id=tenant_id, environment_id=environment_id))
            except Exception:
                pass
        return results

    def health_check_all(self) -> Dict[str, SecretProviderHealth]:
        """Performs health check on all registered providers."""
        healths: Dict[str, SecretProviderHealth] = {}
        for scheme, provider in self._providers.items():
            try:
                healths[scheme] = provider.health_check()
            except Exception as e:
                healths[scheme] = SecretProviderHealth(
                    status="UNHEALTHY",
                    provider_name=provider.provider_name,
                    details={"error": str(e)},
                )
        return healths


_DEFAULT_REGISTRY: Optional[SecretProviderRegistry] = None


def get_default_secret_registry() -> SecretProviderRegistry:
    """Returns the singleton process-wide SecretProviderRegistry."""
    global _DEFAULT_REGISTRY
    if _DEFAULT_REGISTRY is None:
        _DEFAULT_REGISTRY = SecretProviderRegistry()
    return _DEFAULT_REGISTRY


def set_default_secret_registry(registry: SecretProviderRegistry) -> None:
    """Overrides the global SecretProviderRegistry."""
    global _DEFAULT_REGISTRY
    _DEFAULT_REGISTRY = registry
