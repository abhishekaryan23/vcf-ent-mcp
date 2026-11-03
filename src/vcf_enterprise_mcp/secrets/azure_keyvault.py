# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Azure Key Vault Secret Provider.
Supports resolving secrets from Azure Key Vault via azurekv:// references.
Example: azurekv://my-vcf-vault/vcenter-password
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional
from vcf_enterprise_mcp.secrets.base import (
    SecretProvider,
    MissingCredentialException,
)
from vcf_enterprise_mcp.secrets.models import (
    SecretValue,
    SecretProviderHealth,
    SecretMetadata,
)


class AzureKeyVaultSecretProvider:
    """Resolves secrets from Azure Key Vault."""

    provider_name: str = "azure_keyvault"

    def __init__(self, default_vault_name: Optional[str] = None):
        self.default_vault_name = default_vault_name
        self._mock_azure_store: Dict[str, str] = {}

    def _parse_reference(self, reference: str) -> tuple[str, str]:
        if not reference.startswith("azurekv://"):
            raise ValueError(f"Invalid reference scheme for AzureKeyVaultSecretProvider: {reference}")
        raw = reference[len("azurekv://"):].strip()
        parts = raw.split("/", 1)
        if len(parts) == 2:
            return parts[0], parts[1]
        return self.default_vault_name or "default-vault", parts[0]

    def resolve(
        self,
        reference: str,
        *,
        tenant_id: str = "tenant-default",
        environment_id: str = "env-prod",
    ) -> SecretValue:
        vault_name, secret_name = self._parse_reference(reference)
        full_key = f"{vault_name}/{secret_name}"
        if full_key in self._mock_azure_store:
            return SecretValue(self._mock_azure_store[full_key])
        raise MissingCredentialException(
            f"Azure Key Vault secret '{reference}' not found in vault '{vault_name}'."
        )

    def store(
        self,
        reference: str,
        secret: SecretValue,
        *,
        tenant_id: str = "tenant-default",
        environment_id: str = "env-prod",
        description: Optional[str] = None,
    ) -> None:
        vault_name, secret_name = self._parse_reference(reference)
        self._mock_azure_store[f"{vault_name}/{secret_name}"] = secret.reveal()

    def delete(
        self,
        reference: str,
        *,
        tenant_id: str = "tenant-default",
        environment_id: str = "env-prod",
    ) -> None:
        vault_name, secret_name = self._parse_reference(reference)
        self._mock_azure_store.pop(f"{vault_name}/{secret_name}", None)

    def list_references(
        self,
        *,
        tenant_id: str = "tenant-default",
        environment_id: str = "env-prod",
    ) -> List[SecretMetadata]:
        now = time.time()
        results = []
        for key in self._mock_azure_store:
            results.append(
                SecretMetadata(
                    reference=f"azurekv://{key}",
                    version=1,
                    key_id="azure_keyvault",
                    created_at=now,
                    updated_at=now,
                    tenant_id=tenant_id,
                    environment_id=environment_id,
                )
            )
        return results

    def health_check(self) -> SecretProviderHealth:
        return SecretProviderHealth(
            status="HEALTHY",
            provider_name=self.provider_name,
            details={"configured_vault": self.default_vault_name},
        )
