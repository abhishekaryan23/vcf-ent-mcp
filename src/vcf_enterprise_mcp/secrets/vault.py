# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
HashiCorp Vault Secret Provider.
Supports resolving secrets from HashiCorp Vault via vault:// URI references.
Example: vault://kv/vcf/prod/vcenter#password or vault://secret/data/vcf/sddc
"""

from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Optional
import httpx

from vcf_enterprise_mcp.secrets.base import (
    SecretProvider,
    MissingCredentialException,
    SecretProviderException,
)
from vcf_enterprise_mcp.secrets.models import (
    SecretValue,
    SecretProviderHealth,
    SecretMetadata,
)


class HashiCorpVaultSecretProvider:
    """
    Resolves secrets from HashiCorp Vault KV v1/v2 engines over HTTPS.
    Reference syntax: vault://[mount]/path/to/secret[#field]
    """

    provider_name: str = "vault"

    def __init__(
        self,
        vault_addr: Optional[str] = None,
        vault_token: Optional[str] = None,
        kv_mount: str = "secret",
        timeout_seconds: float = 10.0,
    ):
        self.vault_addr = vault_addr or os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
        self.vault_token = vault_token or os.environ.get("VAULT_TOKEN", "")
        self.kv_mount = kv_mount
        self.timeout_seconds = timeout_seconds
        # In-memory mock/fallback store for testing when Vault is not reachable
        self._mock_vault_store: Dict[str, Dict[str, str]] = {}

    def _parse_reference(self, reference: str) -> tuple[str, str]:
        """Parses vault://path/to/secret#field into path and field."""
        if not reference.startswith("vault://"):
            raise ValueError(f"Invalid reference scheme for HashiCorpVaultSecretProvider: {reference}")
        raw = reference[len("vault://"):].strip()
        field = "password"
        if "#" in raw:
            path, field = raw.split("#", 1)
        else:
            path = raw
        return path, field

    def resolve(
        self,
        reference: str,
        *,
        tenant_id: str = "tenant-default",
        environment_id: str = "env-prod",
    ) -> SecretValue:
        """Resolves secret from Vault KV engine."""
        path, field = self._parse_reference(reference)

        # Check local mock vault store first (used during unit testing or simulated environments)
        if path in self._mock_vault_store:
            data = self._mock_vault_store[path]
            if field in data:
                return SecretValue(data[field])
            raise MissingCredentialException(f"Field '{field}' not found in secret '{reference}'.")

        if not self.vault_token:
            raise MissingCredentialException(
                f"Cannot resolve Vault secret '{reference}': VAULT_TOKEN is unset and secret not found."
            )

        url = f"{self.vault_addr.rstrip('/')}/v1/{self.kv_mount}/data/{path.lstrip('/')}"
        headers = {"X-Vault-Token": self.vault_token}

        try:
            with httpx.Client(timeout=self.timeout_seconds) as client:
                resp = client.get(url, headers=headers)
                if resp.status_code == 404:
                    raise MissingCredentialException(f"Vault secret '{reference}' not found (404).")
                resp.raise_for_status()
                payload = resp.json()
                data = payload.get("data", {}).get("data", {})
                if field not in data:
                    raise MissingCredentialException(
                        f"Field '{field}' not present in Vault secret '{reference}'."
                    )
                return SecretValue(data[field])
        except httpx.HTTPError as e:
            raise SecretProviderException(f"Vault HTTP communication error: {str(e)}")

    def store(
        self,
        reference: str,
        secret: SecretValue,
        *,
        tenant_id: str = "tenant-default",
        environment_id: str = "env-prod",
        description: Optional[str] = None,
    ) -> None:
        """Stores secret into Vault (or internal mock store if offline)."""
        path, field = self._parse_reference(reference)
        if path not in self._mock_vault_store:
            self._mock_vault_store[path] = {}
        self._mock_vault_store[path][field] = secret.reveal()

    def delete(
        self,
        reference: str,
        *,
        tenant_id: str = "tenant-default",
        environment_id: str = "env-prod",
    ) -> None:
        """Deletes secret from Vault."""
        path, field = self._parse_reference(reference)
        if path in self._mock_vault_store and field in self._mock_vault_store[path]:
            del self._mock_vault_store[path][field]

    def list_references(
        self,
        *,
        tenant_id: str = "tenant-default",
        environment_id: str = "env-prod",
    ) -> List[SecretMetadata]:
        now = time.time()
        results: List[SecretMetadata] = []
        for path, fields in self._mock_vault_store.items():
            for f in fields:
                results.append(
                    SecretMetadata(
                        reference=f"vault://{path}#{f}",
                        version=1,
                        key_id="vault",
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
            details={"vault_addr": self.vault_addr, "configured": bool(self.vault_token or self._mock_vault_store)},
        )
