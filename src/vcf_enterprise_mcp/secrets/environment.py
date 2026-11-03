# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Environment Variable Secret Provider.
Resolves credentials from local system environment variables using env:// references.
Suitable for local development, lab testing, Digital Twin, and PoC evaluations.
"""

from __future__ import annotations

import os
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


class EnvironmentSecretProvider:
    """
    Resolves secrets from process environment variables.
    Reference format: env://VARIABLE_NAME or env://VCF_MCP_VCENTER_PASSWORD
    """

    provider_name: str = "environment"

    def __init__(self, prefix: str = ""):
        self.prefix = prefix

    def _extract_var_name(self, reference: str) -> str:
        """Parses and validates environment variable reference."""
        if not reference.startswith("env://"):
            raise ValueError(f"Invalid reference scheme for EnvironmentSecretProvider: {reference}")
        var_name = reference[len("env://"):].strip()
        if not var_name:
            raise ValueError(f"Empty environment variable name in reference: {reference}")
        return var_name

    def resolve(
        self,
        reference: str,
        *,
        tenant_id: str = "tenant-default",
        environment_id: str = "env-prod",
    ) -> SecretValue:
        """
        Resolves secret from environment variable.
        Raises MissingCredentialException if the variable is unset or empty. Never falls back.
        """
        var_name = self._extract_var_name(reference)
        value = os.environ.get(var_name)
        if value is None or len(value) == 0:
            raise MissingCredentialException(
                f"Credential not configured: Environment variable '{var_name}' (referenced via '{reference}') is unset or empty."
            )
        return SecretValue(value)

    def store(
        self,
        reference: str,
        secret: SecretValue,
        *,
        tenant_id: str = "tenant-default",
        environment_id: str = "env-prod",
        description: Optional[str] = None,
    ) -> None:
        """Stores secret in process environment (primarily for test harness and local sessions)."""
        var_name = self._extract_var_name(reference)
        os.environ[var_name] = secret.reveal()

    def delete(
        self,
        reference: str,
        *,
        tenant_id: str = "tenant-default",
        environment_id: str = "env-prod",
    ) -> None:
        """Deletes variable from process environment."""
        var_name = self._extract_var_name(reference)
        os.environ.pop(var_name, None)

    def list_references(
        self,
        *,
        tenant_id: str = "tenant-default",
        environment_id: str = "env-prod",
    ) -> List[SecretMetadata]:
        """Lists metadata of configured environment variables matching VCF_ or custom prefixes."""
        now = time.time()
        results: List[SecretMetadata] = []
        for key in sorted(os.environ.keys()):
            if key.startswith("VCF_") and any(k in key for k in ("PASSWORD", "SECRET", "TOKEN", "KEY")):
                results.append(
                    SecretMetadata(
                        reference=f"env://{key}",
                        version=1,
                        key_id="environment",
                        created_at=now,
                        updated_at=now,
                        tenant_id=tenant_id,
                        environment_id=environment_id,
                        description=f"Process environment variable {key}",
                    )
                )
        return results

    def health_check(self) -> SecretProviderHealth:
        """Returns provider status."""
        return SecretProviderHealth(
            status="HEALTHY",
            provider_name=self.provider_name,
            details={"accessible_env_count": len(os.environ)},
        )
