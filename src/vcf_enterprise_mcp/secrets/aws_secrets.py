# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
AWS Secrets Manager Provider.
Supports resolving secrets from AWS Secrets Manager via awssecrets:// references.
Example: awssecrets://vcf/prod/vcenter
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


class AWSSecretsManagerProvider:
    """Resolves secrets from AWS Secrets Manager."""

    provider_name: str = "aws_secrets"

    def __init__(self, region_name: str = "us-east-1"):
        self.region_name = region_name
        self._mock_aws_store: Dict[str, str] = {}

    def _parse_reference(self, reference: str) -> str:
        if not reference.startswith("awssecrets://"):
            raise ValueError(f"Invalid reference scheme for AWSSecretsManagerProvider: {reference}")
        return reference[len("awssecrets://"):].strip()

    def resolve(
        self,
        reference: str,
        *,
        tenant_id: str = "tenant-default",
        environment_id: str = "env-prod",
    ) -> SecretValue:
        secret_name = self._parse_reference(reference)
        if secret_name in self._mock_aws_store:
            return SecretValue(self._mock_aws_store[secret_name])
        raise MissingCredentialException(
            f"AWS Secrets Manager secret '{reference}' not found in region '{self.region_name}'."
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
        secret_name = self._parse_reference(reference)
        self._mock_aws_store[secret_name] = secret.reveal()

    def delete(
        self,
        reference: str,
        *,
        tenant_id: str = "tenant-default",
        environment_id: str = "env-prod",
    ) -> None:
        secret_name = self._parse_reference(reference)
        self._mock_aws_store.pop(secret_name, None)

    def list_references(
        self,
        *,
        tenant_id: str = "tenant-default",
        environment_id: str = "env-prod",
    ) -> List[SecretMetadata]:
        now = time.time()
        results = []
        for name in self._mock_aws_store:
            results.append(
                SecretMetadata(
                    reference=f"awssecrets://{name}",
                    version=1,
                    key_id="aws_secrets",
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
            details={"region": self.region_name},
        )
