# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
CyberArk Central Credential Provider (CCP) Secret Provider implementation.
Provides runtime resolution of VCF infrastructure credentials from CyberArk PAM
via standardized 'cyberark://' reference URIs.
"""

from __future__ import annotations

import urllib.parse
from typing import Any, Dict, List, Optional, Tuple, Union

from vcf_enterprise_mcp.secrets.base import (
    SecretProvider,
    SecretProviderException,
    MissingCredentialException,
)
from vcf_enterprise_mcp.secrets.models import (
    SecretValue,
    SecretMaterial,
    SecretMetadata,
    SecretProviderHealth,
    SecretReference,
    RequestContext,
)
from vcf_enterprise_mcp.secrets.cyberark.config import CyberArkConfig
from vcf_enterprise_mcp.secrets.cyberark.client import CyberArkCCPClient
from vcf_enterprise_mcp.secrets.cyberark.models import CyberArkQueryParams
from vcf_enterprise_mcp.secrets.cyberark.health import CyberArkHealthChecker


class CyberArkCCPSecretProvider(SecretProvider):
    """
    Enterprise Secret Provider resolving privileged credentials from CyberArk PAM
    via Central Credential Provider (CCP) AIMWebService REST API.
    """

    provider_name: str = "cyberark"

    def __init__(
        self,
        config: Optional[CyberArkConfig] = None,
        client: Optional[CyberArkCCPClient] = None,
    ):
        self.config = config or CyberArkConfig.from_env()
        self.client = client or CyberArkCCPClient(self.config)
        self.health_checker = CyberArkHealthChecker(self.config, self.client.authenticator)
        self._tracked_references: Dict[str, SecretMetadata] = {}

    def parse_reference(self, reference_str: str) -> Tuple[str, str, Dict[str, str], Optional[str]]:
        """
        Parses cyberark:// reference URI into (safe, object_name, query_params, field).
        
        Supported syntaxes:
          - cyberark://Enterprise-PAM/vcenter-prod
          - cyberark://Enterprise-PAM/vcenter-prod#password
          - cyberark://Enterprise-PAM/vcenter-prod?appid=VCF-MCP&username=administrator@vsphere.local
        """
        if not reference_str.startswith("cyberark://"):
            raise ValueError(f"Invalid reference URI for CyberArk provider: {reference_str}")

        parsed = urllib.parse.urlparse(reference_str)
        safe = parsed.netloc
        path = parsed.path.lstrip("/")

        # If netloc is empty, first path segment is safe
        if not safe and path:
            parts = path.split("/", 1)
            safe = parts[0]
            object_name = parts[1] if len(parts) > 1 else ""
        else:
            object_name = path

        if not safe:
            safe = self.config.default_safe or ""

        query_dict = dict(urllib.parse.parse_qsl(parsed.query))
        fragment = parsed.fragment or None

        return safe, object_name, query_dict, fragment

    def resolve(
        self,
        reference: Union[str, SecretReference],
        *,
        tenant_id: str = "tenant-default",
        environment_id: str = "env-prod",
        request_context: Optional[RequestContext] = None,
    ) -> SecretMaterial:
        """Resolves cyberark:// reference into SecretMaterial (which duck-types as SecretValue)."""
        return self.resolve_material(
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
        Retrieves credential from CyberArk CCP and packages it into SecretMaterial.
        Ensures retrieved secrets are never persisted or exposed.
        """
        ref_str = reference.uri if isinstance(reference, SecretReference) else reference
        if not ref_str:
            raise MissingCredentialException("Empty CyberArk credential reference provided.")

        safe, object_name, query_dict, fragment = self.parse_reference(ref_str)

        if not safe:
            raise SecretProviderException(
                f"CyberArk Safe must be specified in reference URI or default_safe config: '{ref_str}'"
            )
        if not object_name and not query_dict.get("username"):
            raise SecretProviderException(
                f"CyberArk account Object name or username query must be specified: '{ref_str}'"
            )

        app_id = query_dict.get("appid") or (request_context.app_id if request_context else None) or self.config.app_id
        user_name = query_dict.get("username")
        address = query_dict.get("address")
        folder = query_dict.get("folder", "root")
        reason = (
            query_dict.get("reason")
            or (request_context.reason if request_context else None)
            or self.config.default_reason
        )

        query_params = CyberArkQueryParams(
            app_id=app_id,
            safe=safe,
            folder=folder,
            object_name=object_name if object_name else None,
            user_name=user_name,
            address=address,
            reason=reason,
        )

        account = self.client.get_account(query_params)
        material = account.to_secret_material(
            reference_uri=ref_str,
            tenant_id=tenant_id,
            environment_id=environment_id,
        )

        # Track metadata reference (without password)
        if material.metadata:
            self._tracked_references[ref_str] = material.metadata

        return material

    def store(
        self,
        reference: str,
        secret: SecretValue,
        *,
        tenant_id: str = "tenant-default",
        environment_id: str = "env-prod",
        description: Optional[str] = None,
    ) -> None:
        """CyberArk CCP is a read-only retrieval interface."""
        raise SecretProviderException(
            "CyberArk Central Credential Provider (CCP) is a read-only credential retrieval service. "
            "Accounts must be created or updated directly within CyberArk Enterprise Password Vault (EPV)."
        )

    def delete(
        self,
        reference: str,
        *,
        tenant_id: str = "tenant-default",
        environment_id: str = "env-prod",
    ) -> None:
        """CyberArk CCP is a read-only retrieval interface."""
        raise SecretProviderException(
            "CyberArk Central Credential Provider (CCP) is a read-only credential retrieval service."
        )

    def list_references(
        self,
        *,
        tenant_id: str = "tenant-default",
        environment_id: str = "env-prod",
    ) -> List[SecretMetadata]:
        """Returns metadata of references resolved during runtime session."""
        return [
            m for m in self._tracked_references.values()
            if m.tenant_id == tenant_id and m.environment_id == environment_id
        ]

    def health_check(self) -> SecretProviderHealth:
        """Executes connectivity check against CyberArk CCP."""
        return self.health_checker.check_health()
