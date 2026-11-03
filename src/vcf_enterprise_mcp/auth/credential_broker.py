# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Zero-Trust Credential Broker & Secret Redaction Engine.
Ensures that the LLM client never receives infrastructure credentials, tokens, or private keys.
"""

from __future__ import annotations
import re
from typing import Dict, Any, Optional, List
from vcf_enterprise_mcp.auth.identity import Principal
from vcf_enterprise_mcp.config.settings import UpstreamVCFConfig
from vcf_enterprise_mcp.auth.untrusted import sanitize_freeform_string
from vcf_enterprise_mcp.secrets.models import SecretValue, SecretMaterial
from vcf_enterprise_mcp.secrets.registry import SecretProviderRegistry, get_default_secret_registry


class CredentialBroker:
    """Brokers upstream VCF sessions using JIT delegated tokens without exposing them to the LLM."""

    # Sensitive key patterns that must never enter LLM context
    SENSITIVE_KEY_PATTERNS = [
        re.compile(r"password", re.IGNORECASE),
        re.compile(r"secret", re.IGNORECASE),
        re.compile(r"token", re.IGNORECASE),
        re.compile(r"key", re.IGNORECASE),
        re.compile(r"cookie", re.IGNORECASE),
        re.compile(r"authorization", re.IGNORECASE),
        re.compile(r"cert", re.IGNORECASE),
        re.compile(r"session", re.IGNORECASE),
        re.compile(r"kubeconfig", re.IGNORECASE),
    ]

    def __init__(
        self,
        config: Optional[UpstreamVCFConfig] = None,
        secret_registry: Optional[SecretProviderRegistry] = None,
    ):
        self.config = config or UpstreamVCFConfig()
        self.secret_registry = secret_registry or get_default_secret_registry()
        # Upstream sessions are created by adapter/transport/vcf_sessions.py (real per-component login);
        # the broker only resolves credentials and redacts secrets. It never invents tokens.

    def resolve_credential(
        self,
        reference: str,
        tenant_id: str = "tenant-default",
        environment_id: str = "env-prod",
    ) -> SecretValue:
        """Resolves a credential reference into an immutable SecretValue wrapper."""
        return self.secret_registry.resolve(
            reference,
            tenant_id=tenant_id,
            environment_id=environment_id,
        )

    def resolve_material(
        self,
        reference: str,
        tenant_id: str = "tenant-default",
        environment_id: str = "env-prod",
    ) -> SecretMaterial:
        """Resolves a credential reference into complete SecretMaterial (including optional username)."""
        return self.secret_registry.resolve_material(
            reference,
            tenant_id=tenant_id,
            environment_id=environment_id,
        )

    def redact_secrets_from_data(self, data: Any) -> Any:
        """
        Recursively inspects data structures and replaces sensitive values
        with '[REDACTED]' or vault references before sending output to the LLM.
        """
        if isinstance(data, dict):
            clean_dict = {}
            for k, v in data.items():
                if isinstance(v, (SecretValue, SecretMaterial)):
                    clean_dict[k] = "[REDACTED]"
                elif any(p.search(k) for p in self.SENSITIVE_KEY_PATTERNS):
                    if isinstance(v, str) and (v.startswith("http://") or v.startswith("https://")):
                        clean_dict[k] = v  # URLs are safe
                    else:
                        clean_dict[k] = f"vault://credentials/subsystem-{k.lower()}-ref"
                else:
                    clean_dict[k] = self.redact_secrets_from_data(v)
            return clean_dict

        if isinstance(data, list):
            return [self.redact_secrets_from_data(item) for item in data]

        if isinstance(data, tuple):
            return tuple(self.redact_secrets_from_data(item) for item in data)

        if isinstance(data, (SecretValue, SecretMaterial)):
            return "[REDACTED]"

        if isinstance(data, str):
            return sanitize_freeform_string(data)

        return data
