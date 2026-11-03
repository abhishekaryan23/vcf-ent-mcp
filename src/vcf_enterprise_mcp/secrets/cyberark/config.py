# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Configuration loader and settings validation for CyberArk PAM integration.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from vcf_enterprise_mcp.secrets.models import SecretValue
from vcf_enterprise_mcp.secrets.cyberark.models import CyberArkOperatingMode
from vcf_enterprise_mcp.secrets.cyberark.errors import CyberArkConfigurationException


@dataclass
class CyberArkConfig:
    """Type-safe configuration settings for CyberArk Central Credential Provider."""
    ccp_url: str = ""
    app_id: str = "VCF-Enterprise-MCP"
    default_safe: Optional[str] = None
    operating_mode: CyberArkOperatingMode = CyberArkOperatingMode.CYBERARK_CCP
    client_cert_path: Optional[str] = None
    client_key_path: Optional[str] = None
    client_key_passphrase: Optional[SecretValue] = None
    ca_bundle_path: Optional[str] = None
    verify_ssl: bool = True
    timeout_seconds: float = 10.0
    max_retries: int = 3
    backoff_factor: float = 0.5
    cache_ttl_seconds: float = 0.0  # 0.0 disables caching (live fail-closed queries)
    default_reason: str = "VCF Enterprise MCP runtime authentication"

    @classmethod
    def from_env(cls) -> "CyberArkConfig":
        """Factory initializing CyberArk configuration from environment variables."""
        ccp_url = os.environ.get("VCF_MCP_CYBERARK_CCP_URL", "").strip()
        app_id = os.environ.get("VCF_MCP_CYBERARK_APP_ID", "VCF-Enterprise-MCP").strip()
        safe = os.environ.get("VCF_MCP_CYBERARK_SAFE", None)
        if safe:
            safe = safe.strip()

        cert_path = os.environ.get("VCF_MCP_CYBERARK_CLIENT_CERT", None)
        key_path = os.environ.get("VCF_MCP_CYBERARK_CLIENT_KEY", None)
        passphrase_raw = os.environ.get("VCF_MCP_CYBERARK_CLIENT_KEY_PASSPHRASE", None)
        passphrase = SecretValue(passphrase_raw) if passphrase_raw else None

        ca_bundle = os.environ.get("VCF_MCP_CYBERARK_CA_BUNDLE", None)

        verify_ssl_raw = os.environ.get("VCF_MCP_CYBERARK_VERIFY_SSL", "true").lower()
        verify_ssl = verify_ssl_raw not in ("false", "0", "no", "off")

        timeout_str = os.environ.get("VCF_MCP_CYBERARK_TIMEOUT", "10.0")
        try:
            timeout_seconds = float(timeout_str)
        except ValueError:
            timeout_seconds = 10.0

        reason = os.environ.get(
            "VCF_MCP_CYBERARK_REASON",
            "VCF Enterprise MCP runtime authentication",
        )

        return cls(
            ccp_url=ccp_url,
            app_id=app_id,
            default_safe=safe,
            client_cert_path=cert_path,
            client_key_path=key_path,
            client_key_passphrase=passphrase,
            ca_bundle_path=ca_bundle,
            verify_ssl=verify_ssl,
            timeout_seconds=timeout_seconds,
            default_reason=reason,
        )

    def validate(self) -> None:
        """Validates configuration parameters; raises CyberArkConfigurationException on defects."""
        if not self.ccp_url:
            raise CyberArkConfigurationException(
                "CyberArk CCP URL is required. Configure via VCF_MCP_CYBERARK_CCP_URL or configuration file."
            )
        if not (self.ccp_url.startswith("https://") or self.ccp_url.startswith("http://")):
            raise CyberArkConfigurationException(
                f"Invalid CyberArk CCP URL '{self.ccp_url}'. Must begin with https:// or http://."
            )
        if not self.app_id:
            raise CyberArkConfigurationException("CyberArk AppID cannot be empty.")

        if self.client_cert_path and not Path(self.client_cert_path).is_file():
            raise CyberArkConfigurationException(
                f"Configured CyberArk client certificate not found: {self.client_cert_path}"
            )
        if self.client_key_path and not Path(self.client_key_path).is_file():
            raise CyberArkConfigurationException(
                f"Configured CyberArk client key not found: {self.client_key_path}"
            )
        if self.ca_bundle_path and not Path(self.ca_bundle_path).is_file():
            raise CyberArkConfigurationException(
                f"Configured CyberArk CA bundle not found: {self.ca_bundle_path}"
            )
