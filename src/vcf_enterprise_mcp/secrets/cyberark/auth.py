# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Authentication and TLS/mTLS configuration for CyberArk Central Credential Provider (CCP).
"""

from __future__ import annotations

import ssl
from typing import Dict, Optional
from vcf_enterprise_mcp.secrets.cyberark.config import CyberArkConfig
from vcf_enterprise_mcp.secrets.cyberark.errors import CyberArkConfigurationException
from vcf_enterprise_mcp.core.headers import get_current_trace_context


class CyberArkAuthenticator:
    """Manages TLS/mTLS contexts and HTTP headers for CyberArk CCP REST interactions."""

    def __init__(self, config: CyberArkConfig):
        self.config = config

    def create_ssl_context(self) -> ssl.SSLContext:
        """
        Creates a hardened, fail-closed SSLContext supporting server validation and optional client mTLS.
        """
        if not self.config.verify_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx

        # Strict TLS verification
        ctx = ssl.create_default_context(
            purpose=ssl.Purpose.SERVER_AUTH,
            cafile=self.config.ca_bundle_path,
        )
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

        # Enforce minimum TLS 1.2
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        # Configure client certificate for mTLS if specified
        if self.config.client_cert_path and self.config.client_key_path:
            passphrase = (
                self.config.client_key_passphrase.reveal_for_transport()
                if self.config.client_key_passphrase
                else None
            )
            try:
                ctx.load_cert_chain(
                    certfile=self.config.client_cert_path,
                    keyfile=self.config.client_key_path,
                    password=passphrase,
                )
            except Exception as e:
                raise CyberArkConfigurationException(
                    f"Failed to load CyberArk client mTLS certificate/key: {e}"
                ) from e

        return ctx

    def get_request_headers(self, custom_headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Constructs standardized HTTP headers with traceparent and JSON acceptance."""
        headers = {
            "Accept": "application/json",
            "User-Agent": "VCF-Enterprise-MCP/0.9 (CyberArk-CCP-Client)",
        }
        trace_ctx = get_current_trace_context()
        if trace_ctx:
            headers["traceparent"] = trace_ctx.to_header()

        if custom_headers:
            headers.update(custom_headers)
        return headers
