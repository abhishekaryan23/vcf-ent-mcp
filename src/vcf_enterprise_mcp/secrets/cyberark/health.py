# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Health verification and connectivity checks for CyberArk Central Credential Provider (CCP).
"""

from __future__ import annotations

import time
import urllib.request
import urllib.error
from typing import Any, Dict

from vcf_enterprise_mcp.secrets.models import SecretProviderHealth
from vcf_enterprise_mcp.secrets.cyberark.config import CyberArkConfig
from vcf_enterprise_mcp.secrets.cyberark.auth import CyberArkAuthenticator


class CyberArkHealthChecker:
    """Evaluates liveness and reachability of the CyberArk CCP AIMWebService."""

    def __init__(self, config: CyberArkConfig, authenticator: Optional[CyberArkAuthenticator] = None):
        self.config = config
        self.authenticator = authenticator or CyberArkAuthenticator(config)

    def check_health(self) -> SecretProviderHealth:
        """Performs non-intrusive probe against configured CyberArk CCP service endpoint."""
        now = time.time()
        if not self.config.ccp_url:
            return SecretProviderHealth(
                status="DEGRADED",
                provider_name="cyberark",
                details={"reason": "CyberArk CCP URL not configured (unbound)"},
                checked_at=now,
            )

        headers = self.authenticator.get_request_headers()
        req = urllib.request.Request(self.config.ccp_url, headers=headers, method="GET")
        ssl_ctx = self.authenticator.create_ssl_context()

        try:
            start_t = time.perf_counter()
            with urllib.request.urlopen(req, timeout=self.config.timeout_seconds, context=ssl_ctx) as resp:
                elapsed_ms = (time.perf_counter() - start_t) * 1000.0
                status_code = resp.status
                return SecretProviderHealth(
                    status="HEALTHY",
                    provider_name="cyberark",
                    details={
                        "endpoint": self.config.ccp_url,
                        "http_status": status_code,
                        "latency_ms": round(elapsed_ms, 2),
                        "mode": self.config.operating_mode.value,
                    },
                    checked_at=now,
                )
        except urllib.error.HTTPError as he:
            # An HTTP 400 or 404 from CCP often means the endpoint is live and answering AIMWebService queries
            elapsed_ms = (time.perf_counter() - start_t) * 1000.0 if "start_t" in locals() else 0.0
            if he.code in (400, 401, 403, 404):
                return SecretProviderHealth(
                    status="HEALTHY",
                    provider_name="cyberark",
                    details={
                        "endpoint": self.config.ccp_url,
                        "http_status": he.code,
                        "note": "Endpoint responsive to AIMWebService requests",
                        "latency_ms": round(elapsed_ms, 2),
                    },
                    checked_at=now,
                )
            return SecretProviderHealth(
                status="DEGRADED",
                provider_name="cyberark",
                details={
                    "endpoint": self.config.ccp_url,
                    "http_status": he.code,
                    "error": str(he),
                },
                checked_at=now,
            )
        except Exception as ex:
            return SecretProviderHealth(
                status="UNHEALTHY",
                provider_name="cyberark",
                details={
                    "endpoint": self.config.ccp_url,
                    "error": str(ex),
                },
                checked_at=now,
            )
