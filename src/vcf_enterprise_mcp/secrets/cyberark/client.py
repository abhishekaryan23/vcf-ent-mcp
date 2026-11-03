# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
REST Client for CyberArk Central Credential Provider (CCP) AIMWebService.
Handles HTTP/TLS transport, retries with exponential backoff, SSRF validation,
and explicit error code mapping.
"""

from __future__ import annotations

import json
import random
import time
import urllib.request
import urllib.error
import urllib.parse
from typing import Any, Callable, Dict, Optional, Tuple

from vcf_enterprise_mcp.adapter.ssrf_guard import SSRFGuard
from vcf_enterprise_mcp.secrets.models import SecretValue
from vcf_enterprise_mcp.secrets.cyberark.config import CyberArkConfig
from vcf_enterprise_mcp.secrets.cyberark.auth import CyberArkAuthenticator
from vcf_enterprise_mcp.secrets.cyberark.models import CyberArkQueryParams, CyberArkAccount
from vcf_enterprise_mcp.secrets.cyberark.errors import (
    CyberArkException,
    CyberArkAuthenticationException,
    CyberArkAccountNotFoundException,
    CyberArkSafeNotFoundException,
    CyberArkAccountLockedException,
    CyberArkRateLimitException,
    CyberArkCommunicationException,
)


class CyberArkCCPClient:
    """Enterprise REST client for CyberArk CCP AIMWebService."""

    def __init__(
        self,
        config: CyberArkConfig,
        authenticator: Optional[CyberArkAuthenticator] = None,
        ssrf_guard: Optional[SSRFGuard] = None,
        mock_handler: Optional[Callable[[urllib.request.Request], Tuple[int, bytes, Dict[str, str]]]] = None,
    ):
        self.config = config
        self.authenticator = authenticator or CyberArkAuthenticator(config)
        self.ssrf_guard = ssrf_guard or SSRFGuard()
        self.mock_handler = mock_handler

    def get_account(self, query_params: CyberArkQueryParams) -> CyberArkAccount:
        """
        Retrieves account credentials from CyberArk Central Credential Provider.
        Parses response safely, placing secret content directly into an immutable SecretValue wrapper.
        """
        # 1. Base URL & query parameter assembly
        base_url = self.config.ccp_url
        if "?" in base_url:
            full_url = f"{base_url}&{query_params.to_query_string()}"
        else:
            full_url = f"{base_url}?{query_params.to_query_string()}"

        # 2. SSRF Destination Validation
        self.ssrf_guard.resolve_destination(full_url)

        headers = self.authenticator.get_request_headers()
        req = urllib.request.Request(full_url, headers=headers, method="GET")

        # 3. Handle Mock Execution (In-memory testing)
        if self.mock_handler is not None:
            status_code, body_bytes, _ = self.mock_handler(req)
            return self._handle_response_payload(status_code, body_bytes, query_params)

        # 4. Live Execution with Exponential Backoff
        ssl_ctx = self.authenticator.create_ssl_context()
        attempts = 0
        last_exception: Optional[Exception] = None

        while attempts < self.config.max_retries:
            attempts += 1
            try:
                with urllib.request.urlopen(req, timeout=self.config.timeout_seconds, context=ssl_ctx) as resp:
                    status_code = resp.status
                    body_bytes = resp.read()
                    return self._handle_response_payload(status_code, body_bytes, query_params)
            except urllib.error.HTTPError as he:
                status_code = he.code
                body_bytes = he.read()
                # 4xx client errors should not retry unless 429
                if status_code == 429:
                    last_exception = CyberArkRateLimitException("CyberArk CCP rate limit exceeded.")
                    time.sleep(self.config.backoff_factor * (2 ** (attempts - 1)) + random.uniform(0.01, 0.05))
                    continue
                return self._handle_response_payload(status_code, body_bytes, query_params)
            except (urllib.error.URLError, TimeoutError) as ue:
                last_exception = CyberArkCommunicationException(
                    f"Communication failure connecting to CyberArk CCP ({full_url}): {ue}",
                    original_cause=ue,
                )
                if attempts < self.config.max_retries:
                    sleep_time = self.config.backoff_factor * (2 ** (attempts - 1)) + random.uniform(0.01, 0.05)
                    time.sleep(sleep_time)
                    continue

        if last_exception:
            raise last_exception
        raise CyberArkCommunicationException(f"Failed to communicate with CyberArk CCP after {attempts} attempts.")

    def _handle_response_payload(
        self,
        status_code: int,
        body_bytes: bytes,
        query_params: CyberArkQueryParams,
    ) -> CyberArkAccount:
        """Parses JSON response or maps error payload into typed CyberArk exceptions."""
        try:
            payload: Dict[str, Any] = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
        except Exception:
            payload = {}

        if 200 <= status_code < 300:
            content_str = payload.get("Content")
            if not content_str:
                raise CyberArkException(
                    f"CyberArk CCP returned HTTP {status_code} with missing or empty 'Content' property."
                )

            account = CyberArkAccount(
                safe=payload.get("Safe", query_params.safe),
                object_name=payload.get("Name", query_params.object_name or "unknown"),
                content=SecretValue(content_str),
                user_name=payload.get("UserName", query_params.user_name),
                address=payload.get("Address", query_params.address),
                policy_id=payload.get("PolicyID"),
                device_type=payload.get("DeviceType"),
                folder=payload.get("Folder", query_params.folder),
                extra_properties={k: v for k, v in payload.items() if k not in ("Content", "UserName")},
            )
            return account

        # Error Handling & CyberArk Error Code Mapping
        error_code = payload.get("ErrorCode") or f"HTTP_{status_code}"
        error_msg = payload.get("ErrorMsg") or f"CyberArk CCP error with status {status_code}"

        if error_code in ("APPAP004E", "APPAP005E", "APPAP009E") or status_code == 404:
            raise CyberArkAccountNotFoundException(
                f"Account '{query_params.object_name or query_params.user_name}' not found in safe '{query_params.safe}': {error_msg}",
                error_code=error_code,
            )

        if error_code in ("APPAP133E", "APPAP082E") or status_code == 401:
            raise CyberArkAuthenticationException(
                f"Application '{query_params.app_id}' failed authentication or lacks authorization: {error_msg}",
                error_code=error_code,
            )

        if error_code in ("APPAP272E", "APPAP002E") or status_code == 403:
            raise CyberArkSafeNotFoundException(
                f"Safe '{query_params.safe}' does not exist or AppID lacks retrieve rights: {error_msg}",
                error_code=error_code,
            )

        if error_code == "APPAP330E":
            raise CyberArkAccountLockedException(
                f"Account '{query_params.object_name}' is locked by CyberArk CPM or active management: {error_msg}",
                error_code=error_code,
            )

        if status_code == 429:
            raise CyberArkRateLimitException(f"Rate limited by CyberArk CCP: {error_msg}")

        raise CyberArkException(f"CyberArk CCP request failed ({error_code}): {error_msg}", error_code=error_code)
