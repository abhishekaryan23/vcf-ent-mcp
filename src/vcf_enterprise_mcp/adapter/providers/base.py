# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Base VCF Provider Interface and Common Request Dispatcher.
Decouples domain APIs from underlying HTTP transport and serialization.
"""

from __future__ import annotations
import urllib.parse
from abc import ABC
from typing import Dict, Any, Optional, List
from vcf_enterprise_mcp.adapter.transport.base import (
    BaseTransport,
    TransportRequest,
    TransportResponse,
)
from vcf_enterprise_mcp.adapter.transport.auth import BaseUpstreamAuth
from vcf_enterprise_mcp.adapter.transport.errors import UpstreamAuthException
from vcf_enterprise_mcp.adapter.models import ReconciliationStatus, ReconciliationResult


class BaseVCFProvider(ABC):
    """Abstract base provider for VMware infrastructure appliances."""

    def __init__(
        self,
        endpoint_url: str,
        transport: BaseTransport,
        auth: Optional[BaseUpstreamAuth] = None,
        api_version: str = "9.1.1",
        tenant_id: str = "tenant-default",
        environment_id: str = "env-prod",
    ):
        self.endpoint_url = endpoint_url.rstrip("/")
        self.transport = transport
        self.auth = auth
        self.api_version = api_version
        self.tenant_id = tenant_id
        self.environment_id = environment_id

    def _build_url(self, path: str) -> str:
        clean_path = path if path.startswith("/") else f"/{path}"
        return f"{self.endpoint_url}{clean_path}"

    def request(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout_seconds: float = 30.0,
    ) -> TransportResponse:
        """Constructs, authenticates, and dispatches a synchronous request via the transport."""
        url = self._build_url(path)
        req_headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": f"vcf-enterprise-mcp/1.0.0 (API {self.api_version})",
        }
        if headers:
            req_headers.update(headers)

        req = TransportRequest(
            method=method.upper(),
            url=url,
            headers=req_headers,
            params=params,
            json_body=json_body,
            timeout_seconds=timeout_seconds,
            tenant_id=self.tenant_id,
            environment_id=self.environment_id,
        )

        if self.auth:
            req = self.auth.apply(req)

        try:
            return self.transport.send(req)
        except UpstreamAuthException as exc:
            # A 401 means the request was rejected before processing (expired session),
            # so one re-login and resend is safe even for mutations. 403 is a real denial.
            if not self.auth or exc.details.get("status_code") != 401:
                raise
            self.auth.invalidate()
            req.headers.pop("Authorization", None)
            req.headers.pop("vmware-api-session-id", None)
            return self.transport.send(self.auth.apply(req))

    async def request_async(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout_seconds: float = 30.0,
    ) -> TransportResponse:
        """Constructs, authenticates, and dispatches an asynchronous request via the transport."""
        url = self._build_url(path)
        req_headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": f"vcf-enterprise-mcp/1.0.0 (API {self.api_version})",
        }
        if headers:
            req_headers.update(headers)

        req = TransportRequest(
            method=method.upper(),
            url=url,
            headers=req_headers,
            params=params,
            json_body=json_body,
            timeout_seconds=timeout_seconds,
            tenant_id=self.tenant_id,
            environment_id=self.environment_id,
        )

        if self.auth:
            req = self.auth.apply(req)

        try:
            return await self.transport.send_async(req)
        except UpstreamAuthException as exc:
            if not self.auth or exc.details.get("status_code") != 401:
                raise
            self.auth.invalidate()
            req.headers.pop("Authorization", None)
            req.headers.pop("vmware-api-session-id", None)
            return await self.transport.send_async(self.auth.apply(req))

    async def reconcile_operation(
        self,
        intent: Any,
    ) -> ReconciliationResult:
        """
        Probes upstream provider to determine whether mutation was applied.
        Subclasses should override with vendor-specific queries.
        Default implementation returns UNKNOWN to ensure safety (never blindly assume APPLIED).
        """
        return ReconciliationResult(
            status=ReconciliationStatus.UNKNOWN,
            details={"message": f"Provider '{self.__class__.__name__}' does not have a specialized reconciliation probe for operation."},
        )
