# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Base Transport Models and Abstract Interface for Upstream VCF Communication.
Defines TransportRequest, TransportResponse, and BaseTransport.
"""

from __future__ import annotations
import json
import urllib.parse
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from dataclasses import dataclass, field


@dataclass
class TransportRequest:
    """Represents an HTTP request destined for an upstream VCF appliance."""
    method: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    params: Optional[Dict[str, Any]] = None
    json_body: Optional[Any] = None
    data: Optional[bytes] = None
    timeout_seconds: float = 30.0
    tenant_id: str = "tenant-default"
    environment_id: str = "env-prod"

    def get_full_url(self) -> str:
        if not self.params:
            return self.url
        query_string = urllib.parse.urlencode({k: v for k, v in self.params.items() if v is not None}, doseq=True)
        sep = "&" if "?" in self.url else "?"
        return f"{self.url}{sep}{query_string}"

    def get_body_bytes(self) -> Optional[bytes]:
        if self.data is not None:
            return self.data
        if self.json_body is not None:
            return json.dumps(self.json_body).encode("utf-8")
        return None


@dataclass
class TransportResponse:
    """Represents an HTTP response received from an upstream VCF appliance."""
    status_code: int
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    elapsed_seconds: float = 0.0

    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 300

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def json(self) -> Any:
        if not self.body:
            return None
        return json.loads(self.text)


class BaseTransport(ABC):
    """Abstract interface for all upstream VCF transport implementations."""

    @abstractmethod
    def send(self, request: TransportRequest) -> TransportResponse:
        """Synchronously executes a transport request against the upstream endpoint."""
        raise NotImplementedError

    @abstractmethod
    async def send_async(self, request: TransportRequest) -> TransportResponse:
        """Asynchronously executes a transport request against the upstream endpoint."""
        raise NotImplementedError
