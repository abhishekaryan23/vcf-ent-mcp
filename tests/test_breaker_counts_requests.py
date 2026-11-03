# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""A request that is retried counts once in the circuit breaker, so one tool call cannot open it."""

import socket

import pytest

from vcf_enterprise_mcp.adapter.ssrf_guard import SSRFGuard
from vcf_enterprise_mcp.adapter.transport.base import TransportRequest
from vcf_enterprise_mcp.adapter.transport.errors import UpstreamConnectionException
from vcf_enterprise_mcp.adapter.transport.http import HTTPTransport
from vcf_enterprise_mcp.core.errors import ProviderUnavailableException


def _closed_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()  # nothing listens here any more
    return port


def test_retries_of_one_request_count_once_and_the_error_says_what_to_check(monkeypatch):
    monkeypatch.setattr(HTTPTransport, "_calculate_backoff", lambda self, attempt: 0)
    transport = HTTPTransport(ssrf_guard=SSRFGuard(), max_retries=3)
    url = f"http://127.0.0.1:{_closed_port()}/api/vcenter/cluster"
    with pytest.raises(UpstreamConnectionException) as exc:
        transport.send(TransportRequest("GET", url))
    assert "is running" in str(exc.value)  # connection refused explains what to check
    cb = next(iter(transport.circuit_breakers.values()))
    assert cb._failure_count == 1
    with pytest.raises(UpstreamConnectionException):  # the next call is still tried, not refused by the breaker
        transport.send(TransportRequest("GET", url))


def test_open_breaker_says_when_requests_resume(monkeypatch):
    monkeypatch.setattr(HTTPTransport, "_calculate_backoff", lambda self, attempt: 0)
    transport = HTTPTransport(ssrf_guard=SSRFGuard(), max_retries=0)
    url = f"http://127.0.0.1:{_closed_port()}/x"
    for _ in range(3):
        with pytest.raises(UpstreamConnectionException):
            transport.send(TransportRequest("GET", url))
    with pytest.raises(ProviderUnavailableException) as exc:
        transport.send(TransportRequest("GET", url))
    assert "resume by themselves in" in str(exc.value)
