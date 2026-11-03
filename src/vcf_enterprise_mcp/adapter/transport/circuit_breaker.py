# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Provider Circuit Breaker for Upstream VCF Endpoints.
Prevents cascading failures by opening circuit on repeated connection/timeout/server errors.
"""

from __future__ import annotations
import time
from enum import Enum
from typing import Optional
from vcf_enterprise_mcp.core.errors import ProviderUnavailableException


class CircuitState(str, Enum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class TransportCircuitBreaker:
    """Thread-safe circuit breaker tracking upstream endpoint health."""

    def __init__(
        self,
        endpoint_id: str,
        failure_threshold: int = 3,
        recovery_time_seconds: float = 30.0,
    ):
        self.endpoint_id = endpoint_id
        self.failure_threshold = failure_threshold
        self.recovery_time_seconds = recovery_time_seconds
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._last_failure_time = 0.0

    @property
    def state(self) -> CircuitState:
        if self._state == CircuitState.OPEN:
            if time.time() - self._last_failure_time > self.recovery_time_seconds:
                self._state = CircuitState.HALF_OPEN
        return self._state

    def record_success(self) -> None:
        self._failure_count = 0
        self._state = CircuitState.CLOSED

    def record_failure(self, reason: str = "") -> None:
        self._failure_count += 1
        self._last_failure_time = time.time()
        if self._failure_count >= self.failure_threshold:
            self._state = CircuitState.OPEN

    def allow_request(self) -> bool:
        current_state = self.state
        if current_state == CircuitState.CLOSED:
            return True
        if current_state == CircuitState.HALF_OPEN:
            return True
        return False

    def retry_in_seconds(self) -> int:
        return max(1, int(self.recovery_time_seconds - (time.time() - self._last_failure_time)) + 1)

    def check_or_raise(self) -> None:
        if not self.allow_request():
            raise ProviderUnavailableException(
                provider=self.endpoint_id,
                reason=(f"Circuit breaker for upstream endpoint '{self.endpoint_id}' is OPEN (failed {self._failure_count} consecutive "
                        f"requests). Requests to it resume by themselves in {self.retry_in_seconds()} s."),
            )
