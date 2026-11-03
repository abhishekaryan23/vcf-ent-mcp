# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Capability Provider Registry for Enterprise VCF MCP Control Plane.
Decouples MCP tools from specific appliance endpoints with:
1. Provider Precedence & Authority (distinguishing AUTHORITATIVE source from OBSERVED/DERIVED telemetry).
2. Per-Provider Circuit Breakers (CLOSED -> OPEN -> HALF_OPEN).
3. Data Freshness Metadata on resource entities.
4. Seamless failover across providers (e.g., vCenter -> VCF Operations).
"""

from __future__ import annotations
import time
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field
from enum import Enum
from vcf_enterprise_mcp.core.errors import VCFEnterpriseException, ProviderUnavailableException


class CircuitState(str, Enum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class ProviderCircuitBreaker:
    """Per-provider circuit breaker protecting upstream infrastructure from cascading load."""

    def __init__(self, provider_id: str, failure_threshold: int = 3, reset_timeout: float = 30.0):
        self.provider_id = provider_id
        self.failure_threshold = failure_threshold
        self.reset_timeout = reset_timeout
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.last_failure_time = 0.0

    def record_success(self) -> None:
        self.failure_count = 0
        self.state = CircuitState.CLOSED

    def record_failure(self, reason: str = "") -> None:
        self.failure_count += 1
        self.last_failure_time = time.time()
        if self.failure_count >= self.failure_threshold:
            self.state = CircuitState.OPEN

    def allow_request(self) -> bool:
        if self.state == CircuitState.CLOSED:
            return True
        now = time.time()
        if self.state == CircuitState.OPEN:
            if now - self.last_failure_time > self.reset_timeout:
                self.state = CircuitState.HALF_OPEN
                return True
            return False
        if self.state == CircuitState.HALF_OPEN:
            return True
        return False


class CapabilityNotFoundException(VCFEnterpriseException):
    def __init__(self, capability: str, env_id: str):
        super().__init__(
            message=f"Capability '{capability}' is not provided in environment '{env_id}'.",
            error_code=-32011,
        )


@dataclass
class ProviderEntry:
    """Prioritized provider entry offering a capability."""
    provider_id: str
    provider_type: str         # "vcenter", "sddc_manager", "fleet_lcm", "nsx", "vcf_operations"
    endpoint_url: str
    api_version: str           # e.g. "9.1.1"
    priority: int = 100        # Higher integer = higher priority
    authoritative: bool = True # True = authoritative ground truth; False = observed/derived telemetry
    is_healthy: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)
    circuit_breaker: ProviderCircuitBreaker = field(default=None)

    @property
    def provider_instance_id(self) -> str:
        return self.provider_id

    def __post_init__(self):
        if self.circuit_breaker is None:
            self.circuit_breaker = ProviderCircuitBreaker(self.provider_id)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provider": self.provider_id,
            "provider_type": self.provider_type,
            "api_version": self.api_version,
            "endpoint_url": self.endpoint_url,
            "priority": self.priority,
            "authoritative": self.authoritative,
            "is_healthy": self.is_healthy,
            "circuit_state": self.circuit_breaker.state.value,
        }


# Backward-compatible alias for CapabilityRegistration
CapabilityRegistration = ProviderEntry


class CapabilityProviderRegistry:
    """Central registry mapping logical capabilities to prioritized, circuit-broken providers."""

    def __init__(self, environment_id: str = "prod-vcf"):
        self.environment_id = environment_id
        # Capability name -> List of ProviderEntries sorted by priority descending
        self._capabilities: Dict[str, List[ProviderEntry]] = {}

    def register(self, reg: ProviderEntry, capability_name: Optional[str] = None) -> None:
        cap = capability_name or getattr(reg, "capability_name", None)
        if not cap:
            cap = "default"
        entries = self._capabilities.setdefault(cap, [])
        # Replace if same provider_id exists
        entries = [e for e in entries if e.provider_id != reg.provider_id]
        entries.append(reg)
        entries.sort(key=lambda x: (x.priority, 1 if x.authoritative else 0), reverse=True)
        self._capabilities[cap] = entries

    def resolve(self, capability_name: str) -> ProviderEntry:
        """
        Resolves the highest-priority healthy provider whose circuit breaker is not OPEN.
        Prefers authoritative providers over observed providers.
        """
        entries = self._capabilities.get(capability_name)
        if not entries:
            raise CapabilityNotFoundException(capability_name, self.environment_id)

        # Find first provider that allows request
        for entry in entries:
            if entry.is_healthy and entry.circuit_breaker.allow_request():
                return entry

        # If all tripped, raise ProviderUnavailableException
        first = entries[0]
        raise ProviderUnavailableException(
            provider=first.provider_id,
            reason=f"All providers for capability '{capability_name}' are unavailable or circuit-broken (active state: {first.circuit_breaker.state.value}).",
        )

    def record_provider_failure(self, capability_name: str, provider_id: str, reason: str = "") -> None:
        """Records a failure on a provider to trip its circuit breaker."""
        entries = self._capabilities.get(capability_name, [])
        for e in entries:
            if e.provider_id == provider_id:
                e.circuit_breaker.record_failure(reason)

    def record_provider_success(self, capability_name: str, provider_id: str) -> None:
        """Records a success to close or reset the circuit breaker."""
        entries = self._capabilities.get(capability_name, [])
        for e in entries:
            if e.provider_id == provider_id:
                e.circuit_breaker.record_success()

    def has_capability(self, capability_name: str) -> bool:
        return capability_name in self._capabilities and len(self._capabilities[capability_name]) > 0

    def to_registry_dict(self) -> Dict[str, Any]:
        return {
            "environment": self.environment_id,
            "capabilities": {
                name: [entry.to_dict() for entry in entries]
                for name, entries in self._capabilities.items()
            }
        }

    @classmethod
    def create_default(
        cls,
        environment_id: str = "prod-vcf",
        version: str = "9.1.1",
        vc_url: str = "http://127.0.0.1:9090",
        sddc_url: str = "http://127.0.0.1:9080",
        nsx_url: str = "http://127.0.0.1:9081",
        ops_url: str = "http://127.0.0.1:9082",
    ) -> "CapabilityProviderRegistry":
        """Builds default baseline registry with authoritative and secondary providers."""
        reg = cls(environment_id=environment_id)

        # VM Lifecycle: Authoritative vCenter (priority 100), secondary VCF Operations (priority 50, observed)
        reg.register(ProviderEntry(
            provider_id="vcenter-01",
            provider_type="vcenter",
            api_version=version,
            endpoint_url=vc_url,
            priority=100,
            authoritative=True,
        ), capability_name="vm.lifecycle")
        reg.register(ProviderEntry(
            provider_id="vcf-operations-01",
            provider_type="vcf_operations",
            api_version=version,
            endpoint_url=ops_url,
            priority=50,
            authoritative=False,
        ), capability_name="vm.lifecycle")

        # Compute Inventory
        reg.register(ProviderEntry(
            provider_id="vcenter-01",
            provider_type="vcenter",
            api_version=version,
            endpoint_url=vc_url,
            priority=100,
            authoritative=True,
        ), capability_name="compute.inventory")

        # Domain Lifecycle: SDDC Manager (or future Fleet LCM)
        reg.register(ProviderEntry(
            provider_id="sddc-manager-01",
            provider_type="sddc_manager",
            api_version=version,
            endpoint_url=sddc_url,
            priority=100,
            authoritative=True,
        ), capability_name="domain.lifecycle")

        # Network Segments
        reg.register(ProviderEntry(
            provider_id="nsx-manager-01",
            provider_type="nsx",
            api_version=version,
            endpoint_url=nsx_url,
            priority=100,
            authoritative=True,
        ), capability_name="network.segments")

        # Telemetry
        reg.register(ProviderEntry(
            provider_id="vcf-operations-01",
            provider_type="vcf_operations",
            api_version=version,
            endpoint_url=ops_url,
            priority=100,
            authoritative=True,
        ), capability_name="telemetry.promql")

        # Disaster Recovery / Live Recovery
        reg.register(ProviderEntry(
            provider_id="live-recovery-01",
            provider_type="live_recovery",
            api_version=version,
            endpoint_url=sddc_url,
            priority=100,
            authoritative=True,
        ), capability_name="dr.recovery")

        return reg

    @classmethod
    def create_for_components(
        cls,
        environment_id: str = "prod-vcf",
        version: str = "9.1.1",
        vc_url: Optional[str] = None,
        sddc_url: Optional[str] = None,
        nsx_url: Optional[str] = None,
        ops_url: Optional[str] = None,
    ) -> "CapabilityProviderRegistry":
        """Registry for real VCF with only the components that are configured (each is optional).

        A capability without a provider is simply absent, so the tools that need it are not offered
        (core/protocol.py prunes them with has_capability) instead of pointing at a placeholder address.
        """
        reg = cls(environment_id=environment_id)
        if vc_url:
            vc = dict(provider_id="vcenter-01", provider_type="vcenter", api_version=version, endpoint_url=vc_url,
                      priority=100, authoritative=True)
            reg.register(ProviderEntry(**vc), capability_name="vm.lifecycle")
            reg.register(ProviderEntry(**vc), capability_name="compute.inventory")
            if ops_url:  # observed secondary for VM data
                reg.register(ProviderEntry(provider_id="vcf-operations-01", provider_type="vcf_operations", api_version=version,
                                           endpoint_url=ops_url, priority=50, authoritative=False), capability_name="vm.lifecycle")
        if sddc_url:
            reg.register(ProviderEntry(provider_id="sddc-manager-01", provider_type="sddc_manager", api_version=version,
                                       endpoint_url=sddc_url, priority=100, authoritative=True), capability_name="domain.lifecycle")
            reg.register(ProviderEntry(provider_id="live-recovery-01", provider_type="live_recovery", api_version=version,
                                       endpoint_url=sddc_url, priority=100, authoritative=True), capability_name="dr.recovery")
        if nsx_url:
            reg.register(ProviderEntry(provider_id="nsx-manager-01", provider_type="nsx", api_version=version,
                                       endpoint_url=nsx_url, priority=100, authoritative=True), capability_name="network.segments")
        if ops_url:
            reg.register(ProviderEntry(provider_id="vcf-operations-01", provider_type="vcf_operations", api_version=version,
                                       endpoint_url=ops_url, priority=100, authoritative=True), capability_name="telemetry.promql")
        return reg
