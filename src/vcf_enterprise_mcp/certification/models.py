# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
VCF Real-World Certification Framework Models.
Defines verification levels, component types, certification operations, profiles, and results.
"""

from __future__ import annotations
from enum import Enum
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
import time


class VerificationLevel(str, Enum):
    """Hierarchical qualification level for VCF interoperability certification."""
    UNVERIFIED = "UNVERIFIED"
    UNIT_TEST_ONLY = "UNIT_TEST_ONLY"
    SPEC_VERIFIED = "SPEC_VERIFIED"
    DIGITAL_TWIN_VERIFIED = "DIGITAL_TWIN_VERIFIED"
    REAL_VCF_VERIFIED = "REAL_VCF_VERIFIED"
    GA_CERTIFIED = "GA_CERTIFIED"


class ComponentType(str, Enum):
    """Core VMware Cloud Foundation subsystems under certification."""
    SDDC_MANAGER = "sddc_manager"
    VCENTER = "vcenter"
    NSX = "nsx"
    VCF_OPERATIONS = "vcf_operations"


@dataclass
class CertificationOperation:
    """An individual platform operation verified within a certification profile."""
    name: str
    component: ComponentType
    transport_route: str  # "direct" or "mediated"
    required_capabilities: List[str] = field(default_factory=list)
    description: str = ""
    is_destructive: bool = False
    test_params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class OperationResult:
    """Outcome of certifying an individual operation."""
    operation_name: str
    component: ComponentType
    transport_route: str
    verification_level: VerificationLevel
    status: str  # "PASS", "FAIL", "SKIPPED"
    latency_ms: float
    error_message: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CertificationProfile:
    """Defines a target VCF release specification and operations matrix to certify."""
    profile_name: str
    vcf_version: str
    component_versions: Dict[str, str] = field(default_factory=dict)
    operations: List[CertificationOperation] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CertificationResult:
    """Consolidated outcome of running a certification profile."""
    profile_name: str
    vcf_version: str
    verification_level: VerificationLevel
    timestamp: float = field(default_factory=time.time)
    operation_results: List[OperationResult] = field(default_factory=list)

    @property
    def total_operations(self) -> int:
        return len(self.operation_results)

    @property
    def passed_count(self) -> int:
        return sum(1 for r in self.operation_results if r.status == "PASS")

    @property
    def failed_count(self) -> int:
        return sum(1 for r in self.operation_results if r.status == "FAIL")

    @property
    def skipped_count(self) -> int:
        return sum(1 for r in self.operation_results if r.status == "SKIPPED")

    @property
    def passed_operations(self) -> int:
        return self.passed_count

    @property
    def failed_operations(self) -> int:
        return self.failed_count

    @property
    def passed(self) -> bool:
        return self.is_successful

    @property
    def pass_rate(self) -> float:
        return (self.passed_count / self.total_operations * 100.0) if self.total_operations > 0 else 0.0

    @property
    def is_successful(self) -> bool:
        return self.failed_count == 0 and self.passed_count > 0

    @property
    def direct_vcenter_success(self) -> bool:
        """Verifies SDDC Manager Independence for vCenter-direct calls."""
        vc_ops = [r for r in self.operation_results if r.component == ComponentType.VCENTER and r.transport_route == "direct"]
        return len(vc_ops) > 0 and all(r.status == "PASS" for r in vc_ops)

    @property
    def direct_nsx_success(self) -> bool:
        """Verifies SDDC Manager Independence for NSX-direct calls."""
        nsx_ops = [r for r in self.operation_results if r.component == ComponentType.NSX and r.transport_route == "direct"]
        return len(nsx_ops) > 0 and all(r.status == "PASS" for r in nsx_ops)
