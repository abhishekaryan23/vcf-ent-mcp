# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
VCF Adapter & Onboarding Package.
"""

from vcf_enterprise_mcp.adapter.version_adapter import VCFVersionAdapter
from vcf_enterprise_mcp.adapter.discovery import (
    EnvironmentProfile,
    CapabilityMatrix,
    OnboardingEngine,
)
from vcf_enterprise_mcp.adapter.models import (
    PlatformMode,
    ResourceRevision,
    ReconciliationStatus,
    ReconciliationResult,
    ExecutionIntent,
)

from vcf_enterprise_mcp.adapter.ssrf_guard import SSRFGuard, ResolvedDestination

__all__ = [
    "PlatformMode",
    "VCFVersionAdapter",
    "EnvironmentProfile",
    "CapabilityMatrix",
    "OnboardingEngine",
    "ResourceRevision",
    "ReconciliationStatus",
    "ReconciliationResult",
    "ExecutionIntent",
    "SSRFGuard",
    "ResolvedDestination",
]
