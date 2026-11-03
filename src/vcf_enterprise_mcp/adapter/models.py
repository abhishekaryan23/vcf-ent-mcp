# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Infrastructure Adapter Domain Models, Typed Revisions, and Reconciliation Contracts.
"""

from __future__ import annotations
import time
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, Any, Optional


class PlatformMode(str, Enum):
    """Execution mode for infrastructure platform client."""
    REAL_VCF = "REAL_VCF"
    DIGITAL_TWIN = "DIGITAL_TWIN"
    UNIT_TEST = "UNIT_TEST"


@dataclass(frozen=True)
class ResourceRevision:
    """Typed monotonic revision tracking for infrastructure resources (TOCTOU protection)."""
    provider: str
    value: str

    def __str__(self) -> str:
        return self.value

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, ResourceRevision):
            return self.provider == other.provider and self.value == other.value
        if isinstance(other, str):
            return self.value == other
        return False

    def is_newer_than(self, other: ResourceRevision) -> bool:
        """Determines if this revision represents a newer state than another revision."""
        if not isinstance(other, ResourceRevision):
            return False
        try:
            self_num = int(self.value.replace("rev-", ""))
            other_num = int(other.value.replace("rev-", ""))
            return self_num > other_num
        except ValueError:
            return self.value != other.value


class ReconciliationStatus(str, Enum):
    """Result status of outbox intent reconciliation against upstream appliance."""
    APPLIED = "APPLIED"              # Mutation was definitely applied upstream
    NOT_APPLIED = "NOT_APPLIED"      # Mutation was definitely NOT applied upstream
    IN_PROGRESS = "IN_PROGRESS"      # Upstream task is currently executing
    FAILED = "FAILED"                # Upstream task failed
    UNKNOWN = "UNKNOWN"              # Indeterminate remote state; NEVER blindly retry


@dataclass(frozen=True)
class ReconciliationResult:
    """Outcome of attempting to reconcile an execution intent against upstream state."""
    status: ReconciliationStatus
    details: Dict[str, Any] = field(default_factory=dict)
    observed_revision: Optional[ResourceRevision] = None


@dataclass
class ExecutionIntent:
    """Durable intent record persisted before dispatching mutation to upstream provider."""
    intent_id: str
    workflow_id: str
    step_id: str
    target_resource: str
    operation_id: str
    desired_state: Dict[str, Any]
    fencing_token: int = 0
    state: str = "EXECUTION_INTENT_RECORDED"
    recorded_at: float = field(default_factory=time.time)
    resolved_at: float = 0.0
    outcome: str = ""
    tenant_id: str = "tenant-default"
    environment_id: str = "env-prod"
    expected_revision: Optional[ResourceRevision] = None
