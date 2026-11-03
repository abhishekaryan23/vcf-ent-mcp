# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Admission Controller, Rate Budgets & Backpressure Management.
Protects the enterprise VCF infrastructure and MCP control plane from operational storms,
concurrent workflow starvation, and runaway LLM agent loops.
Separates LLM routing rate limits from downstream VCF infrastructure limits.
"""

from __future__ import annotations
import time
import threading
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from vcf_enterprise_mcp.policy.models import RiskClass
from vcf_enterprise_mcp.core.errors import RateLimitBudgetExceededException


@dataclass
class AdmissionBudgetConfig:
    """Configurable rate limits and concurrency budgets."""
    principal_reads_per_minute: int = 300
    principal_writes_per_minute: int = 20
    concurrent_lifecycle_workflows: int = 1
    concurrent_vm_changes: int = 20
    component_rates_per_second: Dict[str, int] = field(default_factory=lambda: {
        "nsx": 25,
        "vcenter": 50,
        "sddc_manager": 20,
        "vcf_operations": 40,
    })


class AdmissionController:
    """
    Evaluates requests against rate and concurrency budgets before dispatch.
    Applies backpressure when limits are approached.
    """

    def __init__(self, config: Optional[AdmissionBudgetConfig] = None):
        self.config = config or AdmissionBudgetConfig()
        self._lock = threading.RLock()
        # principal_id -> List[timestamps]
        self._user_read_timestamps: Dict[str, list] = {}
        self._user_write_timestamps: Dict[str, list] = {}
        # Active in-flight counters
        self._active_lifecycle_workflows = 0
        self._active_vm_changes = 0
        # Component rate tracking
        self._component_timestamps: Dict[str, list] = {}

    def admit_request(
        self,
        principal_id: str,
        risk_class: RiskClass,
        tool_name: str,
        target_component: str = "vcenter",
    ) -> None:
        """
        Evaluates whether a request can be admitted or must be throttled.
        Raises RateLimitBudgetExceededException if budget is exhausted.
        """
        now = time.time()
        one_minute_ago = now - 60.0
        one_second_ago = now - 1.0

        with self._lock:
            # 1. Principal Read/Write rate limits
            if risk_class == RiskClass.READ:
                reads = self._user_read_timestamps.setdefault(principal_id, [])
                reads[:] = [t for t in reads if t > one_minute_ago]
                if len(reads) >= self.config.principal_reads_per_minute:
                    raise RateLimitBudgetExceededException(
                        f"Principal '{principal_id}' exceeded read limit ({self.config.principal_reads_per_minute}/min). Backpressure applied."
                    )
                reads.append(now)
            else:
                writes = self._user_write_timestamps.setdefault(principal_id, [])
                writes[:] = [t for t in writes if t > one_minute_ago]
                if len(writes) >= self.config.principal_writes_per_minute:
                    raise RateLimitBudgetExceededException(
                        f"Principal '{principal_id}' exceeded write limit ({self.config.principal_writes_per_minute}/min). Operation throttled."
                    )
                writes.append(now)

            # 2. Concurrency budgets for high-blast operations
            if "upgrade" in tool_name or risk_class == RiskClass.HIGH_IMPACT:
                if self._active_lifecycle_workflows >= self.config.concurrent_lifecycle_workflows:
                    raise RateLimitBudgetExceededException(
                        f"Concurrency budget exhausted: Only {self.config.concurrent_lifecycle_workflows} active domain lifecycle workflow permitted concurrently."
                    )

            if "resize" in tool_name or "power" in tool_name:
                if self._active_vm_changes >= self.config.concurrent_vm_changes:
                    raise RateLimitBudgetExceededException(
                        f"Concurrency budget exhausted: Max {self.config.concurrent_vm_changes} concurrent VM mutations permitted."
                    )

            # 3. Downstream VCF Component Rate Limits
            comp_rate = self.config.component_rates_per_second.get(target_component, 30)
            comp_ts = self._component_timestamps.setdefault(target_component, [])
            comp_ts[:] = [t for t in comp_ts if t > one_second_ago]
            if len(comp_ts) >= comp_rate:
                raise RateLimitBudgetExceededException(
                    f"Component '{target_component}' rate budget exhausted ({comp_rate} req/sec). Backpressure applied."
                )
            comp_ts.append(now)

    def enter_operation(self, tool_name: str) -> None:
        with self._lock:
            if "upgrade" in tool_name:
                self._active_lifecycle_workflows += 1
            if "resize" in tool_name or "power" in tool_name:
                self._active_vm_changes += 1

    def exit_operation(self, tool_name: str) -> None:
        with self._lock:
            if "upgrade" in tool_name and self._active_lifecycle_workflows > 0:
                self._active_lifecycle_workflows -= 1
            if ("resize" in tool_name or "power" in tool_name) and self._active_vm_changes > 0:
                self._active_vm_changes -= 1
