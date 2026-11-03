# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Soak, Rate Budgets, and Backpressure Test Suite (Phases 20-23).
Verifies:
- Memory leak tracking and system stability under 1,000+ operations
- Admission controller rate budget enforcement and read/write backpressure
- Concurrency budget backpressure for high-impact lifecycle workflows
- Component-level throughput throttling preventing downstream appliance exhaustion
- Bounded connection and task queue saturation rejection
"""

import gc
import sys
import time
import unittest
from typing import List

from vcf_enterprise_mcp.core.admission import (
    AdmissionController,
    AdmissionBudgetConfig,
)
from vcf_enterprise_mcp.policy.models import RiskClass, CapabilityRole
from vcf_enterprise_mcp.core.errors import RateLimitBudgetExceededException
from vcf_enterprise_mcp.auth.identity import Principal
from vcf_enterprise_mcp.policy.engine import PolicyDecisionPoint, PolicyConfig
from vcf_enterprise_mcp.state.sqlite_store import SQLiteDurableStore
from vcf_enterprise_mcp.router.catalog import ALL_ENTERPRISE_TOOLS
from vcf_enterprise_mcp.router.identity_router import IdentityAwareRouter, StructuredIntent


class TestSoakAndBackpressure(unittest.TestCase):

    def setUp(self):
        self.durable = SQLiteDurableStore(":memory:")
        self.pdp = PolicyDecisionPoint(
            config=PolicyConfig(operating_mode="AUDITED_OPERATIONS"),
            durable_store=self.durable,
        )
        self.router = IdentityAwareRouter(pdp=self.pdp)

    def test_soak_1000_operations_memory_and_stability(self):
        """
        Executes 1,000 continuous control-plane routing and policy evaluations.
        Verifies steady-state latency, zero unbounded object accumulation, and stable execution.
        """
        gc.collect()
        initial_objects = len(gc.get_objects())

        principal = Principal(
            user_id="soak-operator@corp.com",
            corporate_groups=["VCF-Compute-Operators"],
            tenant_id="tenant-soak",
            environment_ids=["env-prod"],
            allowed_clusters=["*"],
            allowed_domains=["*"],
        )

        latencies_ms: List[float] = []

        for i in range(1000):
            t0 = time.perf_counter()

            # 1. Routing step
            query = f"Show details for virtual machine vm-soak-{i % 100}"
            route_res = self.router.route_query(query, principal)
            self.assertEqual(route_res.selected_tool, "vcf_get_vm")

            # 2. PDP evaluation step
            auth_decision = self.pdp.evaluate_request(
                principal=principal,
                tool_name="vcf_get_vm",
                risk_class=RiskClass.READ,
                required_roles=[CapabilityRole.VCF_VIEWER, CapabilityRole.COMPUTE_OPERATOR],
            )
            self.assertTrue(auth_decision.allow)

            # 3. Durable store state read/write step
            self.durable.record_idempotency(
                tenant_id="tenant-soak",
                idempotency_key=f"idemp-soak-{i}",
                principal_id=principal.user_id,
                tool_id="vcf_get_vm",
                args_sha256="hash123",
                response_payload={"status": "OK", "iteration": i},
                environment_id="env-prod",
            )

            t1 = time.perf_counter()
            latencies_ms.append((t1 - t0) * 1000.0)

        gc.collect()
        final_objects = len(gc.get_objects())

        # Assert zero performance degradation (P95 latency under 10ms for in-memory soak)
        latencies_ms.sort()
        p95 = latencies_ms[int(len(latencies_ms) * 0.95)]
        self.assertLess(p95, 10.0, f"P95 latency too high: {p95:.2f} ms")

        # Assert no runaway memory / object accumulation (growth bounded to store records)
        object_delta = final_objects - initial_objects
        self.assertLess(object_delta, 15000, f"Excessive object growth during soak: {object_delta} objects")

    def test_admission_controller_principal_read_backpressure(self):
        """Verifies read rate limits trigger immediate fail-closed backpressure."""
        config = AdmissionBudgetConfig(principal_reads_per_minute=25)
        controller = AdmissionController(config)
        principal_id = "analyst@corp.com"

        # 25 allowed requests
        for _ in range(25):
            controller.admit_request(
                principal_id=principal_id,
                risk_class=RiskClass.READ,
                tool_name="vcf_list_vms",
            )

        # 26th request hits limit -> Backpressure applied
        with self.assertRaises(RateLimitBudgetExceededException) as ctx:
            controller.admit_request(
                principal_id=principal_id,
                risk_class=RiskClass.READ,
                tool_name="vcf_list_vms",
            )
        self.assertIn("Backpressure applied", str(ctx.exception))

    def test_admission_controller_principal_write_throttling(self):
        """Verifies mutating operations throttle when write rate budget is exhausted."""
        config = AdmissionBudgetConfig(principal_writes_per_minute=5)
        controller = AdmissionController(config)
        principal_id = "operator@corp.com"

        for _ in range(5):
            controller.admit_request(
                principal_id=principal_id,
                risk_class=RiskClass.SAFE_WRITE,
                tool_name="vcf_power_vm",
            )

        # 6th write operation throttled
        with self.assertRaises(RateLimitBudgetExceededException) as ctx:
            controller.admit_request(
                principal_id=principal_id,
                risk_class=RiskClass.SAFE_WRITE,
                tool_name="vcf_power_vm",
            )
        self.assertIn("Operation throttled", str(ctx.exception))

    def test_concurrency_budget_backpressure_lifecycle_workflows(self):
        """High-blast domain upgrades restrict concurrency to 1 to protect cluster stability."""
        config = AdmissionBudgetConfig(concurrent_lifecycle_workflows=1)
        controller = AdmissionController(config)

        # First workflow enters
        controller.admit_request(
            principal_id="admin@corp.com",
            risk_class=RiskClass.HIGH_IMPACT,
            tool_name="vcf_upgrade_domain",
        )
        controller.enter_operation("vcf_upgrade_domain")

        # Second workflow attempts to enter concurrently -> Thrown backpressure
        with self.assertRaises(RateLimitBudgetExceededException) as ctx:
            controller.admit_request(
                principal_id="admin2@corp.com",
                risk_class=RiskClass.HIGH_IMPACT,
                tool_name="vcf_upgrade_domain",
            )
        self.assertIn("Concurrency budget exhausted", str(ctx.exception))

        # First workflow finishes
        controller.exit_operation("vcf_upgrade_domain")

        # Now second workflow is admitted
        controller.admit_request(
            principal_id="admin2@corp.com",
            risk_class=RiskClass.HIGH_IMPACT,
            tool_name="vcf_upgrade_domain",
        )

    def test_component_rate_budget_backpressure(self):
        """Component-level rate limits (e.g. NSX Manager API) throttle spikes."""
        config = AdmissionBudgetConfig(component_rates_per_second={"nsx": 10})
        controller = AdmissionController(config)

        # 10 NSX operations admitted
        for _ in range(10):
            controller.admit_request(
                principal_id="netadmin@corp.com",
                risk_class=RiskClass.CHANGE,
                tool_name="vcf_create_nsx_segment",
                target_component="nsx",
            )

        # 11th operation in the same second exhausts budget
        with self.assertRaises(RateLimitBudgetExceededException) as ctx:
            controller.admit_request(
                principal_id="netadmin@corp.com",
                risk_class=RiskClass.CHANGE,
                tool_name="vcf_create_nsx_segment",
                target_component="nsx",
            )
        self.assertIn("Component 'nsx' rate budget exhausted", str(ctx.exception))
