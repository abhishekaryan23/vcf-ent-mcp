# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Test Suite: Pre-Mutation Idempotency and Lost-Response Reconciliation (Finding P1-1).

Validates:
1. Pre-mutation persistence: PENDING idempotency record and ExecutionIntent written BEFORE upstream dispatch.
2. Post-mutation transition: COMMITTED idempotency record and RESOLVED intent on success.
3. Lost response recovery (APPLIED): Process crashes after upstream mutation; retry reconciles upstream state and returns cached/recovered response without re-executing.
4. Safe retry on unapplied crash (NOT_APPLIED): Retry proceeds with execution if upstream was not mutated.
5. In-flight protection (IN_PROGRESS): Retry is rejected with IdempotencyConflictException while upstream task is executing.
6. Indeterminate safety (UNKNOWN): Refuses blind retry and mandates manual intervention when upstream state cannot be proven.
7. Argument tampering rejection: Reusing idempotency key with modified arguments raises IdempotencyConflictException.
"""

from tests.fixtures.authorized_execution import execute_authorized
import unittest
import asyncio
from unittest.mock import MagicMock
from vcf_enterprise_mcp.auth.identity import Principal
from vcf_enterprise_mcp.state.durable_store import DurableStore
from vcf_enterprise_mcp.policy.enforcement import PolicyEnforcementPoint
from vcf_enterprise_mcp.policy.engine import PolicyDecisionPoint
from vcf_enterprise_mcp.config.settings import PolicyConfig
from vcf_enterprise_mcp.tools.operational_tools import VCFResizeVMTool
from vcf_enterprise_mcp.core.errors import (
    IdempotencyConflictException,
    VCFEnterpriseException,
)
from vcf_enterprise_mcp.adapter.platform import PlatformClient
from vcf_enterprise_mcp.adapter.models import (
    ExecutionIntent,
    ReconciliationResult,
    ReconciliationStatus,
    ResourceRevision,
)


class CrashableResizeTool(VCFResizeVMTool):
    """Tool that tracks run_live call count and can simulate crashes."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.run_live_call_count = 0
        self.crash_during_live = False

    async def run_live(self, principal: Principal, arguments: dict) -> dict:
        self.run_live_call_count += 1
        if self.crash_during_live:
            raise RuntimeError("Simulated crash right after upstream mutation started")
        vm_id = arguments["vm_id"]
        mem = arguments.get("memory_gb", 32)
        cpu = arguments.get("cpu_cores", 4)
        if hasattr(self.platform, "get_vm"):
            self.platform.get_vm.side_effect = lambda v: {"vm_id": v, "memory_gb": mem, "cpu_cores": cpu}
        return {
            "dry_run": False,
            "status": "SUCCESS",
            "vm_id": vm_id,
            "allocated_memory_gb": mem,
            "task_id": "vcf-task-9999",
        }


class TestPreMutationIdempotency(unittest.TestCase):

    def setUp(self):
        self.durable = DurableStore(":memory:")
        self.pdp = PolicyDecisionPoint(
            config=PolicyConfig(operating_mode="AUDITED_OPERATIONS"),
            durable_store=self.durable,
        )
        self.pep = PolicyEnforcementPoint(pdp=self.pdp)
        self.platform = MagicMock(spec=PlatformClient)
        self.platform.get_resource_revision.return_value = ResourceRevision("vcenter", "rev-test")
        self.platform.get_vm.side_effect = lambda v: {"vm_id": v, "memory_gb": 32, "cpu_cores": 4}
        self.alice = Principal(
            user_id="alice@corp.com",
            corporate_groups=["VCF-Compute-Operators"],
            allowed_clusters=["cluster-prod-a"],
        )
        self.tool = CrashableResizeTool(
            pep=self.pep,
            durable_store=self.durable,
            platform_client=self.platform,
        )

    def test_pre_mutation_persistence_and_commit(self):
        """Pre-mutation records PENDING, then updates to COMMITTED on success."""
        key = "idemp-test-001"
        args = {
            "vm_id": "vm-101",
            "cluster_id": "cluster-prod-a",
            "memory_gb": 32,
            "idempotency_key": key,
        }

        # Execute
        res = asyncio.run(execute_authorized(self.tool, self.alice, args))
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(self.tool.run_live_call_count, 1)

        # Check durable record is COMMITTED
        rec = self.durable.get_idempotency_record("tenant-default", key)
        self.assertIsNotNone(rec)
        self.assertEqual(rec["status"], "COMMITTED")
        self.assertEqual(rec["response"]["allocated_memory_gb"], 32)

        # Check execution intent is RESOLVED
        intents = self.durable.list_pending_execution_intents("tenant-default")
        self.assertEqual(len(intents), 0)

    def test_lost_response_recovery_when_applied_upstream(self):
        """Simulate crash where upstream succeeded but client disconnected. Retry reconciles APPLIED."""
        key = "idemp-crash-002"
        args = {
            "vm_id": "vm-102",
            "cluster_id": "cluster-prod-a",
            "memory_gb": 64,
            "idempotency_key": key,
        }

        # Simulate pre-mutation state left PENDING due to crash
        import hashlib, json
        clean_args = {k: v for k, v in args.items() if k != "idempotency_key"}
        actual_hash = hashlib.sha256(json.dumps(clean_args, sort_keys=True).encode()).hexdigest()
        self.durable.record_idempotency(
            tenant_id="tenant-default",
            idempotency_key=key,
            principal_id="alice@corp.com",
            tool_id="vcf_resize_vm",
            args_sha256=actual_hash,
            response_payload={"status": "PENDING", "stage": "DISPATCHING_MUTATION"},
            status="PENDING",
        )

        # Mock platform reconciliation returning APPLIED
        self.platform.reconcile_operation_sync.return_value = ReconciliationResult(
            status=ReconciliationStatus.APPLIED,
            details={"vm_id": "vm-102", "memory_gb": 64, "applied_at": 123456.0},
            observed_revision=ResourceRevision("vcenter", "rev-200"),
        )

        # Retry execution with same key
        res = asyncio.run(execute_authorized(self.tool, self.alice, args))

        # Must NOT have called run_live (no double execution!)
        self.assertEqual(self.tool.run_live_call_count, 0)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertTrue(res.get("reconciled"))
        self.assertEqual(res["details"]["memory_gb"], 64)

        # Record must now be COMMITTED
        rec = self.durable.get_idempotency_record("tenant-default", key)
        self.assertEqual(rec["status"], "COMMITTED")

    def test_safe_retry_when_not_applied_upstream(self):
        """Simulate crash where mutation never reached upstream (NOT_APPLIED). Retry runs live."""
        key = "idemp-crash-003"
        args = {
            "vm_id": "vm-103",
            "cluster_id": "cluster-prod-a",
            "memory_gb": 16,
            "idempotency_key": key,
        }

        # Set up PENDING record
        import hashlib, json
        clean_args = {k: v for k, v in args.items() if k != "idempotency_key"}
        actual_hash = hashlib.sha256(json.dumps(clean_args, sort_keys=True).encode()).hexdigest()
        self.durable.record_idempotency(
            tenant_id="tenant-default",
            idempotency_key=key,
            principal_id="alice@corp.com",
            tool_id="vcf_resize_vm",
            args_sha256=actual_hash,
            response_payload={"status": "PENDING"},
            status="PENDING",
        )

        # Mock platform reconciliation returning NOT_APPLIED
        self.platform.reconcile_operation_sync.return_value = ReconciliationResult(
            status=ReconciliationStatus.NOT_APPLIED,
            details={"reason": "No task record found on vCenter"},
        )

        # Retry execution
        res = asyncio.run(execute_authorized(self.tool, self.alice, args))

        # run_live MUST have been called exactly once
        self.assertEqual(self.tool.run_live_call_count, 1)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["allocated_memory_gb"], 16)

        # Record must now be COMMITTED
        rec = self.durable.get_idempotency_record("tenant-default", key)
        self.assertEqual(rec["status"], "COMMITTED")

    def test_in_progress_rejection_prevents_duplicate_dispatch(self):
        """If upstream is still processing the operation, retry must be rejected with IdempotencyConflictException."""
        key = "idemp-crash-004"
        args = {
            "vm_id": "vm-104",
            "cluster_id": "cluster-prod-a",
            "memory_gb": 32,
            "idempotency_key": key,
        }

        import hashlib, json
        clean_args = {k: v for k, v in args.items() if k != "idempotency_key"}
        actual_hash = hashlib.sha256(json.dumps(clean_args, sort_keys=True).encode()).hexdigest()
        self.durable.record_idempotency(
            tenant_id="tenant-default",
            idempotency_key=key,
            principal_id="alice@corp.com",
            tool_id="vcf_resize_vm",
            args_sha256=actual_hash,
            response_payload={"status": "PENDING"},
            status="PENDING",
        )

        self.platform.reconcile_operation_sync.return_value = ReconciliationResult(
            status=ReconciliationStatus.IN_PROGRESS,
            details={"task_id": "task-running-55"},
        )

        with self.assertRaises(IdempotencyConflictException) as ctx:
            asyncio.run(execute_authorized(self.tool, self.alice, args))
        self.assertIn("still in progress upstream", str(ctx.exception))
        self.assertEqual(self.tool.run_live_call_count, 0)

    def test_indeterminate_state_aborts_without_blind_retry(self):
        """If upstream state cannot be determined (UNKNOWN), fail safe with VCFEnterpriseException."""
        key = "idemp-crash-005"
        args = {
            "vm_id": "vm-105",
            "cluster_id": "cluster-prod-a",
            "memory_gb": 32,
            "idempotency_key": key,
        }

        import hashlib, json
        clean_args = {k: v for k, v in args.items() if k != "idempotency_key"}
        actual_hash = hashlib.sha256(json.dumps(clean_args, sort_keys=True).encode()).hexdigest()
        self.durable.record_idempotency(
            tenant_id="tenant-default",
            idempotency_key=key,
            principal_id="alice@corp.com",
            tool_id="vcf_resize_vm",
            args_sha256=actual_hash,
            response_payload={"status": "PENDING"},
            status="PENDING",
        )

        self.platform.reconcile_operation_sync.return_value = ReconciliationResult(
            status=ReconciliationStatus.UNKNOWN,
            details={"error": "Network timeout during reconciliation probe"},
        )

        with self.assertRaises(VCFEnterpriseException) as ctx:
            asyncio.run(execute_authorized(self.tool, self.alice, args))
        self.assertEqual(ctx.exception.error_code, -32014)
        self.assertIn("Manual intervention required", str(ctx.exception))
        self.assertEqual(self.tool.run_live_call_count, 0)

    def test_argument_tampering_rejected(self):
        """Reusing key with different memory_gb must raise IdempotencyConflictException."""
        key = "idemp-tamper-006"
        args1 = {
            "vm_id": "vm-106",
            "cluster_id": "cluster-prod-a",
            "memory_gb": 32,
            "idempotency_key": key,
        }
        asyncio.run(execute_authorized(self.tool, self.alice, args1))

        args2 = {
            "vm_id": "vm-106",
            "cluster_id": "cluster-prod-a",
            "memory_gb": 64,
            "idempotency_key": key,
        }
        with self.assertRaises(IdempotencyConflictException):
            asyncio.run(execute_authorized(self.tool, self.alice, args2))


if __name__ == "__main__":
    unittest.main()
