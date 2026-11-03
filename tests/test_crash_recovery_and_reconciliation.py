# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Test Suite: Crash Recovery, Typed Resource Revisions, and Upstream Reconciliation (Item 6, P0-6).
Validates:
1. ResourceRevision is a typed frozen dataclass with provider and value attributes.
2. No integer/string comparison bugs (eliminating `rev > 0`).
3. Outbox execution intent reconciliation correctly maps to APPLIED, NOT_APPLIED, IN_PROGRESS, UNKNOWN.
4. UNKNOWN state strictly halts automated retries and transitions to MANUAL_INTERVENTION_REQUIRED.
5. Provider reconciliation probes accurately inspect actual infrastructure state.
"""

import json
import unittest
import pytest
from vcf_enterprise_mcp.adapter.models import (
    ResourceRevision,
    ReconciliationStatus,
    ReconciliationResult,
    ExecutionIntent,
)
from vcf_enterprise_mcp.adapter.platform import PlatformClient
from vcf_enterprise_mcp.state.sqlite_store import SQLiteDurableStore
from vcf_enterprise_mcp.workflows.enterprise_workflow import (
    EnterpriseWorkflowEngine,
    EnterpriseWorkflow,
    WorkflowStepDefinition,
    WorkflowState,
)
from vcf_enterprise_mcp.core.errors import ReconciliationRequiredException


class TestCrashRecoveryAndReconciliation(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.durable = SQLiteDurableStore(":memory:")
        self.platform = PlatformClient()
        self.engine = EnterpriseWorkflowEngine(self.durable, self.platform)

    def test_typed_resource_revision_semantics(self):
        """ResourceRevision enforces strict typing, provider tagging, and safe comparisons."""
        rev1 = ResourceRevision(provider="vcenter", value="rev-100")
        rev2 = ResourceRevision(provider="vcenter", value="rev-100")
        rev3 = ResourceRevision(provider="vcenter", value="rev-101")
        rev_nsx = ResourceRevision(provider="nsx", value="rev-100")

        # Immutability
        with self.assertRaises(Exception):
            rev1.value = "rev-999"  # Frozen dataclass must not allow mutation

        # Equality
        self.assertEqual(rev1, rev2)
        self.assertNotEqual(rev1, rev3)
        self.assertNotEqual(rev1, rev_nsx)  # Different provider!

        # String representation
        self.assertEqual(str(rev1), "rev-100")
        self.assertEqual(rev1, "rev-100")  # Safe comparison with string

        # Ordering / newer check
        self.assertTrue(rev3.is_newer_than(rev1))
        self.assertFalse(rev1.is_newer_than(rev3))

    def test_platform_client_returns_typed_revision(self):
        """PlatformClient.get_resource_revision returns a typed ResourceRevision."""
        rev_vm = self.platform.get_resource_revision("vm-101")
        self.assertIsInstance(rev_vm, ResourceRevision)
        self.assertEqual(rev_vm.provider, "vcenter")
        self.assertEqual(rev_vm.value, "rev-201")

        rev_domain = self.platform.get_resource_revision("mgmt-domain")
        self.assertIsInstance(rev_domain, ResourceRevision)
        self.assertEqual(rev_domain.provider, "sddc-manager")

        rev_bumped = self.platform.update_resource_revision("vm-101", "rev-205")
        self.assertIsInstance(rev_bumped, ResourceRevision)
        self.assertEqual(rev_bumped.value, "rev-205")

    def test_reconciliation_applied_outcome_resolves_intent(self):
        """When upstream reconciliation proves APPLIED, intent resolves to SUCCESS without re-executing."""
        # Record pending intent in durable store
        intent_id = "intent-test-applied-01"
        self.durable.record_execution_intent(
            intent_id=intent_id,
            workflow_id="wf-01",
            step_id="step-01",
            target_resource="vm-101",
            operation_id="resize_vm",
            desired_state={"memory_gb": 64, "reconciliation_status": "APPLIED"},
            fencing_token=10,
        )

        reports = self.engine.reconcile_in_flight_workflows()
        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0]["status"], "APPLIED")
        self.assertEqual(reports[0]["reconciliation_outcome"], "RECONCILED_SUCCESS")

        # Intent must now be resolved in durable store
        stored_intent = self.durable.get_execution_intent(intent_id=intent_id)
        self.assertEqual(stored_intent["state"], "RESOLVED")
        self.assertEqual(stored_intent["outcome"], "AUTO_RECONCILED_APPLIED")

    def test_reconciliation_not_applied_outcome_marks_failed(self):
        """When upstream reconciliation proves NOT_APPLIED, intent is marked FAILED."""
        intent_id = "intent-test-not-applied-01"
        self.durable.record_execution_intent(
            intent_id=intent_id,
            workflow_id="wf-02",
            step_id="step-01",
            target_resource="vm-101",
            operation_id="resize_vm",
            desired_state={"memory_gb": 64, "reconciliation_status": "NOT_APPLIED"},
            fencing_token=11,
        )

        reports = self.engine.reconcile_in_flight_workflows()
        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0]["status"], "NOT_APPLIED")
        self.assertEqual(reports[0]["reconciliation_outcome"], "RECONCILED_NOT_APPLIED")

        stored_intent = self.durable.get_execution_intent(intent_id=intent_id)
        self.assertEqual(stored_intent["state"], "FAILED")
        self.assertEqual(stored_intent["outcome"], "AUTO_RECONCILED_NOT_APPLIED")

    def test_reconciliation_in_progress_outcome_keeps_pending(self):
        """When upstream reconciliation indicates IN_PROGRESS, intent remains pending."""
        intent_id = "intent-test-in-progress-01"
        self.durable.record_execution_intent(
            intent_id=intent_id,
            workflow_id="wf-03",
            step_id="step-01",
            target_resource="mgmt-domain",
            operation_id="upgrade_domain",
            desired_state={"target_version": "9.1.1", "reconciliation_status": "IN_PROGRESS"},
            fencing_token=12,
        )

        reports = self.engine.reconcile_in_flight_workflows()
        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0]["status"], "IN_PROGRESS")
        self.assertEqual(reports[0]["reconciliation_outcome"], "IN_PROGRESS")

        # Intent must still be pending in durable store
        stored_intent = self.durable.get_execution_intent(intent_id=intent_id)
        self.assertEqual(stored_intent["state"], "EXECUTION_INTENT_RECORDED")

    def test_reconciliation_unknown_outcome_transitions_to_manual_intervention(self):
        """When remote state is UNKNOWN, system NEVER retries and flags MANUAL_INTERVENTION_REQUIRED."""
        intent_id = "intent-test-unknown-01"
        self.durable.record_execution_intent(
            intent_id=intent_id,
            workflow_id="wf-04",
            step_id="step-01",
            target_resource="mgmt-domain",
            operation_id="upgrade_domain",
            desired_state={"target_version": "9.1.1", "reconciliation_status": "UNKNOWN"},
            fencing_token=13,
        )

        reports = self.engine.reconcile_in_flight_workflows()
        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0]["status"], "UNKNOWN")
        self.assertEqual(reports[0]["reconciliation_outcome"], "MANUAL_INTERVENTION_REQUIRED")

        stored_intent = self.durable.get_execution_intent(intent_id=intent_id)
        self.assertEqual(stored_intent["state"], "MANUAL_INTERVENTION_REQUIRED")
        self.assertEqual(stored_intent["outcome"], "AUTO_RECONCILED_INDETERMINATE")

    async def test_vcenter_provider_reconcile_probe(self):
        """VCenterProvider.reconcile_operation probes VM attributes to verify mutation."""
        from vcf_enterprise_mcp.adapter.providers.vcenter import VCenterProvider
        from vcf_enterprise_mcp.adapter.transport.base import BaseTransport, TransportResponse

        class MockVCenterTransport(BaseTransport):
            def send(self, request):
                if "/hardware" in request.url:
                    return TransportResponse(status_code=200, body=b"{}")
                if "/api/vcenter/vm/vm-101" in request.url:
                    # Return VM with 64GB (65536 MiB)
                    vm_data = json.dumps({"value": {"memory_size_MiB": 65536, "power_state": "POWERED_ON"}}).encode("utf-8")
                    return TransportResponse(
                        status_code=200,
                        body=vm_data,
                    )
                return TransportResponse(status_code=404, body=b"{}")

            async def send_async(self, request):
                return self.send(request)

        vc = VCenterProvider(endpoint_url="https://vc.corp.local", transport=MockVCenterTransport())

        # Test intent matching actual state -> APPLIED
        intent_match = ExecutionIntent(
            intent_id="intent-vc-1",
            workflow_id="wf-1",
            step_id="s1",
            target_resource="vm-101",
            operation_id="resize_vm",
            desired_state={"memory_gb": 64},
        )
        res_match = await vc.reconcile_operation(intent_match)
        self.assertEqual(res_match.status, ReconciliationStatus.APPLIED)

        # Test intent not matching actual state -> NOT_APPLIED
        intent_mismatch = ExecutionIntent(
            intent_id="intent-vc-2",
            workflow_id="wf-1",
            step_id="s1",
            target_resource="vm-101",
            operation_id="resize_vm",
            desired_state={"memory_gb": 128},
        )
        res_mismatch = await vc.reconcile_operation(intent_mismatch)
        self.assertEqual(res_mismatch.status, ReconciliationStatus.NOT_APPLIED)
