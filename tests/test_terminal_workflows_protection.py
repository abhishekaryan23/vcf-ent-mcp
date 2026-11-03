# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Tests for terminal workflow and task state protection (P2-1).
Verifies that completed, failed, cancelled, or compensated workflows/tasks cannot be mutated or re-executed.
"""

import unittest
from vcf_enterprise_mcp.workflows.enterprise_workflow import (
    EnterpriseWorkflow,
    WorkflowStepDefinition,
    EnterpriseWorkflowEngine,
    WorkflowState,
)
from vcf_enterprise_mcp.workflows.task_store import TaskStore, MCPTask
from vcf_enterprise_mcp.core.errors import WorkflowExecutionException
from vcf_enterprise_mcp.auth.identity import Principal
from vcf_enterprise_mcp.state.sqlite_store import SQLiteDurableStore
from vcf_enterprise_mcp.adapter.platform import PlatformClient, PlatformMode


class TestTerminalWorkflowsProtection(unittest.TestCase):
    """Test suite ensuring terminal workflows and tasks are protected against re-execution/mutation."""

    def setUp(self):
        self.store = SQLiteDurableStore(":memory:")
        self.platform = PlatformClient(mode=PlatformMode.UNIT_TEST)
        self.engine = EnterpriseWorkflowEngine(
            durable_store=self.store,
            platform_client=self.platform,
        )
        self.task_store = TaskStore(durable_store=self.store)
        self.principal = Principal(
            user_id="operator-alice",
            tenant_id="tenant-prod",
            corporate_groups=["VCF-Platform-Admins"],
            roles=["Operator"],
            environment_ids=["env-prod"],
        )

    def _create_sample_workflow(self, workflow_id: str, state: WorkflowState) -> EnterpriseWorkflow:
        steps = [
            WorkflowStepDefinition(
                step_id="step-1",
                name="Power On VM",
                target_resource="vm-101",
                operation="vc.vms.power",
                desired_state={"state": "POWERED_ON"},
            ),
            WorkflowStepDefinition(
                step_id="step-2",
                name="Verify Telemetry",
                target_resource="vm-101",
                operation="telemetry.query",
                desired_state={"status": "healthy"},
            ),
        ]
        wf = EnterpriseWorkflow(
            workflow_id=workflow_id,
            name="Test Flow",
            initiator_id="operator-alice",
            steps=steps,
        )
        wf.state = state
        self.engine.register_workflow(wf)
        return wf

    def test_workflow_is_terminal_property(self):
        """Verifies EnterpriseWorkflow.is_terminal accurately detects terminal states."""
        wf = self._create_sample_workflow("wf-term-prop", WorkflowState.PLANNED)
        self.assertFalse(wf.is_terminal)

        wf.state = WorkflowState.EXECUTING
        self.assertFalse(wf.is_terminal)

        for terminal_state in [
            WorkflowState.SUCCEEDED,
            WorkflowState.FAILED,
            WorkflowState.CANCELLED,
            WorkflowState.COMPENSATED,
        ]:
            wf.state = terminal_state
            self.assertTrue(wf.is_terminal)

    def test_execute_step_rejects_succeeded_workflow(self):
        """Verifies execute_step raises WorkflowExecutionException for SUCCEEDED workflow."""
        wf = self._create_sample_workflow("wf-succeeded", WorkflowState.SUCCEEDED)

        with self.assertRaises(WorkflowExecutionException) as ctx:
            self.engine.execute_step(
                workflow_id=wf.workflow_id,
                step_idx=0,
                action_fn=lambda state, token: None,
            )
        self.assertIn("terminal state 'SUCCEEDED'", str(ctx.exception))

    def test_execute_step_rejects_failed_workflow(self):
        """Verifies execute_step raises WorkflowExecutionException for FAILED workflow."""
        wf = self._create_sample_workflow("wf-failed", WorkflowState.FAILED)

        with self.assertRaises(WorkflowExecutionException) as ctx:
            self.engine.execute_step(
                workflow_id=wf.workflow_id,
                step_idx=0,
                action_fn=lambda state, token: None,
            )
        self.assertIn("terminal state 'FAILED'", str(ctx.exception))

    def test_execute_step_rejects_cancelled_workflow(self):
        """Verifies execute_step raises WorkflowExecutionException for CANCELLED workflow."""
        wf = self._create_sample_workflow("wf-cancelled", WorkflowState.CANCELLED)

        with self.assertRaises(WorkflowExecutionException) as ctx:
            self.engine.execute_step(
                workflow_id=wf.workflow_id,
                step_idx=0,
                action_fn=lambda state, token: None,
            )
        self.assertIn("terminal state 'CANCELLED'", str(ctx.exception))

    def test_execute_step_rejects_compensated_workflow(self):
        """Verifies execute_step raises WorkflowExecutionException for COMPENSATED workflow."""
        wf = self._create_sample_workflow("wf-compensated", WorkflowState.COMPENSATED)

        with self.assertRaises(WorkflowExecutionException) as ctx:
            self.engine.execute_step(
                workflow_id=wf.workflow_id,
                step_idx=0,
                action_fn=lambda state, token: None,
            )
        self.assertIn("terminal state 'COMPENSATED'", str(ctx.exception))

    def test_task_is_terminal_property(self):
        """Verifies MCPTask.is_terminal accurately identifies terminal task statuses."""
        task = self.task_store.create_task("vcf_power_vm", self.principal)
        self.assertFalse(task.is_terminal)

        for status in ["COMPLETED", "SUCCEEDED", "FAILED", "CANCELLED", "COMPENSATED"]:
            task.status = status
            self.assertTrue(task.is_terminal)

    def test_update_task_progress_rejects_terminal_tasks(self):
        """Verifies update_task_progress raises WorkflowExecutionException for completed/failed/cancelled tasks."""
        task = self.task_store.create_task("vcf_power_vm", self.principal)
        self.task_store.complete_task(task.task_id, {"status": "done"}, principal=self.principal)

        # Attempt to update completed task
        with self.assertRaises(WorkflowExecutionException) as ctx:
            self.task_store.update_task_progress(
                task_id=task.task_id,
                current_step=1,
                step_desc="New step",
                principal=self.principal,
            )
        self.assertIn("terminal state 'COMPLETED'", str(ctx.exception))

    def test_complete_and_fail_task_reject_already_terminal(self):
        """Verifies complete_task and fail_task reject tasks that are already terminal."""
        task = self.task_store.create_task("vcf_power_vm", self.principal)
        self.task_store.fail_task(task.task_id, "Initial failure", principal=self.principal)

        # Attempt to complete an already failed task
        with self.assertRaises(WorkflowExecutionException) as ctx:
            self.task_store.complete_task(task.task_id, {"ok": True}, principal=self.principal)
        self.assertIn("terminal state 'FAILED'", str(ctx.exception))

        # Attempt to fail an already failed task
        with self.assertRaises(WorkflowExecutionException) as ctx:
            self.task_store.fail_task(task.task_id, "Second failure", principal=self.principal)
        self.assertIn("terminal state 'FAILED'", str(ctx.exception))

    def test_cancel_task_on_terminal_task(self):
        """Verifies cancel_task safely returns not cancelled when task is already in terminal state."""
        task = self.task_store.create_task("vcf_power_vm", self.principal)
        self.task_store.complete_task(task.task_id, {"status": "done"}, principal=self.principal)

        res = self.task_store.cancel_task(task.task_id, principal=self.principal)
        self.assertFalse(res["cancelled"])
        self.assertIn("already COMPLETED", res["reason"])


if __name__ == "__main__":
    unittest.main()
