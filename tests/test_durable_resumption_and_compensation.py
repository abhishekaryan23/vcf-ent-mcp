# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Test Suite: Durable Workflow Resumption and Compensation Boundaries.
Validates:
- L3 workflow recovery after simulated control plane crash/reboot
- Step-by-step compensation boundaries (reversible vs irreversible actions)
- Refusal of automated rollback once an irreversible step (firmware flash) is executed
"""

import unittest
import os
import tempfile
from vcf_enterprise_mcp.auth.identity import Principal
from vcf_enterprise_mcp.state.durable_store import DurableStore
from vcf_enterprise_mcp.workflows.task_store import TaskStore, WorkflowStep
from vcf_enterprise_mcp.workflows.engine import VCFWorkflowEngine, DOMAIN_UPGRADE_STEPS
from vcf_enterprise_mcp.adapter.platform import PlatformClient


class TestDurableResumptionAndCompensation(unittest.TestCase):

    def setUp(self):
        # Create persistent file-backed SQLite database to survive simulated crashes
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp_dir.name, "vcf_durable_test.db")
        self.durable = DurableStore(self.db_path)
        self.task_store = TaskStore(durable_store=self.durable)
        self.platform = PlatformClient()
        self.engine = VCFWorkflowEngine(task_store=self.task_store, platform_client=self.platform)
        self.admin = Principal(
            user_id="admin@corp.com",
            corporate_groups=["VCF-Platform-Admins"],
            allowed_clusters=["*"],
        )

    def tearDown(self):
        if hasattr(self, "durable") and self.durable:
            try:
                self.durable.close()
            except Exception:
                pass
        self.tmp_dir.cleanup()

    def test_workflow_resumption_after_simulated_process_crash(self):
        # 1. Start domain upgrade workflow with plan and approval
        dry_res = self.engine.plan_domain_upgrade(
            domain_id="mgmt-domain",
            target_version="9.1.1",
            principal=self.admin,
            dry_run=True,
        )
        sec_admin = Principal(
            user_id="sec-admin@corp.com",
            corporate_groups=["VCF-Platform-Admins"],
            allowed_clusters=["*"],
        )
        auth = self.engine.plan_manager.approve_plan(dry_res["plan_id"], approver=sec_admin)
        res = self.engine.plan_domain_upgrade(
            domain_id="mgmt-domain",
            target_version="9.1.1",
            principal=self.admin,
            dry_run=False,
            plan_id=dry_res["plan_id"],
            approval_id=auth.approval_id,
            nonce=auth.nonce,
            arguments={"domain_id": "mgmt-domain", "target_version": "9.1.1"},
        )
        task_id = res["task_id"]
        self.assertEqual(res["status"], "RUNNING")

        # 2. Simulate process crash / pod termination by closing connections and dereferencing engine
        self.durable.close()
        del self.engine
        del self.task_store
        del self.durable

        # 3. Simulate new container pod booting up and attaching to the same persistent SQLite database
        recovered_durable = DurableStore(self.db_path)
        recovered_store = TaskStore(durable_store=recovered_durable)
        recovered_engine = VCFWorkflowEngine(task_store=recovered_store, platform_client=self.platform)

        # 4. Recover in-flight workflows
        resumed_tasks = recovered_engine.resume_in_flight_workflows()
        self.assertTrue(len(resumed_tasks) >= 1)
        matched = next((t for t in resumed_tasks if t["task_id"] == task_id), None)
        self.assertIsNotNone(matched)

        # Check recovered task via tasks/get
        task_after_recovery = recovered_store.get_task(task_id, self.admin)
        self.assertIn(task_after_recovery.status, ["RUNNING", "COMPLETED"])
        recovered_durable.close()

    def test_compensation_boundary_cancellation_rules(self):
        task = self.task_store.create_task(
            tool_name="vcf_upgrade_domain",
            principal=self.admin,
            steps=DOMAIN_UPGRADE_STEPS,
        )

        # Step 1: Precheck is reversible -> cancellation succeeds
        self.task_store.update_task_progress(task.task_id, 1, DOMAIN_UPGRADE_STEPS[0].name)
        can_res1 = self.task_store.cancel_task(task.task_id, self.admin)
        self.assertTrue(can_res1["cancelled"])
        self.assertTrue(can_res1["isReversible"])

        # Reset task to running past Step 5 (Server hardware firmware flash - irreversible!)
        task.status = "RUNNING"
        self.task_store.update_task_progress(task.task_id, 5, DOMAIN_UPGRADE_STEPS[4].name)

        # Cancellation MUST fail and refuse to advertise automated rollback
        can_res2 = self.task_store.cancel_task(task.task_id, self.admin)
        self.assertFalse(can_res2["cancelled"])
        self.assertIn("irreversible compensation boundary", can_res2["reason"])
        self.assertFalse(can_res2["isReversible"])


if __name__ == "__main__":
    unittest.main()
