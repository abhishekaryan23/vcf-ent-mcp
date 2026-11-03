# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Test Suite: TOCTOU Prevention, Execution Plans, and Single-Use Approvals.
Validates:
- Dry-run generating immutable execution plans without executable approvals
- Four-Eyes Principle (initiator cannot approve own plan)
- Nonce single-use replay protection
- Argument tampering detection
- TOCTOU detection: Aborting with PlanStaleException when resource revision changes prior to execution
"""

import unittest
from vcf_enterprise_mcp.auth.identity import Principal
from vcf_enterprise_mcp.state.durable_store import DurableStore
from vcf_enterprise_mcp.adapter.platform import PlatformClient
from vcf_enterprise_mcp.workflows.execution_plans import ExecutionPlanManager
from vcf_enterprise_mcp.core.errors import (
    PlanStaleException,
    AuthorizationDeniedException,
    VCFEnterpriseException,
)


class TestTOCTOUApprovalsAndPlans(unittest.TestCase):

    def setUp(self):
        self.durable = DurableStore(":memory:")
        self.platform = PlatformClient()
        self.plan_mgr = ExecutionPlanManager(
            durable_store=self.durable,
            platform_client=self.platform,
            tenant_id="tenant-prod",
            environment_id="env-vcf-01",
        )
        self.alice = Principal(
            user_id="alice@corp.com",
            corporate_groups=["VCF-Compute-Operators"],
            allowed_clusters=["cluster-prod-a"],
        )
        self.bob_admin = Principal(
            user_id="bob-admin@corp.com",
            corporate_groups=["VCF-Platform-Admins"],
            allowed_clusters=["*"],
        )

    def test_dry_run_creates_plan_without_executable_token(self):
        plan = self.plan_mgr.create_dry_run_plan(
            principal=self.alice,
            tool_id="vcf_upgrade_domain",
            arguments={"domain_id": "mgmt-domain", "target_version": "9.1.1"},
            impact_summary={"clusters": 2, "hosts": 8},
            target_resource_ids=["mgmt-domain", "cluster-prod-a"],
        )
        self.assertTrue(plan["dry_run"])
        self.assertEqual(plan["status"], "PENDING_APPROVAL")
        self.assertTrue(plan["plan_id"].startswith("plan_"))
        self.assertIn("mgmt-domain", plan["resource_revisions"])
        # Plan is NOT executable directly
        self.assertTrue(plan["requires_approval"])

    def test_four_eyes_separation_of_duties_enforced(self):
        plan = self.plan_mgr.create_dry_run_plan(
            principal=self.alice,
            tool_id="vcf_upgrade_domain",
            arguments={"domain_id": "mgmt-domain"},
            impact_summary={"hosts": 4},
            target_resource_ids=["mgmt-domain"],
        )

        # Alice attempts to approve her own plan -> Denied!
        with self.assertRaises(AuthorizationDeniedException) as ctx:
            self.plan_mgr.approve_plan(plan["plan_id"], approver=self.alice)
        self.assertIn("cannot approve their own plan", str(ctx.exception))

        # Authorized administrator Bob can approve
        auth = self.plan_mgr.approve_plan(plan["plan_id"], approver=self.bob_admin)
        self.assertEqual(auth.approver, "bob-admin@corp.com")
        self.assertTrue(len(auth.nonce) >= 32)

    def test_single_use_nonce_and_replay_protection(self):
        plan = self.plan_mgr.create_dry_run_plan(
            principal=self.alice,
            tool_id="vcf_upgrade_domain",
            arguments={"domain_id": "mgmt-domain"},
            impact_summary={},
            target_resource_ids=["mgmt-domain"],
        )
        auth = self.plan_mgr.approve_plan(plan["plan_id"], approver=self.bob_admin)

        # First execution consumes nonce successfully
        val1 = self.plan_mgr.validate_plan_for_execution(
            plan_id=plan["plan_id"],
            approval_id=auth.approval_id,
            nonce=auth.nonce,
            current_arguments={"domain_id": "mgmt-domain"},
            caller=self.alice,
        )
        self.assertIsNotNone(val1)

        # Second execution with same nonce MUST fail (replay attack rejected)
        with self.assertRaises(AuthorizationDeniedException) as ctx:
            self.plan_mgr.validate_plan_for_execution(
                plan_id=plan["plan_id"],
                approval_id=auth.approval_id,
                nonce=auth.nonce,
                current_arguments={"domain_id": "mgmt-domain"},
                caller=self.alice,
            )
        self.assertIn("already been consumed (replay rejected)", str(ctx.exception))

    def test_argument_tampering_detection(self):
        plan = self.plan_mgr.create_dry_run_plan(
            principal=self.alice,
            tool_id="vcf_resize_vm",
            arguments={"vm_id": "vm-101", "memory_gb": 32},
            impact_summary={},
            target_resource_ids=["vm-101"],
        )
        auth = self.plan_mgr.approve_plan(plan["plan_id"], approver=self.bob_admin)

        # Caller modifies arguments (requests 64GB instead of approved 32GB)
        tampered_args = {"vm_id": "vm-101", "memory_gb": 64}
        with self.assertRaises(AuthorizationDeniedException) as ctx:
            self.plan_mgr.validate_plan_for_execution(
                plan_id=plan["plan_id"],
                approval_id=auth.approval_id,
                nonce=auth.nonce,
                current_arguments=tampered_args,
                caller=self.alice,
            )
        self.assertIn("Tampering detected", str(ctx.exception))

    def test_toctou_revision_change_aborts_with_plan_stale(self):
        # 1. Alice creates dry-run plan on cluster-prod-a
        initial_rev = self.platform.get_resource_revision("cluster-prod-a")
        plan = self.plan_mgr.create_dry_run_plan(
            principal=self.alice,
            tool_id="vcf_upgrade_domain",
            arguments={"domain_id": "mgmt-domain"},
            impact_summary={},
            target_resource_ids=["cluster-prod-a"],
        )
        self.assertEqual(plan["resource_revisions"]["cluster-prod-a"], initial_rev)

        auth = self.plan_mgr.approve_plan(plan["plan_id"], approver=self.bob_admin)

        # 2. TOCTOU Event: Another system modifies cluster-prod-a (revision bumps)
        self.platform.update_resource_revision("cluster-prod-a", "rev-999-new-state")

        # 3. Execution attempt detects TOCTOU violation and aborts with PlanStaleException
        with self.assertRaises(PlanStaleException) as ctx:
            self.plan_mgr.validate_plan_for_execution(
                plan_id=plan["plan_id"],
                approval_id=auth.approval_id,
                nonce=auth.nonce,
                current_arguments={"domain_id": "mgmt-domain"},
                caller=self.alice,
            )
        self.assertIn("TOCTOU violation", str(ctx.exception))
        self.assertIn("revision changed from 'rev-100' to 'rev-999-new-state'", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
