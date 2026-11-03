# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Test Suite: Strict Multi-Tenant Isolation (SEC-02).
Verifies:
1. Cross-tenant task inspection denial.
2. Cross-tenant task cancellation denial.
3. Cross-tenant task progress update denial.
4. Cross-tenant execution plan access denial.
5. Cross-tenant plan approval denial.
6. Cross-tenant approval nonce consumption denial.
7. Durable SQL store query isolation (same ID across tenants isolated).
8. Multi-tenant resource leasing isolation (same resource ID in different tenants).
9. Tamper-evident audit chain isolation between tenants.
"""

import unittest
from vcf_enterprise_mcp.auth.identity import Principal
from vcf_enterprise_mcp.state.durable_store import SQLiteDurableStore, PostgresDurableStore
from vcf_enterprise_mcp.workflows.task_store import TaskStore, WorkflowStep
from vcf_enterprise_mcp.workflows.execution_plans import ExecutionPlanManager
from vcf_enterprise_mcp.state.leases import ResourceLeaseManager
from vcf_enterprise_mcp.adapter.platform import PlatformClient
from vcf_enterprise_mcp.policy.models import RiskClass, ApprovalPolicy
from vcf_enterprise_mcp.core.errors import (
    AuthorizationDeniedException,
    TaskNotFoundException,
    VCFEnterpriseException,
)


class TestTenantIsolationSEC02(unittest.TestCase):
    """Validates absolute boundary isolation between tenants across storage, tasks, plans, and leases."""

    def setUp(self):
        self.durable = SQLiteDurableStore(":memory:")
        self.platform = PlatformClient()
        self.task_store = TaskStore(durable_store=self.durable)

        # Tenant A Principals
        self.user_a = Principal(
            user_id="user@tenant-a.corp",
            tenant_id="tenant-alpha",
            corporate_groups=["VCF-Compute-Operators"],
            allowed_clusters=["cluster-prod-a"],
        )
        self.admin_a = Principal(
            user_id="admin@tenant-a.corp",
            tenant_id="tenant-alpha",
            corporate_groups=["VCF-Platform-Admins"],
            allowed_clusters=["*"],
        )

        # Tenant B Principals
        self.user_b = Principal(
            user_id="user@tenant-b.corp",
            tenant_id="tenant-beta",
            corporate_groups=["VCF-Compute-Operators"],
            allowed_clusters=["cluster-prod-b"],
        )
        self.admin_b = Principal(
            user_id="admin@tenant-b.corp",
            tenant_id="tenant-beta",
            corporate_groups=["VCF-Platform-Admins"],
            allowed_clusters=["*"],
        )

        self.plan_mgr_a = ExecutionPlanManager(
            durable_store=self.durable,
            platform_client=self.platform,
            tenant_id="tenant-alpha",
            environment_id="env-prod",
        )
        self.plan_mgr_b = ExecutionPlanManager(
            durable_store=self.durable,
            platform_client=self.platform,
            tenant_id="tenant-beta",
            environment_id="env-prod",
        )

    def test_cross_tenant_task_access_denial(self):
        """Tenant B user cannot inspect or retrieve a task created by Tenant A."""
        task_a = self.task_store.create_task(
            tool_name="vcf_power_vm",
            principal=self.user_a,
            steps=[WorkflowStep("Power on", is_reversible=True)],
        )

        # Tenant A user can read own task
        retrieved_a = self.task_store.get_task(task_a.task_id, self.user_a)
        self.assertEqual(retrieved_a.task_id, task_a.task_id)

        # Tenant B user is denied access to Tenant A task
        with self.assertRaises((AuthorizationDeniedException, TaskNotFoundException)):
            self.task_store.get_task(task_a.task_id, self.user_b)

        # Tenant B administrator is ALSO denied access across tenant boundary
        with self.assertRaises((AuthorizationDeniedException, TaskNotFoundException)):
            self.task_store.get_task(task_a.task_id, self.admin_b)

    def test_cross_tenant_task_cancellation_denial(self):
        """Tenant B administrator cannot cancel Tenant A's in-flight task."""
        task_a = self.task_store.create_task(
            tool_name="vcf_upgrade_domain",
            principal=self.user_a,
            steps=[WorkflowStep("Hypervisor upgrade", is_reversible=False)],
        )

        # Tenant B admin attempts cancellation -> Denied
        with self.assertRaises((AuthorizationDeniedException, TaskNotFoundException)):
            self.task_store.cancel_task(task_a.task_id, self.admin_b)

        # Task in Tenant A remains active
        task_check = self.task_store.get_task(task_a.task_id, self.user_a)
        self.assertEqual(task_check.status, "PENDING")

    def test_cross_tenant_task_progress_update_denial(self):
        """Tenant B caller cannot update or tamper with Tenant A task progress."""
        task_a = self.task_store.create_task(
            tool_name="vcf_power_vm",
            principal=self.user_a,
            steps=[WorkflowStep("Step 1", is_reversible=True), WorkflowStep("Step 2", is_reversible=True)],
        )

        with self.assertRaises((AuthorizationDeniedException, TaskNotFoundException)):
            self.task_store.update_task_progress(
                task_id=task_a.task_id,
                current_step=2,
                step_desc="Tampered step",
                principal=self.user_b,
            )

    def test_cross_tenant_plan_access_and_approval_denial(self):
        """Execution plan created in Tenant A cannot be viewed or approved by Tenant B."""
        plan_a = self.plan_mgr_a.create_dry_run_plan(
            principal=self.user_a,
            tool_id="vcf_upgrade_domain",
            arguments={"domain_id": "mgmt-domain-alpha"},
            impact_summary={"clusters": 2},
            target_resource_ids=["mgmt-domain-alpha"],
        )
        plan_id = plan_a["plan_id"]

        # Tenant B admin attempts to approve Tenant A plan -> Denied
        with self.assertRaises(VCFEnterpriseException) as ctx:
            self.plan_mgr_b.approve_plan(plan_id, approver=self.admin_b)
        self.assertIn("not found in tenant", str(ctx.exception).lower())

        # Legitimate Tenant A admin approves plan
        auth_a = self.plan_mgr_a.approve_plan(plan_id, approver=self.admin_a)
        self.assertEqual(auth_a.tenant_id, "tenant-alpha")

        # Tenant B user attempts to execute using Tenant A's plan and authorization
        with self.assertRaises((AuthorizationDeniedException, VCFEnterpriseException)):
            self.plan_mgr_b.validate_plan_for_execution(
                plan_id=plan_id,
                approval_id=auth_a.approval_id,
                nonce=auth_a.nonce,
                current_arguments={"domain_id": "mgmt-domain-alpha"},
                caller=self.user_b,
            )

    def test_cross_tenant_nonce_consumption_denial(self):
        """Single-use nonce issued in Tenant A cannot be consumed in Tenant B."""
        plan_a = self.plan_mgr_a.create_dry_run_plan(
            principal=self.user_a,
            tool_id="vcf_upgrade_domain",
            arguments={"domain_id": "mgmt-domain-alpha"},
            impact_summary={},
            target_resource_ids=["mgmt-domain-alpha"],
        )
        auth_a = self.plan_mgr_a.approve_plan(plan_a["plan_id"], approver=self.admin_a)

        # Attempt to consume approval under Tenant B coordinates -> Fails
        consumed, msg = self.durable.consume_approval(
            "tenant-beta", "env-prod", auth_a.approval_id, auth_a.nonce
        )
        self.assertFalse(consumed)
        self.assertIn("not found in tenant", msg)

        # Nonce remains unconsumed in Tenant A
        consumed_a, msg_a = self.durable.consume_approval(
            "tenant-alpha", "env-prod", auth_a.approval_id, auth_a.nonce
        )
        self.assertTrue(consumed_a)

    def test_same_entity_id_isolated_across_tenants(self):
        """Same entity IDs (tasks, plans) coexisting in different tenants do not collide or leak."""
        shared_task_id = "task-fixed-id-100"
        self.durable.save_task(shared_task_id, "tenant-alpha", "env-prod", "user-a", "tool-a", "RUNNING", 10.0)
        self.durable.save_task(shared_task_id, "tenant-beta", "env-prod", "user-b", "tool-b", "COMPLETED", 100.0)

        task_a = self.durable.get_task("tenant-alpha", "env-prod", shared_task_id)
        task_b = self.durable.get_task("tenant-beta", "env-prod", shared_task_id)

        self.assertIsNotNone(task_a)
        self.assertIsNotNone(task_b)
        self.assertEqual(task_a["tool_name"], "tool-a")
        self.assertEqual(task_a["progress"], 10.0)
        self.assertEqual(task_b["tool_name"], "tool-b")
        self.assertEqual(task_b["progress"], 100.0)

    def test_multi_tenant_resource_leases_isolated(self):
        """Resource lease in Tenant A does not block identical resource ID in Tenant B."""
        lease_mgr_a = ResourceLeaseManager(self.durable, tenant_id="tenant-alpha")
        lease_mgr_b = ResourceLeaseManager(self.durable, tenant_id="tenant-beta")

        res_id = "vm-shared-id-99"

        # Tenant A acquires lease on vm-shared-id-99
        lease_a = lease_mgr_a.acquire_exclusive(res_id, lease_holder="worker-a", ttl_seconds=30.0)
        self.assertEqual(lease_a.tenant_id, "tenant-alpha")

        # Tenant B can ALSO acquire lease on its own vm-shared-id-99 concurrently!
        lease_b = lease_mgr_b.acquire_exclusive(res_id, lease_holder="worker-b", ttl_seconds=30.0)
        self.assertEqual(lease_b.tenant_id, "tenant-beta")

        # Tenant A cannot re-acquire same resource without conflict
        with self.assertRaises(Exception):
            lease_mgr_a.acquire_exclusive(res_id, lease_holder="worker-a2", ttl_seconds=30.0)

        # Release Tenant A lease
        lease_mgr_a.release(res_id, lease_holder="worker-a")
        # Tenant B lease remains intact
        active_b = lease_mgr_b.get_active_lease(res_id)
        self.assertIsNotNone(active_b)
        self.assertEqual(active_b.owner, "worker-b")

    def test_multi_tenant_audit_chain_isolation(self):
        """Audit events recorded in Tenant A are not visible or chained into Tenant B."""
        h_a1 = self.durable.record_audit_event_chained("tenant-alpha", "env-prod", "ev-a1", {"action": "write-a"})
        h_a2 = self.durable.record_audit_event_chained("tenant-alpha", "env-prod", "ev-a2", {"action": "write-a2"})

        h_b1 = self.durable.record_audit_event_chained("tenant-beta", "env-prod", "ev-b1", {"action": "write-b"})

        # Tenant A chain integrity passes
        ok_a, _ = self.durable.verify_audit_integrity("tenant-alpha", "env-prod")
        self.assertTrue(ok_a)

        # Tenant B chain integrity passes
        ok_b, _ = self.durable.verify_audit_integrity("tenant-beta", "env-prod")
        self.assertTrue(ok_b)

        # Latest hash in Tenant A is h_a2, in Tenant B is h_b1
        self.assertEqual(self.durable.get_latest_audit_hash("tenant-alpha", "env-prod"), h_a2)
        self.assertEqual(self.durable.get_latest_audit_hash("tenant-beta", "env-prod"), h_b1)


if __name__ == "__main__":
    unittest.main()
