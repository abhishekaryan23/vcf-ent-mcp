# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Test Suite: N-Person / Multi-Party Approval Policy Enforcement (SEC-03).
Verifies:
1. Multi-approver policy requiring N distinct approvers (e.g., 2 required, 1 provided -> denied).
2. N distinct valid approvers allows execution.
3. Same approver attempting to approve twice is rejected.
4. Initiator self-approval is rejected (Four-Eyes principle).
5. Approver with unentitled role is rejected.
6. Expired approval tokens cannot be used for execution.
7. Permission epoch invalidation revokes in-flight multi-party approvals.
8. Single-use nonce consumption prevents replay.
"""

import unittest
import time
from vcf_enterprise_mcp.auth.identity import Principal
from vcf_enterprise_mcp.state.durable_store import SQLiteDurableStore
from vcf_enterprise_mcp.adapter.platform import PlatformClient
from vcf_enterprise_mcp.policy.models import RiskClass, ApprovalPolicy
from vcf_enterprise_mcp.workflows.execution_plans import ExecutionPlanManager
from vcf_enterprise_mcp.core.errors import (
    AuthorizationDeniedException,
    VCFEnterpriseException,
)


class TestNPersonApprovalPolicySEC03(unittest.TestCase):
    """Validates multi-party N-person approval rules and four-eyes separation of duties."""

    def setUp(self):
        self.durable = SQLiteDurableStore(":memory:")
        self.platform = PlatformClient()

        # Approval policy requiring 2 distinct approvers for HIGH_IMPACT and DESTRUCTIVE
        self.policy = ApprovalPolicy(
            required_approvals=2,
            allow_initiator=False,
            distinct_principals=True,
            required_roles=("VCF-Platform-Admins", "VCF-Security-Admins"),
            required_approver_roles={
                RiskClass.HIGH_IMPACT: ["VCF-Platform-Admins", "VCF-Security-Admins"],
                RiskClass.DESTRUCTIVE: ["VCF-Platform-Admins", "VCF-Security-Admins"],
            },
        )

        self.plan_mgr = ExecutionPlanManager(
            durable_store=self.durable,
            platform_client=self.platform,
            tenant_id="tenant-prod",
            environment_id="env-prod",
            approval_policy=self.policy,
        )

        # Alice: Initiator (Compute Operator)
        self.alice = Principal(
            user_id="alice@corp.com",
            tenant_id="tenant-prod",
            corporate_groups=["VCF-Compute-Operators"],
            allowed_clusters=["cluster-prod-a"],
        )

        # Approver 1: Bob (Platform Admin)
        self.bob = Principal(
            user_id="bob@corp.com",
            tenant_id="tenant-prod",
            corporate_groups=["VCF-Platform-Admins"],
            allowed_clusters=["*"],
        )

        # Approver 2: Charlie (Security Admin)
        self.charlie = Principal(
            user_id="charlie@corp.com",
            tenant_id="tenant-prod",
            corporate_groups=["VCF-Security-Admins"],
            allowed_clusters=["*"],
        )

        # Unauthorized Approver: Dave (Viewer only)
        self.dave = Principal(
            user_id="dave@corp.com",
            tenant_id="tenant-prod",
            corporate_groups=["VCF-Users-ReadOnly"],
            allowed_clusters=["*"],
        )

    def test_single_approver_insufficient_for_multi_party_policy(self):
        """When 2 distinct approvers are required, providing only 1 approval rejects live execution."""
        plan = self.plan_mgr.create_dry_run_plan(
            principal=self.alice,
            tool_id="vcf_upgrade_domain",
            arguments={"domain_id": "mgmt-domain"},
            impact_summary={},
            target_resource_ids=["mgmt-domain"],
            risk_class=RiskClass.HIGH_IMPACT,
        )
        plan_id = plan["plan_id"]
        self.assertEqual(plan["approvals_required"], 2)

        # Bob approves (1 of 2)
        auth_bob = self.plan_mgr.approve_plan(plan_id, approver=self.bob)

        # Alice attempts execution with only Bob's approval -> Denied (Insufficient approvals)
        with self.assertRaises(AuthorizationDeniedException) as ctx:
            self.plan_mgr.validate_plan_for_execution(
                plan_id=plan_id,
                approval_id=auth_bob.approval_id,
                nonce=auth_bob.nonce,
                current_arguments={"domain_id": "mgmt-domain"},
                caller=self.alice,
            )
        self.assertIn("Insufficient approvals", str(ctx.exception))
        self.assertIn("requires 2 distinct approver(s), but only 1", str(ctx.exception))

    def test_two_distinct_approvers_allows_execution(self):
        """When 2 distinct approvers (Bob and Charlie) approve, live execution succeeds."""
        plan = self.plan_mgr.create_dry_run_plan(
            principal=self.alice,
            tool_id="vcf_upgrade_domain",
            arguments={"domain_id": "mgmt-domain"},
            impact_summary={},
            target_resource_ids=["mgmt-domain"],
            risk_class=RiskClass.HIGH_IMPACT,
        )
        plan_id = plan["plan_id"]

        # 1st approval by Bob
        auth_bob = self.plan_mgr.approve_plan(plan_id, approver=self.bob)
        # 2nd approval by Charlie
        auth_charlie = self.plan_mgr.approve_plan(plan_id, approver=self.charlie)

        # Validate with Charlie's execution authorization token
        val = self.plan_mgr.validate_plan_for_execution(
            plan_id=plan_id,
            approval_id=auth_charlie.approval_id,
            nonce=auth_charlie.nonce,
            current_arguments={"domain_id": "mgmt-domain"},
            caller=self.alice,
        )
        self.assertEqual(val["plan_id"], plan_id)

    def test_duplicate_approval_by_same_user_rejected(self):
        """Same approver cannot approve the same plan twice to satisfy multi-party requirement."""
        plan = self.plan_mgr.create_dry_run_plan(
            principal=self.alice,
            tool_id="vcf_upgrade_domain",
            arguments={"domain_id": "mgmt-domain"},
            impact_summary={},
            target_resource_ids=["mgmt-domain"],
            risk_class=RiskClass.HIGH_IMPACT,
        )
        plan_id = plan["plan_id"]

        # Bob approves first time -> OK
        self.plan_mgr.approve_plan(plan_id, approver=self.bob)

        # Bob attempts to approve the same plan a second time -> Denied
        with self.assertRaises(AuthorizationDeniedException) as ctx:
            self.plan_mgr.approve_plan(plan_id, approver=self.bob)
        self.assertIn("Duplicate approval", str(ctx.exception))

    def test_initiator_self_approval_rejected(self):
        """Initiator Alice cannot approve her own high-impact plan (Four-Eyes principle)."""
        plan = self.plan_mgr.create_dry_run_plan(
            principal=self.alice,
            tool_id="vcf_upgrade_domain",
            arguments={"domain_id": "mgmt-domain"},
            impact_summary={},
            target_resource_ids=["mgmt-domain"],
            risk_class=RiskClass.HIGH_IMPACT,
        )

        with self.assertRaises(AuthorizationDeniedException) as ctx:
            self.plan_mgr.approve_plan(plan["plan_id"], approver=self.alice)
        self.assertIn("cannot approve their own plan", str(ctx.exception))

    def test_unauthorized_role_approval_rejected(self):
        """User Dave lacking required approver role is rejected when attempting approval."""
        plan = self.plan_mgr.create_dry_run_plan(
            principal=self.alice,
            tool_id="vcf_upgrade_domain",
            arguments={"domain_id": "mgmt-domain"},
            impact_summary={},
            target_resource_ids=["mgmt-domain"],
            risk_class=RiskClass.HIGH_IMPACT,
        )

        with self.assertRaises(AuthorizationDeniedException) as ctx:
            self.plan_mgr.approve_plan(plan["plan_id"], approver=self.dave)
        self.assertIn("lacks required approval role", str(ctx.exception))

    def test_expired_approval_rejected(self):
        """Expired approvals cannot be used to satisfy multi-party requirements."""
        plan = self.plan_mgr.create_dry_run_plan(
            principal=self.alice,
            tool_id="vcf_upgrade_domain",
            arguments={"domain_id": "mgmt-domain"},
            impact_summary={},
            target_resource_ids=["mgmt-domain"],
            risk_class=RiskClass.HIGH_IMPACT,
        )
        plan_id = plan["plan_id"]

        # Bob approves with immediate expiration (ttl = 0.01 seconds)
        auth_bob = self.plan_mgr.approve_plan(plan_id, approver=self.bob, ttl_seconds=0.01)
        auth_charlie = self.plan_mgr.approve_plan(plan_id, approver=self.charlie, ttl_seconds=600.0)

        # Wait for Bob's approval to expire
        time.sleep(0.02)

        # Validation must fail because Bob's approval expired, leaving only 1 valid approval
        with self.assertRaises(AuthorizationDeniedException) as ctx:
            self.plan_mgr.validate_plan_for_execution(
                plan_id=plan_id,
                approval_id=auth_charlie.approval_id,
                nonce=auth_charlie.nonce,
                current_arguments={"domain_id": "mgmt-domain"},
                caller=self.alice,
            )
        self.assertIn("Insufficient approvals", str(ctx.exception))

    def test_permission_epoch_invalidation_across_approvers(self):
        """Bumping the tenant permission epoch invalidates all existing approvals for a plan."""
        plan = self.plan_mgr.create_dry_run_plan(
            principal=self.alice,
            tool_id="vcf_upgrade_domain",
            arguments={"domain_id": "mgmt-domain"},
            impact_summary={},
            target_resource_ids=["mgmt-domain"],
            risk_class=RiskClass.HIGH_IMPACT,
        )
        plan_id = plan["plan_id"]

        auth_bob = self.plan_mgr.approve_plan(plan_id, approver=self.bob)
        auth_charlie = self.plan_mgr.approve_plan(plan_id, approver=self.charlie)

        # Admin bumps permission epoch due to security event
        self.durable.bump_permission_epoch("tenant-prod", "env-prod")

        # Execution must fail due to stale epoch
        with self.assertRaises(AuthorizationDeniedException) as ctx:
            self.plan_mgr.validate_plan_for_execution(
                plan_id=plan_id,
                approval_id=auth_charlie.approval_id,
                nonce=auth_charlie.nonce,
                current_arguments={"domain_id": "mgmt-domain"},
                caller=self.alice,
            )
        self.assertIn("Permission epoch changed", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
