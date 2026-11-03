# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Test Suite: Permission Epochs, Authorization Freshness, and Cache Isolation.
Validates:
- Permission epoch incrementation upon native permission change / user revocation
- Automatic invalidation of cached authorization decisions and outstanding approval tokens
- Tool catalogue cache isolation (User A never receives User B tools)
"""

import unittest
from vcf_enterprise_mcp.auth.identity import Principal
from vcf_enterprise_mcp.policy.models import RiskClass, CapabilityRole, NormalizedCapability
from vcf_enterprise_mcp.policy.engine import PolicyDecisionPoint
from vcf_enterprise_mcp.policy.enforcement import PolicyEnforcementPoint
from vcf_enterprise_mcp.state.durable_store import DurableStore
from vcf_enterprise_mcp.workflows.execution_plans import ExecutionPlanManager
from vcf_enterprise_mcp.adapter.platform import PlatformClient
from vcf_enterprise_mcp.core.errors import AuthorizationDeniedException, VCFEnterpriseException


class TestPermissionEpochsAndFreshness(unittest.TestCase):

    def setUp(self):
        self.durable = DurableStore(":memory:")
        from vcf_enterprise_mcp.config.settings import PolicyConfig
        self.pdp = PolicyDecisionPoint(
            config=PolicyConfig(operating_mode="AUDITED_OPERATIONS"),
            durable_store=self.durable,
            tenant_id="tenant-prod",
            environment_id="env-vcf-01",
        )
        self.pep = PolicyEnforcementPoint(pdp=self.pdp)
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
        self.admin = Principal(
            user_id="admin@corp.com",
            corporate_groups=["VCF-Platform-Admins"],
            allowed_clusters=["*"],
        )

    def test_permission_epoch_initialization_and_bump(self):
        epoch1 = self.pdp.get_current_epoch()
        self.assertEqual(epoch1, 100)

        # Admin alters permissions or revokes access -> bump epoch
        epoch2 = self.pdp.bump_epoch_on_permission_change()
        self.assertEqual(epoch2, 101)

        epoch3 = self.pdp.bump_epoch_on_permission_change()
        self.assertEqual(epoch3, 102)

    def test_epoch_invalidation_of_approval_tokens(self):
        # Alice creates dry-run plan under epoch 100
        plan = self.plan_mgr.create_dry_run_plan(
            principal=self.alice,
            tool_id="vcf_upgrade_domain",
            arguments={"domain_id": "mgmt-domain"},
            impact_summary={"clusters": 2},
            target_resource_ids=["mgmt-domain"],
        )
        self.assertEqual(plan["permission_epoch"], 100)

        # Admin approves plan under epoch 100
        auth = self.plan_mgr.approve_plan(plan["plan_id"], approver=self.admin)
        self.assertEqual(auth.permission_epoch, 100)

        # Revocation event occurs: permission epoch bumped from 100 -> 101
        self.pdp.bump_epoch_on_permission_change()

        # Alice attempts to execute the plan: must be rejected because epoch changed!
        with self.assertRaises(AuthorizationDeniedException) as ctx:
            self.plan_mgr.validate_plan_for_execution(
                plan_id=plan["plan_id"],
                approval_id=auth.approval_id,
                nonce=auth.nonce,
                current_arguments={"domain_id": "mgmt-domain"},
                caller=self.alice,
            )
        self.assertIn("Permission epoch changed", str(ctx.exception))

    def test_tools_list_cache_isolation_between_principals(self):
        sample_tools = [
            {"name": "vcf_list_vms", "_enterprise_meta": {"risk_class": RiskClass.READ, "required_roles": [CapabilityRole.VCF_VIEWER]}},
            {"name": "vcf_resize_vm", "_enterprise_meta": {"risk_class": RiskClass.CHANGE, "required_roles": [CapabilityRole.COMPUTE_OPERATOR]}},
            {"name": "vcf_create_nsx_segment", "_enterprise_meta": {"risk_class": RiskClass.CHANGE, "required_roles": [CapabilityRole.NETWORK_ADMIN]}},
        ]

        # Compute Operator Alice
        alice_tools = [t["name"] for t in self.pep.filter_visible_tools(self.alice, sample_tools)]
        self.assertIn("vcf_list_vms", alice_tools)
        self.assertIn("vcf_resize_vm", alice_tools)
        self.assertNotIn("vcf_create_nsx_segment", alice_tools)

        # Network Operator Bob
        bob = Principal(user_id="bob@corp.com", corporate_groups=["VCF-Network-Operators"])
        bob_tools = [t["name"] for t in self.pep.filter_visible_tools(bob, sample_tools)]
        self.assertIn("vcf_list_vms", bob_tools)
        self.assertNotIn("vcf_resize_vm", bob_tools)
        self.assertNotIn("vcf_create_nsx_segment", bob_tools)

        # Tools are strictly isolated per caller
        self.assertNotEqual(alice_tools, bob_tools)


if __name__ == "__main__":
    unittest.main()
