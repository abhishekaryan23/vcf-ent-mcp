# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Test Suite: High-Risk Execution Gate Enforcement (SEC-04).
Verifies:
1. live CHANGE without plan -> denied (ApprovalRequiredException).
2. live CHANGE without authorization -> denied.
3. live CHANGE without nonce -> denied.
4. live CHANGE with caller-supplied 'approved: true' -> denied (no bypass).
5. live CHANGE with plan for different tool -> denied (AuthorizationDeniedException).
6. live CHANGE with plan for different resource -> denied (AuthorizationDeniedException).
7. Valid flow with approved execution plan and single-use nonce -> succeeds and consumes nonce.
"""

import unittest
import asyncio
from vcf_enterprise_mcp.auth.identity import Principal
from vcf_enterprise_mcp.policy.models import RiskClass, CapabilityRole, ApprovalPolicy
from vcf_enterprise_mcp.policy.enforcement import PolicyEnforcementPoint
from vcf_enterprise_mcp.policy.engine import PolicyDecisionPoint
from vcf_enterprise_mcp.config.settings import PolicyConfig
from vcf_enterprise_mcp.state.durable_store import SQLiteDurableStore
from vcf_enterprise_mcp.workflows.execution_plans import ExecutionPlanManager
from vcf_enterprise_mcp.tools.operational_tools import VCFResizeVMTool
from vcf_enterprise_mcp.tools.workflow_tools import VCFUpgradeDomainTool
from vcf_enterprise_mcp.workflows.engine import VCFWorkflowEngine
from vcf_enterprise_mcp.core.errors import (
    ApprovalRequiredException,
    AuthorizationDeniedException,
)


class TestHighRiskExecutionGateSEC04(unittest.TestCase):
    """Validates execution gate enforcement for mutating high-risk tools."""

    def setUp(self):
        self.durable = SQLiteDurableStore(":memory:")
        self.config = PolicyConfig(
            operating_mode="FULL_ENFORCEMENT",
            require_approval_for_high_impact=True,
            require_approval_for_destructive=True,
            require_approval_for_change=True,
        )
        self.pdp = PolicyDecisionPoint(config=self.config, durable_store=self.durable)
        self.pep = PolicyEnforcementPoint(pdp=self.pdp)
        self.approval_policy = ApprovalPolicy(
            required_approvals=1,
            allow_initiator=False,
            distinct_principals=True,
            required_roles=("VCF-Platform-Admins", "VCF-Compute-Admins"),
            required_approver_roles={
                RiskClass.CHANGE: ["VCF-Platform-Admins", "VCF-Compute-Admins"],
                RiskClass.HIGH_IMPACT: ["VCF-Platform-Admins", "VCF-Lifecycle-Admins"],
            },
        )
        self.plan_mgr = ExecutionPlanManager(
            durable_store=self.durable,
            tenant_id="tenant-prod",
            environment_id="env-prod",
            approval_policy=self.approval_policy,
        )

        self.resize_tool = VCFResizeVMTool(
            pep=self.pep,
            durable_store=self.durable,
            plan_manager=self.plan_mgr,
            tenant_id="tenant-prod",
        )

        # Alice: Compute Operator (Initiator)
        self.alice = Principal(
            user_id="alice@corp.com",
            tenant_id="tenant-prod",
            corporate_groups=["VCF-Compute-Operators"],
            allowed_clusters=["cluster-prod-a"],
        )

        # Bob: Compute Admin (Approver)
        self.bob = Principal(
            user_id="bob@corp.com",
            tenant_id="tenant-prod",
            corporate_groups=["VCF-Compute-Admins", "VCF-Platform-Admins"],
            allowed_clusters=["*"],
        )

    def _run(self, coro):
        return asyncio.run(coro)

    def test_live_change_without_plan_denied(self):
        """Live execution of a CHANGE tool without plan credentials raises ApprovalRequiredException."""
        args = {
            "vm_id": "vm-101",
            "cluster_id": "cluster-prod-a",
            "memory_gb": 32,
            "dry_run": False,
        }
        with self.assertRaises(ApprovalRequiredException) as ctx:
            self._run(self.resize_tool.execute(self.alice, args))
        self.assertIn("PEP Approval Required", str(ctx.exception))

    def test_live_change_without_authorization_denied(self):
        """Live execution with plan_id but missing approval_id raises ApprovalRequiredException."""
        plan = self.plan_mgr.create_dry_run_plan(
            principal=self.alice,
            tool_id="vcf_resize_vm",
            arguments={"vm_id": "vm-101", "cluster_id": "cluster-prod-a", "memory_gb": 32},
            impact_summary={"vm_id": "vm-101"},
            target_resource_ids=["vm-101"],
            risk_class=RiskClass.CHANGE,
        )
        args = {
            "vm_id": "vm-101",
            "cluster_id": "cluster-prod-a",
            "memory_gb": 32,
            "plan_id": plan["plan_id"],
            "nonce": "test-nonce-123",
            "dry_run": False,
        }
        with self.assertRaises(ApprovalRequiredException) as ctx:
            self._run(self.resize_tool.execute(self.alice, args))
        self.assertIn("PEP Approval Required", str(ctx.exception))

    def test_live_change_without_nonce_denied(self):
        """Live execution with plan_id and approval_id but missing nonce raises ApprovalRequiredException."""
        plan = self.plan_mgr.create_dry_run_plan(
            principal=self.alice,
            tool_id="vcf_resize_vm",
            arguments={"vm_id": "vm-101", "cluster_id": "cluster-prod-a", "memory_gb": 32},
            impact_summary={"vm_id": "vm-101"},
            target_resource_ids=["vm-101"],
            risk_class=RiskClass.CHANGE,
        )
        auth = self.plan_mgr.approve_plan(plan["plan_id"], approver=self.bob)
        args = {
            "vm_id": "vm-101",
            "cluster_id": "cluster-prod-a",
            "memory_gb": 32,
            "plan_id": plan["plan_id"],
            "approval_id": auth.approval_id,
            "dry_run": False,
        }
        with self.assertRaises(ApprovalRequiredException) as ctx:
            self._run(self.resize_tool.execute(self.alice, args))
        self.assertIn("PEP Approval Required", str(ctx.exception))

    def test_live_change_with_caller_approved_true_denied(self):
        """Passing approved: true or arguments['approved']=True without valid plan/auth is rejected."""
        args = {
            "vm_id": "vm-101",
            "cluster_id": "cluster-prod-a",
            "memory_gb": 32,
            "approved": True,
            "dry_run": False,
        }
        with self.assertRaises(ApprovalRequiredException) as ctx:
            self._run(self.resize_tool.execute(self.alice, args, approved=True))
        self.assertIn("PEP Approval Required", str(ctx.exception))

    def test_live_change_with_plan_for_different_tool_denied(self):
        """An approved plan minted for tool A cannot be used to execute tool B."""
        # Create plan for vcf_create_nsx_segment
        plan = self.plan_mgr.create_dry_run_plan(
            principal=self.alice,
            tool_id="vcf_create_nsx_segment",
            arguments={"segment_name": "seg-test", "gateway_id": "gw-1", "cidr": "10.0.0.0/24"},
            impact_summary={},
            target_resource_ids=["seg-test"],
            risk_class=RiskClass.CHANGE,
        )
        auth = self.plan_mgr.approve_plan(plan["plan_id"], approver=self.bob)

        # Attempt to use NSX segment plan to execute vcf_resize_vm
        args = {
            "vm_id": "vm-101",
            "cluster_id": "cluster-prod-a",
            "memory_gb": 32,
            "plan_id": plan["plan_id"],
            "approval_id": auth.approval_id,
            "nonce": auth.nonce,
            "dry_run": False,
        }
        with self.assertRaises(AuthorizationDeniedException) as ctx:
            self._run(self.resize_tool.execute(self.alice, args))
        self.assertIn("Tool mismatch", str(ctx.exception))

    def test_live_change_with_plan_for_different_resource_denied(self):
        """An approved plan minted for vm-101 cannot be used to execute against vm-999."""
        plan = self.plan_mgr.create_dry_run_plan(
            principal=self.alice,
            tool_id="vcf_resize_vm",
            arguments={"vm_id": "vm-101", "cluster_id": "cluster-prod-a", "memory_gb": 32},
            impact_summary={"target_resource_ids": ["vm-101"]},
            target_resource_ids=["vm-101"],
            risk_class=RiskClass.CHANGE,
        )
        auth = self.plan_mgr.approve_plan(plan["plan_id"], approver=self.bob)

        # Execute targeting vm-999
        args = {
            "vm_id": "vm-999",
            "cluster_id": "cluster-prod-a",
            "memory_gb": 32,
            "plan_id": plan["plan_id"],
            "approval_id": auth.approval_id,
            "nonce": auth.nonce,
            "dry_run": False,
        }
        with self.assertRaises(AuthorizationDeniedException) as ctx:
            self._run(self.resize_tool.execute(self.alice, args))
        self.assertIn("Resource mismatch", str(ctx.exception))

    def test_valid_flow_succeeds_and_consumes_nonce(self):
        """Valid dry-run plan -> approval -> live execution succeeds and nonce consumption prevents replay."""
        # 1. Create plan
        args = {"vm_id": "vm-101", "cluster_id": "cluster-prod-a", "memory_gb": 32}
        plan = self.plan_mgr.create_dry_run_plan(
            principal=self.alice,
            tool_id="vcf_resize_vm",
            arguments=args,
            impact_summary={"target_resource_ids": ["vm-101"]},
            target_resource_ids=["vm-101"],
            risk_class=RiskClass.CHANGE,
        )
        plan_id = plan["plan_id"]

        # 2. Approve plan by authorized Bob
        auth = self.plan_mgr.approve_plan(plan_id, approver=self.bob)

        # 3. Execute live with plan credentials
        exec_args = dict(args)
        exec_args.update({
            "plan_id": plan_id,
            "approval_id": auth.approval_id,
            "nonce": auth.nonce,
            "dry_run": False,
        })
        res = self._run(self.resize_tool.execute(self.alice, exec_args))
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["allocated_memory_gb"], 32)

        # 4. Replay attempt with same nonce is denied
        with self.assertRaises(AuthorizationDeniedException) as ctx:
            self._run(self.resize_tool.execute(self.alice, exec_args))
        self.assertIn("already been consumed", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()


class TestPlanExpirySignedValueIsStored(TestHighRiskExecutionGateSEC04):
    """Regression: the store used to recompute expires_at a few ms after the manager signed it.
    When the two values straddled a 0.01 s boundary the approval signature failed at random."""

    def test_clock_skew_across_rounding_boundary_still_verifies(self):
        from unittest import mock
        import vcf_enterprise_mcp.state.sqlite_store as store_mod
        import vcf_enterprise_mcp.workflows.execution_plans as plans_mod
        real = plans_mod.time.time
        base = real()
        base = int(base) + 0.004  # signed value rounds down to .00 ...
        store_clock = mock.Mock(time=mock.Mock(return_value=base + 0.007))  # ... a store-side value would round to .01
        with mock.patch.object(plans_mod.time, "time", return_value=base), mock.patch.object(store_mod, "time", store_clock):
            args = {"vm_id": "vm-101", "cluster_id": "cluster-prod-a", "memory_gb": 32}
            plan = self.plan_mgr.create_dry_run_plan(
                principal=self.alice, tool_id="vcf_resize_vm", arguments=args,
                impact_summary={"target_resource_ids": ["vm-101"]}, target_resource_ids=["vm-101"],
                risk_class=RiskClass.CHANGE,
            )
            auth = self.plan_mgr.approve_plan(plan["plan_id"], approver=self.bob)
            self.plan_mgr.validate_plan_for_execution(
                plan_id=plan["plan_id"], approval_id=auth.approval_id, nonce=auth.nonce,
                current_arguments=args, caller=self.alice,
            )
