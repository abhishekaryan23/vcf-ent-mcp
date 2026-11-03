# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Unit Tests for Dry-Run Simulation, Approval Gates, and MCP Tasks Extension (MCP 2026-07-28).
Runs in-memory with zero external test runner dependencies (uses standard library unittest).
"""

from __future__ import annotations
from vcf_enterprise_mcp.policy.models import RiskClass
import sys
import os
import unittest
import asyncio
import json

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC_DIR = os.path.join(BASE_DIR, "src")
sys.path.insert(0, SRC_DIR)

from vcf_enterprise_mcp.core.protocol import EnterpriseMCPProtocolEngine
from vcf_enterprise_mcp.config.settings import PolicyConfig
from tests.fixtures.test_tokens import ALICE_BEARER, ADMIN_BEARER
from vcf_enterprise_mcp.auth.identity import Principal


class TestDryRunAndWorkflowTasks(unittest.TestCase):
    """Validates dry-run execution, high-impact approvals, and MCP Tasks extension tracking."""

    def setUp(self):
        self.engine = EnterpriseMCPProtocolEngine()
        self.engine.pep.pdp.config.operating_mode = "FULL_ENFORCEMENT"
        self.alice_auth = ALICE_BEARER
        self.admin_auth = ADMIN_BEARER

    def _run(self, coro):
        return asyncio.run(coro)

    def test_operational_tool_dry_run(self):
        """Validates that dry_run=True returns simulated changes without applying mutations."""
        req = {
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "vcf_resize_vm",
                "arguments": {
                    "vm_id": "vm-102",
                    "memory_gb": 32,
                    "cluster_id": "cluster-prod-a",
                    "dry_run": True,
                },
            },
        }
        res = self._run(self.engine.handle_jsonrpc_request(req, auth_header=self.alice_auth))
        self.assertNotIn("error", res)
        text = res["result"]["content"][0]["text"]
        data = json.loads(text)
        self.assertTrue(data["dry_run"])
        self.assertTrue(data["allowed"])
        self.assertIn("RAM: 16 GB -> 32 GB", data["changes"])
        self.assertEqual(data["capacity_after"]["cluster_free_ram_gb"], 496)

    def test_workflow_upgrade_dry_run_and_approval_gate(self):
        """Workload domain upgrade dry_run produces pre-check plan; live run requires approval."""
        # 1. Dry run succeeds without approval
        dry_req = {
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {
                "name": "vcf_upgrade_domain",
                "arguments": {
                    "domain_id": "wld-app-a",
                    "target_version": "9.1.1",
                    "dry_run": True,
                },
            },
        }
        dry_res = self._run(self.engine.handle_jsonrpc_request(dry_req, auth_header=self.admin_auth))
        self.assertNotIn("error", dry_res)
        data = json.loads(dry_res["result"]["content"][0]["text"])
        self.assertTrue(data["dry_run"])
        self.assertTrue(data["approval_required"])
        self.assertEqual(data["impact_plan"]["affected_hosts"], 8)
        self.assertEqual(data["impact_plan"]["affected_vms"], 64)
        plan_id = data["plan_id"]
        self.assertTrue(plan_id.startswith("plan_"))

        # 2. Live run without approval is blocked by PEP
        live_unapproved = {
            "jsonrpc": "2.0",
            "id": 12,
            "method": "tools/call",
            "params": {
                "name": "vcf_upgrade_domain",
                "arguments": {
                    "domain_id": "wld-app-a",
                    "target_version": "9.1.1",
                    "dry_run": False,
                },
                "approved": False,
            },
        }
        unapp_res = self._run(self.engine.handle_jsonrpc_request(live_unapproved, auth_header=self.admin_auth))
        # Tool failures are CallToolResults with isError=true (not JSON-RPC errors) so the model can read them.
        self.assertNotIn("error", unapp_res)
        self.assertTrue(unapp_res["result"]["isError"])
        self.assertEqual(unapp_res["result"]["structuredContent"]["error"]["code"], -32002)  # ApprovalRequiredException
        self.assertIn("PEP Approval Required", unapp_res["result"]["content"][0]["text"])

        # 2b. Live run with caller-supplied 'approved: true' but without approved plan is rejected!
        live_fake = {
            "jsonrpc": "2.0",
            "id": 122,
            "method": "tools/call",
            "params": {
                "name": "vcf_upgrade_domain",
                "arguments": {
                    "domain_id": "wld-app-a",
                    "target_version": "9.1.1",
                    "dry_run": False,
                },
                "approved": True,
            },
        }
        fake_res = self._run(self.engine.handle_jsonrpc_request(live_fake, auth_header=self.admin_auth))
        self.assertTrue(fake_res["result"]["isError"])
        self.assertEqual(fake_res["result"]["structuredContent"]["error"]["code"], -32002)

        # 3. Legitimate approval from authorized approver (Four-Eyes principle)
        admin_principal = self.engine.idp.validate_bearer_token(self.admin_auth)
        second_admin = Principal(
            user_id="sec-admin@corp.com",
            corporate_groups=["VCF-Platform-Admins"],
            tenant_id=admin_principal.tenant_id,
            environment_ids=admin_principal.environment_ids,
        )
        auth = self.engine.plan_manager.approve_plan(plan_id, approver=second_admin)

        # Live run with signed authorization, plan_id, and single-use nonce succeeds and launches MCP Task
        live_approved = {
            "jsonrpc": "2.0",
            "id": 13,
            "method": "tools/call",
            "params": {
                "name": "vcf_upgrade_domain",
                "arguments": {
                    "domain_id": "wld-app-a",
                    "target_version": "9.1.1",
                    "dry_run": False,
                    "plan_id": plan_id,
                    "approval_id": auth.approval_id,
                    "nonce": auth.nonce,
                },
            },
        }
        app_res = self._run(self.engine.handle_jsonrpc_request(live_approved, auth_header=self.admin_auth))
        self.assertNotIn("error", app_res)
        task_data = json.loads(app_res["result"]["content"][0]["text"])
        self.assertFalse(task_data["dry_run"])
        task_id = task_data["task_id"]
        self.assertTrue(task_id.startswith("task-"))

        # 4. Monitor task via MCP Tasks extension tasks/get
        task_req = {
            "jsonrpc": "2.0",
            "id": 14,
            "method": "tasks/get",
            "params": {"taskId": task_id},
        }
        task_res = self._run(self.engine.handle_jsonrpc_request(task_req, auth_header=self.admin_auth))
        self.assertNotIn("error", task_res)
        task_info = task_res["result"]
        self.assertEqual(task_info["taskId"], task_id)
        self.assertEqual(task_info["status"], "RUNNING")
        self.assertEqual(task_info["approvalStatus"], "APPROVED")

    def test_audit_record_creation_and_provenance(self):
        """Verifies that an immutable audit record is created capturing identity and action."""
        initial_count = len(self.engine.audit.records)
        req = {
            "jsonrpc": "2.0",
            "id": 15,
            "method": "tools/call",
            "params": {
                "name": "vcf_power_vm",
                "arguments": {
                    "vm_id": "vm-101",
                    "action": "start",
                    "cluster_id": "cluster-prod-a",
                    "dry_run": False,
                },
            },
        }
        principal = self.engine.idp.validate_bearer_token(self.alice_auth)
        approver = self.engine.idp.validate_bearer_token(self.admin_auth)
        args = req["params"]["arguments"]
        plan = self.engine.plan_manager.create_dry_run_plan(principal, "vcf_power_vm", args, {}, ["vm-101"], RiskClass.SAFE_WRITE)
        auth = self.engine.plan_manager.approve_plan(plan["plan_id"], approver)
        args.update(plan_id=plan["plan_id"], approval_id=auth.approval_id, nonce=auth.nonce)
        res = self._run(self.engine.handle_jsonrpc_request(req, auth_header=self.alice_auth))
        self.assertNotIn("error", res)
        self.assertEqual(len(self.engine.audit.records), initial_count + 1)

        last_record = self.engine.audit.records[-1]
        self.assertEqual(last_record.actor["user_id"], "alice@corp.com")
        self.assertEqual(last_record.tool, "vcf_power_vm")
        self.assertEqual(last_record.result_status, "SUCCESS")


if __name__ == "__main__":
    unittest.main()
