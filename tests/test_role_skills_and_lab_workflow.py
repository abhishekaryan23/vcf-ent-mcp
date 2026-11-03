# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Comprehensive Test Suite for Single-Task Role Skills, Plan Handback Lifecycle,
Extended Role Tools, and Developer Laptop / Lab Mode Usability.
"""

from __future__ import annotations
import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path

from vcf_enterprise_mcp.auth.idp import EnterpriseIdPValidator
from vcf_enterprise_mcp.auth.kms import LocalKMSKeyManager
from vcf_enterprise_mcp.auth.lab_auth import mint_lab_jwt_token
from vcf_enterprise_mcp.cli import main as cli_main
from vcf_enterprise_mcp.core.protocol import EnterpriseMCPProtocolEngine
from vcf_enterprise_mcp.policy.models import CapabilityRole, ROLE_PRESET_CAPABILITIES
from vcf_enterprise_mcp.router.identity_router import IdentityAwareRouter
from vcf_enterprise_mcp.skills import get_skill_registry
from vcf_enterprise_mcp.state.sqlite_store import SQLiteDurableStore
from vcf_enterprise_mcp.workflows.task_store import TaskStore


class TestRoleSkillsAndLabWorkflow(unittest.TestCase):
    """Verifies single-task role skills, MCP prompts/resources, plan handback, and laptop lab mode."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_control_plane.db")
        self.durable = SQLiteDurableStore(self.db_path)
        self.task_store = TaskStore(durable_store=self.durable)
        self.engine = EnterpriseMCPProtocolEngine(task_store=self.task_store)
        self.engine.pep.pdp.config.operating_mode = "AUDITED_OPERATIONS"
        self.engine.idp.config.allow_lab_tokens = True  # lab tokens are opt-in (F7)

        from tests.fixtures.test_tokens import (
            ALICE_BEARER,
            BOB_BEARER,
            ADMIN_BEARER,
            register_test_keys,
        )
        from vcf_enterprise_mcp.auth.lab_auth import register_lab_key_in_jwks
        register_test_keys(self.engine.idp.jwks_manager)
        self.key_file = os.path.join(self.temp_dir.name, "lab_jwt.pem")
        register_lab_key_in_jwks(self.engine.idp.jwks_manager, custom_path=self.key_file)
        auditor_info = mint_lab_jwt_token(
            user_id="auditor@corp.com",
            role="VCF_AUDITOR",
            custom_key_path=self.key_file,
        )
        self.alice_bearer = ALICE_BEARER
        self.bob_bearer = BOB_BEARER
        self.admin_bearer = ADMIN_BEARER
        self.auditor_bearer = auditor_info["authorization_header"]

    def tearDown(self):
        self.temp_dir.cleanup()

    def _run(self, coro):
        return asyncio.run(coro)

    def test_all_capability_roles_populated_in_presets(self):
        """Every operational CapabilityRole must have non-empty normalized capabilities."""
        for role in CapabilityRole:
            if role == CapabilityRole.MCP_ADMIN:
                continue
            self.assertIn(role, ROLE_PRESET_CAPABILITIES)
            self.assertGreater(
                len(ROLE_PRESET_CAPABILITIES[role]),
                0,
                f"Role {role.value} has empty capability preset",
            )

    def test_single_responsibility_skill_catalog_and_mcp_prompts(self):
        """Verifies prompts/list and prompts/get are role-filtered and enforce single-task tool whitelists."""
        reg = get_skill_registry()
        all_skills = reg.list_all_skills()
        self.assertGreaterEqual(len(all_skills), 18)

        # Alice (COMPUTE_OPERATOR) lists prompts
        res = self._run(
            self.engine.handle_jsonrpc_request(
                {"jsonrpc": "2.0", "id": 1, "method": "prompts/list"},
                auth_header=self.alice_bearer,
            )
        )
        prompts = res["result"]["prompts"]
        prompt_names = {p["name"] for p in prompts}
        self.assertEqual(res["result"]["cacheScope"], "private")
        self.assertIn("vcf-compute-vm-triage", prompt_names)
        self.assertIn("vcf-compute-vm-power-cycle", prompt_names)
        self.assertIn("vcf-compute-vm-rightsize", prompt_names)
        # Network Admin and Lifecycle Admin skills must NOT be visible to Compute Operator
        self.assertNotIn("vcf-network-segment-provision", prompt_names)
        self.assertNotIn("vcf-lifecycle-domain-upgrade", prompt_names)

        # Alice fetches vcf-compute-vm-rightsize prompt
        get_res = self._run(
            self.engine.handle_jsonrpc_request(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "prompts/get",
                    "params": {
                        "name": "vcf-compute-vm-rightsize",
                        "arguments": {"vm_id": "vm-101", "memory_gb": "32"},
                    },
                },
                auth_header=self.alice_bearer,
            )
        )
        self.assertNotIn("error", get_res)
        self.assertEqual(
            get_res["result"]["allowedTools"],
            ["vcf_get_vm", "vcf_query_telemetry", "vcf_resize_vm", "vcf_get_plan"],
        )
        self.assertIn("vm-101", get_res["result"]["messages"][0]["content"]["text"])

        # Alice attempts to fetch Network Admin skill -> Denied
        denied_res = self._run(
            self.engine.handle_jsonrpc_request(
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "prompts/get",
                    "params": {"name": "vcf-network-segment-provision"},
                },
                auth_header=self.alice_bearer,
            )
        )
        self.assertIn("error", denied_res)
        self.assertEqual(denied_res["error"]["code"], -32001)

    def test_active_skill_scoping_in_tools_list(self):
        """Activating a single-task skill restricts tools/list strictly to that skill's tool whitelist."""
        res = self._run(
            self.engine.handle_jsonrpc_request(
                {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/list",
                    "params": {"skill": "vcf-compute-vm-power-cycle"},
                },
                auth_header=self.alice_bearer,
            )
        )
        self.assertNotIn("error", res)
        self.assertEqual(res["result"]["activeSkill"], "vcf-compute-vm-power-cycle")
        tool_names = [t["name"] for t in res["result"]["tools"]]
        self.assertEqual(set(tool_names), {"vcf_get_vm", "vcf_power_vm", "vcf_get_plan"})  # write skills also get plan status

    def test_in_band_plan_discovery_approval_and_initiator_handback(self):
        """
        Verifies the full in-band MCP workflow:
        1. Operator runs dry_run=True -> gets plan_id
        2. Approver calls enterprise/plans/list -> discovers pending plan_id
        3. Approver calls enterprise/plans/get -> inspects impact without seeing initiator nonce
        4. Approver calls enterprise/plans/approve -> approves plan
        5. Initiator calls enterprise/plans/get -> receives approval_id and single-use nonce
        6. Initiator executes live mutation with plan_id, approval_id, and nonce -> SUCCESS
        """
        # 1. Operator dry-run
        dry_res = self._run(
            self.engine.handle_jsonrpc_request(
                {
                    "jsonrpc": "2.0",
                    "id": 10,
                    "method": "tools/call",
                    "params": {
                        "name": "vcf_power_vm",
                        "arguments": {"vm_id": "vm-101", "action": "restart", "dry_run": True},
                    },
                },
                auth_header=self.alice_bearer,
            )
        )
        dry_payload = json.loads(dry_res["result"]["content"][0]["text"])
        plan_id = dry_payload["plan_id"]
        self.assertTrue(plan_id.startswith("plan_"))

        # 2. Approver lists pending plans
        list_res = self._run(
            self.engine.handle_jsonrpc_request(
                {
                    "jsonrpc": "2.0",
                    "id": 11,
                    "method": "enterprise/plans/list",
                    "params": {"status": "PENDING_APPROVAL"},
                },
                auth_header=self.admin_bearer,
            )
        )
        plan_ids = [p["plan_id"] for p in list_res["result"]["plans"]]
        self.assertIn(plan_id, plan_ids)

        # 3. Approver approves plan
        app_res = self._run(
            self.engine.handle_jsonrpc_request(
                {
                    "jsonrpc": "2.0",
                    "id": 12,
                    "method": "enterprise/plans/approve",
                    "params": {"plan_id": plan_id},
                },
                auth_header=self.admin_bearer,
            )
        )
        self.assertIn("approval_id", app_res["result"])

        # 4. Non-initiator (Bob) inspects plan -> does NOT receive nonce
        bob_get = self._run(
            self.engine.handle_jsonrpc_request(
                {
                    "jsonrpc": "2.0",
                    "id": 13,
                    "method": "enterprise/plans/get",
                    "params": {"plan_id": plan_id},
                },
                auth_header=self.bob_bearer,
            )
        )
        self.assertNotIn("nonce", bob_get["result"])

        # 5. Initiator (Alice) calls enterprise/plans/get -> receives approval_id and nonce handback
        alice_get = self._run(
            self.engine.handle_jsonrpc_request(
                {
                    "jsonrpc": "2.0",
                    "id": 14,
                    "method": "enterprise/plans/get",
                    "params": {"plan_id": plan_id},
                },
                auth_header=self.alice_bearer,
            )
        )
        self.assertTrue(alice_get["result"]["ready_to_execute"])
        approval_id = alice_get["result"]["approval_id"]
        nonce = alice_get["result"]["nonce"]

        # 6. Initiator executes live mutation
        live_res = self._run(
            self.engine.handle_jsonrpc_request(
                {
                    "jsonrpc": "2.0",
                    "id": 15,
                    "method": "tools/call",
                    "params": {
                        "name": "vcf_power_vm",
                        "arguments": {
                            "vm_id": "vm-101",
                            "action": "restart",
                            "dry_run": False,
                            "plan_id": plan_id,
                            "approval_id": approval_id,
                            "nonce": nonce,
                        },
                    },
                },
                auth_header=self.alice_bearer,
            )
        )
        live_payload = json.loads(live_res["result"]["content"][0]["text"])
        self.assertEqual(live_payload["status"], "SUCCESS")

    def test_extended_lifecycle_and_role_tools(self):
        """Tests the 9 new role tools (domains, clusters, datastores, segments, gateways, snapshots, bundles, audit)."""
        tool_calls = [
            ("vcf_list_domains", {}),
            ("vcf_list_clusters", {"domain_id": "wld-app-a"}),
            ("vcf_list_datastores", {"cluster_id": "cluster-prod-a"}),
            ("vcf_list_nsx_segments", {"gateway_id": "t1-gw-prod"}),
            ("vcf_list_nsx_gateways", {"tier": "TIER_1"}),
            ("vcf_list_snapshots", {"vm_id": "vm-101"}),
            ("vcf_list_upgrade_bundles", {"domain_id": "mgmt-domain", "target_version": "9.1.1"}),
            ("vcf_verify_audit_chain", {"limit": 10}),
        ]
        for idx, (tool_name, args) in enumerate(tool_calls, start=20):
            res = self._run(
                self.engine.handle_jsonrpc_request(
                    {
                        "jsonrpc": "2.0",
                        "id": idx,
                        "method": "tools/call",
                        "params": {"name": tool_name, "arguments": args},
                    },
                    auth_header=self.admin_bearer,
                )
            )
            self.assertNotIn("error", res, f"Tool {tool_name} failed: {res}")
            self.assertFalse(res["result"]["isError"])

        # Test VM name resolution in vcf_get_vm
        vm_res = self._run(
            self.engine.handle_jsonrpc_request(
                {
                    "jsonrpc": "2.0",
                    "id": 35,
                    "method": "tools/call",
                    "params": {"name": "vcf_get_vm", "arguments": {"vm_id": "web-frontend-01"}},
                },
                auth_header=self.alice_bearer,
            )
        )
        vm_payload = json.loads(vm_res["result"]["content"][0]["text"])
        self.assertEqual(vm_payload["vm_id"], "vm-101")

    def test_mcp_resources_list_and_read(self):
        """Verifies resources/list and resources/read expose pending plans, skill catalog, and audit status."""
        list_res = self._run(
            self.engine.handle_jsonrpc_request(
                {"jsonrpc": "2.0", "id": 40, "method": "resources/list"},
                auth_header=self.auditor_bearer,
            )
        )
        uris = {r["uri"] for r in list_res["result"]["resources"]}
        self.assertIn("vcf://plans/pending", uris)
        self.assertIn("vcf://skills/catalog", uris)
        self.assertIn("vcf://audit/status", uris)
        self.assertIn("vcf://skills/vcf-auditor-chain-verification", uris)

        read_res = self._run(
            self.engine.handle_jsonrpc_request(
                {
                    "jsonrpc": "2.0",
                    "id": 41,
                    "method": "resources/read",
                    "params": {"uri": "vcf://skills/vcf-auditor-chain-verification"},
                },
                auth_header=self.auditor_bearer,
            )
        )
        self.assertIn("SOC2 Tamper-Evident Audit Chain Verification", read_res["result"]["contents"][0]["text"])

    def test_laptop_lab_jwt_minting_and_self_approval_workflow(self):
        """Verifies local laptop JWT minting, deterministic KMS keys across instances, and lab auto-approval."""
        key_file = os.path.join(self.temp_dir.name, "lab_jwt.pem")
        token_info = mint_lab_jwt_token(
            user_id="dev-laptop@lab.local",
            role="STORAGE_ADMIN",
            allowed_clusters=["cluster-prod-a"],
            custom_key_path=key_file,
        )
        bearer = token_info["authorization_header"]

        # Validate minted token through EnterpriseIdPValidator
        principal = self.engine.idp.validate_bearer_token(bearer)
        self.assertEqual(principal.user_id, "dev-laptop@lab.local")

        # Enable laptop lab auto-approve and test 2-step dry-run -> live execution of vcf_delete_snapshot
        old_auto = os.environ.get("VCF_LAB_AUTO_APPROVE")
        try:
            os.environ["VCF_LAB_AUTO_APPROVE"] = "true"
            dry_res = self._run(
                self.engine.handle_jsonrpc_request(
                    {
                        "jsonrpc": "2.0",
                        "id": 50,
                        "method": "tools/call",
                        "params": {
                            "name": "vcf_delete_snapshot",
                            "arguments": {
                                "vm_id": "vm-101",
                                "snapshot_id": "snap-vm-101-baseline",
                                "dry_run": True,
                            },
                        },
                    },
                    auth_header=bearer,
                )
            )
            dry_data = json.loads(dry_res["result"]["content"][0]["text"])
            self.assertEqual(dry_data["status"], "APPROVED")
            self.assertIn("approval_id", dry_data)
            self.assertIn("nonce", dry_data)

            live_res = self._run(
                self.engine.handle_jsonrpc_request(
                    {
                        "jsonrpc": "2.0",
                        "id": 51,
                        "method": "tools/call",
                        "params": {
                            "name": "vcf_delete_snapshot",
                            "arguments": {
                                "vm_id": "vm-101",
                                "snapshot_id": "snap-vm-101-baseline",
                                "dry_run": False,
                                "plan_id": dry_data["plan_id"],
                                "approval_id": dry_data["approval_id"],
                                "nonce": dry_data["nonce"],
                            },
                        },
                    },
                    auth_header=bearer,
                )
            )
            live_data = json.loads(live_res["result"]["content"][0]["text"])
            self.assertEqual(live_data["status"], "SUCCESS")
            self.assertTrue(live_data["deleted"])
        finally:
            if old_auto is None:
                os.environ.pop("VCF_LAB_AUTO_APPROVE", None)
            else:
                os.environ["VCF_LAB_AUTO_APPROVE"] = old_auto

    def test_deterministic_kms_key_id_across_ha_nodes(self):
        """Two KMS instances initialized with the same master_secret produce identical key_ids and verify signatures."""
        secret = b"shared-ha-cluster-secret-key-32b"
        node_a = LocalKMSKeyManager(master_secret=secret)
        node_b = LocalKMSKeyManager(master_secret=secret)
        self.assertEqual(node_a.active_key_id, node_b.active_key_id)

        sig, kid, alg, ver = node_a.sign_digest("canonical-plan-digest-123")
        self.assertTrue(node_b.verify_signature("canonical-plan-digest-123", sig, kid, ver))

    def test_cli_init_lab_token_mint_and_skills_commands(self):
        """Verifies CLI developer commands (init-lab, token mint, skills list/show, plans list)."""
        cfg_path = os.path.join(self.temp_dir.name, "lab_config.yaml")
        rc = cli_main(["init-lab", "--config", cfg_path, "--role", "COMPUTE_OPERATOR"])
        self.assertEqual(rc, 0)
        self.assertTrue(Path(cfg_path).exists())

        rc_mint = cli_main(["token", "mint", "--role", "NETWORK_ADMIN", "--raw"])
        self.assertEqual(rc_mint, 0)

        rc_skills = cli_main(["skills", "list", "--role", "COMPUTE_OPERATOR"])
        self.assertEqual(rc_skills, 0)

        rc_show = cli_main(["skills", "show", "vcf-compute-vm-power-cycle"])
        self.assertEqual(rc_show, 0)

        rc_plans = cli_main(["plans", "list", "--db", self.db_path])
        self.assertEqual(rc_plans, 0)


if __name__ == "__main__":
    unittest.main()
