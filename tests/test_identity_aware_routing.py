# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Unit Tests for Identity-Aware Routing and Dynamic Principal-Sensitive tools/list.
Runs in-memory with zero external test runner dependencies (uses standard library unittest).
"""

from __future__ import annotations
import sys
import os
import unittest
import asyncio

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC_DIR = os.path.join(BASE_DIR, "src")
sys.path.insert(0, SRC_DIR)

from vcf_enterprise_mcp.auth.idp import EnterpriseIdPValidator
from vcf_enterprise_mcp.core.protocol import EnterpriseMCPProtocolEngine
from vcf_enterprise_mcp.router.identity_router import IdentityAwareRouter
from vcf_enterprise_mcp.policy.engine import PolicyDecisionPoint
from vcf_enterprise_mcp.config.settings import PolicyConfig


class TestIdentityAwareRoutingAndDiscovery(unittest.TestCase):
    """Validates that tools/list is principal-sensitive and routing enforces identity and scopes."""

    def setUp(self):
        self.idp = EnterpriseIdPValidator()
        self.engine = EnterpriseMCPProtocolEngine()
        self.engine.pep.pdp.config.operating_mode = "FULL_ENFORCEMENT"
        self.router = IdentityAwareRouter(PolicyDecisionPoint(PolicyConfig(operating_mode="FULL_ENFORCEMENT")))
        from tests.fixtures.test_tokens import ALICE_BEARER, BOB_BEARER, ADMIN_BEARER, register_test_keys
        register_test_keys(self.engine.idp.jwks_manager)
        register_test_keys(self.idp.jwks_manager)
        self.alice_bearer = ALICE_BEARER
        self.bob_bearer = BOB_BEARER
        self.admin_bearer = ADMIN_BEARER

    def _run(self, coro):
        return asyncio.run(coro)

    def test_dynamic_tools_list_for_compute_operator(self):
        """Alice (Compute Operator) only receives compute & viewer tools; network and lifecycle admin tools are omitted."""
        req = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        res = self._run(self.engine.handle_jsonrpc_request(req, auth_header=self.alice_bearer))
        tools = res["result"]["tools"]
        tool_names = {t["name"] for t in tools}

        # Should be present
        self.assertIn("vcf_list_vms", tool_names)
        self.assertIn("vcf_get_vm", tool_names)
        self.assertIn("vcf_power_vm", tool_names)
        self.assertIn("vcf_resize_vm", tool_names)
        self.assertIn("vcf_create_snapshot", tool_names)

        # Should NOT be present
        self.assertNotIn("vcf_create_nsx_segment", tool_names)  # Requires NETWORK_ADMIN
        self.assertNotIn("vcf_upgrade_domain", tool_names)      # Requires LIFECYCLE_ADMIN

    def test_dynamic_tools_list_for_network_operator(self):
        """Bob (Network Operator) receives viewer and network query tools, but NOT VM power or upgrades."""
        req = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
        res = self._run(self.engine.handle_jsonrpc_request(req, auth_header=self.bob_bearer))
        tools = res["result"]["tools"]
        tool_names = {t["name"] for t in tools}

        self.assertIn("vcf_get_health", tool_names)
        self.assertNotIn("vcf_power_vm", tool_names)
        self.assertNotIn("vcf_upgrade_domain", tool_names)

    def test_dynamic_tools_list_discovery_only_mode(self):
        """When control plane is in DISCOVERY_ONLY mode, only READ tools are advertised to anyone."""
        self.engine.pep.pdp.config.operating_mode = "DISCOVERY_ONLY"
        req = {"jsonrpc": "2.0", "id": 3, "method": "tools/list"}
        res = self._run(self.engine.handle_jsonrpc_request(req, auth_header=self.admin_bearer))
        tools = res["result"]["tools"]
        tool_names = {t["name"] for t in tools}

        self.assertIn("vcf_list_vms", tool_names)
        self.assertIn("vcf_get_health", tool_names)
        self.assertNotIn("vcf_power_vm", tool_names)
        self.assertNotIn("vcf_resize_vm", tool_names)
        self.assertNotIn("vcf_upgrade_domain", tool_names)

        # Reset mode
        self.engine.pep.pdp.config.operating_mode = "FULL_ENFORCEMENT"

    def test_router_pipeline_parameter_extraction(self):
        """Validates query routing to vcf_resize_vm with memory parameter extraction."""
        alice = self.idp.validate_bearer_token(self.alice_bearer)
        res = self.router.route_query(
            query="Please increase memory of vm-102 to 32GB in datacenter 1",
            principal=alice,
            target_cluster="cluster-prod-a",
        )
        self.assertEqual(res.status, "MATCHED")
        self.assertEqual(res.selected_tool, "vcf_resize_vm")
        self.assertEqual(res.extracted_parameters.get("vm_id"), "vm-102")
        self.assertEqual(res.extracted_parameters.get("memory_gb"), 32)
        self.assertEqual(res.extracted_parameters.get("datacenter_id"), "dc1")

    def test_router_hard_negative_separation(self):
        """Query asking for physical hosts routes to vcf_list_hosts, not vcf_list_vms."""
        admin = self.idp.validate_bearer_token(self.admin_bearer)
        res = self.router.route_query(
            query="List all physical ESXi hosts commissioned in the datacenter",
            principal=admin,
        )
        self.assertEqual(res.status, "MATCHED")
        self.assertEqual(res.selected_tool, "vcf_list_hosts")

    def test_router_scope_denial(self):
        """Routing fails when query specifies a cluster outside the user's scope."""
        alice = self.idp.validate_bearer_token(self.alice_bearer)
        res = self.router.route_query(
            query="Power on VM vm-201 in cluster-prod-b",
            principal=alice,
            target_cluster="cluster-prod-b",
        )
        self.assertEqual(res.status, "ROUTE_UNCERTAIN")
        self.assertIn("Resource scope denial", res.reasoning)

    def test_router_safe_abstention_on_ambiguity(self):
        """Off-topic queries safely abstain rather than triggering unrelated tools."""
        alice = self.idp.validate_bearer_token(self.alice_bearer)
        res = self.router.route_query(
            query="Translate this poem into Latin",
            principal=alice,
        )
        self.assertEqual(res.status, "ROUTE_UNCERTAIN")


if __name__ == "__main__":
    unittest.main()
