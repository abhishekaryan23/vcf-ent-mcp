# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Unit Tests for Corporate IdP Claims, Capability Role Overlays, and the PDP Intersection Formula.
Runs in-memory with zero external test runner dependencies (uses standard library unittest).
"""

from __future__ import annotations
import sys
import os
import unittest

# Ensure src is in sys.path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC_DIR = os.path.join(BASE_DIR, "src")
sys.path.insert(0, SRC_DIR)

from vcf_enterprise_mcp.auth.identity import Principal
from vcf_enterprise_mcp.auth.idp import EnterpriseIdPValidator
from vcf_enterprise_mcp.policy.models import RiskClass, CapabilityRole, ResourceScope
from vcf_enterprise_mcp.policy.engine import PolicyDecisionPoint
from vcf_enterprise_mcp.config.settings import PolicyConfig


class TestIdentityAndPDPIntersection(unittest.TestCase):
    """Validates that Effective Permission = Corporate Identity ∩ VCF entitlement ∩ MCP policy ∩ Resource scope."""

    def setUp(self):
        self.idp = EnterpriseIdPValidator()
        self.pdp = PolicyDecisionPoint(PolicyConfig(operating_mode="FULL_ENFORCEMENT"))

    def test_idp_token_claim_mapping(self):
        """Verifies parsing of corporate Bearer tokens into verified Principal claims."""
        from tests.fixtures.test_tokens import ALICE_BEARER, BOB_BEARER, ADMIN_BEARER
        from vcf_enterprise_mcp.core.errors import AuthorizationDeniedException
        # Alice: Compute Operator
        alice = self.idp.validate_bearer_token(ALICE_BEARER)
        self.assertEqual(alice.user_id, "alice@corp.com")
        self.assertIn("VCF-Compute-Operators", alice.corporate_groups)
        self.assertEqual(alice.allowed_clusters, ["cluster-prod-a"])

        # Bob: Network Operator
        bob = self.idp.validate_bearer_token(BOB_BEARER)
        self.assertEqual(bob.user_id, "bob@corp.com")
        self.assertIn("VCF-Network-Operators", bob.corporate_groups)

        # Anonymous Guest denied by default
        with self.assertRaises(AuthorizationDeniedException):
            self.idp.validate_bearer_token(None)

        # Anonymous allowed ONLY when explicitly enabled in non-production environment
        from vcf_enterprise_mcp.config.settings import IdPConfig
        dev_idp = EnterpriseIdPValidator(config=IdPConfig(allow_anonymous=True))
        guest = dev_idp.validate_bearer_token(None)
        self.assertEqual(guest.user_id, "anonymous@corp.local")
        self.assertIn("VCF-Guest-ReadOnly", guest.corporate_groups)

    def test_pdp_role_overlay_mapping(self):
        """Verifies mapping of corporate directory groups to restrictive overlay capability roles."""
        from tests.fixtures.test_tokens import ALICE_BEARER
        alice = self.idp.validate_bearer_token(ALICE_BEARER)
        roles = self.pdp.get_effective_roles_for_principal(alice)
        self.assertIn(CapabilityRole.COMPUTE_OPERATOR, roles)
        self.assertIn(CapabilityRole.VCF_VIEWER, roles)
        self.assertNotIn(CapabilityRole.NETWORK_ADMIN, roles)

    def test_pdp_intersection_allowed_in_scope(self):
        """Alice can resize a VM in cluster-prod-a."""
        from tests.fixtures.test_tokens import ALICE_BEARER
        alice = self.idp.validate_bearer_token(ALICE_BEARER)
        decision = self.pdp.evaluate_request(
            principal=alice,
            tool_name="vcf_resize_vm",
            risk_class=RiskClass.CHANGE,
            required_roles=[CapabilityRole.COMPUTE_OPERATOR],
            target_resource={"cluster_id": "cluster-prod-a", "domain_id": "wld-app-a"},
        )
        self.assertTrue(decision.allow)
        self.assertIn("Authorized under policy intersection", decision.reason)

    def test_pdp_intersection_denied_out_of_scope(self):
        """Alice CANNOT resize a VM in cluster-prod-b (Resource scope boundary enforcement)."""
        from tests.fixtures.test_tokens import ALICE_BEARER, ADMIN_BEARER
        alice = self.idp.validate_bearer_token(ALICE_BEARER)
        decision = self.pdp.evaluate_request(
            principal=alice,
            tool_name="vcf_resize_vm",
            risk_class=RiskClass.CHANGE,
            required_roles=[CapabilityRole.COMPUTE_OPERATOR],
            target_resource={"cluster_id": "cluster-prod-b", "domain_id": "wld-app-b"},
        )
        self.assertFalse(decision.allow)
        self.assertIn("Resource scope violation", decision.reason)

    def test_pdp_intersection_denied_insufficient_role(self):
        """Alice (Compute Operator) CANNOT create an NSX network segment (requires NETWORK_ADMIN)."""
        from tests.fixtures.test_tokens import ALICE_BEARER
        alice = self.idp.validate_bearer_token(ALICE_BEARER)
        decision = self.pdp.evaluate_request(
            principal=alice,
            tool_name="vcf_create_nsx_segment",
            risk_class=RiskClass.CHANGE,
            required_roles=[CapabilityRole.NETWORK_ADMIN],
            target_resource={"cluster_id": "cluster-prod-a"},
        )
        self.assertFalse(decision.allow)
        self.assertIn("lacks required capability role", decision.reason)

    def test_pdp_discovery_only_mode_blocks_mutations(self):
        """When in DISCOVERY_ONLY mode, all mutations are blocked regardless of roles."""
        from tests.fixtures.test_tokens import ADMIN_BEARER
        discovery_pdp = PolicyDecisionPoint(PolicyConfig(operating_mode="DISCOVERY_ONLY"))
        admin = self.idp.validate_bearer_token(ADMIN_BEARER)

        # Read operation is allowed
        read_dec = discovery_pdp.evaluate_request(
            principal=admin,
            tool_name="vcf_list_vms",
            risk_class=RiskClass.READ,
            required_roles=[CapabilityRole.VCF_VIEWER],
        )
        self.assertTrue(read_dec.allow)

        # Mutating operation is blocked
        write_dec = discovery_pdp.evaluate_request(
            principal=admin,
            tool_name="vcf_power_vm",
            risk_class=RiskClass.SAFE_WRITE,
            required_roles=[CapabilityRole.COMPUTE_OPERATOR],
            target_resource={"cluster_id": "cluster-prod-a"},
        )
        self.assertFalse(write_dec.allow)
        self.assertIn("Control Plane is in DISCOVERY_ONLY mode", write_dec.reason)


if __name__ == "__main__":
    unittest.main()
