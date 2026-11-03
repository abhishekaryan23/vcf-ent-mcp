# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Unit & Security Regression Tests for Mandatory KMS Signature Verification (Item 5, P0-5).
Verifies that the live execution gate unconditionally validates cryptographic KMS signatures,
rejects forged/tampered signatures, detects argument tampering and TOCTOU revision changes,
enforces expiration and permission epochs, and blocks replay attacks.
"""

import time
import pytest
import unittest
from vcf_enterprise_mcp.auth.identity import Principal
from vcf_enterprise_mcp.auth.kms import LocalKMSKeyManager
from vcf_enterprise_mcp.state.sqlite_store import SQLiteDurableStore
from vcf_enterprise_mcp.policy.models import RiskClass, CapabilityRole
from vcf_enterprise_mcp.config.settings import PolicyConfig
from vcf_enterprise_mcp.policy.engine import PolicyDecisionPoint
from vcf_enterprise_mcp.policy.enforcement import PolicyEnforcementPoint
from vcf_enterprise_mcp.workflows.execution_plans import ExecutionPlanManager, SignedExecutionAuthorization
from vcf_enterprise_mcp.core.errors import (
    AuthorizationDeniedException,
    PlanStaleException,
    ApprovalRequiredException,
    VCFEnterpriseException,
)
from vcf_enterprise_mcp.tools.base import BaseEnterpriseTool


class MockPlatform:
    def __init__(self):
        self._revisions = {
            "cluster-prod-a": "rev-100",
            "vm-101": "rev-201",
            "mgmt-domain": "rev-501",
        }

    def get_resource_revision(self, rid: str) -> str:
        return self._revisions.get(rid, "rev-100")

    def bump_revision(self, rid: str, new_rev: str) -> None:
        self._revisions[rid] = new_rev


class HighImpactMutatingTool(BaseEnterpriseTool):
    name = "vcf_upgrade_domain"
    level = "L3_MUTATE"
    risk_class = RiskClass.HIGH_IMPACT
    required_roles = [CapabilityRole.LIFECYCLE_ADMIN]

    async def _execute_live(self, principal: Principal, arguments: dict, agent_info=None, trace_id=None):
        return {"status": "SUCCESS", "domain_id": arguments.get("domain_id")}


class TestKMSSignatureEnforcement(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.durable = SQLiteDurableStore(db_path=":memory:")
        self.kms = LocalKMSKeyManager(master_secret="test-kms-master-secret-00000000000")
        self.platform = MockPlatform()
        self.plan_mgr = ExecutionPlanManager(
            durable_store=self.durable,
            platform_client=self.platform,
            tenant_id="tenant-acme",
            environment_id="env-prod",
            kms_manager=self.kms,
        )

        self.alice_operator = Principal(
            user_id="alice@corp.com",
            tenant_id="tenant-acme",
            environment_ids=("env-prod",),
            roles=[CapabilityRole.LIFECYCLE_OPERATOR, CapabilityRole.LIFECYCLE_ADMIN],
            corporate_groups=["corp-cloud-admins"],
            allowed_domains=["*"],
            allowed_clusters=["*"],
        )
        self.bob_approver = Principal(
            user_id="bob@corp.com",
            tenant_id="tenant-acme",
            environment_ids=("env-prod",),
            roles=[CapabilityRole.LIFECYCLE_ADMIN],
            corporate_groups=["VCF-Platform-Admins", "VCF-Lifecycle-Admins"],
            allowed_domains=["*"],
            allowed_clusters=["*"],
        )

    def _create_and_approve_standard_plan(self):
        plan = self.plan_mgr.create_dry_run_plan(
            principal=self.alice_operator,
            tool_id="vcf_upgrade_domain",
            arguments={"domain_id": "mgmt-domain"},
            impact_summary={"approvals_required": 1, "risk_class": "HIGH_IMPACT"},
            target_resource_ids=["mgmt-domain"],
        )
        signed_auth = self.plan_mgr.approve_plan(plan["plan_id"], approver=self.bob_approver)
        return plan, signed_auth

    def test_valid_signature_execution_succeeds(self):
        """Legitimate execution with valid KMS-signed authorization succeeds."""
        plan, signed_auth = self._create_and_approve_standard_plan()

        validated_plan = self.plan_mgr.validate_plan_for_execution(
            plan_id=plan["plan_id"],
            approval_id=signed_auth.approval_id,
            nonce=signed_auth.nonce,
            current_arguments={"domain_id": "mgmt-domain"},
            caller=self.alice_operator,
        )
        self.assertEqual(validated_plan["plan_id"], plan["plan_id"])

    def test_missing_signature_rejected(self):
        """Approval record with missing or empty signature is strictly rejected."""
        plan, signed_auth = self._create_and_approve_standard_plan()

        # Corrupt stored approval in database to have an empty signature
        with self.durable._lock:
            cur = self.durable._conn.cursor()
            cur.execute(
                "UPDATE approvals SET signature = '' WHERE approval_id = ?",
                (signed_auth.approval_id,)
            )
            self.durable._conn.commit()

        with self.assertRaises(AuthorizationDeniedException) as ctx:
            self.plan_mgr.validate_plan_for_execution(
                plan_id=plan["plan_id"],
                approval_id=signed_auth.approval_id,
                nonce=signed_auth.nonce,
                current_arguments={"domain_id": "mgmt-domain"},
                caller=self.alice_operator,
            )
        self.assertIn("Cryptographic signature is missing", str(ctx.exception))

    def test_forged_kms_signature_rejected(self):
        """Tampered or forged cryptographic KMS signature is strictly rejected."""
        plan, signed_auth = self._create_and_approve_standard_plan()

        # Corrupt signature in database
        forged_sig = "deadbeef" * 8
        with self.durable._lock:
            cur = self.durable._conn.cursor()
            cur.execute(
                "UPDATE approvals SET signature = ? WHERE approval_id = ?",
                (forged_sig, signed_auth.approval_id)
            )
            self.durable._conn.commit()

        with self.assertRaises(AuthorizationDeniedException) as ctx:
            self.plan_mgr.validate_plan_for_execution(
                plan_id=plan["plan_id"],
                approval_id=signed_auth.approval_id,
                nonce=signed_auth.nonce,
                current_arguments={"domain_id": "mgmt-domain"},
                caller=self.alice_operator,
            )
        self.assertIn("Cryptographic signature verification failed", str(ctx.exception))

    def test_tampered_signed_auth_object_mismatch_rejected(self):
        """If caller passes a signed_auth object whose signature does not match stored record, reject."""
        plan, signed_auth = self._create_and_approve_standard_plan()

        tampered_auth = SignedExecutionAuthorization(
            approval_id=signed_auth.approval_id,
            plan_id=signed_auth.plan_id,
            approver=signed_auth.approver,
            nonce=signed_auth.nonce,
            issued_at=signed_auth.issued_at,
            expires_at=signed_auth.expires_at,
            permission_epoch=signed_auth.permission_epoch,
            canonical_plan_hash=signed_auth.canonical_plan_hash,
            signature="bad-forged-signature-0000000000",
            key_id=signed_auth.key_id,
        )

        with self.assertRaises(AuthorizationDeniedException) as ctx:
            self.plan_mgr.validate_plan_for_execution(
                plan_id=plan["plan_id"],
                approval_id=signed_auth.approval_id,
                nonce=signed_auth.nonce,
                current_arguments={"domain_id": "mgmt-domain"},
                caller=self.alice_operator,
                signed_auth=tampered_auth,
            )
        self.assertIn("Tampering detected", str(ctx.exception))

    def test_tampered_arguments_after_signing_rejected(self):
        """Changing mutation arguments after dry-run and approval triggers tampering detection."""
        plan, signed_auth = self._create_and_approve_standard_plan()

        # Caller tampers with argument (target domain altered)
        tampered_args = {"domain_id": "mgmt-domain-malicious"}
        with self.assertRaises(AuthorizationDeniedException) as ctx:
            self.plan_mgr.validate_plan_for_execution(
                plan_id=plan["plan_id"],
                approval_id=signed_auth.approval_id,
                nonce=signed_auth.nonce,
                current_arguments=tampered_args,
                caller=self.alice_operator,
            )
        self.assertIn("Tampering detected", str(ctx.exception))

    def test_resource_revision_change_triggers_toctou_plan_stale(self):
        """Resource state change between approval and execution triggers PlanStaleException."""
        plan, signed_auth = self._create_and_approve_standard_plan()

        # Out-of-band modification to resource
        self.platform.bump_revision("mgmt-domain", "rev-999-tampered")

        with self.assertRaises(PlanStaleException) as ctx:
            self.plan_mgr.validate_plan_for_execution(
                plan_id=plan["plan_id"],
                approval_id=signed_auth.approval_id,
                nonce=signed_auth.nonce,
                current_arguments={"domain_id": "mgmt-domain"},
                caller=self.alice_operator,
            )
        self.assertIn("TOCTOU violation", str(ctx.exception))
        self.assertIn("rev-999-tampered", str(ctx.exception))

    def test_expired_authorization_rejected(self):
        """Approval authorizations that have exceeded their TTL are rejected."""
        plan = self.plan_mgr.create_dry_run_plan(
            principal=self.alice_operator,
            tool_id="vcf_upgrade_domain",
            arguments={"domain_id": "mgmt-domain"},
            impact_summary={"approvals_required": 1, "risk_class": "HIGH_IMPACT"},
            target_resource_ids=["mgmt-domain"],
        )
        # Create approval with negative TTL so it is immediately expired
        signed_auth = self.plan_mgr.approve_plan(
            plan["plan_id"],
            approver=self.bob_approver,
            ttl_seconds=-10.0,
        )

        with self.assertRaises(AuthorizationDeniedException) as ctx:
            self.plan_mgr.validate_plan_for_execution(
                plan_id=plan["plan_id"],
                approval_id=signed_auth.approval_id,
                nonce=signed_auth.nonce,
                current_arguments={"domain_id": "mgmt-domain"},
                caller=self.alice_operator,
            )
        self.assertIn("has expired", str(ctx.exception))

    def test_revoked_permission_epoch_invalidates_authorization(self):
        """Revoking or bumping permission epoch invalidates all outstanding approved plans."""
        plan, signed_auth = self._create_and_approve_standard_plan()

        # Administrative security event bumps tenant permission epoch
        self.durable.bump_permission_epoch("tenant-acme", "env-prod")

        with self.assertRaises(AuthorizationDeniedException) as ctx:
            self.plan_mgr.validate_plan_for_execution(
                plan_id=plan["plan_id"],
                approval_id=signed_auth.approval_id,
                nonce=signed_auth.nonce,
                current_arguments={"domain_id": "mgmt-domain"},
                caller=self.alice_operator,
            )
        self.assertIn("Permission epoch changed", str(ctx.exception))

    def test_nonce_replay_rejected(self):
        """Single-use approval nonce cannot be reused (replay protection)."""
        plan, signed_auth = self._create_and_approve_standard_plan()

        # First execution succeeds
        self.plan_mgr.validate_plan_for_execution(
            plan_id=plan["plan_id"],
            approval_id=signed_auth.approval_id,
            nonce=signed_auth.nonce,
            current_arguments={"domain_id": "mgmt-domain"},
            caller=self.alice_operator,
        )

        # Second execution with same nonce MUST fail
        with self.assertRaises(AuthorizationDeniedException) as ctx:
            self.plan_mgr.validate_plan_for_execution(
                plan_id=plan["plan_id"],
                approval_id=signed_auth.approval_id,
                nonce=signed_auth.nonce,
                current_arguments={"domain_id": "mgmt-domain"},
                caller=self.alice_operator,
            )
        self.assertIn("already been consumed (replay rejected)", str(ctx.exception))

    def test_tool_binding_mismatch_rejected(self):
        """Plan created for tool A cannot be executed with tool B."""
        plan, signed_auth = self._create_and_approve_standard_plan()

        with self.assertRaises(AuthorizationDeniedException) as ctx:
            self.plan_mgr.validate_plan_for_execution(
                plan_id=plan["plan_id"],
                approval_id=signed_auth.approval_id,
                nonce=signed_auth.nonce,
                current_arguments={"domain_id": "mgmt-domain"},
                caller=self.alice_operator,
                expected_tool_id="vcf_resize_vm",
            )
        self.assertIn("Tool mismatch", str(ctx.exception))

    def test_missing_execution_parameters_rejected(self):
        """Calling validation with missing plan_id, approval_id, or nonce raises explicit error."""
        with self.assertRaises(VCFEnterpriseException):
            self.plan_mgr.validate_plan_for_execution(
                plan_id="",
                approval_id="appr-123",
                nonce="nonce-123",
                current_arguments={},
                caller=self.alice_operator,
            )

        with self.assertRaises(AuthorizationDeniedException):
            self.plan_mgr.validate_plan_for_execution(
                plan_id="plan-123",
                approval_id="",
                nonce="nonce-123",
                current_arguments={},
                caller=self.alice_operator,
            )

        with self.assertRaises(AuthorizationDeniedException):
            self.plan_mgr.validate_plan_for_execution(
                plan_id="plan-123",
                approval_id="appr-123",
                nonce="",
                current_arguments={},
                caller=self.alice_operator,
            )

    async def test_base_tool_live_execution_requires_approval_parameters(self):
        """BaseEnterpriseTool enforces approval_id, plan_id, and nonce on mutating live operations."""
        config = PolicyConfig(
            operating_mode="FULL_ENFORCEMENT",
            require_approval_for_high_impact=True,
        )
        pdp = PolicyDecisionPoint(config=config, durable_store=self.durable)
        pep = PolicyEnforcementPoint(pdp=pdp)
        tool = HighImpactMutatingTool(
            pep=pep,
            durable_store=self.durable,
            plan_manager=self.plan_mgr,
            tenant_id="tenant-acme",
        )

        # Attempting live execution without plan_id, approval_id, nonce must raise ApprovalRequiredException
        with self.assertRaises(ApprovalRequiredException) as ctx:
            await tool.execute(
                principal=self.alice_operator,
                arguments={"domain_id": "mgmt-domain", "target_version": "9.1.1", "dry_run": False},
            )
        self.assertIn("Approval Required", str(ctx.exception))
