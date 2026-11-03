# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Tests for KnownIssueRegistry execution checks and mutation blocking (P2-3).
Verifies that VENDOR_CONFIRMED issues with blocks_mutation=True prevent live mutations.
"""

from tests.fixtures.authorized_execution import execute_authorized
import unittest
from vcf_enterprise_mcp.router.known_issues import (
    KnownIssue,
    KnownIssueRegistry,
    IssueSource,
    ConfidenceClass,
)
from vcf_enterprise_mcp.tools.operational_tools import VCFPowerVMTool, VCFResizeVMTool
from vcf_enterprise_mcp.tools.query_tools import VCFGetVMTool
from vcf_enterprise_mcp.core.errors import KnownIssueBlockedException
from vcf_enterprise_mcp.auth.identity import Principal
from vcf_enterprise_mcp.state.sqlite_store import SQLiteDurableStore
from vcf_enterprise_mcp.adapter.platform import PlatformClient, PlatformMode
from vcf_enterprise_mcp.adapter.version_adapter import VCFVersionAdapter
from vcf_enterprise_mcp.policy.enforcement import PolicyEnforcementPoint
from vcf_enterprise_mcp.policy.engine import PolicyDecisionPoint
from vcf_enterprise_mcp.config.settings import PolicyConfig


class TestKnownIssuesEnforcement(unittest.TestCase):
    """Test suite ensuring known Broadcom issues guard live mutating operations."""

    def setUp(self):
        self.store = SQLiteDurableStore(":memory:")
        self.registry = KnownIssueRegistry()
        self.version_adapter = VCFVersionAdapter("9.1.1")
        self.platform = PlatformClient(
            mode=PlatformMode.UNIT_TEST,
            version_adapter=self.version_adapter,
        )
        self.pdp = PolicyDecisionPoint(PolicyConfig(operating_mode="AUDITED_OPERATIONS"))
        self.pep = PolicyEnforcementPoint(self.pdp)
        self.operator = Principal(
            user_id="operator-bob",
            tenant_id="tenant-prod",
            corporate_groups=["VCF-Platform-Admins"],
            roles=["Operator"],
            environment_ids=["env-prod"],
            allowed_clusters=["*"],
            allowed_domains=["*"],
        )

    def test_vendor_confirmed_blocking_issue_halts_mutation(self):
        """Verifies a VENDOR_CONFIRMED issue with blocks_mutation=True blocks power_vm."""
        blocking_issue = KnownIssue(
            id="VCF-91-VC-CRIT-01",
            component="vcenter",
            title="Critical VM power state deadlock on ESXi 8.0 Update 3",
            affected_versions=["9.1.1"],
            fixed_versions=["9.1.2"],
            trigger={"action": "power"},
            symptoms=["Host disconnect during power state transition"],
            workaround={"description": "Upgrade host to ESXi 8.0 U3b patch before power actions"},
            source=IssueSource(source_type="BROADCOM_KB", source_id="KB-991823", verified_at="2026-09-24"),
            confidence=ConfidenceClass.VENDOR_CONFIRMED,
            blocks_mutation=True,
        )
        self.registry.register(blocking_issue)

        tool = VCFPowerVMTool(
            pep=self.pep,
            durable_store=self.store,
            platform_client=self.platform,
            known_issue_registry=self.registry,
        )

        import asyncio
        with self.assertRaises(KnownIssueBlockedException) as ctx:
            asyncio.run(execute_authorized(tool,
                principal=self.operator,
                arguments={"vm_id": "vm-prod-101", "action": "start"},
            ))

        self.assertIn("VCF-91-VC-CRIT-01", str(ctx.exception))
        self.assertIn("Critical VM power state deadlock", str(ctx.exception))
        self.assertEqual(ctx.exception.details["source"], "KB-991823")
        self.assertEqual(ctx.exception.details["confidence"], "VENDOR_CONFIRMED")

    def test_fixed_version_permits_mutation(self):
        """Verifies upgrading the component to a fixed version allows execution to proceed."""
        blocking_issue = KnownIssue(
            id="VCF-91-VC-CRIT-02",
            component="vcenter",
            title="Memory resize failure on vCenter 9.0.0",
            affected_versions=["9.0.0"],
            fixed_versions=["9.0.1", "9.1.0", "9.1.1"],
            trigger={"action": "resize"},
            symptoms=["Memory allocation dropped"],
            workaround={"description": "Update vCenter to 9.0.1"},
            source=IssueSource(source_type="BROADCOM_KB", source_id="KB-882190", verified_at="2025-08-10"),
            confidence=ConfidenceClass.VENDOR_CONFIRMED,
            blocks_mutation=True,
        )
        self.registry.register(blocking_issue)

        # Active version is 9.1.1 (a fixed version)
        self.version_adapter.set_component_version("vcenter", "9.1.1")

        tool = VCFResizeVMTool(
            pep=self.pep,
            durable_store=self.store,
            platform_client=self.platform,
            known_issue_registry=self.registry,
        )

        import asyncio
        res = asyncio.run(execute_authorized(tool,
            principal=self.operator,
            arguments={"vm_id": "vm-prod-101", "memory_gb": 16},
        ))
        self.assertEqual(res["status"], "SUCCESS")

    def test_non_blocking_issue_allows_mutation(self):
        """Verifies issue with blocks_mutation=False (advisory/telemetry) does not halt mutation."""
        advisory_issue = KnownIssue(
            id="VCF-91-VC-ADV-01",
            component="vcenter",
            title="Minor UI latency during snapshot operations",
            affected_versions=["9.1.1"],
            fixed_versions=[],
            trigger={"action": "start"},
            symptoms=["UI spinner delays"],
            workaround={"description": "Ignore cosmetic delay"},
            source=IssueSource(source_type="RELEASE_NOTE", source_id="RN-2026-09", verified_at="2026-09-01"),
            confidence=ConfidenceClass.VENDOR_CONFIRMED,
            blocks_mutation=False,
        )
        self.registry.register(advisory_issue)

        tool = VCFPowerVMTool(
            pep=self.pep,
            durable_store=self.store,
            platform_client=self.platform,
            known_issue_registry=self.registry,
        )

        import asyncio
        res = asyncio.run(execute_authorized(tool,
            principal=self.operator,
            arguments={"vm_id": "vm-prod-101", "action": "start"},
        ))
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["new_power_state"], "POWERED_ON")

    def test_experimental_issue_does_not_block_without_flag(self):
        """Verifies OBSERVED or EXPERIMENTAL issue does not block execution by default."""
        experimental_issue = KnownIssue(
            id="VCF-91-EXP-01",
            component="vcenter",
            title="Unconfirmed community report of vMotion pause",
            affected_versions=["9.1.1"],
            fixed_versions=[],
            trigger={"action": "start"},
            symptoms=["Transient pause"],
            workaround={"description": "None"},
            source=IssueSource(source_type="TELEMETRY", source_id="COMM-102", verified_at="2026-09-15"),
            confidence=ConfidenceClass.EXPERIMENTAL,
            blocks_mutation=True,  # Declared with blocks_mutation, but confidence is EXPERIMENTAL
        )
        self.registry.register(experimental_issue)

        tool = VCFPowerVMTool(
            pep=self.pep,
            durable_store=self.store,
            platform_client=self.platform,
            known_issue_registry=self.registry,
        )

        import asyncio
        res = asyncio.run(execute_authorized(tool,
            principal=self.operator,
            arguments={"vm_id": "vm-prod-101", "action": "start"},
        ))
        self.assertEqual(res["status"], "SUCCESS")

    def test_read_query_tools_never_blocked_by_mutation_issues(self):
        """Verifies read-only query tools (RiskClass.READ) are never blocked by mutation-blocking issues."""
        blocking_issue = KnownIssue(
            id="VCF-91-VC-READ-SAFETY",
            component="vcenter",
            title="Critical VM power state deadlock",
            affected_versions=["9.1.1"],
            fixed_versions=[],
            trigger={},  # Matches any trigger
            symptoms=["Host lock"],
            workaround={"description": "Avoid changes"},
            source=IssueSource(source_type="BROADCOM_KB", source_id="KB-991823", verified_at="2026-09-24"),
            confidence=ConfidenceClass.VENDOR_CONFIRMED,
            blocks_mutation=True,
        )
        self.registry.register(blocking_issue)

        query_tool = VCFGetVMTool(
            pep=self.pep,
            durable_store=self.store,
            platform_client=self.platform,
            known_issue_registry=self.registry,
        )

        import asyncio
        res = asyncio.run(execute_authorized(query_tool,
            principal=self.operator,
            arguments={"vm_id": "vm-101"},
        ))
        self.assertIn("vm_id", res)


if __name__ == "__main__":
    unittest.main()
