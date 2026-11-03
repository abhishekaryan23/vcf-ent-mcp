# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Known-Issue Knowledge Base with Source Provenance and Confidence Classes.
Tracks Broadcom KBs, CVEs, and observed defects across VCF 9.x baselines.
Enforces that only VENDOR_CONFIRMED issues automatically alter safety or routing behavior.
"""

from __future__ import annotations
from enum import Enum
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field


class ConfidenceClass(str, Enum):
    VENDOR_CONFIRMED = "VENDOR_CONFIRMED"  # Official Broadcom KB / Release Note
    OBSERVED = "OBSERVED"                  # Empirically observed in lab / telemetry
    EXPERIMENTAL = "EXPERIMENTAL"          # Community or proactive speculative rule


@dataclass
class IssueSource:
    source_type: str  # "BROADCOM_KB", "RELEASE_NOTE", "CVE", "TELEMETRY"
    source_id: str    # e.g. "KB-94821", "CVE-2026-3128"
    verified_at: str  # ISO-8601 date e.g. "2026-09-20"


@dataclass
class KnownIssue:
    id: str
    component: str  # "sddc_manager", "vcenter", "nsx", "vcf_operations", "vsan"
    title: str
    affected_versions: List[str]
    fixed_versions: List[str]
    trigger: Dict[str, Any]
    symptoms: List[str]
    workaround: Dict[str, Any]
    source: IssueSource
    confidence: ConfidenceClass
    blocks_mutation: bool = False

    def is_applicable(self, component: str, version: str) -> bool:
        if self.component != component and self.component != "all":
            return False
        if version in self.fixed_versions:
            return False
        return version in self.affected_versions or "all" in self.affected_versions

    def should_block_operation(self, allow_experimental: bool = False) -> bool:
        if not self.blocks_mutation:
            return False
        if self.confidence == ConfidenceClass.VENDOR_CONFIRMED:
            return True
        return allow_experimental and self.confidence in [ConfidenceClass.OBSERVED, ConfidenceClass.EXPERIMENTAL]

    def matches_trigger(self, tool_name: str, arguments: Optional[Dict[str, Any]] = None) -> bool:
        """
        Determines whether the operational context matches the issue trigger specifications.
        Returns True if all declared trigger predicates are satisfied.
        """
        if not self.trigger:
            return True
        args = arguments or {}
        for k, v in self.trigger.items():
            if k in ("tool", "tool_name"):
                if v != tool_name:
                    return False
            elif k == "action":
                arg_action = args.get("action")
                if arg_action:
                    if v != arg_action and v not in tool_name:
                        return False
                else:
                    if v not in tool_name:
                        return False
            else:
                # Specific argument match
                if k in args and args[k] != v:
                    return False
        return True


class KnownIssueRegistry:
    """Registry of known issues with provenance and automated guardrails."""

    def __init__(self):
        self._issues: Dict[str, KnownIssue] = {}
        self._seed_default_issues()

    def register(self, issue: KnownIssue) -> None:
        self._issues[issue.id] = issue

    def get_issue(self, issue_id: str) -> Optional[KnownIssue]:
        return self._issues.get(issue_id)

    def find_issues(self, component: str, version: str) -> List[KnownIssue]:
        return [
            iss for iss in self._issues.values()
            if iss.is_applicable(component, version)
        ]

    def check_operation_safety(
        self,
        component: str,
        version: str,
        tool_name: str,
        arguments: Optional[Dict[str, Any]] = None,
        allow_experimental: bool = False,
    ) -> List[KnownIssue]:
        """
        Evaluates known issues against the requested operation and returns any
        applicable issues that block execution.
        """
        args = arguments or {}
        blocking = []
        for issue in self.find_issues(component, version):
            if issue.should_block_operation(allow_experimental=allow_experimental):
                if issue.matches_trigger(tool_name, args):
                    blocking.append(issue)
        return blocking

    def _seed_default_issues(self) -> None:
        # Issue 1: ESXi 8.x network connection list under memory constraints (Broadcom KB 391821)
        self.register(KnownIssue(
            id="ESXI-80-NET-391821",
            component="esxi",
            title="esxcli network ip connection list fails under host memory constraints",
            affected_versions=["8.0", "8.0.0", "8.0.1", "8.0.2", "8.0.3"],
            fixed_versions=[],
            trigger={"command": "esxcli_network_ip_connection_list"},
            symptoms=["esxcli network connection listing fails with memory allocation error"],
            workaround={"description": "Reduce host memory pressure by migrating or powering off non-essential virtual machines"},
            source=IssueSource(source_type="BROADCOM_KB", source_id="KB-391821", verified_at="2026-09-26"),
            confidence=ConfidenceClass.VENDOR_CONFIRMED,
            blocks_mutation=False,
        ))

        # Issue 2: vSAN ESA memory allocation anomaly under heavy NVMe scrub (Unverified Community Seed)
        self.register(KnownIssue(
            id="VCF-91-VSAN-4491",
            component="vsan",
            title="vSAN ESA transient memory alert during deep scrubbing",
            affected_versions=["9.1.0"],
            fixed_versions=["9.1.1"],
            trigger={"metric": "scrub_active"},
            symptoms=["Transient high memory usage alarm on ESA storage nodes"],
            workaround={"description": "Cosmetic reporting anomaly; throttle scrub rate in vCenter"},
            source=IssueSource(source_type="BROADCOM_KB", source_id="KB-419820", verified_at="2026-06-12"),
            confidence=ConfidenceClass.OBSERVED,
            blocks_mutation=False,
        ))

        # Issue 3: VCF 9.1 / NSX VIP certificate missing SAN during upgrade precheck (Broadcom KB 440910)
        self.register(KnownIssue(
            id="VCF-91-NSX-440910",
            component="nsx",
            title="NSX VIP certificate lacks Subject Alternative Name (SAN) during planning precheck",
            affected_versions=["9.1.0", "9.1.1"],
            fixed_versions=[],
            trigger={"action": "upgrade", "precheck": True, "certificate_missing_san": True},
            symptoms=["NSX planning precheck fails validation before domain upgrade"],
            workaround={"description": "Manual administrative review: Reissue NSX VIP certificate with required FQDN and IP SAN entries before retrying upgrade precheck"},
            source=IssueSource(source_type="BROADCOM_KB", source_id="KB-440910", verified_at="2026-09-26"),
            confidence=ConfidenceClass.VENDOR_CONFIRMED,
            blocks_mutation=True,
        ))

        # Issue 4: VCF 9.1 component upgrade ordering violation (Broadcom KB 440630)
        self.register(KnownIssue(
            id="VCF-91-LCM-440630",
            component="sddc_manager",
            title="VCF 9.1 upgrade component execution sequence out-of-order",
            affected_versions=["9.1.0"],
            fixed_versions=["9.1.1"],
            trigger={"action": "upgrade", "out_of_order": True},
            symptoms=["Domain upgrade fails or leaves management services in degraded state"],
            workaround={"description": "Follow strict component upgrade order including Management Services first"},
            source=IssueSource(source_type="BROADCOM_KB", source_id="KB-440630", verified_at="2026-09-25"),
            confidence=ConfidenceClass.VENDOR_CONFIRMED,
            blocks_mutation=True,
        ))

        # Issue 5: Experimental observation
        self.register(KnownIssue(
            id="VCF-91-NSX-EXP-01",
            component="nsx",
            title="High packet drops observed during BGP graceful restart testing in lab",
            affected_versions=["9.1.1"],
            fixed_versions=[],
            trigger={"bgp_graceful_restart": True},
            symptoms=["Packet drops on Tier-0 edge uplink"],
            workaround={"description": "Use static BFD timers"},
            source=IssueSource(source_type="TELEMETRY", source_id="LAB-EXP-902", verified_at="2026-09-18"),
            confidence=ConfidenceClass.OBSERVED,
            blocks_mutation=False,
        ))
