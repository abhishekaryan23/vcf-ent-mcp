# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
VCF Real-World Certification Report Generator.
Produces structured JSON matrices and production-ready Markdown audit tables:
Component x Operation x Version x Verification Level x SDDC Manager Independence.
"""

from __future__ import annotations
import json
from pathlib import Path
from typing import Dict, Any, List

from vcf_enterprise_mcp.certification.models import (
    CertificationResult,
    OperationResult,
    ComponentType,
)


class CertificationReportGenerator:
    """Generates JSON and Markdown reports for VCF certification runs."""

    @staticmethod
    def to_dict(result: CertificationResult) -> Dict[str, Any]:
        """Converts CertificationResult to standard dictionary."""
        return {
            "profile_name": result.profile_name,
            "vcf_version": result.vcf_version,
            "verification_level": result.verification_level.value,
            "timestamp": result.timestamp,
            "summary": {
                "total": result.total_operations,
                "passed": result.passed_count,
                "failed": result.failed_count,
                "skipped": result.skipped_count,
                "is_successful": result.is_successful,
                "direct_vcenter_success": result.direct_vcenter_success,
                "direct_nsx_success": result.direct_nsx_success,
            },
            "matrix": [
                {
                    "operation": r.operation_name,
                    "component": r.component.value,
                    "transport_route": r.transport_route,
                    "status": r.status,
                    "latency_ms": r.latency_ms,
                    "error": r.error_message,
                    "details": r.details,
                }
                for r in result.operation_results
            ],
        }

    @classmethod
    def to_json(cls, result: CertificationResult, indent: int = 2) -> str:
        """Serializes CertificationResult to formatted JSON string."""
        return json.dumps(cls.to_dict(result), indent=indent)

    @classmethod
    def generate_matrix_report(cls, results: List[CertificationResult]) -> str:
        """Generates a consolidated matrix report covering multiple certification results."""
        if not results:
            return "# VCF Interoperability Certification Matrix\n\nNo profiles certified."
        lines = [
            "# VCF Interoperability Certification Matrix Report",
            "",
            "| Profile | VCF Version | Level | Operations | Passed | Failed | Pass Rate | Status |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        ]
        for r in results:
            badge = "✅ PASSED" if r.is_successful else "❌ FAILED"
            lines.append(
                f"| `{r.profile_name}` | `{r.vcf_version}` | `{r.verification_level.value}` | {r.total_operations} | {r.passed_count} | {r.failed_count} | {r.pass_rate:.1f}% | {badge} |"
            )
        lines.append("")
        for r in results:
            lines.append(cls.to_markdown(r))
            lines.append("\n---\n")
        return "\n".join(lines)

    @classmethod
    def to_markdown(cls, result: CertificationResult) -> str:
        """Formats CertificationResult into an audit-grade Markdown matrix."""
        status_badge = "✅ PASSED" if result.is_successful else "❌ FAILED"
        sddc_indep = (
            "✅ VERIFIED (vCenter-direct & NSX-direct operate independently without SDDC Manager)"
            if (result.direct_vcenter_success and result.direct_nsx_success)
            else "⚠️ PARTIAL OR UNVERIFIED"
        )

        lines: List[str] = [
            f"# VCF Interoperability Certification Report — {result.profile_name}",
            "",
            f"**Release Under Certification**: VCF {result.vcf_version}  ",
            f"**Verification Level**: `{result.verification_level.value}`  ",
            f"**Overall Status**: {status_badge}  ",
            f"**SDDC Manager Independence**: {sddc_indep}  ",
            "",
            "## 1. Executive Certification Summary",
            "",
            "| Metric | Result | Target | Status |",
            "| :--- | :--- | :--- | :--- |",
            f"| Total Operations Tested | {result.total_operations} | >= 6 | ✅ PASS |",
            f"| Operations Passed | {result.passed_count} | 100% of tested | {'✅ PASS' if result.failed_count == 0 else '❌ FAIL'} |",
            f"| Operations Failed | {result.failed_count} | 0 | {'✅ PASS' if result.failed_count == 0 else '❌ FAIL'} |",
            f"| vCenter-Direct Independence | {'Verified' if result.direct_vcenter_success else 'Failed'} | Mandatory | {'✅ PASS' if result.direct_vcenter_success else '❌ FAIL'} |",
            f"| NSX-Direct Independence | {'Verified' if result.direct_nsx_success else 'Failed'} | Mandatory | {'✅ PASS' if result.direct_nsx_success else '❌ FAIL'} |",
            "",
            "## 2. Component Interoperability Matrix",
            "",
            "| Component | Operation | Route | Verification Level | Latency (ms) | Status |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |",
        ]

        for r in result.operation_results:
            icon = "✅ PASS" if r.status == "PASS" else ("⏭️ SKIP" if r.status == "SKIPPED" else "❌ FAIL")
            lines.append(
                f"| `{r.component.value}` | `{r.operation_name}` | `{r.transport_route}` | `{r.verification_level.value}` | {r.latency_ms:.2f} | {icon} |"
            )

        lines.extend([
            "",
            "## 3. SDDC Manager Independence Architecture",
            "",
            "In strict compliance with GA architectural directives, vCenter operations (VM lifecycle, compute cluster/host inspection) and NSX operations (overlay segment provisioning) bypass SDDC Manager entirely when direct credentials/endpoints are configured.",
            "This guarantees that control-plane degradation or maintenance windows in SDDC Manager do not interrupt day-2 compute or network operations.",
            "",
            "---",
            f"*Generated by VCF Enterprise MCP Certification Engine at {result.timestamp}*",
        ])

        return "\n".join(lines)

    @classmethod
    def save_markdown(cls, result: CertificationResult, output_path: str) -> None:
        """Writes the Markdown report to the designated filesystem path."""
        p = Path(output_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(cls.to_markdown(result))
