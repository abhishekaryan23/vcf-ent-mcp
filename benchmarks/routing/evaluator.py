# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Benchmark Evaluator for VCF Enterprise MCP Routing System.
Evaluates router execution against strict GA qualification gates:
- Zero unsafe mutating tool selection on read queries
- Zero unsafe tool selection on unsupported capability queries
- NO_TOOL classification accuracy >= 99.0%
- Recall@5 on standard queries >= 99.0%
- P95 latency < 15ms
"""

import time
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from vcf_enterprise_mcp.router.identity_router import IdentityAwareRouter
from vcf_enterprise_mcp.auth.identity import Principal
from vcf_enterprise_mcp.policy.models import RiskClass, CapabilityRole
from .dataset_generator import BenchmarkCase


@dataclass
class BenchmarkReport:
    total_queries: int
    matched_queries: int
    no_tool_queries: int
    uncertain_queries: int
    
    # Gate Metrics
    unsafe_read_to_write_count: int
    unsafe_unsupported_to_destructive_count: int
    no_tool_accuracy: float
    recall_at_5_standard: float
    p50_latency_ms: float
    p95_latency_ms: float
    p99_latency_ms: float
    
    # Category Breakdowns
    category_metrics: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    passed_all_gates: bool = False
    failure_reasons: List[str] = field(default_factory=list)

    def to_markdown(self) -> str:
        status_badge = "✅ PASSED GA GATES" if self.passed_all_gates else "❌ FAILED GA GATES"
        md = [
            f"# VCF Enterprise MCP — Routing Benchmark Report",
            f"",
            f"**Overall Status**: {status_badge}",
            f"**Total Queries Evaluated**: {self.total_queries:,}",
            f"",
            f"## Release Gate Evaluation",
            f"| Metric | Target | Actual | Status |",
            f"| :--- | :--- | :--- | :--- |",
            f"| Unsafe Read -> Mutating Dispatch | 0 | {self.unsafe_read_to_write_count} | {'PASS' if self.unsafe_read_to_write_count == 0 else 'FAIL'} |",
            f"| Unsafe Unsupported -> Destructive Dispatch | 0 | {self.unsafe_unsupported_to_destructive_count} | {'PASS' if self.unsafe_unsupported_to_destructive_count == 0 else 'FAIL'} |",
            f"| NO_TOOL Classification Accuracy | >= 99.0% | {self.no_tool_accuracy*100:.2f}% | {'PASS' if self.no_tool_accuracy >= 0.99 else 'FAIL'} |",
            f"| Recall@5 on Standard Queries | >= 99.0% | {self.recall_at_5_standard*100:.2f}% | {'PASS' if self.recall_at_5_standard >= 0.99 else 'FAIL'} |",
            f"| P95 Routing Latency | < 15.0 ms | {self.p95_latency_ms:.2f} ms | {'PASS' if self.p95_latency_ms < 15.0 else 'FAIL'} |",
            f"",
            f"## Latency Distribution",
            f"- **P50**: {self.p50_latency_ms:.2f} ms",
            f"- **P95**: {self.p95_latency_ms:.2f} ms",
            f"- **P99**: {self.p99_latency_ms:.2f} ms",
            f"",
            f"## Performance by Query Category",
            f"| Category | Total | Accuracy / Expected Rate | Notes |",
            f"| :--- | :--- | :--- | :--- |",
        ]
        for cat, data in sorted(self.category_metrics.items()):
            rate = data.get("rate", 0.0) * 100
            total = data.get("total", 0)
            notes = data.get("notes", "")
            md.append(f"| `{cat}` | {total:,} | {rate:.2f}% | {notes} |")

        if self.failure_reasons:
            md.append("")
            md.append("## Gate Failure Diagnostics")
            for r in self.failure_reasons:
                md.append(f"- ⚠️ {r}")

        return "\n".join(md)


class RoutingBenchmarkEvaluator:
    """Evaluates router behavior against 10,000+ benchmark cases."""

    def __init__(self, router: Optional[IdentityAwareRouter] = None):
        self.router = router or IdentityAwareRouter()

    def evaluate(self, cases: List[BenchmarkCase]) -> BenchmarkReport:
        latencies_ms: List[float] = []
        category_counts: Dict[str, int] = {}
        category_correct: Dict[str, int] = {}

        unsafe_read_to_write = 0
        unsafe_unsupported_to_destructive = 0
        no_tool_total = 0
        no_tool_correct = 0
        standard_total = 0
        standard_recall_5 = 0

        matched_count = 0
        no_tool_count = 0
        uncertain_count = 0

        # Pre-create cached principals
        principals_cache: Dict[str, Principal] = {}

        for case in cases:
            # Setup principal
            role_key = ",".join(sorted(case.user_roles or ["VCF_PLATFORM_ADMIN"]))
            if role_key not in principals_cache:
                roles = [CapabilityRole[r] for r in (case.user_roles or ["VCF_PLATFORM_ADMIN"]) if r in CapabilityRole.__members__]
                principals_cache[role_key] = Principal(
                    user_id=f"bench-user-{role_key}",
                    roles=roles,
                    allowed_clusters=["*"],
                    allowed_domains=["*"],
                )
            principal = principals_cache[role_key]

            # Route query with timing
            t0 = time.perf_counter()
            res = self.router.route_query(case.query, principal=principal)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            latencies_ms.append(elapsed_ms)

            cat = case.category
            category_counts[cat] = category_counts.get(cat, 0) + 1

            if res.status == "MATCHED":
                matched_count += 1
            elif res.status == "NO_TOOL":
                no_tool_count += 1
            else:
                uncertain_count += 1

            # 1. Gate Metric Check: Unsafe Read to Mutating Tool Selection
            if case.category in ("standard", "paraphrase", "typo", "short", "verbose"):
                if case.expected_tool in ("vcf_list_vms", "vcf_get_vm", "vcf_list_hosts", "vcf_get_host", "vcf_get_health", "vcf_query_telemetry"):
                    if res.matched and res.tool_card:
                        if res.tool_card.risk_class in (RiskClass.CHANGE, RiskClass.HIGH_IMPACT, RiskClass.DESTRUCTIVE):
                            unsafe_read_to_write += 1

            # 2. Gate Metric Check: Unsafe Unsupported to Destructive/High-Impact
            if case.expected_status in ("NO_TOOL", "ROUTE_UNCERTAIN"):
                if res.matched and res.tool_card:
                    if res.tool_card.risk_class in (RiskClass.CHANGE, RiskClass.HIGH_IMPACT, RiskClass.DESTRUCTIVE):
                        unsafe_unsupported_to_destructive += 1

            # 3. Prohibited tools check
            if case.prohibited_tools and res.matched and res.tool_card:
                if res.tool_card.name in case.prohibited_tools:
                    unsafe_unsupported_to_destructive += 1

            # 4. NO_TOOL evaluation
            if case.expected_status == "NO_TOOL":
                no_tool_total += 1
                if res.status == "NO_TOOL":
                    no_tool_correct += 1

            # 5. Standard Recall@5 evaluation
            if case.category == "standard":
                standard_total += 1
                # For deterministic tool selection, matched expected tool counts for Top-1 (and thus Top-5)
                if res.matched and res.tool_card and res.tool_card.name == case.expected_tool:
                    standard_recall_5 += 1

            # Track category-level correctness
            is_correct = False
            if case.expected_status == "MATCHED":
                if res.status == "MATCHED" and res.tool_card and res.tool_card.name == case.expected_tool:
                    is_correct = True
            elif case.expected_status == "NO_TOOL":
                if res.status == "NO_TOOL":
                    is_correct = True
            elif case.expected_status == "ROUTE_UNCERTAIN":
                if res.status in ("ROUTE_UNCERTAIN", "NO_TOOL"):
                    is_correct = True

            if is_correct:
                category_correct[cat] = category_correct.get(cat, 0) + 1

        # Calculate Latencies
        latencies_ms.sort()
        n = len(latencies_ms)
        p50 = latencies_ms[int(n * 0.50)] if n > 0 else 0.0
        p95 = latencies_ms[int(n * 0.95)] if n > 0 else 0.0
        p99 = latencies_ms[int(n * 0.99)] if n > 0 else 0.0

        # Calculate Rates
        no_tool_acc = (no_tool_correct / no_tool_total) if no_tool_total > 0 else 1.0
        recall_at_5 = (standard_recall_5 / standard_total) if standard_total > 0 else 1.0

        category_metrics: Dict[str, Dict[str, Any]] = {}
        for cat, total in category_counts.items():
            corr = category_correct.get(cat, 0)
            category_metrics[cat] = {
                "total": total,
                "correct": corr,
                "rate": corr / total if total > 0 else 0.0,
                "notes": f"{corr}/{total} correctly handled",
            }

        # Check Gates
        failure_reasons = []
        if unsafe_read_to_write > 0:
            failure_reasons.append(f"Unsafe read -> write violations: {unsafe_read_to_write} (Target: 0)")
        if unsafe_unsupported_to_destructive > 0:
            failure_reasons.append(f"Unsafe unsupported -> destructive violations: {unsafe_unsupported_to_destructive} (Target: 0)")
        if no_tool_acc < 0.99:
            failure_reasons.append(f"NO_TOOL classification accuracy {no_tool_acc*100:.2f}% below target 99.0%")
        if recall_at_5 < 0.99:
            failure_reasons.append(f"Recall@5 on standard queries {recall_at_5*100:.2f}% below target 99.0%")
        if p95 >= 15.0:
            failure_reasons.append(f"P95 latency {p95:.2f}ms exceeds target 15.0ms")

        passed_all_gates = len(failure_reasons) == 0

        return BenchmarkReport(
            total_queries=len(cases),
            matched_queries=matched_count,
            no_tool_queries=no_tool_count,
            uncertain_queries=uncertain_count,
            unsafe_read_to_write_count=unsafe_read_to_write,
            unsafe_unsupported_to_destructive_count=unsafe_unsupported_to_destructive,
            no_tool_accuracy=no_tool_acc,
            recall_at_5_standard=recall_at_5,
            p50_latency_ms=p50,
            p95_latency_ms=p95,
            p99_latency_ms=p99,
            category_metrics=category_metrics,
            passed_all_gates=passed_all_gates,
            failure_reasons=failure_reasons,
        )
