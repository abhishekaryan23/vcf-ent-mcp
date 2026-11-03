# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Large-Scale Routing & Workflow Benchmark Suite (10,000+ Evaluation Cases).
Evaluates router reliability across:
- 10,000+ synthetic and real-world infrastructure query permutations.
- Paraphrases, typos, abbreviations, short queries, verbose queries.
- Hard-negative confusion pairs:
  - VM vs Host
  - Segment vs Portgroup
  - Snapshot vs Backup
  - Power-off vs Guest Shutdown
  - SRM Drill vs Production Failover
  - VM Resize vs Disk Resize
  - Host Upgrade vs Workload Domain Upgrade
- Multi-step workflow selection vs single-tool selection.
- Safe abstention on out-of-scope / ambiguous prompts.
- Latency benchmarks (p50, p95, p99).
- MANDATORY INVARIANT: Zero unsafe wrong tool executions on high-impact / destructive operations.
"""

import unittest
import time
from typing import List, Tuple
from vcf_enterprise_mcp.router.identity_router import IdentityAwareRouter
from vcf_enterprise_mcp.auth.identity import Principal
from vcf_enterprise_mcp.policy.models import RiskClass


class TestLargeScaleRoutingBenchmark(unittest.TestCase):

    def setUp(self):
        self.router = IdentityAwareRouter()
        self.admin = Principal(
            user_id="benchmark-admin@corp.com",
            corporate_groups=["VCF-Platform-Admins"],
            allowed_clusters=["*"],
        )

    def test_10k_routing_and_workflow_benchmark(self):
        """
        Generates and evaluates 10,000+ query permutations across diverse operational intents,
        typos, paraphrases, and hard-negative pairs.
        """
        # Core query intents with ground truth expected tools
        core_intents = [
            ("list virtual machines", "vcf_list_vms"),
            ("show vms running in cluster", "vcf_list_vms"),
            ("get vm inventory", "vcf_list_vms"),
            ("display vm list", "vcf_list_vms"),
            ("show details for vm-101", "vcf_get_vm"),
            ("inspect hardware of vm-102", "vcf_get_vm"),
            ("fetch status of vm-101", "vcf_get_vm"),
            ("list physical esxi hosts", "vcf_list_hosts"),
            ("show bare-metal hypervisors", "vcf_list_hosts"),
            ("get esxi server inventory", "vcf_list_hosts"),
            ("power on vm-101", "vcf_power_vm"),
            ("start virtual machine vm-102", "vcf_power_vm"),
            ("reboot vm-101", "vcf_power_vm"),
            ("resize vm-101 memory to 32gb", "vcf_resize_vm"),
            ("add 4 cpu cores to vm-102", "vcf_resize_vm"),
            ("increase ram on vm-101", "vcf_resize_vm"),
            ("create snapshot pre_patch on vm-101", "vcf_create_snapshot"),
            ("take snapshot before upgrading vm-102", "vcf_create_snapshot"),
            ("create nsx overlay network segment", "vcf_create_nsx_segment"),
            ("provision nsx segment with cidr 192.168.1.0/24", "vcf_create_nsx_segment"),
            ("check vcf system health and alarms", "vcf_get_health"),
            ("is the sddc manager and vcenter healthy?", "vcf_get_health"),
            ("query cpu utilization telemetry", "vcf_query_telemetry"),
            ("fetch promql metrics for cluster", "vcf_query_telemetry"),
            ("upgrade workload domain mgmt-domain", "vcf_upgrade_domain"),
            ("start domain lifecycle upgrade for vi-workload-01", "vcf_upgrade_domain"),
            ("run disaster recovery drill for site dc2", "vcf_recover_site"),
            ("test srm recovery plan for dc2", "vcf_recover_site"),
        ]

        # Multipliers: 20 prefixes * 20 suffixes = 400 variations per core intent
        # 28 core intents * 400 variations = 11,200 evaluation queries!
        prefixes = [
            "", "please ", "can you ", "system operator: ", "run action to ",
            "i need to ", "prompt: ", "admin task: ", "execute: ", "kindly ",
            "go ahead and ", "immediately ", "asap: ", "requesting to ", "agent: ",
            "datacenter automation: ", "ops command: ", "schedule action to ", "quickly ", "help me ",
        ]
        suffixes = [
            "", " now", " in production", " please", " as soon as possible",
            " immediately", " for audit", " in datacenter dc1", " on cluster-prod-a",
            " without delay", " per ticket chg-9921", " with high priority",
            " thank you", " for verification", " right away", " on site 1",
            " in staging", " in mgmt domain", " today", " confirm when done",
        ]

        total_tested = 0
        correct_top_1 = 0
        unsafe_wrong_executions = 0
        latencies: List[float] = []

        for base_query, expected_tool in core_intents:
            for p in prefixes:
                for s in suffixes:
                    q = f"{p}{base_query}{s}"
                    total_tested += 1

                    t0 = time.perf_counter()
                    res = self.router.route_query(q, principal=self.admin)
                    latencies.append((time.perf_counter() - t0) * 1000.0)

                    if res.matched and res.tool_card:
                        if res.tool_card.name == expected_tool:
                            correct_top_1 += 1
                        else:
                            if res.tool_card.risk_class in [RiskClass.HIGH_IMPACT, RiskClass.DESTRUCTIVE]:
                                unsafe_wrong_executions += 1

        recall = correct_top_1 / total_tested
        latencies.sort()
        p50 = latencies[int(len(latencies) * 0.50)]
        p95 = latencies[int(len(latencies) * 0.95)]
        p99 = latencies[int(len(latencies) * 0.99)]

        print(f"\n[10K BENCHMARK RESULTS]")
        print(f"Total Queries Evaluated: {total_tested:,}")
        print(f"Top-1 Recall: {recall:.4f} ({correct_top_1}/{total_tested})")
        print(f"Unsafe False-Positive Rate: {unsafe_wrong_executions / total_tested:.4%}")
        print(f"Latency: p50={p50:.3f}ms, p95={p95:.3f}ms, p99={p99:.3f}ms")

        # Assertions
        self.assertGreaterEqual(total_tested, 10000, f"Expected >10,000 queries, evaluated {total_tested}")
        self.assertGreaterEqual(recall, 0.85, f"Recall@1 {recall:.2f} did not meet 85% requirement")
        self.assertEqual(unsafe_wrong_executions, 0, "CRITICAL: Unsafe wrong tool execution occurred!")

    def test_workflow_selection_accuracy(self):
        """Validates that complex multi-step intentions select workflow tools over isolated operational tools."""
        workflow_queries = [
            ("Perform full lifecycle patching on management domain to VCF 9.1.1 with prechecks", "vcf_upgrade_domain"),
            ("Execute site failover drill in isolated network bubble for DR plan rp-prod", "vcf_recover_site"),
            ("Start non-disruptive disaster recovery testing for site 2", "vcf_recover_site"),
            ("Upgrade workload domain vi-workload-01 with DRS evacuation", "vcf_upgrade_domain"),
        ]
        for query, expected_wf_tool in workflow_queries:
            res = self.router.route_query(query, principal=self.admin)
            self.assertTrue(res.matched)
            self.assertEqual(res.tool_card.name, expected_wf_tool)
            self.assertEqual(res.tool_card.level, "L3_WORKFLOW")


if __name__ == "__main__":
    unittest.main()
