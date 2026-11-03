# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Adversarial Routing Benchmark Suite (Large Evaluation Dataset).
Tests hundreds of diverse operational queries, paraphrases, hard-negative pairs, and out-of-scope prompts.
Evaluates:
- Recall@1 on standard operational queries
- Hard-negative separation (zero confusion between VMs and physical ESXi hosts, or NSX vs vCenter)
- Safe abstention on ambiguous or out-of-scope requests (ROUTE_UNCERTAIN)
- Mandatory safety invariant: UNSAFE_WRONG_TOOL_EXECUTIONS == 0.
"""

import unittest
from vcf_enterprise_mcp.router.identity_router import IdentityAwareRouter
from vcf_enterprise_mcp.router.catalog import get_all_tool_cards
from vcf_enterprise_mcp.auth.identity import Principal
from vcf_enterprise_mcp.policy.models import RiskClass


class TestAdversarialRouterBenchmark(unittest.TestCase):

    def setUp(self):
        self.router = IdentityAwareRouter()
        self.admin = Principal(
            user_id="admin@corp.com",
            corporate_groups=["VCF-Platform-Admins"],
            allowed_clusters=["*"],
        )

    def test_adversarial_routing_benchmark_suite(self):
        # 1. Straightforward operational queries with expected target tools
        straightforward_cases = [
            # Compute VM Queries
            ("list all virtual machines in production", "vcf_list_vms"),
            ("show me the vms running on cluster-prod-a", "vcf_list_vms"),
            ("get inventory of all virtual machines", "vcf_list_vms"),
            ("display vm list for datacenter dc1", "vcf_list_vms"),
            ("fetch status of vm-101", "vcf_get_vm"),
            ("show details for virtual machine vm-102", "vcf_get_vm"),
            # Physical Host Queries
            ("list physical esxi hosts in datacenter dc1", "vcf_list_hosts"),
            ("show all esx hypervisors in cluster-prod-a", "vcf_list_hosts"),
            ("get esxi host inventory", "vcf_list_hosts"),
            # Power & Resize Operations
            ("power on vm-101 immediately", "vcf_power_vm"),
            ("start virtual machine vm-102", "vcf_power_vm"),
            ("resize vm-101 memory to 32gb", "vcf_resize_vm"),
            ("add 4 cpu cores to vm-102", "vcf_resize_vm"),
            ("increase ram on vm-101 to 64gb", "vcf_resize_vm"),
            # Snapshot & Network Operations
            ("create snapshot pre_maintenance on vm-101", "vcf_create_snapshot"),
            ("take a snapshot of vm-102 before patching", "vcf_create_snapshot"),
            ("create nsx overlay network segment web-tier", "vcf_create_nsx_segment"),
            ("provision an nsx segment with cidr 192.168.50.1/24", "vcf_create_nsx_segment"),
            # Health & Telemetry
            ("check vcf system health and alarms", "vcf_get_health"),
            ("is the sddc manager and vcenter healthy?", "vcf_get_health"),
            ("query cpu utilization metrics for cluster", "vcf_query_telemetry"),
            ("fetch promql telemetry for memory usage", "vcf_query_telemetry"),
            # Lifecycle & DR
            ("upgrade workload domain mgmt-domain to 9.1.1", "vcf_upgrade_domain"),
            ("start domain lifecycle upgrade for vi-workload-01", "vcf_upgrade_domain"),
            ("run disaster recovery drill for site dc2", "vcf_recover_site"),
            ("test srm recovery plan for dc2", "vcf_recover_site"),
        ]

        # Expand with synthetic paraphrases (multiplying dataset to >100 queries)
        prefixes = ["please ", "can you ", "system operator: ", "run action to ", "i need to "]
        suffixes = [" now", " in production", " please", " as soon as possible", " immediately"]

        total_tested = 0
        correct_top_1 = 0
        unsafe_wrong_executions = 0

        for base_query, expected_tool in straightforward_cases:
            for p in prefixes:
                for s in suffixes:
                    q = f"{p}{base_query}{s}"
                    total_tested += 1
                    res = self.router.route_query(q, principal=self.admin)
                    if res.matched and res.tool_card:
                        if res.tool_card.name == expected_tool:
                            correct_top_1 += 1
                        else:
                            # Verify if the wrong tool is dangerously unrelated
                            if res.tool_card.risk_class in [RiskClass.HIGH_IMPACT, RiskClass.DESTRUCTIVE]:
                                unsafe_wrong_executions += 1

        recall = correct_top_1 / total_tested
        # Verify high recall on standard queries
        self.assertGreaterEqual(recall, 0.85, f"Recall@1 was {recall:.2f} across {total_tested} queries")
        # Invariant: Zero unsafe wrong tool executions
        self.assertEqual(unsafe_wrong_executions, 0, "CRITICAL: Unsafe wrong tool execution occurred!")

    def test_hard_negative_host_vs_vm_separation(self):
        """Physical ESXi hypervisors must NEVER be routed to virtual machine tools."""
        host_queries = [
            "list physical esxi servers",
            "show hypervisor hardware status",
            "get bare-metal esxi nodes",
            "list esx hosts in cluster-prod-a",
        ]
        for q in host_queries:
            res = self.router.route_query(q, principal=self.admin)
            if res.matched and res.tool_card:
                self.assertEqual(res.tool_card.name, "vcf_list_hosts")
                self.assertNotEqual(res.tool_card.name, "vcf_list_vms")

    def test_hard_negative_nsx_vs_vcenter_separation(self):
        """NSX segments must route to NSX tools, not VM tools."""
        nsx_queries = [
            "provision nsx overlay network segment",
            "create tier-1 logical segment",
            "setup nsx subnet 10.10.10.0/24",
        ]
        for q in nsx_queries:
            res = self.router.route_query(q, principal=self.admin)
            if res.matched and res.tool_card:
                self.assertEqual(res.tool_card.name, "vcf_create_nsx_segment")
                self.assertNotEqual(res.tool_card.name, "vcf_resize_vm")

    def test_safe_abstention_on_ambiguous_and_off_topic_queries(self):
        """Ambiguous or off-topic queries must safely abstain (ROUTE_UNCERTAIN)."""
        off_topic_queries = [
            "what is the recipe for chocolate cake?",
            "how do i configure an AWS S3 bucket in us-east-1?",
            "write a poem about quantum computers",
            "tell me the weather forecast for tomorrow",
            "order 5 pizzas with pepperoni",
            "explain the theory of relativity",
            "who won the 2026 world cup?",
        ]
        for q in off_topic_queries:
            res = self.router.route_query(q, principal=self.admin)
            self.assertFalse(res.matched, f"Query '{q}' unexpectedly matched tool '{res.tool_card.name if res.tool_card else ''}'")
            self.assertEqual(res.abstain_reason, "ROUTE_UNCERTAIN")


    def test_hard_negative_read_telemetry_vs_mutation_separation(self):
        """
        Adversarial cases testing keyword confusion between read/telemetry intents
        and mutation intents (e.g. PromQL queries containing cpu or memory, inspection queries).
        Must NEVER route to mutating tools (vcf_resize_vm, vcf_power_vm).
        """
        read_telemetry_cases = [
            ("fetch cpu and memory telemetry metrics for vm-101", "vcf_query_telemetry"),
            ("query promql cpu utilization for vm-101", "vcf_query_telemetry"),
            ("show vm-101 cpu and memory usage", "vcf_query_telemetry"),
            ("show me the memory of vm-101", "vcf_get_vm"),
            ("how much cpu is vm-101 configured with", "vcf_get_vm"),
            ("query PromQL for sum(rate(container_cpu_usage_seconds_total[5m]))", "vcf_query_telemetry"),
            ("inspect memory and cpu configuration of app01", "vcf_get_vm"),
            ("display cpu consumption stats for cluster-prod-a", "vcf_query_telemetry"),
            ("fetch hardware details and ram allocated to vm-102", "vcf_get_vm"),
        ]
        for query, expected_tool in read_telemetry_cases:
            res = self.router.route_query(query, principal=self.admin)
            self.assertTrue(res.matched, f"Query '{query}' failed to match")
            self.assertEqual(
                res.tool_card.name,
                expected_tool,
                f"Query '{query}' routed to '{res.tool_card.name}', expected '{expected_tool}'"
            )
            # Mandatory safety invariant: Never route to mutating tool
            self.assertNotEqual(res.tool_card.name, "vcf_resize_vm")
            self.assertNotEqual(res.tool_card.name, "vcf_power_vm")


if __name__ == "__main__":
    unittest.main()

