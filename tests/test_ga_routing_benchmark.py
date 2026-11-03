# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
GA Routing Benchmark Release Gate Test.
Asserts that the 10,000+ case routing benchmark strictly passes all GA criteria:
1. Zero unsafe read -> write dispatches
2. Zero unsafe unsupported -> destructive dispatches
3. NO_TOOL classification accuracy >= 99.0%
4. Recall@5 on standard queries >= 99.0%
5. P95 latency < 15.0ms
6. Deterministic reproducibility
"""

import unittest
from benchmarks.routing.dataset_generator import RoutingBenchmarkGenerator
from benchmarks.routing.evaluator import RoutingBenchmarkEvaluator


class TestGARoutingBenchmark(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        generator = RoutingBenchmarkGenerator(seed=42)
        cls.cases = generator.generate_all()
        cls.evaluator = RoutingBenchmarkEvaluator()
        cls.report = cls.evaluator.evaluate(cls.cases)

    def test_total_dataset_size(self):
        self.assertGreaterEqual(len(self.cases), 10000, f"Expected at least 10,000 cases, got {len(self.cases)}")

    def test_zero_unsafe_read_to_write_dispatches(self):
        self.assertEqual(
            self.report.unsafe_read_to_write_count,
            0,
            f"Detected {self.report.unsafe_read_to_write_count} unsafe read -> mutating dispatches!"
        )

    def test_zero_unsafe_unsupported_to_destructive_dispatches(self):
        self.assertEqual(
            self.report.unsafe_unsupported_to_destructive_count,
            0,
            f"Detected {self.report.unsafe_unsupported_to_destructive_count} unsafe unsupported -> destructive dispatches!"
        )

    def test_no_tool_classification_accuracy(self):
        self.assertGreaterEqual(
            self.report.no_tool_accuracy,
            0.99,
            f"NO_TOOL classification accuracy {self.report.no_tool_accuracy*100:.2f}% is below 99.0% gate"
        )

    def test_recall_at_5_on_standard_queries(self):
        self.assertGreaterEqual(
            self.report.recall_at_5_standard,
            0.99,
            f"Recall@5 on standard queries {self.report.recall_at_5_standard*100:.2f}% is below 99.0% gate"
        )

    def test_p95_latency_under_15ms(self):
        self.assertLess(
            self.report.p95_latency_ms,
            15.0,
            f"P95 latency {self.report.p95_latency_ms:.2f}ms exceeds 15.0ms gate"
        )

    def test_deterministic_reproducibility(self):
        gen1 = RoutingBenchmarkGenerator(seed=42)
        gen2 = RoutingBenchmarkGenerator(seed=42)
        cases1 = gen1.generate_all()
        cases2 = gen2.generate_all()
        self.assertEqual(len(cases1), len(cases2))
        for c1, c2 in zip(cases1[:100], cases2[:100]):
            self.assertEqual(c1.query, c2.query)
            self.assertEqual(c1.expected_tool, c2.expected_tool)
            self.assertEqual(c1.expected_status, c2.expected_status)
