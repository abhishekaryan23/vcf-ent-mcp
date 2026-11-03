# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Routing Benchmark Runner CLI for VCF Enterprise MCP.
Runs the 10,000+ query benchmark suite and generates an audited Markdown report.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Optional, List
from .dataset_generator import RoutingBenchmarkGenerator, BenchmarkCase
from .evaluator import RoutingBenchmarkEvaluator, BenchmarkReport


def run_routing_benchmark(
    dataset_path: Optional[str] = None,
    output_report_path: Optional[str] = None,
    seed: int = 42,
) -> BenchmarkReport:
    """Executes the full routing benchmark evaluation."""
    cases: List[BenchmarkCase] = []
    
    if dataset_path and Path(dataset_path).exists():
        print(f"Loading benchmark dataset from {dataset_path}...")
        with open(dataset_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    d = json.loads(line)
                    cases.append(BenchmarkCase(**d))
        print(f"Loaded {len(cases):,} benchmark cases.")
    else:
        print(f"Generating 10,000+ synthetic and real-world benchmark cases (seed={seed})...")
        generator = RoutingBenchmarkGenerator(seed=seed)
        cases = generator.generate_all()
        if dataset_path:
            generator.save_to_file(dataset_path)
            print(f"Saved generated dataset to {dataset_path}.")

    print("Evaluating router behavior against release gate metrics...")
    evaluator = RoutingBenchmarkEvaluator()
    report = evaluator.evaluate(cases)

    md_content = report.to_markdown()
    if output_report_path:
        out = Path(output_report_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w", encoding="utf-8") as f:
            f.write(md_content)
        print(f"Audited benchmark report written to {output_report_path}.")

    return report


def main():
    parser = argparse.ArgumentParser(description="VCF Enterprise MCP Routing Benchmark")
    parser.add_argument("--dataset", type=str, default="benchmarks/routing/benchmark_dataset.jsonl", help="Path to JSONL dataset")
    parser.add_argument("--report", type=str, default="docs/audits/routing_benchmark_report.md", help="Path to Markdown report")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for deterministic generation")
    args = parser.parse_args()

    report = run_routing_benchmark(
        dataset_path=args.dataset,
        output_report_path=args.report,
        seed=args.seed,
    )
    print("\n" + report.to_markdown())
    if not report.passed_all_gates:
        sys.exit(1)


if __name__ == "__main__":
    main()
