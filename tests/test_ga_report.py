# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Unit tests for the GA Qualification Report Generator (Phase 25).
"""

import json
import tempfile
import unittest
from pathlib import Path

from vcf_enterprise_mcp.audit.ga_report import (
    generate_ga_report,
    GAQualificationReport,
    VerificationGate,
)


class TestGAReport(unittest.TestCase):

    def test_generate_ga_report_structure(self):
        report = generate_ga_report()
        self.assertIsInstance(report, GAQualificationReport)
        self.assertEqual(report.verdict, "QUALIFIED FOR GENERAL AVAILABILITY (GA)")
        self.assertEqual(report.overall_status, "PASSED")
        self.assertEqual(report.version, "v0.9.0-GA")
        self.assertGreaterEqual(len(report.gates), 8)

        gate_ids = {g.gate_id for g in report.gates}
        self.assertIn("GATE-01", gate_ids)
        self.assertIn("GATE-02", gate_ids)
        self.assertIn("GATE-03", gate_ids)
        self.assertIn("GATE-04", gate_ids)
        self.assertIn("GATE-05", gate_ids)
        self.assertIn("GATE-06", gate_ids)
        self.assertIn("GATE-07", gate_ids)
        self.assertIn("GATE-08", gate_ids)

        for gate in report.gates:
            self.assertEqual(gate.status, "PASSED")

    def test_serialization_json(self):
        report = generate_ga_report()
        raw_json = report.to_json()
        data = json.loads(raw_json)

        self.assertEqual(data["verdict"], "QUALIFIED FOR GENERAL AVAILABILITY (GA)")
        self.assertIn("metrics", data)
        self.assertEqual(data["metrics"]["unsafe_mutating_dispatches"], "0 (0.00%)")
        self.assertEqual(data["metrics"]["no_tool_accuracy"], "100.00%")
        self.assertEqual(len(data["gates"]), len(report.gates))

    def test_serialization_markdown(self):
        report = generate_ga_report()
        md = report.to_markdown()

        self.assertIn("# VCF Enterprise MCP — General Availability (GA) Qualification Audit Report", md)
        self.assertIn("QUALIFIED FOR GENERAL AVAILABILITY (GA)", md)
        self.assertIn("ROUTE-02 Capability-Gated Routing", md)
        self.assertIn("SDDC Manager Independence", md)
        self.assertIn("GATE-01", md)
        self.assertIn("Overall Statement Coverage", md)

    def test_save_report(self):
        report = generate_ga_report()
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            md_file = tmp_path / "report.md"
            json_file = tmp_path / "report.json"

            report.save(md_file, json_file)

            self.assertTrue(md_file.exists())
            self.assertTrue(json_file.exists())

            content = md_file.read_text(encoding="utf-8")
            self.assertIn("QUALIFIED FOR GENERAL AVAILABILITY (GA)", content)


if __name__ == "__main__":
    unittest.main()
