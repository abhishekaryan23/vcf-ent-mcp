# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
import tempfile
from pathlib import Path
import unittest

from repo_explainer import analyze, render, source_view


class RepoExplainerTests(unittest.TestCase):
    def test_generic_repo_is_portable_and_flags_source_pattern(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "sample"
            (root / "src").mkdir(parents=True)
            (root / "src" / "app.py").write_text("def main():\n    eval('2 + 2')\n")
            report = analyze(str(root))
            self.assertFalse(report["is_vcf"])
            self.assertEqual(report["language"], "Python")
            self.assertEqual(report["flags"][0]["name"], "Dynamic code execution")
            page = render(report, root / "report.html")
            self.assertIn("Check these before rollout", page)
            self.assertIn("From zero to verified", page)
            self.assertIn("src/app.py:2", page)
            self.assertIn('data-group="journey"', page)
            self.assertNotIn("@@TITLE@@", page)
            self.assertIn("src/app.py", source_view(str(root), "src/app.py", 2))

    def test_source_view_rejects_path_escape(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "sample"
            root.mkdir()
            (root / "main.py").write_text("print('ok')\n")
            outside = Path(folder) / "outside.py"
            outside.write_text("SECRET\n")
            with self.assertRaises(ValueError):
                source_view(str(root), "../outside.py", 1)

    def test_unknown_filenames_still_get_a_starting_point(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "odd-project"
            root.mkdir()
            (root / "quartz.py").write_text("print('ok')\n")
            report = analyze(str(root))
            self.assertEqual(report["stages"][0]["label"], "Source")
            page = render(report)
            self.assertIn("quartz.py:1", page)
            self.assertNotIn("MCP JSON-RPC request", page)

    def test_html_escapes_repository_name(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "repo<script>"
            root.mkdir()
            (root / "main.py").write_text("print('ok')\n")
            page = render(analyze(str(root)))
            self.assertNotIn("repo<script>", page)
            self.assertIn("repo&lt;script&gt;", page)


if __name__ == "__main__":
    unittest.main()
