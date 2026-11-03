# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Test Suite: Enterprise VCF MCP Administration CLI (vcf-mcp).
Tests all administrative subcommands, parsers, error cases, and execution flows.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from vcf_enterprise_mcp.cli import main, build_parser


class TestEnterpriseCLI(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_parser_construction(self):
        """Validates parser structure and supported subcommands."""
        parser = build_parser()
        self.assertIsNotNone(parser)
        parsed = parser.parse_args(["setup"])
        self.assertEqual(parsed.command, "setup")

        parsed_local = parser.parse_args(["local", "check"])
        self.assertEqual(parsed_local.command, "local")
        self.assertEqual(parsed_local.local_action, "check")

        parsed_bundle = parser.parse_args(["support-bundle", "create", "--output", "test.tar.gz"])
        self.assertEqual(parsed_bundle.command, "support-bundle")
        self.assertEqual(parsed_bundle.bundle_action, "create")
        self.assertEqual(parsed_bundle.output, "test.tar.gz")

    def test_setup_command(self):
        """Validates setup command creates ~/.vcf-mcp/config.yaml with secure permissions."""
        with tempfile.TemporaryDirectory() as fake_home:
            with patch("pathlib.Path.home", return_value=fake_home):
                from pathlib import Path
                with patch("pathlib.Path.home", return_value=Path(fake_home)):
                    code = main(["setup"])
                    self.assertEqual(code, 0)
                    config_file = Path(fake_home) / ".vcf-mcp" / "config.yaml"
                    self.assertTrue(config_file.exists())
                    content = config_file.read_text(encoding="utf-8")
                    self.assertIn("DISCOVERY_ONLY", content)

    def test_local_check_command(self):
        """Validates local check diagnostic output."""
        code = main(["local", "check"])
        self.assertEqual(code, 0)

    @patch("vcf_enterprise_mcp.core.server.main")
    def test_local_start_command(self, mock_server_main):
        """Validates local start delegates to server.main."""
        code = main(["local", "start", "--mode", "stdio"])
        self.assertEqual(code, 0)
        mock_server_main.assert_called_once_with(mode="stdio")

    def test_support_bundle_command(self):
        """Validates support bundle creates a valid tar.gz archive."""
        out_tar = os.path.join(self.temp_dir.name, "bundle.tar.gz")
        code = main(["support-bundle", "create", "--output", out_tar])
        self.assertEqual(code, 0)
        self.assertTrue(os.path.exists(out_tar))
        self.assertGreater(os.path.getsize(out_tar), 0)

    def test_certify_command(self):
        """Validates certify subcommand runs profile verification."""
        from unittest.mock import patch
        from vcf_enterprise_mcp.adapter.transport.errors import UpstreamConnectionException
        with patch("vcf_enterprise_mcp.adapter.transport.http.HTTPTransport.send", side_effect=UpstreamConnectionException("twin", "offline")):
            code = main(["certify", "--profile", "vcf_9_1_1", "--target", "digital_twin"])
        self.assertEqual(code, 1)

    def test_certify_matrix_command(self):
        """Validates certify-matrix subcommand generates report file."""
        out_matrix = os.path.join(self.temp_dir.name, "matrix.md")
        code = main(["certify-matrix", "--target", "digital_twin", "--output", out_matrix])
        self.assertEqual(code, 0)
        self.assertTrue(os.path.exists(out_matrix))
        with open(out_matrix, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("VCF Interoperability Certification Matrix", content)

    @patch("vcf_enterprise_mcp.audit.ga_report.main")
    def test_ga_report_command(self, mock_ga_main):
        """Validates ga-report triggers qualification audit script."""
        code = main(["ga-report"])
        self.assertEqual(code, 0)
        mock_ga_main.assert_called_once()

    @patch("vcf_enterprise_mcp.core.server.main")
    def test_server_command(self, mock_server_main):
        """Validates server command starts server in requested mode."""
        code = main(["server", "--mode", "stdio"])
        self.assertEqual(code, 0)
        mock_server_main.assert_called_once_with(mode="stdio")

    def test_credentials_lifecycle_cli(self):
        """Validates credentials add -> list -> test -> rotate -> delete workflow via CLI."""
        tenant = "cli-test-tenant"
        env = "cli-test-env"
        cred_name = "test-vcenter"
        ref = f"local://{env}/{cred_name}"

        # 1. Add
        add_code = main([
            "credentials", "add",
            "--name", cred_name,
            "--username", "admin@vsphere.local",
            "--password", "SuperSecretPass123!",
            "--provider", "local",
            "--tenant", tenant,
            "--env", env,
        ])
        self.assertEqual(add_code, 0)

        # 2. List
        list_code = main([
            "credentials", "list",
            "--tenant", tenant,
            "--env", env,
        ])
        self.assertEqual(list_code, 0)

        # 3. Test resolution
        test_code = main([
            "credentials", "test",
            ref,
            "--tenant", tenant,
            "--env", env,
        ])
        self.assertEqual(test_code, 0)

        # 4. Rotate
        rotate_code = main([
            "credentials", "rotate",
            ref,
            "--new-password", "RotatedSecretPass456!",
            "--tenant", tenant,
            "--env", env,
        ])
        self.assertEqual(rotate_code, 0)

        # 5. Delete
        del_code = main([
            "credentials", "delete",
            ref,
            "--tenant", tenant,
            "--env", env,
        ])
        self.assertEqual(del_code, 0)


if __name__ == "__main__":
    unittest.main()


class TestCliCredentialHygiene(unittest.TestCase):
    """init-lab never stores a built-in default password; passwords on argv are warned about."""

    def test_init_lab_without_password_stores_nothing_and_keeps_tls_on_for_real_vcf(self):
        import contextlib, io, os, tempfile, yaml
        from unittest import mock
        from vcf_enterprise_mcp.cli import main as cli_main
        with tempfile.TemporaryDirectory() as tmp:
            cfg = os.path.join(tmp, "config.yaml")
            env = {"VCF_MCP_CREDENTIALS_PATH": os.path.join(tmp, "c.json"), "VCF_MCP_MASTER_KEY_PATH": os.path.join(tmp, "m.key"),
                   "VCF_MCP_KMS_KEY_PATH": os.path.join(tmp, "k.key"), "VCF_MCP_LAB_JWT_KEY_PATH": os.path.join(tmp, "lab.pem")}
            err = io.StringIO()
            with mock.patch.dict(os.environ, env), mock.patch("sys.stdin.isatty", return_value=False), \
                    contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli_main(["init-lab", "--config", cfg, "--target", "real_vcf"]), 0)
            data = yaml.safe_load(open(cfg))
            self.assertNotIn("credential_ref", data["vcf"])
            self.assertTrue(data["vcf"]["verify_ssl"])
            self.assertFalse(os.path.exists(env["VCF_MCP_CREDENTIALS_PATH"]) and "VMwareLab" in open(env["VCF_MCP_CREDENTIALS_PATH"]).read())
            self.assertIn("built-in local administrator", err.getvalue())

    def test_password_on_command_line_is_warned(self):
        import contextlib, io
        from vcf_enterprise_mcp.cli import _warn_password_on_command_line
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            _warn_password_on_command_line("x")
        self.assertIn("shell history", err.getvalue())
