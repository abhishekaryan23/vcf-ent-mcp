# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""CLI defaults that a new user hits first: `credentials add` must use the same environment the other credential commands
and the server use, and endpoint overrides must apply to typed appliance names."""

from vcf_enterprise_mcp.adapter.connectivity import apply_endpoint_override
from vcf_enterprise_mcp.cli import main


def test_credentials_add_defaults_match_list_test_rotate_delete(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("VCF_MCP_HOME", str(tmp_path))
    monkeypatch.setenv("VCF_MCP_CREDENTIALS_PATH", str(tmp_path / "creds.json"))
    monkeypatch.setenv("VCF_MCP_MASTER_KEY_PATH", str(tmp_path / "master.key"))
    pw = tmp_path / "pw"
    pw.write_text("a-test-password")
    assert main(["credentials", "add", "--name", "vc", "--username", "svc", "--provider", "local", "--password-file", str(pw)]) == 0
    ref = "local://env-prod/vc"
    assert ref in capsys.readouterr().out
    # No --env anywhere: every command must agree on the default environment.
    assert main(["credentials", "list"]) == 0 and ref in capsys.readouterr().out
    assert main(["credentials", "test", ref]) == 0
    assert main(["credentials", "rotate", ref, "--new-password", "another-test-password"]) == 0
    assert main(["credentials", "delete", ref]) == 0


def test_apply_endpoint_override_maps_only_listed_names():
    overrides = {"vc01.corp.example": "https://203.0.113.10:8443"}
    assert apply_endpoint_override("https://vc01.corp.example/ui", overrides) == "https://203.0.113.10:8443"
    assert apply_endpoint_override("https://VC01.corp.example.", overrides) == "https://203.0.113.10:8443"
    assert apply_endpoint_override("https://other.corp.example", overrides) == "https://other.corp.example"
    assert apply_endpoint_override("https://vc01.corp.example", {}) == "https://vc01.corp.example"
    assert apply_endpoint_override(None, overrides) is None
