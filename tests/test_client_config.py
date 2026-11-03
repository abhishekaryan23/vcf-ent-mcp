# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
import json
import os
import shlex
import tomllib
from pathlib import Path

import pytest

from vcf_enterprise_mcp.cli import _HARNESSES, main

SECRET = "eyJhbGciOiJSUzI1NiJ9.REALTOKEN.sig"
ARGS = ["server", "--mode", "stdio"]


def run(capsys, harness, *extra):
    assert main(["client-config", harness, *extra]) == 0
    out = capsys.readouterr()
    return out.out, out.err


def entry_of(harness, out):
    if harness == "claude-code":
        parts = shlex.split(out)
        i = parts.index("--")
        env = dict(p.split("=", 1) for j, p in enumerate(parts[:i]) if parts[j - 1] == "--env")
        return {"command": parts[i + 1], "args": parts[i + 2:], "env": env}
    if harness == "codex":
        return tomllib.loads(out)["mcp_servers"]["vcf-enterprise"]
    data = json.loads(out)
    return data["servers" if harness == "vscode" else "mcpServers"]["vcf-enterprise"]


@pytest.mark.parametrize("harness", _HARNESSES)
def test_valid_output(capsys, harness):
    out, err = run(capsys, harness)
    e = entry_of(harness, out)
    assert os.path.isabs(e["command"])
    assert e["args"] == ARGS
    assert "~" not in json.dumps(e)
    assert Path(e["env"]["VCF_ENTERPRISE_MCP_CONFIG"]).is_absolute()
    assert e["env"]["VCF_MCP_DB_PATH"].endswith("control_plane.db")
    assert "VCF_MCP_AUTH_TOKEN" not in e["env"]  # personal mode (the starter config): no token
    assert "personal mode" in err and "token mint" not in err


@pytest.mark.parametrize("harness", _HARNESSES)
def test_team_entry_has_the_token_placeholder(capsys, harness):
    out, err = run(capsys, harness, "--team")
    assert entry_of(harness, out)["env"]["VCF_MCP_AUTH_TOKEN"] == "Bearer <paste your token>"
    assert "token mint" in err


def test_starter_config_is_personal_and_an_existing_team_config_gets_the_token_entry(capsys, tmp_path):
    import yaml
    cfg = tmp_path / "c.yaml"
    out, _ = run(capsys, "generic", "--config", str(cfg))
    assert yaml.safe_load(cfg.read_text())["server"]["access_mode"] == "personal"
    assert "VCF_MCP_AUTH_TOKEN" not in entry_of("generic", out)["env"]
    team = tmp_path / "team.yaml"
    team.write_text("server: {mode: stdio}\nidp: {allow_lab_tokens: true}\n")  # an existing config without the key = team
    out, err = run(capsys, "generic", "--config", str(team))
    assert entry_of("generic", out)["env"]["VCF_MCP_AUTH_TOKEN"] == "Bearer <paste your token>"
    assert "team mode" in err


def test_vscode_shape(capsys):
    out, _ = run(capsys, "vscode")
    data = json.loads(out)
    assert "servers" in data and "mcpServers" not in data
    assert data["servers"]["vcf-enterprise"]["type"] == "stdio"


def test_claude_code_command(capsys):
    out, _ = run(capsys, "claude-code")
    assert out.startswith("claude mcp add")
    assert "--scope user" in out


def test_custom_config(capsys, tmp_path):
    cfg = tmp_path / "my config.yaml"
    out, _ = run(capsys, "codex", "--config", str(cfg))
    assert tomllib.loads(out)["mcp_servers"]["vcf-enterprise"]["env"]["VCF_ENTERPRISE_MCP_CONFIG"] == str(cfg)
    out, _ = run(capsys, "claude-code", "--config", str(cfg))
    assert entry_of("claude-code", out)["env"]["VCF_ENTERPRISE_MCP_CONFIG"] == str(cfg)


@pytest.mark.parametrize("harness", _HARNESSES)
def test_no_token_leak_without_flag(capsys, monkeypatch, harness):
    monkeypatch.setenv("VCF_MCP_AUTH_TOKEN", SECRET)
    out, err = run(capsys, harness)
    assert SECRET not in out and SECRET not in err


@pytest.mark.parametrize("harness", _HARNESSES)
def test_token_from_env(capsys, monkeypatch, harness):
    monkeypatch.setenv("VCF_MCP_AUTH_TOKEN", SECRET)
    out, _ = run(capsys, harness, "--token-from-env")
    assert entry_of(harness, out)["env"]["VCF_MCP_AUTH_TOKEN"] == SECRET


def test_toml_escaping(capsys, tmp_path):
    cfg = tmp_path / 'we"ird\\dir' / "c.yaml"
    out, _ = run(capsys, "codex", "--config", str(cfg))
    assert tomllib.loads(out)["mcp_servers"]["vcf-enterprise"]["env"]["VCF_ENTERPRISE_MCP_CONFIG"] == str(cfg)
