# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""First start with no usable configuration, partial configurations, and applying setup without a restart (review F1, F5)."""

import asyncio
import json
import os

import pytest
import yaml

from vcf_enterprise_mcp.auth.lab_auth import mint_lab_jwt_token
from vcf_enterprise_mcp.config.settings import EnterpriseSettings
from vcf_enterprise_mcp.config.starter import ensure_starter_config
from vcf_enterprise_mcp.core import server


@pytest.fixture()
def lab(tmp_path, monkeypatch):
    """An isolated state directory with a starter config and an MCP_ADMIN lab token."""
    for key in ("VCF_PLATFORM_MODE", "VCF_MCP_ENV", "VCF_OPERATING_MODE", "VCF_GATEWAY_URL"):
        monkeypatch.delenv(key, raising=False)
    cfg_path = tmp_path / "config.yaml"
    monkeypatch.setenv("VCF_MCP_HOME", str(tmp_path))
    monkeypatch.setenv("VCF_ENTERPRISE_MCP_CONFIG", str(cfg_path))
    monkeypatch.setenv("VCF_MCP_DB_PATH", str(tmp_path / "cp.db"))
    monkeypatch.setenv("VCF_MCP_LAB_JWT_KEY_PATH", str(tmp_path / "jwt.pem"))
    monkeypatch.setenv("VCF_MCP_CREDENTIALS_PATH", str(tmp_path / "creds.json"))
    monkeypatch.setenv("VCF_MCP_MASTER_KEY_PATH", str(tmp_path / "master.key"))
    assert ensure_starter_config(cfg_path) is True
    assert ensure_starter_config(cfg_path) is False  # never overwrites
    token = mint_lab_jwt_token(user_id="admin@corp.com", role="MCP_ADMIN", custom_key_path=str(tmp_path / "jwt.pem"))["authorization_header"]
    return tmp_path, cfg_path, token


def rpc(engine, token, method, params=None, id_=1):
    return asyncio.run(engine.handle_jsonrpc_request({"jsonrpc": "2.0", "id": id_, "method": method, "params": params or {}}, auth_header=token))


def build(cfg_path):
    cfg = EnterpriseSettings.load_from_yaml(str(cfg_path))
    engine = server._build_engine_from_settings(cfg)
    engine.reloader = server._make_reloader(cfg)
    return engine


def test_no_default_appliance_name_leaks_into_a_real_config():
    assert EnterpriseSettings().vcf.sddc_manager_fqdn is None
    with pytest.raises(ValueError):
        server._build_real_vcf_platform(EnterpriseSettings())  # nothing configured: refuse, never guess a target


def test_starter_config_names_no_appliance_and_loads(lab):
    _, cfg_path, _ = lab
    text = cfg_path.read_text()
    assert "sddc" not in text.lower().replace("setup mode", "") and "corp.internal" not in text
    cfg = EnterpriseSettings.load_from_yaml(str(cfg_path))
    assert cfg.idp.allow_lab_tokens is True and cfg.server.production_mode is False
    assert oct(cfg_path.stat().st_mode & 0o777) == "0o600"


def test_server_with_no_appliance_boots_into_setup_mode_and_serves_only_setup_tools(lab):
    _, cfg_path, token = lab
    engine = build(cfg_path)
    assert engine.setup_mode
    init = rpc(engine, token, "initialize")["result"]
    assert "vcf_setup" in init["instructions"]
    names = {t["name"] for t in rpc(engine, token, "tools/list")["result"]["tools"]}
    assert names == {"vcf_setup", "vcf_access_report", "vcf_find_tool"}
    blocked = rpc(engine, token, "tools/call", {"name": "vcf_list_vms", "arguments": {}})["result"]
    assert blocked["isError"] and "vcf_setup" in blocked["content"][0]["text"]
    first = rpc(engine, token, "tools/call", {"name": "vcf_setup", "arguments": {}})["result"]
    assert "NEEDS_INPUT" in first["content"][0]["text"]


def test_a_partial_config_loads_and_offers_only_the_tools_it_can_serve(lab):
    _, cfg_path, token = lab
    data = yaml.safe_load(cfg_path.read_text())
    data["vcf"] = {"vcenter_url": "https://vc.corp.example", "component_usernames": {"vcenter": "svc"}, "allowed_dns_suffixes": [".corp.example"]}
    cfg_path.write_text(yaml.safe_dump(data))
    engine = build(cfg_path)
    assert not engine.setup_mode
    assert set(engine.platform.component_auth) == {"vcenter"}
    reg = engine.platform.registry
    assert reg.has_capability("vm.lifecycle") and not reg.has_capability("network.segments") and not reg.has_capability("domain.lifecycle")
    names = {t["name"] for t in rpc(engine, token, "tools/list")["result"]["tools"]}
    assert "vcf_list_vms" in names and "vcf_setup" in names
    assert not names & {"vcf_list_nsx_segments", "vcf_list_domains", "vcf_diagnose"}
    miss = rpc(engine, token, "tools/call", {"name": "vcf_list_nsx_segments", "arguments": {}})["result"]
    assert miss["isError"] and "not configured" in miss["content"][0]["text"]


def test_completed_setup_takes_effect_without_a_restart(lab):
    tmp, cfg_path, token = lab
    engine = build(cfg_path)
    assert engine.setup_mode
    done = rpc(engine, token, "tools/call", {"name": "vcf_setup", "arguments": {
        "target": "digital_twin", "goals": ["monitor"], "endpoints": {"digital_twin": "http://127.0.0.1:8085"},
        "disable": [], "read_only": True}})["result"]
    payload = json.loads(done["content"][0]["text"])
    assert payload["status"] == "COMPLETE" and payload["reloaded"] is True
    assert "no restart is needed" in payload["next_steps"][0]
    assert not engine.setup_mode and engine.reloader is not None  # same engine object, now fully configured
    assert engine.drain_notifications() == [{"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}]
    names = {t["name"] for t in rpc(engine, token, "tools/list")["result"]["tools"]}
    assert "vcf_list_vms" in names  # the real tools appeared
    assert yaml.safe_load(cfg_path.read_text())["server"]["environment"] == "digital_twin"


def test_stdio_loop_replies_to_requests_only_and_announces_the_change(lab, monkeypatch, capsys):
    tmp, cfg_path, token = lab
    monkeypatch.setenv("VCF_MCP_AUTH_TOKEN", token)
    lines = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "vcf_setup", "arguments": {
            "target": "digital_twin", "goals": ["monitor"], "endpoints": {"digital_twin": "http://127.0.0.1:8085"},
            "disable": [], "read_only": True}}},
    ]
    import io
    monkeypatch.setattr(server.sys, "stdin", io.StringIO("".join(json.dumps(x) + "\n" for x in lines)))
    asyncio.run(server.run_stdio_control_plane(EnterpriseSettings.load_from_yaml(str(cfg_path))))
    out = [json.loads(x) for x in capsys.readouterr().out.splitlines()]
    assert [o.get("id") for o in out if "id" in o] == [1, 2]          # nothing for the notification
    assert out[-1] == {"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}


def test_client_config_creates_the_state_folder_and_a_starter_config(tmp_path, monkeypatch, capsys):
    from vcf_enterprise_mcp.cli import main
    home = tmp_path / "fresh-home" / ".vcf-mcp"
    monkeypatch.setenv("VCF_MCP_HOME", str(home))
    monkeypatch.delenv("VCF_ENTERPRISE_MCP_CONFIG", raising=False)
    monkeypatch.delenv("VCF_MCP_DB_PATH", raising=False)
    monkeypatch.chdir(tmp_path)  # hermetic: whatever the developer's working directory holds must not matter
    assert main(["client-config", "lmstudio"]) == 0
    out = capsys.readouterr()
    assert (home / "config.yaml").is_file()
    entry = json.loads(out.out)["mcpServers"]["vcf-enterprise"]
    assert entry["env"]["VCF_ENTERPRISE_MCP_CONFIG"] == str(home / "config.yaml")
    assert entry["env"]["VCF_MCP_DB_PATH"] == str(home / "control_plane.db")
    assert "created a starter config" in out.err and "personal mode" in out.err
    assert "VCF_MCP_AUTH_TOKEN" not in entry["env"]
    assert not os.path.exists("vcf_control_plane.db")  # nothing is ever written to the working directory


def test_old_working_directory_database_is_adopted_once(tmp_path, monkeypatch):
    from vcf_enterprise_mcp.core import paths
    monkeypatch.setenv("VCF_MCP_HOME", str(tmp_path / "state"))
    monkeypatch.delenv("VCF_MCP_DB_PATH", raising=False)
    old_dir = tmp_path / "where-i-used-to-run-it"
    old_dir.mkdir()
    (old_dir / "vcf_control_plane.db").write_bytes(b"old plans")
    monkeypatch.chdir(old_dir)
    db = paths.default_db_path()
    assert db == str(tmp_path / "state" / "control_plane.db")
    assert open(db, "rb").read() == b"old plans"
    (old_dir / "vcf_control_plane.db").write_bytes(b"changed later")
    paths.default_db_path()
    assert open(db, "rb").read() == b"old plans"  # copied once, never overwritten


def test_unwritable_state_folder_gives_a_fix_not_files_in_the_working_directory(tmp_path, monkeypatch):
    from vcf_enterprise_mcp.secrets.local_encrypted import LocalEncryptedSecretProvider
    from vcf_enterprise_mcp.secrets.models import SecretValue
    locked = tmp_path / "locked"
    locked.mkdir()
    store = LocalEncryptedSecretProvider(storage_path=str(locked / "credentials.json"))
    locked.chmod(0o500)
    monkeypatch.chdir(tmp_path)
    try:
        with pytest.raises(PermissionError, match="VCF_MCP_HOME"):
            store.store("local://lab/x", SecretValue("s3cret-value"))
    finally:
        locked.chmod(0o700)
    assert not (tmp_path / ".vcf-mcp").exists()


def test_legacy_state_directory_is_migrated_not_lost(tmp_path, monkeypatch):
    from vcf_enterprise_mcp.core import paths
    monkeypatch.delenv("VCF_MCP_HOME", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".vcf_mcp").mkdir()
    (tmp_path / ".vcf_mcp" / "master.key").write_text("old-key")
    (tmp_path / ".vcf-mcp").mkdir()
    (tmp_path / ".vcf-mcp" / "config.yaml").write_text("keep: me")
    monkeypatch.setattr(paths, "_migrated", False)
    assert paths.state_dir() == tmp_path / ".vcf-mcp"
    assert (tmp_path / ".vcf-mcp" / "master.key").read_text() == "old-key"
    assert (tmp_path / ".vcf-mcp" / "config.yaml").read_text() == "keep: me"  # never overwritten
    assert paths.default_db_path() == str(tmp_path / ".vcf-mcp" / "control_plane.db")


def test_vcf_find_tool_answers_in_setup_mode(lab):
    """It is advertised in setup mode, so calling it must not be refused with 'not available'."""
    _, cfg_path, token = lab
    engine = build(cfg_path)
    assert engine.setup_mode
    res = rpc(engine, token, "tools/call", {"name": "vcf_find_tool", "arguments": {"task": "how do I set this up?"}})["result"]
    text = res["content"][0]["text"]
    assert "is not available" not in text and "vcf_setup" in text


def test_starter_config_listens_on_loopback_for_http_mode(lab):
    _, cfg_path, _ = lab
    cfg = EnterpriseSettings.load_from_yaml(str(cfg_path))
    assert cfg.server.host == "127.0.0.1" and cfg.server.port == 8443


def test_configured_urls_follow_endpoint_overrides():
    """A typed appliance name that does not resolve here can be mapped to a reachable address (docs: vcf.endpoint_overrides)."""
    cfg = EnterpriseSettings()
    cfg.vcf.vcenter_url = "https://vc01.corp.example"
    cfg.vcf.nsx_url = "https://nsx01.corp.example"
    cfg.vcf.endpoint_overrides = {"vc01.corp.example": "https://203.0.113.10"}
    urls = server._real_vcf_urls(cfg.vcf)
    assert urls["vcenter"] == "https://203.0.113.10"
    assert urls["nsx"] == "https://nsx01.corp.example"  # unmapped names are used as typed
