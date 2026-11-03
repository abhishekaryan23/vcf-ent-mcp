# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""Conformance against the official MCP Python SDK client (what most harnesses are built on).

The SDK validates every response against the MCP schema, so a server that passes here is accepted by
strict clients (Claude Desktop/Code, Cursor, VS Code, LM Studio, ...). Skipped when `mcp` is not installed.
"""

import os
import sys

import pytest

mcp = pytest.importorskip("mcp")
from mcp import ClientSession, StdioServerParameters  # noqa: E402
from mcp.client.stdio import stdio_client  # noqa: E402


def _params(tmp_path, with_token=True):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("server: {mode: stdio, environment: testing, storage_mode: LOCAL_LAB}\n"
                   "policy: {operating_mode: DISCOVERY_ONLY}\n"
                   "idp: {enabled: true, issuer_url: 'https://idp.corp.internal', client_id: vcf-mcp-client, allow_lab_tokens: true}\n")
    env = {"HOME": str(tmp_path), "PATH": os.environ.get("PATH", ""), "VCF_ENTERPRISE_MCP_CONFIG": str(cfg), "VCF_MCP_HOME": str(tmp_path),
           "VCF_MCP_DB_PATH": str(tmp_path / "cp.db"), "VCF_MCP_CREDENTIALS_PATH": str(tmp_path / "creds.json"),
           "VCF_MCP_MASTER_KEY_PATH": str(tmp_path / "master.key"), "VCF_MCP_KMS_KEY_PATH": str(tmp_path / "kms.key"),
           "VCF_MCP_LAB_JWT_KEY_PATH": str(tmp_path / "jwt.pem"),
           "PYTHONPATH": os.pathsep.join([os.path.abspath("src"), os.environ.get("PYTHONPATH", "")])}
    from vcf_enterprise_mcp.auth.lab_auth import mint_lab_jwt_token
    if with_token:
        env["VCF_MCP_AUTH_TOKEN"] = mint_lab_jwt_token(user_id="sdk@lab", role="VCF_PLATFORM_ADMIN",
                                                       custom_key_path=str(tmp_path / "jwt.pem"))["authorization_header"]
    return StdioServerParameters(command=sys.executable, args=["-c", "from vcf_enterprise_mcp.core.server import main; main()"],
                                 env=env, cwd=str(tmp_path))


@pytest.mark.anyio
async def test_official_client_handshake_tools_prompts_and_setup(tmp_path):
    async with stdio_client(_params(tmp_path)) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            assert init.server_info.name == "vcf-enterprise-mcp-control-plane"
            assert init.instructions and "UNOFFICIAL" in init.instructions
            tools = (await session.list_tools()).tools
            names = {t.name for t in tools}
            assert {"vcf_setup", "vcf_access_report", "vcf_find_tool"} <= names
            assert all(t.input_schema.get("type") == "object" for t in tools)
            prompts = (await session.list_prompts()).prompts
            assert any(p.name == "vcf-oncall-troubleshoot" for p in prompts)
            res = await session.call_tool("vcf_setup", {})
            assert not res.is_error and "NEEDS_INPUT" in res.content[0].text
            found = await session.call_tool("vcf_find_tool", {"task": "the CRM app cannot reach its database"})
            assert "vcf_trace_application" in found.content[0].text


@pytest.mark.anyio
async def test_handshake_works_without_a_token_and_the_problem_is_reported_at_tools_list(tmp_path):
    async with stdio_client(_params(tmp_path, with_token=False)) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()  # must not fail: the harness would only show "server crashed"
            assert "AUTHENTICATION PROBLEM" in init.instructions
            with pytest.raises(Exception) as err:  # McpError / MCPError depending on the SDK version
                await session.list_tools()
            assert "VCF_MCP_AUTH_TOKEN" in str(err.value)
            res = await session.call_tool("vcf_setup", {})
            assert res.is_error and "VCF_MCP_AUTH_TOKEN" in res.content[0].text


@pytest.mark.anyio
async def test_cold_start_with_no_config_file_boots_into_setup_mode(tmp_path):
    """README path: mint a token, add the server, ask for setup. No config exists yet; the server must still start."""
    params = _params(tmp_path)
    cfg = tmp_path / "config.yaml"
    cfg.unlink()  # nothing configured at all
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            assert "vcf_setup" in init.instructions
            names = {t.name for t in (await session.list_tools()).tools}
            assert names == {"vcf_setup", "vcf_access_report", "vcf_find_tool"}
            res = await session.call_tool("vcf_setup", {})
            assert not res.is_error and "NEEDS_INPUT" in res.content[0].text
            lst = await session.call_tool("vcf_list_vms", {})
            assert lst.is_error and "vcf_setup" in lst.content[0].text
    assert cfg.exists()  # the starter config was created for the next start
