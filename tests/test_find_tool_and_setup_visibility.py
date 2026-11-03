# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""vcf_find_tool knows about setup, read-only mode keeps setup reachable, default skill prunes tools/list (review F15, F19)."""

import asyncio
import json

from tests.fixtures.test_tokens import ADMIN_BEARER
from vcf_enterprise_mcp.config.settings import EnterpriseSettings
from vcf_enterprise_mcp.core.protocol import EnterpriseMCPProtocolEngine
from vcf_enterprise_mcp.setup.safety_profile import SafetyProfile
from vcf_enterprise_mcp.tools.find_tool import rank


def call(engine, method, params=None):
    req = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
    return asyncio.run(engine.handle_jsonrpc_request(req, auth_header=ADMIN_BEARER))["result"]


def test_find_tool_routes_setup_questions_to_vcf_setup():
    for phrase in ("set up VCF MCP", "setup the vcf mcp", "how do I connect to my vCenter", "configure this for the first time",
                   "get started", "I want to change the service account"):
        assert rank(phrase)[0]["tool"] == "vcf_setup", phrase
    assert rank("what can you do")[0]["tool"] == "vcf_access_report"
    assert rank("the CRM app cannot reach its database")[0]["tool"] != "vcf_setup"


def test_find_tool_answer_for_setup_names_the_role_and_never_asks_for_passwords():
    engine = EnterpriseMCPProtocolEngine()
    out = call(engine, "tools/call", {"name": "vcf_find_tool", "arguments": {"task": "set up VCF MCP"}})
    answer = json.loads(out["content"][0]["text"])
    assert answer["best"] == "vcf_setup" and "MCP_ADMIN" in answer["remember"] and "Never ask" in answer["remember"]


def test_read_only_mode_does_not_hide_the_setup_tools(tmp_path):
    engine = EnterpriseMCPProtocolEngine()
    engine.pep.pdp.config.operating_mode = "AUDITED_OPERATIONS"
    profile = SafetyProfile(tmp_path / "safety.json")
    profile.tighten([], reason="test", actor="t", read_only=True)
    engine.pep.safety_profile = profile
    names = {t["name"] for t in call(engine, "tools/list")["tools"]}
    assert {"vcf_setup", "vcf_access_report"} <= names
    assert "vcf_power_vm" not in names                 # real changes stay hidden
    profile.tighten(["vcf_setup"], reason="test", actor="t")
    assert "vcf_setup" not in {t["name"] for t in call(engine, "tools/list")["tools"]}   # an explicit block still works


def test_default_skill_pre_prunes_tools_list_for_small_models():
    plain = EnterpriseMCPProtocolEngine()
    full = {t["name"] for t in call(plain, "tools/list")["tools"]}
    pruned = EnterpriseMCPProtocolEngine(config=EnterpriseSettings(server={"default_skill": "vcf-viewer-inventory-summary"}))
    result = call(pruned, "tools/list")
    names = {t["name"] for t in result["tools"]}
    assert result["activeSkill"] == "vcf-viewer-inventory-summary"
    assert len(names) < len(full) and {"vcf_setup", "vcf_find_tool", "vcf_access_report"} <= names
    stale = EnterpriseMCPProtocolEngine(config=EnterpriseSettings(server={"default_skill": "no-such-skill"}))
    assert {t["name"] for t in call(stale, "tools/list")["tools"]} == full   # a stale default never breaks the listing
