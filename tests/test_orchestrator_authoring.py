# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""Orchestrator 9.1 authoring: script linter, workflow compiler, guardrails, tool routing and skills."""

import pytest

from vcf_enterprise_mcp.automation import orchestrator as orch
from vcf_enterprise_mcp.automation.js_lint import lint_javascript, lint_script
from vcf_enterprise_mcp.automation.wf_compiler import SpecError, compile_spec
from vcf_enterprise_mcp.router.catalog import ALL_ENTERPRISE_TOOLS
from vcf_enterprise_mcp.skills import get_skill_registry
from vcf_enterprise_mcp.tools.find_tool import rank


@pytest.mark.parametrize("script,rule", [
    ("class A {}", "unsupported_class"),
    ("async function f() { await g(); }", "unsupported_async_await"),
    ("var x = a?.b;", "unsupported_optional_chaining"),
    ("var x = a ?? 1;", "unsupported_nullish"),
    ("var x = [...a];", "unsupported_spread"),
    ("const {a, b} = obj;", "unsupported_destructuring"),
    ("function f(a, b = 2) { return a; }", "unsupported_default_params"),
    ("var r = /a+/u;", "unsupported_regex_u_flag"),
    ("var n = new Intl.NumberFormat();", "unsupported_intl"),
    ("var f = new java.io.File('/etc/passwd');", "java_access"),
    ("var x = eval('1+1');", "dynamic_code"),
    ("var password = 'Sup3rSecret!';", "hardcoded_secret"),
    ("var s = 'done ✅';", "non_ascii"),
])
def test_linter_rejects_what_rhino_9x_or_security_rules_forbid(script, rule):
    assert rule in [e["rule"] for e in lint_javascript(script).errors]


def test_linter_accepts_modern_syntax_only_at_the_rhino_1_7_15_level_and_ignores_strings():
    ok = ("const vms = VcPlugin.getAllVirtualMachines();\nlet names = [];\nfor (const vm of vms) { names.push(vm.name); }\n"
          "var big = vms.filter(v => v.summary.storage.committed > 2 ** 30);\nvar o = {class: 1, async: 2};\n"
          "var msg = `found ${names.length}`; // class X ?. ?? ... async await\nvar d = a / b / c;\nreturn msg;")
    assert lint_javascript(ok, level="rhino_1_7_15").ok
    # The default level is plain ES5, which is what a real 9.1.1 server was proven to run.
    rules = {e["rule"] for e in lint_javascript(ok).errors}
    assert {"unsupported_let_const", "unsupported_arrow", "unsupported_template", "unsupported_for_of"} <= rules
    assert all(e["fix"] for e in lint_javascript(ok).errors)


def test_8x_is_es5_only():
    assert "unsupported_let_const" in [e["rule"] for e in lint_javascript("let x = 1;", "8.18.0").errors]


def test_python_get_token_warning_only_on_9_1_0():
    assert lint_script("t = context.getToken()", "python:3.11", "9.1.0.0").warnings
    assert not lint_script("t = context.getToken()", "python:3.11", "9.1.1.0").warnings


SPEC = {"name": "Expand disk", "inputs": [{"name": "vmName", "type": "string"}, {"name": "addGB", "type": "number"}],
        "outputs": [{"name": "summary", "type": "string"}], "variables": [{"name": "ok", "type": "boolean"}],
        "steps": [{"id": "check", "type": "script", "script": "ok = addGB > 0;", "reads": ["addGB"], "writes": ["ok"]},
                  {"id": "gate", "type": "decision", "condition": "return ok;", "reads": ["ok"], "then": "grow", "else": "bad"},
                  {"id": "grow", "type": "action", "action": "com.mcp.storage/expandDisk", "args": ["vmName", "addGB"], "result": "summary", "next": "done"},
                  {"id": "bad", "type": "error_end"}, {"id": "done", "type": "end"}],
        "on_error": "bad"}


def test_compiler_builds_linked_schema_with_error_handler():
    schema, scripts = compile_spec(SPEC)
    items = {i["name"]: i for i in schema["workflow-item"]}
    assert schema["root-name"] == "item1" and items["item1"]["out-name"] == "item2"
    assert items["item2"]["type"] == "custom-condition" and items["item2"]["alt-out-name"] == "item4"
    assert items["item3"]["script-module"] == "com.mcp.storage/expandDisk" and items["item3"]["catch-name"] == "item4"
    assert items["item4"]["end-mode"] == "1" and items["item5"]["end-mode"] == "0"
    assert {a["name"] for a in schema["attrib"]} == {"ok", "errorMessage"}
    assert len(scripts) == 3


@pytest.mark.parametrize("mutate,needle", [
    (lambda s: s["steps"][0].update(reads=["missing"]), "not declared"),
    (lambda s: s["steps"][0].update(type="loop"), "unknown type"),
    (lambda s: s["steps"][1].update({"else": "nowhere"}), "unknown step"),
    (lambda s: s.update(steps=[]), "no steps"),
    (lambda s: s["steps"][2].update(action="expandDisk"), "module/actionName"),
])
def test_compiler_errors_say_what_to_fix(mutate, needle):
    import copy
    spec = copy.deepcopy(SPEC)
    mutate(spec)
    with pytest.raises(SpecError) as exc:
        compile_spec(spec)
    assert any(needle in p["message"] for p in exc.value.problems) and all(p["fix"] for p in exc.value.problems)


def test_guardrails_keep_the_mcp_inside_its_own_content():
    cfg = {"managed_category": "MCP-Managed", "module_prefix": "com.mcp"}
    orch._check_managed_path(cfg, "MCP-Managed/Storage")
    orch._check_module(cfg, "com.mcp.storage")
    for bad in ("Northwind/Storage", "MCP-ManagedX", "Library/vCenter"):
        with pytest.raises(orch.OrchestratorRefused):
            orch._check_managed_path(cfg, bad)
    for bad in ("com.vmware.library.vc", "com.mcpx"):
        with pytest.raises(orch.OrchestratorRefused):
            orch._check_module(cfg, bad)


ROUTING = {
    "the CRM app cannot reach its database": "vcf_trace_application",
    "why is everything slow in prod and nobody can log in": "vcf_diagnose",
    "vcenter won't load for the prod domain": "vcf_diagnose",
    "is the Payments website down?": "vcf_trace_application",
    "show me how the networks are built, which are VPC and which are VDS": "vcf_list_networks",
    "which SDDC tasks failed last night": "vcf_list_failed_tasks",
    "list active alarms": "vcf_list_alerts",
    "create a new cloud template for 3 web servers": "vcf_automation_create_template",
    "what image mappings and flavors exist in assembler": "vcf_automation_list",
    "run the expand disk workflow on fin-ora01": "vcf_orch_run",
    "use our existing automation to rotate the admin password": "vcf_orch_run",
    "the run is waiting for input, confirm it": "vcf_orch_answer",
    "write an action that returns powered-off VMs": "vcf_orch_save_action",
    "create a python action that calls the ITSM API": "vcf_orch_save_action",
    "build a workflow that pre-stages an AD account and then expands a disk": "vcf_orch_save_workflow",
    "create workflow for decommissioning test VMs": "vcf_orch_save_workflow",
    "edit workflow Disk usage report to add a step": "vcf_orch_save_workflow",
    "is this javascript supported by the rhino engine?": "vcf_orch_validate",
    "check script before I save it": "vcf_orch_validate",
    "roll back the workflow to the previous version": "vcf_orch_rollback",
    "add a rest host for ServiceNow to orchestrator": "vcf_orch_add_integration",
    "connect orchestrator to the EU active directory": "vcf_orch_add_integration",
    "the vcenter shows unusable in orchestrator, reconnect vcenter": "vcf_orch_add_integration",
    "add powershell host for the windows team": "vcf_orch_add_integration",
    "store the ITSM url in a configuration element": "vcf_orch_set_configuration",
    "create a python environment with requests for my action": "vcf_orch_create_environment",
    "install the SNMP plug-in": "vcf_orch_install_plugin",
    "what orchestrator version is this and which known issue applies": "vcf_orch_about",
    "find workflow that expands disks in orchestrator": "vcf_orch_list",
    "show me the failed runs of the expand disk workflow": "vcf_orch_list_executions",
    "show the run history of that workflow": "vcf_orch_list_executions",
    "export the orchestrator package com.mcp.reports": "vcf_orch_export_package",
    "back up the package": "vcf_orch_export_package",
    "build a package from what you saved": "vcf_orch_build_package",
    "what have you saved in orchestrator": "vcf_orch_tracked_changes",
    "try this script on orchestrator before saving": "vcf_orch_try_script",
    "run this javascript snippet on orchestrator": "vcf_orch_try_script",
    "list vms": "vcf_list_vms",
    "show workload domains": "vcf_list_domains",
    "what can you do with my access": "vcf_access_report",
    "domain controller for the finance AD forest is unreachable": "vcf_trace_application",
    "users cannot login, authentication errors": "vcf_diagnose",
}


@pytest.mark.parametrize("task,tool", list(ROUTING.items()))
def test_find_tool_routes_plain_requests(task, tool):
    got = rank(task)
    assert got and got[0]["tool"] == tool, f"{task!r}: got {[g['tool'] for g in got[:3]]}"


def test_every_routed_tool_and_skill_exists():
    from vcf_enterprise_mcp.tools.find_tool import INTENTS
    from vcf_enterprise_mcp.core.protocol import EnterpriseMCPProtocolEngine
    names = {c.name for c in ALL_ENTERPRISE_TOOLS} | {d["name"] for d in EnterpriseMCPProtocolEngine.SETUP_TOOL_DEFINITIONS}
    skills = {s.name for s in get_skill_registry().list_all_skills()}
    for tool, skill, *_ in INTENTS:
        assert tool in names
        assert skill is None or skill in skills
    for s in get_skill_registry().list_all_skills():
        assert set(s.allowed_tools) <= names, s.name


def test_new_tool_descriptions_are_small_model_friendly():
    for c in ALL_ENTERPRISE_TOOLS:
        if c.name.startswith("vcf_orch_") or c.name == "vcf_find_tool":
            assert len(c.description) < 1400, c.name
            assert "USE FOR" in c.description or c.name == "vcf_find_tool", c.name
            if c.risk_class.value != "READ":
                assert "dry_run" in c.schema["properties"] and "plan_id" in c.schema["properties"], c.name


def test_small_model_spec_variants_are_accepted():
    spec = {"name": "Disk usage report", "inputs": [{"name": "vmName", "type": "string"}], "outputs": [{"name": "report", "type": "string"}],
            "variables": [{"name": "report", "type": "string"}],
            "steps": [{"id": "r", "type": "script", "script": {"script": "report = 'x ' + vmName;", "reads": ["vmName"], "writes": ["report"]}}]}
    schema, scripts = compile_spec(spec)
    assert scripts[0]["script"] == "report = 'x ' + vmName;" and schema["attrib"] == []


def test_mcp_reference_in_script_is_rejected_with_the_right_fix():
    errs = lint_javascript("var key = 'local://ITSM/apiKey';").errors
    assert any(e["rule"] == "mcp_reference_in_script" and "vcf_orch_set_configuration" in e["fix"] for e in errs)


def test_find_tool_falls_back_to_workflow_search_for_unknown_actions():
    import asyncio
    from vcf_enterprise_mcp.tools.find_tool import VCFFindToolTool
    tool = VCFFindToolTool.__new__(VCFFindToolTool)
    out = asyncio.run(tool.run_live(None, {"task": "rotate the local admin password on eu-app01"}))
    assert out["best"] in ("vcf_orch_list", "vcf_orch_run")


def test_read_only_orchestrator_account_is_refused_before_planning():
    class P:
        def request(self, method, path, params=None, json_body=None, headers=None):
            class R:
                status_code, is_success = 200, True

                def json(self):
                    return {"roles": ["Workflow Designer", "Viewer"]}
            return R()
    with pytest.raises(orch.OrchestratorRefused, match="READ-ONLY"):
        orch._check_writable(P())
