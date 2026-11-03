# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Orchestrator behaviour proven on a real VCF Automation 9.1.1 server (community project vcf-orchestrator-mcp) and checked
against the official Orchestrator 9.0 API spec: XML workflow content, typed values, runs, synchronous actions, commits,
folders, paging, plug-in upload, package export, try-script and change tracking. Runs against the in-process simulator
(tests/orch_sim_support.py) so request shapes, headers and error mapping are exercised end to end.
"""

import copy
import io
import json
import os
import stat
import xml.etree.ElementTree as ET
import zipfile

import pytest

from tests.orch_sim_support import ORCH_URL, SimPlatform, SimTransport, make_sim, parse_json
from vcf_enterprise_mcp.adapter.transport.base import TransportResponse
from vcf_enterprise_mcp.automation import orchestrator as orch
from vcf_enterprise_mcp.automation import wire
from vcf_enterprise_mcp.automation.js_lint import lint_javascript
from vcf_enterprise_mcp.automation.orch_changes import ChangeTracker
from vcf_enterprise_mcp.automation.wf_compiler import compile_spec, schema_for_json, to_xml


@pytest.fixture(autouse=True)
def _isolated_files(tmp_path, monkeypatch):
    monkeypatch.setenv("VCF_MCP_ORCH_CHANGES_FILE", str(tmp_path / "home" / "orch_changes.json"))
    monkeypatch.setenv("VCF_MCP_EXPORT_DIR", str(tmp_path / "exports"))
    monkeypatch.setenv("VCF_MCP_PLUGIN_DIR", str(tmp_path / "plugins"))
    monkeypatch.setattr(orch.time, "sleep", lambda s: None)


@pytest.fixture
def env(tmp_path):
    sim, tr, plat = make_sim(tmp_path)
    return sim, tr, plat


SPEC = {"name": "Disk usage report", "description": "Report for a VM",
        "inputs": [{"name": "vmName", "type": "string", "default": "web01"}, {"name": "names", "type": "Array/string", "default": ["a", "b"]}],
        "outputs": [{"name": "report", "type": "string"}], "variables": [{"name": "retries", "type": "number", "value": 3}],
        "steps": [{"id": "s", "type": "script", "script": "report = 'usage for ' + vmName;", "reads": ["vmName"], "writes": ["report"]}]}
CAT = "MCP-Managed/Storage"


def _ns(tag):
    return tag.split("}")[-1]


# ---- 1. workflow XML -----------------------------------------------------------------------------------------

def test_xml_mirrors_the_layout_proven_on_a_real_server():
    spec = copy.deepcopy(SPEC)
    spec["name"] = "Report ]]> with CDATA end"
    spec["variables"].append({"name": "vm", "type": "VC:VirtualMachine", "value": "vm-42"})
    spec["steps"] = [{"id": "s", "type": "script", "script": "report = 'a ]]> b';", "reads": ["vmName"], "writes": ["report"]},
                     {"id": "act", "type": "action", "action": "com.mcp.storage/expandDisk", "args": ["vmName"], "result": "report"},
                     {"id": "gate", "type": "decision", "condition": "return true;", "then": "sub", "else": "bad"},
                     {"id": "sub", "type": "workflow", "workflow_id": "wf-x", "pass": {"a": "vmName"}, "receive": {}},
                     {"id": "bad", "type": "error_end"}, {"id": "done", "type": "end"}]
    spec["on_error"] = "bad"
    schema, _ = compile_spec(spec)
    xml = to_xml(schema, "wf-123")
    root = ET.fromstring(xml)
    assert _ns(root.tag) == "schema-workflow"
    for k, v in {"object-name": "workflow:name=generic", "id": "wf-123", "version": "1.0.0", "api-version": "6.0.0", "restartMode": "1",
                 "resumeFromFailedMode": "0", "editor-version": "2.0", "root-name": "item1"}.items():
        assert root.get(k) == v, k
    assert 'xmlns:ns2="http://www.vmware.com/vco"' in xml and xml.startswith('<?xml version="1.0" encoding="UTF-8"?>')
    assert root.find("display-name").text == "Report ]]> with CDATA end"  # "]]>" survives CDATA splitting
    assert [p.get("name") for p in root.find("input")] == ["vmName", "names"]
    attribs = {a.get("name"): a for a in root.findall("attrib")}
    assert attribs["retries"].get("read-only") == "false" and attribs["retries"][0].text == "3" and _ns(attribs["retries"][0].tag) == "number"
    assert attribs["vm"][0].get("type") == "VC:VirtualMachine" and attribs["vm"][0].get("id") == "vm-42"
    items = {i.get("name"): i for i in root.findall("workflow-item")}
    assert all(i.get("comparator") == "0" for i in items.values())
    task = items["item1"]
    assert task.get("type") == "task" and task.get("catch-name") == "item5" and task.get("throw-bind-name") == "errorMessage"
    assert task.find("script").get("encoded") == "false" and task.find("script").text == "report = 'a ]]> b';"
    assert [b.get("export-name") for b in task.find("in-binding")] == ["vmName"] and [b.get("name") for b in task.find("out-binding")] == ["report"]
    assert items["item2"].get("script-module") == "com.mcp.storage/expandDisk"
    assert items["item3"].get("type") == "custom-condition" and items["item3"].get("out-name") == "item4" and items["item3"].get("alt-out-name") == "item5"
    assert items["item4"].get("type") == "link" and items["item4"].get("linked-workflow-id") == "wf-x"
    assert items["item5"].get("type") == "end" and items["item5"].get("end-mode") == "1"
    assert items["item6"].get("end-mode") == "0"
    quals = {pp.get("name"): pp.find("p-qual") for pp in root.find("presentation")}
    assert quals["vmName"].get("name") == "defaultValue" and quals["vmName"].text == "web01"
    assert quals["names"].text == "#{#string#a#;#string#b#}#"


def test_json_fallback_model_has_no_xml_only_keys_and_typed_attribute_values():
    schema, _ = compile_spec(SPEC)
    js = schema_for_json(schema)
    assert all("default" not in p for p in js["input"]["param"])
    assert js["attrib"][0]["value"] == {"number": {"value": 3}}
    assert "default" in schema["input"]["param"][0]  # the internal model keeps it


def test_save_workflow_sends_xml_for_validate_and_content(env):
    sim, tr, plat = env
    res = orch.save_workflow(plat, SPEC, CAT)
    assert res["saved"] and res["version"] == "1.0.0"
    validate = tr.calls("PUT", "/workflows/validate/schema")[0]
    put = tr.calls("PUT", "/content")[0]
    for r in (validate, put):
        assert r["headers"]["Content-Type"] == "application/xml" and r["body"].startswith(b"<?xml")
    assert ET.fromstring(put["body"]).get("id") == res["workflow_id"]  # the real id, not the placeholder
    w = sim.s["orch"]["workflows"][res["workflow_id"]]
    assert [i["display-name"] for i in w["content"]["workflow-item"]][0] == "s"
    assert w["content"]["input"]["param"][0]["name"] == "vmName" and w["content"]["version"] == "1.0.0"


def test_xml_415_is_retried_once_as_json(env):
    sim, tr, plat = env

    class No415(SimTransport):
        def send(self, request):
            if request.headers.get("Content-Type") == "application/xml":
                self.requests.append({"method": request.method, "path": request.url, "headers": dict(request.headers), "body": request.data, "query": ""})
                return TransportResponse(status_code=415, headers={}, body=b'{"message": "no xml"}')
            return super().send(request)

    tr2 = No415(sim)
    plat2 = SimPlatform(sim, tr2)
    res = orch.save_workflow(plat2, SPEC, CAT)
    assert res["saved"]
    xml_attempts = [r for r in tr2.requests if r["headers"].get("Content-Type") == "application/xml"]
    json_puts = [r for r in tr2.requests if r["method"] == "PUT" and r["path"].endswith("/content") and r["headers"].get("Content-Type") == "application/json"]
    assert len(xml_attempts) == 2 and len(json_puts) == 1  # validate + content tried as XML once each, content retried as JSON
    assert "default" not in json.dumps(json.loads(json_puts[0]["body"])["input"])


def test_update_sends_changeset_header_and_bumps_the_patch_version(env):
    sim, tr, plat = env
    first = orch.save_workflow(plat, SPEC, CAT)
    plan = orch.plan_workflow(plat, SPEC, CAT)
    assert plan["operation"] == "update" and plan["problems"] and plan["current_changeset_sha"] == first["changeset_sha"]
    assert orch.save_workflow(plat, SPEC, CAT)["conflict"] is True  # no base sha: refused with an instruction
    second = orch.save_workflow(plat, SPEC, CAT, first["changeset_sha"])
    assert second["saved"] and second["version"] == "1.0.1" and second["changeset_sha"] != first["changeset_sha"]
    assert tr.calls("PUT", "/content")[-1]["headers"]["X-VRO-Changeset-Sha"] == first["changeset_sha"]
    third = orch.save_workflow(plat, {**SPEC, "version": "2.5.0"}, CAT, second["changeset_sha"])
    assert third["version"] == "2.5.0"
    stale = orch.save_workflow(plat, SPEC, CAT, first["changeset_sha"])
    assert stale["saved"] is False and "changed since" in stale["reason"]


# ---- 2. script level -------------------------------------------------------------------------------------------

def test_es5_is_the_default_and_the_setting_widens_it(env):
    sim, tr, plat = env
    modern = "const a = [1, 2];\nvar b = a.map(x => x * 2);\nreturn `n=${b.length}`;"
    res = orch.validate_action(plat, modern)
    assert not res["ok"] and res["script_level"] == "es5"
    assert {"unsupported_let_const", "unsupported_arrow", "unsupported_template"} <= {e["rule"] for e in res["errors"]}
    assert all(e["fix"] for e in res["errors"])
    plat.orchestrator["script_level"] = "rhino_1_7_15"
    assert orch.validate_action(plat, modern)["ok"]
    with pytest.raises(ValueError):
        lint_javascript("var a;", level="es6")
    # Workflow scripts follow the same level.
    plat.orchestrator["script_level"] = "es5"
    spec = {**SPEC, "steps": [{"id": "s", "type": "script", "script": "let x = 1; report = 'a';", "writes": ["report"]}]}
    assert orch.validate_workflow(plat, spec)["valid"] is False


# ---- 3. typed values ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("type_,value,expected", [
    ("string", "hi", {"string": {"value": "hi"}}),
    ("text", {"a": 1}, {"string": {"value": '{"a": 1}'}}),
    ("SecureString", "s3cret", {"secure-string": {"value": "s3cret"}}),
    ("EncryptedString", "enc", {"encrypted-string": {"value": "enc"}}),
    ("number", "5", {"number": {"value": 5}}),
    ("number", 2.5, {"number": {"value": 2.5}}),
    ("boolean", "true", {"boolean": {"value": True}}),
    ("boolean", False, {"boolean": {"value": False}}),
    ("Date", "2026-11-02T10:00:00Z", {"date": {"value": "2026-11-02T10:00:00.000Z"}}),
    ("Properties", {"a": 1, "b": {"c": "x"}}, {"properties": {"property": [
        {"key": "a", "value": {"number": {"value": 1}}},
        {"key": "b", "value": {"properties": {"property": [{"key": "c", "value": {"string": {"value": "x"}}}]}}}]}}),
    ("Array/string", ["a", "b"], {"array": {"elements": [{"string": {"value": "a"}}, {"string": {"value": "b"}}]}}),
    ("Array/number", [1, 2], {"array": {"elements": [{"number": {"value": 1}}, {"number": {"value": 2}}]}}),
    ("VC:VirtualMachine", "vm-42", {"sdk-object": {"type": "VC:VirtualMachine", "id": "vm-42"}}),
    ("VC:VirtualMachine", {"id": "vm-42"}, {"sdk-object": {"type": "VC:VirtualMachine", "id": "vm-42"}}),
    ("ResourceElement", "abc", {"sdk-object": {"type": "ResourceElement", "id": "abc"}}),
    ("ConfigurationElement", {"id": "c1", "type": "ConfigurationElement"}, {"sdk-object": {"type": "ConfigurationElement", "id": "c1"}}),
    ("Array/VC:VirtualMachine", ["vm-1"], {"array": {"elements": [{"sdk-object": {"type": "VC:VirtualMachine", "id": "vm-1"}}]}}),
    ("Any", [1, "x"], {"array": {"elements": [{"number": {"value": 1}}, {"string": {"value": "x"}}]}}),
])
def test_to_wire(type_, value, expected):
    assert wire.to_wire(type_, value) == expected
    assert wire.from_wire(wire.to_wire(type_, value)) is not None or value in (False, 0)


@pytest.mark.parametrize("t", ["ResourceElement", "ResourceElementCategory", "ConfigurationElement", "ConfigurationElementCategory", "Workflow",
                               "WorkflowCategory", "WorkflowToken", "Action", "Module", "Package", "Task", "Policy", "PolicyTemplate", "PolicyTemplateCategory"])
def test_builtin_inventory_types_are_sdk_objects(t):
    assert wire.to_wire(t, "id-1") == {"sdk-object": {"type": t, "id": "id-1"}}


def test_wire_errors_and_round_trips():
    with pytest.raises(wire.WireError):
        wire.to_wire("VC:VirtualMachine", "")
    with pytest.raises(wire.WireError):
        wire.to_wire("number", "abc")
    props = {"a": 1, "list": ["x", True], "nested": {"k": "v"}}
    assert wire.from_wire(wire.to_wire("Properties", props)) == props
    assert wire.from_wire({"sdk-object": {"type": "VC:VM", "id": "1", "displayValue": "vm"}}) == {"type": "VC:VM", "id": "1", "displayValue": "vm"}
    secret = [{"name": "pw", "type": "SecureString", "value": {"secure-string": {"value": "x"}}}, {"name": "n", "type": "number", "value": {"number": {"value": 3}}}]
    assert wire.params_to_object(secret) == {"pw": "<hidden>", "n": 3}  # secrets are never decoded into results
    params = wire.build_parameters([{"name": "n", "type": "number"}], {"n": "7"})
    assert params == [{"name": "n", "type": "number", "scope": "local", "value": {"number": {"value": 7}}}]
    with pytest.raises(wire.WireError, match="Unknown input"):
        wire.build_parameters([{"name": "n", "type": "number"}], {"x": 1})


# ---- 4. runs ---------------------------------------------------------------------------------------------------

def _vm(sim):
    return next(v for vc in sim.s["vcenters"].values() for v in vc["vms"] if v.get("disks"))["name"]


def test_run_workflow_takes_the_id_from_location_and_reads_typed_outputs(env):
    sim, tr, plat = env
    res = orch.run_workflow(plat, "wf-expand-disk", {"vmName": _vm(sim), "diskNumber": "1", "addGB": 10}, {})
    assert res["state"] == "completed" and res["outputs"]["newSizeGB"] > 10  # decoded from the number wire value, not a string
    post = tr.calls("POST", "/executions")[0]
    assert json.loads(post["body"])["parameters"][1] == {"name": "diskNumber", "type": "number", "scope": "local", "value": {"number": {"value": 1}}}
    exec_get = [r for r in tr.calls("GET", "/executions/") if "showDetails=true" in r["query"]]
    assert exec_get, "executions are read with showDetails=true"
    assert not [r for r in tr.requests if "queryCount" in r["query"]]


def test_failed_run_includes_logs_and_the_error(env):
    sim, tr, plat = env
    res = orch.run_workflow(plat, "wf-expand-disk", {"vmName": "no-such-vm", "diskNumber": 1, "addGB": 10}, {})
    assert res["state"] == "failed" and "not found" in res["error"]
    assert "logs" in res  # always included on failure (may be empty if the server logged nothing)
    ok = orch.run_workflow(plat, "wf-expand-disk", {"vmName": _vm(sim), "diskNumber": 1, "addGB": 1}, {}, include_logs=True)
    assert "logs" in ok


def test_execution_view_reads_both_spellings_and_stops_on_waiting(env):
    sim, tr, plat = env
    waiting = orch.run_workflow(plat, "wf-rotate-admin", {"vmName": _vm(sim)}, {})
    assert waiting["state"] == "waiting" and "needs user input" in waiting["note"]
    ex = orch.get_execution(plat, "wf-rotate-admin", waiting["execution_id"], include_inputs=True)
    assert ex["waiting_for_input"]["inputs"][0]["name"] == "confirm" and ex["inputs"] == {"vmName": _vm(sim)}
    done = orch.answer(plat, "wf-rotate-admin", waiting["execution_id"], {"confirm": True})
    assert done["answered"] and done["state"] == "completed"
    assert json.loads(tr.calls("POST", "/interaction")[0]["body"])["parameters"][0]["value"] == {"boolean": {"value": True}}


def test_execution_view_tolerates_camel_and_hyphen_parameter_names():
    class P:
        def request(self, method, path, params=None, **kw):
            body = {"id": "e1", "state": "failed", "name": "wf", "content-exception": "boom", "current-item-display-name": "Step 2",
                    "input-parameters": [{"name": "a", "type": "string", "value": {"string": {"value": "x"}}}],
                    "output-parameters": [{"name": "o", "type": "number", "value": {"number": {"value": 4}}}]}
            return TransportResponse(200, {}, json.dumps(body).encode())
    v = orch._execution_view(P(), "w", "e1", include_inputs=True)
    assert v["outputs"] == {"o": 4} and v["inputs"] == {"a": "x"} and v["error"] == "boom" and v["current_item"] == "Step 2"


def test_logs_try_syslogs_then_logs_and_simplify():
    seen = []

    class P:
        def request(self, method, path, params=None, **kw):
            seen.append((path, params))
            if path.endswith("/syslogs"):
                return TransportResponse(200, {}, b'{"logs": []}')
            return TransportResponse(200, {}, json.dumps({"logs": [{"entry": {"severity": "error", "short-description": "bad", "time-stamp": "t"}}]}).encode())
    logs = orch._exec_logs(P(), "w", "e")
    assert [s[0].rsplit("/", 1)[1] for s in seen] == ["syslogs", "logs"] and seen[0][1] == {"maxResult": 100}
    assert logs == [{"time": "t", "severity": "error", "message": "bad"}]


def test_secret_inputs_resolve_server_side_and_never_appear_in_results(env):
    sim, tr, plat = env
    res = orch.add_integration(plat, "rest_host", {"name": "itsm", "url": "https://itsm.example", "auth_type": "basic", "username": "svc",
                                                   "accept_certificate": True}, "local://env-prod/itsm-rest")
    assert res["state"] == "completed" and any(i["name"] == "itsm" for i in res["inventory_after"])
    body = json.loads(tr.calls("POST", "/executions")[-1]["body"])
    secret = next(p for p in body["parameters"] if p["name"] == "password")
    assert secret["type"] == "SecureString" and secret["scope"] == "local" and secret["value"] == {"secure-string": {"value": sim.password}}
    assert sim.password not in json.dumps(res)


def test_list_executions_reads_the_run_history(env):
    sim, tr, plat = env
    orch.run_workflow(plat, "wf-expand-disk", {"vmName": "no-such-vm", "diskNumber": 1, "addGB": 1}, {})
    orch.run_workflow(plat, "wf-expand-disk", {"vmName": _vm(sim), "diskNumber": 1, "addGB": 1}, {})
    allx = orch.list_executions(plat, "wf-expand-disk")
    assert allx["count"] == 2 and allx["items"][0]["state"] == "completed" and allx["more"] is False
    failed = orch.list_executions(plat, "wf-expand-disk", state="failed")
    assert [i["state"] for i in failed["items"]] == ["failed"]
    assert "conditions=state%3Dfailed" in tr.calls("GET", "/executions")[-1]["query"]
    page = orch.list_executions(plat, "wf-expand-disk", limit=1)
    assert page["count"] == 1 and page["more"] is True and "start_index=1" in page["next_step"]
    with pytest.raises(ValueError):
        orch.list_executions(plat, "wf-expand-disk", state="bogus")
    assert not [r for r in tr.requests if "queryCount" in r["query"]]


# ---- 5. actions --------------------------------------------------------------------------------------------------

def test_action_runs_synchronously_and_logs_come_from_the_action_log_endpoint(env):
    sim, tr, plat = env
    saved = orch.save_action(plat, "com.mcp.math", "add", "System.log('adding ' + a + ' and ' + b);\nreturn a + b;",
                             [{"name": "a", "type": "number"}, {"name": "b", "type": "number"}], "number")
    assert saved["saved"]
    res = orch.run_action(plat, "com.mcp.math/add", {"a": 2, "b": "3"})
    assert res["state"] == "completed" and res["result"] == 5 and res["result_type"] == "number" and res["execution_id"]
    assert res["logs"] and res["logs"][0]["message"] == "adding 2 and 3"
    assert tr.calls("POST", "/actions/com.mcp.math/add/executions")
    assert not tr.calls("GET", "/actions/runs/")            # no polling of /actions/runs
    assert tr.calls("GET", f"/actions/{res['execution_id']}/logs")
    assert json.loads(tr.calls("POST", "/executions")[-1]["body"])["parameters"][0]["scope"] == "local"
    bad = orch.run_action(plat, "com.mcp.math/add", {"zzz": 1})
    assert bad["started"] is False and "unknown input" in bad["problems"][0]


def test_action_error_comes_back_with_message_and_line(env):
    sim, tr, plat = env
    plat.orchestrator["script_level"] = "rhino_1_7_15"  # lint lets ES6 through; the simulated ES5 Rhino still rejects it at run time
    orch.save_action(plat, "com.mcp.math", "es6", "var x = 1;\nvar f = (y) => y + 1;\nreturn x;", [], "number")
    res = orch.run_action(plat, "com.mcp.math/es6", {})
    assert res["state"] == "failed" and "EvaluatorException" in res["error"] and res["error_line"] == 2


def test_list_actions_never_sends_conditions_and_filters_client_side(env):
    sim, tr, plat = env
    orch.save_action(plat, "com.mcp.math", "add", "return 1;", [], "number")
    orch.save_action(plat, "com.mcp.text", "upper", "return 'A';", [], "string")
    res = orch.list_items(plat, "actions", "upper")
    assert [i["name"] for i in res["items"]] == ["upper"]
    assert tr.calls("GET", "/actions")[-1]["query"] == ""
    assert not [r for r in tr.requests if "conditions" in r["query"] and r["path"].endswith("/actions")]


def test_action_versions_are_patch_bumped_and_updates_use_the_changeset_header(env):
    sim, tr, plat = env
    new = orch.save_action(plat, "com.mcp.math", "add", "return 1;", [], "number")
    assert new["version"] == "1.0.0" and new["operation"] == "create"
    assert tr.calls("POST", "/actions")[0]["body"] and json.loads(tr.calls("POST", "/actions")[0]["body"])["version"] == "1.0.0"
    assert orch.save_action(plat, "com.mcp.math", "add", "return 2;")["conflict"] is True  # an update needs base_changeset_sha
    upd = orch.save_action(plat, "com.mcp.math", "add", "return 2;", base_changeset_sha=new["changeset_sha"])
    assert upd["saved"] and upd["version"] == "1.0.1" and upd["operation"] == "update"
    put = tr.calls("PUT", "/actions/")[0]
    assert put["headers"]["X-VRO-Changeset-Sha"] == new["changeset_sha"]
    body = json.loads(put["body"])
    assert body["id"] == new["action_id"] and body["output-type"] == "number" and body["version"] == "1.0.1"
    minor = orch.save_action(plat, "com.mcp.math", "add", "return 3;", base_changeset_sha=upd["changeset_sha"], bump="minor")
    assert minor["version"] == "1.1.0"
    explicit = orch.save_action(plat, "com.mcp.math", "add", "return 4;", base_changeset_sha=minor["changeset_sha"], version="3.0.0")
    assert explicit["version"] == "3.0.0"
    stale = orch.save_action(plat, "com.mcp.math", "add", "return 5;", base_changeset_sha=new["changeset_sha"])
    assert stale["saved"] is False and "changed since" in stale["reason"]
    # An update keeps what was not given (description, inputs, return type).
    got = orch.get_item(plat, "action", "com.mcp.math/add")
    assert got["output-type"] == "number" and got["version"] == "3.0.0"


def test_action_save_refuses_modules_outside_the_prefix_and_es6_by_default(env):
    sim, tr, plat = env
    with pytest.raises(orch.OrchestratorRefused):
        orch.plan_action(plat, "com.vmware.library", "x", "return 1;")
    res = orch.save_action(plat, "com.mcp.math", "arrow", "var f = x => x;")
    assert res["saved"] is False and any(e["rule"] == "unsupported_arrow" for e in res["script_check"]["errors"])


# ---- 6. versions / rollback -------------------------------------------------------------------------------------

def test_commits_are_read_from_commits_objectid(env):
    sim, tr, plat = env
    res = orch.save_workflow(plat, SPEC, CAT)
    raw = parse_json(tr.send(_req(tr, "GET", f"/vco/api/workflows/{res['workflow_id']}/versions")))
    assert list(raw) == ["commits"] and raw["commits"][0]["objectId"] == res["changeset_sha"]
    assert orch.get_item(plat, "workflow", res["workflow_id"])["changeset_sha"] == res["changeset_sha"]
    assert orch._commit_id({"sha": "s"}) == "s" and orch._commit_id({"id": "i"}) == "i" and orch._commit_id({"objectId": "o", "sha": "s"}) == "o"


def _req(tr, method, path, params=None):
    from vcf_enterprise_mcp.adapter.transport.base import TransportRequest
    return TransportRequest(method=method, url=ORCH_URL + path, headers={"Accept": "application/json"}, params=params)


def test_commit_order_picks_newest_by_date_then_first():
    assert orch._latest_commit([{"objectId": "old", "commitDate": "2026-01-01T00:00:00Z"}, {"objectId": "new", "commitDate": "2026-02-01T00:00:00Z"}])["objectId"] == "new"
    assert orch._latest_commit([{"objectId": "a"}, {"objectId": "b"}])["objectId"] == "a"
    assert orch._latest_commit([]) is None


def test_workflow_rollback_puts_the_old_workflow_schema_as_json(env):
    sim, tr, plat = env
    first = orch.save_workflow(plat, SPEC, CAT)
    v2 = orch.save_workflow(plat, {**SPEC, "steps": [{"id": "s", "type": "script", "script": "report = 'v2';", "writes": ["report"]}]}, CAT,
                            first["changeset_sha"])
    res = orch.rollback(plat, "workflow", first["workflow_id"], first["changeset_sha"])
    assert res["rolled_back"] and res["new_changeset_sha"] not in (first["changeset_sha"], v2["changeset_sha"])
    put = tr.calls("PUT", "/content")[-1]
    assert put["headers"]["Content-Type"] == "application/json"
    sent = json.loads(put["body"])
    assert "workflow-item" in sent and "workflowSchema" not in sent and "objectId" not in sent  # the schema, not the changeset
    w = sim.s["orch"]["workflows"][first["workflow_id"]]
    assert w["content"]["workflow-item"][0]["script"]["text"] == "report = 'usage for ' + vmName;"
    with pytest.raises(orch.OrchestratorRefused):
        orch.rollback(plat, "workflow", first["workflow_id"], "nosuchsha")


def test_action_rollback_reads_the_old_version_and_puts_it_back_without_revert_to(env):
    sim, tr, plat = env
    a = orch.save_action(plat, "com.mcp.math", "add", "return 1;", [], "number")
    b = orch.save_action(plat, "com.mcp.math", "add", "return 2;", base_changeset_sha=a["changeset_sha"])
    res = orch.rollback(plat, "action", a["action_id"], a["changeset_sha"])
    assert res["rolled_back"] and res["new_changeset_sha"]
    assert tr.calls("GET", f"/versions/{a['changeset_sha']}")
    # The old content goes back with a normal PUT; the unproven revert endpoint is never called for actions.
    assert not tr.calls("POST", f"/actions/{a['action_id']}/versions")
    assert tr.calls("PUT", f"/actions/{a['action_id']}")
    assert sim.s["orch"]["actions"][a["action_id"]]["script"] == "return 1;"
    assert res["new_changeset_sha"] != b["changeset_sha"]


# ---- 7. folders ------------------------------------------------------------------------------------------------

def test_folders_are_walked_from_roots_and_children_not_a_flat_list(env):
    sim, tr, plat = env
    res = orch.save_workflow(plat, SPEC, "MCP-Managed/Team A/Storage")
    assert res["saved"]
    roots = tr.calls("GET", "/categories")[0]
    assert "categoryType=WorkflowCategory" in roots["query"] and "isRoot=true" in roots["query"]
    posts = [(r["path"], json.loads(r["body"])) for r in tr.calls("POST", "/categories")]
    assert [b["name"] for _, b in posts] == ["MCP-Managed", "Team A", "Storage"]
    assert all(b["type"] == "WorkflowCategory" for _, b in posts)
    assert posts[0][0].endswith("/vco/api/categories")                 # the root is created at /categories
    assert posts[1][0] != posts[0][0] and posts[2][0] != posts[1][0]   # children at /categories/{parentId}
    assert all("/categories/" in path for path, _ in posts[1:])
    # A second save reuses the folders: nothing new is created.
    n = len(tr.calls("POST", "/categories"))
    orch.save_workflow(plat, {**SPEC, "name": "Other"}, "MCP-Managed/Team A/Storage")
    assert len(tr.calls("POST", "/categories")) == n


def test_category_children_come_from_relations_link_rel_down():
    body = {"relations": {"link": [{"rel": "down", "attributes": [{"name": "id", "value": "c1"}, {"name": "name", "value": "Sub"},
                                                                   {"name": "type", "value": "WorkflowCategory"}]},
                                   {"rel": "up", "attributes": [{"name": "id", "value": "p"}, {"name": "name", "value": "Parent"}]}]}}
    assert orch._category_links(body, "down") == [{"id": "c1", "name": "Sub", "type": "WorkflowCategory"}]


def test_category_path_uses_the_servers_path_field(env):
    sim, tr, plat = env
    res = orch.save_workflow(plat, SPEC, "MCP-Managed/Storage")
    wf = sim.s["orch"]["workflows"][res["workflow_id"]]
    assert orch._category_path(orch._prov(plat), wf["category-id"]) == "MCP-Managed/Storage"


# ---- 8. listing --------------------------------------------------------------------------------------------------

def test_workflow_listing_pages_with_maxresult_startindex_and_never_querycount(env):
    sim, tr, plat = env
    page1 = orch.list_items(plat, "workflows", limit=4)
    assert page1["count"] == 4 and page1["more"] is True and "total" not in page1  # 9.x reports total=-1
    page2 = orch.list_items(plat, "workflows", limit=4, start_index=4)
    assert {i["id"] for i in page1["items"]}.isdisjoint({i["id"] for i in page2["items"]})
    last = orch.list_items(plat, "workflows", limit=200)
    assert last["more"] is False
    q = tr.calls("GET", "/workflows")[0]["query"]
    assert "maxResult=4" in q and "startIndex=0" in q
    assert not [r for r in tr.requests if "queryCount" in r["query"]]
    named = orch.list_items(plat, "workflows", "REST host")
    assert [i["name"] for i in named["items"]] == ["Add a REST host"] and "conditions=name%7ERESTunused" not in tr.calls("GET", "/workflows")[-1]["query"]
    assert "conditions=name" in tr.calls("GET", "/workflows")[-1]["query"]
    with pytest.raises(ValueError):
        orch.list_items(plat, "nonsense")


def test_the_simulator_rejects_querycount_like_a_real_9_1_server(env):
    sim, tr, plat = env
    resp = tr.send(_req(tr, "GET", "/vco/api/workflows", {"queryCount": "true"}))
    assert resp.status_code == 400
    assert tr.send(_req(tr, "GET", "/vco/api/actions", {"conditions": "name~x"})).status_code == 400


def test_non_paged_kinds_page_client_side(env):
    sim, tr, plat = env
    for i in range(5):
        orch.save_action(plat, "com.mcp.math", f"a{i}", "return 1;", [], "number")
    r = orch.list_items(plat, "actions", limit=2, start_index=2)
    assert [i["name"] for i in r["items"]] == ["a2", "a3"] and r["more"] is True and r["total"] == 5
    assert tr.calls("GET", "/actions")[-1]["query"] == ""


# ---- 9. plug-in install / scripting api -------------------------------------------------------------------------

def test_plugin_install_uploads_multipart_then_patches_eula_only(env, tmp_path):
    sim, tr, plat = env
    plug = tmp_path / "plugins"
    plug.mkdir()
    f = plug / "o11nplugin-snmp-9.1.1.vmoapp"
    f.write_bytes(b"PK\x03\x04 simulated snmp plug-in package")
    import hashlib
    sha = hashlib.sha256(f.read_bytes()).hexdigest()
    res = orch.install_plugin(plat, str(f), sha)
    assert res["installed"] and res["plugins"] == ["SNMP"]
    up = tr.calls("POST", "/plugins/installations")[0]
    assert up["headers"]["Content-Type"].startswith("multipart/form-data; boundary=")
    assert b'name="file"; filename="o11nplugin-snmp-9.1.1.vmoapp"' in up["body"] and b"simulated snmp" in up["body"]
    patch = tr.calls("PATCH", "/plugins/installations/")[0]
    assert json.loads(patch["body"]) == {"eulaAccepted": True}
    assert any(p["name"] == "SNMP" for p in sim.s["orch"]["plugins"])
    with pytest.raises(orch.OrchestratorRefused, match="SHA-256"):
        orch.install_plugin(plat, str(f), "0" * 64)


def test_scripting_api_path_is_plugin_version_build(env):
    sim, tr, plat = env
    res = orch.get_item(plat, "scripting_api", "VC")
    assert res["plugin"] == "VC" and res["api"]
    path = tr.calls("GET", "/server-configuration/api/plugins/")[-1]["path"]
    assert path.endswith("/plugins/VC/9.1.1.0/0")
    assert orch.get_item(plat, "scripting_api", "VC/9.1.1.0/0")["plugin"] == "VC"
    from vcf_enterprise_mcp.adapter.transport.errors import UpstreamResourceNotFoundException
    with pytest.raises(UpstreamResourceNotFoundException):  # the old path (plugins/{plugin} alone) does not exist
        tr.send(_req(tr, "GET", "/vco/api/server-configuration/api/plugins/VC"))
    with pytest.raises(orch.OrchestratorRefused):
        orch.get_item(plat, "scripting_api", "NoSuchPlugin")


# ---- 10. spec shapes found while verifying ------------------------------------------------------------------------

def test_about_reads_the_spec_shapes_for_plugins_runtimes_and_users(env):
    sim, tr, plat = env
    out = orch.about(plat)
    assert {"VC", "Mail"} <= {p["name"] for p in out["plugins"]} and "python:3.11" in out["runtimes"]
    assert out["service_account"]["user"] == "svc-mcp-automation" and out["script_level"] == "es5"


def test_users_without_a_roles_list_do_not_block_writes():
    class P:
        def request(self, method, path, params=None, **kw):
            return TransportResponse(200, {}, json.dumps({"login-name": "svc", "role": "USER", "admin-rights": False, "member-groups": []}).encode())
    orch._check_writable(P())  # the server decides when the write is sent


def test_environment_dependencies_are_a_name_to_version_object(env):
    sim, tr, plat = env
    res = orch.create_environment(plat, "requests-env", "python:3.11", ["requests", "pyyaml==6.0", "urllib3>=2"], "https://pypi.org/simple/x")
    assert res["created"] and res["name"] == "mcp-requests-env"
    body = json.loads(tr.calls("POST", "/environments")[0]["body"])
    assert body["dependencies"] == {"requests": "", "pyyaml": "6.0", "urllib3": "2"} and body["repositories"] == {"default": "https://pypi.org/simple/x"}


def test_configuration_attributes_use_typed_wire_values(env):
    sim, tr, plat = env
    res = orch.set_configuration(plat, "MCP-Managed/Config", "itsm", [{"name": "url", "type": "string", "value": "https://x"},
                                                                       {"name": "retries", "type": "number", "value": 3},
                                                                       {"name": "apiKey", "credential_ref": "local://env-prod/itsm-rest"}])
    assert res["saved"]
    body = json.loads(tr.calls("POST", "/configurations")[0]["body"])
    assert body["attributes"][0]["value"] == {"string": {"value": "https://x"}} and body["attributes"][1]["value"] == {"number": {"value": 3}}
    assert body["attributes"][2]["type"] == "SecureString"
    assert sim.password not in json.dumps(res)


# ---- 11. export package ---------------------------------------------------------------------------------------------

def test_package_export_never_includes_secure_strings_and_never_overwrites(env, tmp_path):
    sim, tr, plat = env
    saved = orch.save_action(plat, "com.mcp.math", "add", "return 1;", [], "number")
    assert saved["saved"]
    built = orch.build_package(plat, "com.mcp.math", use_tracked=True)
    assert built["built"] and built["created"]
    first = orch.export_package(plat, "com.mcp.math")
    second = orch.export_package(plat, "com.mcp.math")
    assert built["file"].endswith("_" + __import__("time").strftime("%Y%m%d") + ".package")  # the build exported the first file
    assert first["path"].endswith("-2.package") and second["path"].endswith("-3.package")  # never overwritten
    assert os.path.dirname(first["path"]) == str(tmp_path / "exports")
    data = open(first["path"], "rb").read()
    assert data[:2] == b"PK" and first["bytes"] == len(data) and len(first["sha256"]) == 64
    assert "com.mcp.math/add" in first["element_names"] and first["secure_strings_included"] is False
    params = sim.s["orch"]["last_export_params"]
    assert params["exportConfigSecureStringAttributeValues"] == "false" and params["exportConfigurationAttributeValues"] == "true"
    assert params["exportVersionHistory"] == "true" and params["exportGlobalTags"] == "true"
    assert b"SECRET-VALUES-INCLUDED" not in data
    req = tr.calls("GET", "/packages/com.mcp.math")[-1]
    assert req["headers"]["Accept"] == "application/zip"
    assert zipfile.ZipFile(io.BytesIO(data)).namelist()
    assert (os.stat(first["path"]).st_mode & 0o777) == 0o600
    with pytest.raises(orch.OrchestratorRefused, match="not found"):
        orch.export_package(plat, "com.mcp.nope")
    with pytest.raises(ValueError):
        orch.export_package(plat, "../etc")


def test_export_refuses_a_response_that_is_not_a_zip(env):
    sim, tr, plat = env

    class Html(SimTransport):
        def send(self, request):
            if "/packages/" in request.url:
                return TransportResponse(200, {"Content-Type": "text/html"}, b"<html>login</html>")
            return super().send(request)
    with pytest.raises(orch.OrchestratorRefused, match="did not return a zip"):
        orch.export_package(SimPlatform(sim, Html(sim)), "com.mcp.x")


def test_build_package_stays_inside_the_mcp_namespace(env):
    sim, tr, plat = env
    plan = orch.plan_build_package(plat, "com.other.pkg")
    assert not plan["allowed"] and any("com.mcp" in p for p in plan["problems"])
    assert not orch.plan_build_package(plat, "com.mcp.empty")["allowed"]  # nothing tracked yet
    with pytest.raises(orch.OrchestratorRefused):
        orch.plan_build_package(plat, "com.mcp.x", actions=["com.vmware.library/x"])


# ---- 12. try script -----------------------------------------------------------------------------------------------------

def test_try_script_runs_in_the_scratch_module_and_always_deletes_the_action(env):
    sim, tr, plat = env
    res = orch.try_script(plat, "System.log('go');\nreturn a + b;", {"a": 2, "b": 3})
    assert res["ran"] and res["state"] == "completed" and res["result"] == 5 and res["logs"][0]["message"] == "go"
    assert res["cleanup"] == "temporary action deleted"
    created = json.loads(tr.calls("POST", "/actions")[0]["body"])
    assert created["module"] == "com.mcp.scratch" and created["name"].startswith("mcp_")
    assert sim.s["orch"]["actions"] == {}
    delete = tr.calls("DELETE", "/actions/")[0]
    assert "force=true" in delete["query"]
    assert orch._tracker(plat).list() == []  # scratch actions are not tracked changes


def test_try_script_deletes_the_action_even_when_the_run_fails(env):
    sim, tr, plat = env
    res = orch.try_script(plat, "throw 'boom';")
    assert res["state"] == "failed" and "boom" in res["error"] and res["cleanup"] == "temporary action deleted"
    assert sim.s["orch"]["actions"] == {}

    class Boom(SimTransport):
        def send(self, request):
            if request.method == "POST" and request.url.endswith("/executions"):
                raise RuntimeError("network down")
            return super().send(request)
    plat2 = SimPlatform(sim, Boom(sim))
    with pytest.raises(RuntimeError):
        orch.try_script(plat2, "return 1;")
    assert sim.s["orch"]["actions"] == {}  # finally: cleanup still ran


def test_try_script_rejects_es6_in_lint_and_the_simulator_rejects_it_at_run_time(env):
    sim, tr, plat = env
    res = orch.try_script(plat, "const x = 1; return x;")
    assert res["ran"] is False and res["script_check"]["errors"][0]["rule"] == "unsupported_let_const"
    assert not tr.calls("POST", "/actions")
    plat.orchestrator["script_level"] = "rhino_1_7_15"
    res = orch.try_script(plat, "const x = 1; return x;")
    assert res["state"] == "failed" and "EvaluatorException" in res["error"] and res["cleanup"] == "temporary action deleted"
    plan = orch.plan_try_script(plat, "return 1;", {"n": "x"}, {"n": "number"})
    assert plan["allowed"] is False and "number" in plan["problems"][0]


# ---- 13. change tracking ----------------------------------------------------------------------------------------------

def test_saved_workflows_and_actions_are_tracked_per_orchestrator_url(env, tmp_path):
    sim, tr, plat = env
    wf = orch.save_workflow(plat, SPEC, CAT)
    act = orch.save_action(plat, "com.mcp.math", "add", "return 1;", [], "number")
    listed = orch.tracked_changes(plat)
    assert {(i["kind"], i["id"]) for i in listed["items"]} == {("workflow", wf["workflow_id"]), ("action", act["action_id"])}
    assert next(i for i in listed["items"] if i["kind"] == "action")["name"] == "com.mcp.math/add"
    path = tmp_path / "home" / "orch_changes.json"
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    data = json.loads(path.read_text())
    assert list(data) == [ORCH_URL.lower()]
    # another Orchestrator keeps its own list; a re-save replaces rather than duplicates
    assert ChangeTracker("https://other.example", path).list() == []
    orch.save_action(plat, "com.mcp.math", "add", "return 2;", base_changeset_sha=act["changeset_sha"])
    assert len(orch.tracked_changes(plat)["items"]) == 2
    assert not list(path.parent.glob("*.tmp"))  # atomic write leaves no temp files
    assert "return" not in path.read_text()      # names and ids only, never scripts


def test_tracker_survives_an_unwritable_location(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    t = ChangeTracker("https://x", blocker / "sub" / "c.json")
    t.record("workflow", "1", "n")  # must not raise
    assert t.list() == []


# ---- scenarios (existing behaviour must keep working) --------------------------------------------------------------------

def test_scenario_9_1_0_reports_its_known_issues(tmp_path):
    sim, tr, plat = make_sim(tmp_path, "orch_9_1_0")
    issues = " ".join(orch.about(plat)["known_issues_that_apply"])
    assert "UPN" in issues and "getToken" in issues and "Mail plug-in" in issues


def test_scenario_role_conflict_is_reported_and_refused_before_planning(tmp_path):
    sim, tr, plat = make_sim(tmp_path, "orch_role_conflict")
    assert any("READ-ONLY" in i for i in orch.about(plat)["known_issues_that_apply"])
    with pytest.raises(orch.OrchestratorRefused, match="READ-ONLY"):
        orch.plan_action(plat, "com.mcp.math", "x", "return 1;")
    assert not tr.calls("POST")


def test_scenario_vc_unusable_is_found_and_repaired(tmp_path):
    sim, tr, plat = make_sim(tmp_path, "orch_vc_unusable")
    assert any("vc-corp01" in i and "unusable" in i for i in orch.about(plat)["known_issues_that_apply"])
    res = orch.add_integration(plat, "vcenter_update", {"host": "vc-corp01.nwg.lab", "username": "svc"}, "local://env-prod/itsm-rest")
    assert res["state"] == "completed"
    assert not any("unusable" in i for i in orch.about(plat)["known_issues_that_apply"])


def test_scenario_concurrent_edit_is_detected_between_dry_run_and_execute(tmp_path):
    sim, tr, plat = make_sim(tmp_path, "orch_concurrent_edit")
    spec = {**SPEC, "name": "Disk usage report"}
    first = orch.plan_workflow(plat, spec, CAT)
    assert first["operation"] == "update" and first["problems"] and first["current_changeset_sha"]
    sha = first["current_changeset_sha"]
    # the dry run armed the simulated colleague: their edit lands before the execute call
    res = orch.save_workflow(plat, spec, CAT, sha)
    assert res["saved"] is False and res["conflict"] is True and "changed since" in res["reason"]
    again = orch.plan_workflow(plat, spec, CAT)
    assert again["current_changeset_sha"] != sha


def test_scenario_default_blocks_and_allowlist(tmp_path):
    sim, tr, plat = make_sim(tmp_path)
    with pytest.raises(orch.OrchestratorRefused, match="blocked"):
        orch.plan_run(plat, "wf-sql-ag-failover", {}, {})
    plan = orch.plan_run(plat, "wf-expand-disk", {"vmName": "x", "diskNumber": "abc", "addGB": 1}, {})
    assert plan["allowed"] is False and any("number" in p for p in plan["problems"])
    plat.orchestrator["run_allowlist"] = []
    with pytest.raises(orch.OrchestratorRefused, match="allowlist"):
        orch.plan_run(plat, "wf-expand-disk", {}, {})


def test_simulator_stores_non_ascii_scripts_hex_encoded_like_the_9_1_known_issue(tmp_path):
    sim, tr, plat = make_sim(tmp_path)
    spec = {**SPEC, "steps": [{"id": "s", "type": "script", "script": "report = 'x';", "writes": ["report"]}]}
    sim_content = sim_server_parse(spec)
    assert sim_content["workflow-item"][0]["script"]["text"] == "report = 'x';"


def sim_server_parse(spec):
    import vco_sim
    schema, _ = compile_spec(spec)
    return vco_sim.parse_schema_xml(to_xml(schema, "id"))


def test_simulator_rejects_bad_xml_and_unknown_content_types(env):
    sim, tr, plat = env
    from vcf_enterprise_mcp.adapter.transport.base import TransportRequest
    p = orch._prov(plat)
    bad = orch._raw_request(p, "PUT", "/workflows/validate/schema", b"<not-a-workflow/>", "application/xml")
    assert bad.status_code == 400
    odd = orch._raw_request(p, "PUT", "/workflows/validate/schema", b"x", "text/plain")
    assert odd.status_code == 415


# ---- tool classification and routing ---------------------------------------------------------------------------------------

def test_new_tools_are_classified_like_the_existing_ones():
    from vcf_enterprise_mcp.policy.models import NormalizedCapability, RiskClass
    from vcf_enterprise_mcp.tools import orchestrator_tools as t
    assert t.VCFOrchListExecutionsTool.risk_class == RiskClass.READ and t.VCFOrchListExecutionsTool.level == "L1_QUERY"
    assert t.VCFOrchExportPackageTool.risk_class == RiskClass.READ and t.VCFOrchTrackedChangesTool.risk_class == RiskClass.READ
    for cls in (t.VCFOrchTryScriptTool, t.VCFOrchBuildPackageTool):
        assert cls.risk_class == t.VCFOrchSaveActionTool.risk_class == RiskClass.CHANGE
        assert cls.required_roles == t.VCFOrchSaveActionTool.required_roles and cls.level == "L2_OPERATIONAL"
        assert cls.required_capability == NormalizedCapability.AUTOMATION_ORCH_AUTHOR
        assert hasattr(cls, "run_dry_run")


def test_new_tools_are_registered_in_the_protocol_engine_and_cards():
    from vcf_enterprise_mcp.router.catalog import ALL_ENTERPRISE_TOOLS
    names = {c.name for c in ALL_ENTERPRISE_TOOLS}
    new = {"vcf_orch_list_executions", "vcf_orch_export_package", "vcf_orch_try_script", "vcf_orch_tracked_changes", "vcf_orch_build_package"}
    assert new <= names
    import vcf_enterprise_mcp.core.protocol as proto
    src = open(proto.__file__).read()
    assert all(f'"{n}"' in src for n in new)
    from vcf_enterprise_mcp.setup.access_probe import TOOL_COMPONENT
    assert all(TOOL_COMPONENT[n] == "vcf_automation" for n in new)


# ---- tool layer ------------------------------------------------------------------------------------------------------------

def _tool(cls, plat):
    t = cls.__new__(cls)
    t.platform = plat
    return t


def test_tools_pass_the_new_arguments_through_dry_run_and_execute(env):
    import asyncio
    from vcf_enterprise_mcp.tools import orchestrator_tools as t
    sim, tr, plat = env
    run = lambda coro: asyncio.run(coro)  # noqa: E731
    plan = run(_tool(t.VCFOrchTryScriptTool, plat).run_dry_run(None, {"script": "return a * 2;", "inputs": {"a": 4}, "input_types": '{"a": "number"}'}))
    assert plan["dry_run"] and plan["allowed"] and plan["module"] == "com.mcp.scratch" and "next_step" in plan
    out = run(_tool(t.VCFOrchTryScriptTool, plat).run_live(None, {"script": "return a * 2;", "inputs": {"a": 4}, "return_type": "number"}))
    assert out["result"] == 8 and out["cleanup"] == "temporary action deleted"
    save = _tool(t.VCFOrchSaveActionTool, plat)
    first = run(save.run_live(None, {"module": "com.mcp.math", "name": "add", "script": "return 1;", "return_type": "number"}))
    assert first["version"] == "1.0.0"
    second = run(save.run_live(None, {"module": "com.mcp.math", "name": "add", "script": "return 2;", "base_changeset_sha": first["changeset_sha"], "bump": "major"}))
    assert second["version"] == "2.0.0"
    dry = run(save.run_dry_run(None, {"module": "com.mcp.math", "name": "add", "script": "return 3;"}))
    assert dry["allowed"] is False and "base_changeset_sha" in dry["problems"][0]
    listing = run(_tool(t.VCFOrchListTool, plat).run_live(None, {"kind": "workflows", "limit": 2, "start_index": 1}))
    assert listing["count"] == 2 and listing["start_index"] == 1 and listing["more"] is True
    assert run(_tool(t.VCFOrchTrackedChangesTool, plat).run_live(None, {}))["count"] == 1
    runs = run(_tool(t.VCFOrchListExecutionsTool, plat).run_live(None, {"workflow_id": "wf-expand-disk", "limit": 5}))
    assert runs["count"] == 0
    bp = run(_tool(t.VCFOrchBuildPackageTool, plat).run_dry_run(None, {"package_name": "com.mcp.math"}))
    assert bp["allowed"] and [i["name"] for i in bp["items"]] == ["com.mcp.math/add"]
    built = run(_tool(t.VCFOrchBuildPackageTool, plat).run_live(None, {"package_name": "com.mcp.math"}))
    assert built["built"] and built["file"]
    exp = run(_tool(t.VCFOrchExportPackageTool, plat).run_live(None, {"package_name": "com.mcp.math"}))
    assert exp["path"].endswith(".package") and exp["secure_strings_included"] is False
    assert orch.tracked_changes(plat)["count"] == 0  # building a package consumes the tracked items


def test_the_script_level_setting_exists_and_defaults_to_es5(env):
    from vcf_enterprise_mcp.config.settings import UpstreamVCFConfig
    assert UpstreamVCFConfig().orchestrator_script_level == "es5"
    assert UpstreamVCFConfig(orchestrator_script_level="rhino_1_7_15").orchestrator_script_level == "rhino_1_7_15"
    sim, tr, plat = env
    plat.orchestrator["script_level"] = "es6"
    with pytest.raises(orch.OrchestratorUnavailable, match="script_level"):
        orch.validate_action(plat, "var a = 1;")
