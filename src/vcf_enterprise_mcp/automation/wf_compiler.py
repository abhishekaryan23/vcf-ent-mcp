# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Compiles a small, model-friendly workflow spec into the Orchestrator 9.1 `schema-workflow`.

compile_spec() builds the internal model (a dict shaped like the JSON schema-workflow) used for
linting and validation. to_xml() serializes that model to the XML `schema-workflow` document that
is the proven format on a real VCF Automation 9.1.1 server (sent with Content-Type
application/xml to PUT /vco/api/workflows/{id}/content and PUT /vco/api/workflows/validate/schema;
the API spec accepts JSON as well, so schema_for_json() is the fallback). The XML layout is
ported from workflow.ts in vcf-orchestrator-mcp by imtrinity94 (MIT), see THIRD_PARTY_NOTICES.md.

Item type values: task (scriptable task, also action calls), link (nested workflow),
custom-condition (scripted decision), end (end-mode 0 = success, 1 = error). The community
project proved task / custom-condition / end on a real server; `link` and the catch-name /
throw-bind-name error handler are the API reference's names and are not proven there.

Spec:
{
  "name": "Expand disk and notify", "description": "...",
  "inputs":  [{"name": "vmName", "type": "string", "description": "...", "default": "web01"}],
  "outputs": [{"name": "newSizeGB", "type": "number"}],
  "variables": [{"name": "vm", "type": "VC:VirtualMachine"}, {"name": "retries", "type": "number", "value": 3}],
  "steps": [
    {"id": "find", "type": "script", "name": "Find VM", "script": "vm = ...;", "reads": ["vmName"], "writes": ["vm"]},
    {"id": "grow", "type": "action", "action": "com.mcp.storage/expandDisk", "args": ["vm", "addGB"], "result": "newSizeGB"},
    {"id": "big", "type": "decision", "condition": "return newSizeGB > 1000;", "reads": ["newSizeGB"], "then": "warn", "else": "done"},
    {"id": "sub", "type": "workflow", "workflow_id": "<id>", "pass": {"subInput": "vm"}, "receive": {"subOut": "x"}},
    {"id": "done", "type": "end"},
    {"id": "failed", "type": "error_end"}
  ],
  "on_error": "failed"
}
Steps run in order unless a step has "next" (or then/else for decisions). An end step is added
when the last step is not one.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from vcf_enterprise_mcp.automation.wire import cdata, presentation_default, to_wire, xml_value, _xa

STEP_TYPES = ("script", "action", "decision", "workflow", "end", "error_end")
NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class SpecError(ValueError):
    def __init__(self, problems: List[Dict[str, str]]):
        super().__init__("; ".join(p["message"] for p in problems))
        self.problems = problems


def _params(items) -> List[Dict[str, Any]]:
    out = []
    for p in items or []:
        d = {"name": p["name"], "type": p.get("type", "string"), "description": p.get("description", "")}
        if p.get("default") is not None:
            d["default"] = p["default"]
        out.append(d)
    return out


def _normalize(spec: Dict[str, Any]) -> Dict[str, Any]:
    """Accept common variants small models produce: nested {"script": {"script": ..., "reads": ...}} steps,
    "code" instead of "script", and variables that repeat an output."""
    import copy
    spec = copy.deepcopy(spec or {})
    for st in spec.get("steps") or []:
        if not isinstance(st, dict):
            continue
        inner = st.get("script")
        if isinstance(inner, dict):
            st["script"] = inner.get("script") or inner.get("text") or inner.get("code") or ""
            for k in ("reads", "writes"):
                if k in inner and k not in st:
                    st[k] = inner[k]
        if "code" in st and "script" not in st:
            st["script"] = st.pop("code")
        if isinstance(st.get("condition"), dict):
            st["condition"] = st["condition"].get("script") or st["condition"].get("text") or ""
    outs = {o.get("name") for o in spec.get("outputs") or [] if isinstance(o, dict)}
    ins = {i.get("name") for i in spec.get("inputs") or [] if isinstance(i, dict)}
    spec["variables"] = [v for v in spec.get("variables") or [] if not (isinstance(v, dict) and v.get("name") in outs | ins)]
    return spec


def compile_spec(spec: Dict[str, Any]) -> Tuple[Dict[str, Any], List[Dict[str, str]]]:
    """Returns (schema-workflow, scripts) where scripts lists every script for linting."""
    problems: List[Dict[str, str]] = []
    spec = _normalize(spec)

    def bad(msg, fix, where=""):
        problems.append({"where": where, "message": msg, "fix": fix})

    if not spec.get("name"):
        bad("The workflow needs a name.", 'Add "name": "My workflow".', "name")
    inputs, outputs, variables = spec.get("inputs") or [], spec.get("outputs") or [], spec.get("variables") or []
    types: Dict[str, str] = {}
    for group, label in ((inputs, "inputs"), (outputs, "outputs"), (variables, "variables")):
        for p in group:
            if not isinstance(p, dict) or not p.get("name"):
                bad(f"Every entry in {label} needs a name and a type.", '{"name": "vmName", "type": "string"}', label)
                continue
            if not NAME_RE.match(p["name"]):
                bad(f"'{p['name']}' is not a valid variable name.", "Use letters, digits and _ only, starting with a letter.", label)
            if p["name"] in types:
                if label == "variables" and types[p["name"]] == p.get("type", "string"):
                    continue  # already an input/output of the same type: harmless repeat
                bad(f"'{p['name']}' is declared twice with different types.", "Declare it once (an output is already a variable).", label)
            types[p["name"]] = p.get("type", "string")
    steps = spec.get("steps") or []
    if not steps:
        bad("The workflow has no steps.", 'Add "steps": [{"id": "s1", "type": "script", "script": "..."}].', "steps")
    ids = [s.get("id") for s in steps if isinstance(s, dict)]
    for s in steps:
        if not isinstance(s, dict) or not s.get("id"):
            bad("Every step needs an id.", '{"id": "s1", "type": "script", ...}', "steps")
    if len(set(ids)) != len(ids):
        bad("Step ids must be unique.", "Rename the duplicate step ids.", "steps")
    on_error = spec.get("on_error")
    if on_error and on_error not in ids:
        bad(f"on_error points to unknown step '{on_error}'.", f"Use one of: {', '.join(i for i in ids if i)}.", "on_error")
    if problems:
        raise SpecError(problems)

    last = steps[-1]
    if last.get("type") not in ("end", "error_end"):
        steps = steps + [{"id": "__end", "type": "end"}]
    item_name = {s["id"]: f"item{i + 1}" for i, s in enumerate(steps)}
    need_err_attr = False
    items, scripts = [], []

    def ref(target, where):
        if target not in item_name:
            bad(f"Step '{where}' points to unknown step '{target}'.", f"Use one of: {', '.join(item_name)}.", where)
            return None
        return item_name[target]

    def binds(names, where, direction):
        out = []
        for n in names or []:
            if n not in types:
                bad(f"Step '{where}' {direction} '{n}', which is not declared.",
                    f'Declare it in inputs, outputs or variables with its type, e.g. {{"name": "{n}", "type": "string"}}.', where)
                continue
            out.append({"name": n, "type": types[n], "export-name": n, "description": ""})
        return {"bind": out}

    for i, s in enumerate(steps):
        sid, st = s["id"], s.get("type")
        nxt = s.get("next") or (steps[i + 1]["id"] if i + 1 < len(steps) else None)
        base = {"name": item_name[sid], "display-name": s.get("name") or sid, "position": {"x": 140 + 180 * i, "y": 80}}
        if st not in STEP_TYPES:
            bad(f"Step '{sid}' has unknown type '{st}'.", f"Use one of: {', '.join(STEP_TYPES)}.", sid)
            continue
        if st in ("script", "action", "workflow") and on_error and on_error != sid:
            base["catch-name"] = item_name.get(on_error)
            base["throw-bind-name"] = "errorMessage"
            need_err_attr = True
        if st == "script":
            if not s.get("script"):
                bad(f"Script step '{sid}' has no script.", 'Add "script": "...".', sid)
            item = {**base, "type": "task", "script": {"text": s.get("script", ""), "encoded": False},
                    "in-binding": binds(s.get("reads"), sid, "reads"), "out-binding": binds(s.get("writes"), sid, "writes")}
            scripts.append({"step": sid, "script": s.get("script", "")})
        elif st == "action":
            act = str(s.get("action", ""))
            if "/" not in act:
                bad(f"Action step '{sid}' needs action 'module/actionName'.", 'e.g. "action": "com.mcp.storage/expandDisk".', sid)
                continue
            module, name = act.rsplit("/", 1)
            args = s.get("args") or []
            result = s.get("result")
            text = (f"{result} = " if result else "") + f'System.getModule("{module}").{name}({", ".join(args)});'
            item = {**base, "type": "task", "script-module": act, "script": {"text": text, "encoded": False},
                    "in-binding": binds(args, sid, "passes"), "out-binding": binds([result] if result else [], sid, "returns into")}
            scripts.append({"step": sid, "script": text})
        elif st == "decision":
            cond = s.get("condition", "")
            if "return" not in cond:
                bad(f"Decision '{sid}' must return true or false.", 'e.g. "condition": "return count > 0;"', sid)
            item = {**base, "type": "custom-condition", "script": {"text": cond, "encoded": False},
                    "in-binding": binds(s.get("reads"), sid, "reads"), "out-binding": {"bind": []},
                    "out-name": ref(s.get("then", ""), sid), "alt-out-name": ref(s.get("else", ""), sid)}
            scripts.append({"step": sid, "script": cond})
            items.append(item)
            continue
        elif st == "workflow":
            if not s.get("workflow_id"):
                bad(f"Workflow step '{sid}' needs workflow_id.", "Find it with vcf_orch_list kind=workflows.", sid)
            pin = [{"name": k, "type": types.get(v, "string"), "export-name": v, "description": ""} for k, v in (s.get("pass") or {}).items()]
            pout = [{"name": k, "type": types.get(v, "string"), "export-name": v, "description": ""} for k, v in (s.get("receive") or {}).items()]
            for v in list((s.get("pass") or {}).values()) + list((s.get("receive") or {}).values()):
                if v not in types:
                    bad(f"Workflow step '{sid}' uses '{v}', which is not declared.", "Declare it in inputs, outputs or variables.", sid)
            item = {**base, "type": "link", "linked-workflow-id": s.get("workflow_id"), "in-binding": {"bind": pin}, "out-binding": {"bind": pout}}
        elif st == "end":
            items.append({**base, "type": "end", "end-mode": "0"})
            continue
        else:  # error_end
            need_err_attr = True
            items.append({**base, "type": "end", "end-mode": "1",
                          "in-binding": {"bind": [{"name": "errorMessage", "type": "string", "export-name": "errorMessage", "description": ""}]}})
            continue
        if nxt:
            item["out-name"] = ref(nxt, sid)
        items.append(item)
    if problems:
        raise SpecError(problems)
    attrib = []
    for v in variables:
        a = {"name": v["name"], "type": v.get("type", "string"), "description": v.get("description", "")}
        if v.get("value") is not None:
            a["value"] = v["value"]
        attrib.append(a)
    if need_err_attr and "errorMessage" not in types:
        attrib.append({"name": "errorMessage", "type": "string", "description": "Error caught by the workflow's error handler"})
    schema = {
        "display-name": spec["name"], "description": spec.get("description", ""), "version": spec.get("version", "1.0.0"),
        "position": {"x": 100, "y": 50}, "root-name": items[0]["name"],
        "input": {"param": _params(inputs)}, "output": {"param": _params(outputs)}, "attrib": attrib,
        "presentation": {}, "ref-types": "", "workflow-item": items, "workflow-note": [], "api-version": "6.0.0",
    }
    return schema, scripts


# ---- serialization -------------------------------------------------------------------------------------------

NIL_ID = "00000000-0000-0000-0000-000000000000"


def schema_for_json(schema: Dict[str, Any]) -> Dict[str, Any]:
    """The internal model as a JSON schema-workflow (the fallback format): defaults dropped, attribute values typed."""
    import copy
    out = copy.deepcopy(schema)
    for side in ("input", "output"):
        for prm in (out.get(side) or {}).get("param", []):
            prm.pop("default", None)
    for a in out.get("attrib", []):
        if "value" in a:
            a["value"] = to_wire(a.get("type"), a["value"])
    return out


def _bind_xml(tag: str, binding: Optional[Dict[str, Any]]) -> str:
    binds = (binding or {}).get("bind") or []
    if not binds:
        return f"<{tag}/>"
    return f"<{tag}>" + "".join(f'<bind name="{_xa(b["name"])}" type="{_xa(b["type"])}" export-name="{_xa(b["export-name"])}"/>' for b in binds) + f"</{tag}>"


def _param_xml(p: Dict[str, Any]) -> str:
    desc = f"<description>{cdata(p['description'])}</description>" if p.get("description") else ""
    return f'<param name="{_xa(p["name"])}" type="{_xa(p["type"])}">{desc}</param>'


def to_xml(schema: Dict[str, Any], workflow_id: str = NIL_ID) -> str:
    """XML `schema-workflow` (application/xml) for the internal model, mirroring the layout proven on a real server."""
    items = schema.get("workflow-item") or []
    parts: List[str] = []
    for it in items:
        t = it.get("type")
        attrs = f'name="{_xa(it["name"])}"'
        for key in ("out-name", "alt-out-name", "catch-name", "throw-bind-name"):
            if it.get(key):
                attrs += f' {key}="{_xa(it[key])}"'
        attrs += f' type="{_xa(t)}"'
        if t == "end":
            attrs += f' end-mode="{_xa(it.get("end-mode", "0"))}"'
        if it.get("linked-workflow-id"):
            attrs += f' linked-workflow-id="{_xa(it["linked-workflow-id"])}"'
        if it.get("script-module"):
            attrs += f' script-module="{_xa(it["script-module"])}"'
        attrs += ' comparator="0"'
        pos = it.get("position") or {}
        position = f'<position y="{pos.get("y", 60)}" x="{pos.get("x", 100)}"/>'
        body = ""
        if it.get("display-name") and t != "end":
            body += f"<display-name>{cdata(it['display-name'])}</display-name>"
        script = (it.get("script") or {}).get("text") if it.get("script") else None
        if script is not None and t in ("task", "custom-condition"):
            body += f'<script encoded="false">{cdata(script)}</script>'
        if t in ("task", "custom-condition", "link") or (it.get("in-binding") or {}).get("bind"):
            body += _bind_xml("in-binding", it.get("in-binding"))
        if t in ("task", "link"):
            body += _bind_xml("out-binding", it.get("out-binding"))
        if it.get("description"):
            body += f"<description>{cdata(it['description'])}</description>"
        parts.append(f"<workflow-item {attrs}>{body}{position}</workflow-item>")
    attribs = ""
    for a in schema.get("attrib") or []:
        desc = f"<description>{cdata(a['description'])}</description>" if a.get("description") else ""
        attribs += (f'<attrib name="{_xa(a["name"])}" type="{_xa(a["type"])}" read-only="false">'
                    f"{xml_value(a['type'], a.get('value'))}{desc}</attrib>")
    pparams = ""
    for prm in (schema.get("input") or {}).get("param", []):
        v = presentation_default(prm["type"], prm.get("default"))
        if v:
            pparams += (f'<p-param name="{_xa(prm["name"])}"><desc>{cdata(prm.get("description") or prm["name"])}</desc>'
                        f'<p-qual kind="static" name="defaultValue" type="{_xa(prm["type"])}">{v}</p-qual></p-param>')
    pos = schema.get("position") or {}
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<schema-workflow xmlns:ns2="http://www.vmware.com/vco" root-name="{_xa(schema["root-name"])}" '
        f'object-name="workflow:name=generic" id="{_xa(workflow_id)}" version="{_xa(schema.get("version") or "1.0.0")}" '
        'api-version="6.0.0" restartMode="1" resumeFromFailedMode="0" editor-version="2.0">'
        f"<display-name>{cdata(schema.get('display-name', ''))}</display-name>"
        f"<description>{cdata(schema.get('description', ''))}</description>"
        f'<position y="{pos.get("y", 50)}" x="{pos.get("x", 100)}"/>'
        f"<input>{''.join(_param_xml(p) for p in (schema.get('input') or {}).get('param', []))}</input>"
        f"<output>{''.join(_param_xml(p) for p in (schema.get('output') or {}).get('param', []))}</output>"
        f"{attribs}{''.join(parts)}<presentation>{pparams}</presentation></schema-workflow>"
    )
