# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Simulated VCF Operations Orchestrator 9.1 REST API (/vco/api) for the Northwind enterprise.

Paths and shapes follow the official Orchestrator 9.0 OpenAPI spec and what a community MCP proved on a
real VCF Automation 9.1.1 server (vcf-orchestrator-mcp by imtrinity94, MIT). Behaviour that matters for the
MCP is modelled on purpose:
- workflow content arrives as XML `schema-workflow` (application/xml) or JSON; XML is parsed into the same
  model JSON uses (other content types get HTTP 415);
- changesets: GET .../versions answers {"commits": [WsCommit]} newest first, a commit id is `objectId`,
  POST .../versions returns a WsCommit, X-VRO-Changeset-Sha conflicts answer 409 on workflows and actions;
- GET /workflows pages with maxResult/startIndex, reports total=-1 and answers 400 to queryCount; the other
  list endpoints take no query at all (400 if one is sent);
- categories: roots via isRoot=true, children via GET /categories/{id} relations.link rel=down;
- actions run synchronously (POST /actions/{module}/{name}/executions answers the result), with logs at
  GET /actions/{execution-id}/logs; workflow runs answer 202 with a Location header and are read with
  showDetails=true, logs at /syslogs and /logs;
- a Rhino syntax check written separately from the MCP's linter: ES6+ syntax (let/const, arrow functions,
  template literals, for...of, generators, class, async, ?., ??, spread, destructuring, default parameters)
  fails at run time with an EvaluatorException, like plain ES5 Rhino does;
- 9.1 known issues: non-ASCII scripts are stored hex-encoded (K1); a vCenter connection can be 'unusable'
  (K4); Workflow Designer + Viewer means read-only (KB 438403);
- Broadcom's plug-in configuration workflows ("Add a REST host", ...), which check the SecureString
  password and add the endpoint to the plug-in inventory; a workflow that waits for user input;
- plug-in installation: multipart upload (field `file`) then PATCH {"eulaAccepted": true};
- package export as a zip (GET /packages/{name}, Accept application/zip).
Scenario flags (in state["orch_flags"]): version_9_1_0, role_conflict, vc_unusable, concurrent_edit.
Simulator extension: GET /users also lists `roles`, which the real API does not, so the role-conflict
scenario can be detected.
"""

from __future__ import annotations

import ast
import hashlib
import io
import json
import re
import secrets
import time
import xml.etree.ElementTree as ET
import zipfile
from email.parser import BytesParser

# ---- Rhino (ES5) syntax check ---------------------------------------------------------------------------

UNSUPPORTED = [
    (re.compile(r"(^|[^.\w$])class\s+[A-Za-z_$]"), "class"), (re.compile(r"(^|[^.\w$])async\s+function|(^|[^.\w$])await\s"), "async/await"),
    (re.compile(r"\?\."), "?."), (re.compile(r"\?\?"), "??"), (re.compile(r"\.\.\.[A-Za-z_$\[{(]"), "spread"),
    (re.compile(r"(^|[^\w$])(const|let|var)\s*[{\[]"), "destructuring"), (re.compile(r"function\s*\w*\s*\([^)]*=[^=>]"), "default parameter"),
    (re.compile(r"(^|[^.\w$])(let|const)\s+[A-Za-z_$]"), "let/const"), (re.compile(r"=>"), "arrow function"),
    (re.compile(r"`"), "template literal"), (re.compile(r"\bfor\s*\(\s*(var\s+)?[\w$]+\s+of\s"), "for...of"),
    (re.compile(r"function\s*\*"), "generator"),
]


def _strip_strings(src: str) -> str:
    return re.sub(r"//[^\n]*|/\*.*?\*/|\"(\\.|[^\"\\])*\"|'(\\.|[^'\\])*'|`(\\.|[^`\\])*`", '""', src, flags=re.S)


def _strip_comments_and_quotes(src: str) -> str:
    """Like _strip_strings but keeps backticks visible (a template literal is a syntax error for ES5 Rhino)."""
    return re.sub(r"//[^\n]*|/\*.*?\*/|\"(\\.|[^\"\\])*\"|'(\\.|[^'\\])*'", '""', src, flags=re.S)


def rhino_check(src: str, with_line: bool = False):
    code = _strip_comments_and_quotes(src or "")
    for pat, what in UNSUPPORTED:
        m = pat.search(code)
        if m:
            line = code.count("\n", 0, m.start()) + 1
            msg = f"org.mozilla.javascript.EvaluatorException: syntax error ({what} is not supported by this Rhino version) (script#{line})"
            return (msg, line) if with_line else msg
    return (None, None) if with_line else None


def _sha(obj) -> str:
    return hashlib.sha1(json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()


def _link(attrs, rel=None):
    d = {"href": "", "attributes": [{"name": k, "value": v} for k, v in attrs.items()]}
    if rel:
        d["rel"] = rel
    return d


class Raw:
    """A response with explicit bytes / content type / extra headers (tools/org_sim/server.py writes it as is)."""

    def __init__(self, raw_bytes, content_type="application/json", headers=None):
        self.raw_bytes, self.content_type, self.headers = raw_bytes, content_type, headers or {}


def _json_raw(obj, headers):
    return Raw(json.dumps(obj).encode(), "application/json", headers)


# ---- wire values (written separately from the MCP's wire.py) --------------------------------------------

def _unwire(v):
    if not isinstance(v, dict) or len(v) != 1:
        return v
    k, inner = next(iter(v.items()))
    if k in ("string", "secure-string", "encrypted-string", "number", "boolean", "date", "regex"):
        return inner.get("value") if isinstance(inner, dict) else inner
    if k == "array":
        return [_unwire(x) for x in (inner or {}).get("elements", [])]
    if k == "properties":
        return {p["key"]: _unwire(p.get("value")) for p in (inner or {}).get("property", [])}
    if k == "sdk-object":
        return {"type": inner.get("type"), "id": inner.get("id")}
    return v


def _wire(value, type_=None):
    t = (type_ or "").lower()
    if t.startswith("array/") or isinstance(value, list):
        inner = (type_ or "")[6:] or None
        return {"array": {"elements": [_wire(x, inner) for x in (value or [])]}}
    if t == "number" or (isinstance(value, (int, float)) and not isinstance(value, bool) and t in ("", "any")):
        return {"number": {"value": value}}
    if t == "boolean" or isinstance(value, bool):
        return {"boolean": {"value": value}}
    if t == "properties" or isinstance(value, dict):
        return {"properties": {"property": [{"key": k, "value": _wire(x)} for k, x in (value or {}).items()]}}
    return {"string": {"value": "" if value is None else str(value)}}


# ---- workflow XML -> the JSON model ----------------------------------------------------------------------

def _tag(el):
    return el.tag.split("}")[-1]


def _txt(parent, name):
    el = next((c for c in parent if _tag(c) == name), None)
    return (el.text or "") if el is not None else ""


def _pos(el):
    p = next((c for c in el if _tag(c) == "position"), None)
    return {"x": float(p.get("x", 0)), "y": float(p.get("y", 0))} if p is not None else {"x": 0, "y": 0}


def _binds(it, name):
    b = next((c for c in it if _tag(c) == name), None)
    return {"bind": [{"name": x.get("name"), "type": x.get("type"), "export-name": x.get("export-name"), "description": ""}
                     for x in (b if b is not None else []) if _tag(x) == "bind"]}


def _xml_value(a):
    v = next((c for c in a if _tag(c) not in ("description",)), None)
    if v is None:
        return None
    t = _tag(v)
    if t == "number":
        return float(v.text)
    if t == "boolean":
        return (v.text or "").strip() == "true"
    if t == "string":
        return v.text or ""
    if t == "array":
        return [(c.text or "") for c in v]
    if t == "sdk-object":
        return {"type": v.get("type"), "id": v.get("id")}
    return None


def parse_schema_xml(text):
    """schema-workflow XML -> the JSON schema-workflow model. Raises ValueError with a server-like message."""
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValueError(f"Unparseable XML: {exc}")
    if _tag(root) != "schema-workflow":
        raise ValueError(f"Unexpected root element '{_tag(root)}', expected schema-workflow")
    if not root.get("root-name"):
        raise ValueError("schema-workflow needs a root-name")
    items = []
    for it in (c for c in root if _tag(c) == "workflow-item"):
        d = {k: it.get(k) for k in ("name", "type", "out-name", "alt-out-name", "catch-name", "throw-bind-name", "end-mode", "linked-workflow-id",
                                    "script-module") if it.get(k) is not None}
        d["display-name"] = _txt(it, "display-name")
        d["position"] = _pos(it)
        sc = next((c for c in it if _tag(c) == "script"), None)
        if sc is not None:
            d["script"] = {"text": sc.text or "", "encoded": sc.get("encoded") == "true"}
        d["in-binding"], d["out-binding"] = _binds(it, "in-binding"), _binds(it, "out-binding")
        if _txt(it, "description"):
            d["description"] = _txt(it, "description")
        items.append(d)
    params = lambda side: {"param": [{"name": p.get("name"), "type": p.get("type"), "description": _txt(p, "description")}  # noqa: E731
                                     for s in root if _tag(s) == side for p in s if _tag(p) == "param"]}
    pres = {}
    for pp in (p for s in root if _tag(s) == "presentation" for p in s if _tag(p) == "p-param"):
        q = next((c for c in pp if _tag(c) == "p-qual" and c.get("name") == "defaultValue"), None)
        if q is not None:
            pres[pp.get("name")] = q.text or ""
    return {"display-name": _txt(root, "display-name"), "description": _txt(root, "description"), "version": root.get("version") or "0.0.0",
            "position": _pos(root), "root-name": root.get("root-name"), "input": params("input"), "output": params("output"),
            "attrib": [{"name": a.get("name"), "type": a.get("type"), "description": _txt(a, "description"), "value": _xml_value(a)}
                       for a in root if _tag(a) == "attrib"],
            "presentation": {"defaults": pres}, "ref-types": "", "workflow-item": items, "workflow-note": [], "id": root.get("id")}


def _read_schema(h, body):
    """The posted workflow schema as the JSON model (parsing XML), or (None, error response)."""
    ctype = (h.headers.get("Content-Type") or "").split(";")[0].strip().lower()
    if ctype in ("application/xml", "text/xml"):
        try:
            return parse_schema_xml(getattr(h, "_raw_body", b"").decode("utf-8")), None
        except ValueError as exc:
            return None, (400, {"status": "Bad Request", "message": str(exc)})
    if ctype == "application/json":
        if not isinstance(body, dict):
            return None, (400, {"status": "Bad Request", "message": "Unparseable JSON body"})
        return json.loads(json.dumps(body)), None
    return None, (415, {"status": "Unsupported Media Type", "message": f"Content type '{ctype or 'none'}' is not supported"})


# ---- built-in content ---------------------------------------------------------------------------------

def _simple_schema(name, inputs, outputs, script="// library workflow", interaction=False, version="1.0.0"):
    items = [{"name": "item1", "type": "input" if interaction else "task", "display-name": "Run", "out-name": "item0",
              "script": {"text": script, "encoded": False}, "in-binding": {"bind": []}, "out-binding": {"bind": []}},
             {"name": "item0", "type": "end", "end-mode": "0"}]
    return {"display-name": name, "description": "", "version": version, "position": {"x": 0, "y": 0}, "root-name": "item1",
            "input": {"param": [{"name": i["name"], "type": i["type"], "description": i.get("description", "")} for i in inputs]},
            "output": {"param": [{"name": o["name"], "type": o["type"]} for o in outputs]}, "attrib": [], "presentation": {},
            "ref-types": "", "workflow-item": items, "workflow-note": []}


CONFIG_WORKFLOWS = {
    "Add a vCenter Server instance": ("Library/vCenter/Configuration", "VC", [("host", "string"), ("port", "number"), ("username", "string"),
                                                                             ("password", "SecureString"), ("ignoreCertificateWarnings", "boolean")]),
    "Update a vCenter Server instance": ("Library/vCenter/Configuration", "VC", [("host", "string"), ("username", "string"), ("password", "SecureString")]),
    "Add a REST host": ("Library/HTTP-REST/Configuration", "RESTPlugin", [("name", "string"), ("url", "string"), ("authentication", "string"),
                                                                         ("username", "string"), ("password", "SecureString"), ("acceptCertificate", "boolean")]),
    "Add an Active Directory server": ("Library/Microsoft/Active Directory/Configuration", "AD", [("host", "string"), ("port", "number"), ("baseDN", "string"),
                                                                                                 ("username", "string"), ("password", "SecureString"),
                                                                                                 ("useSSL", "boolean"), ("alias", "string")]),
    "Add a PowerShell host": ("Library/PowerShell/Configuration", "PowerShell", [("name", "string"), ("host", "string"), ("port", "number"),
                                                                                ("transportProtocol", "string"), ("authentication", "string"),
                                                                                ("username", "string"), ("password", "SecureString")]),
    "Add an SSH Host": ("Library/SSH/Configuration", "SSH", [("hostname", "string"), ("port", "number"), ("username", "string"), ("password", "SecureString")]),
}


def build_orch(automation, flags):
    o = {"flags": set(flags or ()), "categories": {}, "workflows": {}, "actions": {}, "configurations": {}, "environments": {},
         "executions": {}, "action_runs": {}, "action_logs": {}, "installations": {}, "packages": {}, "last_export_params": None,
         "plugins": [{"name": n, "version": v, "displayName": d} for n, v, d in (
             ("VC", "9.1.1.0", "vCenter Server"), ("RESTPlugin", "9.1.1.0", "HTTP-REST"), ("AD", "9.1.1.0", "Active Directory"),
             ("PowerShell", "9.1.1.0", "PowerShell"), ("SSH", "9.1.1.0", "SSH"), ("Mail", "9.1.0.0300", "Mail"))],
         "inventory": {"VC": [{"name": "vc-mgmt01.nwg.lab", "state": "ok"}, {"name": "vc-corp01.nwg.lab", "state": "ok"},
                              {"name": "vc-fin01.nwg.lab", "state": "ok"}],
                       "AD": [{"name": f, "state": "ok"} for f in automation["ad_plugin_forests"]], "RESTPlugin": [], "PowerShell": [], "SSH": []}}
    if "vc_unusable" in o["flags"]:
        o["inventory"]["VC"][1]["state"] = "unusable"

    def cat(path):
        parent = ""
        for part in path.split("/"):
            cid = next((c["id"] for c in o["categories"].values() if c["name"] == part and c["parent"] == parent), None)
            if not cid:
                cid = "cat-" + secrets.token_hex(4)
                o["categories"][cid] = {"id": cid, "name": part, "parent": parent}
            parent = cid
        return parent

    for name, (path, plugin, params) in CONFIG_WORKFLOWS.items():
        wid = "wf-" + hashlib.md5(name.encode()).hexdigest()[:10]
        o["workflows"][wid] = {"id": wid, "name": name, "category-id": cat(path), "description": f"{plugin} plug-in configuration workflow",
                               "builtin": "config", "plugin": plugin, "versions": [],
                               "content": _simple_schema(name, [{"name": n, "type": t} for n, t in params], [])}
    paths = {"wf-expand-disk": "Northwind/Storage", "wf-ad-computer": "Northwind/Active Directory", "wf-sql-ag-failover": "Northwind/SQL",
             "wf-nsx-tag": "Northwind/Network"}
    for w in automation["workflows"]:
        o["workflows"][w["id"]] = {"id": w["id"], "name": w["name"], "category-id": cat(paths.get(w["id"], "Northwind")), "description": w["description"],
                                   "builtin": "northwind", "versions": [],
                                   "content": _simple_schema(w["name"], w["inputs"], w["outputs"])}
    o["workflows"]["wf-rotate-admin"] = {"id": "wf-rotate-admin", "name": "Rotate local admin password (asks for confirmation)",
                                         "category-id": cat("Northwind/Security"), "description": "Rotates the local Administrator password on a Windows VM after an operator confirms.",
                                         "builtin": "interaction", "versions": [],
                                         "content": _simple_schema("Rotate local admin password (asks for confirmation)", [{"name": "vmName", "type": "string"}], [], interaction=True)}
    if "concurrent_edit" in o["flags"]:
        cid = cat("MCP-Managed/Storage")
        content = _simple_schema("Disk usage report", [{"name": "vmName", "type": "string"}], [{"name": "report", "type": "string"}],
                                 script="report = 'disk usage for ' + vmName;")
        o["workflows"]["wf-disk-report"] = {"id": "wf-disk-report", "name": "Disk usage report", "category-id": cid, "description": "",
                                            "builtin": None, "content": content,
                                            "versions": [{"sha": _sha(content), "message": "initial", "user": "svc-mcp-automation", "date": "2026-10-01T10:00:00Z",
                                                          "content": json.loads(json.dumps(content))}]}
    o["cat"] = cat
    return o


def validate_schema(o, schema):
    msgs = []

    def m(sev, title, text, owner=""):
        msgs.append({"severity": sev, "title": title, "text": text, "owner": owner, "details": {}})

    for f in ("display-name", "input", "output", "attrib", "workflow-item", "position", "presentation"):
        if f not in schema:
            m("error", "Missing field", f"'{f}' is required")
    items = {i.get("name"): i for i in schema.get("workflow-item", [])}
    if schema.get("root-name") not in items:
        m("error", "No start item", "root-name must name a workflow item")
    if not any(i.get("type") == "end" for i in items.values()):
        m("error", "No end item", "A workflow needs at least one end item")
    known = {p["name"] for p in (schema.get("input") or {}).get("param", [])} | {p["name"] for p in (schema.get("output") or {}).get("param", [])} | \
            {a["name"] for a in schema.get("attrib", [])}
    for n, it in items.items():
        t = it.get("type")
        if t not in ("task", "link", "custom-condition", "condition", "end", "input", "foreach", "switch", "waiting-timer", "waiting-event"):
            m("error", "Unknown item type", f"{n}: type '{t}'", n)
        for key in ("out-name", "alt-out-name", "catch-name"):
            if it.get(key) and it[key] not in items:
                m("error", "Broken link", f"{n}.{key} -> '{it[key]}' does not exist", n)
        if t in ("task", "custom-condition") and not (it.get("script") or {}).get("text"):
            m("error", "Empty script", f"{n} has no script", n)
        if t == "custom-condition" and not it.get("alt-out-name"):
            m("error", "Decision without else", f"{n} needs alt-out-name", n)
        if t == "link" and it.get("linked-workflow-id") not in o["workflows"]:
            m("error", "Unknown workflow", f"{n} links to workflow '{it.get('linked-workflow-id')}', which does not exist", n)
        for side in ("in-binding", "out-binding"):
            for b in (it.get(side) or {}).get("bind", []):
                if b.get("export-name") not in known:
                    m("error", "Unbound parameter", f"{n} binds '{b.get('export-name')}', which is not an input, output or attribute", n)
        err = rhino_check((it.get("script") or {}).get("text", "")) if t in ("task", "custom-condition") else None
        if err:
            m("error", "Script error", f"{n}: {err}", n)
    reachable, todo = set(), [schema.get("root-name")]
    while todo:
        x = todo.pop()
        if x in reachable or x not in items:
            continue
        reachable.add(x)
        todo += [items[x].get(k) for k in ("out-name", "alt-out-name", "catch-name") if items[x].get(k)]
    for n in items:
        if n not in reachable:
            m("warning", "Unreachable item", f"{n} can never run", n)
    return msgs


# ---- request handling -----------------------------------------------------------------------------------

LIST_QUERY_KEYS = ("maxResult", "startIndex", "queryCount", "conditions", "keys", "sortOrders", "tags")


def _ws_commit(v):
    return {"objectId": v["sha"], "parentId": v.get("parent"), "message": v.get("message", ""), "authorName": v.get("user"), "committerName": v.get("user"),
            "commitDate": v.get("date"), "diffEntries": []}


def _new_commit(item, user, message, snapshot):
    prev = item["versions"][-1]["sha"] if item["versions"] else None
    v = {"sha": secrets.token_hex(20), "parent": prev, "message": message, "user": user, "date": _now(), "content": json.loads(json.dumps(snapshot, default=str))}
    item["versions"].append(v)
    return v


def _bad(msg, code=400):
    return code, {"status": "Bad Request" if code == 400 else "Error", "message": msg}


def handle(sim, h, method, path, q, body, user):
    """Returns (code, obj, user)."""
    a = sim.s["automation"]
    if not sim.s.get("orch"):
        sim.s["orch"] = build_orch(a, sim.s.get("orch_flags"))
    o = sim.s["orch"]
    p = path[len("/vco/api"):] or "/"
    W = o["workflows"]
    ok = lambda obj, code=200, headers=None: (code, _json_raw(obj, headers) if headers else obj, user)  # noqa: E731
    nf = (404, {"status": "Not Found", "message": f"{p} not found"}, user)
    err = lambda msg, code=400: (code, {"status": "Bad Request" if code == 400 else "Error", "message": msg}, user)  # noqa: E731
    if method in ("POST", "PUT", "PATCH", "DELETE") and "role_conflict" in o["flags"]:
        return 403, {"status": "Forbidden", "message": "The user has read-only access (Viewer role takes precedence)."}, user
    if p == "/about":
        return ok({"version": "9.1.0.0" if "version_9_1_0" in o["flags"] else "9.1.1.0", "build-number": "25812345", "api-version": "9.1.1"})
    if p == "/healthstatus":
        return ok({"state": "RUNNING"})
    if p == "/users":
        roles = ["Workflow Designer", "Viewer"] if "role_conflict" in o["flags"] else ["Workflow Designer"]
        login = "svc-mcp-automation@corp.nwg.lab" if "version_9_1_0" in o["flags"] else "svc-mcp-automation"
        return ok({"login-name": login, "display-name": login, "role": "USER", "admin-rights": False, "member-groups": [], "roles": roles})
    if p == "/plugins":
        rows = [{"moduleName": x["name"], "description": x["displayName"], "version": x["version"], "buildNumber": x["version"].rsplit(".", 1)[-1],
                 "fileName": f"o11nplugin-{x['name'].lower()}.vmoapp", "enabled": True} for x in o["plugins"]]
        return ok({"total": len(rows), "plugins": rows})
    if p == "/server-configuration/polyglot-runtimes":
        return ok({"polyglotRuntimes": ["python:3.11", "node:20", "powercli:13-powershell-7.4"]})
    if p == "/server-configuration/api":
        return ok({"plugins": [x["name"] for x in o["plugins"]]})
    if p.startswith("/server-configuration/api/plugins/"):
        parts = p.split("/")  # ['', 'server-configuration', 'api', 'plugins', plugin, version, build]
        if len(parts) != 7:
            return nf
        name = parts[4]
        if not any(x["name"] == name and x["version"] == parts[5] for x in o["plugins"]):
            return nf
        api = {"VC": ["VcPlugin.getAllVirtualMachines(): Array/VC:VirtualMachine", "VC:VirtualMachine.name", "VC:VirtualMachine.runtime.powerState",
                      "VC:VirtualMachine.summary.storage.committed", "System.getModule('com.vmware.library.vc.vm').getVirtualMachineByName(name)"],
               "RESTPlugin": ["RESTHostManager.getHosts()", "RESTHost.createRequest(method, url, content): RESTRequest", "RESTRequest.execute(): RESTResponse",
                              "RESTResponse.statusCode", "RESTResponse.contentAsString"],
               "AD": ["ActiveDirectory.createComputerAD(name, ou)", "ActiveDirectory.getComputerAD(name)"],
               "Mail": ["new EmailMessage()", "EmailMessage.sendMessage()", "EmailMessage.addMimePart(part, type)"]}.get(name)
        return ok({"plugin": name, "api": api}) if api else nf
    if p.startswith("/catalog/"):
        ns = p.split("/")[2]
        return ok({"link": [_link(x) for x in o["inventory"].get(ns, [])]})

    # ---- categories ----
    if p == "/categories" and method == "GET":
        if any(k in q for k in ("maxResult", "startIndex", "queryCount", "conditions")):
            return err("This list takes no paging or filter parameters")
        cats = list(o["categories"].values())
        if (q.get("isRoot") or ["false"])[0] == "true":
            cats = [c for c in cats if not c["parent"]]
        return ok({"link": [_link({"id": c["id"], "name": c["name"], "type": "WorkflowCategory"}) for c in cats], "total": len(cats)})
    if p.startswith("/categories") and method == "POST":
        parent = p.split("/")[2] if p.count("/") >= 2 else ""
        if parent and parent not in o["categories"]:
            return nf
        b = body or {}
        if (b.get("type") or b.get("categoryType")) != "WorkflowCategory" or not b.get("name"):
            return err("A category needs a name and type WorkflowCategory")
        if any(c["name"] == b["name"] and c["parent"] == parent for c in o["categories"].values()):
            return err(f"A category named '{b['name']}' already exists here")
        cid = "cat-" + secrets.token_hex(4)
        o["categories"][cid] = {"id": cid, "name": b.get("name"), "parent": parent}
        sim._save_automation()
        return ok({"id": cid, "name": b.get("name"), "type": "WorkflowCategory", "path": _cat_path(o, cid)}, 201, {"Location": f"/vco/api/categories/{cid}"})
    if p.startswith("/categories/"):
        c = o["categories"].get(p.split("/")[2])
        if not c:
            return nf
        kids = [k for k in o["categories"].values() if k["parent"] == c["id"]]
        return ok({"id": c["id"], "name": c["name"], "type": "WorkflowCategory", "path": _cat_path(o, c["id"]),
                   "relations": {"link": [_link({"id": k["id"], "name": k["name"], "type": "WorkflowCategory"}, rel="down") for k in kids]}})

    # ---- workflows ----
    if p == "/workflows" and method == "GET":
        if "queryCount" in q:
            return err("Unrecognized request parameter 'queryCount'")
        conds = q.get("conditions", [])
        name = next((c[5:].lower() for c in conds if c.startswith("name~")), None)
        items = [w for w in W.values() if not name or name in w["name"].lower()]
        start, maxr = int((q.get("startIndex") or ["0"])[0]), int((q.get("maxResult") or ["100"])[0])
        page = items[start:start + maxr]
        return ok({"link": [_link({"id": w["id"], "name": w["name"], "description": w["description"], "version": w["content"].get("version", "1.0.0"),
                                   "categoryId": w["category-id"], "categoryName": _cat_path(o, w["category-id"])}) for w in page],
                   "total": -1, "startIndex": start})
    if p == "/workflows" and method == "POST":
        b = body or {}
        if not b.get("name") or b.get("category-id") not in o["categories"]:
            return err("name and an existing category-id are required")
        if (q.get("uniqueName") or ["false"])[0] == "true" and any(w["name"] == b["name"] for w in W.values()):
            return err(f"A workflow named '{b['name']}' already exists")
        wid = secrets.token_hex(8) + "-" + secrets.token_hex(2)
        W[wid] = {"id": wid, "name": b["name"], "category-id": b["category-id"], "description": b.get("description", ""), "builtin": None,
                  "versions": [], "content": _simple_schema(b["name"], [], [], version="0.0.0")}
        sim._save_automation()
        return ok({"id": wid, "name": b["name"], "category-id": b["category-id"]}, 201, {"Location": f"/vco/api/workflows/{wid}"})
    if p == "/workflows/validate/schema" and method == "PUT":
        schema, bad = _read_schema(h, body)
        if bad:
            return bad[0], bad[1], user
        return ok({"messages": validate_schema(o, schema)})
    if p.startswith("/workflows/"):
        parts = p.split("/")
        w = W.get(parts[2])
        if not w:
            return nf
        rest = parts[3:]
        if not rest and method == "GET":
            return ok({"id": w["id"], "name": w["name"], "description": w["description"], "version": w["content"].get("version", "1.0.0"),
                       "category-id": w["category-id"], "categoryName": _cat_path(o, w["category-id"]),
                       "inputParameters": [{"name": i["name"], "type": i["type"]} for i in (w["content"].get("input") or {}).get("param", [])],
                       "outputParameters": [{"name": i["name"], "type": i["type"]} for i in (w["content"].get("output") or {}).get("param", [])]})
        if rest == ["content"] and method == "GET":
            return ok(w["content"])
        if rest == ["content"] and method == "PUT":
            want = h.headers.get("X-VRO-Changeset-Sha")
            if want and w["versions"] and want != w["versions"][-1]["sha"]:
                return 409, {"status": "Conflict", "message": "The workflow was modified by someone else (changeset mismatch)."}, user
            content, bad = _read_schema(h, body)
            if bad:
                return bad[0], bad[1], user
            content.pop("id", None)
            for it in content.get("workflow-item", []):  # 9.1 known issue K1
                txt = (it.get("script") or {}).get("text", "")
                if any(ord(ch) > 127 for ch in txt):
                    it["script"] = {"text": txt.encode().hex(), "encoded": True}
            w["content"] = content
            sim._save_automation()
            return 204, None, user
        if rest == ["validate"]:
            return ok({"messages": validate_schema(o, w["content"])})
        if rest == ["versions"] and method == "GET":
            # A colleague edits the workflow in the Orchestrator client right after the MCP's dry run
            # (the dry run is the first read of this workflow's version list; their edit lands before the second).
            if "concurrent_edit" in o["flags"] and w["id"] == "wf-disk-report":
                o["version_reads"] = o.get("version_reads", 0) + 1
                if o["version_reads"] == 2:
                    c2 = json.loads(json.dumps(w["content"]))
                    c2["description"] = "edited in the Orchestrator client by jane.doe"
                    w["content"] = c2
                    _new_commit(w, "jane.doe@corp.nwg.lab", "manual edit", c2)
            return ok({"commits": [_ws_commit(v) for v in reversed(w["versions"])]})
        if len(rest) == 2 and rest[0] == "versions" and method == "GET":
            v = next((v for v in w["versions"] if v["sha"] == rest[1]), None)
            return ok({**_ws_commit(v), "workflowSchema": v["content"]}) if v else nf
        if rest == ["versions"] and method == "POST":
            v = _new_commit(w, user, (body or {}).get("message", ""), w["content"])
            sim._save_automation()
            return ok(_ws_commit(v), 201)
        if rest == ["executions"] and method == "GET":
            exs = [e for e in o["executions"].values() if e["workflow"] == w["id"]]
            for c in q.get("conditions", []):
                if c.startswith("state="):
                    exs = [e for e in exs if e["state"] == c[6:]]
            start, maxr = int((q.get("startIndex") or ["0"])[0]), int((q.get("maxResult") or ["100"])[0])
            exs = list(reversed(exs))
            return ok({"relations": {"link": [_link({"id": e["id"], "name": e["name"], "state": e["state"], "startDate": e["start"], "endDate": e.get("end"),
                                                     "startedBy": e.get("started_by")}) for e in exs[start:start + maxr]], "total": -1, "startIndex": start}})
        if rest == ["executions"] and method == "POST":
            return _run(sim, o, w, body or {}, user)
        if len(rest) >= 2 and rest[0] == "executions":
            ex = o["executions"].get(rest[1])
            if not ex or ex["workflow"] != w["id"]:
                return nf
            if rest[2:] == ["state"] and method == "GET":
                return ok({"value": ex["state"]})
            if rest[2:] == ["state"] and method == "DELETE":
                ex["state"] = "canceled"
                return 204, None, user
            if rest[2:] == ["syslogs"]:
                return ok({"logs": [{"severity": "info", "origin": "server", "short-description": line, "time-stamp": ex["start"]} for line in ex.get("log", [])]})
            if rest[2:] == ["logs"]:
                return ok({"logs": [{"entry": {"severity": "info", "short-description": line, "time-stamp": ex["start"]}} for line in ex.get("log", [])]})
            if rest[2:] == ["interaction"]:
                if ex["state"] != "waiting":
                    return err("The execution is not waiting for input")
                if method == "GET":
                    return ok({"input-parameters": [{"name": "confirm", "type": "boolean", "description": f"Rotate the password of {ex['vm']}?"}]})
                if method == "DELETE":
                    ex.update(state="canceled", end=_now())
                    return 204, None, user
                vals = _params(body or {})
                ex["state"] = "completed" if vals.get("confirm") in (True, "true") else "canceled"
                ex["log"].append(f"operator answered confirm={vals.get('confirm')}")
                if ex["state"] == "completed":
                    ex["outputs"] = {}
                sim._save_automation()
                return 204, None, user
            if not rest[2:]:
                return ok(_ex_view(ex, (q.get("showDetails") or ["false"])[0] == "true"))
        return nf

    # ---- actions ----
    A = o["actions"]
    if p == "/actions" and method == "GET":
        if any(k in q for k in LIST_QUERY_KEYS):
            return err("GET /actions takes no query parameters")
        return ok({"link": [_link({"id": x["id"], "name": x["name"], "module": x["module"], "fqn": f"{x['module']}/{x['name']}", "version": x.get("version")})
                            for x in A.values()], "total": -1})
    if p == "/actions" and method == "POST":
        b = body or {}
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_-]*(\.[A-Za-z0-9_-]+)*$", str(b.get("name", ""))) or not b.get("module"):
            return err("name (valid identifier) and module are required")
        if any(x["name"] == b["name"] and x["module"] == b["module"] for x in A.values()):
            return err(f"Action {b['module']}/{b['name']} already exists")
        if not b.get("version"):
            return err("version is required")
        aid = secrets.token_hex(8)
        A[aid] = {**{k: b.get(k) for k in ("name", "module", "script", "description", "runtime", "output-type", "input-parameters")}, "id": aid,
                  "version": b["version"], "versions": []}
        _new_commit(A[aid], user, "created", b)
        sim._save_automation()
        return ok(_action_view(A[aid]), 201, {"Location": f"/vco/api/actions/{aid}"})
    if p.startswith("/actions/runs/"):
        r = o["action_runs"].get(p.split("/")[3])
        return ok(r) if r else nf
    if p.startswith("/actions/") and p.endswith("/logs") and p.count("/") == 3 and p.split("/")[2] in o["action_runs"]:
        return ok({"logs": o["action_logs"].get(p.split("/")[2], [])})  # GET /actions/{execution-id}/logs
    if p.startswith("/actions/"):
        parts = p.split("/")[2:]  # after /actions
        x, rest = _action_route(A, parts)
        if not x:
            return nf
        if not rest and method == "GET":
            return ok(_action_view(x))
        if not rest and method == "PUT":
            b = body or {}
            want = h.headers.get("X-VRO-Changeset-Sha")
            if want and x["versions"] and want != x["versions"][-1]["sha"]:
                return 409, {"status": "Conflict", "message": "The action was modified by someone else (changeset mismatch)."}, user
            x.update({k: b[k] for k in ("script", "description", "runtime", "output-type", "input-parameters", "version") if k in b})
            _new_commit(x, user, "updated", b)
            sim._save_automation()
            return ok({"errors": []})
        if not rest and method == "DELETE":
            A.pop(x["id"], None)
            sim._save_automation()
            return ok({})
        if rest == ["versions"] and method == "GET":
            return ok({"commits": [_ws_commit(v) for v in reversed(x["versions"])]})
        if rest == ["versions"] and method == "POST":
            v = _new_commit(x, user, (body or {}).get("message", ""), {k: x.get(k) for k in ("script", "description", "runtime", "output-type", "input-parameters", "version")})
            sim._save_automation()
            return ok(_ws_commit(v), 201)
        if len(rest) == 2 and rest[0] == "versions" and method == "GET":
            v = next((v for v in x["versions"] if v["sha"] == rest[1]), None)
            return ok({**{k: v["content"].get(k) for k in ("script", "description", "runtime", "output-type", "input-parameters", "version")},
                       "id": x["id"], "module": x["module"], "name": x["name"]}) if v else nf
        if rest == ["executions"] and method == "POST":
            return _run_action(o, x, body or {}, user)
        return nf

    # ---- configurations, environments, plug-ins, packages ----
    if p in ("/configurations", "/environments", "/packages", "/plugins", "/resources", "/policies") and method == "GET" and any(k in q for k in LIST_QUERY_KEYS):
        return err(f"GET {p} takes no query parameters")
    if p == "/configurations" and method == "GET":
        return ok({"link": [_link({"id": c["id"], "name": c["name"]}) for c in o["configurations"].values()]})
    if p == "/configurations" and method == "POST" or (p.startswith("/configurations/") and method == "PUT"):
        b = body or {}
        cid = p.split("/")[2] if p.startswith("/configurations/") else secrets.token_hex(6)
        attrs = []
        for at in b.get("attributes", []):
            if at.get("type") == "SecureString":
                val = (at.get("value") or {}).get("secure-string", {}).get("value", "")
                attrs.append({"name": at["name"], "type": "SecureString", "value": {"secure-string": {"value": "*****"}},
                              "_matches_store": secrets.compare_digest(str(val), sim.password)})
            else:
                attrs.append(at)
        o["configurations"][cid] = {"id": cid, "name": b.get("name"), "category-id": b.get("category-id"), "attributes": attrs}
        sim._save_automation()
        return ok({"id": cid}, 201 if method == "POST" else 200, {"Location": f"/vco/api/configurations/{cid}"})
    if p.startswith("/configurations/") and method == "GET":
        c = o["configurations"].get(p.split("/")[2])
        return ok({k: v for k, v in c.items()} if c else {}) if c else nf
    if p == "/environments" and method == "GET":
        return ok({"link": [_link({"id": e["id"], "name": e["name"], "runtime": e["runtime"]}) for e in o["environments"].values()]})
    if p == "/environments" and method == "POST":
        b = body or {}
        if not isinstance(b.get("dependencies", {}), dict) or not isinstance(b.get("repositories", {}), dict):
            return err("dependencies and repositories must be objects of name to value")
        eid = secrets.token_hex(6)
        o["environments"][eid] = {"id": eid, "name": b.get("name"), "runtime": b.get("runtime"), "dependencies": b.get("dependencies", {}),
                                  "repositories": b.get("repositories", {})}
        sim._save_automation()
        return ok({"id": eid, "status": "UP_TO_DATE"}, 201)
    if p == "/plugins/installations" and method == "POST":
        ctype = h.headers.get("Content-Type") or ""
        if not ctype.lower().startswith("multipart/form-data"):
            return 415, {"status": "Unsupported Media Type", "message": "multipart/form-data with a 'file' part is required"}, user
        fname, raw = _multipart_file(ctype, getattr(h, "_raw_body", b""))
        if raw is None:
            return err("The multipart body has no 'file' part")
        name = "SNMP" if b"snmp" in raw.lower() else "CustomPlugin"
        iid = secrets.token_hex(6)
        o["installations"][iid] = {"id": iid, "fileName": fname, "plugins": [{"moduleName": name, "version": "9.1.1.0", "buildNumber": "0", "fileName": fname}]}
        return ok({"id": iid, "fileName": fname, "eula": f"{name} plug-in end user license agreement", "plugins": o["installations"][iid]["plugins"],
                   "expiresInMillis": 600000}, 201)
    if p.startswith("/plugins/installations/") and method == "PATCH":
        inst = o["installations"].get(p.split("/")[3])
        if not inst:
            return nf
        b = body or {}
        if set(b) - {"eulaAccepted"}:
            return err(f"Unrecognized field(s) {sorted(set(b) - {'eulaAccepted'})}: the confirmation takes only eulaAccepted")
        if b.get("eulaAccepted") is not True:
            return err("The EULA must be accepted")
        o["plugins"] += [{"name": x["moduleName"], "version": x["version"], "displayName": x["moduleName"]} for x in inst["plugins"]]
        del o["installations"][inst["id"]]
        sim._save_automation()
        return ok({"pluginInstallResults": [{"plugin": x, "pluginInstallState": "INSTALLED"} for x in inst["plugins"]]})

    # ---- packages ----
    P = o["packages"]
    if p == "/packages" and method == "GET":
        return ok({"link": [_link({"name": n, "description": v["description"]}) for n, v in P.items()], "total": len(P)})
    if p.startswith("/packages/"):
        parts = p.split("/")[2:]
        pkg = P.get(parts[0])
        if len(parts) == 1 and method == "PUT":
            if parts[0] in P:
                return err(f"Package {parts[0]} already exists")
            P[parts[0]] = {"description": (body or {}).get("description", ""), "workflows": [], "actions": []}
            sim._save_automation()
            return 201, None, user
        if not pkg:
            return nf
        if len(parts) == 1 and method == "GET":
            o["last_export_params"] = {k: v[0] for k, v in q.items()}
            if "zip" not in (h.headers.get("Accept") or ""):
                return 406, {"status": "Not Acceptable", "message": "Use Accept: application/zip"}, user
            return 200, Raw(_package_zip(o, parts[0], pkg, (q.get("exportConfigSecureStringAttributeValues") or ["false"])[0] == "true"),
                            "application/zip", {"Content-Disposition": f'attachment; filename="{parts[0]}.package"'}), user
        if len(parts) == 3 and parts[1] == "workflow" and method == "POST":
            if parts[2] not in W:
                return nf
            pkg["workflows"].append(parts[2])
            return ok({}, 200)
        if len(parts) == 4 and parts[1] == "action" and method == "POST":
            x = next((x for x in A.values() if x["module"] == parts[2] and x["name"] == parts[3]), None)
            if not x:
                return nf
            pkg["actions"].append(x["id"])
            return ok({}, 200)
    return nf


def _action_route(A, parts):
    """(action, rest) for /actions/{id}[/...] and /actions/{module}/{name}[/...]."""
    if not parts:
        return None, []
    if parts[0] in A and (len(parts) == 1 or parts[1] in ("versions", "executions", "logs")):
        return A[parts[0]], parts[1:]
    if len(parts) >= 2:
        x = next((x for x in A.values() if x["module"] == parts[0] and x["name"] == parts[1]), None)
        if x:
            return x, parts[2:]
    return None, []


def _action_view(x):
    return {"id": x["id"], "name": x["name"], "module": x["module"], "fqn": f"{x['module']}/{x['name']}", "version": x.get("version"),
            "description": x.get("description") or "", "script": x.get("script"), "runtime": x.get("runtime"),
            "output-type": x.get("output-type"), "input-parameters": x.get("input-parameters") or []}


def _multipart_file(content_type, raw):
    msg = BytesParser().parsebytes(b"Content-Type: " + content_type.encode() + b"\r\nMIME-Version: 1.0\r\n\r\n" + raw)
    for part in msg.get_payload() if msg.is_multipart() else []:
        if part.get_param("name", header="content-disposition") == "file":
            return part.get_filename(), part.get_payload(decode=True)
    return None, None


def _package_zip(o, name, pkg, secure):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("dunes-meta-inf", f"package={name}\n")
        for wid in pkg["workflows"]:
            w = o["workflows"][wid]
            z.writestr(f"elements/{wid}/info", f"type=Workflow\nname={w['name']}\n")
            z.writestr(f"elements/{wid}/data", json.dumps(w["content"]))
        for aid in pkg["actions"]:
            x = o["actions"].get(aid)
            if x:
                z.writestr(f"elements/{aid}/info", f"type=Action\nname={x['module']}/{x['name']}\n")
                z.writestr(f"elements/{aid}/data", x.get("script") or "")
        if secure:
            z.writestr("secure-strings", "SECRET-VALUES-INCLUDED")
    return buf.getvalue()


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _cat_path(o, cid):
    parts = []
    while cid and cid in o["categories"]:
        parts.append(o["categories"][cid]["name"])
        cid = o["categories"][cid]["parent"]
    return "/".join(reversed(parts))


def _params(body):
    out = {}
    for prm in body.get("parameters", []):
        out[prm.get("name")] = _unwire(prm.get("value"))
    return out


def _ex_view(ex, details=False):
    d = {"id": ex["id"], "name": ex["name"], "state": ex["state"], "start-date": ex["start"], "end-date": ex.get("end"),
         "started-by": ex.get("started_by"),
         "outputParameters": [{"name": k, "type": t, "scope": "local", "value": _wire(v, t)} for k, (t, v) in ex.get("typed_outputs", {}).items()]
         or [{"name": k, "type": "string", "scope": "local", "value": {"string": {"value": v}}} for k, v in ex.get("outputs", {}).items()],
         **({"content-exception": ex["error"]} if ex.get("error") else {})}
    if details:
        d["inputParameters"] = [{"name": k, "type": "string", "scope": "local", "value": _wire(v)} for k, v in ex.get("inputs", {}).items()]
        d["current-item-display-name"] = ex.get("current_item", "")
    return d


# ---- action execution (a tiny evaluator: enough to return inputs, literals and + - * / expressions) -----------

def _js_value(node, env):
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        if node.id in env:
            return env[node.id]
        if node.id in ("true", "false"):
            return node.id == "true"
        raise ValueError(node.id)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        return -_js_value(node.operand, env)
    if isinstance(node, ast.BinOp):
        l, r = _js_value(node.left, env), _js_value(node.right, env)
        if isinstance(node.op, ast.Add):
            if isinstance(l, str) or isinstance(r, str):
                f = lambda v: str(int(v)) if isinstance(v, float) and v.is_integer() else str(v)  # noqa: E731
                return f(l) + f(r)
            return l + r
        return {ast.Sub: lambda: l - r, ast.Mult: lambda: l * r, ast.Div: lambda: l / r, ast.Mod: lambda: l % r}[type(node.op)]()
    raise ValueError("unsupported")


def _js_eval(expr, env):
    py = expr.strip().replace("===", "==").replace("!==", "!=")
    return _js_value(ast.parse(py, mode="eval").body, env)


def _run_action(o, x, body, user):
    declared = {i["name"]: i.get("type", "string") for i in x.get("input-parameters") or []}
    unknown = [n for n in (pr.get("name") for pr in body.get("parameters", [])) if n not in declared]
    if unknown:
        return 400, {"status": "Bad Request", "message": f"Unknown parameter(s): {', '.join(map(str, unknown))}"}, user
    params = _params(body)
    exec_id = secrets.token_hex(6)
    script = x.get("script") or ""
    logs, value, state, errmsg, errline = [], None, "completed", None, None
    err, line = (rhino_check(script, with_line=True) if not x.get("runtime") else (None, None))
    if err:
        state, errmsg, errline = "failed", err, line
    else:
        code = _strip_comments_and_quotes(script)
        env = {k: (float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else v) for k, v in params.items()}
        for m in re.finditer(r"System\.(log|warn|error)\(\s*(.+?)\s*\)\s*;", script):
            try:
                logs.append((m.group(1), str(_js_eval(m.group(2), env))))
            except Exception:
                logs.append((m.group(1), m.group(2)))
        th = re.search(r"throw\s+(?:new\s+Error\(\s*)?[\"'](.*?)[\"']", script)
        if th and "if" not in code:
            state, errmsg = "failed", th.group(1)
            errline = script[:th.start()].count("\n") + 1
        else:
            ret = re.findall(r"return\s+(.+?)\s*;", script, flags=re.S)
            try:
                value = _js_eval(ret[-1], env) if ret else None
            except Exception:
                value = "ok"
    rtype = x.get("output-type") or "string"
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    res = {"name": "result", "type": rtype, "scope": "local", "state": state, "execution-id": exec_id,
           **({"value": _wire(value, rtype)} if value is not None and state == "completed" else {}),
           **({"errorMessage": errmsg, "errorLineNumber": errline} if errmsg else {})}
    o["action_logs"][exec_id] = [{"severity": s, "short-description": t, "time-stamp": _now()} for s, t in logs]
    o["action_runs"][exec_id] = res
    return 200, res, user


def _run(sim, o, w, body, user):
    params = _params(body)
    declared = {x["name"]: x["type"] for x in (w["content"].get("input") or {}).get("param", [])}
    missing = [n for n in declared if params.get(n) in (None, "")]
    if missing:
        return 400, {"status": "Bad Request", "message": f"Missing input parameter(s): {', '.join(missing)}"}, user
    eid = secrets.token_hex(8)
    ex = {"id": eid, "workflow": w["id"], "name": w["name"], "state": "completed", "start": _now(), "log": [], "outputs": {}, "started_by": user,
          "inputs": {k: ("<secure>" if declared.get(k) == "SecureString" else v) for k, v in params.items()}}
    if w.get("builtin") == "northwind":
        legacy = {"parameters": [{"name": k, "value": {"string": {"value": v}}} for k, v in params.items()]}
        code, res, _ = sim._run_workflow(next(x for x in sim.s["automation"]["workflows"] if x["id"] == w["id"]), legacy, user)
        old = sim.s["automation"]["executions"][res["id"]]
        outs = {op["name"]: next(iter(op["value"].values()))["value"] for op in old["output-parameters"]}
        otypes = {op["name"]: op["type"] for op in (w["content"].get("output") or {}).get("param", [])}
        ex.update(state=old["state"], error=old.get("content-exception"), outputs=outs,
                  typed_outputs={k: (otypes.get(k, "string"), v) for k, v in outs.items()})
    elif w.get("builtin") == "config":
        pw = next((params[n] for n, t in declared.items() if t == "SecureString"), "")
        if not secrets.compare_digest(str(pw), sim.password):
            ex.update(state="failed", error=f"{w['plugin']}: authentication failed for user '{params.get('username')}' (401 Unauthorized)")
        else:
            name = params.get("name") or params.get("host") or params.get("hostname") or params.get("url")
            inv = o["inventory"].setdefault(w["plugin"], [])
            existing = next((x for x in inv if x["name"] == name), None)
            if existing:
                existing["state"] = "ok"
            else:
                inv.append({"name": name, "state": "ok"})
            ex["log"].append(f"{w['plugin']} endpoint {name} registered")
    elif w.get("builtin") == "interaction":
        if not sim._vm_by_name(params.get("vmName", "")):
            ex.update(state="failed", error=f"VM '{params.get('vmName')}' not found")
        else:
            ex.update(state="waiting", vm=params["vmName"])
            ex["log"].append("waiting for operator confirmation")
    else:
        items = {i["name"]: i for i in w["content"].get("workflow-item", [])}
        cur, steps = w["content"].get("root-name"), 0
        env = {k: (float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else v) for k, v in params.items()}
        while cur in items and steps < 100:
            steps += 1
            it = items[cur]
            ex["current_item"] = it.get("display-name", "")
            if it.get("type") == "end":
                if it.get("end-mode") == "1":
                    ex["state"] = "failed"
                    ex["error"] = ex.get("error") or "Workflow ended in its error handler"
                break
            txt = (it.get("script") or {}).get("text", "")
            err = rhino_check(txt) if it.get("type") in ("task", "custom-condition") else None
            if not err and "throw " in _strip_strings(txt) and "if" not in txt:
                err = "Error thrown by script"
            if not err and it.get("type") == "task":
                # Evaluate simple assignments (x = 'a' + vmName;) so outputs come from the real inputs.
                for m in re.finditer(r"(?m)^\s*(?:var\s+)?([A-Za-z_]\w*)\s*=\s*([^=;][^;]*);", txt):
                    try:
                        env[m.group(1)] = _js_eval(m.group(2), env)
                    except Exception:
                        pass
            ex["log"].append(f"{it.get('display-name')}: {'error ' + err if err else 'ok'}")
            if err:
                ex["error"] = f"{err} (Workflow:{w['name']} / {it.get('display-name')} (item {cur})#1)"
                if it.get("catch-name"):
                    cur = it["catch-name"]
                    continue
                ex["state"] = "failed"
                break
            cur = it.get("out-name")
        for op in (w["content"].get("output") or {}).get("param", []):
            if ex["state"] == "completed":
                val = env.get(op["name"]) if "env" in locals() else None
                if isinstance(val, float) and val.is_integer():
                    val = int(val)
                ex.setdefault("typed_outputs", {})[op["name"]] = (op["type"], val if val is not None else
                                                                  (f"<{op['name']} from simulated run>" if not op["type"].startswith("Array") else []))
    ex["end"] = None if ex["state"] == "waiting" else _now()
    o["executions"][eid] = ex
    sim._save_automation()
    return 202, Raw(b"", "application/json", {"Location": f"/vco/api/workflows/{w['id']}/executions/{eid}"}), user
