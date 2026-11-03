# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
VCF Operations Orchestrator 9.1 (embedded in VCF Automation, or standalone) through the
official REST API at /vco/api (Broadcom "VCF Operations Orchestrator API 9.1").

read     GET /about, /healthstatus, /plugins, /server-configuration/polyglot-runtimes, /users,
         /workflows (maxResult/startIndex), /workflows/{id}, /workflows/{id}/content, /workflows/{id}/versions,
         /workflows/{id}/executions, /actions, /actions/{module}/{name}, /actions/{id}/versions,
         /categories (isRoot, then /categories/{id} relations), /configurations, /environments,
         /workflows/{w}/executions/{e}[?showDetails=true|/state|/syslogs|/logs|/interaction],
         /actions/{execution}/logs, /catalog/{namespace}/..., /server-configuration/api[/plugins/{p}/{v}/{b}],
         /packages/{name} (application/zip)
validate PUT /workflows/validate/schema (XML, JSON fallback on 415), GET /workflows/{id}/validate
write    POST /categories[/{id}], POST|PUT /actions, DELETE /actions/{id}?force=true, POST /workflows,
         PUT /workflows/{id}/content (XML or JSON, X-VRO-Changeset-Sha), POST /workflows/{id}/versions,
         POST /workflows/{w}/executions, POST|DELETE .../interaction, DELETE .../state,
         POST /actions/{module}/{name}/executions (synchronous result), POST|PUT /configurations,
         POST /environments, POST /plugins/installations (multipart) + PATCH /plugins/installations/{id},
         PUT /packages/{name} + POST /packages/{name}/{workflow|action}/...

Proven on a real VCF Automation 9.1.1 server by the community project vcf-orchestrator-mcp (imtrinity94, MIT;
see THIRD_PARTY_NOTICES.md): XML workflow content, typed values (wire.py), run/execution handling, synchronous
action runs, the folder walk, patch-bumped versions and package export are ported from it. Everything else was
checked against the official Orchestrator 9.0 OpenAPI spec.

Guardrails (see docs/plan_orchestrator_9_1.md):
- The MCP creates and edits only inside its own category root and action module prefix.
- Workflows run only from that root or from admin-allowlisted category paths, never blocked ones.
- Every script is linted (js_lint, plain ES5 by default) before saving; server-side validation must report no errors.
- SecureString inputs come only from secret references, resolved here and never returned.
- Updates send the changeset id read during the dry run, so concurrent edits are not overwritten.
- Package export never includes SecureString values.
"""

from __future__ import annotations

import fnmatch
import hashlib
import io
import json
import os
import re
import secrets
import time
import urllib.parse
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from vcf_enterprise_mcp.adapter.providers.vcenter import VCenterProvider
from vcf_enterprise_mcp.adapter.transport.base import TransportRequest, TransportResponse
from vcf_enterprise_mcp.adapter.transport.errors import UpstreamAuthException, UpstreamResourceNotFoundException
from vcf_enterprise_mcp.automation import wire
from vcf_enterprise_mcp.automation.js_lint import SCRIPT_LEVELS, lint_script
from vcf_enterprise_mcp.automation.orch_changes import ChangeTracker
from vcf_enterprise_mcp.automation.wf_compiler import NIL_ID, SpecError, compile_spec, schema_for_json, to_xml

API = "/vco/api"
TERMINAL_STATES = {"completed", "failed", "canceled"}
STOP_WAITING_STATES = {"waiting", "waiting-signal", "suspended"}
EXECUTION_STATES = {"completed", "failed", "canceled", "running", "waiting", "waiting-signal", "suspended", "initializing"}


class OrchestratorUnavailable(Exception):
    pass


class OrchestratorRefused(Exception):
    """A guardrail refused the request; the message says why and what to do instead."""


def _cfg(platform: Any) -> Dict[str, Any]:
    cfg = getattr(platform, "orchestrator", None)
    if not cfg:
        raise OrchestratorUnavailable("Orchestrator is not configured (vcf.orchestrator_url or vcf.automation_url, plus the "
                                      "'vcf_automation' credential).")
    return cfg


def _prov(platform: Any) -> VCenterProvider:
    cfg = _cfg(platform)
    return VCenterProvider(endpoint_url=cfg["url"], transport=platform.transport, auth=cfg["auth"])


def _level(platform: Any) -> str:
    level = str(_cfg(platform).get("script_level") or "es5")
    if level not in SCRIPT_LEVELS:
        raise OrchestratorUnavailable(f"vcf.orchestrator_script_level must be one of: {', '.join(SCRIPT_LEVELS)} (got '{level}').")
    return level


def _tracker(platform: Any) -> ChangeTracker:
    return ChangeTracker(str(_cfg(platform)["url"]))


# ---- HTTP helpers ------------------------------------------------------------------------------------

def _get(p, path, params=None):
    return p.request("GET", API + path, params=params).json()


def _get_opt(p, path, params=None):
    """GET that answers None when the object does not exist (the transport raises on HTTP 404)."""
    try:
        return _get(p, path, params)
    except UpstreamResourceNotFoundException:
        return None


def _msg(data) -> Optional[str]:
    return (data or {}).get("message") if isinstance(data, dict) else None


def _json(resp) -> Any:
    try:
        return resp.json()
    except Exception:
        return None


def _send(p, method, path, body=None, params=None, headers=None):
    resp = p.request(method, API + path, params=params, json_body=body, headers=headers)
    data = _json(resp)
    if not resp.is_success:
        raise OrchestratorRefused(f"Orchestrator returned HTTP {resp.status_code} for {method} {path}: {_msg(data) or 'no details'}")
    return data


def _created_id(resp: TransportResponse, data: Any = None) -> Optional[str]:
    """Id of a created object: the body's id, else the last segment of the Location header."""
    data = data if data is not None else _json(resp)
    if isinstance(data, dict) and data.get("id"):
        return str(data["id"])
    loc = next((v for k, v in (resp.headers or {}).items() if k.lower() == "location"), None)
    return loc.rstrip("/").split("/")[-1] if loc else None


def _raw_request(p, method: str, path: str, data: bytes, content_type: str, params=None, headers=None,
                 accept: str = "application/json", timeout: float = 120.0) -> TransportResponse:
    """A request with a non-JSON body (XML workflow content, multipart upload), authenticated like provider.request."""
    req_headers = {"Accept": accept, "Content-Type": content_type, "User-Agent": f"vcf-enterprise-mcp/1.0.0 (API {p.api_version})"}
    req_headers.update(headers or {})
    req = TransportRequest(method=method.upper(), url=p._build_url(API + path), headers=req_headers, params=params, data=data,
                           timeout_seconds=timeout, tenant_id=p.tenant_id, environment_id=p.environment_id)
    if p.auth:
        req = p.auth.apply(req)
    try:
        return p.transport.send(req)
    except UpstreamAuthException as exc:
        if not p.auth or exc.details.get("status_code") != 401:
            raise
        p.auth.invalidate()  # 401: rejected before processing, so one re-login and resend is safe
        req.headers.pop("Authorization", None)
        return p.transport.send(p.auth.apply(req))


def _attrs(link):
    return {a.get("name"): a.get("value") for a in link.get("attributes") or []}


def _links(data) -> List[Dict[str, Any]]:
    """Link list of an inventory response: top-level `link`, or `relations.link`."""
    if not isinstance(data, dict):
        return []
    return list(data.get("link") or (data.get("relations") or {}).get("link") or [])


def _version_tuple(v: str):
    return tuple(int(x) for x in "".join(c if c.isdigit() or c == "." else " " for c in v).split()[0].split(".") if x.isdigit())


def bump_version(v: Optional[str], level: str = "patch") -> str:
    """x.y.z bumped by level; empty, non-semver or 0.0.0 becomes 1.0.0."""
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)", str(v or ""))
    if not m or (m.group(1), m.group(2), m.group(3)) == ("0", "0", "0"):
        return "1.0.0"
    major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
    if level == "major":
        return f"{major + 1}.0.0"
    if level == "minor":
        return f"{major}.{minor + 1}.0"
    return f"{major}.{minor}.{patch + 1}"


# ---- commits (versions) -------------------------------------------------------------------------------

def _commit_id(c: Dict[str, Any]) -> Optional[str]:
    return c.get("objectId") or c.get("sha") or c.get("id")


def _commits(p, kind: str, item_id: str) -> List[Dict[str, Any]]:
    """GET /{workflows|actions}/{id}/versions answers {"commits": [WsCommit]}."""
    data = _get_opt(p, f"/{kind}/{urllib.parse.quote(item_id, safe='')}/versions") or {}
    return list(data.get("commits") or data.get("versions") or [])


def _latest_commit(commits: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Newest commit: by commitDate when every commit has one, else the first (the history is newest first)."""
    if not commits:
        return None
    if all(c.get("commitDate") for c in commits):
        return max(commits, key=lambda c: str(c["commitDate"]))
    return commits[0]


def _latest_commit_id(p, kind: str, item_id: str) -> Optional[str]:
    c = _latest_commit(_commits(p, kind, item_id))
    return _commit_id(c) if c else None


# ---- read ----------------------------------------------------------------------------------------

def _plugin_list(data) -> List[Dict[str, Any]]:
    """GET /plugins is {"total", "plugins": [WsInstalledPlugin]} (older payloads used "plugin")."""
    rows = (data or {}).get("plugins") or (data or {}).get("plugin") or []
    return [{"name": x.get("moduleName") or x.get("name"), "version": x.get("version"), "display_name": x.get("displayName") or x.get("description"),
             "build": x.get("buildNumber"), "enabled": x.get("enabled")} for x in rows]


def about(platform: Any) -> Dict[str, Any]:
    p = _prov(platform)
    info = _get(p, "/about") or {}
    version = str(info.get("version", "?"))
    health = _get(p, "/healthstatus") or {}
    out: Dict[str, Any] = {"version": version, "build": info.get("build-number"), "health": health.get("state") or health.get("serverState")}
    plugins = _plugin_list(_get(p, "/plugins"))
    out["plugins"] = plugins
    rt = _get(p, "/server-configuration/polyglot-runtimes") or {}
    names = rt.get("polyglotRuntimes") or rt.get("o11n-polyglot-runtime") or rt.get("runtimes") or []
    out["runtimes"] = [r.get("name") if isinstance(r, dict) else r for r in names]
    me = _get(p, "/users") or {}
    roles = list(me.get("roles") or ([me["role"]] if me.get("role") else []))
    if me.get("admin-rights") and "Administrator" not in roles:
        roles.append("Administrator")
    login = me.get("login-name") or me.get("name")
    out["service_account"] = {"user": login, "roles": roles}
    issues = []
    if "Viewer" in roles and any(r in roles for r in ("Workflow Designer", "Developer")):
        issues.append("This account has both Workflow Designer and Viewer roles: the most restrictive wins, so it is READ-ONLY "
                      "(Broadcom KB 438403). Remove the Viewer role from its groups, then log in again.")
    if "Administrator" in roles:
        issues.append("This account is an Orchestrator Administrator: more privilege than the MCP needs. Use a Workflow Designer "
                      "account scoped to the MCP category.")
    if version.startswith("9.1.0"):
        if len([r for r in roles if r]) > 1:
            issues.append("9.1.0 known issue: scheduled and long-running workflows fail when the requesting user has more than one "
                          "VCF Automation role (fixed in 9.1.1).")
        if "@" in str(login or ""):
            issues.append("9.1.0 known issue: with VCF SSO, local Orchestrator roles are ignored for UPN logins (fixed in 9.1.1); "
                          "assign global roles.")
        issues.append("9.1.0 known issue: context.getToken() breaks after token refresh in Python runtimes (fixed in 9.1.1).")
    mail = next((x for x in plugins if str(x.get("name", "")).lower() == "mail"), None)
    if mail and _version_tuple(str(mail.get("version"))) < (9, 1, 0, 401):
        issues.append(f"Mail plug-in {mail.get('version')} cannot send attachments on 9.1 (KB 447131); 9.1.0.0401 fixes it.")
    try:
        vcs = _get(p, "/catalog/VC/SdkConnection") or {}
        for link in _links(vcs):
            a = _attrs(link)
            if str(a.get("state", "")).lower() not in ("", "ok", "connected"):
                issues.append(f"vCenter connection '{a.get('name')}' in the vCenter plug-in is {a.get('state')}: workflows against it fail. "
                              "Fix: vcf_orch_add_integration kind=vcenter_update for that vCenter (Broadcom KB 452127).")
    except Exception:
        pass
    out["known_issues_that_apply"] = issues
    out["script_level"] = _level(platform)
    out["guardrails"] = {k: _cfg(platform)[k] for k in ("managed_category", "module_prefix", "run_allowlist", "blocked")}
    return out


LIST_PATHS = {"workflows": "/workflows", "actions": "/actions", "categories": "/categories", "configurations": "/configurations",
              "environments": "/environments", "plugins": "/plugins", "packages": "/packages", "resources": "/resources", "policies": "/policies"}
# Only /workflows takes maxResult/startIndex/conditions in the Orchestrator API (/actions and the others take no
# query at all); queryCount is never sent: 9.1 answers HTTP 400 and 9.x reports total=-1 anyway.
SERVER_PAGED = {"workflows"}
MAX_LIMIT = 200


def list_items(platform: Any, kind: str, name_filter: Optional[str] = None, limit: int = 50, start_index: int = 0) -> Dict[str, Any]:
    if kind not in LIST_PATHS:
        raise ValueError(f"kind must be one of: {', '.join(LIST_PATHS)}")
    try:
        limit, start_index = max(1, min(int(limit or 50), MAX_LIMIT)), max(0, int(start_index or 0))
    except (TypeError, ValueError):
        raise ValueError("limit and start_index must be whole numbers.")
    p = _prov(platform)
    params: Dict[str, Any] = {}
    paged = kind in SERVER_PAGED
    if paged:
        params = {"maxResult": limit, "startIndex": start_index}
        if name_filter:
            params["conditions"] = f"name~{name_filter}"
    data = _get(p, LIST_PATHS[kind], params or None) or {}
    if kind == "plugins":
        items = _plugin_list(data)
    elif _links(data):
        items = [_attrs(link) for link in _links(data)]
    else:
        items = data.get(kind[:-1]) or data.get(kind) or data.get("items") or []
    server_count = len(items)
    if name_filter:
        q = name_filter.lower()
        items = [i for i in items if q in str(i.get("name", "")).lower() or q in str(i.get("fqn", "")).lower()]
    if paged:
        more = server_count >= limit
        page = items
    else:
        page = items[start_index:start_index + limit]
        more = start_index + limit < len(items)
    out: Dict[str, Any] = {"kind": kind, "count": len(page), "items": page, "more": more, "limit": limit, "start_index": start_index}
    total = data.get("total")
    if isinstance(total, int) and total >= 0:  # 9.x reports -1 (unknown)
        out["total"] = total
    elif not paged:
        out["total"] = len(items)
    if more:
        out["next_step"] = f"More results exist: call again with start_index={start_index + limit}" + ("" if name_filter else " or narrow with name.")
    return out


def _workflow(p, wid):
    wf = _get(p, f"/workflows/{wid}") or {}
    content = _get(p, f"/workflows/{wid}/content") or {}
    return wf, content


def _resolve_action(p, ref: str) -> Dict[str, Any]:
    """An action by id, or by 'module/name' (GET /actions/{module}/{name})."""
    ref = str(ref)
    if "/" in ref:
        module, name = ref.rsplit("/", 1)
        a = _get_opt(p, f"/actions/{urllib.parse.quote(module, safe='')}/{urllib.parse.quote(name, safe='')}")
    else:
        a = _get_opt(p, f"/actions/{urllib.parse.quote(ref, safe='')}")
    if not a:
        raise OrchestratorRefused(f"Action {ref} not found. Find it with vcf_orch_list kind=actions name=...")
    return a


def _action_inputs(a: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [{"name": x.get("name"), "type": x.get("type", "string"), "description": x.get("description", "")}
            for x in (a.get("input-parameters") or a.get("inputParameters") or [])]


def _action_return_type(a: Dict[str, Any]) -> Optional[str]:
    return a.get("output-type") or a.get("outputParameterType") or a.get("outputType")


def get_item(platform: Any, kind: str, item_id: str, workflow_id: Optional[str] = None) -> Dict[str, Any]:
    p = _prov(platform)
    if kind == "workflow":
        wf, content = _workflow(p, item_id)
        return {"id": item_id, "name": wf.get("name"), "version": wf.get("version"), "category": wf.get("categoryName") or wf.get("category-id"),
                "inputs": (content.get("input") or {}).get("param", []), "outputs": (content.get("output") or {}).get("param", []),
                "steps": [{"name": i.get("name"), "type": i.get("type"), "display_name": i.get("display-name"),
                           "script": (i.get("script") or {}).get("text"), "next": i.get("out-name")} for i in content.get("workflow-item", [])],
                "changeset_sha": _latest_commit_id(p, "workflows", item_id)}
    if kind == "action":
        a = _resolve_action(p, item_id)
        out = {k: a.get(k) for k in ("id", "name", "module", "fqn", "version", "runtime", "script", "description")}
        out["input-parameters"] = _action_inputs(a)
        out["output-type"] = _action_return_type(a)
        out["changeset_sha"] = _latest_commit_id(p, "actions", a.get("id") or item_id)
        return out
    if kind == "configuration":
        c = _get(p, f"/configurations/{item_id}") or {}
        for att in c.get("attributes", []):
            if str(att.get("type", "")).lower() == "securestring":
                att["value"] = "<hidden>"
        return c
    if kind == "execution":
        if not workflow_id:
            raise ValueError("kind=execution needs workflow_id as well as id (the execution id).")
        return get_execution(platform, workflow_id, item_id, include_logs=True)
    if kind == "scripting_api":
        if item_id in ("", "all", "plugins"):
            return _get(p, "/server-configuration/api") or {}
        return _plugin_api(p, item_id)
    raise ValueError("kind must be workflow, action, configuration, execution or scripting_api")


def _plugin_api(p, ref: str) -> Dict[str, Any]:
    """The scripting API of one plug-in: GET /server-configuration/api/plugins/{plugin}/{version}/{build}.
    `ref` is the plug-in name from vcf_orch_about (version and build are looked up) or 'plugin/version/build'."""
    parts = [x for x in str(ref).split("/") if x]
    if len(parts) == 3:
        plugin, version, build = parts
    else:
        data = _get(p, "/plugins") or {}
        row = next((x for x in (data.get("plugins") or data.get("plugin") or []) if ref in (x.get("moduleName"), x.get("name"))), None)
        if not row:
            raise OrchestratorRefused(f"Plug-in '{ref}' is not installed. Names come from vcf_orch_about (plugins), or pass plugin/version/build.")
        plugin, version = row.get("moduleName") or row.get("name"), str(row.get("version", ""))
        build = str(row.get("buildNumber") or version.rsplit(".", 1)[-1])
    q = urllib.parse.quote
    return _get(p, f"/server-configuration/api/plugins/{q(plugin, safe='')}/{q(version, safe='')}/{q(build, safe='')}") or {}


# ---- executions ---------------------------------------------------------------------------------------

def _simplify_logs(body: Any, limit: int) -> List[Dict[str, Any]]:
    if not body:
        return []
    if isinstance(body, str):
        return [{"message": x} for x in body.splitlines() if x][-limit:]
    rows = body.get("logs") if isinstance(body, dict) else body
    rows = rows if isinstance(rows, list) else [rows] if rows else []
    out = []
    for r in rows[-limit:]:
        e = r.get("entry", r) if isinstance(r, dict) else {"message": str(r)}
        out.append({"time": e.get("time-stamp") or e.get("timeStamp") or e.get("timestamp"), "severity": e.get("severity"),
                    "message": e.get("short-description") or e.get("message") or e.get("description") or e.get("shortDescription")})
    return out


def _exec_logs(p, workflow_id: str, execution_id: str, limit: int = 100) -> List[Dict[str, Any]]:
    """Execution logs: /syslogs first, then /logs (which one a server fills differs); [] if neither answers."""
    for suffix in ("/syslogs", "/logs"):
        try:
            logs = _simplify_logs(_get(p, f"/workflows/{workflow_id}/executions/{execution_id}{suffix}", {"maxResult": limit}), limit)
        except Exception:
            continue
        if logs:
            return logs
    return []


def _execution_view(p, workflow_id: str, execution_id: str, include_inputs: bool = False) -> Dict[str, Any]:
    ex = _get(p, f"/workflows/{workflow_id}/executions/{execution_id}", {"showDetails": "true"}) or {}
    outs = ex.get("outputParameters") or ex.get("output-parameters")
    out = {"execution_id": ex.get("id", execution_id), "workflow_id": workflow_id, "workflow": ex.get("name"), "state": ex.get("state"),
           "outputs": wire.params_to_object(outs), "started_at": ex.get("start-date"), "ended_at": ex.get("end-date")}
    if ex.get("started-by"):
        out["started_by"] = ex["started-by"]
    if ex.get("current-item-display-name"):
        out["current_item"] = ex["current-item-display-name"]
    if ex.get("content-exception"):
        out["error"] = ex["content-exception"]
    if include_inputs:
        out["inputs"] = wire.params_to_object(ex.get("inputParameters") or ex.get("input-parameters"))
    return out


def get_execution(platform: Any, workflow_id: str, execution_id: str, include_logs: bool = False, include_inputs: bool = False) -> Dict[str, Any]:
    p = _prov(platform)
    out = _execution_view(p, workflow_id, execution_id, include_inputs)
    if out.get("state") == "waiting":
        inter = _get_opt(p, f"/workflows/{workflow_id}/executions/{execution_id}/interaction") or {}
        out["waiting_for_input"] = {"inputs": inter.get("input-parameters", []), "next_step": "vcf_orch_answer with these inputs, or cancel=true"}
    if include_logs or out.get("state") == "failed":
        out["logs"] = _exec_logs(p, workflow_id, execution_id)
    return out


def list_executions(platform: Any, workflow_id: str, limit: int = 20, state: Optional[str] = None, start_index: int = 0) -> Dict[str, Any]:
    """Recent executions of one workflow (read-only): GET /workflows/{id}/executions."""
    if state and state not in EXECUTION_STATES:
        raise ValueError(f"state must be one of: {', '.join(sorted(EXECUTION_STATES))}")
    limit = max(1, min(int(limit or 20), MAX_LIMIT))
    start_index = max(0, int(start_index or 0))
    p = _prov(platform)
    params: Dict[str, Any] = {"maxResult": limit, "startIndex": start_index}
    if state:
        params["conditions"] = f"state={state}"
    data = _get(p, f"/workflows/{urllib.parse.quote(str(workflow_id), safe='')}/executions", params) or {}
    items = []
    for link in _links(data):
        a = _attrs(link)
        items.append({"execution_id": a.get("id"), "name": a.get("name"), "state": a.get("state"),
                      "started_at": a.get("startDate") or a.get("start-date"), "ended_at": a.get("endDate") or a.get("end-date"),
                      "started_by": a.get("startedBy") or a.get("started-by")})
    out: Dict[str, Any] = {"workflow_id": workflow_id, "count": len(items), "items": items, "more": len(items) >= limit, "limit": limit,
                           "start_index": start_index}
    total = data.get("total") if "total" in data else (data.get("relations") or {}).get("total")
    if isinstance(total, int) and total >= 0:
        out["total"] = total
    if out["more"]:
        out["next_step"] = f"More runs exist: call again with start_index={start_index + limit}."
    return out


# ---- validation -------------------------------------------------------------------------------------

def _server_version(p) -> str:
    try:
        return str((_get(p, "/about") or {}).get("version", "9.1.1"))
    except Exception:
        return "9.1.1"


def validate_action(platform: Any, script: str, runtime: str = "javascript") -> Dict[str, Any]:
    p = _prov(platform)
    ver = _server_version(p)
    res = lint_script(script, runtime, ver, _plugin_versions(p), _level(platform)).to_dict()
    res["server_version"] = ver
    res["script_level"] = _level(platform)
    return res


def _plugin_versions(p) -> Dict[str, str]:
    try:
        return {x["name"]: x["version"] for x in _plugin_list(_get(p, "/plugins"))}
    except Exception:
        return {}


def _put_schema(p, method: str, path: str, schema: Dict[str, Any], workflow_id: str, headers=None) -> TransportResponse:
    """Send a workflow schema as XML (proven on a real 9.1.1 server); on HTTP 415 retry once as JSON."""
    resp = _raw_request(p, method, path, to_xml(schema, workflow_id).encode("utf-8"), "application/xml", headers=headers)
    if resp.status_code == 415:
        resp = p.request(method, API + path, json_body=schema_for_json(schema), headers=headers)
    return resp


def validate_workflow(platform: Any, spec: Dict[str, Any], workflow_id: Optional[str] = None) -> Dict[str, Any]:
    p = _prov(platform)
    ver = _server_version(p)
    try:
        schema, scripts = compile_spec(spec)
    except SpecError as exc:
        return {"valid": False, "stage": "spec", "errors": exc.problems, "warnings": []}
    errors, warnings = [], []
    plugins, level = _plugin_versions(p), _level(platform)
    for s in scripts:
        r = lint_script(s["script"], "javascript", ver, plugins, level)
        errors += [{**e, "step": s["step"]} for e in r.errors]
        warnings += [{**w, "step": s["step"]} for w in r.warnings]
    if errors:
        return {"valid": False, "stage": "script_check", "errors": errors, "warnings": warnings}
    resp = _put_schema(p, "PUT", "/workflows/validate/schema", schema, workflow_id or NIL_ID)
    srv = _json(resp) or {}
    if not resp.is_success:
        errors.append({"rule": "server_validation", "message": f"Orchestrator returned HTTP {resp.status_code} for the schema: {_msg(srv) or 'no details'}"})
    for m in srv.get("messages", []):
        (errors if str(m.get("severity", "")).lower() in ("error", "fatal") else warnings).append(
            {"rule": "server_validation", "message": f"{m.get('title', '')}: {m.get('text', '')}".strip(": "), "owner": m.get("owner")})
    return {"valid": not errors, "stage": "server_validation", "errors": errors, "warnings": warnings, "item_count": len(schema["workflow-item"]),
            "server_version": ver, "format": "xml" if resp.status_code != 415 else "json"}


# ---- categories (folders) -------------------------------------------------------------------------------

def _category_links(body: Any, rel: str = "*") -> List[Dict[str, Any]]:
    """Child categories of a category (relations.link rel=down) or the root list (plain link): [{id, name, type}]."""
    out = []
    for link in _links(body):
        if rel != "*" and link.get("rel") != rel:
            continue
        a = _attrs(link)
        if a.get("id") and (not a.get("type") or a.get("type") == "WorkflowCategory"):
            out.append({"id": a["id"], "name": a.get("name"), "type": a.get("type")})
    return out


def _category_path(p, cat_id: str) -> str:
    """Slash path of a category: its `path` field when the server gives one, else walked up via rel=up links."""
    parts, cur, seen = [], cat_id, set()
    while cur and cur not in seen:
        seen.add(cur)
        c = _get_opt(p, f"/categories/{cur}") or {}
        if not c:
            break
        name, path = c.get("name"), str(c.get("path") or "").strip("/")
        if path and not parts:
            return path if path.split("/")[-1] == name else f"{path}/{name}"
        parts.append(name)
        up = next((_attrs(link).get("id") for link in _links(c) if link.get("rel") == "up"), None)
        cur = up or c.get("parent-id") or c.get("parentId")
    return "/".join(reversed([x for x in parts if x]))


def _ensure_category(p, path: str) -> str:
    """Creates (inside the managed root only) and returns the category id for 'Root/Sub/...'.
    Walks from the root categories (GET /categories?categoryType=WorkflowCategory&isRoot=true), then each
    category's children (GET /categories/{id}, relations.link rel=down)."""
    names = [x.strip() for x in path.split("/") if x.strip()]
    if not names:
        raise OrchestratorRefused("The workflow category must be a path like 'MCP-Managed/Team'.")
    children = _category_links(_get(p, "/categories", {"categoryType": "WorkflowCategory", "isRoot": "true"}))
    parent: Optional[str] = None
    for name in names:
        hit = next((c for c in children if c["name"] == name), None) or next((c for c in children if str(c["name"]).lower() == name.lower()), None)
        if hit:
            parent = hit["id"]
        else:
            body = {"name": name, "type": "WorkflowCategory", "description": "Managed by the VCF Enterprise MCP"}
            resp = p.request("POST", f"{API}/categories/{parent}" if parent else f"{API}/categories", json_body=body)
            if not resp.is_success:
                raise OrchestratorRefused(f"Orchestrator returned HTTP {resp.status_code} creating the category '{name}': {_msg(_json(resp)) or 'no details'}")
            parent = _created_id(resp)
            if not parent:
                raise OrchestratorRefused(f"Created the category '{name}' but Orchestrator returned no id.")
        children = _category_links(_get(p, f"/categories/{parent}"), "down")
    return parent or ""


def _check_writable(p):
    """Refuse before planning a change the server will reject: a read-only account (Viewer wins over
    Workflow Designer for non-admins, Broadcom KB 438403) or an account with no authoring role.
    GET /users lists no roles on some servers (role / admin-rights / member-groups only): then the server decides."""
    try:
        me = _get(p, "/users") or {}
    except Exception:
        return
    roles = me.get("roles")
    if roles is None or me.get("admin-rights"):
        return
    if "Administrator" in roles:
        return
    if "Viewer" in roles or not any(r in roles for r in ("Workflow Designer", "Developer")):
        raise OrchestratorRefused(f"The MCP's Orchestrator account has roles {roles}: it is READ-ONLY, so this change would fail. "
                                  "With Workflow Designer and Viewer together the most restrictive role wins (Broadcom KB 438403). "
                                  "Ask an Orchestrator admin to remove the Viewer role from the service account's groups, then retry.")


def _check_managed_path(cfg, path: str):
    root = cfg["managed_category"].strip("/")
    if not (path == root or path.startswith(root + "/")):
        raise OrchestratorRefused(f"The MCP only creates or edits workflows under '{root}/'. '{path}' is outside it. Put the workflow in "
                                  f"'{root}/<team>' or ask an admin to change vcf.orchestrator_managed_category.")


def _check_module(cfg, module: str):
    pre = cfg["module_prefix"].rstrip(".")
    if not (module == pre or module.startswith(pre + ".")):
        raise OrchestratorRefused(f"The MCP only creates or edits actions in modules starting with '{pre}.' (e.g. {pre}.storage). "
                                  f"'{module}' is outside it.")


# ---- authoring: actions ---------------------------------------------------------------------------------

def _sha(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest()


def _diff(old: str, new: str) -> Dict[str, Any]:
    import difflib
    lines = list(difflib.unified_diff(old.splitlines(), new.splitlines(), "current", "proposed", lineterm="", n=1))
    return {"changed_lines": sum(1 for x in lines if x[:1] in "+-" and not x.startswith(("+++", "---"))), "preview": lines[:40]}


def _find_action(p, module: str, name: str) -> Optional[Dict[str, Any]]:
    q = urllib.parse.quote
    return _get_opt(p, f"/actions/{q(module, safe='')}/{q(name, safe='')}")


def _conflict_problem(kind: str, label: str, current: Optional[str], base: Optional[str]) -> Optional[str]:
    if not current or base == current:
        return None
    if not base:
        return (f"'{label}' already exists: this is an UPDATE. Dry-run again with base_changeset_sha=\"{current}\" (the version you "
                "are changing) and pass the same value when executing, so a concurrent edit is never overwritten.")
    return (f"The {kind} changed since base_changeset_sha {base[:12]} (current {current[:12]}): someone edited it. "
            "Review the current version (vcf_orch_get) and dry-run again with the current changeset.")


def plan_action(platform: Any, module: str, name: str, script: str, inputs=None, return_type: Optional[str] = None,
                runtime: str = "javascript", description: str = "", base_changeset_sha: Optional[str] = None,
                version: Optional[str] = None, bump: Optional[str] = None) -> Dict[str, Any]:
    p = _prov(platform)
    _check_writable(p)
    cfg = _cfg(platform)
    _check_module(cfg, module)
    if bump and bump not in ("patch", "minor", "major"):
        raise ValueError("bump must be patch, minor or major.")
    lint = validate_action(platform, script, runtime)
    existing = _find_action(p, module, name)
    sha = _latest_commit_id(p, "actions", existing["id"]) if existing and existing.get("id") else None
    target = version or (bump_version(existing.get("version"), bump or "patch") if existing else "1.0.0")
    problems = []
    conflict = _conflict_problem("action", f"{module}/{name}", sha, base_changeset_sha) if existing else None
    if conflict:
        problems.append(conflict)
    return {"operation": "update" if existing else "create", "action": f"{module}/{name}", "action_id": existing.get("id") if existing else None,
            "runtime": runtime, "inputs": inputs if inputs is not None else (_action_inputs(existing) if existing else []),
            "return_type": return_type or (_action_return_type(existing) if existing else None) or "string", "script_check": lint,
            "script_sha256": hashlib.sha256(script.encode()).hexdigest(), "current_version": existing.get("version") if existing else None,
            "version": target, "current_changeset_sha": sha, "problems": problems,
            "diff": _diff(existing.get("script", ""), script) if existing else None, "allowed": lint["ok"] and not problems}


def save_action(platform: Any, module: str, name: str, script: str, inputs=None, return_type: Optional[str] = None,
                runtime: str = "javascript", description: str = "", base_changeset_sha: Optional[str] = None,
                version: Optional[str] = None, bump: Optional[str] = None) -> Dict[str, Any]:
    plan = plan_action(platform, module, name, script, inputs, return_type, runtime, description, base_changeset_sha, version, bump)
    if plan["problems"]:
        return {"saved": False, "conflict": True, "reason": plan["problems"][0]}
    if not plan["allowed"]:
        return {"saved": False, "reason": "The script failed the checks.", "script_check": plan["script_check"]}
    p = _prov(platform)
    existing = _find_action(p, module, name) if plan["operation"] == "update" else None
    body: Dict[str, Any] = {"module": module, "name": name, "version": plan["version"], "script": script,
                            "description": description or (existing or {}).get("description", ""),
                            "input-parameters": [{"name": i["name"], "type": i.get("type", "string"), "description": i.get("description", "")}
                                                 for i in plan["inputs"]],
                            "output-type": plan["return_type"]}
    if runtime != "javascript":
        body["runtime"] = runtime
    elif existing and existing.get("runtime"):
        body["runtime"] = existing["runtime"]
    warnings = list(plan["script_check"]["warnings"])
    if plan["operation"] == "update":
        aid = plan["action_id"]
        headers = {"X-VRO-Changeset-Sha": base_changeset_sha} if base_changeset_sha else None
        resp = p.request("PUT", f"{API}/actions/{aid}", json_body={**body, "id": aid}, headers=headers)
        if resp.status_code == 409:
            return {"saved": False, "conflict": True, "reason": "Orchestrator rejected the update: someone changed the action since your dry run."}
        if not resp.is_success:
            raise OrchestratorRefused(f"Orchestrator returned HTTP {resp.status_code} for PUT /actions/{aid}: {_msg(_json(resp)) or 'no details'}")
        update_errors = (_json(resp) or {}).get("errors") or []
        if update_errors:
            warnings.append({"rule": "update_references", "message": f"Orchestrator reported {len(update_errors)} problem(s) updating references: "
                             + "; ".join(str(e.get("message")) for e in update_errors[:3])})
    else:
        resp = p.request("POST", f"{API}/actions", params={"uniqueName": "true"}, json_body=body)
        if not resp.is_success:
            raise OrchestratorRefused(f"Orchestrator returned HTTP {resp.status_code} for POST /actions: {_msg(_json(resp)) or 'no details'}")
        aid = _created_id(resp)
        if not aid:
            aid = (_find_action(p, module, name) or {}).get("id")
    sha = _latest_commit_id(p, "actions", aid) if aid else None
    if aid:
        _tracker(platform).record("action", aid, f"{module}/{name}", plan["version"], changeset_sha=sha)
    return {"saved": True, "operation": plan["operation"], "action_id": aid, "fqn": f"{module}/{name}", "version": plan["version"],
            "changeset_sha": sha, "warnings": warnings}


# ---- authoring: workflows -------------------------------------------------------------------------------

def _wf_version(spec: Dict[str, Any], existing_version: Optional[str]) -> str:
    if spec.get("version"):
        return str(spec["version"])
    return bump_version(existing_version, spec.get("bump") or "patch") if existing_version is not None else "1.0.0"


def _find_workflow(platform, p, cfg, name: str, category: str) -> Optional[Dict[str, Any]]:
    matches = [w for w in list_items(platform, "workflows", name, limit=MAX_LIMIT)["items"] if w.get("name") == name]
    if not matches:
        return None
    scored = []
    for w in matches:
        path = _category_path(p, w["categoryId"]) if w.get("categoryId") else str(w.get("categoryName") or "")
        scored.append((0 if path == category else 1, w, path))
    scored.sort(key=lambda t: t[0])
    w, path = scored[0][1], scored[0][2]
    if path:
        _check_managed_path(cfg, path)
    return w


def plan_workflow(platform: Any, spec: Dict[str, Any], category: str, base_changeset_sha: Optional[str] = None) -> Dict[str, Any]:
    p = _prov(platform)
    _check_writable(p)
    cfg = _cfg(platform)
    category = category.strip("/")
    _check_managed_path(cfg, category)
    existing = _find_workflow(platform, p, cfg, spec.get("name"), category) if spec.get("name") else None
    sha, old_items, current_version = None, [], None
    if existing:
        sha = _latest_commit_id(p, "workflows", existing["id"])
        current_version = (_get_opt(p, f"/workflows/{existing['id']}") or {}).get("version")
        old_items = [i.get("display-name") for i in (_get_opt(p, f"/workflows/{existing['id']}/content") or {}).get("workflow-item", [])]
    version = _wf_version(spec, current_version if existing else None)
    spec = {**spec, "version": version}
    check = validate_workflow(platform, spec, existing["id"] if existing else None)
    problems = []
    conflict = _conflict_problem("workflow", spec.get("name"), sha, base_changeset_sha) if existing else None
    if conflict:
        problems.append(conflict)
    return {"operation": "update" if existing else "create", "workflow": spec.get("name"), "category": category,
            "workflow_id": existing.get("id") if existing else None, "current_changeset_sha": sha, "current_version": current_version,
            "version": version, "steps": [s.get("name") or s.get("id") for s in spec.get("steps") or []], "current_steps": old_items or None,
            "validation": check, "problems": problems, "allowed": check["valid"] and not problems, "spec_sha256": _sha(spec)}


def save_workflow(platform: Any, spec: Dict[str, Any], category: str, base_changeset_sha: Optional[str] = None) -> Dict[str, Any]:
    plan = plan_workflow(platform, spec, category, base_changeset_sha)
    if plan["problems"]:
        return {"saved": False, "conflict": True, "reason": plan["problems"][0]}
    if not plan["allowed"]:
        return {"saved": False, "reason": "The workflow did not validate.", "validation": plan["validation"]}
    p = _prov(platform)
    category = category.strip("/")
    spec = {**spec, "version": plan["version"]}
    schema, _ = compile_spec(spec)
    if plan["operation"] == "create":
        cat_id = _ensure_category(p, category)
        resp = p.request("POST", f"{API}/workflows", params={"uniqueName": "true"},
                         json_body={"name": spec["name"], "description": spec.get("description", ""), "category-id": cat_id})
        if not resp.is_success:
            return {"saved": False, "reason": f"Orchestrator did not create the workflow: HTTP {resp.status_code} {_msg(_json(resp)) or ''}".strip()}
        wid = _created_id(resp)
        if not wid:
            return {"saved": False, "reason": "Orchestrator created the workflow but returned no id."}
        headers = None
    else:
        wid = plan["workflow_id"]
        headers = {"X-VRO-Changeset-Sha": base_changeset_sha} if base_changeset_sha else None
    resp = _put_schema(p, "PUT", f"/workflows/{wid}/content", schema, wid, headers)
    if resp.status_code == 409:
        return {"saved": False, "conflict": True, "reason": "Orchestrator rejected the update: someone changed the workflow since your dry run."}
    if not resp.is_success:
        return {"saved": False, "workflow_id": wid, "reason": f"Orchestrator returned HTTP {resp.status_code} when saving the workflow content: "
                                                              f"{_msg(_json(resp)) or 'no details'}"}
    post = _get_opt(p, f"/workflows/{wid}/validate") or {}
    errs = [m for m in post.get("messages", []) if str(m.get("severity", "")).lower() in ("error", "fatal")]
    commit_resp = p.request("POST", f"{API}/workflows/{wid}/versions",
                            json_body={"message": f"MCP {plan['operation']}: {spec['name']} (spec {plan['spec_sha256'][:12]})"})
    commit = (_json(commit_resp) or {}) if commit_resp.is_success else {}
    sha = _commit_id(commit) or _latest_commit_id(p, "workflows", wid)
    _tracker(platform).record("workflow", wid, spec["name"], plan["version"], folder=category, changeset_sha=sha)
    return {"saved": True, "operation": plan["operation"], "workflow_id": wid, "category": category, "version": plan["version"],
            "changeset_sha": sha, "post_save_validation_errors": errs, "warnings": plan["validation"]["warnings"]}


def rollback(platform: Any, kind: str, item_id: str, changeset_sha: str) -> Dict[str, Any]:
    p = _prov(platform)
    if kind not in ("workflow", "action"):
        raise ValueError("kind must be workflow or action")
    cfg = _cfg(platform)
    q = urllib.parse.quote
    if kind == "action":
        cur = _get_opt(p, f"/actions/{q(item_id, safe='')}") or {}
        if not cur:
            raise OrchestratorRefused(f"Action {item_id} not found.")
        _check_module(cfg, cur.get("module", ""))
        old = _get_opt(p, f"/actions/{q(item_id, safe='')}/versions/{q(changeset_sha, safe='')}")
        if not old:
            raise OrchestratorRefused(f"Changeset {changeset_sha} not found for action {item_id} (see vcf_orch_get kind=action).")
        # Read the old version and write it back with PUT (a normal save, so Orchestrator records the new version).
        # POST /actions/{id}/versions is "revertActionToChangeset" in the spec, but its body is unproven, so it is not called.
        body = {"id": item_id, "module": cur["module"], "name": cur["name"], "version": bump_version(cur.get("version")),
                "script": old.get("script", ""), "description": old.get("description", cur.get("description", "")),
                "input-parameters": _action_inputs(old) if (old.get("input-parameters") or old.get("inputParameters")) else _action_inputs(cur),
                "output-type": _action_return_type(old) or _action_return_type(cur) or "string"}
        _send(p, "PUT", f"/actions/{item_id}", body)
        sha = _latest_commit_id(p, "actions", item_id)
        _tracker(platform).record("action", item_id, f"{cur['module']}/{cur['name']}", body["version"], changeset_sha=sha)
        return {"rolled_back": True, "kind": kind, "id": item_id, "to_changeset": changeset_sha, "new_changeset_sha": sha}
    wf = _get_opt(p, f"/workflows/{item_id}") or {}
    path = _category_path(p, wf.get("category-id") or wf.get("categoryId") or "")
    _check_managed_path(cfg, path or wf.get("categoryName", ""))
    # GET /workflows/{id}/versions/{sha} is a WsWorkflowChangeSet: its workflowSchema is the content to write back.
    old = _get_opt(p, f"/workflows/{item_id}/versions/{q(changeset_sha, safe='')}")
    schema = (old or {}).get("workflowSchema")
    if not schema:
        raise OrchestratorRefused(f"Changeset {changeset_sha} not found for workflow {item_id} (see vcf_orch_get kind=workflow).")
    resp = p.request("PUT", f"{API}/workflows/{item_id}/content", json_body=schema, headers={"Content-Type": "application/json"})
    if not resp.is_success:
        raise OrchestratorRefused(f"Orchestrator returned HTTP {resp.status_code} writing the old content back: {_msg(_json(resp)) or 'no details'}")
    commit = _send(p, "POST", f"/workflows/{item_id}/versions", {"message": f"MCP rollback to {changeset_sha[:12]}"}) or {}
    sha = _commit_id(commit) or _latest_commit_id(p, "workflows", item_id)
    _tracker(platform).record("workflow", item_id, wf.get("name") or item_id, wf.get("version"), folder=path or None, changeset_sha=sha)
    return {"rolled_back": True, "kind": kind, "id": item_id, "to_changeset": changeset_sha, "new_changeset_sha": sha}


# ---- runs ------------------------------------------------------------------------------------------

def _run_allowed(platform, p, wid) -> Dict[str, Any]:
    cfg = _cfg(platform)
    wf = _get_opt(p, f"/workflows/{wid}") or {}
    if not wf:
        raise OrchestratorRefused(f"Workflow {wid} not found. Find it with vcf_orch_list kind=workflows name=...")
    name = wf.get("name")
    path = _category_path(p, wf.get("category-id") or wf.get("categoryId") or "") or wf.get("categoryName", "")
    if name in cfg["blocked"]:
        raise OrchestratorRefused(f"'{name}' is on the blocked list (vcf.orchestrator_blocked_workflows): run it in Orchestrator directly.")
    root = cfg["managed_category"].strip("/")
    allowed = path == root or path.startswith(root + "/") or any(fnmatch.fnmatch(path, pat) or fnmatch.fnmatch(path + "/", pat)
                                                                  for pat in cfg["run_allowlist"])
    if not allowed:
        raise OrchestratorRefused(f"'{name}' is in category '{path}', which is not on the MCP run allowlist ({', '.join([root + '/*'] + cfg['run_allowlist'])}). "
                                  "Ask an admin to add it to vcf.orchestrator_run_allowlist.")
    return {"name": name, "category": path}


def _declared_inputs(p, workflow_id: str) -> List[Dict[str, Any]]:
    content = _get(p, f"/workflows/{workflow_id}/content") or {}
    declared = (content.get("input") or {}).get("param")
    if declared is None:
        wf = _get(p, f"/workflows/{workflow_id}") or {}
        declared = wf.get("inputParameters") or wf.get("input-parameters") or []
    return list(declared)


def plan_run(platform: Any, workflow_id: str, inputs: Dict[str, Any], secret_inputs: Dict[str, str]) -> Dict[str, Any]:
    p = _prov(platform)
    _check_writable(p)
    info = _run_allowed(platform, p, workflow_id)
    declared = {x["name"]: x for x in _declared_inputs(p, workflow_id)}
    problems = []
    for n in list(inputs) + list(secret_inputs):
        if n not in declared:
            problems.append(f"unknown input '{n}' (inputs: {', '.join(declared) or 'none'})")
    for n, d in declared.items():
        is_secret = str(d.get("type", "")).lower() == "securestring"
        if is_secret and n in inputs:
            problems.append(f"'{n}' is a SecureString: pass it in secret_inputs as a credential reference, never as plain text")
        if not is_secret and n in secret_inputs:
            problems.append(f"'{n}' is not a SecureString; pass it in inputs")
        if n not in inputs and n not in secret_inputs and not d.get("optional"):
            problems.append(f"missing input '{n}' ({d.get('type')})")
        if n in inputs and not is_secret:
            try:
                wire.to_wire(d.get("type"), inputs[n])
            except wire.WireError as exc:
                problems.append(f"input '{n}': {exc}")
    for n, ref in secret_inputs.items():
        if not isinstance(ref, str) or "://" not in ref:
            problems.append(f"secret_inputs['{n}'] must be a credential reference like local://env-prod/name, not a value")
    return {"workflow": info["name"], "category": info["category"], "workflow_id": workflow_id, "inputs": inputs,
            "secret_inputs": {k: v for k, v in secret_inputs.items()}, "problems": problems, "allowed": not problems,
            "declared_inputs": [{"name": n, "type": d.get("type")} for n, d in declared.items()]}


def _secret_param(platform, name: str, ref: str) -> Dict[str, Any]:
    if not platform.resolve_secret:
        raise OrchestratorUnavailable("No secret store is configured on the MCP server.")
    return {"name": name, "type": "SecureString", "scope": "local", "value": wire.to_wire("SecureString", platform.resolve_secret(ref))}


def run_workflow(platform: Any, workflow_id: str, inputs: Dict[str, Any], secret_inputs: Dict[str, str], wait_seconds: float = 20.0,
                 include_logs: bool = False) -> Dict[str, Any]:
    plan = plan_run(platform, workflow_id, inputs, secret_inputs)
    if not plan["allowed"]:
        return {"started": False, "problems": plan["problems"], "declared_inputs": plan["declared_inputs"]}
    p = _prov(platform)
    defs = [{"name": d["name"], "type": d["type"]} for d in plan["declared_inputs"]]
    params = wire.build_parameters(defs, inputs)
    for n, ref in secret_inputs.items():
        params.append(_secret_param(platform, n, ref))
    resp = p.request("POST", f"{API}/workflows/{workflow_id}/executions", json_body={"parameters": params})
    params = None  # drop secret values as soon as possible
    data = _json(resp)
    if not resp.is_success:
        raise OrchestratorRefused(f"Orchestrator returned HTTP {resp.status_code} starting the workflow: {_msg(data) or 'no details'}")
    eid = _created_id(resp, data)
    if not eid:
        raise OrchestratorRefused(f"The workflow started but Orchestrator returned no execution id (HTTP {resp.status_code}).")
    return _wait(platform, workflow_id, eid, wait_seconds, data, include_logs)


def _wait(platform, workflow_id, eid, wait_seconds, started=None, include_logs=False):
    p = _prov(platform)
    deadline, delay, ex, timed_out = time.time() + wait_seconds, 1.0, {}, True
    while True:
        ex = _execution_view(p, workflow_id, eid)
        if ex.get("state") in TERMINAL_STATES or ex.get("state") in STOP_WAITING_STATES:
            timed_out = False
            break
        remaining = deadline - time.time()
        if remaining <= 0:
            break
        time.sleep(min(delay, remaining))
        delay = min(delay * 1.5, 5.0)
    out = {"started": True, **ex}
    if timed_out:
        out["note"] = "Still running: check later with vcf_orch_get kind=execution."
    elif ex.get("state") in STOP_WAITING_STATES:
        out["note"] = f"The run is '{ex.get('state')}': it needs user input (vcf_orch_answer) or a signal."
    if include_logs or ex.get("state") == "failed":
        out["logs"] = _exec_logs(p, workflow_id, eid)
    return out


def answer(platform: Any, workflow_id: str, execution_id: str, inputs: Dict[str, Any], cancel: bool = False) -> Dict[str, Any]:
    p = _prov(platform)
    _run_allowed(platform, p, workflow_id)
    if cancel:
        p.request("DELETE", f"{API}/workflows/{workflow_id}/executions/{execution_id}/interaction")
        return {"cancelled": True, **get_execution(platform, workflow_id, execution_id)}
    inter = _get(p, f"/workflows/{workflow_id}/executions/{execution_id}/interaction") or {}
    defs = [{"name": x["name"], "type": x.get("type", "string")} for x in inter.get("input-parameters", [])]
    missing = [d["name"] for d in defs if d["name"] not in inputs]
    if missing:
        return {"answered": False, "problems": [f"missing answer for '{n}'" for n in missing], "expected": inter.get("input-parameters")}
    _send(p, "POST", f"/workflows/{workflow_id}/executions/{execution_id}/interaction",
          {"parameters": wire.build_parameters(defs, inputs, strict=False)})
    return {"answered": True, **_wait(platform, workflow_id, execution_id, 15.0)}


def _run_action_by_ref(p, a: Dict[str, Any], inputs: Dict[str, Any]) -> Dict[str, Any]:
    """POST /actions/{module}/{name}/executions answers the result synchronously (WsActionExecutionResult)."""
    defs = _action_inputs(a)
    known = {d["name"] for d in defs}
    unknown = [n for n in inputs if n not in known]
    if unknown:
        return {"started": False, "problems": [f"unknown input '{n}' (inputs: {', '.join(sorted(known)) or 'none'})" for n in unknown]}
    q = urllib.parse.quote
    resp = p.request("POST", f"{API}/actions/{q(a['module'], safe='')}/{q(a['name'], safe='')}/executions",
                     json_body={"parameters": wire.build_parameters(defs, inputs)}, timeout_seconds=120.0)
    res = _json(resp) or {}
    if not resp.is_success:
        raise OrchestratorRefused(f"Orchestrator returned HTTP {resp.status_code} running the action: {_msg(res) or 'no details'}")
    exec_id = res.get("execution-id") or res.get("executionId")
    out: Dict[str, Any] = {"started": True, "action": f"{a.get('module')}/{a.get('name')}", "state": res.get("state"),
                           "result": None if res.get("value") is None else wire.from_wire(res["value"]), "result_type": res.get("type"),
                           "execution_id": exec_id}
    if res.get("errorMessage"):
        out["error"] = res["errorMessage"]
        if res.get("errorLineNumber") is not None:
            out["error_line"] = res["errorLineNumber"]
    logs: List[Dict[str, Any]] = []
    if exec_id:
        try:
            logs = _simplify_logs(_get(p, f"/actions/{urllib.parse.quote(str(exec_id), safe='')}/logs"), 200)
        except Exception:
            pass
    out["logs"] = logs
    return out


def run_action(platform: Any, action_id: str, inputs: Dict[str, Any]) -> Dict[str, Any]:
    cfg, p = _cfg(platform), _prov(platform)
    a = _resolve_action(p, action_id)
    _check_module(cfg, a.get("module", ""))
    return _run_action_by_ref(p, a, inputs)


def plan_try_script(platform: Any, script: str, inputs: Optional[Dict[str, Any]] = None, input_types: Optional[Dict[str, str]] = None,
                    return_type: str = "Any") -> Dict[str, Any]:
    p = _prov(platform)
    _check_writable(p)
    cfg = _cfg(platform)
    module = cfg["module_prefix"].rstrip(".") + ".scratch"
    _check_module(cfg, module)
    lint = validate_action(platform, script, "javascript")
    defs = _script_defs(inputs or {}, input_types or {})
    problems = []
    for d in defs:
        try:
            wire.to_wire(d["type"], (inputs or {})[d["name"]])
        except wire.WireError as exc:
            problems.append(f"input '{d['name']}': {exc}")
    return {"module": module, "inputs": [{"name": d["name"], "type": d["type"]} for d in defs], "return_type": return_type,
            "script_check": lint, "script_sha256": hashlib.sha256(script.encode()).hexdigest(), "problems": problems,
            "note": f"A temporary action in {module} is created, run with these inputs and deleted again (even if the run fails).",
            "allowed": lint["ok"] and not problems}


def _script_defs(inputs: Dict[str, Any], types: Dict[str, str]) -> List[Dict[str, str]]:
    return [{"name": n, "type": types.get(n) or wire.guess_type(v), "description": ""} for n, v in inputs.items()]


def try_script(platform: Any, script: str, inputs: Optional[Dict[str, Any]] = None, input_types: Optional[Dict[str, str]] = None,
               return_type: str = "Any") -> Dict[str, Any]:
    """Runs a script snippet as a temporary action in <prefix>.scratch and always deletes it again."""
    plan = plan_try_script(platform, script, inputs, input_types, return_type)
    if not plan["allowed"]:
        return {"ran": False, "problems": plan["problems"], "script_check": plan["script_check"]}
    p, inputs = _prov(platform), inputs or {}
    module = plan["module"]
    name = f"mcp_{int(time.time()):x}_{secrets.token_hex(3)}"
    body = {"module": module, "name": name, "version": "1.0.0", "script": script, "description": "Temporary action (vcf_orch_try_script)",
            "input-parameters": _script_defs(inputs, input_types or {}), "output-type": return_type}
    resp = p.request("POST", f"{API}/actions", params={"uniqueName": "true"}, json_body=body)
    if not resp.is_success:
        raise OrchestratorRefused(f"Orchestrator returned HTTP {resp.status_code} creating the temporary action: {_msg(_json(resp)) or 'no details'}")
    aid = _created_id(resp) or (_find_action(p, module, name) or {}).get("id")
    cleanup = "no temporary action was created"
    try:
        a = _resolve_action(p, f"{module}/{name}")
        res = _run_action_by_ref(p, a, inputs)
    finally:
        if aid:
            try:
                d = p.request("DELETE", f"{API}/actions/{aid}", params={"force": "true"})
                cleanup = "temporary action deleted" if d.is_success else f"DELETE failed (HTTP {d.status_code}): remove {module}/{name} by hand"
            except Exception as exc:  # never hide the run result because cleanup failed
                cleanup = f"DELETE failed ({type(exc).__name__}): remove {module}/{name} by hand"
    res["ran"] = res.get("started", True)
    res["cleanup"] = cleanup
    res["warnings"] = plan["script_check"]["warnings"]
    return res


# ---- integrations, configuration, environments, plug-ins ----------------------------------------------

# kind -> (official configuration workflow name, plug-in, non-secret inputs (MCP name -> workflow input), secret input name)
INTEGRATIONS = {
    "vcenter": ("Add a vCenter Server instance", "VC", {"host": "host", "port": "port", "username": "username", "ignore_certificate_warnings": "ignoreCertificateWarnings"}, "password"),
    "vcenter_update": ("Update a vCenter Server instance", "VC", {"host": "host", "username": "username"}, "password"),
    "rest_host": ("Add a REST host", "RESTPlugin", {"name": "name", "url": "url", "auth_type": "authentication", "username": "username", "accept_certificate": "acceptCertificate"}, "password"),
    "active_directory": ("Add an Active Directory server", "AD", {"host": "host", "port": "port", "base_dn": "baseDN", "username": "username", "use_ssl": "useSSL", "forest": "alias"}, "password"),
    "powershell_host": ("Add a PowerShell host", "PowerShell", {"name": "name", "host": "host", "port": "port", "transport": "transportProtocol", "auth": "authentication", "username": "username"}, "password"),
    "ssh_host": ("Add an SSH Host", "SSH", {"host": "hostname", "port": "port", "username": "username"}, "password"),
}


def plan_integration(platform: Any, kind: str, settings: Dict[str, Any], credential_ref: Optional[str]) -> Dict[str, Any]:
    _check_writable(_prov(platform))
    if kind not in INTEGRATIONS:
        raise ValueError(f"kind must be one of: {', '.join(INTEGRATIONS)}")
    wf_name, plugin, mapping, secret = INTEGRATIONS[kind]
    p = _prov(platform)
    plugins = {x.get("name") for x in _plugin_list(_get(p, "/plugins"))}
    problems = []
    if plugin not in plugins:
        problems.append(f"The {plugin} plug-in is not installed. Install it first (vcf_orch_install_plugin).")
    wf = next((w for w in list_items(platform, "workflows", wf_name, limit=MAX_LIMIT)["items"] if w.get("name") == wf_name), None)
    if not wf:
        problems.append(f"The official configuration workflow '{wf_name}' was not found in the library.")
    unknown = [k for k in settings if k not in mapping]
    if unknown:
        problems.append(f"Unknown settings {unknown}; for {kind} use: {', '.join(mapping)}")
    if any(k in settings for k in ("password", "secret", "token")):
        problems.append("Do not pass passwords in settings: give credential_ref (a reference such as local://env-prod/name).")
    if not credential_ref or "://" not in str(credential_ref):
        problems.append("credential_ref is required: a secret reference stored with 'vcf-mcp credentials add' or vcf_setup, never the password itself.")
    inputs = {}
    if wf:
        declared = {x["name"]: x for x in _declared_inputs(p, wf["id"])}
        inputs = {mapping[k]: v for k, v in settings.items() if k in mapping and mapping[k] in declared}
        req = [n for n, d in declared.items() if n not in inputs and n != secret and not d.get("optional")]
        if req:
            problems.append(f"'{wf_name}' also needs: {', '.join(req)} (settings names: "
                            f"{', '.join(k for k, v in mapping.items() if v in req) or req})")
    # Plan fields are name/value pairs so the output redactor (which masks keys like *auth*, *pass*) does not hide
    # harmless settings from the approver; the secret itself only ever appears as a reference.
    return {"integration": kind, "configuration_workflow": wf_name, "workflow_id": (wf or {}).get("id"), "plugin": plugin,
            "workflow_inputs": [{"name": k, "value": v} for k, v in inputs.items()], "_inputs": inputs,
            "credential_input": {"name": secret, "uses_reference": credential_ref}, "problems": problems, "allowed": not problems,
            "verify_after": f"plug-in inventory {plugin} lists the new endpoint as usable"}


def add_integration(platform: Any, kind: str, settings: Dict[str, Any], credential_ref: str) -> Dict[str, Any]:
    plan = plan_integration(platform, kind, settings, credential_ref)
    if not plan["allowed"]:
        return {"added": False, "problems": plan["problems"]}
    # Configuration workflows live in the vendor library; this guarded call path is the one exception to the run allowlist.
    p = _prov(platform)
    defs = [{"name": x["name"], "type": x.get("type", "string")} for x in _declared_inputs(p, plan["workflow_id"])]
    params = wire.build_parameters(defs, plan["_inputs"], strict=False)
    sname, ref = plan["credential_input"]["name"], plan["credential_input"]["uses_reference"]
    params.append(_secret_param(platform, sname, ref))
    resp = p.request("POST", f"{API}/workflows/{plan['workflow_id']}/executions", json_body={"parameters": params})
    params = None
    data = _json(resp)
    if not resp.is_success:
        raise OrchestratorRefused(f"Orchestrator returned HTTP {resp.status_code} starting '{plan['configuration_workflow']}': {_msg(data) or 'no details'}")
    res = _wait(platform, plan["workflow_id"], _created_id(resp, data), 30.0, data)
    try:
        inv = _get(p, f"/catalog/{plan['plugin']}") or {}
        res["inventory_after"] = [_attrs(link) for link in _links(inv)]
    except Exception:
        pass
    res["integration"] = kind
    return res


def set_configuration(platform: Any, category: str, name: str, attributes: List[Dict[str, Any]]) -> Dict[str, Any]:
    _check_writable(_prov(platform))
    cfg, p = _cfg(platform), _prov(platform)
    _check_managed_path(cfg, category.strip("/"))
    attrs = []
    for a in attributes:
        if a.get("credential_ref"):
            attrs.append({"name": a["name"], "type": "SecureString", "value": wire.to_wire("SecureString", platform.resolve_secret(a["credential_ref"]))})
        else:
            if str(a.get("type", "")).lower() == "securestring":
                raise OrchestratorRefused(f"Attribute '{a['name']}' is a SecureString: give credential_ref instead of a value.")
            attrs.append({"name": a["name"], "type": a.get("type", "string"), "value": wire.to_wire(a.get("type", "string"), a.get("value"))})
    existing = next((c for c in list_items(platform, "configurations", name, limit=MAX_LIMIT)["items"] if c.get("name") == name), None)
    body = {"name": name, "category-id": _ensure_category(p, category.strip("/")), "attributes": attrs}
    if existing:
        _send(p, "PUT", f"/configurations/{existing['id']}", {**body, "id": existing["id"]})
        cid = existing["id"]
    else:
        resp = p.request("POST", f"{API}/configurations", json_body=body)
        if not resp.is_success:
            raise OrchestratorRefused(f"Orchestrator returned HTTP {resp.status_code} creating the configuration: {_msg(_json(resp)) or 'no details'}")
        cid = _created_id(resp)
    attrs = None
    return {"saved": True, "configuration_id": cid, "name": name, "category": category,
            "attributes": [{"name": a["name"], "from_credential_ref": bool(a.get("credential_ref"))} for a in attributes]}


def _env_dependencies(deps: List[str]) -> Dict[str, str]:
    """The API takes dependencies as {name: version}; accept 'name', 'name==1.2', 'name@1.2' or 'name>=1.2'."""
    out = {}
    for d in deps:
        m = re.match(r"^([^=<>@~!\s]+)\s*(?:==|@|>=|<=|~=|=)?\s*(.*)$", str(d).strip())
        out[m.group(1)] = (m.group(2) or "").strip() if m else ""
    return out


def create_environment(platform: Any, name: str, runtime: str, dependencies: List[str], repository_url: Optional[str] = None) -> Dict[str, Any]:
    _check_writable(_prov(platform))
    cfg, p = _cfg(platform), _prov(platform)
    rt = _get(p, "/server-configuration/polyglot-runtimes") or {}
    runtimes = [r.get("name") if isinstance(r, dict) else r for r in (rt.get("polyglotRuntimes") or rt.get("o11n-polyglot-runtime") or rt.get("runtimes") or [])]
    if runtime not in runtimes:
        raise OrchestratorRefused(f"Runtime '{runtime}' is not available on this server. Available: {', '.join(map(str, runtimes))}.")
    if repository_url and not any(repository_url.startswith(x) for x in cfg["repository_allowlist"]):
        raise OrchestratorRefused(f"Repository {repository_url} is not on vcf.orchestrator_repository_allowlist "
                                  f"({', '.join(cfg['repository_allowlist']) or 'empty'}).")
    if not name.startswith(cfg["module_prefix"].split(".")[-1] + "-") and not name.startswith("mcp-"):
        name = "mcp-" + name
    body: Dict[str, Any] = {"name": name, "runtime": runtime, "dependencies": _env_dependencies(dependencies)}
    if repository_url:
        body["repositories"] = {"default": repository_url}
    resp = p.request("POST", f"{API}/environments", json_body=body)
    res = _json(resp) or {}
    if not resp.is_success:
        raise OrchestratorRefused(f"Orchestrator returned HTTP {resp.status_code} creating the environment: {_msg(res) or 'no details'}")
    return {"created": True, "environment_id": _created_id(resp, res), "name": name, "runtime": runtime, "dependencies": dependencies,
            "status": res.get("status", "building")}


def _multipart(field: str, filename: str, data: bytes) -> Tuple[bytes, str]:
    boundary = "----vcfmcp" + secrets.token_hex(12)
    safe = re.sub(r'[\r\n"\\]', "_", filename)
    head = (f'--{boundary}\r\nContent-Disposition: form-data; name="{field}"; filename="{safe}"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n").encode()
    return head + data + f"\r\n--{boundary}--\r\n".encode(), f"multipart/form-data; boundary={boundary}"


def install_plugin(platform: Any, file_path: str, sha256: str) -> Dict[str, Any]:
    p = _prov(platform)
    real = os.path.realpath(file_path)
    allowed_dir = os.path.realpath(os.environ.get("VCF_MCP_PLUGIN_DIR", os.path.expanduser("~/.vcf-mcp/plugins")))
    if not real.startswith(allowed_dir + os.sep):
        raise OrchestratorRefused(f"Plug-in files must be placed in {allowed_dir} (VCF_MCP_PLUGIN_DIR) on the MCP server.")
    if not real.endswith((".vmoapp", ".dar")):
        raise OrchestratorRefused("Orchestrator plug-ins are .vmoapp (or .dar) files.")
    with open(real, "rb") as fh:
        data = fh.read()
    actual = hashlib.sha256(data).hexdigest()
    if actual.lower() != sha256.lower():
        raise OrchestratorRefused(f"SHA-256 mismatch: file is {actual}, expected {sha256}. Download the plug-in again from Broadcom.")
    body, content_type = _multipart("file", os.path.basename(real), data)
    resp = _raw_request(p, "POST", "/plugins/installations", body, content_type, timeout=300.0)
    inst = _json(resp) if resp.is_success else {}
    if not (inst or {}).get("id"):
        return {"installed": False, "reason": f"Upload failed (HTTP {resp.status_code})."}
    # The only field the confirmation takes is eulaAccepted; approving this plan is the human's acceptance of the EULA.
    done = _send(p, "PATCH", f"/plugins/installations/{inst['id']}", {"eulaAccepted": True}) or {}
    return {"installed": True, "installation_id": inst["id"], "plugins": [x.get("moduleName") or x.get("name") for x in inst.get("plugins", [])],
            "results": done.get("pluginInstallResults"), "sha256": actual}


# ---- packages ------------------------------------------------------------------------------------------

def export_dir() -> Path:
    return Path(os.environ.get("VCF_MCP_EXPORT_DIR") or (Path(os.environ.get("VCF_MCP_HOME") or (Path.home() / ".vcf-mcp")) / "exports")).expanduser()


def _safe_name(n: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", n).lstrip(".") or "package"


def _zip_elements(data: bytes) -> Dict[str, Any]:
    """Entry and (best effort) element names of a .package zip."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            entries = z.namelist()
            names = []
            for e in entries:
                if re.match(r"^elements/[^/]+/info$", e):
                    txt = z.read(e).decode("utf-8", "replace")
                    m = re.search(r"(?:^|\n)\s*(?:name|display-name)\s*[=:]\s*(.+)", txt) or re.search(r"<(?:display-)?name>(?:<!\[CDATA\[)?([^<\]]+)", txt)
                    if m:
                        names.append(m.group(1).strip())
            return {"entries": entries[:200], "entry_count": len(entries), "element_names": names[:200]}
    except zipfile.BadZipFile:
        return {"entries": [], "entry_count": 0, "element_names": []}


def export_package(platform: Any, package_name: str, include_version_history: bool = True, include_global_tags: bool = True) -> Dict[str, Any]:
    """Downloads a package as a .package file (read-only on Orchestrator). SecureString values are NEVER exported."""
    name = str(package_name or "").strip()
    if not name or "/" in name:
        raise ValueError("package_name must be an exact package name such as com.mcp.reports (list them with vcf_orch_list kind=packages).")
    p = _prov(platform)
    params = {"exportConfigurationAttributeValues": "true", "exportConfigSecureStringAttributeValues": "false",
              "exportVersionHistory": "true" if include_version_history else "false", "exportGlobalTags": "true" if include_global_tags else "false"}
    try:
        resp = p.request("GET", f"{API}/packages/{urllib.parse.quote(name, safe='')}", params=params,
                         headers={"Accept": "application/zip"}, timeout_seconds=300.0)
    except UpstreamResourceNotFoundException:
        raise OrchestratorRefused(f"Package '{name}' not found. Names are case-sensitive: list them with vcf_orch_list kind=packages.")
    if not resp.is_success:
        raise OrchestratorRefused(f"Export of '{name}' failed: HTTP {resp.status_code} {_msg(_json(resp)) or ''}".strip())
    data = resp.body
    if data[:2] != b"PK":
        raise OrchestratorRefused(f"Orchestrator did not return a zip for '{name}' ({len(data)} bytes, content-type {resp.headers.get('Content-Type', 'none')}).")
    folder = export_dir()
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    base = _safe_name(name) + "_" + time.strftime("%Y%m%d")
    n, path = 1, None
    while path is None:  # never overwrite: -2, -3, ...; O_EXCL makes the choice race-free
        candidate = folder / (f"{base}.package" if n == 1 else f"{base}-{n}.package")
        try:
            fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            n += 1
            continue
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        path = candidate
    return {"package": name, "path": str(path), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "secure_strings_included": False,
            **_zip_elements(data)}


def tracked_changes(platform: Any) -> Dict[str, Any]:
    items = _tracker(platform).list()
    return {"orchestrator": _cfg(platform)["url"], "count": len(items), "items": items,
            "note": "Workflows and actions saved through this MCP, newest last. vcf_orch_build_package puts them into a package."}


PACKAGE_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*(\.[A-Za-z0-9_-]+)+$")


def plan_build_package(platform: Any, package_name: str, workflows: Optional[List[str]] = None, actions: Optional[List[str]] = None,
                       use_tracked: bool = True, description: str = "") -> Dict[str, Any]:
    p = _prov(platform)
    _check_writable(p)
    cfg = _cfg(platform)
    pre = cfg["module_prefix"].rstrip(".")
    problems = []
    if not PACKAGE_NAME.match(package_name or ""):
        problems.append("package_name must look like com.mcp.reports (letters, digits, dots).")
    elif not (package_name == pre or package_name.startswith(pre + ".")):
        problems.append(f"The MCP only builds packages named '{pre}.<name>' (got '{package_name}').")
    items: List[Dict[str, str]] = []
    if use_tracked:
        for t in _tracker(platform).list():
            if t.get("kind") in ("workflow", "action"):
                items.append({"kind": t["kind"], "id": t["id"], "name": t.get("name", t["id"])})
    for wid in workflows or []:
        info = _run_allowed_managed(platform, p, wid)
        items.append({"kind": "workflow", "id": wid, "name": info})
    for ref in actions or []:
        a = _resolve_action(p, ref)
        _check_module(cfg, a.get("module", ""))
        items.append({"kind": "action", "id": a["id"], "name": f"{a['module']}/{a['name']}"})
    seen, unique = set(), []
    for i in items:
        if (i["kind"], i["id"]) not in seen:
            seen.add((i["kind"], i["id"]))
            unique.append(i)
    if not unique:
        problems.append("Nothing to package: no tracked changes and no workflows/actions listed. Save something through the MCP first.")
    return {"package": package_name, "items": unique, "description": description, "problems": problems, "allowed": not problems,
            "note": "The package file is exported to the MCP export folder; SecureString values are never included."}


def _run_allowed_managed(platform, p, wid) -> str:
    wf = _get_opt(p, f"/workflows/{wid}") or {}
    if not wf:
        raise OrchestratorRefused(f"Workflow {wid} not found.")
    path = _category_path(p, wf.get("category-id") or wf.get("categoryId") or "") or wf.get("categoryName", "")
    _check_managed_path(_cfg(platform), path)
    return wf.get("name") or wid


def build_package(platform: Any, package_name: str, workflows: Optional[List[str]] = None, actions: Optional[List[str]] = None,
                  use_tracked: bool = True, description: str = "") -> Dict[str, Any]:
    plan = plan_build_package(platform, package_name, workflows, actions, use_tracked, description)
    if not plan["allowed"]:
        return {"built": False, "problems": plan["problems"]}
    p = _prov(platform)
    q = urllib.parse.quote
    existing = any(_attrs(link).get("name") == package_name for link in _links(_get(p, "/packages") or {}))
    if not existing:
        _send(p, "PUT", f"/packages/{q(package_name, safe='')}", {"description": description})
    added, failed = [], []
    for it in plan["items"]:
        if it["kind"] == "workflow":
            path = f"/packages/{q(package_name, safe='')}/workflow/{q(it['id'], safe='')}"
        else:
            module, name = it["name"].rsplit("/", 1)
            path = f"/packages/{q(package_name, safe='')}/action/{q(module, safe='')}/{q(name, safe='')}"
        r = p.request("POST", API + path)
        (added if r.is_success else failed).append(it if r.is_success else {**it, "error": f"HTTP {r.status_code} {_msg(_json(r)) or ''}".strip()})
    if not added:
        raise OrchestratorRefused(f"Package {package_name} exists but no element could be added: {json.dumps(failed)[:600]}")
    exported = export_package(platform, package_name)
    _tracker(platform).forget([i["id"] for i in added])
    return {"built": True, "created": not existing, "package": package_name, "added": added, **({"failed": failed} if failed else {}),
            "file": exported["path"], "bytes": exported["bytes"], "sha256": exported["sha256"], "element_names": exported["element_names"]}
