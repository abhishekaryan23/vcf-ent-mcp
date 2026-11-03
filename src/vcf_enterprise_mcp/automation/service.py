# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
VCF Automation 9 (VM Apps organization): Assembler cloud templates and the embedded
Orchestrator, through the documented REST APIs:

- Assembler: GET/POST /blueprint/api/blueprints, POST /blueprint/api/blueprint-validation,
  GET /deployment/api/deployments, GET /iaas/api/{projects,images,flavors,fabric-networks}.
- Orchestrator: GET /vco/api/workflows, GET /vco/api/workflows/{id},
  POST /vco/api/workflows/{id}/executions, GET /vco/api/workflows/{id}/executions/{eid}.

Auth: the organization API token is exchanged for a bearer token (VCFAutomationTokenAuth).
Authoring new Orchestrator workflows/actions needs a package import (multipart), which this
module does not do: it runs and inspects existing workflows only.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from vcf_enterprise_mcp.adapter.providers.vcenter import VCenterProvider


class AutomationUnavailable(Exception):
    pass


def _prov(platform: Any) -> VCenterProvider:
    if not getattr(platform, "automation", None):
        raise AutomationUnavailable("VCF Automation is not configured (vcf.automation_url, vcf.automation_org and a credential for "
                                    "component 'vcf_automation', the organization API token).")
    url, auth = platform.automation
    return VCenterProvider(endpoint_url=url, transport=platform.transport, auth=auth)


def _get(p, path, params=None):
    return p.request("GET", path, params=params).json()


def _attrs(link: Dict[str, Any]) -> Dict[str, Any]:
    return {a.get("name"): a.get("value") for a in link.get("attributes") or []}


KINDS = ("projects", "templates", "deployments", "images", "flavors", "networks")


def inventory(platform: Any, kind: str, project_id: Optional[str] = None) -> Dict[str, Any]:
    p = _prov(platform)
    params = {"projects": project_id} if project_id else None
    if kind == "workflows":
        items = [_attrs(link) for link in (_get(p, "/vco/api/workflows") or {}).get("link", [])]
    else:
        path = {"projects": "/iaas/api/projects", "templates": "/blueprint/api/blueprints", "deployments": "/deployment/api/deployments",
                "images": "/iaas/api/images", "flavors": "/iaas/api/flavors", "networks": "/iaas/api/fabric-networks"}[kind]
        items = (_get(p, path, params if kind in ("templates", "deployments") else None) or {}).get("content", [])
    hint = {"images": "Use the 'name' as image: in a Cloud.vSphere.Machine.", "flavors": "Use the 'name' as flavor:.",
            "networks": "Select a network in a template with constraints: - tag: '<one of its tags>'.",
            "templates": "vcf_automation_get kind=template returns the YAML."}.get(kind, "")
    return {"kind": kind, "count": len(items), "items": items, **({"hint": hint} if hint else {})}


def get_template(platform: Any, template_id: str) -> Dict[str, Any]:
    return _get(_prov(platform), f"/blueprint/api/blueprints/{template_id}")


def get_workflow(platform: Any, workflow_id: str) -> Dict[str, Any]:
    wf = _get(_prov(platform), f"/vco/api/workflows/{workflow_id}")
    return {"id": wf.get("id"), "name": wf.get("name"), "description": wf.get("description"),
            "inputs": [{"name": i.get("name"), "type": i.get("type"), "required": "required" in str(i.get("description", ""))}
                       for i in wf.get("input-parameters") or []],
            "outputs": [{"name": o.get("name"), "type": o.get("type")} for o in wf.get("output-parameters") or []]}


def validate_template(platform: Any, project_id: str, content: str) -> Dict[str, Any]:
    r = _prov(platform).request("POST", "/blueprint/api/blueprint-validation", json_body={"projectId": project_id, "content": content}).json()
    msgs = r.get("validationMessages", [])
    return {"valid": bool(r.get("valid")), "errors": [m for m in msgs if m.get("type") == "ERROR"],
            "warnings": [m for m in msgs if m.get("type") != "ERROR"]}


def create_template(platform: Any, project_id: str, name: str, content: str, description: str = "") -> Dict[str, Any]:
    check = validate_template(platform, project_id, content)
    if not check["valid"]:
        return {"created": False, "reason": "The template does not validate; fix the errors and try again.", **check}
    r = _prov(platform).request("POST", "/blueprint/api/blueprints",
                                json_body={"projectId": project_id, "name": name, "description": description, "content": content}).json()
    return {"created": True, "template": r, "warnings": check["warnings"],
            "note": "Saved as a DRAFT cloud template; release a version in Assembler before it appears in the catalog."}


def _param(name: str, wf_type: str, value: Any) -> Dict[str, Any]:
    t = (wf_type or "string").lower()
    if t == "number":
        return {"name": name, "type": "number", "value": {"number": {"value": float(value)}}}
    if t == "boolean":
        return {"name": name, "type": "boolean", "value": {"boolean": {"value": bool(value)}}}
    return {"name": name, "type": wf_type or "string", "value": {"string": {"value": str(value)}}}


def check_workflow_inputs(platform: Any, workflow_id: str, inputs: Dict[str, Any]) -> Dict[str, Any]:
    wf = get_workflow(platform, workflow_id)
    declared = {i["name"]: i for i in wf["inputs"]}
    problems = [f"missing required input '{n}'" for n, i in declared.items() if i["required"] and inputs.get(n) in (None, "")]
    problems += [f"unknown input '{n}' (declared: {', '.join(declared)})" for n in inputs if n not in declared]
    for n, v in inputs.items():
        if n in declared and declared[n]["type"] == "number":
            try:
                float(v)
            except (TypeError, ValueError):
                problems.append(f"input '{n}' must be a number")
    return {"workflow": wf, "problems": problems}


def run_workflow(platform: Any, workflow_id: str, inputs: Dict[str, Any], wait_seconds: float = 20.0) -> Dict[str, Any]:
    chk = check_workflow_inputs(platform, workflow_id, inputs)
    if chk["problems"]:
        return {"started": False, "problems": chk["problems"], "workflow_inputs": chk["workflow"]["inputs"]}
    types = {i["name"]: i["type"] for i in chk["workflow"]["inputs"]}
    p = _prov(platform)
    started = p.request("POST", f"/vco/api/workflows/{workflow_id}/executions",
                        json_body={"parameters": [_param(n, types[n], v) for n, v in inputs.items()]}).json() or {}
    eid = started.get("id")
    deadline = time.time() + wait_seconds
    ex = {}
    while eid and time.time() < deadline:
        ex = get_execution(platform, workflow_id, eid)
        if ex["state"] not in ("running", "waiting", "waiting-signal"):
            break
        time.sleep(1.0)
    return {"started": True, "execution_id": eid, **(ex or {"state": started.get("state", "running")})}


def get_execution(platform: Any, workflow_id: str, execution_id: str) -> Dict[str, Any]:
    ex = _get(_prov(platform), f"/vco/api/workflows/{workflow_id}/executions/{execution_id}") or {}
    outputs = {}
    for o in ex.get("output-parameters") or []:
        val = o.get("value") or {}
        inner = next(iter(val.values()), {}) if isinstance(val, dict) and val else {}
        outputs[o.get("name")] = inner.get("value") if isinstance(inner, dict) else inner
    out = {"execution_id": ex.get("id", execution_id), "workflow": ex.get("name"), "state": ex.get("state"), "outputs": outputs,
           "started_at": ex.get("start-date"), "ended_at": ex.get("end-date")}
    if ex.get("content-exception"):
        out["error"] = ex["content-exception"]
    return out
