# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
vcf_find_tool: tells the model which tool (and skill) fits a task, with ready-to-use example
arguments. Meant for small or fast models that struggle to choose among many tools: one cheap
call, deterministic answer, only tools this user may call.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

from vcf_enterprise_mcp.auth.identity import Principal
from vcf_enterprise_mcp.policy.models import CapabilityRole, RiskClass
from vcf_enterprise_mcp.tools.base import BaseEnterpriseTool

# (tool, skill, trigger phrases/words, example arguments, one-line when-to-use)
INTENTS: List[tuple] = [
    ("vcf_diagnose", "vcf-oncall-troubleshoot", ["down", "broken", "not working", "outage", "why", "failing", "error", "cannot", "can't",
     "slow", "root cause", "incident", "unreachable", "login fail", "won't load", "won+load", "won+work", "not+loading"], {"symptom": "<what users report>"},
     "Something is down or failing and you do not know where: start here."),
    ("vcf_trace_application", "vcf-oncall-troubleshoot", ["app", "application", "service", "crm", "ledger", "payments", "website", "database",
     "sql", "oracle", "proxy", "web server", "ad forest", "domain controller", "availability group", "cluster", "website+down", "app+down", "application+down", "service+down", "portal+down", "website+slow"], {"application": "<app name>"},
     "ONE named application or service is affected: map its VMs, networks, firewall rules and problems."),
    ("vcf_list_networks", "vcf-oncall-troubleshoot", ["network", "networks", "vpc", "segment", "port group", "vlan", "nsx manager shared",
     "overlay", "subnet", "topology"], {"domain": "<optional workload domain>"}, "How networking is built: NSX vs VDS vs VPC, shared NSX managers."),
    ("vcf_list_failed_tasks", "vcf-oncall-troubleshoot", ["failed task", "sddc task", "workflow failed in sddc", "upgrade failed", "task error"], {},
     "Failed SDDC Manager tasks."),
    ("vcf_list_alerts", "vcf-oncall-troubleshoot", ["alert", "alarm", "alerts", "alarms"], {}, "Active VCF Operations alerts and NSX alarms."),
    ("vcf_automation_list", "vcf-automation-cloud-template", ["cloud template", "blueprint", "catalog", "deployment", "image mapping", "flavor",
     "assembler", "project"], {"kind": "templates"}, "Assembler: list projects/templates/deployments/images/flavors/networks."),
    ("vcf_automation_create_template", "vcf-automation-cloud-template", ["create template", "new template", "create blueprint", "cloud template for",
     "self-service template", "assembler template", "create+template", "new+template", "build+template", "write+template", "create+blueprint", "make+template"], {"project_id": "<id>", "name": "<name>", "content": "<YAML>", "dry_run": True},
     "Save a new Assembler cloud template (validate first)."),
    ("vcf_orch_list", "vcf-orchestrator-run-workflow", ["orchestrator", "workflow", "workflows", "vro", "action", "actions", "find workflow"], {"kind": "workflows", "name": "<part of name>"}, "Find Orchestrator workflows, actions, categories, configurations."),
    ("vcf_orch_run", "vcf-orchestrator-run-workflow", ["run workflow", "execute workflow", "start workflow", "use automation", "existing automation",
     "expand disk", "failover", "run the automation", "trigger workflow"], {"workflow_id": "<id>", "inputs": {"<name>": "<value>"}, "dry_run": True},
     "Run an existing Orchestrator workflow (dry run -> approval -> run)."),
    ("vcf_orch_answer", "vcf-orchestrator-run-workflow", ["waiting", "user interaction", "answer", "confirm run", "waiting for input"],
     {"workflow_id": "<id>", "execution_id": "<id>", "inputs": {}, "dry_run": True}, "Answer or cancel a run that waits for input."),
    ("vcf_orch_save_action", "vcf-orchestrator-author-action", ["create action", "write action", "new action", "script action", "javascript action",
     "python action", "powershell action", "update action", "write+action", "create+action", "new+action", "build+action", "edit+action", "update+action", "make+action"], {"module": "com.mcp.<area>", "name": "<actionName>", "script": "<code>", "inputs": [{"name": "x", "type": "string"}],
     "return_type": "string", "dry_run": True}, "Create or update an Orchestrator action (checked: plain ES5 for the Rhino engine)."),
    ("vcf_orch_save_workflow", "vcf-orchestrator-author-workflow", ["create workflow", "build workflow", "new workflow", "write workflow",
     "automate", "update workflow", "edit workflow", "create+workflow", "build+workflow", "new+workflow", "write+workflow", "edit+workflow", "update+workflow", "make+workflow", "change+workflow"], {"category": "MCP-Managed/<team>", "workflow": {"name": "<name>", "inputs": [], "outputs": [],
     "variables": [], "steps": [{"id": "s1", "type": "script", "script": "System.log('hi');"}]}, "dry_run": True},
     "Create or update an Orchestrator workflow from a step list."),
    ("vcf_orch_validate", "vcf-orchestrator-author-workflow", ["validate", "check script", "lint", "is this javascript supported", "rhino",
     "es6", "modern javascript"], {"script": "<code>"}, "Check a script or workflow spec without saving anything."),
    ("vcf_orch_rollback", "vcf-orchestrator-author-workflow", ["rollback", "roll back", "revert", "undo change", "previous version"],
     {"kind": "workflow", "id": "<id>", "changeset_sha": "<sha>", "dry_run": True}, "Revert an MCP-managed workflow or action to a previous version."),
    ("vcf_orch_add_integration", "vcf-orchestrator-integration", ["add vcenter", "add rest host", "add active directory", "add ad server",
     "add powershell host", "add ssh host", "integration", "connect orchestrator to", "plug-in endpoint", "unusable vcenter", "reconnect vcenter", "add+rest", "add+host", "connect+orchestrator", "add+vcenter", "add+directory", "register+endpoint"],
     {"kind": "rest_host", "settings": {"name": "<name>", "url": "https://..."}, "credential_ref": "local://env-prod/<ref>", "dry_run": True},
     "Add or repair an Orchestrator plug-in endpoint using Broadcom's configuration workflow; secrets only by reference."),
    ("vcf_orch_set_configuration", "vcf-orchestrator-integration", ["configuration element", "config element", "store setting"],
     {"category": "MCP-Managed/<team>", "name": "<name>", "attributes": [{"name": "url", "type": "string", "value": "..."}], "dry_run": True},
     "Create or update a configuration element (secrets by credential_ref)."),
    ("vcf_orch_create_environment", "vcf-orchestrator-author-action", ["python environment", "node environment", "powershell environment",
     "dependencies", "pip", "npm", "module for action", "python+environment", "create+environment", "node+environment", "powershell+environment", "environment+requests"], {"name": "<name>", "runtime": "<from vcf_orch_about runtimes>", "dependencies": ["requests"], "dry_run": True},
     "Create an action environment with dependencies."),
    ("vcf_orch_install_plugin", "vcf-orchestrator-plugin-install", ["install plugin", "install plug-in", "vmoapp", "new plugin", "install+plug-in", "install+plugin"],
     {"file_path": "<path in plug-in dir>", "sha256": "<from Broadcom>", "dry_run": True}, "Install an Orchestrator plug-in (admin, high impact)."),
    ("vcf_orch_list_executions", "vcf-orchestrator-run-workflow", ["execution history", "run history", "previous runs", "recent runs", "failed runs",
     "list executions", "past runs", "failed+runs", "workflow+runs", "workflow+history", "list+executions", "recent+executions"],
     {"workflow_id": "<id>", "state": "failed", "limit": 10}, "List recent runs (executions) of one Orchestrator workflow."),
    ("vcf_orch_export_package", "vcf-orchestrator-package", ["export package", "download package", "backup package", "orchestrator package", ".package",
     "export+package", "download+package", "backup+package", "back+package"], {"package_name": "<exact package name>"},
     "Download an Orchestrator package as a file (secrets never included)."),
    ("vcf_orch_build_package", "vcf-orchestrator-package", ["build package", "create package", "package our changes", "package+workflows", "package+changes",
     "build+package", "create+package", "package+saved", "make+package"], {"package_name": "com.mcp.<name>", "dry_run": True},
     "Put what the MCP saved into an Orchestrator package and export it."),
    ("vcf_orch_tracked_changes", "vcf-orchestrator-package", ["tracked changes", "what did you change", "what did you save", "what have you saved",
     "changes you made", "tracked+changes", "saved+workflows", "what+saved"], {}, "List the workflows and actions this MCP saved in Orchestrator."),
    ("vcf_orch_try_script", "vcf-orchestrator-author-action", ["try script", "test script", "run snippet", "try this snippet", "try+script", "test+script",
     "run+snippet", "try+snippet", "test+snippet", "try+javascript", "run+javascript", "test+javascript"], {"script": "return 1 + 1;", "inputs": {}, "dry_run": True},
     "Run a JavaScript snippet on Orchestrator in a temporary action (deleted afterwards)."),
    ("vcf_orch_about", "vcf-orchestrator-run-workflow", ["orchestrator version", "orchestrator health", "known issue", "plugins installed",
     "orchestrator roles", "what can orchestrator"], {}, "Orchestrator version, health, plug-ins, runtimes, role problems and known issues that apply."),
    ("vcf_get_plan", None, ["plan status", "approval status", "is it approved", "was it approved", "has the plan been approved", "plan+approved",
     "approved+plan", "plan+status", "approval+status", "plan+ready", "approve+link", "approval+link", "plan_id"], {"plan_id": "<plan_id from the dry run>"},
     "Check whether a dry-run plan has been approved by the person, whether it is ready to execute, and how to approve it."),
    ("vcf_list_vms", "vcf-viewer-inventory-summary", ["list vms", "virtual machines", "inventory", "how many vms"], {}, "List VMs across all vCenters."),
    ("vcf_list_domains", "vcf-viewer-inventory-summary", ["workload domain", "domains", "vcf domains"], {}, "List VCF workload domains."),
    ("vcf_setup", None, ["set up", "setup", "set-up", "onboard", "onboarding", "get started", "first time", "service account", "re-run setup",
     "set+up", "setup+vcf", "setup+mcp", "configure+mcp", "configure+vcf", "connect+vcf", "connect+vcenter", "connect+appliances",
     "connect+appliance", "add+appliance", "add+account", "change+account", "change+credentials", "re-run+setup"], {},
     "Guided setup: connect VCF appliances, collect passwords on a private page, verify access, switch off risky actions. Needs the MCP_ADMIN or VCF_PLATFORM_ADMIN role."),
    ("vcf_access_report", None, ["what can you do", "my access", "permissions", "capabilities"], {}, "What this MCP can do with your access."),
]

_WORD = re.compile(r"[a-z0-9\-]+")


def rank(task: str) -> List[Dict[str, Any]]:
    text = " " + " ".join(_WORD.findall(task.lower())) + " "
    words = set(text.split())
    scored = []
    for tool, skill, triggers, example, when in INTENTS:
        score = 0.0
        for t in triggers:
            if "+" in t:  # all words present, any order: verb + object intent
                if all(w in words for w in t.split("+")):
                    score += 4.0
            elif " " in t or "-" in t:
                if f" {t} " in text or t in text:
                    score += 3.0
            elif t in words:
                score += 1.0
        if score:
            scored.append((score, tool, skill, example, when))
    scored.sort(key=lambda x: -x[0])
    return [{"tool": t, "skill": s, "example_arguments": e, "use_when": w, "score": sc} for sc, t, s, e, w in scored]


class VCFFindToolTool(BaseEnterpriseTool):
    name = "vcf_find_tool"
    level = "L1_QUERY"
    risk_class = RiskClass.READ
    required_roles = list(CapabilityRole)
    required_capability = None

    async def run_live(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        task = str(arguments.get("task") or "").strip()
        if not task:
            return {"error": "Describe the task in plain words, e.g. {\"task\": \"the CRM app cannot reach its database\"}."}
        ranked = rank(task)[:3]
        verbs = {"rotate", "expand", "resize", "restart", "reset", "patch", "provision", "decommission", "migrate", "backup", "clone",
                 "create", "delete", "add", "remove", "enable", "disable", "configure", "update", "run", "execute", "renew", "join"}
        if not ranked and verbs & set(re.findall(r"[a-z]+", task.lower())):
            return {"best": "vcf_orch_list", "call_it_like_this": {"name": "vcf_orch_list", "arguments": {"kind": "workflows", "name": "<one key word, e.g. rotate>"}},
                    "skill": "vcf-orchestrator-run-workflow",
                    "why": "No dedicated tool does this, but an existing Orchestrator workflow may. Search by one key word, read its inputs with "
                           "vcf_orch_get, then run it with vcf_orch_run (dry run, approval, run).",
                    "alternatives": [{"tool": "vcf_orch_save_workflow", "use_when": "No workflow exists and the user wants one built."}]}
        if not ranked:
            return {"best": None, "advice": "No specific tool matched. For anything broken call vcf_diagnose; to see what you can do call vcf_access_report."}
        best = ranked[0]
        if best["tool"] == "vcf_setup":
            return {"best": "vcf_setup", "call_it_like_this": {"name": "vcf_setup", "arguments": {}}, "skill": None,
                    "why": best["use_when"],
                    "remember": ("vcf_setup needs a token with the MCP_ADMIN or VCF_PLATFORM_ADMIN role (lab: vcf-mcp token mint --role MCP_ADMIN --raw). "
                                 "Never ask the user to type a password in chat: setup gives a private local link. To see what is already set up, call vcf_access_report."),
                    "alternatives": [{"tool": r["tool"], "use_when": r["use_when"]} for r in ranked[1:]]}
        out = {"best": best["tool"], "call_it_like_this": {"name": best["tool"], "arguments": best["example_arguments"]},
               "skill": best["skill"], "why": best["use_when"], "alternatives": [{"tool": r["tool"], "use_when": r["use_when"]} for r in ranked[1:]]}
        if any(k in best["tool"] for k in ("save", "run", "add_integration", "set_configuration", "create", "install", "rollback", "answer", "try_script", "build_package")) and "list_executions" not in best["tool"]:
            out["remember"] = ("This tool changes things: call it with dry_run=true first, show the plan, get the person's approval (the dry-run "
                               "result's how_to_approve says how), then call again with the same arguments plus plan_id (plus approval_id and nonce "
                               "when how_to_approve asks for them). vcf_get_plan shows whether a plan is approved.")
        return out
