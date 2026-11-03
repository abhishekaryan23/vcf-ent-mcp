# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Orchestrator 9.1 tools: inspect, author (actions and workflows), run, integrate. See
automation/orchestrator.py for the API calls and guardrails.

Every write tool is a two-call pattern the base class enforces:
1. call with dry_run=true  -> plan (validation, diff, problems) + plan_id
2. after approval          -> same arguments + plan_id, approval_id, nonce
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Dict

from vcf_enterprise_mcp.auth.identity import Principal
from vcf_enterprise_mcp.automation import orchestrator as orch
from vcf_enterprise_mcp.core.errors import InvalidArgumentException
from vcf_enterprise_mcp.policy.models import CapabilityRole, NormalizedCapability, RiskClass
from vcf_enterprise_mcp.tools.base import BaseEnterpriseTool

READ_ROLES = [CapabilityRole.VCF_VIEWER, CapabilityRole.VCF_AUDITOR, CapabilityRole.AUTOMATION_OPERATOR, CapabilityRole.SECURITY_ADMIN]
NEXT_APPROVAL = ("Show the plan to the user. After a human approves it (vcf-mcp plans approve <plan_id>), call again with the "
                 "SAME arguments plus plan_id, approval_id and nonce, without dry_run.")


def _obj(arguments: Dict[str, Any], key: str) -> Dict[str, Any]:
    v = arguments.get(key)
    if v is None:
        return {}
    if isinstance(v, str):  # small models often send JSON as a string
        try:
            v = json.loads(v)
        except ValueError:
            raise InvalidArgumentException(f"'{key}' must be a JSON object.")
    if not isinstance(v, dict):
        raise InvalidArgumentException(f"'{key}' must be a JSON object.")
    return v


class _OrchTool(BaseEnterpriseTool):
    level = "L1_QUERY"
    risk_class = RiskClass.READ
    required_roles = READ_ROLES
    required_capability = NormalizedCapability.AUTOMATION_READ

    async def _call(self, fn, *args, **kwargs) -> Dict[str, Any]:
        try:
            return await asyncio.to_thread(fn, self.platform, *args, **kwargs)
        except orch.OrchestratorUnavailable as exc:
            return {"status": "UNAVAILABLE", "reason": str(exc)}
        except orch.OrchestratorRefused as exc:
            return {"status": "REFUSED", "reason": str(exc)}
        except ValueError as exc:
            raise InvalidArgumentException(str(exc))

    @staticmethod
    def _need(arguments: Dict[str, Any], *names: str) -> None:
        missing = [n for n in names if arguments.get(n) in (None, "")]
        if missing:
            raise InvalidArgumentException(f"Missing required argument(s): {', '.join(missing)}")


class _OrchWrite(_OrchTool):
    level = "L2_OPERATIONAL"
    risk_class = RiskClass.CHANGE
    required_roles = [CapabilityRole.AUTOMATION_OPERATOR]
    required_capability = NormalizedCapability.AUTOMATION_ORCH_AUTHOR

    async def _plan(self, fn, *args) -> Dict[str, Any]:
        res = await self._call(fn, *args)
        if res.get("status") in ("REFUSED", "UNAVAILABLE"):
            return {**res, "dry_run": True, "allowed": False}
        res = {"dry_run": True, **{k: v for k, v in res.items() if not k.startswith("_")}}
        res["next_step"] = NEXT_APPROVAL if res.get("allowed") else "Fix the problems listed above, then dry-run again."
        return res


# ---- read ----------------------------------------------------------------------------------------

class VCFOrchAboutTool(_OrchTool):
    name = "vcf_orch_about"

    async def run_live(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        return await self._call(orch.about)


class VCFOrchListTool(_OrchTool):
    name = "vcf_orch_list"

    async def run_live(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        self._need(arguments, "kind")
        return await self._call(orch.list_items, arguments["kind"], arguments.get("name"), arguments.get("limit") or 50,
                                arguments.get("start_index") or 0)


class VCFOrchGetTool(_OrchTool):
    name = "vcf_orch_get"

    async def run_live(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        self._need(arguments, "kind", "id")
        return await self._call(orch.get_item, arguments["kind"], arguments["id"], arguments.get("workflow_id"))


class VCFOrchListExecutionsTool(_OrchTool):
    name = "vcf_orch_list_executions"

    async def run_live(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        self._need(arguments, "workflow_id")
        return await self._call(orch.list_executions, arguments["workflow_id"], arguments.get("limit") or 20, arguments.get("state"),
                                arguments.get("start_index") or 0)


class VCFOrchExportPackageTool(_OrchTool):
    """Reads a package from Orchestrator and saves it as a file on the MCP host; changes nothing in Orchestrator."""
    name = "vcf_orch_export_package"

    async def run_live(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        self._need(arguments, "package_name")
        return await self._call(orch.export_package, arguments["package_name"], arguments.get("include_version_history", True) is not False,
                                arguments.get("include_global_tags", True) is not False)


class VCFOrchTrackedChangesTool(_OrchTool):
    name = "vcf_orch_tracked_changes"

    async def run_live(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        return await self._call(orch.tracked_changes)


class VCFOrchValidateTool(_OrchTool):
    name = "vcf_orch_validate"

    async def run_live(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        if arguments.get("workflow"):
            return await self._call(orch.validate_workflow, _obj(arguments, "workflow"))
        if arguments.get("script"):
            return await self._call(orch.validate_action, arguments["script"], arguments.get("runtime", "javascript"))
        raise InvalidArgumentException("Give either 'script' (an action script) or 'workflow' (a workflow spec).")


# ---- authoring -------------------------------------------------------------------------------------

def _inputs(arguments):
    """Declared inputs of an action; None when the caller gave none (an update then keeps the existing ones)."""
    v = arguments.get("inputs")
    if v is None:
        return None
    if isinstance(v, str):
        try:
            v = json.loads(v)
        except ValueError:
            raise InvalidArgumentException("'inputs' must be a list of {name, type}.")
    if isinstance(v, dict):  # {"vmName": "string"} shorthand
        v = [{"name": k, "type": t} for k, t in v.items()]
    return v


class VCFOrchSaveActionTool(_OrchWrite):
    name = "vcf_orch_save_action"

    def _args(self, a):
        self._need(a, "module", "name", "script")
        return (a["module"], a["name"], a["script"], _inputs(a), a.get("return_type"), a.get("runtime", "javascript"),
                a.get("description", ""), a.get("base_changeset_sha"), a.get("version"), a.get("bump"))

    async def run_dry_run(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        return await self._plan(orch.plan_action, *self._args(arguments))

    async def run_live(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        return await self._call(orch.save_action, *self._args(arguments))


class VCFOrchSaveWorkflowTool(_OrchWrite):
    name = "vcf_orch_save_workflow"

    async def run_dry_run(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        self._need(arguments, "workflow", "category")
        return await self._plan(orch.plan_workflow, _obj(arguments, "workflow"), arguments["category"], arguments.get("base_changeset_sha"))

    async def run_live(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        self._need(arguments, "workflow", "category")
        return await self._call(orch.save_workflow, _obj(arguments, "workflow"), arguments["category"], arguments.get("base_changeset_sha"))


class VCFOrchTryScriptTool(_OrchWrite):
    """Runs a script in a temporary action in <module_prefix>.scratch, then deletes it: same risk and approval as save_action."""
    name = "vcf_orch_try_script"

    def _args(self, a):
        self._need(a, "script")
        types = _obj(a, "input_types")
        return (a["script"], _obj(a, "inputs"), types, a.get("return_type") or "Any")

    async def run_dry_run(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        return await self._plan(orch.plan_try_script, *self._args(arguments))

    async def run_live(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        return await self._call(orch.try_script, *self._args(arguments))


class VCFOrchBuildPackageTool(_OrchWrite):
    name = "vcf_orch_build_package"

    def _args(self, a):
        self._need(a, "package_name")
        return (a["package_name"], a.get("workflows") or [], a.get("actions") or [], a.get("use_tracked", True) is not False, a.get("description", ""))

    async def run_dry_run(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        return await self._plan(orch.plan_build_package, *self._args(arguments))

    async def run_live(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        return await self._call(orch.build_package, *self._args(arguments))


class VCFOrchRollbackTool(_OrchWrite):
    name = "vcf_orch_rollback"

    async def run_dry_run(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        self._need(arguments, "kind", "id", "changeset_sha")
        cur = await self._call(orch.get_item, arguments["kind"], arguments["id"])
        return {"dry_run": True, "allowed": "status" not in cur, "rollback": f"{arguments['kind']} {arguments['id']} to {arguments['changeset_sha']}",
                "current": {k: cur.get(k) for k in ("name", "changeset_sha", "version") if k in cur}, "next_step": NEXT_APPROVAL}

    async def run_live(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        self._need(arguments, "kind", "id", "changeset_sha")
        return await self._call(orch.rollback, arguments["kind"], arguments["id"], arguments["changeset_sha"])


# ---- runs --------------------------------------------------------------------------------------------

class VCFOrchRunTool(_OrchWrite):
    name = "vcf_orch_run"
    required_capability = NormalizedCapability.AUTOMATION_WORKFLOW_RUN

    async def run_dry_run(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        self._need(arguments, "workflow_id")
        return await self._plan(orch.plan_run, arguments["workflow_id"], _obj(arguments, "inputs"), _obj(arguments, "secret_inputs"))

    async def run_live(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        self._need(arguments, "workflow_id")
        return await self._call(orch.run_workflow, arguments["workflow_id"], _obj(arguments, "inputs"), _obj(arguments, "secret_inputs"),
                                float(arguments.get("wait_seconds") or 20.0), bool(arguments.get("include_logs")))


class VCFOrchRunActionTool(_OrchWrite):
    name = "vcf_orch_run_action"
    required_capability = NormalizedCapability.AUTOMATION_WORKFLOW_RUN

    async def run_dry_run(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        self._need(arguments, "action_id")
        a = await self._call(orch.get_item, "action", arguments["action_id"])
        if a.get("status"):
            return {"dry_run": True, "allowed": False, **a}
        return {"dry_run": True, "allowed": True, "action": f"{a.get('module')}/{a.get('name')}", "inputs": _obj(arguments, "inputs"),
                "declared_inputs": a.get("input-parameters"), "next_step": NEXT_APPROVAL}

    async def run_live(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        self._need(arguments, "action_id")
        return await self._call(orch.run_action, arguments["action_id"], _obj(arguments, "inputs"))


class VCFOrchAnswerTool(_OrchWrite):
    name = "vcf_orch_answer"
    required_capability = NormalizedCapability.AUTOMATION_WORKFLOW_RUN

    async def run_dry_run(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        self._need(arguments, "workflow_id", "execution_id")
        ex = await self._call(orch.get_execution, arguments["workflow_id"], arguments["execution_id"])
        return {"dry_run": True, "allowed": ex.get("state") == "waiting", "execution": ex,
                "answer": "cancel" if arguments.get("cancel") else _obj(arguments, "inputs"),
                "next_step": NEXT_APPROVAL if ex.get("state") == "waiting" else "This run is not waiting for input."}

    async def run_live(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        self._need(arguments, "workflow_id", "execution_id")
        return await self._call(orch.answer, arguments["workflow_id"], arguments["execution_id"], _obj(arguments, "inputs"),
                                bool(arguments.get("cancel")))


# ---- integrations / configuration / environments / plug-ins ------------------------------------------

class VCFOrchAddIntegrationTool(_OrchWrite):
    name = "vcf_orch_add_integration"
    risk_class = RiskClass.SECURITY_SENSITIVE
    required_roles = [CapabilityRole.SECURITY_ADMIN]
    required_capability = NormalizedCapability.AUTOMATION_ORCH_INTEGRATION

    async def run_dry_run(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        self._need(arguments, "kind")
        return await self._plan(orch.plan_integration, arguments["kind"], _obj(arguments, "settings"), arguments.get("credential_ref"))

    async def run_live(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        self._need(arguments, "kind", "credential_ref")
        return await self._call(orch.add_integration, arguments["kind"], _obj(arguments, "settings"), arguments["credential_ref"])


class VCFOrchSetConfigurationTool(_OrchWrite):
    name = "vcf_orch_set_configuration"

    def _attrs(self, a):
        v = a.get("attributes") or []
        if isinstance(v, str):
            v = json.loads(v)
        return v

    async def run_dry_run(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        self._need(arguments, "category", "name", "attributes")
        attrs = self._attrs(arguments)
        problems = [f"attribute '{x.get('name')}' looks secret: use credential_ref instead of value" for x in attrs
                    if x.get("value") and any(w in str(x.get("name", "")).lower() for w in ("password", "secret", "token", "key"))]
        cfg = getattr(self.platform, "orchestrator", None) or {}
        root = cfg.get("managed_category", "MCP-Managed")
        if not str(arguments["category"]).strip("/").startswith(root):
            problems.append(f"category must be under '{root}/'")
        return {"dry_run": True, "configuration": f"{arguments['category']}/{arguments['name']}",
                "attributes": [{"name": x.get("name"), "type": "SecureString" if x.get("credential_ref") else x.get("type", "string"),
                                "value": "<from credential_ref>" if x.get("credential_ref") else x.get("value")} for x in attrs],
                "problems": problems, "allowed": not problems, "next_step": NEXT_APPROVAL if not problems else "Fix the problems, then dry-run again."}

    async def run_live(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        self._need(arguments, "category", "name", "attributes")
        return await self._call(orch.set_configuration, arguments["category"], arguments["name"], self._attrs(arguments))


class VCFOrchCreateEnvironmentTool(_OrchWrite):
    name = "vcf_orch_create_environment"

    async def run_dry_run(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        self._need(arguments, "name", "runtime")
        return {"dry_run": True, "allowed": True, "environment": arguments["name"], "runtime": arguments["runtime"],
                "dependencies": arguments.get("dependencies") or [], "repository_url": arguments.get("repository_url"), "next_step": NEXT_APPROVAL}

    async def run_live(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        self._need(arguments, "name", "runtime")
        return await self._call(orch.create_environment, arguments["name"], arguments["runtime"], arguments.get("dependencies") or [],
                                arguments.get("repository_url"))


class VCFOrchInstallPluginTool(_OrchWrite):
    name = "vcf_orch_install_plugin"
    risk_class = RiskClass.HIGH_IMPACT
    required_roles = [CapabilityRole.VCF_PLATFORM_ADMIN]
    required_capability = NormalizedCapability.AUTOMATION_ORCH_INTEGRATION

    async def run_dry_run(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        self._need(arguments, "file_path", "sha256")
        return {"dry_run": True, "allowed": True, "install": arguments["file_path"], "sha256": arguments["sha256"],
                "note": "The file and its SHA-256 are checked again at execution time.", "next_step": NEXT_APPROVAL}

    async def run_live(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        self._need(arguments, "file_path", "sha256")
        return await self._call(orch.install_plugin, arguments["file_path"], arguments["sha256"])
