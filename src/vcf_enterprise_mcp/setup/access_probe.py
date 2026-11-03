# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Discovers what a configured service account can actually do on each VCF component,
then maps that to the MCP tools it makes usable.

Official 9.x operations used (all read-only):
- vCenter: GET /api/session (Cis.Session_get) for the user; VI/JSON
  AuthorizationManager.HasUserPrivilegeOnEntities on the root folder for privileges.
- SDDC Manager: GET /v1/domains (read access); GET /v1/users succeeds only for ADMIN.
- NSX: GET /api/v1/aaa/user-info (user_name, roles).
- VCF Operations: GET /suite-api/api/auth/currentuser and .../currentuser/permissions.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, List, Optional

from vcf_enterprise_mcp.adapter.providers.base import BaseVCFProvider
from vcf_enterprise_mcp.adapter.providers.vcenter import VCenterProvider
from vcf_enterprise_mcp.adapter.transport.auth import BaseUpstreamAuth
from vcf_enterprise_mcp.adapter.transport.base import BaseTransport
from vcf_enterprise_mcp.adapter.connectivity import classify_connection_error
from vcf_enterprise_mcp.adapter.transport.errors import TransportException, UpstreamAuthException
from vcf_enterprise_mcp.setup.access_guide import (
    OVER_PERMISSIVE_ROLES,
    TOOL_IMPACT,
    VCENTER_ADMIN_MARKERS,
    VCENTER_PRIVILEGES,
    is_local_admin,
)

# Which component each tool needs. Health also reads VCF Operations but degrades without it.
TOOL_COMPONENT = {
    "vcf_list_vms": "vcenter", "vcf_get_vm": "vcenter", "vcf_list_hosts": "vcenter",
    "vcf_list_clusters": "vcenter", "vcf_list_datastores": "vcenter", "vcf_list_snapshots": "vcenter",
    "vcf_power_vm": "vcenter", "vcf_resize_vm": "vcenter", "vcf_create_snapshot": "vcenter",
    "vcf_delete_snapshot": "vcenter",
    "vcf_list_domains": "sddc_manager", "vcf_get_health": "sddc_manager",
    "vcf_list_upgrade_bundles": "sddc_manager", "vcf_upgrade_domain": "sddc_manager",
    "vcf_list_nsx_segments": "nsx", "vcf_list_nsx_gateways": "nsx", "vcf_create_nsx_segment": "nsx",
    "vcf_query_telemetry": "vcf_operations",
    "vcf_recover_site": None,
    # Troubleshooting starts at SDDC Manager (discovery), then reads every vCenter, NSX and VCF Operations.
    "vcf_diagnose": "sddc_manager", "vcf_check_component": "sddc_manager", "vcf_list_failed_tasks": "sddc_manager",
    "vcf_list_alerts": "sddc_manager", "vcf_trace_application": "sddc_manager", "vcf_list_networks": "sddc_manager",
}
# VCF Automation / Orchestrator tools: configured outside guided setup (vcf.automation_url + its API token).
TOOL_COMPONENT.update({t: "vcf_automation" for t in (
    "vcf_automation_list", "vcf_automation_get", "vcf_automation_validate_template", "vcf_automation_create_template",
    "vcf_orch_about", "vcf_orch_list", "vcf_orch_get", "vcf_orch_validate", "vcf_orch_save_action", "vcf_orch_save_workflow",
    "vcf_orch_rollback", "vcf_orch_run", "vcf_orch_run_action", "vcf_orch_answer", "vcf_orch_add_integration",
    "vcf_orch_set_configuration", "vcf_orch_create_environment", "vcf_orch_install_plugin", "vcf_orch_list_executions", "vcf_orch_export_package",
    "vcf_orch_tracked_changes", "vcf_orch_try_script", "vcf_orch_build_package")})

NSX_WRITE_ROLES = {"enterprise_admin", "network_engineer"}


@dataclass
class ComponentAccess:
    component: str
    configured: bool = False
    reachable: bool = False
    authenticated: bool = False
    identity: Optional[str] = None
    roles: List[str] = field(default_factory=list)
    privileges: Dict[str, bool] = field(default_factory=dict)
    privileges_verified: bool = False
    local_admin: bool = False
    over_permissive: bool = False
    findings: List[str] = field(default_factory=list)
    error: Optional[str] = None
    # Why the check failed, when it did: cause class, plain-language summary and the exact config key/YAML to change
    # (adapter/connectivity.py). login_rejected is True only for a real authentication rejection (HTTP 401, or 403
    # while logging in); only then are saved passwords discarded.
    problem: Optional[Dict[str, Any]] = None
    login_rejected: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


ProviderFactory = Callable[[str, str, BaseUpstreamAuth], BaseVCFProvider]


class AccessProbe:
    def __init__(self, transport: BaseTransport, api_version: str = "9.1.1", vcf_config: Any = None):
        self.transport = transport
        self.api_version = api_version
        self.vcf_config = vcf_config  # lets problem fixes show the existing allowlists plus the addition

    def _provider(self, url: str, auth: BaseUpstreamAuth) -> VCenterProvider:
        # VCenterProvider adds vi_json_release(); the generic request() works for every component.
        return VCenterProvider(endpoint_url=url, transport=self.transport, auth=auth, api_version=self.api_version)

    def probe(self, component: str, url: str, username: str, auth: BaseUpstreamAuth) -> ComponentAccess:
        result = ComponentAccess(component=component, configured=True, identity=username)
        prov = self._provider(url, auth)
        try:
            getattr(self, f"_probe_{component}")(prov, result)
            result.reachable = True
        except UpstreamAuthException as exc:
            result.reachable = True
            status = exc.details.get("status_code")
            # 401 is always a bad credential. 403 is a rejected login only for session-based components that have no
            # session yet; an authenticated account that is merely forbidden (e.g. NSX Basic auth) keeps its password.
            result.login_rejected = status == 401 or (status == 403 and getattr(auth, "has_session", None) is False)
            if result.login_rejected:
                result.error = f"Login rejected (HTTP {status}). Check the username and password."
            else:
                result.error = (f"The account authenticated but is not permitted to read {component} (HTTP {status}); it needs a "
                                "read role there. The saved password was kept.")
            result.problem = classify_connection_error(exc, url, self.vcf_config).to_dict()
        except Exception as exc:  # never surface raw upstream text that might echo input
            problem = classify_connection_error(exc, url, self.vcf_config)
            result.problem = problem.to_dict()
            result.error = f"{problem.summary}"

        result.local_admin = is_local_admin(component, result.identity)
        over_roles = [r for r in result.roles if r in OVER_PERMISSIVE_ROLES.get(component, ())]
        admin_privs = [p for p in VCENTER_ADMIN_MARKERS if result.privileges.get(p)]
        result.over_permissive = result.local_admin or bool(over_roles) or bool(admin_privs)
        if result.local_admin:
            result.findings.append(
                f"'{result.identity}' is a built-in local administrator account. It cannot be scoped, "
                "is shared with break-glass use, and gives the MCP every destructive action on this component."
            )
        if over_roles:
            result.findings.append(f"Account holds administrator role(s): {', '.join(over_roles)}.")
        if admin_privs:
            result.findings.append("Account holds administrator privileges at the vCenter root: " + ", ".join(admin_privs) + ".")
        return result

    # ---- per component -----------------------------------------------------------

    def _probe_vcenter(self, prov: VCenterProvider, result: ComponentAccess) -> None:
        info = prov.request("GET", "/api/session").json() or {}
        result.authenticated = True
        result.identity = info.get("user") or result.identity
        wanted = sorted({p for privs in VCENTER_PRIVILEGES.values() for p in privs} | set(VCENTER_ADMIN_MARKERS) | {"System.Read"})
        body = {
            "entities": [{"_typeName": "ManagedObjectReference", "type": "Folder", "value": "group-d1"}],
            "userName": result.identity,
            "privId": wanted,
        }
        try:
            path = f"/sdk/vim25/{prov.vi_json_release()}/AuthorizationManager/AuthorizationManager/HasUserPrivilegeOnEntities"
            rows = prov.request("POST", path, json_body=body).json() or []
            for row in rows:
                for avail in row.get("privAvailability") or []:
                    result.privileges[avail.get("privId")] = bool(avail.get("isGranted"))
            result.privileges_verified = bool(result.privileges)
        except TransportException:
            result.findings.append("vCenter privileges could not be read (VI/JSON privilege check failed); write access is unverified.")

    def _probe_sddc_manager(self, prov: BaseVCFProvider, result: ComponentAccess) -> None:
        prov.request("GET", "/v1/domains")
        result.authenticated = True
        try:
            users = prov.request("GET", "/v1/users").json() or {}
            mine = [u for u in users.get("elements", []) if isinstance(u, dict)
                    and str(u.get("name", "")).split("@")[0].lower() == str(result.identity or "").split("@")[0].lower()]
            role = ((mine[0].get("role") or {}).get("name") if mine else None)
            result.roles = [str(role).upper()] if role else ["ADMIN"]  # only ADMIN may list users at all
        except UpstreamAuthException:
            result.roles = ["OPERATOR_OR_VIEWER"]
            result.findings.append("SDDC Manager role is OPERATOR or VIEWER (not ADMIN); upgrades need OPERATOR, which cannot be confirmed read-only.")

    def _probe_nsx(self, prov: BaseVCFProvider, result: ComponentAccess) -> None:
        info = prov.request("GET", "/api/v1/aaa/user-info").json() or {}
        result.authenticated = True
        result.identity = info.get("user_name") or result.identity
        result.roles = sorted({r.get("role") for r in (info.get("roles") or []) if isinstance(r, dict) and r.get("role")})
        result.privileges_verified = True

    def _probe_vcf_operations(self, prov: BaseVCFProvider, result: ComponentAccess) -> None:
        user = prov.request("GET", "/suite-api/api/auth/currentuser").json() or {}
        result.authenticated = True
        result.identity = user.get("username") or result.identity
        roles = set(user.get("roleNames") or [])
        perms = prov.request("GET", "/suite-api/api/auth/currentuser/permissions").json() or {}
        for p in perms.get("permissions") or []:
            if p.get("roleName"):
                roles.add(p["roleName"])
        result.roles = sorted(roles)
        result.privileges_verified = True


def evaluate_tools(access: Dict[str, ComponentAccess], tools: List[str], safety_profile: Any = None,
                   risk_classes: Optional[Dict[str, str]] = None) -> Dict[str, Dict[str, str]]:
    """Per tool: AVAILABLE, UNVERIFIED, BLOCKED_BY_VCF_ACCESS, NOT_CONFIGURED, DISABLED_BY_OPERATOR or NOT_IMPLEMENTED."""
    risk_classes = risk_classes or {}
    out: Dict[str, Dict[str, str]] = {}
    for tool in tools:
        component = TOOL_COMPONENT.get(tool)
        impact = TOOL_IMPACT.get(tool)
        entry = {"impact": impact.level if impact else "READ"}
        if safety_profile is not None and safety_profile.is_tool_disabled(tool, risk_classes.get(tool)):
            entry.update(state="DISABLED_BY_OPERATOR", why=safety_profile.disabled_reason(tool) or "disabled")
        elif component is None:
            entry.update(state="NOT_IMPLEMENTED", why="No real-VCF provider exists for this tool yet.")
        else:
            acc = access.get(component)
            if acc is None or not acc.configured:
                entry.update(state="NOT_CONFIGURED", why=f"{component} is not configured.")
            elif not acc.authenticated:
                entry.update(state="BLOCKED_BY_VCF_ACCESS", why=acc.error or f"Cannot log in to {component}.")
            else:
                entry.update(_write_access(tool, component, acc))
        out[tool] = entry
    return out


def _write_access(tool: str, component: str, acc: ComponentAccess) -> Dict[str, str]:
    if tool not in TOOL_IMPACT:
        return {"state": "AVAILABLE", "why": "Read access confirmed."}
    if component == "vcenter":
        needed = VCENTER_PRIVILEGES.get(tool, ())
        if not acc.privileges_verified:
            return {"state": "UNVERIFIED", "why": "vCenter privileges could not be read; needs " + ", ".join(needed) + "."}
        missing = [p for p in needed if not acc.privileges.get(p)]
        if missing:
            # Least-privilege roles are assigned on folders/clusters, so absence at the root is expected.
            return {"state": "UNVERIFIED", "why": "Not granted at the vCenter root (fine if scoped to specific folders/clusters): " + ", ".join(missing) + "."}
        return {"state": "AVAILABLE", "why": "Required vCenter privileges are granted at the root folder."}
    if component == "nsx":
        if NSX_WRITE_ROLES & set(acc.roles):
            return {"state": "AVAILABLE", "why": "NSX role allows segment changes."}
        return {"state": "BLOCKED_BY_VCF_ACCESS", "why": "NSX role must include network_engineer (or enterprise_admin)."}
    if component == "sddc_manager":
        if "ADMIN" in acc.roles:
            return {"state": "AVAILABLE", "why": "SDDC Manager ADMIN role (more than needed; OPERATOR is enough)."}
        if "OPERATOR" in acc.roles:
            return {"state": "AVAILABLE", "why": "SDDC Manager OPERATOR role."}
        return {"state": "UNVERIFIED", "why": "Needs SDDC Manager OPERATOR role; VIEWER cannot upgrade."}
    return {"state": "UNVERIFIED", "why": "Write access not verifiable."}
