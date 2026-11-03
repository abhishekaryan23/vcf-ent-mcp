# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
MCP 2026-07-28 Stateless Protocol Handler & Tasks Extension.
Enforces per-principal dynamic tool discovery (cacheScope=private), header/body agreement validation,
W3C trace propagation, and robust Task management (tasks/get, tasks/update, tasks/cancel, subscriptions/listen).
NOTE: In strict compliance with MCP 2026-07-28, tasks/list is deliberately omitted to prevent cross-user leakage.
"""

from __future__ import annotations
import json
import os
import uuid
import logging
from typing import Dict, Any, List, Optional
from vcf_enterprise_mcp.auth.identity import Principal
from vcf_enterprise_mcp.auth.idp import EnterpriseIdPValidator
from vcf_enterprise_mcp.auth.credential_broker import CredentialBroker
from vcf_enterprise_mcp.policy.enforcement import PolicyEnforcementPoint
from vcf_enterprise_mcp.policy.models import CapabilityRole
from vcf_enterprise_mcp.router.catalog import get_all_tool_cards, EnterpriseToolCard
from vcf_enterprise_mcp.skills.registry import SkillCatalogRegistry, get_skill_registry
from vcf_enterprise_mcp.workflows.task_store import TaskStore
from vcf_enterprise_mcp.workflows.engine import VCFWorkflowEngine
from vcf_enterprise_mcp.tools import (
    VCFListVMsTool,
    VCFGetVMTool,
    VCFListHostsTool,
    VCFGetHealthTool,
    VCFQueryTelemetryTool,
    VCFListDomainsTool,
    VCFListClustersTool,
    VCFListDatastoresTool,
    VCFListNSXSegmentsTool,
    VCFListNSXGatewaysTool,
    VCFListSnapshotsTool,
    VCFListUpgradeBundlesTool,
    VCFVerifyAuditChainTool,
    VCFDiagnoseTool,
    VCFCheckComponentTool,
    VCFListFailedTasksTool,
    VCFListAlertsTool,
    VCFTraceApplicationTool, VCFListNetworksTool, VCFAutomationListTool, VCFAutomationGetTool,
    VCFAutomationValidateTemplateTool, VCFAutomationCreateTemplateTool,
    VCFFindToolTool, VCFGetPlanTool, VCFOrchAboutTool, VCFOrchListTool, VCFOrchGetTool, VCFOrchValidateTool, VCFOrchSaveActionTool, VCFOrchSaveWorkflowTool, VCFOrchRollbackTool, VCFOrchRunTool, VCFOrchRunActionTool, VCFOrchAnswerTool, VCFOrchAddIntegrationTool, VCFOrchSetConfigurationTool, VCFOrchCreateEnvironmentTool, VCFOrchInstallPluginTool,
    VCFOrchListExecutionsTool, VCFOrchExportPackageTool, VCFOrchTrackedChangesTool, VCFOrchTryScriptTool, VCFOrchBuildPackageTool,
    VCFPowerVMTool,
    VCFResizeVMTool,
    VCFCreateSnapshotTool,
    VCFDeleteSnapshotTool,
    VCFCreateNSXSegmentTool,
    VCFUpgradeDomainTool,
    VCFRecoverSiteTool,
)
from vcf_enterprise_mcp.adapter.platform import PlatformClient
from vcf_enterprise_mcp.audit.recorder import AuditRecorder
from vcf_enterprise_mcp.core.headers import validate_mcp_headers, TraceContext, set_current_trace_context
from vcf_enterprise_mcp.core.errors import (
    VCFEnterpriseException,
    TaskNotFoundException,
    AuthorizationDeniedException,
    ApprovalRequiredException,
    SSRFViolationException,
)
from vcf_enterprise_mcp.router.known_issues import KnownIssueRegistry
from vcf_enterprise_mcp.policy.models import PolicyDecision, RiskClass
from vcf_enterprise_mcp.setup.safety_profile import SafetyProfile, default_home
from vcf_enterprise_mcp.auth.personal import ACCESS_PERSONAL, ACCESS_TEAM, local_user_id, personal_principal, resolve_access_mode
from vcf_enterprise_mcp.workflows.personal_approval import APPROVAL_KEY, CLIENT_ELICITS, PersonalApproval

logger = logging.getLogger(__name__)


class EnterpriseMCPProtocolEngine:
    """Implements stateless MCP 2026-07-28 JSON-RPC 2.0 protocol with Enterprise-Managed Auth & Tasks."""

    def __init__(
        self,
        idp_validator: Optional[EnterpriseIdPValidator] = None,
        pep: Optional[PolicyEnforcementPoint] = None,
        task_store: Optional[TaskStore] = None,
        audit_recorder: Optional[AuditRecorder] = None,
        platform_client: Optional[PlatformClient] = None,
        known_issue_registry: Optional[KnownIssueRegistry] = None,
        skill_registry: Optional[SkillCatalogRegistry] = None,
        config: Optional[Any] = None,
        setup_wizard: Optional[Any] = None,
        setup_mode: bool = False,
        reloader: Optional[Any] = None,
    ):
        self.config = config
        self._setup_wizard = setup_wizard
        # setup_mode: no VCF appliance is configured yet, so only the setup tools are served.
        # reloader: callable returning a freshly built engine from the saved settings; used to apply
        # guided-setup results without restarting the MCP server.
        self.setup_mode = setup_mode
        self.reloader = reloader
        self.pending_notifications: List[Dict[str, Any]] = []
        self.idp = idp_validator or EnterpriseIdPValidator()
        self.pep = pep or PolicyEnforcementPoint()
        self.task_store = task_store or TaskStore()
        self.platform = platform_client or PlatformClient()
        self.known_issues = known_issue_registry or KnownIssueRegistry()
        self.skill_registry = skill_registry or get_skill_registry()
        self.audit = audit_recorder or AuditRecorder(durable_store=self.task_store.durable)
        self.redactor = getattr(self.audit, "redactor", None) or CredentialBroker()

        # Shared workflow engine using this task_store, platform_client and durable state
        self.wf_engine = VCFWorkflowEngine(task_store=self.task_store, platform_client=self.platform)
        self.plan_manager = self.wf_engine.plan_manager

        # Access mode (auth/personal.py): "personal" = one person on their own machine (local identity, they confirm each
        # change themselves); "team" = tokens for every call and a separate approver. Absent in the config = team.
        self.access_mode = resolve_access_mode(config) if config is not None else ACCESS_TEAM
        self.personal_principal = None
        self.personal_approval = None
        if self.access_mode == ACCESS_PERSONAL:
            self.personal_principal = personal_principal(config)
            self.personal_approval = PersonalApproval(
                durable=self.task_store.durable, user_id=local_user_id(config), home=self.setup_home,
                plan_manager=self.plan_manager, db_path=getattr(self.task_store.durable, "db_path", None))
            self.plan_manager.enable_personal(self.personal_approval)

        # Wire tools with PEP, audit, durable store, platform_client, and known_issues
        d_store = self.task_store.durable
        self.tool_instances = {
            "vcf_list_vms": VCFListVMsTool(pep=self.pep, audit_recorder=self.audit, durable_store=d_store, platform_client=self.platform, known_issue_registry=self.known_issues),
            "vcf_get_vm": VCFGetVMTool(pep=self.pep, audit_recorder=self.audit, durable_store=d_store, platform_client=self.platform, known_issue_registry=self.known_issues),
            "vcf_list_hosts": VCFListHostsTool(pep=self.pep, audit_recorder=self.audit, durable_store=d_store, platform_client=self.platform, known_issue_registry=self.known_issues),
            "vcf_get_health": VCFGetHealthTool(pep=self.pep, audit_recorder=self.audit, durable_store=d_store, platform_client=self.platform, known_issue_registry=self.known_issues),
            "vcf_query_telemetry": VCFQueryTelemetryTool(pep=self.pep, audit_recorder=self.audit, durable_store=d_store, platform_client=self.platform, known_issue_registry=self.known_issues),
            "vcf_list_domains": VCFListDomainsTool(pep=self.pep, audit_recorder=self.audit, durable_store=d_store, platform_client=self.platform, known_issue_registry=self.known_issues),
            "vcf_list_clusters": VCFListClustersTool(pep=self.pep, audit_recorder=self.audit, durable_store=d_store, platform_client=self.platform, known_issue_registry=self.known_issues),
            "vcf_list_datastores": VCFListDatastoresTool(pep=self.pep, audit_recorder=self.audit, durable_store=d_store, platform_client=self.platform, known_issue_registry=self.known_issues),
            "vcf_list_nsx_segments": VCFListNSXSegmentsTool(pep=self.pep, audit_recorder=self.audit, durable_store=d_store, platform_client=self.platform, known_issue_registry=self.known_issues),
            "vcf_list_nsx_gateways": VCFListNSXGatewaysTool(pep=self.pep, audit_recorder=self.audit, durable_store=d_store, platform_client=self.platform, known_issue_registry=self.known_issues),
            "vcf_list_snapshots": VCFListSnapshotsTool(pep=self.pep, audit_recorder=self.audit, durable_store=d_store, platform_client=self.platform, known_issue_registry=self.known_issues),
            "vcf_list_upgrade_bundles": VCFListUpgradeBundlesTool(pep=self.pep, audit_recorder=self.audit, durable_store=d_store, platform_client=self.platform, known_issue_registry=self.known_issues),
            "vcf_verify_audit_chain": VCFVerifyAuditChainTool(pep=self.pep, audit_recorder=self.audit, durable_store=d_store, platform_client=self.platform, known_issue_registry=self.known_issues),
            "vcf_diagnose": VCFDiagnoseTool(pep=self.pep, audit_recorder=self.audit, durable_store=d_store, platform_client=self.platform, known_issue_registry=self.known_issues),
            "vcf_check_component": VCFCheckComponentTool(pep=self.pep, audit_recorder=self.audit, durable_store=d_store, platform_client=self.platform, known_issue_registry=self.known_issues),
            "vcf_list_failed_tasks": VCFListFailedTasksTool(pep=self.pep, audit_recorder=self.audit, durable_store=d_store, platform_client=self.platform, known_issue_registry=self.known_issues),
            "vcf_list_alerts": VCFListAlertsTool(pep=self.pep, audit_recorder=self.audit, durable_store=d_store, platform_client=self.platform, known_issue_registry=self.known_issues),
            "vcf_find_tool": VCFFindToolTool(pep=self.pep, audit_recorder=self.audit, durable_store=d_store, platform_client=self.platform, known_issue_registry=self.known_issues),
            "vcf_get_plan": VCFGetPlanTool(pep=self.pep, audit_recorder=self.audit, durable_store=d_store, plan_manager=self.plan_manager, platform_client=self.platform, known_issue_registry=self.known_issues),
            "vcf_orch_about": VCFOrchAboutTool(pep=self.pep, audit_recorder=self.audit, durable_store=d_store, platform_client=self.platform, known_issue_registry=self.known_issues),
            "vcf_orch_list": VCFOrchListTool(pep=self.pep, audit_recorder=self.audit, durable_store=d_store, platform_client=self.platform, known_issue_registry=self.known_issues),
            "vcf_orch_get": VCFOrchGetTool(pep=self.pep, audit_recorder=self.audit, durable_store=d_store, platform_client=self.platform, known_issue_registry=self.known_issues),
            "vcf_orch_validate": VCFOrchValidateTool(pep=self.pep, audit_recorder=self.audit, durable_store=d_store, platform_client=self.platform, known_issue_registry=self.known_issues),
            "vcf_orch_save_action": VCFOrchSaveActionTool(pep=self.pep, audit_recorder=self.audit, durable_store=d_store, platform_client=self.platform, known_issue_registry=self.known_issues),
            "vcf_orch_save_workflow": VCFOrchSaveWorkflowTool(pep=self.pep, audit_recorder=self.audit, durable_store=d_store, platform_client=self.platform, known_issue_registry=self.known_issues),
            "vcf_orch_rollback": VCFOrchRollbackTool(pep=self.pep, audit_recorder=self.audit, durable_store=d_store, platform_client=self.platform, known_issue_registry=self.known_issues),
            "vcf_orch_run": VCFOrchRunTool(pep=self.pep, audit_recorder=self.audit, durable_store=d_store, platform_client=self.platform, known_issue_registry=self.known_issues),
            "vcf_orch_run_action": VCFOrchRunActionTool(pep=self.pep, audit_recorder=self.audit, durable_store=d_store, platform_client=self.platform, known_issue_registry=self.known_issues),
            "vcf_orch_answer": VCFOrchAnswerTool(pep=self.pep, audit_recorder=self.audit, durable_store=d_store, platform_client=self.platform, known_issue_registry=self.known_issues),
            "vcf_orch_add_integration": VCFOrchAddIntegrationTool(pep=self.pep, audit_recorder=self.audit, durable_store=d_store, platform_client=self.platform, known_issue_registry=self.known_issues),
            "vcf_orch_set_configuration": VCFOrchSetConfigurationTool(pep=self.pep, audit_recorder=self.audit, durable_store=d_store, platform_client=self.platform, known_issue_registry=self.known_issues),
            "vcf_orch_create_environment": VCFOrchCreateEnvironmentTool(pep=self.pep, audit_recorder=self.audit, durable_store=d_store, platform_client=self.platform, known_issue_registry=self.known_issues),
            "vcf_orch_install_plugin": VCFOrchInstallPluginTool(pep=self.pep, audit_recorder=self.audit, durable_store=d_store, platform_client=self.platform, known_issue_registry=self.known_issues),
            "vcf_orch_list_executions": VCFOrchListExecutionsTool(pep=self.pep, audit_recorder=self.audit, durable_store=d_store, platform_client=self.platform, known_issue_registry=self.known_issues),
            "vcf_orch_export_package": VCFOrchExportPackageTool(pep=self.pep, audit_recorder=self.audit, durable_store=d_store, platform_client=self.platform, known_issue_registry=self.known_issues),
            "vcf_orch_tracked_changes": VCFOrchTrackedChangesTool(pep=self.pep, audit_recorder=self.audit, durable_store=d_store, platform_client=self.platform, known_issue_registry=self.known_issues),
            "vcf_orch_try_script": VCFOrchTryScriptTool(pep=self.pep, audit_recorder=self.audit, durable_store=d_store, platform_client=self.platform, known_issue_registry=self.known_issues),
            "vcf_orch_build_package": VCFOrchBuildPackageTool(pep=self.pep, audit_recorder=self.audit, durable_store=d_store, platform_client=self.platform, known_issue_registry=self.known_issues),
            "vcf_trace_application": VCFTraceApplicationTool(pep=self.pep, audit_recorder=self.audit, durable_store=d_store, platform_client=self.platform, known_issue_registry=self.known_issues),
            "vcf_list_networks": VCFListNetworksTool(pep=self.pep, audit_recorder=self.audit, durable_store=d_store, platform_client=self.platform, known_issue_registry=self.known_issues),
            "vcf_automation_list": VCFAutomationListTool(pep=self.pep, audit_recorder=self.audit, durable_store=d_store, platform_client=self.platform, known_issue_registry=self.known_issues),
            "vcf_automation_get": VCFAutomationGetTool(pep=self.pep, audit_recorder=self.audit, durable_store=d_store, platform_client=self.platform, known_issue_registry=self.known_issues),
            "vcf_automation_validate_template": VCFAutomationValidateTemplateTool(pep=self.pep, audit_recorder=self.audit, durable_store=d_store, platform_client=self.platform, known_issue_registry=self.known_issues),
            "vcf_automation_create_template": VCFAutomationCreateTemplateTool(pep=self.pep, audit_recorder=self.audit, durable_store=d_store, platform_client=self.platform, known_issue_registry=self.known_issues),
            "vcf_power_vm": VCFPowerVMTool(pep=self.pep, audit_recorder=self.audit, durable_store=d_store, plan_manager=self.plan_manager, platform_client=self.platform, known_issue_registry=self.known_issues),
            "vcf_resize_vm": VCFResizeVMTool(pep=self.pep, audit_recorder=self.audit, durable_store=d_store, plan_manager=self.plan_manager, platform_client=self.platform, known_issue_registry=self.known_issues),
            "vcf_create_snapshot": VCFCreateSnapshotTool(pep=self.pep, audit_recorder=self.audit, durable_store=d_store, plan_manager=self.plan_manager, platform_client=self.platform, known_issue_registry=self.known_issues),
            "vcf_delete_snapshot": VCFDeleteSnapshotTool(pep=self.pep, audit_recorder=self.audit, durable_store=d_store, plan_manager=self.plan_manager, platform_client=self.platform, known_issue_registry=self.known_issues),
            "vcf_create_nsx_segment": VCFCreateNSXSegmentTool(pep=self.pep, audit_recorder=self.audit, durable_store=d_store, plan_manager=self.plan_manager, platform_client=self.platform, known_issue_registry=self.known_issues),
            "vcf_upgrade_domain": VCFUpgradeDomainTool(workflow_engine=self.wf_engine, pep=self.pep, audit_recorder=self.audit, durable_store=d_store, plan_manager=self.plan_manager, platform_client=self.platform, known_issue_registry=self.known_issues),
            "vcf_recover_site": VCFRecoverSiteTool(workflow_engine=self.wf_engine, pep=self.pep, audit_recorder=self.audit, durable_store=d_store, plan_manager=self.plan_manager, platform_client=self.platform, known_issue_registry=self.known_issues),
        }

    SUPPORTED_PROTOCOL_VERSIONS = ("2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26")

    TOOL_CAPABILITY_MAP = {
        "vcf_list_vms": "compute.inventory",
        "vcf_get_vm": "compute.inventory",
        "vcf_list_hosts": "compute.inventory",
        "vcf_get_health": "domain.lifecycle",
        "vcf_query_telemetry": "telemetry.promql",
        "vcf_list_domains": "domain.lifecycle",
        "vcf_list_clusters": "compute.inventory",
        "vcf_list_datastores": "compute.inventory",
        "vcf_list_nsx_segments": "network.segments",
        "vcf_list_nsx_gateways": "network.segments",
        "vcf_list_snapshots": "vm.lifecycle",
        "vcf_list_upgrade_bundles": "domain.lifecycle",
        "vcf_diagnose": "domain.lifecycle",
        "vcf_check_component": "domain.lifecycle",
        "vcf_list_failed_tasks": "domain.lifecycle",
        "vcf_list_alerts": "domain.lifecycle",
        "vcf_trace_application": "domain.lifecycle",
        "vcf_list_networks": "domain.lifecycle",
        "vcf_power_vm": "vm.lifecycle",
        "vcf_resize_vm": "vm.lifecycle",
        "vcf_create_snapshot": "vm.lifecycle",
        "vcf_delete_snapshot": "vm.lifecycle",
        "vcf_create_nsx_segment": "network.segments",
        "vcf_upgrade_domain": "domain.lifecycle",
        "vcf_recover_site": "dr.recovery",
    }

    SETUP_ADMIN_ROLES = [CapabilityRole.MCP_ADMIN, CapabilityRole.VCF_PLATFORM_ADMIN]

    SETUP_TOOL_DEFINITIONS = [
        {
            "name": "vcf_setup",
            "description": (
                "[L0_SETUP | MCP_ADMIN or VCF_PLATFORM_ADMIN only; no dry run, plan or approval] Guided, interactive setup. Asks what the user wants to do, which VCF "
                "appliances and service accounts to use, collects passwords on a private local page (never in chat), "
                "verifies the account's real access, warns about over-permissive accounts such as local admins, and lets "
                "the user switch off destructive actions. Call with no arguments to start; never pass passwords or API keys."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "enum": ["digital_twin", "lab", "production"]},
                    "goals": {"type": "array", "items": {"type": "string", "enum": [
                        "monitor", "capacity", "vm_operations", "network", "lifecycle", "disaster_recovery"]}},
                    "endpoints": {"type": "object", "description": "Component base URLs keyed by vcenter, sddc_manager, nsx, vcf_operations (or digital_twin).",
                                  "additionalProperties": {"type": "string"}},
                    "usernames": {"type": "object", "description": "Service-account usernames per component. Usernames only, never passwords.",
                                  "additionalProperties": {"type": "string"}},
                    "disable": {"type": "array", "items": {"type": "string", "enum": [
                        "disable_vm_power", "disable_snapshot_delete", "disable_vm_reconfigure",
                        "disable_network_changes", "disable_upgrades", "disable_dr"]}},
                    "read_only": {"type": "boolean"},
                    "network": {"type": "object", "description": "The user's answers to a network question from a previous result (never passwords): "
                                "apply_suggested_changes (boolean), ca_cert_path (path to a PEM CA bundle on this computer), https_proxy, no_proxy.",
                                "properties": {"apply_suggested_changes": {"type": "boolean"}, "ca_cert_path": {"type": "string"},
                                               "https_proxy": {"type": "string"}, "no_proxy": {"type": "string"}},
                                "additionalProperties": False},
                    "resume": {"type": "string", "description": "Opaque token from the previous vcf_setup result (clients without elicitation)."},
                    "restart": {"type": "boolean"},
                },
                "additionalProperties": False,
            },
            "_enterprise_meta": {"risk_class": RiskClass.SECURITY_SENSITIVE, "required_roles": SETUP_ADMIN_ROLES,
                                 "level": "L0_SETUP", "control_plane_setup": True},
        },
        {
            "name": "vcf_access_report",
            "description": (
                "[L0_SETUP | READ] Explains what this MCP can do for you right now: tools visible to you, the access "
                "verified at setup for each VCF account, warnings about over-permissive accounts, and actions the "
                "operator has switched off. Use when the user asks 'what can you do?'."
            ),
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
            "_enterprise_meta": {"risk_class": RiskClass.READ, "required_roles": list(CapabilityRole), "level": "L0_SETUP",
                                 "control_plane_setup": True},
        },
    ]

    @property
    def setup_home(self):
        return default_home()

    @property
    def setup_wizard(self):
        if self._setup_wizard is None:
            from vcf_enterprise_mcp.setup.wizard import SetupWizard
            from vcf_enterprise_mcp.secrets.registry import get_default_secret_registry
            profile = self.pep.safety_profile
            if profile is None:
                profile = SafetyProfile.at_home(self.setup_home)
                self.pep.safety_profile = profile
            config_path = os.environ.get("VCF_ENTERPRISE_MCP_CONFIG")
            self._setup_wizard = SetupWizard(
                home=self.setup_home,
                safety_profile=profile,
                secret_registry=get_default_secret_registry(),
                config_path=config_path,
                current_config=self.config,
            )
        return self._setup_wizard

    def _is_setup_complete(self) -> bool:
        return (self.setup_home / "access_report.json").exists()

    SETUP_MODE_TOOLS = ("vcf_find_tool",)

    def _auth_help(self, exc: Exception) -> str:
        """Turns a token failure into something a person (or a model reading the log) can act on."""
        if self.personal_principal is not None:
            return (
                f"Authentication failed: {str(getattr(exc, 'message', None) or exc).rstrip('.')}. Personal access mode needs no token, "
                "but this client sent one (VCF_MCP_AUTH_TOKEN) and it was not accepted. Remove VCF_MCP_AUTH_TOKEN from the MCP server "
                "entry and reconnect to act as your local user, or replace it with a valid token."
            )
        return (
            f"Authentication failed: {str(getattr(exc, 'message', None) or exc).rstrip('.')}. "
            "The MCP server needs an access token (JWT) in its environment: set VCF_MCP_AUTH_TOKEN to 'Bearer <jwt>' in your "
            "client's MCP server entry and reconnect. For a lab, create one with "
            "'vcf-mcp token mint --role MCP_ADMIN --raw' (MCP_ADMIN is enough to run vcf_setup); in production use a "
            "token from your identity provider."
        )

    def _identity_instructions(self, principal: Optional[Principal]) -> str:
        if self.personal_principal is None or principal is None:
            return ""
        if principal is self.personal_principal:
            roles = ", ".join(r.value for r in sorted(self.pep.pdp.get_effective_roles_for_principal(principal), key=lambda r: r.value))
            return (f"ACCESS MODE personal: no access token is needed. You act as '{principal.user_id}' (the local user of this computer) "
                    f"with the roles {roles}. ")
        return (f"ACCESS MODE personal with a token: you act as '{principal.user_id}' from the token the client supplied. "
                "Changes are still approved by the local person. ")

    def _approval_instructions(self) -> str:
        if self.personal_principal is None:
            return ("Tools that change anything need two calls: first dry_run=true, then (after a human approves the plan) the same "
                    "arguments plus plan_id, approval_id and nonce. ")
        return ("Tools that change anything need two calls: first dry_run=true, then the same arguments plus plan_id only. The person who "
                "asked approves each change themselves (a confirmation prompt in the chat, or the approval link or terminal command in the "
                "dry-run result's how_to_approve); you can never approve for them and need no approval_id or nonce. vcf_get_plan shows "
                "whether a plan is approved. ")

    def _tool_error_result(self, exc: VCFEnterpriseException, tool_name: Optional[str] = None) -> Dict[str, Any]:
        """CallToolResult for a failed tool execution: readable text for the model, isError=true."""
        raw = self.redactor.redact_secrets_from_data(exc.to_rpc_error())
        message = str(raw.get("message") or exc)
        hint = ""
        if isinstance(exc, ApprovalRequiredException) and self.personal_approval is not None:
            how = (exc.details or {}).get("how_to_approve") if isinstance(getattr(exc, "details", None), dict) else None
            if how:
                where = (f"open {how['approval_url']} in a browser" if how.get("approval_url") else "approve in the chat prompt")
                hint = (f" Next step: the person who asked must approve it themselves ({where}, or run `{how.get('command')}` in their OWN "
                        "terminal), then call the tool again with the SAME arguments plus plan_id only. You cannot approve for them.")
            else:
                hint = (" Next step: call the tool again with dry_run=true to get a plan_id; the person then approves it (chat prompt, the local "
                        "approval link or `vcf-mcp plans approve <plan_id>` in their own terminal); finally call again with the SAME arguments "
                        "plus plan_id only.")
        elif isinstance(exc, ApprovalRequiredException):
            hint = (" Next step: call the tool again with dry_run=true to get a plan; a human then approves it with "
                    "'vcf-mcp plans approve <plan_id>'; finally call again with plan_id, approval_id and nonce.")
        elif isinstance(exc, SSRFViolationException):
            hint = (" This is an MCP network-allowlist problem, not an appliance fault: add the host to vcf.allowed_dns_suffixes "
                    "(or vcf.allowed_cidrs / vcf.endpoint_overrides) in the config file, or run vcf_setup.")
        text = message + hint
        return {
            "isError": True,
            "content": [{"type": "text", "text": text}],
            "structuredContent": {"error": {"code": raw.get("code"), "message": message, "data": raw.get("data") or {}, "tool": tool_name}},
        }

    # ---- personal-mode approval gate ----------------------------------------------------------

    @staticmethod
    def _client_elicits(params: Dict[str, Any]) -> bool:
        """True when this request's client declared MCP elicitation (form mode), the same check guided setup uses."""
        caps = ((params.get("_meta") or {}).get("io.modelcontextprotocol/clientCapabilities") or {}).get("elicitation")
        return caps is not None and (caps == {} or "form" in caps)

    def _needs_personal_gate(self, tool: Any, arguments: Dict[str, Any]) -> bool:
        """A live change with a plan_id but no approval presented: in personal mode the person is asked (or the server looks up
        what they already approved) instead of the model having to carry approval_id and nonce."""
        return bool(
            self.personal_approval is not None
            and getattr(tool, "risk_class", RiskClass.READ) != RiskClass.READ
            and not arguments.get("dry_run") and arguments.get("plan_id")
            and not (arguments.get("approval_id") and arguments.get("nonce")) and not arguments.get("signed_auth")
        )

    async def _personal_gate(self, tool: Any, tool_name: str, principal: Principal, arguments: Dict[str, Any],
                             params: Dict[str, Any]) -> Any:
        """Returns (arguments, None) to execute (approval_id and nonce filled in from the recorded approval) or
        (arguments, result) where result is an elicitation request to send back instead of executing."""
        import asyncio
        mgr, pa = self.plan_manager, self.personal_approval
        # Everything except the approval is checked first, so the person is never asked about a call that would be refused anyway.
        self.pep.authorize_execution(principal, tool_name, {**arguments, "approval_id": "-", "nonce": "-"}, tool.get_tool_meta())
        key = arguments.get("idempotency_key")
        if key:
            tenant = principal.tenant_id or "tenant-default"
            env = (principal.environment_ids[0] if principal.environment_ids else None) or "env-prod"
            cached = tool.durable.get_idempotency_record(tenant, key, environment_id=env)
            if cached and cached.get("status") == "COMMITTED":
                return arguments, None  # a completed call is answered from the record; nobody is asked twice
        plan_id = arguments["plan_id"]
        plan = mgr.plan_for_gate(plan_id, tool_name, arguments, principal)
        await asyncio.to_thread(pa.sync_page_decision, plan)  # a page approval becomes a signed, recorded approval here
        approval = mgr.find_unused_approval(plan)
        if approval:
            return {**arguments, "approval_id": approval["approval_id"], "nonce": approval["nonce"]}, None
        if pa.rejected_on_page(plan):
            raise pa.refusal_after_reject(plan_id)
        if mgr.has_used_approval(plan):
            raise ApprovalRequiredException(
                f"The approval for plan '{plan_id}' was already used. Make a new dry run for another execution.",
                details={"plan_id": plan_id})
        if self._client_elicits(params):
            return await self._elicit_approval(plan, tool_name, principal, arguments, params)
        tenant_id, env_id = mgr._get_effective_coords(principal)
        raise ApprovalRequiredException(
            f"Plan '{plan_id}' has not been approved yet. The person who asked must approve it themselves.",
            details={"plan_id": plan_id, "how_to_approve": pa.how_to_approve(plan_id, tenant_id, env_id)})

    async def _elicit_approval(self, plan: Dict[str, Any], tool_name: str, principal: Principal, arguments: Dict[str, Any],
                               params: Dict[str, Any]) -> Any:
        """MCP elicitation (MRTR form): the client shows the person the plan and an Approve/Reject choice, plus the target name or
        plan code to type for destructive and security-sensitive changes. The model cannot answer it: the answer arrives in
        params.inputResponses, written by the client UI, never in the tool arguments."""
        from vcf_enterprise_mcp.setup.request_state import InvalidRequestStateException, RequestStateCodec
        pa, mgr = self.personal_approval, self.plan_manager
        codec = getattr(self, "_approval_codec", None) or RequestStateCodec(home=self.setup_home)
        self._approval_codec = codec
        binding = f"tools/call:{tool_name}"
        info = pa.info(plan)
        token = params.get("requestState")
        state: Dict[str, Any] = {}
        if token:
            state = codec.decode(token, principal.user_id, binding)
            if state.get("plan_id") != info.plan_id or state.get("plan_hash") != info.plan_hash:
                raise InvalidRequestStateException("issued for a different plan")
        response = (params.get("inputResponses") or {}).get(APPROVAL_KEY)
        attempts = int(state.get("attempts", 0))

        def ask(error: str = "") -> Any:
            new_state = codec.encode(principal.user_id, binding, {"plan_id": info.plan_id, "plan_hash": info.plan_hash, "attempts": attempts})
            return arguments, {"resultType": "input_required", "inputRequests": {APPROVAL_KEY: pa.elicitation_request(info, error)},
                               "requestState": new_state}

        if not token or not isinstance(response, dict):
            return ask()
        content = response.get("content") or {}
        if response.get("action") != "accept" or content.get("decision") != "approve":
            mgr.audit_approval(plan, pa.user_id, "in_client", "REJECTED", info.plan_hash)
            raise AuthorizationDeniedException(
                f"NOT APPROVED: the person {'declined' if response.get('action') != 'accept' else 'rejected'} plan '{info.plan_id}' in the chat prompt. "
                "Nothing was changed.")
        if not pa.confirmation_ok(info, content.get("confirm")):
            attempts += 1
            if attempts >= 3:
                mgr.audit_approval(plan, pa.user_id, "in_client", "REJECTED", info.plan_hash)
                raise AuthorizationDeniedException(
                    f"NOT APPROVED: the confirmation text did not match three times for plan '{info.plan_id}'. Nothing was changed.")
            return ask("That did not match what the plan asks for, so nothing was approved. Try again or reject.")
        signed = mgr.approve_plan(info.plan_id, pa.approver_principal(plan), channel="in_client")
        return {**arguments, "approval_id": signed.approval_id, "nonce": signed.nonce}, None

    async def reload_after_setup(self) -> bool:
        """Rebuilds this engine from the saved settings so completed setup takes effect without a restart."""
        if self.reloader is None:
            return False
        try:
            fresh = self.reloader()
        except Exception:
            logger.exception("Could not reload settings after setup; restart the MCP server to apply them.")
            return False
        reloader = self.reloader
        self.__dict__.update(fresh.__dict__)
        self.reloader = reloader
        self.pending_notifications.append({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"})
        return True

    def drain_notifications(self) -> List[Dict[str, Any]]:
        out, self.pending_notifications = self.pending_notifications, []
        return out

    def _build_raw_tool_definitions(self) -> List[Dict[str, Any]]:
        tool_capability_map = self.TOOL_CAPABILITY_MAP
        raw = [dict(d) for d in self.SETUP_TOOL_DEFINITIONS]
        for card in get_all_tool_cards():
            if self.setup_mode and card.name not in self.SETUP_MODE_TOOLS:
                continue
            req_cap = tool_capability_map.get(card.name)
            if hasattr(self.platform, "registry") and self.platform.registry is not None:
                if req_cap and not self.platform.registry.has_capability(req_cap):
                    # Hide unsupported capabilities when provider is absent (F16)
                    continue
            raw.append({
                "name": card.name,
                "description": f"[{card.level} | {card.risk_class.value}] {card.description}",
                "inputSchema": card.schema,
                "_enterprise_meta": {
                    "risk_class": card.risk_class,
                    "required_roles": card.required_roles,
                    "level": card.level,
                },
            })
        return raw

    # ---- guided setup ----------------------------------------------------------

    def _require_setup_admin(self, principal: Principal) -> None:
        roles = self.pep.pdp.get_effective_roles_for_principal(principal)
        if not any(r in roles for r in self.SETUP_ADMIN_ROLES):
            raise AuthorizationDeniedException(
                f"Principal '{principal.user_id}' needs MCP_ADMIN or VCF_PLATFORM_ADMIN to run setup."
            )

    def _audit_setup(self, principal: Principal, event: str, details: Dict[str, Any], trace_id: Optional[str]) -> None:
        decision = PolicyDecision(allow=True, reason=event, risk_class=RiskClass.SECURITY_SENSITIVE,
                                  tenant_id=principal.tenant_id)
        rec = self.audit.record_call(principal, "vcf_setup", {"event": event, **details}, decision, trace_id=trace_id)
        self.audit.finalize_record(rec, status="SUCCESS", summary=event)

    async def _call_setup_tool(self, tool_name: str, principal: Principal, arguments: Dict[str, Any],
                               params: Dict[str, Any], trace_id: Optional[str]) -> Dict[str, Any]:
        import asyncio
        if tool_name == "vcf_access_report":
            return self._access_report(principal)
        self._require_setup_admin(principal)
        wizard = self.setup_wizard
        wizard.audit = lambda event, details: self._audit_setup(principal, event, details, trace_id)
        meta = params.get("_meta") or {}
        wizard_meta = {
            "clientCapabilities": meta.get("io.modelcontextprotocol/clientCapabilities") or {},
            "inputResponses": params.get("inputResponses"),
            "requestState": params.get("requestState"),
        }
        # The credential step may wait for the user's browser; keep the event loop free.
        out = await asyncio.to_thread(wizard.run, principal, arguments, wizard_meta)
        if out.get("resultType") == "input_required":
            return out
        payload = out["structured"]
        if payload.get("status") == "COMPLETE" and self.reloader is not None:
            # Apply the new endpoints and safety choices now: no client restart. The result is delivered first.
            if await self.reload_after_setup():
                payload["next_steps"] = [
                    "The new configuration is already active; no restart is needed. Your tool list refreshes by itself "
                    "(reconnect or start a new chat if your harness does not refresh it)."
                ] + [n for n in payload.get("next_steps", []) if not n.startswith("Restart the MCP server")]
                payload["reloaded"] = True
            else:
                payload["reloaded"] = False
                payload.setdefault("next_steps", []).insert(0, "The server could not apply the saved configuration automatically: restart it.")
        return {
            "content": [{"type": "text", "text": json.dumps(payload, indent=2)}],
            "structuredContent": payload,
            "isError": False,
        }

    def _access_report(self, principal: Principal) -> Dict[str, Any]:
        profile = self.pep.safety_profile or SafetyProfile.at_home(self.setup_home)
        visible = self.pep.filter_visible_tools(principal, self._build_raw_tool_definitions())
        saved = None
        report_path = self.setup_home / "access_report.json"
        if report_path.exists():
            saved = json.loads(report_path.read_text(encoding="utf-8"))
        payload = {
            "you_are": principal.user_id,
            "access_mode": self.access_mode,
            "your_roles": [r.value for r in self.pep.pdp.get_effective_roles_for_principal(principal)],
            "operating_mode": self.pep.pdp.config.operating_mode,
            "tools_you_can_use_now": [t["name"] for t in visible],
            "switched_off_by_operator": profile.as_dict(),
            "verified_vcf_access": saved,
            "setup_complete": saved is not None,
        }
        if saved is None:
            payload["hint"] = "Setup has not been run. An MCP or platform admin can start it with vcf_setup."
        elif saved.get("over_permissive_components"):
            payload["warning"] = ("Over-permissive VCF accounts are configured for: "
                                  + ", ".join(saved["over_permissive_components"])
                                  + ". Destructive actions may be reachable; see least_privilege_guide.")
        return {"content": [{"type": "text", "text": json.dumps(payload, indent=2)}], "structuredContent": payload, "isError": False}

    async def handle_jsonrpc_request(
        self,
        request: Dict[str, Any],
        auth_header: Optional[str] = None,
        client_ip: str = "127.0.0.1",
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Dispatches JSON-RPC 2.0 requests with enterprise identity extraction,
        header/body agreement validation, and W3C trace propagation.

        Returns None for JSON-RPC notifications (requests without an id): a server must never reply to them.
        """
        if not isinstance(request, dict) or "id" not in request:
            return None  # notification (e.g. notifications/initialized) or a stray response: no reply allowed
        req_id = request.get("id")
        method = request.get("method")
        params = request.get("params") or {}
        auth_problem: Optional[str] = None

        try:
            # 1. Enforce HTTP header agreement and extract W3C TraceContext
            trace_ctx = validate_mcp_headers(headers, request)

            # 2. Extract verified corporate principal. initialize and ping work without a valid token so the
            #    harness can finish its handshake; the problem is reported where it matters (tools/list, tools/call).
            principal = None
            try:
                if not auth_header and self.personal_principal is not None and headers is None:
                    # Personal mode over stdio: no token needed, the caller is the local OS user. A network request
                    # (headers present) never gets this identity, and a supplied token is validated as usual.
                    principal = self.personal_principal
                else:
                    principal = self.idp.validate_bearer_token(auth_header, client_ip)
            except AuthorizationDeniedException as auth_exc:
                help_text = self._auth_help(auth_exc)
                if method in ("initialize", "ping", "server/discover"):
                    auth_problem = help_text
                elif method == "tools/call":
                    return {"jsonrpc": "2.0", "id": req_id, "result": self._tool_error_result(
                        AuthorizationDeniedException(help_text), tool_name=params.get("name"))}
                else:
                    raise AuthorizationDeniedException(help_text) from auth_exc

            if method == "initialize":
                # Version negotiation: answer with the client's version when we support it, else our latest.
                asked = params.get("protocolVersion")
                negotiated = asked if asked in self.SUPPORTED_PROTOCOL_VERSIONS else self.SUPPORTED_PROTOCOL_VERSIONS[0]
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "protocolVersion": negotiated,
                        "serverInfo": {
                            "name": "vcf-enterprise-mcp-control-plane",
                            "title": "VCF Enterprise MCP (unofficial)",
                            "version": "1.0.0",
                            "websiteUrl": "https://github.com/abhishekaryan23/vcf-ent-mcp",
                        },
                        "capabilities": {
                            "tools": {"listChanged": True},
                            "tasks": {"cancel": {}, "requests": {"tools": {"call": {}}}},  # no "list": tasks/list is not offered (cross-user leakage)
                            "resources": {},
                            "prompts": {},
                            # Non-standard capabilities go under "experimental" so strict MCP clients accept the handshake.
                            "experimental": {"enterpriseAuth": {
                                "issuer": self.idp.config.issuer_url,
                                "mode": "ENTERPRISE_MANAGED",
                                "accessMode": self.access_mode,
                            }},
                        },
                        "traceContext": {
                            "traceId": trace_ctx.trace_id,
                            "spanId": trace_ctx.span_id,
                        },
                        "instructions": (
                            "VCF Enterprise MCP: an UNOFFICIAL community project (not a Broadcom/VMware product) "
                            "that is UNDER TESTING. Tell the user this before any setup, and recommend the Digital Twin "
                            "or a non-production lab. "
                            + ("" if self._is_setup_complete() else
                               "Setup has not been completed: offer the user guided setup by calling the vcf_setup tool. ")
                            + (f"AUTHENTICATION PROBLEM: {auth_problem} " if auth_problem else "")
                            + self._identity_instructions(principal)
                            + "When the user asks what you can do, call vcf_access_report. If you are not sure which tool fits a request, call vcf_find_tool with the request in plain words and use the tool and example arguments it returns. "
                            + self._approval_instructions()
                            + "Never ask the user to type "
                              "passwords, API keys or tokens into the chat; vcf_setup collects them on a private local page."
                        ),
                    },
                }

            if method == "ping":
                return {"jsonrpc": "2.0", "id": req_id, "result": {}}

            # Stage 1: Pre-Discovery / Pre-Routing Tool Filtering
            # Enforces cacheScope=private so LLM/gateway never caches personalized catalog across users
            if method == "tools/list":
                all_tools = self._build_raw_tool_definitions()
                active_skill_name = params.get("skill")
                if not active_skill_name and headers:
                    active_skill_name = next(
                        (v for k, v in headers.items() if k.lower() == "mcp-active-skill"),
                        None,
                    )
                from_default = False
                if not active_skill_name:
                    # server.default_skill pre-prunes tools/list for harnesses (small local models) that never send a skill.
                    active_skill_name = getattr(getattr(self.config, "server", None), "default_skill", None)
                    from_default = bool(active_skill_name)
                skill_whitelist: Optional[List[str]] = None
                if active_skill_name:
                    skill_card = self.skill_registry.get_skill(active_skill_name)
                    if not skill_card and from_default:
                        active_skill_name = None  # a stale default never breaks the listing
                    elif not skill_card:
                        return {
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "error": {"code": -32602, "message": f"Role skill '{active_skill_name}' not found."},
                        }
                if active_skill_name:
                    effective_roles = self.pep.pdp.get_effective_roles_for_principal(principal)
                    if CapabilityRole.VCF_PLATFORM_ADMIN not in effective_roles and not any(
                        r in effective_roles for r in skill_card.all_authorized_roles
                    ):
                        if not from_default:
                            raise AuthorizationDeniedException(
                                f"Principal '{principal.user_id}' lacks required role for skill '{active_skill_name}'."
                            )
                        active_skill_name = None  # the default skill is not for this principal: show their normal list
                if active_skill_name:
                    skill_whitelist = list(skill_card.allowed_tools)
                    if from_default:
                        skill_whitelist += [t for t in ("vcf_setup", "vcf_access_report", "vcf_find_tool") if t not in skill_whitelist]

                visible_tools = self.pep.filter_visible_tools(
                    principal,
                    all_tools,
                    active_skill_allowed_tools=skill_whitelist,
                )
                current_epoch = self.pep.pdp.get_current_epoch()
                res_payload: Dict[str, Any] = {
                    "tools": visible_tools,
                    "cacheScope": "private",  # MANDATORY for principal-dependent tools/list
                    "cacheTtl": 60,           # Short TTL
                    "permissionEpoch": current_epoch,
                    "principal": principal.user_id,
                    "mode": self.pep.pdp.config.operating_mode,
                }
                if active_skill_name:
                    res_payload["activeSkill"] = active_skill_name
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": res_payload,
                }

            # MCP 2026-07-28 Prompts Extension: Role-Filtered Single-Task Skills
            if method == "prompts/list":
                effective_roles = self.pep.pdp.get_effective_roles_for_principal(principal)
                is_discovery_only = self.pep.pdp.config.operating_mode == "DISCOVERY_ONLY"
                visible_skills = self.skill_registry.get_skills_for_roles(
                    effective_roles,
                    discovery_only=is_discovery_only,
                )
                prompts = []
                if any(r in effective_roles for r in self.SETUP_ADMIN_ROLES):
                    prompts.append({
                        "name": "vcf_guided_setup",
                        "title": "Set up VCF Enterprise MCP",
                        "description": "Interactive, secure setup: goals, accounts, access check, safety choices.",
                        "arguments": [],
                    })
                for s in visible_skills:
                    desc = s.to_mcp_prompt_descriptor()
                    clean_desc = {k: v for k, v in desc.items() if not k.startswith("_")}
                    clean_desc["role"] = s.role.value
                    clean_desc["riskClass"] = s.risk_class.value
                    clean_desc["allowedTools"] = list(s.allowed_tools)
                    prompts.append(clean_desc)
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "prompts": prompts,
                        "cacheScope": "private",
                        "cacheTtl": 60,
                        "principal": principal.user_id,
                    },
                }

            if method == "prompts/get":
                prompt_name = params.get("name")
                prompt_args = params.get("arguments", {})
                if prompt_name == "vcf_guided_setup":
                    self._require_setup_admin(principal)
                    return {"jsonrpc": "2.0", "id": req_id, "result": {
                        "description": "Interactive, secure setup of VCF Enterprise MCP",
                        "messages": [{"role": "user", "content": {"type": "text", "text": (
                            "Help me set up VCF Enterprise MCP. Call the vcf_setup tool with no arguments and follow its "
                            "steps. If it returns questions instead of a form, ask me each one with your question UI "
                            "(offer the listed options), then call vcf_setup again with my answers and the 'resume' token. "
                            "Never ask me to type a password, API key or token in this chat; when vcf_setup gives a private "
                            "link or a terminal command for credentials, show it to me and wait until I say I'm done. "
                            "When setup finishes, explain plainly what you can and cannot do, repeat every warning "
                            "(especially about local administrator accounts), and show which actions are switched off.")}}],
                    }}
                skill_card = self.skill_registry.get_skill(prompt_name or "")
                if not skill_card:
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {"code": -32602, "message": f"Prompt / Role Skill '{prompt_name}' not found."},
                    }
                effective_roles = self.pep.pdp.get_effective_roles_for_principal(principal)
                if CapabilityRole.VCF_PLATFORM_ADMIN not in effective_roles and not any(
                    r in effective_roles for r in skill_card.all_authorized_roles
                ):
                    raise AuthorizationDeniedException(
                        f"Principal '{principal.user_id}' lacks authorization for role skill '{prompt_name}'."
                    )
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": skill_card.render_mcp_prompt_messages(prompt_args),
                }

            # MCP 2026-07-28 Resources Extension: Role-Scoped Plans, Skills & Audit Resources
            if method == "resources/list":
                effective_roles = self.pep.pdp.get_effective_roles_for_principal(principal)
                is_discovery_only = self.pep.pdp.config.operating_mode == "DISCOVERY_ONLY"
                visible_skills = self.skill_registry.get_skills_for_roles(
                    effective_roles,
                    discovery_only=is_discovery_only,
                )
                resources = [
                    {
                        "uri": "vcf://plans/pending",
                        "name": "Pending Execution Plans",
                        "description": "Pending and approved dry-run execution plans in the caller's tenant and environment.",
                        "mimeType": "application/json",
                    },
                    {
                        "uri": "vcf://skills/catalog",
                        "name": "Authorized Single-Task Role Skills Catalog",
                        "description": "Role-filtered catalog of single-responsibility VCF operational skills and tool whitelists.",
                        "mimeType": "application/json",
                    },
                ]
                if any(
                    r in effective_roles
                    for r in (CapabilityRole.VCF_AUDITOR, CapabilityRole.SECURITY_ADMIN, CapabilityRole.VCF_PLATFORM_ADMIN)
                ):
                    resources.append({
                        "uri": "vcf://audit/status",
                        "name": "Cryptographic Audit Chain Status",
                        "description": "SHA-256 hash chain verification status and recent audit trail summary.",
                        "mimeType": "application/json",
                    })
                for s in visible_skills:
                    resources.append({
                        "uri": f"vcf://skills/{s.name}",
                        "name": f"SKILL.md — {s.title}",
                        "description": f"[{s.role.value}] {s.single_task_objective}",
                        "mimeType": "text/markdown",
                    })
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "resources": resources,
                        "cacheScope": "private",
                    },
                }

            if method == "resources/read":
                uri = params.get("uri", "")
                effective_roles = self.pep.pdp.get_effective_roles_for_principal(principal)
                if uri == "vcf://plans/pending":
                    plans = self.plan_manager.list_plans(principal)
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "contents": [
                                {
                                    "uri": uri,
                                    "mimeType": "application/json",
                                    "text": json.dumps({"plans": plans}, indent=2),
                                }
                            ]
                        },
                    }
                if uri == "vcf://skills/catalog":
                    visible_skills = self.skill_registry.get_skills_for_roles(effective_roles)
                    catalog_data = [s.to_mcp_prompt_descriptor() for s in visible_skills]
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "contents": [
                                {
                                    "uri": uri,
                                    "mimeType": "application/json",
                                    "text": json.dumps({"skills": catalog_data}, indent=2),
                                }
                            ]
                        },
                    }
                if uri == "vcf://audit/status":
                    if not any(
                        r in effective_roles
                        for r in (CapabilityRole.VCF_AUDITOR, CapabilityRole.SECURITY_ADMIN, CapabilityRole.VCF_PLATFORM_ADMIN)
                    ):
                        raise AuthorizationDeniedException("Audit chain resource requires VCF_AUDITOR, SECURITY_ADMIN, or VCF_PLATFORM_ADMIN.")
                    valid, msg = self.task_store.durable.verify_audit_chain_integrity()
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "contents": [
                                {
                                    "uri": uri,
                                    "mimeType": "application/json",
                                    "text": json.dumps({"integrity_verified": valid, "message": msg}, indent=2),
                                }
                            ]
                        },
                    }
                if uri.startswith("vcf://skills/"):
                    skill_name = uri[len("vcf://skills/"):]
                    skill_card = self.skill_registry.get_skill(skill_name)
                    if not skill_card:
                        return {
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "error": {"code": -32602, "message": f"Skill resource '{uri}' not found."},
                        }
                    if CapabilityRole.VCF_PLATFORM_ADMIN not in effective_roles and not any(
                        r in effective_roles for r in skill_card.all_authorized_roles
                    ):
                        raise AuthorizationDeniedException(
                            f"Principal '{principal.user_id}' lacks authorization for skill resource '{uri}'."
                        )
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "contents": [
                                {
                                    "uri": uri,
                                    "mimeType": "text/markdown",
                                    "text": skill_card.to_skill_markdown(),
                                }
                            ]
                        },
                    }
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32602, "message": f"Resource URI '{uri}' not found."},
                }

            # Enterprise extension: list execution plans in caller's tenant/environment
            if method == "enterprise/plans/list":
                status_filter = params.get("status")
                plans = self.plan_manager.list_plans(principal, status=status_filter)
                return {"jsonrpc": "2.0", "id": req_id, "result": {"plans": plans, "count": len(plans)}}

            # Enterprise extension: get execution plan details (includes initiator approval/nonce handback)
            if method == "enterprise/plans/get":
                plan_id = params.get("plan_id")
                if not plan_id:
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {"code": -32602, "message": "Missing required 'plan_id' parameter."},
                    }
                plan_details = self.plan_manager.get_plan(plan_id, principal)
                return {"jsonrpc": "2.0", "id": req_id, "result": plan_details}

            # Enterprise extension: obtain authorization from a separate authenticated approver.
            if method == "enterprise/plans/approve":
                if self.personal_principal is not None:
                    raise AuthorizationDeniedException(
                        "In personal access mode the person approves plans themselves: in the chat prompt, on the local approval link, "
                        "or with `vcf-mcp plans approve <plan_id>` in their own terminal.")
                roles = self.pep.pdp.get_effective_roles_for_principal(principal)
                lab_self_approve = (
                    os.environ.get("VCF_LAB_SELF_APPROVE", "").lower() in ("true", "1", "yes")
                    and os.environ.get("VCF_MCP_ENV", "development").lower() != "production"
                )
                from vcf_enterprise_mcp.workflows.execution_plans import PLAN_APPROVER_ROLES
                approver_roles = set(PLAN_APPROVER_ROLES)
                if not lab_self_approve and not any(r in approver_roles for r in roles):
                    raise AuthorizationDeniedException("Plan approval requires a platform or domain administrator.")
                if self.pep.pdp.config.operating_mode in ("DISABLED", "READ_ONLY", "DISCOVERY_ONLY"):
                    raise AuthorizationDeniedException("Plan approvals are disabled in the current operating mode.")
                approval = self.plan_manager.approve_plan(params.get("plan_id"), principal)
                return {"jsonrpc": "2.0", "id": req_id, "result": approval.to_dict()}

            # Stage 2: Pre-Execution Tool Call Gate
            # Tool failures (validation, approval, policy, upstream) come back as a CallToolResult with
            # isError=true so the model can read the text and self-correct. JSON-RPC errors stay reserved
            # for protocol problems (unknown method, malformed request, bad token on discovery).
            if method == "tools/call":
                tool_name = params.get("name")
                arguments = params.get("arguments") or {}
                approved = params.get("approved", False)
                elicit_token = CLIENT_ELICITS.set(self._client_elicits(params))

                try:
                    if tool_name in ("vcf_setup", "vcf_access_report"):
                        result = await self._call_setup_tool(tool_name, principal, arguments, params, trace_ctx.trace_id)
                        return {"jsonrpc": "2.0", "id": req_id, "result": result}

                    if tool_name not in self.tool_instances:
                        return {
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "result": {
                                "isError": True,
                                "content": [{"type": "text", "text": f"Tool '{tool_name}' not found on control plane."}],
                            },
                        }

                    if self.setup_mode and tool_name not in self.SETUP_MODE_TOOLS:
                        return {"jsonrpc": "2.0", "id": req_id, "result": {
                            "isError": True,
                            "content": [{"type": "text", "text": (
                                "VCF Enterprise MCP has no VCF appliances configured yet, so '" + str(tool_name) + "' is not available. "
                                "Call vcf_setup (needs the MCP_ADMIN or VCF_PLATFORM_ADMIN role) to connect your appliances; "
                                "the tools appear as soon as setup completes.")}],
                        }}

                    req_cap = self.TOOL_CAPABILITY_MAP.get(tool_name)
                    if hasattr(self.platform, "registry") and self.platform.registry is not None:
                        if req_cap and not self.platform.registry.has_capability(req_cap):
                            return {"jsonrpc": "2.0", "id": req_id, "result": {
                                "isError": True,
                                "content": [{"type": "text", "text": (
                                    f"Tool '{tool_name}' is unavailable: the VCF component it needs ('{req_cap}') is not configured. "
                                    "Run vcf_setup to add it (or set the matching vcf.*_url in the config file).")}],
                            }}

                    tool = self.tool_instances[tool_name]
                    if self._needs_personal_gate(tool, arguments):
                        arguments, early = await self._personal_gate(tool, tool_name, principal, arguments, params)
                        if early is not None:
                            return {"jsonrpc": "2.0", "id": req_id, "result": early}
                    result = await tool.execute(
                        principal=principal,
                        arguments=arguments,
                        approved=approved,
                        agent_info=params.get("agent_info"),
                        trace_id=trace_ctx.trace_id,
                    )
                except VCFEnterpriseException as tool_exc:
                    return {"jsonrpc": "2.0", "id": req_id, "result": self._tool_error_result(tool_exc, tool_name=tool_name)}
                finally:
                    CLIENT_ELICITS.reset(elicit_token)

                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(result, indent=2)}],
                        "isError": False,
                    },
                }

            # MCP 2026-07-28 Discover Extension: server/discover
            if method == "server/discover":
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "protocolVersion": "2026-07-28",
                        "serverInfo": {
                            "name": "vcf-enterprise-mcp-control-plane",
                            "title": "VCF Enterprise MCP (unofficial)",
                            "version": "1.0.0",
                            "websiteUrl": "https://github.com/abhishekaryan23/vcf-ent-mcp",
                        },
                        "capabilities": {
                            "tools": {"listChanged": True},
                            "tasks": {"cancel": {}, "requests": {"tools": {"call": {}}}},  # no "list": tasks/list is not offered (cross-user leakage)
                            "resources": {},
                            "prompts": {},
                        },
                    },
                }

            # MCP 2026-07-28 Tasks Extension: tasks/get
            if method == "tasks/get":
                task_id = params.get("taskId") or params.get("task_id")
                if not task_id:
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {"code": -32602, "message": "Missing required 'taskId' parameter."},
                    }
                task = self.task_store.get_task(task_id, principal)
                return {"jsonrpc": "2.0", "id": req_id, "result": task.to_mcp_dict()}

            # MCP 2026-07-28 Tasks Extension: tasks/update
            if method == "tasks/update":
                task_id = params.get("taskId") or params.get("task_id")
                task = self.task_store.get_task(task_id, principal)
                # F18: Separate inspect vs update authority; only task creator or platform admin may update
                effective_roles = self.pep.pdp.get_effective_roles_for_principal(principal)
                is_admin = CapabilityRole.VCF_PLATFORM_ADMIN in effective_roles or CapabilityRole.COMPUTE_ADMIN in effective_roles
                is_owner = (getattr(task, "initiator_id", "") or getattr(task, "creator", "")) == principal.user_id
                if not (is_admin or is_owner):
                    raise AuthorizationDeniedException(
                        f"Principal '{principal.user_id}' lacks authorization to update task '{task_id}'."
                    )
                step = params.get("step", 1)
                desc = params.get("stepDescription", "Step updated")
                # F03: Sanitize task description canary/secrets
                clean_desc = self.redactor.redact_freeform_text(desc) if hasattr(self.redactor, "redact_freeform_text") else desc
                status = params.get("status", "RUNNING")
                updated_task = self.task_store.update_task_progress(task_id, step, clean_desc, status=status)
                return {"jsonrpc": "2.0", "id": req_id, "result": updated_task.to_mcp_dict()}

            # MCP 2026-07-28 Tasks Extension: tasks/cancel
            if method == "tasks/cancel":
                task_id = params.get("taskId") or params.get("task_id")
                cancel_res = self.task_store.cancel_task(task_id, principal)
                return {"jsonrpc": "2.0", "id": req_id, "result": cancel_res}

            # MCP 2026-07-28 Subscriptions Extension: subscriptions/listen
            if method == "subscriptions/listen":
                topic = params.get("topic", "notifications/tools/list_changed")
                # Return confirmed subscription handle
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "subscribed": True,
                        "topic": topic,
                        "subscriber": principal.user_id,
                    },
                }

            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Method '{method}' not found"},
            }

        except VCFEnterpriseException as ve:
            raw_err = ve.to_rpc_error()
            clean_err = self.redactor.redact_secrets_from_data(raw_err)
            return {"jsonrpc": "2.0", "id": req_id, "error": clean_err}
        except Exception as e:
            err_id = f"ERR-{uuid.uuid4().hex[:8].upper()}"
            import traceback
            from vcf_enterprise_mcp.auth.untrusted import sanitize_freeform_string
            clean_msg = sanitize_freeform_string(str(e))
            clean_tb = sanitize_freeform_string(traceback.format_exc())
            logger.error("Internal Control Plane Error [%s]: %s\n%s", err_id, clean_msg, clean_tb)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32603, "message": f"Internal Control Plane Error [{err_id}]: An unexpected error occurred."},
            }
        finally:
            set_current_trace_context(None)
