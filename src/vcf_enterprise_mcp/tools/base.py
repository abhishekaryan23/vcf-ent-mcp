# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Base Enterprise MCP Tool Class.
Enforces the complete enterprise execution lifecycle:
PLAN -> AUTHORIZE -> IDEMPOTENCY -> LEASE -> EXECUTE -> VERIFY -> SANITIZE -> AUDIT.
Guarantees at-least-once delivery with idempotent mutation safety, concurrency leasing,
and postcondition state verification.
"""

from __future__ import annotations
import hashlib
import json
import os
import uuid
from typing import Dict, Any, Optional, List
from vcf_enterprise_mcp.auth.identity import Principal
from vcf_enterprise_mcp.policy.models import RiskClass, CapabilityRole, NormalizedCapability
from vcf_enterprise_mcp.policy.enforcement import PolicyEnforcementPoint
from vcf_enterprise_mcp.audit.recorder import AuditRecorder
from vcf_enterprise_mcp.auth.credential_broker import CredentialBroker
from vcf_enterprise_mcp.state.durable_store import DurableStore
from vcf_enterprise_mcp.auth.untrusted import (
    sanitize_and_classify_payload,
    sanitize_for_external_output,
    sanitize_freeform_string,
)
from vcf_enterprise_mcp.state.leases import ResourceLeaseManager
from vcf_enterprise_mcp.core.errors import (
    IdempotencyConflictException,
    PostconditionFailedException,
    ApprovalRequiredException,
    VCFEnterpriseException,
    KnownIssueBlockedException,
    VersionMismatchException,
    ScopeViolationException,
    AuthorizationDeniedException,
)
from vcf_enterprise_mcp.workflows.execution_plans import ExecutionPlanManager
from vcf_enterprise_mcp.adapter.platform import PlatformClient
from vcf_enterprise_mcp.adapter.models import ExecutionIntent, ReconciliationStatus
from vcf_enterprise_mcp.router.known_issues import KnownIssueRegistry
from vcf_enterprise_mcp.core.schema_validator import validate_tool_arguments
from vcf_enterprise_mcp.router.catalog import get_tool_card_by_name
from vcf_enterprise_mcp.core.headers import get_current_trace_context


class BaseEnterpriseTool:
    """Base class for all scoped enterprise VCF MCP tools."""

    name: str = "base_tool"
    level: str = "L1_QUERY"
    risk_class: RiskClass = RiskClass.READ
    required_roles: list[CapabilityRole] = [CapabilityRole.VCF_VIEWER]
    required_capability: Optional[NormalizedCapability] = None
    subsystem: str = "vcenter"

    def __init__(
        self,
        pep: Optional[PolicyEnforcementPoint] = None,
        audit_recorder: Optional[AuditRecorder] = None,
        redactor: Optional[CredentialBroker] = None,
        durable_store: Optional[DurableStore] = None,
        plan_manager: Optional[ExecutionPlanManager] = None,
        tenant_id: str = "tenant-default",
        platform_client: Optional[PlatformClient] = None,
        known_issue_registry: Optional[KnownIssueRegistry] = None,
    ):
        self.durable = durable_store or DurableStore()
        self.tenant_id = tenant_id
        self.redactor = redactor or CredentialBroker()
        self.audit = audit_recorder or AuditRecorder(redactor=self.redactor, durable_store=self.durable)
        self.pep = pep or PolicyEnforcementPoint()
        self.lease_mgr = ResourceLeaseManager(self.durable, tenant_id=self.tenant_id)
        self.platform = platform_client or PlatformClient()
        self.plan_manager = plan_manager or ExecutionPlanManager(durable_store=self.durable, platform_client=self.platform)
        self.known_issues = known_issue_registry or KnownIssueRegistry()

    def get_tool_meta(self) -> Dict[str, Any]:
        return {
            "risk_class": self.risk_class,
            "required_roles": self.required_roles,
            "required_capability": self.required_capability,
            "level": self.level,
        }

    async def execute(
        self,
        principal: Principal,
        arguments: Dict[str, Any],
        approved: bool = False,
        agent_info: Optional[Dict[str, Any]] = None,
        trace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Lifecycle:
        1. Authorize via PEP (scopes, roles, clearance)
        2. Plan & Approval Validation Gate (for operations requiring approval)
        3. Idempotency Check (same key -> cached result; changed args -> conflict)
        4. Concurrency Lease (exclusive lock on resource for mutating tools)
        5. Execute Dry-Run or Live
        6. Postcondition Verification (never assume HTTP 200 = desired state)
        7. Untrusted Data Sanitization & Classification (anti-prompt injection)
        8. Audit Logging (hash-chained record)
        """
        dry_run = arguments.get("dry_run", False)
        idempotency_key = arguments.get("idempotency_key")

        # 0. Strict Schema Validation Gate (Finding F10)
        card = get_tool_card_by_name(self.name)
        schema = getattr(self, "schema", card.schema if card else None)
        validate_tool_arguments(self.name, arguments, schema)

        # Dynamic Tenant and Environment Binding (Finding F02)
        caller_tenant = principal.tenant_id or self.tenant_id or "tenant-default"
        caller_env = (principal.environment_ids[0] if getattr(principal, "environment_ids", None) else None) or getattr(principal, "environment_id", None) or "env-prod"
        self.tenant_id = caller_tenant

        # Auto-resolve cluster_id and domain_id for target resource if missing (Finding F02 / R02)
        vm_id = arguments.get("vm_id")
        if vm_id and hasattr(self, "platform") and self.platform:
            try:
                vm_info = self.platform.get_vm(vm_id)
                if isinstance(vm_info, dict):
                    cur_cluster = vm_info.get("cluster_id") or vm_info.get("cluster")
                    if arguments.get("cluster_id") and cur_cluster and arguments["cluster_id"] != cur_cluster:
                        raise ScopeViolationException(
                            f"Resource scope mismatch: VM '{vm_id}' is located in cluster '{cur_cluster}', but caller asserted '{arguments['cluster_id']}'. Forgery rejected."
                        )
                    if cur_cluster:
                        arguments["cluster_id"] = cur_cluster

                    cur_domain = vm_info.get("domain_id") or vm_info.get("domain")
                    if arguments.get("domain_id") and cur_domain and arguments["domain_id"] != cur_domain:
                        raise ScopeViolationException(
                            f"Resource scope mismatch: VM '{vm_id}' is located in domain '{cur_domain}', but caller asserted '{arguments['domain_id']}'. Forgery rejected."
                        )
                    if cur_domain:
                        arguments["domain_id"] = cur_domain

                    # Resource tenant/environment ownership check (R02)
                    res_tenant = vm_info.get("tenant_id")
                    if res_tenant and res_tenant != caller_tenant and caller_tenant != "*":
                        raise ScopeViolationException(
                            f"Cross-tenant access violation: VM '{vm_id}' belongs to tenant '{res_tenant}', caller is '{caller_tenant}'."
                        )
                    res_env = vm_info.get("environment_id")
                    if res_env and res_env != caller_env and caller_env != "*":
                        raise ScopeViolationException(
                            f"Cross-environment access violation: VM '{vm_id}' belongs to environment '{res_env}', caller is '{caller_env}'."
                        )
            except ScopeViolationException as sve:
                if hasattr(self.audit, "record_denied_call"):
                    self.audit.record_denied_call(
                        principal=principal,
                        tool_name=self.name,
                        arguments=arguments,
                        reason=str(sve),
                        action_type=self.risk_class.value,
                        tenant_id=caller_tenant,
                        environment_id=caller_env,
                        agent_info=agent_info,
                        dry_run=dry_run,
                        trace_id=trace_id,
                    )
                raise
            except Exception:
                pass

        # 1. Authorize via PEP
        try:
            decision = self.pep.authorize_execution(
                principal=principal,
                tool_name=self.name,
                arguments=arguments,
                tool_meta=self.get_tool_meta(),
                approved=approved,
            )
        except (AuthorizationDeniedException, ScopeViolationException, ApprovalRequiredException) as auth_err:
            if hasattr(self.audit, "record_denied_call"):
                self.audit.record_denied_call(
                    principal=principal,
                    tool_name=self.name,
                    arguments=arguments,
                    reason=str(auth_err),
                    action_type=self.risk_class.value,
                    tenant_id=caller_tenant,
                    environment_id=caller_env,
                    agent_info=agent_info,
                    dry_run=dry_run,
                    trace_id=trace_id,
                )
            raise

        # A completed response may be read again without consuming a second nonce.
        # Authorization and tenant/environment/resource checks still run first.
        if idempotency_key and not dry_run:
            cached = self.durable.get_idempotency_record(caller_tenant, idempotency_key, environment_id=caller_env)
            if cached:
                clean = {k: v for k, v in arguments.items() if k not in ("dry_run", "approval_token", "plan_id", "approval_id", "nonce", "signed_auth", "idempotency_key")}
                digest = hashlib.sha256(json.dumps(clean, sort_keys=True).encode()).hexdigest()
                if cached["args_sha256"] != digest or cached["principal_id"] != principal.user_id or cached["tool_id"] != self.name:
                    raise IdempotencyConflictException("Idempotency key previously recorded with different arguments hash, principal or tool.")
                if cached.get("status") == "COMMITTED":
                    return cached["response"]

        # Plan & Approval Validation Gate (Finding F11 / R05)
        # All live mutations independently require a validated execution plan
        requires_plan = self.risk_class != RiskClass.READ or decision.approval_required
        validated_plan = None
        if requires_plan and not dry_run:
            plan_id = arguments.get("plan_id")
            approval_id = arguments.get("approval_id")
            nonce = arguments.get("nonce")
            signed_auth = arguments.get("signed_auth")

            if not plan_id:
                raise ApprovalRequiredException(
                    f"Tool '{self.name}' ({self.risk_class.value}) requires an execution plan (plan_id). Run with dry_run=True first to generate a deterministic execution plan.",
                    details={"tool": self.name, "approval_required": decision.approval_required, "requires_plan": True},
                )

            if decision.approval_required:
                if not (approval_id and nonce):
                    raise ApprovalRequiredException(
                        f"Tool '{self.name}' requires approved execution plan with plan_id, approval_id, and nonce.",
                        details={"tool": self.name, "approval_required": True},
                    )

            target_res_id = (
                arguments.get("vm_id")
                or arguments.get("cluster_id")
                or arguments.get("domain_id")
                or arguments.get("resource_id")
            )
            target_resources = [target_res_id] if target_res_id else []

            plan_mgr = self.plan_manager or ExecutionPlanManager(
                durable_store=self.durable,
                tenant_id=caller_tenant,
            )
            validated_plan = plan_mgr.validate_plan_for_execution(
                plan_id=plan_id,
                approval_id=approval_id,
                nonce=nonce,
                current_arguments=arguments,
                caller=principal,
                signed_auth=signed_auth,
                expected_tool_id=self.name,
                target_resource_ids=target_resources if target_resources else None,
            )

        # 2. Idempotency Check & Lost-Response Protection (P1-1, F05)
        clean_args = {k: v for k, v in arguments.items() if k not in ["dry_run", "approval_token", "plan_id", "approval_id", "nonce", "signed_auth", "idempotency_key"]}
        args_hash = hashlib.sha256(json.dumps(clean_args, sort_keys=True).encode("utf-8")).hexdigest()
        intent_id = f"intent-{idempotency_key}" if idempotency_key else ""

        target_res_id = (
            arguments.get("vm_id")
            or arguments.get("cluster_id")
            or arguments.get("domain_id")
            or arguments.get("resource_id")
        )

        is_reconciled_retry = False
        if idempotency_key and not dry_run:
            cached_record = self.durable.get_idempotency_record(caller_tenant, idempotency_key, environment_id=caller_env)
            if cached_record:
                if cached_record["args_sha256"] != args_hash:
                    raise IdempotencyConflictException(
                        f"Idempotency conflict: Key '{idempotency_key}' previously recorded with different arguments hash."
                    )
                cached_status = cached_record.get("status", "COMMITTED")
                if cached_status == "COMMITTED":
                    return cached_record["response"]
                elif cached_status == "PENDING":
                    # Prior run was in-flight, crashed, or response was lost! Reconcile with upstream provider.
                    intent = ExecutionIntent(
                        intent_id=intent_id,
                        workflow_id=idempotency_key,
                        step_id="tool_execution",
                        target_resource=str(target_res_id or self.name),
                        operation_id=self.name,
                        desired_state=clean_args,
                        tenant_id=caller_tenant,
                    )
                    reconcile_res = self.platform.reconcile_operation_sync(intent)
                    if reconcile_res.status == ReconciliationStatus.APPLIED:
                        # Mutation was already applied upstream! Recover response and commit idempotency
                        recovered_response = cached_record.get("response") or {}
                        if not recovered_response or recovered_response.get("status") == "PENDING":
                            recovered_response = {
                                "status": "SUCCESS",
                                "message": f"Operation '{self.name}' already applied upstream prior to reconnect/retry.",
                                "reconciled": True,
                                "details": reconcile_res.details,
                            }
                        self.durable.record_idempotency(
                            tenant_id=caller_tenant,
                            idempotency_key=idempotency_key,
                            principal_id=principal.user_id,
                            tool_id=self.name,
                            args_sha256=args_hash,
                            response_payload=recovered_response,
                            status="COMMITTED",
                            environment_id=caller_env,
                        )
                        self.durable.resolve_execution_intent(
                            tenant_id=caller_tenant,
                            environment_id=caller_env,
                            intent_id=intent_id,
                            outcome="APPLIED_ON_RECONCILIATION",
                            state="RESOLVED",
                        )
                        return recovered_response
                    elif reconcile_res.status == ReconciliationStatus.IN_PROGRESS:
                        raise IdempotencyConflictException(
                            f"Operation for idempotency key '{idempotency_key}' is still in progress upstream. Please check status later."
                        )
                    elif reconcile_res.status == ReconciliationStatus.UNKNOWN:
                        raise VCFEnterpriseException(
                            f"Indeterminate remote state during reconciliation for idempotency key '{idempotency_key}'. Manual intervention required.",
                            error_code=-32014,
                        )
                    # If NOT_APPLIED or FAILED, fall through to allow safe retry of the execution
                    is_reconciled_retry = True

        # Check Known Issue Registry and Supported Version Baseline for mutating operations (P2-3, F07)
        if self.risk_class != RiskClass.READ and not dry_run:
            subsystem = getattr(self, "subsystem", None)
            if not subsystem:
                if "nsx" in self.name or "segment" in self.name:
                    subsystem = "nsx"
                elif "sddc" in self.name or "domain" in self.name or "bundle" in self.name or "host" in self.name:
                    subsystem = "sddc_manager"
                elif "health" in self.name or "telemetry" in self.name or "ops" in self.name:
                    subsystem = "vcf_operations"
                else:
                    subsystem = "vcenter"

            comp_ver = "9.1.1"
            if hasattr(self.platform, "version_adapter") and hasattr(self.platform.version_adapter, "get_component_version"):
                comp_ver = self.platform.version_adapter.get_component_version(subsystem)
                if hasattr(self.platform.version_adapter, "is_supported_baseline"):
                    if not self.platform.version_adapter.is_supported_baseline(comp_ver):
                        raise VersionMismatchException(
                            f"Unsupported VCF version '{comp_ver}' for subsystem '{subsystem}'. Fail-closed: mutations blocked on unknown or unverified version baselines."
                        )

            blocking_issues = self.known_issues.check_operation_safety(
                component=subsystem,
                version=comp_ver,
                tool_name=self.name,
                arguments=arguments,
            )
            if blocking_issues:
                issue = blocking_issues[0]
                raise KnownIssueBlockedException(
                    issue_id=issue.id,
                    title=issue.title,
                    details={
                        "component": issue.component,
                        "version": comp_ver,
                        "workaround": issue.workaround,
                        "source": issue.source.source_id,
                        "confidence": issue.confidence.value,
                    },
                )

        # 3. Concurrency Lease and Correlated Audit Record (F22)
        current_trace = get_current_trace_context()
        effective_trace_id = trace_id or (current_trace.trace_id if current_trace else None)
        audit_rec = self.audit.record_call(
            principal=principal,
            tool_name=self.name,
            arguments=arguments,
            decision=decision,
            agent_info=agent_info,
            dry_run=dry_run,
            trace_id=effective_trace_id,
        )

        # Pre-mutation idempotency record and execution intent (P1-1, F05, R03)
        if idempotency_key and not dry_run and self.risk_class != RiskClass.READ:
            if not is_reconciled_retry:
                claim_res = self.durable.record_idempotency(
                    tenant_id=caller_tenant,
                    idempotency_key=idempotency_key,
                    principal_id=principal.user_id,
                    tool_id=self.name,
                    args_sha256=args_hash,
                    response_payload={"status": "PENDING", "stage": "DISPATCHING_MUTATION"},
                    status="PENDING",
                    environment_id=caller_env,
                )
                if claim_res and isinstance(claim_res, dict) and claim_res.get("status") == "COMMITTED":
                    # Concurrent committed race resolved: Another worker committed during this request's execution window!
                    # Return the already-committed response to prevent duplicate dispatch.
                    return claim_res.get("response") or claim_res
            self.durable.record_execution_intent(
                tenant_id=caller_tenant,
                environment_id=caller_env,
                intent_id=intent_id,
                workflow_id=idempotency_key,
                step_id="tool_execution",
                target_resource=str(target_res_id or self.name),
                operation_id=self.name,
                desired_state=clean_args,
                state="EXECUTION_INTENT_RECORDED",
            )

        def recheck_execution_boundary():
            self.pep.authorize_execution(principal, self.name, arguments, self.get_tool_meta(), approved=approved)
            if validated_plan is not None:
                epoch = self.durable.get_permission_epoch(caller_tenant, caller_env)
                if epoch != validated_plan["permission_epoch"]:
                    raise AuthorizationDeniedException("Permission revoked before provider dispatch.")

        try:
            if dry_run:
                raw_result = await self.run_dry_run(principal, arguments)
                # A refused or invalid dry run gets no approvable plan.
                if self.risk_class != RiskClass.READ and not raw_result.get("plan_id") and raw_result.get("allowed", True) is not False:
                    # Only real infrastructure ids are revision-checked. Tools without an infrastructure target
                    # (Orchestrator, Assembler, integrations) have their own concurrency checks (changeset sha).
                    real_target = target_res_id or arguments.get("segment_name")
                    plan = self.plan_manager.create_dry_run_plan(
                        principal, self.name, arguments, raw_result.copy(),
                        [str(real_target)] if real_target else [], self.risk_class)
                    for k in ("plan_id", "canonical_plan_hash", "approval_required", "approvals_required", "approval_id", "nonce", "status", "how_to_approve"):
                        if k in plan:
                            raw_result[k] = plan[k]
                if raw_result.get("plan_id") and self.risk_class != RiskClass.READ and "how_to_approve" not in raw_result:
                    # Plans created inside a tool's own dry run (operational and workflow tools) carry the same hand-off instructions.
                    personal = getattr(self.plan_manager, "personal", None) is not None
                    if personal or raw_result.get("approval_required"):
                        if personal:  # every change needs the person's one confirmation
                            raw_result["approval_required"] = True
                            raw_result["approvals_required"] = 1
                        raw_result["how_to_approve"] = self.plan_manager.how_to_approve_for(raw_result["plan_id"], self.risk_class, principal)
            else:
                # Acquire exclusive lease if target resource exists and action is mutating
                # Unique execution lease owner across processes (F05)
                execution_lease_holder = f"{principal.user_id}:{os.getpid()}:{uuid.uuid4().hex[:8]}"
                if target_res_id and self.risk_class != RiskClass.READ:
                    with self.lease_mgr.lease(target_res_id, lease_holder=execution_lease_holder, ttl_seconds=30.0):
                        recheck_execution_boundary()
                        raw_result = await self.run_live(principal, arguments)
                        # Postcondition Verification
                        post_ok, post_msg = await self.verify_postcondition(principal, arguments, raw_result)
                        if not post_ok:
                            raise PostconditionFailedException(
                                f"Postcondition verification failed for tool '{self.name}': {post_msg}"
                            )
                else:
                    recheck_execution_boundary()
                    raw_result = await self.run_live(principal, arguments)

            # 6. Sanitize untrusted infrastructure strings & classify fields
            sanitized_result = sanitize_and_classify_payload(raw_result)
            clean_result = self.redactor.redact_secrets_from_data(sanitized_result)

            # Save idempotency record on successful live mutation as COMMITTED
            if idempotency_key and not dry_run:
                self.durable.record_idempotency(
                    tenant_id=caller_tenant,
                    idempotency_key=idempotency_key,
                    principal_id=principal.user_id,
                    tool_id=self.name,
                    args_sha256=args_hash,
                    response_payload=clean_result,
                    status="COMMITTED",
                    environment_id=caller_env,
                )
                if intent_id:
                    self.durable.resolve_execution_intent(
                        tenant_id=caller_tenant,
                        environment_id=caller_env,
                        intent_id=intent_id,
                        outcome="COMMITTED",
                        state="RESOLVED",
                    )

            # 7. Finalize audit
            self.audit.finalize_record(
                audit_rec,
                status="SUCCESS",
                summary=f"Tool '{self.name}' executed successfully (dry_run={dry_run}).",
                vcf_task_id=clean_result.get("task_id"),
            )
            return clean_result

        except Exception as e:
            if idempotency_key and not dry_run and intent_id:
                try:
                    self.durable.resolve_execution_intent(
                        tenant_id=caller_tenant,
                        environment_id=caller_env,
                        intent_id=intent_id,
                        outcome=f"ERROR: {str(e)}",
                        state="FAILED",
                    )
                except Exception:
                    pass
            clean_err = sanitize_freeform_string(str(e))
            self.audit.finalize_record(audit_rec, status="FAILED", error=clean_err)
            raise

    async def run_dry_run(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "dry_run": True,
            "simulation": f"Dry-run simulation for {self.name}",
            "status": "VALIDATED",
        }

    async def run_live(self, principal: Principal, arguments: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError

    async def verify_postcondition(
        self,
        principal: Principal,
        arguments: Dict[str, Any],
        execution_result: Dict[str, Any],
    ) -> tuple[bool, str]:
        """
        Verifies that actual infrastructure reached desired state after mutation.
        Default is True; mutating tools override with actual state inspections.
        """
        return True, "Desired state verified"
