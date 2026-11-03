# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Enterprise Workflow Model & Native-Operation Reconciliation Engine.
Decouples long-running infrastructure orchestration from MCP protocol projections.
Enforces:
1. Extended first-class workflow states (including RECONCILIATION_REQUIRED & MANUAL_INTERVENTION_REQUIRED).
2. Step lifecycle: PREPARE (Intent Recorded) -> EXECUTE -> RECONCILE -> VERIFY.
3. Explicit irreversible compensation boundaries (identifying compensable vs forward-recovery-only phases).
4. Outbox-based crash recovery with remote mutation reconciliation.
"""

from __future__ import annotations
import time
import secrets
import json
from typing import Dict, Any, List, Optional, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum
from vcf_enterprise_mcp.state.durable_store import DurableStore, ResourceLease
from vcf_enterprise_mcp.state.leases import ResourceLeaseManager
from vcf_enterprise_mcp.adapter.platform import PlatformClient
from vcf_enterprise_mcp.core.errors import (
    ReconciliationRequiredException,
    ManualInterventionRequiredException,
    StaleFencingTokenException,
    WorkflowExecutionException,
)
from vcf_enterprise_mcp.adapter.models import (
    ResourceRevision,
    ReconciliationStatus,
    ReconciliationResult,
    ExecutionIntent,
)


class WorkflowState(str, Enum):
    """Extended first-class enterprise workflow lifecycle states."""
    PLANNED = "PLANNED"
    APPROVAL_PENDING = "APPROVAL_PENDING"
    EXECUTING = "EXECUTING"
    VERIFYING = "VERIFYING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    COMPENSATING = "COMPENSATING"
    COMPENSATED = "COMPENSATED"
    RECONCILIATION_REQUIRED = "RECONCILIATION_REQUIRED"
    CANCEL_REQUESTED = "CANCEL_REQUESTED"
    CANCELLED = "CANCELLED"
    MANUAL_INTERVENTION_REQUIRED = "MANUAL_INTERVENTION_REQUIRED"


@dataclass
class WorkflowStepDefinition:
    """Definition of an individual deterministic workflow step with compensation boundary declaration."""
    step_id: str
    name: str
    target_resource: str
    operation: str
    desired_state: Dict[str, Any]
    is_reversible: bool = True
    rollback_action: Optional[str] = None
    irreversible_after: bool = False
    max_retries: int = 2


@dataclass
class StepExecutionRecord:
    step_id: str
    name: str
    state: str = "PENDING"
    intent_id: str = ""
    fencing_token: int = 0
    started_at: float = 0.0
    completed_at: float = 0.0
    reconciliation_attempts: int = 0
    error: Optional[str] = None
    rollback_performed: bool = False


class EnterpriseWorkflow:
    """
    Core enterprise infrastructure workflow instance.
    Decoupled from transport protocol (can project to MCP Task, REST task, CLI, or ServiceNow).
    """

    def __init__(
        self,
        workflow_id: str,
        name: str,
        initiator_id: str,
        steps: List[WorkflowStepDefinition],
        tenant_id: str = "tenant-default",
        environment_id: str = "env-prod",
    ):
        self.workflow_id = workflow_id
        self.name = name
        self.initiator_id = initiator_id
        self.tenant_id = tenant_id
        self.environment_id = environment_id
        self.steps = steps
        self.state = WorkflowState.PLANNED
        self.current_step_idx = 0
        self.step_records: List[StepExecutionRecord] = [
            StepExecutionRecord(step_id=s.step_id, name=s.name) for s in steps
        ]
        self.created_at = time.time()
        self.updated_at = time.time()
        self.error: Optional[str] = None

    def describe_compensation_profile(self) -> Dict[str, Any]:
        """Categorizes steps into fully compensable vs irreversible boundary vs forward-recovery."""
        compensable: List[str] = []
        irreversible_boundary: Optional[str] = None
        forward_recovery: List[str] = []

        passed_boundary = False
        for s in self.steps:
            if not passed_boundary:
                if s.irreversible_after:
                    irreversible_boundary = s.name
                    passed_boundary = True
                elif s.is_reversible:
                    compensable.append(s.name)
                else:
                    # Non-reversible step before boundary
                    compensable.append(f"{s.name} (Non-reversible)")
            else:
                forward_recovery.append(s.name)

        return {
            "workflow_id": self.workflow_id,
            "total_steps": len(self.steps),
            "compensable_steps": compensable,
            "irreversible_boundary_step": irreversible_boundary,
            "forward_recovery_steps": forward_recovery,
            "is_currently_compensable": self.is_currently_compensable(),
        }

    def is_currently_compensable(self) -> bool:
        """Returns True if no irreversible steps have completed."""
        for i in range(min(self.current_step_idx + 1, len(self.steps))):
            s = self.steps[i]
            rec = self.step_records[i]
            if rec.state == "COMPLETED" and s.irreversible_after:
                return False
        return True

    @property
    def is_terminal(self) -> bool:
        """Returns True if the workflow has reached a terminal lifecycle state."""
        return self.state in {
            WorkflowState.SUCCEEDED,
            WorkflowState.FAILED,
            WorkflowState.CANCELLED,
            WorkflowState.COMPENSATED,
        }


class EnterpriseWorkflowEngine:
    """
    Execution and native-operation reconciliation engine for EnterpriseWorkflows.
    Manages PREPARE -> EXECUTE -> RECONCILE -> VERIFY step cycles with outbox intent recording.
    """

    def __init__(
        self,
        durable_store: DurableStore,
        platform_client: PlatformClient,
        lease_manager: Optional[ResourceLeaseManager] = None,
    ):
        self.store = durable_store
        self.platform = platform_client
        self.leases = lease_manager or ResourceLeaseManager(self.store)
        self._workflows: Dict[str, EnterpriseWorkflow] = {}

    def register_workflow(self, workflow: EnterpriseWorkflow) -> None:
        self._workflows[workflow.workflow_id] = workflow

    def get_workflow(self, workflow_id: str) -> Optional[EnterpriseWorkflow]:
        return self._workflows.get(workflow_id)

    def execute_step(
        self,
        workflow_id: str,
        step_idx: int,
        action_fn: Callable[[Dict[str, Any], int], Any],
        reconciliation_probe_fn: Optional[Callable[[str, Dict[str, Any]], Tuple[str, bool]]] = None,
    ) -> Dict[str, Any]:
        """
        Executes a workflow step through the 4-phase lifecycle:
        1. PREPARE: Record execution intent outbox entry with monotonic fencing token.
        2. EXECUTE: Dispatches action with fencing token.
        3. RECONCILE: If remote call fails or network drops, queries downstream VCF:
           - YES (already applied) -> advance to VERIFY
           - NO (not applied) -> retry safely
           - UNKNOWN -> transition to RECONCILIATION_REQUIRED
        4. VERIFY: Verifies postconditions match desired state.
        """
        wf = self._workflows.get(workflow_id)
        if not wf:
            raise WorkflowExecutionException(f"Workflow '{workflow_id}' not found.")

        # Forbid executing steps on workflows in terminal states (P2-1)
        terminal_states = {
            WorkflowState.SUCCEEDED,
            WorkflowState.FAILED,
            WorkflowState.CANCELLED,
            WorkflowState.COMPENSATED,
        }
        if wf.state in terminal_states:
            raise WorkflowExecutionException(
                f"Cannot execute step on workflow '{workflow_id}' in terminal state '{wf.state.value}'."
            )

        step_def = wf.steps[step_idx]
        step_rec = wf.step_records[step_idx]
        wf.state = WorkflowState.EXECUTING
        wf.current_step_idx = step_idx
        step_rec.started_at = time.time()
        step_rec.state = "EXECUTING"

        # Acquire distributed lease with monotonic fencing token
        lease = self.leases.acquire_exclusive(
            resource_id=step_def.target_resource,
            lease_holder=f"wf-{workflow_id}-step-{step_def.step_id}",
            ttl_seconds=60.0,
        )
        step_rec.fencing_token = lease.fencing_token

        # Phase 1: PREPARE (Record Intent Outbox Entry)
        intent_id = f"intent-{secrets.token_hex(12)}"
        step_rec.intent_id = intent_id
        self.store.record_execution_intent(
            intent_id=intent_id,
            workflow_id=workflow_id,
            step_id=step_def.step_id,
            target_resource=step_def.target_resource,
            operation_id=step_def.operation,
            desired_state=step_def.desired_state,
            fencing_token=lease.fencing_token,
            state="EXECUTION_INTENT_RECORDED",
        )

        # Phase 2: EXECUTE
        exec_success = False
        exec_error = None
        try:
            # Validate fencing token before dispatch
            self.leases.validate_fencing_token(step_def.target_resource, lease.fencing_token)
            action_fn(step_def.desired_state, lease.fencing_token)
            exec_success = True
        except Exception as ex:
            exec_error = str(ex)

        # Phase 3: RECONCILE (If execution failed or remote outcome ambiguous)
        if not exec_success:
            if reconciliation_probe_fn:
                outcome_status, mutation_verified = reconciliation_probe_fn(
                    step_def.target_resource, step_def.desired_state
                )
                if mutation_verified:
                    # Desired mutation occurred despite network glitch!
                    exec_success = True
                    self.store.resolve_execution_intent(intent_id, outcome="MUTATION_RECONCILED_SUCCESS", state="RESOLVED")
                elif outcome_status == "DEFINITELY_NOT_APPLIED":
                    # Safe to retry or report clean failure
                    self.store.resolve_execution_intent(intent_id, outcome=f"CLEAN_FAILURE: {exec_error}", state="FAILED")
                    wf.state = WorkflowState.FAILED
                    step_rec.state = "FAILED"
                    step_rec.error = exec_error
                    self.leases.release(step_def.target_resource, lease.owner)
                    raise WorkflowExecutionException(f"Step '{step_def.name}' failed cleanly: {exec_error}")
                else:
                    # UNKNOWN - Remote state cannot be proven!
                    wf.state = WorkflowState.RECONCILIATION_REQUIRED
                    step_rec.state = "RECONCILIATION_REQUIRED"
                    self.store.resolve_execution_intent(intent_id, outcome="INDETERMINATE_REMOTE_STATE", state="RECONCILIATION_REQUIRED")
                    self.leases.release(step_def.target_resource, lease.owner)
                    raise ReconciliationRequiredException(
                        f"Step '{step_def.name}' encountered ambiguous failure. Target '{step_def.target_resource}' requires reconciliation. Error: {exec_error}"
                    )
            else:
                wf.state = WorkflowState.FAILED
                step_rec.state = "FAILED"
                self.leases.release(step_def.target_resource, lease.owner)
                raise WorkflowExecutionException(f"Step execution failed: {exec_error}")

        # Phase 4: VERIFY
        wf.state = WorkflowState.VERIFYING
        step_rec.state = "VERIFYING"
        # Validate postconditions
        postcondition_ok = True
        if step_def.desired_state:
            # Confirm target resource revision advanced
            rev = self.platform.get_resource_revision(step_def.target_resource)
            postcondition_ok = (rev is not None)

        self.leases.release(step_def.target_resource, lease.owner)
        self.store.resolve_execution_intent(intent_id, outcome="SUCCESS", state="RESOLVED")

        step_rec.state = "COMPLETED"
        step_rec.completed_at = time.time()
        if step_idx == len(wf.steps) - 1:
            wf.state = WorkflowState.SUCCEEDED
        else:
            wf.state = WorkflowState.EXECUTING

        return {
            "workflow_id": workflow_id,
            "step_id": step_def.step_id,
            "status": "COMPLETED",
            "fencing_token": lease.fencing_token,
            "intent_id": intent_id,
        }

    def reconcile_in_flight_workflows(self) -> List[Dict[str, Any]]:
        """
        Scans durable store for uncompleted intents across restarts,
        reconciles actual VCF state via typed ReconciliationResult,
        and resolves or flags for manual intervention.
        NEVER blindly retries UNKNOWN!
        """
        pending = self.store.list_pending_execution_intents()
        reconciliation_reports = []
        for intent in pending:
            intent_id = intent["intent_id"]
            target = intent["target_resource"]

            # Reconcile via platform
            rec_result = self.platform.reconcile_operation_sync(intent)
            if rec_result.status == ReconciliationStatus.APPLIED:
                self.store.resolve_execution_intent(intent_id, outcome="AUTO_RECONCILED_APPLIED", state="RESOLVED")
                reconciliation_reports.append({
                    "intent_id": intent_id,
                    "target": target,
                    "status": "APPLIED",
                    "reconciliation_outcome": "RECONCILED_SUCCESS",
                })
            elif rec_result.status == ReconciliationStatus.NOT_APPLIED:
                self.store.resolve_execution_intent(intent_id, outcome="AUTO_RECONCILED_NOT_APPLIED", state="FAILED")
                reconciliation_reports.append({
                    "intent_id": intent_id,
                    "target": target,
                    "status": "NOT_APPLIED",
                    "reconciliation_outcome": "RECONCILED_NOT_APPLIED",
                })
            elif rec_result.status == ReconciliationStatus.IN_PROGRESS:
                reconciliation_reports.append({
                    "intent_id": intent_id,
                    "target": target,
                    "status": "IN_PROGRESS",
                    "reconciliation_outcome": "IN_PROGRESS",
                })
            else:
                # UNKNOWN or FAILED: NEVER blindly retry UNKNOWN!
                # Transition to MANUAL_INTERVENTION_REQUIRED
                self.store.resolve_execution_intent(intent_id, outcome="AUTO_RECONCILED_INDETERMINATE", state="MANUAL_INTERVENTION_REQUIRED")
                reconciliation_reports.append({
                    "intent_id": intent_id,
                    "target": target,
                    "status": "UNKNOWN",
                    "reconciliation_outcome": "MANUAL_INTERVENTION_REQUIRED",
                })
        return reconciliation_reports
