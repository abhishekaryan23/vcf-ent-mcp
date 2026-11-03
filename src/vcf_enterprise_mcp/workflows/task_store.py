# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
MCP Tasks Extension Store (MCP 2026-07-28 Protocol).
Provides stateful, durable tracking of asynchronous infrastructure workflows with strict multi-tenant authorization,
high-entropy IDs, explicit compensation boundaries, cancellation, and event subscriptions.
Every task is bound to (tenant_id, environment_id) and protected from cross-tenant access.
"""

from __future__ import annotations
import time
import secrets
import json
from typing import Dict, Any, List, Optional, Set, Callable, Tuple
from dataclasses import dataclass, field
from vcf_enterprise_mcp.auth.identity import Principal
from vcf_enterprise_mcp.state.durable_store import DurableStore
from vcf_enterprise_mcp.core.errors import (
    TaskNotFoundException,
    AuthorizationDeniedException,
    WorkflowExecutionException,
)

TERMINAL_TASK_STATUSES = {
    "SUCCEEDED",
    "COMPLETED",
    "FAILED",
    "CANCELLED",
    "COMPENSATED",
}


@dataclass
class WorkflowStep:
    name: str
    is_reversible: bool = True
    rollback_action: Optional[str] = None
    irreversible_after: bool = False
    completed: bool = False


@dataclass
class MCPTask:
    """Task handle representing an asynchronous long-running infrastructure workflow."""
    task_id: str
    tool_name: str
    initiator_id: str
    tenant_id: str = "tenant-default"
    environment_id: str = "env-prod"
    status: str = "PENDING"  # PENDING, RUNNING, COMPLETED, FAILED, CANCELLED, SUCCEEDED, COMPENSATED
    progress_pct: float = 0.0
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    steps_total: int = 1
    current_step: int = 0
    step_description: str = "Task initialized"
    native_task_id: str = ""
    steps: List[WorkflowStep] = field(default_factory=list)
    impact_summary: Dict[str, Any] = field(default_factory=dict)
    approval_status: str = "NOT_REQUIRED"  # NOT_REQUIRED, PENDING_APPROVAL, APPROVED, REJECTED
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

    def to_mcp_dict(self) -> Dict[str, Any]:
        return {
            "taskId": self.task_id,
            "tool": self.tool_name,
            "initiator": self.initiator_id,
            "tenantId": self.tenant_id,
            "environmentId": self.environment_id,
            "status": self.status,
            "progress": round(self.progress_pct, 2),
            "step": f"{self.current_step}/{self.steps_total}: {self.step_description}",
            "nativeTaskId": self.native_task_id,
            "approvalStatus": self.approval_status,
            "impact": self.impact_summary,
            "isReversible": self.is_currently_reversible(),
            "result": self.result,
            "error": self.error,
            "createdAt": self.created_at,
            "updatedAt": self.updated_at,
        }

    def is_currently_reversible(self) -> bool:
        """Determines if the current workflow state can be safely compensated/rolled back."""
        for step in self.steps[:self.current_step]:
            if step.irreversible_after or not step.is_reversible:
                return False
        return True

    @property
    def is_terminal(self) -> bool:
        """Determines if the task has reached a terminal lifecycle state."""
        return self.status in TERMINAL_TASK_STATUSES


class TaskStore:
    """Manages creation, query, updating, and cancellation of MCP Task handles backed by DurableStore."""

    def __init__(self, durable_store: Optional[DurableStore] = None):
        self.durable = durable_store or DurableStore()
        # Keyed by (tenant_id, environment_id, task_id)
        self._memory_cache: Dict[Tuple[str, str, str], MCPTask] = {}
        self._subscribers: Dict[str, Set[Callable[[Dict[str, Any]], None]]] = {}

    def subscribe(self, topic: str, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Registers a listener for notifications."""
        self._subscribers.setdefault(topic, set()).add(callback)

    def unsubscribe(self, topic: str, callback: Callable[[Dict[str, Any]], None]) -> None:
        if topic in self._subscribers:
            self._subscribers[topic].discard(callback)

    def emit_notification(self, topic: str, payload: Dict[str, Any]) -> None:
        """Delivers real-time notifications to topic subscribers."""
        callbacks = list(self._subscribers.get(topic, []))
        if "/" in topic:
            parent_wildcard = topic.rsplit("/", 1)[0] + "/*"
            callbacks.extend(self._subscribers.get(parent_wildcard, []))

        for cb in callbacks:
            try:
                cb(payload)
            except Exception:
                pass

    def create_task(
        self,
        tool_name: str,
        principal: Principal,
        steps: Optional[List[WorkflowStep]] = None,
        approval_status: str = "NOT_REQUIRED",
        impact_summary: Optional[Dict[str, Any]] = None,
        native_task_id: str = "",
        tenant_id: Optional[str] = None,
        environment_id: Optional[str] = None,
    ) -> MCPTask:
        # High-entropy unguessable task ID
        entropy = secrets.token_urlsafe(24)
        task_id = f"task-{entropy}"
        step_objs = steps or [WorkflowStep(name="Execute operation", is_reversible=True)]

        # Bind strictly to principal's verified tenant and environment
        actual_tenant_id = principal.tenant_id if principal else (tenant_id or "tenant-default")
        actual_env_id = (
            principal.environment_ids[0]
            if principal and principal.environment_ids
            else (environment_id or "env-prod")
        )

        task = MCPTask(
            task_id=task_id,
            tool_name=tool_name,
            initiator_id=principal.user_id if principal else "system",
            tenant_id=actual_tenant_id,
            environment_id=actual_env_id,
            steps_total=len(step_objs),
            steps=step_objs,
            approval_status=approval_status,
            impact_summary=impact_summary or {},
            native_task_id=native_task_id,
        )
        self._memory_cache[(actual_tenant_id, actual_env_id, task_id)] = task

        # Persist to durable store
        self._persist_task(task)
        self.emit_notification(f"notifications/tasks/{task_id}", task.to_mcp_dict())
        return task

    def get_task(self, task_id: str, principal: Principal) -> MCPTask:
        """
        Retrieves task by ID. Enforces strict tenant isolation and caller authorization:
        Caller must belong to the same tenant as the task, and must be either the initiator
        or hold an administrative role within that tenant.
        """
        env_id = principal.environment_ids[0] if principal.environment_ids else "env-prod"
        key = (principal.tenant_id, env_id, task_id)

        task = self._memory_cache.get(key)
        if not task:
            row = self.durable.get_task(principal.tenant_id, env_id, task_id)
            if not row:
                raise TaskNotFoundException(
                    f"Task '{task_id}' not found in tenant '{principal.tenant_id}'."
                )
            task = self._task_from_db_row(row)
            self._memory_cache[key] = task

        # 1. Enforce Tenant Isolation Boundary
        if task.tenant_id != principal.tenant_id and not principal.is_system_operator:
            raise AuthorizationDeniedException(
                f"Tenant Isolation Violation: Caller in tenant '{principal.tenant_id}' cannot access task '{task_id}' in tenant '{task.tenant_id}'."
            )

        # 2. Caller authorization check within the tenant
        is_owner = (principal.user_id == task.initiator_id)
        is_admin = any(g in principal.corporate_groups for g in ["VCF-Platform-Admins", "VCF-Auditors", "corp-cloud-admins"])
        if not (is_owner or is_admin or principal.is_system_operator):
            raise AuthorizationDeniedException(
                f"Access denied: Caller '{principal.user_id}' is not authorized to inspect task '{task_id}'."
            )

        return task

    def update_task_progress(
        self,
        task_id: str,
        current_step: int,
        step_desc: str,
        status: str = "RUNNING",
        native_task_id: Optional[str] = None,
        principal: Optional[Principal] = None,
        tenant_id: Optional[str] = None,
        environment_id: Optional[str] = None,
    ) -> MCPTask:
        t_id = principal.tenant_id if principal else (tenant_id or "tenant-default")
        env_id = (
            principal.environment_ids[0]
            if principal and principal.environment_ids
            else (environment_id or "env-prod")
        )
        key = (t_id, env_id, task_id)

        task = self._memory_cache.get(key)
        if not task:
            row = self.durable.get_task(t_id, env_id, task_id)
            if not row:
                raise TaskNotFoundException(f"Task '{task_id}' not found in tenant '{t_id}'.")
            task = self._task_from_db_row(row)
            self._memory_cache[key] = task

        if task.is_terminal:
            raise WorkflowExecutionException(
                f"Cannot update task '{task_id}' in terminal state '{task.status}'."
            )

        task.current_step = current_step
        task.step_description = step_desc
        task.progress_pct = (current_step / max(task.steps_total, 1)) * 100.0
        task.status = status
        if native_task_id:
            task.native_task_id = native_task_id
        task.updated_at = time.time()

        self._persist_task(task)
        self.emit_notification(f"notifications/tasks/{task_id}", task.to_mcp_dict())
        return task

    def complete_task(
        self,
        task_id: str,
        result: Dict[str, Any],
        principal: Optional[Principal] = None,
        tenant_id: Optional[str] = None,
        environment_id: Optional[str] = None,
    ) -> MCPTask:
        t_id = principal.tenant_id if principal else (tenant_id or "tenant-default")
        env_id = (
            principal.environment_ids[0]
            if principal and principal.environment_ids
            else (environment_id or "env-prod")
        )
        key = (t_id, env_id, task_id)

        task = self._memory_cache.get(key)
        if not task:
            row = self.durable.get_task(t_id, env_id, task_id)
            if not row:
                raise TaskNotFoundException(f"Task '{task_id}' not found in tenant '{t_id}'.")
            task = self._task_from_db_row(row)
            self._memory_cache[key] = task

        if task.is_terminal:
            raise WorkflowExecutionException(
                f"Cannot complete task '{task_id}' in terminal state '{task.status}'."
            )

        task.current_step = task.steps_total
        task.progress_pct = 100.0
        task.status = "COMPLETED"
        task.step_description = "Workflow completed successfully"
        task.result = result
        task.updated_at = time.time()

        self._persist_task(task)
        self.emit_notification(f"notifications/tasks/{task_id}", task.to_mcp_dict())
        return task

    def fail_task(
        self,
        task_id: str,
        error_message: str,
        principal: Optional[Principal] = None,
        tenant_id: Optional[str] = None,
        environment_id: Optional[str] = None,
    ) -> MCPTask:
        t_id = principal.tenant_id if principal else (tenant_id or "tenant-default")
        env_id = (
            principal.environment_ids[0]
            if principal and principal.environment_ids
            else (environment_id or "env-prod")
        )
        key = (t_id, env_id, task_id)

        task = self._memory_cache.get(key)
        if not task:
            row = self.durable.get_task(t_id, env_id, task_id)
            if not row:
                raise TaskNotFoundException(f"Task '{task_id}' not found in tenant '{t_id}'.")
            task = self._task_from_db_row(row)
            self._memory_cache[key] = task

        if task.is_terminal:
            raise WorkflowExecutionException(
                f"Cannot fail task '{task_id}' in terminal state '{task.status}'."
            )

        task.status = "FAILED"
        task.error = error_message
        task.updated_at = time.time()

        self._persist_task(task)
        self.emit_notification(f"notifications/tasks/{task_id}", task.to_mcp_dict())
        return task

    def cancel_task(self, task_id: str, principal: Principal) -> Dict[str, Any]:
        """Cancels an in-flight task after checking tenant isolation and compensation boundaries."""
        task = self.get_task(task_id, principal)

        if task.is_terminal:
            return {"cancelled": False, "status": task.status, "reason": f"Task is already {task.status}"}

        # Check irreversible compensation steps
        if not task.is_currently_reversible():
            return {
                "cancelled": False,
                "status": task.status,
                "reason": "Task has passed an irreversible compensation boundary. Automated rollback not available.",
                "isReversible": False,
            }

        task.status = "CANCELLED"
        task.step_description = f"Cancelled by {principal.user_id}. Compensating executed steps."
        task.updated_at = time.time()
        self._persist_task(task)
        self.emit_notification(f"notifications/tasks/{task_id}", task.to_mcp_dict())
        return {"cancelled": True, "status": "CANCELLED", "isReversible": True}

    def _persist_task(self, task: MCPTask) -> None:
        steps_raw = [
            {
                "name": s.name,
                "is_reversible": s.is_reversible,
                "rollback_action": s.rollback_action,
                "irreversible_after": s.irreversible_after,
                "completed": s.completed,
            }
            for s in task.steps
        ]
        self.durable.save_task(
            task_id=task.task_id,
            tenant_id=task.tenant_id,
            environment_id=task.environment_id,
            principal_id=task.initiator_id,
            tool_name=task.tool_name,
            status=task.status,
            progress=task.progress_pct,
            step=task.step_description,
            native_task_id=task.native_task_id,
            steps_json=json.dumps(steps_raw),
            metadata_json=json.dumps({
                "impact_summary": task.impact_summary,
                "approval_status": task.approval_status,
                "result": task.result,
                "error": task.error,
            }),
        )

    def _task_from_db_row(self, row: Dict[str, Any]) -> MCPTask:
        try:
            steps_data = json.loads(row.get("steps_json", "[]"))
            steps = [
                WorkflowStep(
                    name=s.get("name", "step"),
                    is_reversible=s.get("is_reversible", True),
                    rollback_action=s.get("rollback_action"),
                    irreversible_after=s.get("irreversible_after", False),
                    completed=s.get("completed", False),
                )
                for s in steps_data
            ]
        except Exception:
            steps = []

        try:
            meta = json.loads(row.get("metadata_json", "{}"))
        except Exception:
            meta = {}

        return MCPTask(
            task_id=row["task_id"],
            tool_name=row["tool_name"],
            initiator_id=row["principal_id"],
            tenant_id=row.get("tenant_id", "tenant-default"),
            environment_id=row.get("environment_id", "env-prod"),
            status=row["status"],
            progress_pct=float(row.get("progress", 0.0)),
            step_description=row.get("step", ""),
            native_task_id=row.get("native_task_id", ""),
            created_at=float(row.get("created_at", time.time())),
            updated_at=float(row.get("updated_at", time.time())),
            steps_total=len(steps) if steps else 1,
            steps=steps,
            impact_summary=meta.get("impact_summary", {}),
            approval_status=meta.get("approval_status", "NOT_REQUIRED"),
            result=meta.get("result"),
            error=meta.get("error"),
        )
