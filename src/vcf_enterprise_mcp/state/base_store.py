# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Base Durable Store Interface and Data Contracts for Enterprise VCF MCP Control Plane.
Defines the abstract interface for multi-tenant ACID persistence across Appliance and Enterprise HA modes.
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass


@dataclass
class ResourceLease:
    """Represents a distributed resource lease with a monotonic fencing token."""
    resource_id: str
    owner: str
    fencing_token: int
    expires_at: float
    lease_type: str = "EXCLUSIVE"
    tenant_id: str = "tenant-default"
    environment_id: str = "env-prod"


class DurableStore(ABC):
    """
    Abstract interface for enterprise durable control plane state.
    Every query and mutation strictly requires tenant_id and environment_id.
    """

    @abstractmethod
    def save_task(
        self,
        task_id: str,
        tenant_id: str,
        environment_id: str,
        principal_id: str,
        tool_name: str,
        status: str,
        progress: float = 0.0,
        step: str = "",
        native_task_id: str = "",
        steps_json: str = "[]",
        metadata_json: str = "{}",
    ) -> None:
        pass

    @abstractmethod
    def get_task(
        self,
        tenant_id: str,
        environment_id: Optional[str] = None,
        task_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    def list_resumable_tasks(
        self,
        tenant_id: Optional[str] = None,
        environment_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        pass

    @abstractmethod
    def save_execution_plan(
        self,
        plan_id: str,
        tenant_id: str,
        environment_id: str,
        principal_id: str,
        tool_id: str,
        args_sha256: str,
        normalized_args: Dict[str, Any],
        resource_revisions: Dict[str, str],
        impact_summary: Dict[str, Any],
        permission_epoch: int,
        status: str = "PENDING_APPROVAL",
        ttl_seconds: float = 900.0,
        expires_at: Optional[float] = None,
    ) -> None:
        pass

    @abstractmethod
    def get_execution_plan(
        self,
        tenant_id: str,
        environment_id: Optional[str] = None,
        plan_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        pass

    def list_execution_plans(
        self,
        tenant_id: str,
        environment_id: str = "env-prod",
        status: Optional[str] = None,
        principal_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        return []

    def list_audit_events(
        self,
        tenant_id: str = "tenant-default",
        environment_id: str = "env-prod",
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        return []

    @abstractmethod
    def get_approval(
        self,
        tenant_id: str,
        environment_id: Optional[str] = None,
        approval_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    def save_approval(
        self,
        approval_id: str,
        plan_id: str,
        tenant_id: str = "tenant-default",
        environment_id: str = "env-prod",
        approver_id: str = "",
        nonce: str = "",
        approver_roles: tuple[str, ...] | list[str] = (),
        permission_epoch: int = 100,
        signature: str = "",
        key_id: str = "",
        algorithm: str = "RS256",
        ttl_seconds: float = 600.0,
    ) -> None:
        pass

    @abstractmethod
    def list_valid_approvals(
        self,
        tenant_id: str,
        environment_id: str,
        plan_id: str,
    ) -> List[Dict[str, Any]]:
        pass

    @abstractmethod
    def consume_approval(
        self,
        tenant_id_or_approval_id: str,
        environment_id_or_nonce: str,
        approval_id: Optional[str] = None,
        nonce: Optional[str] = None,
    ) -> Tuple[bool, str]:
        pass

    @abstractmethod
    def consume_approval_nonce(
        self,
        tenant_id: str,
        environment_id: str,
        nonce: str,
    ) -> bool:
        """Atomically consumes an approval nonce. Returns True if consumed, False if replay/expired."""
        pass

    @abstractmethod
    def get_idempotency_record(
        self,
        tenant_id: str,
        idempotency_key: str,
        environment_id: str = "env-prod",
    ) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    def record_idempotency(
        self,
        tenant_id: str,
        idempotency_key: str,
        principal_id: str,
        tool_id: str,
        args_sha256: str,
        response_payload: Dict[str, Any],
        status: str = "COMMITTED",
        environment_id: str = "env-prod",
    ) -> None:
        pass

    @abstractmethod
    def acquire_lease(
        self,
        tenant_id: str,
        resource_id: str,
        lease_holder: str,
        lease_type: str = "EXCLUSIVE",
        ttl_seconds: float = 30.0,
        environment_id: str = "env-prod",
    ) -> Tuple[bool, str, int]:
        pass

    @abstractmethod
    def release_lease(
        self,
        tenant_id: str,
        resource_id: str,
        lease_holder: str,
        environment_id: str = "env-prod",
    ) -> None:
        pass

    @abstractmethod
    def get_active_lease(
        self,
        tenant_id: str,
        resource_id: str,
        environment_id: str = "env-prod",
    ) -> Optional[ResourceLease]:
        pass

    @abstractmethod
    def record_execution_intent(
        self,
        tenant_id: str = "tenant-default",
        environment_id: str = "env-prod",
        intent_id: str = "",
        workflow_id: str = "",
        step_id: str = "",
        target_resource: str = "",
        operation_id: str = "",
        desired_state: Optional[Dict[str, Any]] = None,
        fencing_token: int = 0,
        state: str = "EXECUTION_INTENT_RECORDED",
    ) -> None:
        pass

    @abstractmethod
    def get_execution_intent(
        self,
        tenant_id: str = "tenant-default",
        environment_id: str = "env-prod",
        intent_id: str = "",
    ) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    def list_pending_execution_intents(
        self,
        tenant_id: Optional[str] = None,
        environment_id: Optional[str] = None,
        workflow_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        pass

    @abstractmethod
    def resolve_execution_intent(
        self,
        tenant_id: str = "tenant-default",
        environment_id: str = "env-prod",
        intent_id: str = "",
        outcome: str = "",
        state: str = "RESOLVED",
    ) -> None:
        pass

    @abstractmethod
    def get_permission_epoch(self, tenant_id: str, environment_id: str) -> int:
        pass

    @abstractmethod
    def bump_permission_epoch(self, tenant_id: str, environment_id: str) -> int:
        pass

    @abstractmethod
    def get_principal_epoch(self, tenant_id: str, principal_id: str) -> int:
        pass

    @abstractmethod
    def bump_principal_epoch(self, tenant_id: str, principal_id: str) -> int:
        pass

    @abstractmethod
    def get_policy_epoch(self, tenant_id: str) -> int:
        pass

    @abstractmethod
    def bump_policy_epoch(self, tenant_id: str) -> int:
        pass

    @abstractmethod
    def record_audit_event_chained(
        self,
        tenant_id: str = "tenant-default",
        environment_id: str = "env-prod",
        event_id: str = "",
        record_payload: Optional[Dict[str, Any]] = None,
    ) -> str:
        pass

    @abstractmethod
    def get_latest_audit_hash(self, tenant_id: str = "tenant-default", environment_id: str = "env-prod") -> str:
        pass

    @abstractmethod
    def verify_audit_integrity(self, tenant_id: str = "tenant-default", environment_id: str = "env-prod") -> Tuple[bool, Optional[int]]:
        pass

    @abstractmethod
    def anchor_audit_chain_head(
        self,
        tenant_id: str = "tenant-default",
        environment_id: str = "env-prod",
        external_target: str = "vcf_operations_logs",
    ) -> Dict[str, Any]:
        pass

    @abstractmethod
    def close(self) -> None:
        pass
