# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Immutable Audit Trail & Tamper-Evident Cryptographic Hash Chaining Recorder.
Captures comprehensive provenance for every MCP tool call, routing decision, and VCF task.
Chains audit records using SHA-256 (record[n].hash = sha256(record[n] + record[n-1].hash)).
"""

from __future__ import annotations
import time
import uuid
import hashlib
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from vcf_enterprise_mcp.auth.identity import Principal
from vcf_enterprise_mcp.policy.models import PolicyDecision
from vcf_enterprise_mcp.auth.credential_broker import CredentialBroker
from vcf_enterprise_mcp.state.durable_store import DurableStore


@dataclass
class AuditRecord:
    """Immutable audit record capturing complete operational provenance."""
    request_id: str
    timestamp: float
    actor: Dict[str, Any]
    agent: Dict[str, Any]
    tool: str
    resource: Dict[str, Any]
    action_type: str
    arguments: Dict[str, Any]
    before_state: Optional[Dict[str, Any]]
    authorization: Dict[str, Any]
    dry_run: bool
    tenant_id: str = "tenant-default"
    environment_id: str = "env-prod"
    trace_id: Optional[str] = None
    vcf_task_id: Optional[str] = None
    result_status: str = "PENDING"
    response_summary: Optional[str] = None
    error_message: Optional[str] = None
    current_hash: Optional[str] = None
    prev_hash: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "timestamp": self.timestamp,
            "tenant_id": self.tenant_id,
            "environment_id": self.environment_id,
            "trace_id": self.trace_id,
            "actor": self.actor,
            "agent": self.agent,
            "tool": self.tool,
            "resource": self.resource,
            "action_type": self.action_type,
            "arguments": self.arguments,
            "before_state": self.before_state,
            "authorization": self.authorization,
            "dry_run": self.dry_run,
            "vcf_task_id": self.vcf_task_id,
            "result_status": self.result_status,
            "response_summary": self.response_summary,
            "error_message": self.error_message,
            "current_hash": self.current_hash,
            "prev_hash": self.prev_hash,
        }


class AuditRecorder:
    """Manages the lifecycle and export of immutable audit records with cryptographic hash chaining."""

    def __init__(
        self,
        redactor: Optional[CredentialBroker] = None,
        durable_store: Optional[DurableStore] = None,
    ):
        self.redactor = redactor or CredentialBroker()
        self.durable = durable_store or DurableStore()
        self.records: List[AuditRecord] = []

    def record_call(
        self,
        principal: Principal,
        tool_name: str,
        arguments: Dict[str, Any],
        decision: PolicyDecision,
        agent_info: Optional[Dict[str, Any]] = None,
        before_state: Optional[Dict[str, Any]] = None,
        dry_run: bool = False,
        trace_id: Optional[str] = None,
    ) -> AuditRecord:
        """Initializes and logs an audit record prior to execution."""
        req_id = f"req-{uuid.uuid4().hex[:12]}"
        clean_args = self.redactor.redact_secrets_from_data(arguments)
        clean_before = self.redactor.redact_secrets_from_data(before_state) if before_state else None

        rec = AuditRecord(
            request_id=req_id,
            timestamp=time.time(),
            tenant_id=decision.tenant_id,
            environment_id=decision.environment_id,
            trace_id=trace_id,
            actor=principal.to_audit_dict(),
            agent=agent_info or {"client": "mcp-enterprise-client", "model": "configured-llm"},
            tool=tool_name,
            resource={
                "domain_id": arguments.get("domain_id"),
                "cluster_id": arguments.get("cluster_id") or arguments.get("cluster"),
                "vm_id": arguments.get("vm_id"),
                "host_id": arguments.get("host_id"),
            },
            action_type=decision.risk_class.value,
            arguments=clean_args,
            before_state=clean_before,
            authorization=decision.to_audit_dict(),
            dry_run=dry_run,
            result_status="AUTHORIZED" if decision.allow else "DENIED",
        )
        self.records.append(rec)
        return rec

    def finalize_record(
        self,
        record: AuditRecord,
        status: str = "SUCCESS",
        summary: Optional[str] = None,
        error: Optional[str] = None,
        vcf_task_id: Optional[str] = None,
    ) -> None:
        """Finalizes the audit record and cryptographically chains it in durable storage."""
        record.result_status = status
        record.response_summary = summary
        record.error_message = error
        if vcf_task_id:
            record.vcf_task_id = vcf_task_id

        # Cryptographically chain into durable tamper-evident audit store
        chain_hash = self.durable.record_audit_event_chained(
            tenant_id=record.tenant_id,
            environment_id=record.environment_id,
            event_id=record.request_id,
            record_payload=record.to_dict(),
        )
        record.current_hash = chain_hash

    def record_denied_call(
        self,
        principal: Principal,
        tool_name: str,
        arguments: Dict[str, Any],
        reason: str,
        action_type: str = "READ",
        tenant_id: str = "tenant-default",
        environment_id: str = "env-prod",
        agent_info: Optional[Dict[str, Any]] = None,
        dry_run: bool = False,
        trace_id: Optional[str] = None,
    ) -> AuditRecord:
        """Records a denied or blocked tool call directly into the cryptographic audit chain."""
        req_id = f"req-{uuid.uuid4().hex[:12]}"
        clean_args = self.redactor.redact_secrets_from_data(arguments)
        rec = AuditRecord(
            request_id=req_id,
            timestamp=time.time(),
            tenant_id=tenant_id,
            environment_id=environment_id,
            trace_id=trace_id,
            actor=principal.to_audit_dict(),
            agent=agent_info or {"client": "mcp-enterprise-client", "model": "configured-llm"},
            tool=tool_name,
            resource={
                "domain_id": arguments.get("domain_id"),
                "cluster_id": arguments.get("cluster_id") or arguments.get("cluster"),
                "vm_id": arguments.get("vm_id"),
                "host_id": arguments.get("host_id"),
            },
            action_type=action_type,
            arguments=clean_args,
            before_state=None,
            authorization={"allow": False, "reason": reason},
            dry_run=dry_run,
            result_status="DENIED",
            error_message=reason,
        )
        self.records.append(rec)
        try:
            chain_hash = self.durable.record_audit_event_chained(
                tenant_id=rec.tenant_id,
                environment_id=rec.environment_id,
                event_id=rec.request_id,
                record_payload=rec.to_dict(),
            )
            rec.current_hash = chain_hash
        except Exception:
            pass
        return rec
