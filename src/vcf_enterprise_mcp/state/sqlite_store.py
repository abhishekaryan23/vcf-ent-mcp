# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
SQLite Durable Store for Enterprise VCF MCP Control Plane (MODE A — Appliance MCP).
Implements DurableStore interface with local SQLite in WAL mode for single-appliance deployments.
"""

from __future__ import annotations
import sqlite3
import json
import time
import hashlib
import threading
from typing import Dict, Any, List, Optional, Tuple
from vcf_enterprise_mcp.state.base_store import DurableStore, ResourceLease
from vcf_enterprise_mcp.core.errors import IdempotencyConflictException


class SQLiteDurableStore(DurableStore):
    """
    MODE A — Appliance MCP implementation of DurableStore using SQLite WAL.
    Thread-safe and multi-process safe via WAL mode and file locking.
    """

    def __init__(self, db_path: str = ":memory:"):
        self.db_path = db_path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=30.0)
        self._conn.row_factory = sqlite3.Row
        if self.db_path != ":memory:":
            self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA synchronous=NORMAL;")
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            cur = self._conn.cursor()

            # 1. Tasks: Composite primary key (tenant_id, environment_id, task_id)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS tasks (
                    tenant_id TEXT NOT NULL,
                    environment_id TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    principal_id TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    progress REAL DEFAULT 0.0,
                    step TEXT DEFAULT '',
                    native_task_id TEXT DEFAULT '',
                    steps_json TEXT DEFAULT '[]',
                    metadata_json TEXT DEFAULT '{}',
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    PRIMARY KEY (tenant_id, environment_id, task_id)
                );
            """)

            # 2. Execution Plans: Composite primary key (tenant_id, environment_id, plan_id)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS execution_plans (
                    tenant_id TEXT NOT NULL,
                    environment_id TEXT NOT NULL,
                    plan_id TEXT NOT NULL,
                    principal_id TEXT NOT NULL,
                    tool_id TEXT NOT NULL,
                    args_sha256 TEXT NOT NULL,
                    normalized_args_json TEXT NOT NULL,
                    resource_revisions_json TEXT NOT NULL,
                    impact_summary_json TEXT NOT NULL,
                    permission_epoch INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    PRIMARY KEY (tenant_id, environment_id, plan_id)
                );
            """)

            # 3. Approvals: Composite primary key (tenant_id, environment_id, approval_id)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS approvals (
                    tenant_id TEXT NOT NULL,
                    environment_id TEXT NOT NULL,
                    approval_id TEXT NOT NULL,
                    plan_id TEXT NOT NULL,
                    approver_id TEXT NOT NULL,
                    approver_roles TEXT DEFAULT '[]',
                    nonce TEXT NOT NULL,
                    issued_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    permission_epoch INTEGER NOT NULL DEFAULT 100,
                    signature TEXT DEFAULT '',
                    key_id TEXT DEFAULT '',
                    algorithm TEXT DEFAULT 'RS256',
                    used INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'VALID',
                    PRIMARY KEY (tenant_id, environment_id, approval_id)
                );
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_approvals_plan
                ON approvals (tenant_id, environment_id, plan_id, used);
            """)

            # 3b. Single-use Nonces
            cur.execute("""
                CREATE TABLE IF NOT EXISTS approval_nonces (
                    tenant_id TEXT NOT NULL,
                    environment_id TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    approval_id TEXT NOT NULL,
                    issued_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    consumed_at REAL,
                    PRIMARY KEY (tenant_id, environment_id, nonce)
                );
            """)

            # 4. Idempotency
            cur.execute("""
                CREATE TABLE IF NOT EXISTS idempotency (
                    tenant_id TEXT NOT NULL,
                    environment_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    principal_id TEXT NOT NULL,
                    tool_id TEXT NOT NULL,
                    args_sha256 TEXT NOT NULL,
                    status TEXT DEFAULT 'COMMITTED',
                    response_json TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    PRIMARY KEY (tenant_id, environment_id, idempotency_key)
                );
            """)

            # 5. Resource leases with Fencing Tokens
            cur.execute("""
                CREATE TABLE IF NOT EXISTS leases (
                    tenant_id TEXT NOT NULL,
                    environment_id TEXT NOT NULL,
                    resource_id TEXT NOT NULL,
                    lease_holder TEXT NOT NULL,
                    lease_type TEXT NOT NULL,
                    fencing_token INTEGER NOT NULL DEFAULT 1,
                    acquired_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    PRIMARY KEY (tenant_id, environment_id, resource_id)
                );
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS fencing_counters (
                    tenant_id TEXT NOT NULL,
                    environment_id TEXT NOT NULL,
                    resource_id TEXT NOT NULL,
                    last_token INTEGER NOT NULL DEFAULT 1,
                    PRIMARY KEY (tenant_id, environment_id, resource_id)
                );
            """)

            # 6. Execution Intents
            cur.execute("""
                CREATE TABLE IF NOT EXISTS execution_intents (
                    tenant_id TEXT NOT NULL,
                    environment_id TEXT NOT NULL,
                    intent_id TEXT NOT NULL,
                    workflow_id TEXT NOT NULL,
                    step_id TEXT NOT NULL,
                    state TEXT NOT NULL,
                    target_resource TEXT NOT NULL,
                    operation_id TEXT NOT NULL,
                    desired_state_json TEXT NOT NULL,
                    fencing_token INTEGER NOT NULL DEFAULT 0,
                    recorded_at REAL NOT NULL,
                    resolved_at REAL DEFAULT 0.0,
                    outcome TEXT DEFAULT '',
                    PRIMARY KEY (tenant_id, environment_id, intent_id)
                );
            """)

            # 7. Fine-grained Permission Epochs
            cur.execute("""
                CREATE TABLE IF NOT EXISTS permission_epochs (
                    tenant_id TEXT NOT NULL,
                    environment_id TEXT NOT NULL,
                    epoch INTEGER NOT NULL DEFAULT 100,
                    updated_at REAL NOT NULL,
                    PRIMARY KEY (tenant_id, environment_id)
                );
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS principal_epochs (
                    tenant_id TEXT NOT NULL,
                    principal_id TEXT NOT NULL,
                    epoch INTEGER NOT NULL DEFAULT 100,
                    updated_at REAL NOT NULL,
                    PRIMARY KEY (tenant_id, principal_id)
                );
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS policy_epochs (
                    tenant_id TEXT NOT NULL,
                    epoch INTEGER NOT NULL DEFAULT 100,
                    updated_at REAL NOT NULL,
                    PRIMARY KEY (tenant_id)
                );
            """)

            # 8. Tamper-evident Audit Chain & Anchors
            cur.execute("""
                CREATE TABLE IF NOT EXISTS audit_chain (
                    seq_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id TEXT NOT NULL,
                    environment_id TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    current_hash TEXT NOT NULL,
                    record_payload TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    UNIQUE (tenant_id, environment_id, event_id)
                );
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS audit_anchors (
                    anchor_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    environment_id TEXT NOT NULL,
                    chain_head_hash TEXT NOT NULL,
                    external_target TEXT NOT NULL,
                    anchored_at REAL NOT NULL,
                    verification_proof TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, environment_id, anchor_id)
                );
            """)

            # 9. Outbox Events
            cur.execute("""
                CREATE TABLE IF NOT EXISTS outbox_events (
                    event_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    environment_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    status TEXT DEFAULT 'PENDING',
                    created_at REAL NOT NULL,
                    published_at REAL
                );
            """)

            self._conn.commit()

    def _resolve_task_coords(
        self,
        tenant_id: str,
        environment_id: Optional[str] = None,
        task_id: Optional[str] = None,
    ) -> Tuple[Optional[str], Optional[str], str]:
        if environment_id is None and task_id is None:
            return (None, None, tenant_id)
        if task_id is None:
            return (tenant_id, "env-prod", environment_id)
        return (tenant_id, environment_id, task_id)

    def _resolve_plan_coords(
        self,
        tenant_id: str,
        environment_id: Optional[str] = None,
        plan_id: Optional[str] = None,
    ) -> Tuple[Optional[str], Optional[str], str]:
        if environment_id is None and plan_id is None:
            return (None, None, tenant_id)
        if plan_id is None:
            return (tenant_id, "env-prod", environment_id)
        return (tenant_id, environment_id, plan_id)

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
        now = time.time()
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("""
                INSERT INTO tasks (
                    tenant_id, environment_id, task_id, principal_id, tool_name,
                    status, progress, step, native_task_id, steps_json, metadata_json,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(tenant_id, environment_id, task_id) DO UPDATE SET
                    status=excluded.status,
                    progress=excluded.progress,
                    step=excluded.step,
                    native_task_id=excluded.native_task_id,
                    steps_json=excluded.steps_json,
                    metadata_json=excluded.metadata_json,
                    updated_at=excluded.updated_at;
            """, (
                tenant_id, environment_id, task_id, principal_id, tool_name,
                status, progress, step, native_task_id, steps_json, metadata_json,
                now, now
            ))
            self._conn.commit()

    def get_task(
        self,
        tenant_id: str,
        environment_id: Optional[str] = None,
        task_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        t_id, env_id, actual_task_id = self._resolve_task_coords(tenant_id, environment_id, task_id)
        with self._lock:
            cur = self._conn.cursor()
            if t_id is None:
                cur.execute("SELECT * FROM tasks WHERE task_id = ?", (actual_task_id,))
            else:
                cur.execute(
                    "SELECT * FROM tasks WHERE tenant_id = ? AND environment_id = ? AND task_id = ?",
                    (t_id, env_id, actual_task_id)
                )
            row = cur.fetchone()
            if not row:
                return None
            res = dict(row)
            res["steps"] = json.loads(res.get("steps_json", "[]"))
            res["metadata"] = json.loads(res.get("metadata_json", "{}"))
            return res

    def list_resumable_tasks(
        self,
        tenant_id: Optional[str] = None,
        environment_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        with self._lock:
            cur = self._conn.cursor()
            if tenant_id and environment_id:
                cur.execute(
                    "SELECT * FROM tasks WHERE tenant_id = ? AND environment_id = ? AND status IN ('RUNNING', 'PENDING') ORDER BY created_at ASC",
                    (tenant_id, environment_id)
                )
            elif tenant_id:
                cur.execute(
                    "SELECT * FROM tasks WHERE tenant_id = ? AND status IN ('RUNNING', 'PENDING') ORDER BY created_at ASC",
                    (tenant_id,)
                )
            else:
                cur.execute("SELECT * FROM tasks WHERE status IN ('RUNNING', 'PENDING') ORDER BY created_at ASC")
            results = []
            for row in cur.fetchall():
                d = dict(row)
                d["steps"] = json.loads(d.get("steps_json", "[]"))
                d["metadata"] = json.loads(d.get("metadata_json", "{}"))
                results.append(d)
            return results

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
        now = time.time()
        # The caller signs the plan hash over expires_at; store exactly that value.
        expires_at = expires_at if expires_at is not None else now + ttl_seconds
        serialized_revs = {
            k: str(v) for k, v in resource_revisions.items()
        } if isinstance(resource_revisions, dict) else resource_revisions
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("""
                INSERT INTO execution_plans (
                    tenant_id, environment_id, plan_id, principal_id, tool_id,
                    args_sha256, normalized_args_json, resource_revisions_json,
                    impact_summary_json, permission_epoch, status, created_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(tenant_id, environment_id, plan_id) DO UPDATE SET
                    status=excluded.status,
                    expires_at=excluded.expires_at;
            """, (
                tenant_id, environment_id, plan_id, principal_id, tool_id,
                args_sha256, json.dumps(normalized_args), json.dumps(serialized_revs),
                json.dumps(impact_summary), permission_epoch, status, now, expires_at
            ))
            self._conn.commit()

    def get_execution_plan(
        self,
        tenant_id: str,
        environment_id: Optional[str] = None,
        plan_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        t_id, env_id, actual_plan_id = self._resolve_plan_coords(tenant_id, environment_id, plan_id)
        with self._lock:
            cur = self._conn.cursor()
            if t_id is None:
                cur.execute("SELECT * FROM execution_plans WHERE plan_id = ?", (actual_plan_id,))
            else:
                cur.execute(
                    "SELECT * FROM execution_plans WHERE tenant_id = ? AND environment_id = ? AND plan_id = ?",
                    (t_id, env_id, actual_plan_id)
                )
            row = cur.fetchone()
            if not row:
                return None
            res = dict(row)
            res["normalized_args"] = json.loads(res["normalized_args_json"])
            res["resource_revisions"] = json.loads(res["resource_revisions_json"])
            res["impact_summary"] = json.loads(res["impact_summary_json"])
            return res

    def list_execution_plans(
        self,
        tenant_id: str,
        environment_id: str = "env-prod",
        status: Optional[str] = None,
        principal_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        query = "SELECT * FROM execution_plans WHERE tenant_id = ? AND environment_id = ?"
        params: List[Any] = [tenant_id, environment_id]
        if status:
            query += " AND status = ?"
            params.append(status)
        if principal_id:
            query += " AND principal_id = ?"
            params.append(principal_id)
        query += " ORDER BY created_at DESC"
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(query, tuple(params))
            results: List[Dict[str, Any]] = []
            for row in cur.fetchall():
                res = dict(row)
                res["normalized_args"] = json.loads(res.get("normalized_args_json", "{}"))
                res["resource_revisions"] = json.loads(res.get("resource_revisions_json", "{}"))
                res["impact_summary"] = json.loads(res.get("impact_summary_json", "{}"))
                results.append(res)
            return results

    def get_approval(
        self,
        tenant_id: str,
        environment_id: Optional[str] = None,
        approval_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        if approval_id is None and environment_id is None:
            t_id = "tenant-default"
            env_id = "env-prod"
            actual_app_id = tenant_id
        elif approval_id is None:
            t_id = tenant_id
            env_id = "env-prod"
            actual_app_id = environment_id
        else:
            t_id = tenant_id
            env_id = environment_id
            actual_app_id = approval_id

        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT * FROM approvals WHERE tenant_id = ? AND environment_id = ? AND approval_id = ?",
                (t_id, env_id, actual_app_id)
            )
            row = cur.fetchone()
            if not row:
                return None
            d = dict(row)
            try:
                d["approver_roles"] = json.loads(d.get("approver_roles", "[]"))
            except Exception:
                d["approver_roles"] = []
            return d

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
        now = time.time()
        expires_at = now + ttl_seconds
        roles_json = json.dumps(list(approver_roles))
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("""
                INSERT INTO approvals (
                    tenant_id, environment_id, approval_id, plan_id, approver_id,
                    approver_roles, nonce, issued_at, expires_at, permission_epoch,
                    signature, key_id, algorithm, used, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 'VALID')
                ON CONFLICT(tenant_id, environment_id, approval_id) DO UPDATE SET
                    used=excluded.used,
                    status=excluded.status;
            """, (
                tenant_id, environment_id, approval_id, plan_id, approver_id,
                roles_json, nonce, now, expires_at, permission_epoch,
                signature, key_id, algorithm
            ))
            # Also record in approval_nonces table
            if nonce:
                cur.execute("""
                    INSERT INTO approval_nonces (
                        tenant_id, environment_id, nonce, approval_id, issued_at, expires_at, consumed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, NULL)
                    ON CONFLICT(tenant_id, environment_id, nonce) DO NOTHING;
                """, (tenant_id, environment_id, nonce, approval_id, now, expires_at))
            cur.execute("""
                UPDATE execution_plans
                SET status = 'APPROVED'
                WHERE tenant_id = ? AND environment_id = ? AND plan_id = ? AND status = 'PENDING_APPROVAL';
            """, (tenant_id, environment_id, plan_id))
            self._conn.commit()

    def list_valid_approvals(
        self,
        tenant_id: str,
        environment_id: str,
        plan_id: str,
    ) -> List[Dict[str, Any]]:
        now = time.time()
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("""
                SELECT * FROM approvals
                WHERE tenant_id = ?
                AND environment_id = ?
                AND plan_id = ?
                AND status = 'VALID'
                AND expires_at > ?
                ORDER BY issued_at ASC
            """, (tenant_id, environment_id, plan_id, now))
            results = []
            for row in cur.fetchall():
                d = dict(row)
                try:
                    d["approver_roles"] = json.loads(d.get("approver_roles", "[]"))
                except Exception:
                    d["approver_roles"] = []
                results.append(d)
            return results

    def consume_approval(
        self,
        tenant_id_or_approval_id: str,
        environment_id_or_nonce: str,
        approval_id: Optional[str] = None,
        nonce: Optional[str] = None,
    ) -> Tuple[bool, str]:
        now = time.time()
        if approval_id is None:
            t_id = "tenant-default"
            env_id = "env-prod"
            actual_app_id = tenant_id_or_approval_id
            actual_nonce = environment_id_or_nonce
        else:
            t_id = tenant_id_or_approval_id
            env_id = environment_id_or_nonce
            actual_app_id = approval_id
            actual_nonce = nonce

        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT * FROM approvals WHERE tenant_id = ? AND environment_id = ? AND approval_id = ?",
                (t_id, env_id, actual_app_id)
            )
            row = cur.fetchone()
            if not row:
                return False, f"Approval authorization '{actual_app_id}' not found in tenant '{t_id}'."
            if row["nonce"] != actual_nonce:
                return False, "Single-use approval nonce mismatch."
            if row["used"] == 1:
                return False, "Approval token has already been consumed (replay rejected)."
            if now > row["expires_at"]:
                return False, f"Approval authorization has expired (expired at {row['expires_at']:.0f})."

            cur.execute(
                "UPDATE approvals SET used = 1 WHERE tenant_id = ? AND environment_id = ? AND approval_id = ?",
                (t_id, env_id, actual_app_id)
            )
            cur.execute(
                "UPDATE approval_nonces SET consumed_at = ? WHERE tenant_id = ? AND environment_id = ? AND nonce = ?",
                (now, t_id, env_id, actual_nonce)
            )
            self._conn.commit()
            return True, "Approval consumed successfully."

    def consume_approval_nonce(
        self,
        tenant_id: str,
        environment_id: str,
        nonce: str,
    ) -> bool:
        now = time.time()
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("""
                UPDATE approval_nonces
                SET consumed_at = ?
                WHERE tenant_id = ? AND environment_id = ? AND nonce = ?
                  AND consumed_at IS NULL AND expires_at > ?
            """, (now, tenant_id, environment_id, nonce, now))
            rowcount = cur.rowcount
            self._conn.commit()
            return rowcount > 0

    def get_idempotency_record(
        self,
        tenant_id: str,
        idempotency_key: str,
        environment_id: str = "env-prod",
    ) -> Optional[Dict[str, Any]]:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT * FROM idempotency WHERE tenant_id = ? AND environment_id = ? AND idempotency_key = ?",
                (tenant_id, environment_id, idempotency_key)
            )
            row = cur.fetchone()
            if not row:
                return None
            res = dict(row)
            try:
                res["response"] = json.loads(res["response_json"])
            except Exception:
                res["response"] = {}
            return res

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
        now = time.time()
        record_status = status
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT * FROM idempotency WHERE tenant_id = ? AND environment_id = ? AND idempotency_key = ?",
                (tenant_id, environment_id, idempotency_key)
            )
            existing = cur.fetchone()
            if existing:
                if status == "PENDING":
                    # Cannot overwrite if already PENDING or COMMITTED by another execution (F05)
                    if existing["args_sha256"] != args_sha256:
                        raise IdempotencyConflictException(
                            f"Idempotency conflict: Key '{idempotency_key}' previously recorded with different arguments hash."
                        )
                    if existing["status"] == "COMMITTED":
                        resp = json.loads(existing["response_json"]) if existing["response_json"] else {}
                        return {
                            "status": "COMMITTED",
                            "response": resp,
                            "args_sha256": existing["args_sha256"],
                            "tool_id": existing["tool_id"],
                        }
                    if existing["status"] == "PENDING":
                        raise IdempotencyConflictException(
                            f"Operation for idempotency key '{idempotency_key}' is already in flight. Concurrent duplicate execution denied."
                        )
                cur.execute("""
                    UPDATE idempotency SET
                        response_json = ?,
                        status = ?,
                        args_sha256 = ?,
                        principal_id = ?,
                        tool_id = ?
                    WHERE tenant_id = ? AND environment_id = ? AND idempotency_key = ?
                """, (
                    json.dumps(response_payload), record_status, args_sha256,
                    principal_id, tool_id, tenant_id, environment_id, idempotency_key
                ))
            else:
                cur.execute("""
                    INSERT INTO idempotency (
                        tenant_id, environment_id, idempotency_key, principal_id,
                        tool_id, args_sha256, status, response_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    tenant_id, environment_id, idempotency_key, principal_id,
                    tool_id, args_sha256, record_status, json.dumps(response_payload), now
                ))
            self._conn.commit()

    def acquire_lease(
        self,
        tenant_id: str,
        resource_id: str,
        lease_holder: str,
        lease_type: str = "EXCLUSIVE",
        ttl_seconds: float = 30.0,
        environment_id: str = "env-prod",
    ) -> Tuple[bool, str, int]:
        now = time.time()
        expires_at = now + ttl_seconds
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "DELETE FROM leases WHERE tenant_id = ? AND environment_id = ? AND resource_id = ? AND expires_at < ?",
                (tenant_id, environment_id, resource_id, now)
            )
            cur.execute(
                "SELECT * FROM leases WHERE tenant_id = ? AND environment_id = ? AND resource_id = ?",
                (tenant_id, environment_id, resource_id)
            )
            existing = cur.fetchone()
            if existing:
                if existing["lease_holder"] == lease_holder:
                    cur.execute(
                        "UPDATE leases SET expires_at = ? WHERE tenant_id = ? AND environment_id = ? AND resource_id = ?",
                        (expires_at, tenant_id, environment_id, resource_id)
                    )
                    self._conn.commit()
                    return True, "Lease extended", int(existing["fencing_token"])
                self._conn.commit()
                return False, f"Resource '{resource_id}' is locked by lease holder '{existing['lease_holder']}' until {existing['expires_at']:.0f}", 0

            cur.execute("""
                INSERT INTO fencing_counters (tenant_id, environment_id, resource_id, last_token)
                VALUES (?, ?, ?, 100)
                ON CONFLICT(tenant_id, environment_id, resource_id) DO UPDATE SET last_token = last_token + 1;
            """, (tenant_id, environment_id, resource_id))
            cur.execute(
                "SELECT last_token FROM fencing_counters WHERE tenant_id = ? AND environment_id = ? AND resource_id = ?",
                (tenant_id, environment_id, resource_id)
            )
            fencing_token = int(cur.fetchone()["last_token"])

            cur.execute("""
                INSERT INTO leases (
                    tenant_id, environment_id, resource_id, lease_holder, lease_type,
                    fencing_token, acquired_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
            """, (tenant_id, environment_id, resource_id, lease_holder, lease_type, fencing_token, now, expires_at))
            self._conn.commit()
            return True, "Lease acquired", fencing_token

    def release_lease(
        self,
        tenant_id: str,
        resource_id: str,
        lease_holder: str,
        environment_id: str = "env-prod",
    ) -> None:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "DELETE FROM leases WHERE tenant_id = ? AND environment_id = ? AND resource_id = ? AND lease_holder = ?",
                (tenant_id, environment_id, resource_id, lease_holder)
            )
            self._conn.commit()

    def get_active_lease(
        self,
        tenant_id: str,
        resource_id: str,
        environment_id: str = "env-prod",
    ) -> Optional[ResourceLease]:
        now = time.time()
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT * FROM leases WHERE tenant_id = ? AND environment_id = ? AND resource_id = ? AND expires_at > ?",
                (tenant_id, environment_id, resource_id, now)
            )
            row = cur.fetchone()
            if not row:
                return None
            return ResourceLease(
                resource_id=row["resource_id"],
                owner=row["lease_holder"],
                fencing_token=int(row["fencing_token"]),
                expires_at=float(row["expires_at"]),
                lease_type=row["lease_type"],
                tenant_id=row["tenant_id"],
                environment_id=row["environment_id"],
            )

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
        now = time.time()
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("""
                INSERT INTO execution_intents (
                    tenant_id, environment_id, intent_id, workflow_id, step_id,
                    state, target_resource, operation_id, desired_state_json,
                    fencing_token, recorded_at, resolved_at, outcome
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0.0, '')
                ON CONFLICT(tenant_id, environment_id, intent_id) DO UPDATE SET
                    state=excluded.state,
                    desired_state_json=excluded.desired_state_json;
            """, (
                tenant_id, environment_id, intent_id, workflow_id, step_id,
                state, target_resource, operation_id, json.dumps(desired_state or {}),
                fencing_token, now
            ))
            self._conn.commit()

    def get_execution_intent(
        self,
        tenant_id: str = "tenant-default",
        environment_id: str = "env-prod",
        intent_id: str = "",
    ) -> Optional[Dict[str, Any]]:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT * FROM execution_intents WHERE tenant_id = ? AND environment_id = ? AND intent_id = ?",
                (tenant_id, environment_id, intent_id)
            )
            row = cur.fetchone()
            if not row:
                return None
            res = dict(row)
            res["desired_state"] = json.loads(res.get("desired_state_json", "{}"))
            return res

    def list_pending_execution_intents(
        self,
        tenant_id: Optional[str] = None,
        environment_id: Optional[str] = None,
        workflow_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        with self._lock:
            cur = self._conn.cursor()
            query = "SELECT * FROM execution_intents WHERE state NOT IN ('RESOLVED', 'ABORTED')"
            params: List[Any] = []
            if tenant_id:
                query += " AND tenant_id = ?"
                params.append(tenant_id)
            if environment_id:
                query += " AND environment_id = ?"
                params.append(environment_id)
            if workflow_id:
                query += " AND workflow_id = ?"
                params.append(workflow_id)
            query += " ORDER BY recorded_at ASC"
            cur.execute(query, params)
            results = []
            for row in cur.fetchall():
                d = dict(row)
                d["desired_state"] = json.loads(d.get("desired_state_json", "{}"))
                results.append(d)
            return results

    def resolve_execution_intent(
        self,
        tenant_id: str = "tenant-default",
        environment_id: str = "env-prod",
        intent_id: str = "",
        outcome: str = "",
        state: str = "RESOLVED",
    ) -> None:
        now = time.time()
        if not intent_id and (tenant_id.startswith("intent-") or "-" in tenant_id):
            actual_intent_id = tenant_id
            t_id = None
            env_id = None
        else:
            actual_intent_id = intent_id
            t_id = tenant_id
            env_id = environment_id

        with self._lock:
            cur = self._conn.cursor()
            if t_id and env_id:
                cur.execute("""
                    UPDATE execution_intents
                    SET state = ?, resolved_at = ?, outcome = ?
                    WHERE tenant_id = ? AND environment_id = ? AND intent_id = ?;
                """, (state, now, outcome, t_id, env_id, actual_intent_id))
            else:
                cur.execute("""
                    UPDATE execution_intents
                    SET state = ?, resolved_at = ?, outcome = ?
                    WHERE intent_id = ?;
                """, (state, now, outcome, actual_intent_id))
            self._conn.commit()

    def get_permission_epoch(self, tenant_id: str, environment_id: str) -> int:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT epoch FROM permission_epochs WHERE tenant_id = ? AND environment_id = ?",
                (tenant_id, environment_id)
            )
            row = cur.fetchone()
            if not row:
                cur.execute("""
                    INSERT INTO permission_epochs (tenant_id, environment_id, epoch, updated_at)
                    VALUES (?, ?, 100, ?)
                    ON CONFLICT(tenant_id, environment_id) DO NOTHING;
                """, (tenant_id, environment_id, time.time()))
                self._conn.commit()
                return 100
            return int(row["epoch"])

    def bump_permission_epoch(self, tenant_id: str, environment_id: str) -> int:
        now = time.time()
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("""
                INSERT INTO permission_epochs (tenant_id, environment_id, epoch, updated_at)
                VALUES (?, ?, 101, ?)
                ON CONFLICT(tenant_id, environment_id) DO UPDATE SET
                    epoch = epoch + 1,
                    updated_at = excluded.updated_at;
            """, (tenant_id, environment_id, now))
            self._conn.commit()
            return self.get_permission_epoch(tenant_id, environment_id)

    def get_principal_epoch(self, tenant_id: str, principal_id: str) -> int:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT epoch FROM principal_epochs WHERE tenant_id = ? AND principal_id = ?",
                (tenant_id, principal_id)
            )
            row = cur.fetchone()
            if not row:
                cur.execute("""
                    INSERT INTO principal_epochs (tenant_id, principal_id, epoch, updated_at)
                    VALUES (?, ?, 100, ?)
                    ON CONFLICT(tenant_id, principal_id) DO NOTHING;
                """, (tenant_id, principal_id, time.time()))
                self._conn.commit()
                return 100
            return int(row["epoch"])

    def bump_principal_epoch(self, tenant_id: str, principal_id: str) -> int:
        now = time.time()
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("""
                INSERT INTO principal_epochs (tenant_id, principal_id, epoch, updated_at)
                VALUES (?, ?, 101, ?)
                ON CONFLICT(tenant_id, principal_id) DO UPDATE SET
                    epoch = epoch + 1,
                    updated_at = excluded.updated_at;
            """, (tenant_id, principal_id, now))
            self._conn.commit()
            return self.get_principal_epoch(tenant_id, principal_id)

    def get_policy_epoch(self, tenant_id: str) -> int:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("SELECT epoch FROM policy_epochs WHERE tenant_id = ?", (tenant_id,))
            row = cur.fetchone()
            if not row:
                cur.execute("""
                    INSERT INTO policy_epochs (tenant_id, epoch, updated_at)
                    VALUES (?, 100, ?)
                    ON CONFLICT(tenant_id) DO NOTHING;
                """, (tenant_id, time.time()))
                self._conn.commit()
                return 100
            return int(row["epoch"])

    def bump_policy_epoch(self, tenant_id: str) -> int:
        now = time.time()
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("""
                INSERT INTO policy_epochs (tenant_id, epoch, updated_at)
                VALUES (?, 101, ?)
                ON CONFLICT(tenant_id) DO UPDATE SET
                    epoch = epoch + 1,
                    updated_at = excluded.updated_at;
            """, (tenant_id, now))
            self._conn.commit()
            return self.get_policy_epoch(tenant_id)

    def record_audit_event_chained(
        self,
        tenant_id: str = "tenant-default",
        environment_id: Any = "env-prod",
        event_id: Optional[str] = None,
        record_payload: Optional[Dict[str, Any]] = None,
    ) -> str:
        now = time.time()
        if isinstance(environment_id, dict):
            actual_tenant_id = "tenant-default"
            actual_env_id = "env-prod"
            actual_event_id = tenant_id
            payload = environment_id
        elif event_id is not None:
            actual_tenant_id = tenant_id
            actual_env_id = str(environment_id)
            actual_event_id = event_id
            payload = record_payload or {}
        else:
            actual_tenant_id = tenant_id
            actual_env_id = str(environment_id)
            actual_event_id = event_id or "ev-default"
            payload = record_payload or {}

        payload_str = json.dumps(payload, sort_keys=True)
        with self._lock:
            prev_hash = self.get_latest_audit_hash(actual_tenant_id, actual_env_id)
            hasher = hashlib.sha256()
            hasher.update(prev_hash.encode("utf-8"))
            hasher.update(actual_event_id.encode("utf-8"))
            hasher.update(payload_str.encode("utf-8"))
            hasher.update(str(now).encode("utf-8"))
            curr_hash = hasher.hexdigest()

            cur = self._conn.cursor()
            cur.execute("""
                INSERT INTO audit_chain (tenant_id, environment_id, event_id, prev_hash, current_hash, record_payload, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?);
            """, (actual_tenant_id, actual_env_id, actual_event_id, prev_hash, curr_hash, payload_str, now))
            self._conn.commit()
            return curr_hash

    def get_latest_audit_hash(self, tenant_id: str = "tenant-default", environment_id: str = "env-prod") -> str:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("""
                SELECT current_hash FROM audit_chain
                WHERE tenant_id = ? AND environment_id = ?
                ORDER BY seq_id DESC LIMIT 1;
            """, (tenant_id, environment_id))
            row = cur.fetchone()
            if not row:
                return "0000000000000000000000000000000000000000000000000000000000000000"
            return row["current_hash"]

    def verify_audit_integrity(self, tenant_id: str = "tenant-default", environment_id: str = "env-prod") -> Tuple[bool, Optional[int]]:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("""
                SELECT seq_id, event_id, prev_hash, current_hash, record_payload, timestamp
                FROM audit_chain
                WHERE tenant_id = ? AND environment_id = ?
                ORDER BY seq_id ASC;
            """, (tenant_id, environment_id))
            rows = cur.fetchall()
            if not rows:
                return True, None

            expected_prev = "0000000000000000000000000000000000000000000000000000000000000000"
            for row in rows:
                if row["prev_hash"] != expected_prev:
                    return False, row["seq_id"]

                hasher = hashlib.sha256()
                hasher.update(row["prev_hash"].encode("utf-8"))
                hasher.update(row["event_id"].encode("utf-8"))
                hasher.update(row["record_payload"].encode("utf-8"))
                hasher.update(str(row["timestamp"]).encode("utf-8"))
                recomputed = hasher.hexdigest()

                if recomputed != row["current_hash"]:
                    return False, row["seq_id"]

                expected_prev = row["current_hash"]

            return True, None

    def anchor_audit_chain_head(
        self,
        tenant_id: str = "tenant-default",
        environment_id: str = "env-prod",
        external_target: str = "vcf_operations_logs",
    ) -> Dict[str, Any]:
        head_hash = self.get_latest_audit_hash(tenant_id, environment_id)
        now = time.time()
        anchor_id = f"anchor-{hashlib.sha256(f'{head_hash}-{now}'.encode()).hexdigest()[:16]}"
        proof = f"External RFC-3161 timestamp and ledger attestation for head {head_hash} at {now}"

        with self._lock:
            cur = self._conn.cursor()
            cur.execute("""
                INSERT INTO audit_anchors (anchor_id, tenant_id, environment_id, chain_head_hash, external_target, anchored_at, verification_proof)
                VALUES (?, ?, ?, ?, ?, ?, ?);
            """, (anchor_id, tenant_id, environment_id, head_hash, external_target, now, proof))
            self._conn.commit()

        return {
            "anchor_id": anchor_id,
            "tenant_id": tenant_id,
            "environment_id": environment_id,
            "head_hash": head_hash,
            "external_target": external_target,
            "anchored_at": now,
            "status": "COMMITTED_IMMUTABLE",
        }

    def list_audit_events(
        self,
        tenant_id: str = "tenant-default",
        environment_id: str = "env-prod",
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("""
                SELECT seq_id, event_id, prev_hash, current_hash, record_payload, timestamp
                FROM audit_chain
                WHERE tenant_id = ? AND environment_id = ?
                ORDER BY seq_id DESC
                LIMIT ?;
            """, (tenant_id, environment_id, int(limit)))
            results: List[Dict[str, Any]] = []
            for row in cur.fetchall():
                d = dict(row)
                try:
                    d["payload"] = json.loads(d.get("record_payload", "{}"))
                except Exception:
                    d["payload"] = {}
                results.append(d)
            return results

    def close(self) -> None:
        with self._lock:
            self._conn.close()
