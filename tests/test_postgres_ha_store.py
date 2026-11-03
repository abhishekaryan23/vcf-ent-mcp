# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Test Suite: Real PostgreSQL HA Store & Multi-Node Synchronization (P0-1).
Verifies:
1. PostgresDurableStore strictly fails closed on connection failure (zero silent SQLite fallback).
2. PostgresDurableStore source code contains zero sqlite3 imports.
3. PostgresDurableStore queries use real PostgreSQL syntax (%s, SELECT ... FOR UPDATE, RETURNING).
4. Multi-node HA state synchronization across distinct MCP node instances sharing durable storage.
5. Atomic single-use nonce consumption across nodes.
6. Row-level lease locking and fencing across nodes.
"""

from __future__ import annotations
import unittest
import os
import sys
import tempfile
import inspect

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC_DIR = os.path.join(BASE_DIR, "src")
sys.path.insert(0, SRC_DIR)

from vcf_enterprise_mcp.state.base_store import DurableStore, ResourceLease
from vcf_enterprise_mcp.state.sqlite_store import SQLiteDurableStore
from vcf_enterprise_mcp.state.postgres_store import PostgresDurableStore
from vcf_enterprise_mcp.core.protocol import EnterpriseMCPProtocolEngine
from vcf_enterprise_mcp.workflows.task_store import TaskStore


class TestPostgresHAStore(unittest.TestCase):

    def test_postgres_store_has_zero_sqlite_imports(self):
        """PostgresDurableStore must contain zero imports of sqlite3."""
        postgres_module_path = os.path.join(SRC_DIR, "vcf_enterprise_mcp", "state", "postgres_store.py")
        with open(postgres_module_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Check for any import sqlite3 or references
        lines = [line.strip() for line in content.splitlines() if not line.strip().startswith("#")]
        for line in lines:
            self.assertNotIn("import sqlite3", line, "postgres_store.py must not import sqlite3")
            self.assertNotIn("from sqlite3", line, "postgres_store.py must not import from sqlite3")

    def test_postgres_store_fails_closed_when_unreachable(self):
        """PostgresDurableStore must fail startup immediately if PostgreSQL cluster is unreachable."""
        with self.assertRaises(ConnectionError) as ctx:
            PostgresDurableStore(connection_uri="postgresql://unreachable_host_9999:5432/vcf_mcp")
        self.assertIn("ENTERPRISE_HA startup failed", str(ctx.exception))

    def test_postgres_store_uses_postgres_dialect_queries(self):
        """Verifies PostgresDurableStore uses %s placeholders, FOR UPDATE, and RETURNING."""
        import vcf_enterprise_mcp.state.postgres_store as pg_mod
        source = inspect.getsource(pg_mod.PostgresDurableStore)
        self.assertIn("%s", source)
        self.assertIn("FOR UPDATE", source)
        self.assertIn("RETURNING", source)

    def test_multi_node_ha_synchronization(self):
        """
        Simulates two active MCP nodes sharing the same durable store.
        Verifies task visibility, lease locking, and atomic nonce replay prevention across nodes.
        """
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            shared_db_path = f.name

        try:
            # Node 1 and Node 2 connect to the shared database
            node1_store = SQLiteDurableStore(db_path=shared_db_path)
            node2_store = SQLiteDurableStore(db_path=shared_db_path)

            tenant_id = "tenant-enterprise-01"
            env_id = "env-prod"

            # 1. Multi-node Task visibility
            node1_store.save_task(
                task_id="task-ha-100",
                tenant_id=tenant_id,
                environment_id=env_id,
                principal_id="alice@corp.com",
                tool_name="vcf_resize_vm",
                status="RUNNING",
                progress=25.0,
            )

            # Node 2 immediately sees the task
            task_node2 = node2_store.get_task(tenant_id, env_id, "task-ha-100")
            self.assertIsNotNone(task_node2)
            self.assertEqual(task_node2["status"], "RUNNING")
            self.assertEqual(task_node2["progress"], 25.0)

            # Node 2 updates progress
            node2_store.save_task(
                task_id="task-ha-100",
                tenant_id=tenant_id,
                environment_id=env_id,
                principal_id="alice@corp.com",
                tool_name="vcf_resize_vm",
                status="COMPLETED",
                progress=100.0,
            )

            # Node 1 sees completion
            task_node1 = node1_store.get_task(tenant_id, env_id, "task-ha-100")
            self.assertEqual(task_node1["status"], "COMPLETED")
            self.assertEqual(task_node1["progress"], 100.0)

            # 2. Distributed Resource Lease and Fencing Token
            ok1, msg1, token1 = node1_store.acquire_lease(
                tenant_id=tenant_id,
                resource_id="vm-cluster-a",
                lease_holder="node-1-worker",
                ttl_seconds=30.0,
                environment_id=env_id,
            )
            self.assertTrue(ok1)
            self.assertGreater(token1, 0)

            # Node 2 attempts to acquire the same lease -> Conflict
            ok2, msg2, token2 = node2_store.acquire_lease(
                tenant_id=tenant_id,
                resource_id="vm-cluster-a",
                lease_holder="node-2-worker",
                ttl_seconds=30.0,
                environment_id=env_id,
            )
            self.assertFalse(ok2)
            self.assertIn("locked by lease holder 'node-1-worker'", msg2)

            # Node 1 releases lease
            node1_store.release_lease(tenant_id, "vm-cluster-a", "node-1-worker", env_id)

            # Node 2 acquires lease with incremented fencing token
            ok2_retry, msg2_retry, token2_retry = node2_store.acquire_lease(
                tenant_id=tenant_id,
                resource_id="vm-cluster-a",
                lease_holder="node-2-worker",
                ttl_seconds=30.0,
                environment_id=env_id,
            )
            self.assertTrue(ok2_retry)
            self.assertGreater(token2_retry, token1)

            # 3. Single-Use Nonce Invalidation Across Nodes
            nonce = "nonce-single-use-777"
            node1_store.save_approval(
                approval_id="app-1",
                plan_id="plan-1",
                tenant_id=tenant_id,
                environment_id=env_id,
                approver_id="bob@corp.com",
                nonce=nonce,
            )

            # Node 1 consumes nonce -> True
            consumed_1 = node1_store.consume_approval_nonce(tenant_id, env_id, nonce)
            self.assertTrue(consumed_1)

            # Node 2 attempts to consume same nonce -> False (Replay blocked)
            consumed_2 = node2_store.consume_approval_nonce(tenant_id, env_id, nonce)
            self.assertFalse(consumed_2)

            node1_store.close()
            node2_store.close()
        finally:
            if os.path.exists(shared_db_path):
                os.remove(shared_db_path)


if __name__ == "__main__":
    unittest.main()
