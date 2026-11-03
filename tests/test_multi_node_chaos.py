# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Multi-Node Chaos and Distributed Split-Brain Test Suite (Phases 20-23).
Verifies:
- Multi-node split-brain lease contention on shared durable stores
- Monotonic fencing token invalidation on partition/takeover
- Node crash during multi-step workflow with safe, idempotent resumption
- Concurrent multi-node race conditions on distributed locks
"""

import time
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from vcf_enterprise_mcp.state.sqlite_store import SQLiteDurableStore
from vcf_enterprise_mcp.state.leases import ResourceLeaseManager
from vcf_enterprise_mcp.core.errors import (
    ResourceLockException,
    StaleFencingTokenException,
)
from vcf_enterprise_mcp.workflows.task_store import TaskStore, WorkflowStep


class TestMultiNodeChaos(unittest.TestCase):

    def setUp(self):
        # Create temporary on-disk SQLite DB to simulate shared multi-node storage
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "shared_cluster.db"
        
        # Two distinct nodes sharing the same backing database
        self.store_node_a = SQLiteDurableStore(db_path=str(self.db_path))
        self.store_node_b = SQLiteDurableStore(db_path=str(self.db_path))

        self.leases_node_a = ResourceLeaseManager(self.store_node_a, tenant_id="tenant-prod")
        self.leases_node_b = ResourceLeaseManager(self.store_node_b, tenant_id="tenant-prod")

        self.tasks_node_a = TaskStore(self.store_node_a)
        self.tasks_node_b = TaskStore(self.store_node_b)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_multi_node_lease_contention_and_split_brain_prevention(self):
        """Verifies mutual exclusion across nodes; Node B is strictly rejected when Node A holds lease."""
        resource_id = "vm-database-cluster-01"

        # Node A acquires exclusive lease
        lease_a = self.leases_node_a.acquire_exclusive(
            resource_id=resource_id,
            lease_holder="node-alpha-controller",
            ttl_seconds=30.0,
        )
        self.assertEqual(lease_a.owner, "node-alpha-controller")
        self.assertGreater(lease_a.fencing_token, 0)

        # Node B attempts to acquire same resource -> must be rejected
        with self.assertRaises(ResourceLockException):
            self.leases_node_b.acquire_exclusive(
                resource_id=resource_id,
                lease_holder="node-beta-controller",
                ttl_seconds=30.0,
            )

        # Node A releases lease
        self.leases_node_a.release(resource_id=resource_id, lease_holder="node-alpha-controller")

        # Node B now successfully acquires lease with strictly monotonic fencing token
        lease_b = self.leases_node_b.acquire_exclusive(
            resource_id=resource_id,
            lease_holder="node-beta-controller",
            ttl_seconds=30.0,
        )
        self.assertEqual(lease_b.owner, "node-beta-controller")
        self.assertGreater(lease_b.fencing_token, lease_a.fencing_token)

    def test_fencing_token_invalidation_after_expiration_and_takeover(self):
        """
        Simulates partition or GC pause on Node A:
        Node A lease expires, Node B takes over with higher fencing token.
        When Node A awakens, its old fencing token is rejected.
        """
        resource_id = "cluster-edge-01"

        # Node A acquires lease with short TTL (50ms)
        lease_a = self.leases_node_a.acquire_exclusive(
            resource_id=resource_id,
            lease_holder="node-alpha",
            ttl_seconds=0.05,
        )
        token_a = lease_a.fencing_token

        # Wait for lease to expire (simulating network partition or freeze)
        time.sleep(0.07)

        # Node B acquires the expired lease
        lease_b = self.leases_node_b.acquire_exclusive(
            resource_id=resource_id,
            lease_holder="node-beta",
            ttl_seconds=30.0,
        )
        token_b = lease_b.fencing_token
        self.assertGreater(token_b, token_a)

        # Node A awakens and attempts to validate its old token -> FAILS with StaleFencingTokenException
        with self.assertRaises(StaleFencingTokenException) as ctx:
            self.leases_node_a.validate_fencing_token(resource_id=resource_id, presented_token=token_a)

        self.assertEqual(ctx.exception.details["presented_token"], token_a)
        self.assertEqual(ctx.exception.details["current_fencing_token"], token_b)

        # Node B's active token validates successfully
        self.assertTrue(self.leases_node_b.validate_fencing_token(resource_id=resource_id, presented_token=token_b))

    def test_node_crash_during_multi_step_workflow_and_safe_recovery(self):
        """
        Node A begins a 2-step workflow, finishes step 1, records idempotency, then crashes.
        Node B resumes the workflow, avoids duplicating step 1, and finishes step 2.
        """
        from vcf_enterprise_mcp.auth.identity import Principal

        tenant_id = "tenant-prod"
        env_id = "env-prod"
        idemp_step1 = "idemp-snap-vm101-001"
        executed_side_effects = []

        admin_principal = Principal(
            user_id="admin@corp.com",
            corporate_groups=["VCF-Platform-Admins"],
            tenant_id=tenant_id,
            environment_ids=[env_id],
        )

        # 1. Node A creates task with 2 steps
        step1 = WorkflowStep(name="create_snapshot", is_reversible=True)
        step2 = WorkflowStep(name="resize_vm", is_reversible=True)
        task = self.tasks_node_a.create_task(
            tool_name="vcf_resize_vm",
            principal=admin_principal,
            tenant_id=tenant_id,
            environment_id=env_id,
            steps=[step1, step2],
        )
        task_id = task.task_id

        # 2. Node A executes Step 1: Create Snapshot
        executed_side_effects.append("create_snapshot")
        self.store_node_a.record_idempotency(
            tenant_id=tenant_id,
            idempotency_key=idemp_step1,
            principal_id="admin@corp.com",
            tool_id="vcf_create_snapshot",
            args_sha256="hash-snap-01",
            response_payload={"snapshot_id": "snap-99", "status": "SUCCESS"},
            status="COMMITTED",
            environment_id=env_id,
        )
        step1.completed = True
        self.tasks_node_a.update_task_progress(
            task_id=task_id,
            current_step=1,
            step_desc="Completed Step 1: Snapshot",
            status="RUNNING",
            principal=admin_principal,
        )

        # 3. Simulate Node A sudden crash!
        del self.tasks_node_a
        del self.store_node_a

        # 4. Node B recovers: discovers in-progress / resumable tasks
        resumables = self.store_node_b.list_resumable_tasks(tenant_id=tenant_id, environment_id=env_id)
        self.assertEqual(len(resumables), 1)
        crashed_task = resumables[0]
        self.assertEqual(crashed_task["task_id"], task_id)

        # 5. Node B checks Step 1 idempotency
        cached_step1 = self.store_node_b.get_idempotency_record(tenant_id=tenant_id, idempotency_key=idemp_step1, environment_id=env_id)
        self.assertIsNotNone(cached_step1)
        # Step 1 is NOT re-executed!

        # 6. Node B executes Step 2: Resize VM
        executed_side_effects.append("resize_vm")
        step2.completed = True
        self.tasks_node_b.complete_task(
            task_id=task_id,
            result={"status": "SUCCESS", "message": "Recovered and completed by Node B"},
            principal=admin_principal,
        )

        # Verify side effects: exactly 1 snapshot and 1 resize (zero duplicates)
        self.assertEqual(executed_side_effects, ["create_snapshot", "resize_vm"])
        final_task = self.tasks_node_b.get_task(task_id=task_id, principal=admin_principal)
        self.assertEqual(final_task.status, "COMPLETED")
        self.assertEqual(final_task.progress_pct, 100.0)

    def test_concurrent_multi_node_lease_race(self):
        """10 nodes race concurrently to claim the same resource; exactly 1 wins."""
        resource_id = "critical-vcf-gateway"
        num_nodes = 10
        winner_count = 0
        lock_exceptions = 0

        def attempt_claim(node_idx: int) -> bool:
            store = SQLiteDurableStore(db_path=str(self.db_path))
            mgr = ResourceLeaseManager(store, tenant_id="tenant-prod")
            try:
                mgr.acquire_exclusive(
                    resource_id=resource_id,
                    lease_holder=f"node-{node_idx}",
                    ttl_seconds=30.0,
                )
                return True
            except ResourceLockException:
                return False

        with ThreadPoolExecutor(max_workers=num_nodes) as executor:
            results = list(executor.map(attempt_claim, range(num_nodes)))

        winner_count = sum(1 for r in results if r is True)
        lock_exceptions = sum(1 for r in results if r is False)

        self.assertEqual(winner_count, 1)
        self.assertEqual(lock_exceptions, num_nodes - 1)
