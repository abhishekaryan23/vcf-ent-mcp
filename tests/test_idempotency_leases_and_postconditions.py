# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Test Suite: Idempotency Safety, Resource Leases, and Postcondition Verification.
Validates:
- Idempotent execution (identical key + arguments returns cached response)
- Idempotency conflict rejection (identical key + different arguments raises IdempotencyConflictException)
- Resource leases (exclusive resource locking blocks concurrent clobbering)
- Postcondition verification (detecting when actual infrastructure doesn't achieve requested state)
"""

from tests.fixtures.authorized_execution import execute_authorized
import unittest
import asyncio
from vcf_enterprise_mcp.auth.identity import Principal
from vcf_enterprise_mcp.state.durable_store import DurableStore
from vcf_enterprise_mcp.state.leases import ResourceLeaseManager, ResourceLockException
from vcf_enterprise_mcp.tools.operational_tools import VCFResizeVMTool
from vcf_enterprise_mcp.policy.enforcement import PolicyEnforcementPoint
from vcf_enterprise_mcp.policy.engine import PolicyDecisionPoint
from vcf_enterprise_mcp.config.settings import PolicyConfig
from vcf_enterprise_mcp.core.errors import (
    IdempotencyConflictException,
    PostconditionFailedException,
)


class FaultyResizeTool(VCFResizeVMTool):
    """Simulates a buggy upstream API that returns HTTP 200 without achieving the state."""
    async def run_live(self, principal: Principal, arguments: dict) -> dict:
        # Returns wrong memory allocation (simulating an upstream bug/failure)
        return {
            "dry_run": False,
            "status": "SUCCESS",
            "vm_id": arguments["vm_id"],
            "allocated_memory_gb": 16,  # Did not resize to requested 32!
        }


class TestIdempotencyLeasesAndPostconditions(unittest.TestCase):

    def setUp(self):
        self.durable = DurableStore(":memory:")
        self.pdp = PolicyDecisionPoint(
            config=PolicyConfig(operating_mode="AUDITED_OPERATIONS"),
            durable_store=self.durable,
        )
        self.pep = PolicyEnforcementPoint(pdp=self.pdp)
        self.lease_mgr = ResourceLeaseManager(self.durable)
        self.alice = Principal(
            user_id="alice@corp.com",
            corporate_groups=["VCF-Compute-Operators"],
            allowed_clusters=["cluster-prod-a"],
        )
        self.bob = Principal(
            user_id="bob@corp.com",
            corporate_groups=["VCF-Compute-Operators"],
            allowed_clusters=["cluster-prod-a"],
        )
        self.resize_tool = VCFResizeVMTool(
            pep=self.pep,
            durable_store=self.durable,
        )

    def test_idempotent_mutation_caching(self):
        args = {"vm_id": "vm-101", "cluster_id": "cluster-prod-a", "memory_gb": 32, "idempotency_key": "idemp-vm101-001"}
        # First call executes and records
        res1 = asyncio.run(execute_authorized(self.resize_tool, self.alice, args))
        self.assertEqual(res1["status"], "SUCCESS")
        self.assertEqual(res1["allocated_memory_gb"], 32)

        # Second call with exact same key and arguments returns cached result
        res2 = asyncio.run(execute_authorized(self.resize_tool, self.alice, args))
        self.assertEqual(res1, res2)

    def test_idempotency_conflict_rejection(self):
        args1 = {"vm_id": "vm-101", "cluster_id": "cluster-prod-a", "memory_gb": 32, "idempotency_key": "idemp-vm101-002"}
        asyncio.run(execute_authorized(self.resize_tool, self.alice, args1))

        # Reusing same key with different memory_gb (64 instead of 32) must be rejected!
        args2 = {"vm_id": "vm-101", "cluster_id": "cluster-prod-a", "memory_gb": 64, "idempotency_key": "idemp-vm101-002"}
        with self.assertRaises(IdempotencyConflictException) as ctx:
            asyncio.run(execute_authorized(self.resize_tool, self.alice, args2))
        self.assertIn("previously recorded with different arguments hash", str(ctx.exception))

    def test_resource_lease_exclusive_locking(self):
        # Alice acquires exclusive lease on vm-102 for 30s
        acquired = self.lease_mgr.acquire_exclusive("vm-102", lease_holder=self.alice.user_id, ttl_seconds=30.0)
        self.assertTrue(acquired)

        # Bob concurrently attempts to acquire lease on same vm-102 -> raises ResourceLockException!
        with self.assertRaises(ResourceLockException) as ctx:
            self.lease_mgr.acquire_exclusive("vm-102", lease_holder=self.bob.user_id, ttl_seconds=30.0)
        self.assertIn("locked by lease holder 'alice@corp.com'", str(ctx.exception))

        # Alice releases lease
        self.lease_mgr.release("vm-102", lease_holder=self.alice.user_id)

        # Bob can now acquire lease
        bob_acquired = self.lease_mgr.acquire_exclusive("vm-102", lease_holder=self.bob.user_id, ttl_seconds=30.0)
        self.assertTrue(bob_acquired)

    def test_postcondition_verification_failure_detection(self):
        faulty_tool = FaultyResizeTool(pep=self.pep, durable_store=self.durable)
        args = {"vm_id": "vm-101", "cluster_id": "cluster-prod-a", "memory_gb": 32}

        # Faulty tool returns 16GB instead of requested 32GB -> PostconditionFailedException!
        with self.assertRaises(PostconditionFailedException) as ctx:
            asyncio.run(execute_authorized(faulty_tool, self.alice, args))
        self.assertIn("Postcondition verification failed", str(ctx.exception))
        self.assertIn("Expected 32 GB, got 16 GB", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
