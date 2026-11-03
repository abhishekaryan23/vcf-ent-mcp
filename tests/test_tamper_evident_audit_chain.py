# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Test Suite: Tamper-Evident Cryptographic Hash-Chained Audit Stream.
Validates:
- Cryptographic hash chaining of immutable audit records
- Zero-error integrity verification across sequential events
- Detection of out-of-band tampering or altered audit entries
"""

import unittest
import sqlite3
from vcf_enterprise_mcp.state.durable_store import DurableStore
from vcf_enterprise_mcp.audit.recorder import AuditRecorder
from vcf_enterprise_mcp.auth.identity import Principal
from vcf_enterprise_mcp.policy.models import PolicyDecision, RiskClass


class TestTamperEvidentAuditChain(unittest.TestCase):

    def setUp(self):
        self.durable = DurableStore(":memory:")
        self.recorder = AuditRecorder(durable_store=self.durable)
        self.alice = Principal(user_id="alice@corp.com", corporate_groups=["VCF-Compute-Operators"])

    def test_audit_hash_chaining_and_integrity_verification(self):
        # 1. Record series of operations
        for i in range(5):
            decision = PolicyDecision(allow=True, reason="Authorized", risk_class=RiskClass.READ)
            rec = self.recorder.record_call(
                principal=self.alice,
                tool_name="vcf_list_vms",
                arguments={"cluster_id": f"cluster-0{i}"},
                decision=decision,
            )
            self.recorder.finalize_record(rec, status="SUCCESS", summary=f"Query {i} complete")

        # 2. Verify audit chain integrity
        valid, bad_seq = self.durable.verify_audit_integrity()
        self.assertTrue(valid)
        self.assertIsNone(bad_seq)

    def test_tamper_detection_in_audit_chain(self):
        # Record 3 events
        for i in range(3):
            decision = PolicyDecision(allow=True, reason="Authorized", risk_class=RiskClass.CHANGE)
            rec = self.recorder.record_call(
                principal=self.alice,
                tool_name="vcf_resize_vm",
                arguments={"vm_id": f"vm-{i}", "memory_gb": 32},
                decision=decision,
            )
            self.recorder.finalize_record(rec, status="SUCCESS")

        # Verify integrity initially passes
        valid1, _ = self.durable.verify_audit_integrity()
        self.assertTrue(valid1)

        # Tampering event: Attacker directly alters the database record payload for seq_id = 2
        with self.durable._lock:
            cur = self.durable._conn.cursor()
            cur.execute("UPDATE audit_chain SET record_payload = '{\"tampered\": true}' WHERE seq_id = 2")
            self.durable._conn.commit()

        # Integrity check MUST detect tampering at seq_id = 2
        valid2, bad_seq = self.durable.verify_audit_integrity()
        self.assertFalse(valid2)
        self.assertEqual(bad_seq, 2)


if __name__ == "__main__":
    unittest.main()
