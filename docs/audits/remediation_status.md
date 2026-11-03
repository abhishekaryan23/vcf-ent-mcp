# VCF Enterprise MCP Control Plane — Remediation Status Tracking

> **Historical document (September 2026).** Written about an older commit by an internal review; its readiness wording is superseded by [independent_review_2026_11_02.md](independent_review_2026_11_02.md) and by the project's "unofficial, under testing" status. Not a certification.

Tracking remediation for all findings from `docs/audits/independent_audit_1.0.0.md` and `docs/audits/independent_production_audit_report_v2.md`.

| Finding | Severity | Category | Status | PR / Branch | Tests | Verified |
|---|---|---|---|---|---|---|
| **SEC-01** | P0 | Authentication | **REMEDIATED** | `security/audit-remediation-v1` | `test_jwt_verification.py` | VERIFIED |
| **SEC-02** | P0 | Multi-Tenancy | **REMEDIATED** | `security/audit-remediation-v1` | `test_tenant_isolation.py` | VERIFIED |
| **SEC-03** | P0 | Authorization | **REMEDIATED** | `security/audit-remediation-v1` | `test_n_person_approval.py` | VERIFIED |
| **SEC-04** | P1 | Pre-Mutation Idempotency | **REMEDIATED** | `security/audit-remediation-v1` | `test_pre_mutation_idempotency.py` | VERIFIED |
| **SEC-05** | P0 | Plan KMS Signatures | **REMEDIATED** | `security/audit-remediation-v1` | `test_kms_signature_enforcement.py` | VERIFIED |
| **SEC-06** | P1 | Freeform Secret Scrubbing | **REMEDIATED** | `security/audit-remediation-v1` | `test_freeform_secret_redaction.py` | VERIFIED |
| **SEC-07** | P1 | SSRF & DNS Rebinding | **REMEDIATED** | `security/audit-remediation-v1` | `test_ssrf_dns_rebinding.py` | VERIFIED |
| **SEC-08** | P2 | Mock Credentials in Settings | **CONDITIONAL** | Backlog / Staging | N/A (Vault config) | PENDING_VAULT |
| **ARCH-01** | P0 | PostgreSQL HA Store | **REMEDIATED** | `security/audit-remediation-v1` | `test_postgres_ha_store.py` | VERIFIED |
| **ARCH-02** | P1 | Provider Transport Wiring | **REMEDIATED** | `security/audit-remediation-v1` | `test_tool_provider_wiring.py` | VERIFIED |
| **REL-01** | P0 | Crash Recovery Types | **REMEDIATED** | `security/audit-remediation-v1` | `test_crash_recovery_and_reconciliation.py`| VERIFIED |
| **REL-02** | P2 | Terminal Workflow Safety | **REMEDIATED** | `security/audit-remediation-v2` | `test_terminal_workflows_protection.py`| VERIFIED |
| **ROUTE-01**| P2 | Read vs Mutating Routing | **REMEDIATED** | `security/audit-remediation-v2` | `test_adversarial_router_benchmark.py` | VERIFIED |
| **ROUTE-02**| P2 | Intent Boundary Nuances | **OPEN / BACKLOG**| Backlog / Router v2 | `scratch/test_adversarial_routing.py` | BACKLOG |
| **OBS-01** | P2 | W3C Traceparent Header | **REMEDIATED** | `security/audit-remediation-v2` | `test_traceparent_propagation.py` | VERIFIED |
| **PKG-01** | P0 | Missing PyPI Dependencies | **REMEDIATED** | `security/audit-remediation-v1` | `pip check` | VERIFIED |
| **PKG-02** | P3 | Dynamic CycloneDX 1.5 SBOM| **REMEDIATED** | `security/audit-remediation-v2` | `test_sbom_generation.py` | VERIFIED |
| **TEST-01**| P3 | Code Coverage 79% / 80% | **CONDITIONAL** | Backlog / Quality Gate | `pytest --cov=vcf_enterprise_mcp` | CONDITIONAL |

---

## Remediation Milestones
- **Baseline Release**: `audit-baseline-1.0.0` (Tagged `audit-baseline-1.0.0` — Initial Audit identified 6 P0 blockers).
- **Remediation Wave 1 (`security/audit-remediation-v1`)**: Resolved all 6 P0 blockers and initial P1 security items.
- **Remediation Wave 2 (`security/audit-remediation-v2`)**: Resolved terminal workflow protection, W3C traceparent context propagation, dynamic CycloneDX SBOM generation, read safety gate in intent router, and test suite expansion (204 tests, 100% pass).
- **Production Status**: Promoted to `PILOT READY / CONDITIONAL PRODUCTION READY`.
