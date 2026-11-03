---
name: vcf-auditor-chain-verification
description: >-
  [VCF_AUDITOR | READ] Verify the SHA-256 cryptographic hash chain of the MCP control plane audit log and review recent events.
role: VCF_AUDITOR
risk_class: READ
allowed_tools: [vcf_verify_audit_chain, vcf_get_health]
required_capabilities: [audit.log.verify, lifecycle.domain.read]
---

# SOC2 Tamper-Evident Audit Chain Verification (`vcf-auditor-chain-verification`)

## Single-Responsibility Objective
Verify the SHA-256 cryptographic hash chain of the MCP control plane audit log and review recent events.

- **Primary VCF Role**: `VCF_AUDITOR`
- **Risk Class**: `READ`
- **Strict Tool Whitelist**: `vcf_verify_audit_chain`, `vcf_get_health`

## Input Arguments
- `limit` (optional): Maximum number of recent audit records to inspect (default: 25).

## Preconditions
- Caller holds VCF_AUDITOR, SECURITY_ADMIN, or VCF_PLATFORM_ADMIN role.

## Deterministic SOP Workflow
1. Call `vcf_verify_audit_chain` with `limit={limit}` to validate every SHA-256 hash link (`prev_hash` -> `current_hash`) in durable storage.
2. Inspect returned `recent_events` for any `DENIED` or `FAILED` tool executions and report their trace IDs and actors.

## Postconditions
- Confirm `integrity_verified == True` or immediately escalate tamper evidence.

## Safety Guardrails
- **NEVER**: Auditors must never approve execution plans, modify tasks, or execute infrastructure mutations.
