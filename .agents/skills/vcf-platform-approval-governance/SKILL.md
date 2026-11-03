---
name: vcf-platform-approval-governance
description: >-
  [VCF_PLATFORM_ADMIN | HIGH_IMPACT] Review pending dry-run execution plans, verify target resource state and blast radius, and issue KMS-signed approvals.
role: VCF_PLATFORM_ADMIN
risk_class: HIGH_IMPACT
allowed_tools: [vcf_verify_audit_chain, vcf_get_health, vcf_get_vm, vcf_list_domains]
required_capabilities: [audit.log.verify, lifecycle.domain.read, compute.vm.read]
---

# Execution Plan TOCTOU Review & Cryptographic Approval Governance (`vcf-platform-approval-governance`)

## Single-Responsibility Objective
Review pending dry-run execution plans, verify target resource state and blast radius, and issue KMS-signed approvals.

- **Primary VCF Role**: `VCF_PLATFORM_ADMIN`
- **Risk Class**: `HIGH_IMPACT`
- **Strict Tool Whitelist**: `vcf_verify_audit_chain`, `vcf_get_health`, `vcf_get_vm`, `vcf_list_domains`

## Input Arguments
- `plan_id` (optional): Execution plan ID to inspect and approve.

## Preconditions
- Reviewer must be a distinct principal from the plan initiator (unless in non-production laptop lab mode with `VCF_LAB_SELF_APPROVE=true`).

## Deterministic SOP Workflow
1. Step 1 (Discover Pending Plans): Call `enterprise/plans/list` (or CLI `vcf-mcp plans list`) to view `PENDING_APPROVAL` plans.
2. Step 2 (Inspect Plan Details): Call `enterprise/plans/get` with `plan_id={plan_id}` to inspect `normalized_args`, `resource_revisions`, and `impact_summary`.
3. Step 3 (Verify Infrastructure State): Call `vcf_get_vm` or `vcf_get_health` to confirm target resource readiness.
4. Step 4 (Approve): Call `enterprise/plans/approve` with `plan_id={plan_id}` (or CLI `vcf-mcp plans approve {plan_id}`) to mint a KMS-signed `SignedExecutionAuthorization`.

## Postconditions
- Plan status transitions to `APPROVED` and initiator can retrieve `approval_id` and `nonce` via `enterprise/plans/get`.

## Safety Guardrails
- **NEVER**: Never approve a plan whose resource revisions or arguments do not match the change ticket.
