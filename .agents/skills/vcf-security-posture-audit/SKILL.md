---
name: vcf-security-posture-audit
description: >-
  [SECURITY_ADMIN | READ] Inspect control plane cryptographic audit integrity, appliance health, and security posture.
role: SECURITY_ADMIN
risk_class: READ
allowed_tools: [vcf_verify_audit_chain, vcf_get_health, vcf_list_domains]
required_capabilities: [audit.log.verify, lifecycle.domain.read]
---

# Enterprise VCF Security Posture & Audit Integrity Inspection (`vcf-security-posture-audit`)

## Single-Responsibility Objective
Inspect control plane cryptographic audit integrity, appliance health, and security posture.

- **Primary VCF Role**: `SECURITY_ADMIN`
- **Risk Class**: `READ`
- **Strict Tool Whitelist**: `vcf_verify_audit_chain`, `vcf_get_health`, `vcf_list_domains`

## Input Arguments
- `limit` (optional): Number of recent audit events to inspect (default: 50).

## Preconditions
- Caller holds SECURITY_ADMIN, VCF_AUDITOR, or VCF_PLATFORM_ADMIN role.

## Deterministic SOP Workflow
1. Call `vcf_verify_audit_chain` with `limit={limit}` to verify zero tampering in `audit_chain`.
2. Call `vcf_get_health` and `vcf_list_domains` to inspect subsystem security and domain states.

## Postconditions
- Produce a security posture report covering audit chain integrity and denied access attempts.

## Safety Guardrails
- **NEVER**: Do not modify workload resources during a security posture audit.
