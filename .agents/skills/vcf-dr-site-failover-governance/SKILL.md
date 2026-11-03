---
name: vcf-dr-site-failover-governance
description: >-
  [DR_ADMIN | SAFE_WRITE] Audit cross-domain health and govern disaster recovery test bubble drills across primary and secondary sites.
role: DR_ADMIN
risk_class: SAFE_WRITE
allowed_tools: [vcf_list_domains, vcf_get_health, vcf_recover_site, vcf_get_plan]
required_capabilities: [lifecycle.domain.read, dr.replication.read, dr.failover.execute]
---

# Cross-Site Disaster Recovery Readiness & Drill Governance (`vcf-dr-site-failover-governance`)

## Single-Responsibility Objective
Audit cross-domain health and govern disaster recovery test bubble drills across primary and secondary sites.

- **Primary VCF Role**: `DR_ADMIN`
- **Risk Class**: `SAFE_WRITE`
- **Strict Tool Whitelist**: `vcf_list_domains`, `vcf_get_health`, `vcf_recover_site`, `vcf_get_plan`

## Input Arguments
- `recovery_plan_id` (required): DR recovery plan identifier (e.g. rp-cross-dc).
- `target_site` (optional): Target recovery site (default: dc2).

## Preconditions
- Verify both primary and secondary workload domains are healthy.

## Deterministic SOP Workflow
1. Call `vcf_list_domains` and `vcf_get_health` to validate domain and appliance health.
2. Execute `vcf_recover_site` with `dry_run=True` to evaluate recovery plan blast radius.
3. After approval, execute `vcf_recover_site` with `dry_run=False` and monitor task completion via `tasks/get`.

Approval hand-off: the dry run's `how_to_approve` says how the person approves. In personal mode the person who asked approves (chat prompt, local approval link or their own terminal) and you then call the tool again with the SAME arguments plus `plan_id` only; in team mode a separate approver's `approval_id` and `nonce` are needed as well. `vcf_get_plan` shows whether a plan is approved. Never approve a plan on the person's behalf.

## Postconditions
- Document drill task ID and isolated test bubble network verification.

## Safety Guardrails
- **NEVER**: Never execute unapproved site failovers.
