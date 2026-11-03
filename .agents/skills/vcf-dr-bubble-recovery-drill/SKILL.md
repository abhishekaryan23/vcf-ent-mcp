---
name: vcf-dr-bubble-recovery-drill
description: >-
  [DR_OPERATOR | SAFE_WRITE] Run a non-disruptive disaster recovery failover test drill in an isolated bubble network.
role: DR_OPERATOR
risk_class: SAFE_WRITE
allowed_tools: [vcf_get_health, vcf_recover_site, vcf_get_plan]
required_capabilities: [lifecycle.domain.read, dr.replication.read]
---

# Non-Disruptive Site Recovery Test Bubble Drill (`vcf-dr-bubble-recovery-drill`)

## Single-Responsibility Objective
Run a non-disruptive disaster recovery failover test drill in an isolated bubble network.

- **Primary VCF Role**: `DR_OPERATOR`
- **Risk Class**: `SAFE_WRITE`
- **Strict Tool Whitelist**: `vcf_get_health`, `vcf_recover_site`, `vcf_get_plan`

## Input Arguments
- `recovery_plan_id` (required): DR recovery plan name (e.g. rp-prod).
- `target_site` (optional): Secondary recovery site ID (default: dc2).

## Preconditions
- Verify secondary site health via `vcf_get_health` prior to starting the test bubble drill.

## Deterministic SOP Workflow
1. Step 1 (Health Check): Call `vcf_get_health` to confirm recovery site readiness.
2. Step 2 (Dry-Run Plan): Call `vcf_recover_site` with `recovery_plan_id={recovery_plan_id}`, `target_site={target_site}`, `dry_run=True` to generate `plan_id`.
3. Step 3 (Approval Gate): Obtain approval (`approval_id` and `nonce`) for `plan_id`.
4. Step 4 (Live Drill Execution): Call `vcf_recover_site` with `recovery_plan_id={recovery_plan_id}`, `dry_run=False`, `plan_id`, `approval_id`, and `nonce`.

Approval hand-off: the dry run's `how_to_approve` says how the person approves. In personal mode the person who asked approves (chat prompt, local approval link or their own terminal) and you then call the tool again with the SAME arguments plus `plan_id` only; in team mode a separate approver's `approval_id` and `nonce` are needed as well. `vcf_get_plan` shows whether a plan is approved. Never approve a plan on the person's behalf.

## Postconditions
- Confirm test bubble workflow task is running with zero production traffic impact.

## Safety Guardrails
- **NEVER**: Never initiate an unplanned production failover; only isolated test bubble drills are permitted.
