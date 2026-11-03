---
name: vcf-compute-vm-power-cycle
description: >-
  [COMPUTE_OPERATOR | SAFE_WRITE] Execute a single controlled power action on a target VM using mandatory dry-run planning and postcondition verification.
role: COMPUTE_OPERATOR
risk_class: SAFE_WRITE
allowed_tools: [vcf_get_vm, vcf_power_vm, vcf_get_plan]
required_capabilities: [compute.vm.read, compute.vm.power]
---

# Safe VM Power State Transition (Start / Stop / Restart / Suspend) (`vcf-compute-vm-power-cycle`)

## Single-Responsibility Objective
Execute a single controlled power action on a target VM using mandatory dry-run planning and postcondition verification.

- **Primary VCF Role**: `COMPUTE_OPERATOR`
- **Risk Class**: `SAFE_WRITE`
- **Strict Tool Whitelist**: `vcf_get_vm`, `vcf_power_vm`, `vcf_get_plan`

## Input Arguments
- `vm_id` (required): Target VM ID or name.
- `action` (required): Power action: start, stop, restart, or suspend.

## Preconditions
- Inspect current VM power state via `vcf_get_vm` before generating a dry-run plan.

## Deterministic SOP Workflow
1. Step 1 (Inspect): Call `vcf_get_vm` for `vm_id={vm_id}` to confirm current power state and cluster ownership.
2. Step 2 (Dry-Run Plan): Call `vcf_power_vm` with `vm_id={vm_id}`, `action={action}`, `dry_run=True` to generate a deterministic `plan_id`.
3. Step 3 (Approval Gate): Obtain approval for `plan_id` (via `enterprise/plans/approve`, CLI `vcf-mcp plans approve`, or `enterprise/plans/get` handback).
4. Step 4 (Live Execute & Verify): Call `vcf_power_vm` with `dry_run=False`, `plan_id`, `approval_id`, and `nonce`.

Approval hand-off: the dry run's `how_to_approve` says how the person approves. In personal mode the person who asked approves (chat prompt, local approval link or their own terminal) and you then call the tool again with the SAME arguments plus `plan_id` only; in team mode a separate approver's `approval_id` and `nonce` are needed as well. `vcf_get_plan` shows whether a plan is approved. Never approve a plan on the person's behalf.

## Postconditions
- Verify `new_power_state` matches the expected target state from vCenter.

## Safety Guardrails
- **NEVER**: Never call `vcf_power_vm` with `dry_run=False` without a valid `plan_id`, `approval_id`, and `nonce`.
