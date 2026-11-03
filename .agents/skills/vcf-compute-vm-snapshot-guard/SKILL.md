---
name: vcf-compute-vm-snapshot-guard
description: >-
  [COMPUTE_OPERATOR | SAFE_WRITE] Create a point-in-time VM protection snapshot prior to patching or configuration changes.
role: COMPUTE_OPERATOR
risk_class: SAFE_WRITE
allowed_tools: [vcf_get_vm, vcf_list_snapshots, vcf_create_snapshot, vcf_get_plan]
required_capabilities: [compute.vm.read, compute.vm.snapshot]
---

# Pre-Maintenance VM Point-in-Time Snapshot Creation (`vcf-compute-vm-snapshot-guard`)

## Single-Responsibility Objective
Create a point-in-time VM protection snapshot prior to patching or configuration changes.

- **Primary VCF Role**: `COMPUTE_OPERATOR`
- **Risk Class**: `SAFE_WRITE`
- **Strict Tool Whitelist**: `vcf_get_vm`, `vcf_list_snapshots`, `vcf_create_snapshot`, `vcf_get_plan`

## Input Arguments
- `vm_id` (required): Target VM ID or name.
- `snapshot_name` (required): Descriptive snapshot label (e.g. pre-patch-chg104).

## Preconditions
- Check existing snapshot count via `vcf_list_snapshots` to avoid deep snapshot chains.

## Deterministic SOP Workflow
1. Step 1 (Inspect): Call `vcf_list_snapshots` for `vm_id={vm_id}` to verify existing snapshot chain depth.
2. Step 2 (Dry-Run Plan): Call `vcf_create_snapshot` with `vm_id={vm_id}`, `snapshot_name={snapshot_name}`, `dry_run=True`.
3. Step 3 (Approval Gate): Obtain execution authorization (`approval_id` and `nonce`) for `plan_id`.
4. Step 4 (Live Execute): When lab/VI-JSON snapshots are enabled, execute `vcf_create_snapshot` with `dry_run=False`, `plan_id`, `approval_id`, and `nonce`.

Approval hand-off: the dry run's `how_to_approve` says how the person approves. In personal mode the person who asked approves (chat prompt, local approval link or their own terminal) and you then call the tool again with the SAME arguments plus `plan_id` only; in team mode a separate approver's `approval_id` and `nonce` are needed as well. `vcf_get_plan` shows whether a plan is approved. Never approve a plan on the person's behalf.

## Postconditions
- Verify `snapshot_id` is returned and listed in `vcf_list_snapshots`.

## Safety Guardrails
- **NEVER**: Never use VM snapshots as a substitute for long-term backup archives.
