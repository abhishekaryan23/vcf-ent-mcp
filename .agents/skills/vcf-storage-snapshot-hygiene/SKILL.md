---
name: vcf-storage-snapshot-hygiene
description: >-
  [STORAGE_ADMIN | SAFE_WRITE] Inspect a VM's snapshot chain and safely delete a specific stale snapshot with disk consolidation.
role: STORAGE_ADMIN
risk_class: SAFE_WRITE
allowed_tools: [vcf_list_snapshots, vcf_delete_snapshot, vcf_get_plan]
required_capabilities: [compute.vm.read, compute.vm.snapshot]
---

# VM Snapshot Hygiene & Delta-Disk Consolidation (`vcf-storage-snapshot-hygiene`)

## Single-Responsibility Objective
Inspect a VM's snapshot chain and safely delete a specific stale snapshot with disk consolidation.

- **Primary VCF Role**: `STORAGE_ADMIN`
- **Risk Class**: `SAFE_WRITE`
- **Strict Tool Whitelist**: `vcf_list_snapshots`, `vcf_delete_snapshot`, `vcf_get_plan`

## Input Arguments
- `vm_id` (required): Target VM ID.
- `snapshot_id` (required): Target snapshot ID to remove.

## Preconditions
- Confirm `snapshot_id` exists on `vm_id` via `vcf_list_snapshots`.

## Deterministic SOP Workflow
1. Step 1 (List): Call `vcf_list_snapshots` with `vm_id={vm_id}` to confirm the target `snapshot_id={snapshot_id}`.
2. Step 2 (Dry-Run Plan): Call `vcf_delete_snapshot` with `vm_id={vm_id}`, `snapshot_id={snapshot_id}`, `dry_run=True` to generate `plan_id`.
3. Step 3 (Approval Gate): Obtain approval (`approval_id` and `nonce`) for `plan_id`.
4. Step 4 (Live Execute): Call `vcf_delete_snapshot` with `dry_run=False`, `plan_id`, `approval_id`, and `nonce`.

Approval hand-off: the dry run's `how_to_approve` says how the person approves. In personal mode the person who asked approves (chat prompt, local approval link or their own terminal) and you then call the tool again with the SAME arguments plus `plan_id` only; in team mode a separate approver's `approval_id` and `nonce` are needed as well. `vcf_get_plan` shows whether a plan is approved. Never approve a plan on the person's behalf.

## Postconditions
- Verify snapshot deletion succeeded and delta disks consolidated.

## Safety Guardrails
- **NEVER**: Never delete snapshots without first listing and verifying the exact `snapshot_id`.
