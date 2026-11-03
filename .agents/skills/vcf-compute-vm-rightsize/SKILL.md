---
name: vcf-compute-vm-rightsize
description: >-
  [COMPUTE_OPERATOR | CHANGE] Rightsize a single VM's CPU core count or memory (GB) with TOCTOU revision binding and postcondition verification.
role: COMPUTE_OPERATOR
risk_class: CHANGE
allowed_tools: [vcf_get_vm, vcf_query_telemetry, vcf_resize_vm, vcf_get_plan]
required_capabilities: [compute.vm.read, telemetry.metrics.read, compute.vm.resize.memory]
---

# Controlled VM CPU & Memory Rightsizing (`vcf-compute-vm-rightsize`)

## Single-Responsibility Objective
Rightsize a single VM's CPU core count or memory (GB) with TOCTOU revision binding and postcondition verification.

- **Primary VCF Role**: `COMPUTE_OPERATOR`
- **Risk Class**: `CHANGE`
- **Strict Tool Whitelist**: `vcf_get_vm`, `vcf_query_telemetry`, `vcf_resize_vm`, `vcf_get_plan`

## Input Arguments
- `vm_id` (required): Target VM ID or name.
- `memory_gb` (optional): Target RAM in GB (optional if resizing CPU).
- `cpu_cores` (optional): Target vCPU core count (optional if resizing RAM).

## Preconditions
- Verify current VM CPU/RAM allocation and cluster capacity telemetry prior to dry-run.

## Deterministic SOP Workflow
1. Step 1 (Baseline): Call `vcf_get_vm` for `vm_id={vm_id}` to capture baseline `cpu_cores` and `memory_gb`.
2. Step 2 (Dry-Run Plan): Call `vcf_resize_vm` with `vm_id={vm_id}`, target `memory_gb`/`cpu_cores`, and `dry_run=True` to record resource revision and generate `plan_id`.
3. Step 3 (Approval Handback): Wait for approval or query `enterprise/plans/get` with `plan_id` to retrieve `approval_id` and single-use `nonce`.
4. Step 4 (Live Execute & Verify): Call `vcf_resize_vm` with `dry_run=False`, `plan_id`, `approval_id`, and `nonce`.

Approval hand-off: the dry run's `how_to_approve` says how the person approves. In personal mode the person who asked approves (chat prompt, local approval link or their own terminal) and you then call the tool again with the SAME arguments plus `plan_id` only; in team mode a separate approver's `approval_id` and `nonce` are needed as well. `vcf_get_plan` shows whether a plan is approved. Never approve a plan on the person's behalf.

## Postconditions
- Authoritative vCenter read-back confirms `allocated_memory_gb` and `allocated_cpu_cores` match requested sizing.

## Safety Guardrails
- **NEVER**: Never attempt VMDK disk expansion or NIC reconfiguration through `vcf_resize_vm`.
