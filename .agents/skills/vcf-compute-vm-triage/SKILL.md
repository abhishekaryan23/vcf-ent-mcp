---
name: vcf-compute-vm-triage
description: >-
  [COMPUTE_OPERATOR | READ] Diagnose a single virtual machine's power state, CPU/RAM configuration, and cluster utilization.
role: COMPUTE_OPERATOR
risk_class: READ
allowed_tools: [vcf_get_vm, vcf_list_vms, vcf_query_telemetry]
required_capabilities: [compute.vm.read, telemetry.metrics.read]
---

# Compute VM Hardware, State & Telemetry Triage (`vcf-compute-vm-triage`)

## Single-Responsibility Objective
Diagnose a single virtual machine's power state, CPU/RAM configuration, and cluster utilization.

- **Primary VCF Role**: `COMPUTE_OPERATOR`
- **Risk Class**: `READ`
- **Strict Tool Whitelist**: `vcf_get_vm`, `vcf_list_vms`, `vcf_query_telemetry`

## Input Arguments
- `vm_id` (required): Target VM MOID (e.g. vm-101) or VM name (e.g. workload-vm-101).
- `cluster_id` (optional): Cluster ID hosting the VM.

## Preconditions
- Target VM belongs to a cluster within the operator's allowed resource scope.

## Deterministic SOP Workflow
1. Call `vcf_get_vm` with `vm_id={vm_id}` (supports both vSphere MOID and VM name resolution).
2. Call `vcf_query_telemetry` on the VM's cluster to check `cpu_usage_pct` and `mem_usage_pct`.
3. Summarize current VM sizing, power state, and cluster headroom.

## Postconditions
- Return verified VM hardware configuration and telemetry without mutating VM state.

## Safety Guardrails
- **NEVER**: Do not resize or power-cycle the VM inside this triage skill.
