---
name: vcf-viewer-inventory-summary
description: >-
  [VCF_VIEWER | READ] Enumerate VCF workload domains, compute clusters, and virtual machines in read-only mode.
role: VCF_VIEWER
risk_class: READ
allowed_tools: [vcf_list_domains, vcf_list_clusters, vcf_list_vms]
required_capabilities: [lifecycle.domain.read, compute.cluster.read, compute.vm.read]
---

# VCF Workload Domain, Cluster & VM Inventory Summary (`vcf-viewer-inventory-summary`)

## Single-Responsibility Objective
Enumerate VCF workload domains, compute clusters, and virtual machines in read-only mode.

- **Primary VCF Role**: `VCF_VIEWER`
- **Risk Class**: `READ`
- **Strict Tool Whitelist**: `vcf_list_domains`, `vcf_list_clusters`, `vcf_list_vms`

## Input Arguments
- `cluster_id` (optional): Optional cluster id from vcf_list_clusters; omit to cover every cluster in every vCenter.

## Preconditions
- Caller holds at least VCF_VIEWER read clearance for the target tenant and environment.

## Deterministic SOP Workflow
1. Call `vcf_list_domains` to list active SDDC Manager management and VI workload domains.
2. Call `vcf_list_clusters` to inspect compute clusters and host counts.
3. Call `vcf_list_vms` (add `cluster_id` only if the user named a cluster) to summarize running and powered-off VMs.

## Postconditions
- Report domain, cluster, and VM counts with zero infrastructure mutations.

## Safety Guardrails
- **NEVER**: Do not invoke any L2_OPERATIONAL or L3_WORKFLOW mutating tools.
