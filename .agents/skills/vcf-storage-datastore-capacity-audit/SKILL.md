---
name: vcf-storage-datastore-capacity-audit
description: >-
  [STORAGE_OPERATOR | READ] Inspect vSAN, VMFS, and NFS datastores for free capacity (GB), utilization ratios, and health status.
role: STORAGE_OPERATOR
risk_class: READ
allowed_tools: [vcf_list_datastores, vcf_query_telemetry]
required_capabilities: [storage.datastore.read, telemetry.metrics.read]
---

# vSAN ESA/OSA & Datastore Capacity Audit (`vcf-storage-datastore-capacity-audit`)

## Single-Responsibility Objective
Inspect vSAN, VMFS, and NFS datastores for free capacity (GB), utilization ratios, and health status.

- **Primary VCF Role**: `STORAGE_OPERATOR`
- **Risk Class**: `READ`
- **Strict Tool Whitelist**: `vcf_list_datastores`, `vcf_query_telemetry`

## Input Arguments
- `cluster_id` (optional): Target cluster ID (e.g. cluster-prod-a).
- `datacenter_id` (optional): Datacenter ID (default: dc1).

## Preconditions
- Caller holds STORAGE_OPERATOR, STORAGE_ADMIN, or VCF_VIEWER role.

## Deterministic SOP Workflow
1. Call `vcf_list_datastores` for `cluster_id={cluster_id}` to retrieve total and free capacity (GB) across all datastores.
2. Flag any datastore with less than 20% free capacity as a vSAN slack-space warning.

## Postconditions
- Return structured datastore capacity table with free percentage calculations.

## Safety Guardrails
- **NEVER**: Never delete datastores or modify VM storage policies during capacity auditing.
