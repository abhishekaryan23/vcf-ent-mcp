---
name: vcf-compute-host-cluster-audit
description: >-
  [COMPUTE_ADMIN | READ] Audit commissioned physical ESXi hypervisor hosts, connection states, and cluster distribution.
role: COMPUTE_ADMIN
risk_class: READ
allowed_tools: [vcf_list_clusters, vcf_list_hosts, vcf_query_telemetry]
required_capabilities: [compute.cluster.read, compute.host.read, telemetry.metrics.read]
---

# Physical ESXi Hypervisor Host & Cluster Inventory Audit (`vcf-compute-host-cluster-audit`)

## Single-Responsibility Objective
Audit commissioned physical ESXi hypervisor hosts, connection states, and cluster distribution.

- **Primary VCF Role**: `COMPUTE_ADMIN`
- **Risk Class**: `READ`
- **Strict Tool Whitelist**: `vcf_list_clusters`, `vcf_list_hosts`, `vcf_query_telemetry`

## Input Arguments
- `cluster_id` (optional): Optional compute cluster ID filter.
- `datacenter_id` (optional): Datacenter ID (default: dc1).

## Preconditions
- Caller holds COMPUTE_ADMIN or VCF_VIEWER role.

## Deterministic SOP Workflow
1. Call `vcf_list_clusters` to enumerate compute clusters and host counts.
2. Call `vcf_list_hosts` with `cluster_id={cluster_id}` to inspect individual ESXi host statuses and versions.
3. Call `vcf_query_telemetry` to check cluster-level CPU/memory utilization balance.

## Postconditions
- Identify any disconnected or maintenance-mode ESXi hosts.

## Safety Guardrails
- **NEVER**: Do not execute host decommissioning or domain upgrades inside this audit skill.
