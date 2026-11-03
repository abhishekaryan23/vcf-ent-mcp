---
name: vcf-viewer-health-triage
description: >-
  [VCF_VIEWER | READ] Inspect SDDC Manager, vCenter, and NSX subsystem health scores and active alarms.
role: VCF_VIEWER
risk_class: READ
allowed_tools: [vcf_get_health, vcf_query_telemetry]
required_capabilities: [lifecycle.domain.read, telemetry.metrics.read]
---

# VCF Subsystem Health & Alarm Triage (`vcf-viewer-health-triage`)

## Single-Responsibility Objective
Inspect SDDC Manager, vCenter, and NSX subsystem health scores and active alarms.

- **Primary VCF Role**: `VCF_VIEWER`
- **Risk Class**: `READ`
- **Strict Tool Whitelist**: `vcf_get_health`, `vcf_query_telemetry`

## Input Arguments
- `datacenter_id` (optional): Target datacenter ID (default: dc1).
- `cluster_id` (optional): Target cluster ID for telemetry check.

## Preconditions
- Caller is authenticated with read visibility into the target datacenter.

## Deterministic SOP Workflow
1. Call `vcf_get_health` for `datacenter_id={datacenter_id}` to retrieve consolidated status across SDDC Manager, vCenter, and NSX.
2. If any subsystem is DEGRADED or has active alarms, call `vcf_query_telemetry` for `cluster_id={cluster_id}` to inspect CPU and memory utilization.

## Postconditions
- Produce a structured summary of healthy vs degraded components and active alarms.

## Safety Guardrails
- **NEVER**: Do not attempt automated remediation or VM power/resize operations during health triage.
