---
name: vcf-lifecycle-upgrade-readiness
description: >-
  [LIFECYCLE_OPERATOR | READ] Inspect workload domain status, subsystem health, and applicable SDDC Manager upgrade bundles prior to maintenance.
role: LIFECYCLE_OPERATOR
risk_class: READ
allowed_tools: [vcf_list_domains, vcf_list_upgrade_bundles, vcf_get_health]
required_capabilities: [lifecycle.domain.read, lifecycle.bundle.read]
---

# SDDC Manager Workload Domain Upgrade Readiness & Bundle Audit (`vcf-lifecycle-upgrade-readiness`)

## Single-Responsibility Objective
Inspect workload domain status, subsystem health, and applicable SDDC Manager upgrade bundles prior to maintenance.

- **Primary VCF Role**: `LIFECYCLE_OPERATOR`
- **Risk Class**: `READ`
- **Strict Tool Whitelist**: `vcf_list_domains`, `vcf_list_upgrade_bundles`, `vcf_get_health`

## Input Arguments
- `domain_id` (required): Target workload domain ID (e.g. mgmt-domain or wld-app-a).
- `target_version` (optional): Target VCF release version (default: 9.1.1).

## Preconditions
- Caller holds LIFECYCLE_OPERATOR or LIFECYCLE_ADMIN role.

## Deterministic SOP Workflow
1. Call `vcf_list_domains` to inspect current status and upgrade state of `domain_id={domain_id}`.
2. Call `vcf_list_upgrade_bundles` with `domain_id={domain_id}` and `target_version={target_version}` to identify available `bundle_id` packages.
3. Call `vcf_get_health` to verify zero critical alarms exist before scheduling an upgrade.

## Postconditions
- Report applicable bundle IDs and domain readiness status without initiating an upgrade.

## Safety Guardrails
- **NEVER**: Do not invoke `vcf_upgrade_domain` with `dry_run=False` in the readiness skill.
