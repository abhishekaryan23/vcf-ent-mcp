---
name: vcf-lifecycle-domain-upgrade
description: >-
  [LIFECYCLE_ADMIN | HIGH_IMPACT] Plan and execute a deterministic SDDC Manager workload domain upgrade with two-person approval and durable task tracking.
role: LIFECYCLE_ADMIN
risk_class: HIGH_IMPACT
allowed_tools: [vcf_list_domains, vcf_list_upgrade_bundles, vcf_upgrade_domain, vcf_get_plan]
required_capabilities: [lifecycle.domain.read, lifecycle.bundle.read, lifecycle.domain.upgrade]
---

# Coordinated VCF Workload Domain Lifecycle Upgrade (`vcf-lifecycle-domain-upgrade`)

## Single-Responsibility Objective
Plan and execute a deterministic SDDC Manager workload domain upgrade with two-person approval and durable task tracking.

- **Primary VCF Role**: `LIFECYCLE_ADMIN`
- **Risk Class**: `HIGH_IMPACT`
- **Strict Tool Whitelist**: `vcf_list_domains`, `vcf_list_upgrade_bundles`, `vcf_upgrade_domain`, `vcf_get_plan`

## Input Arguments
- `domain_id` (required): Target workload domain ID.
- `target_version` (required): Target VCF version (e.g. 9.1.1).
- `bundle_id` (optional): Applicable SDDC Manager upgrade bundle ID.

## Preconditions
- Verify applicable `bundle_id` via `vcf_list_upgrade_bundles` and ensure management domain is upgraded before VI workload domains.

## Deterministic SOP Workflow
1. Step 1 (Verify Bundles): Call `vcf_list_upgrade_bundles` for `domain_id={domain_id}` and `target_version={target_version}`.
2. Step 2 (Dry-Run Impact Plan): Call `vcf_upgrade_domain` with `domain_id={domain_id}`, `target_version={target_version}`, `dry_run=True` to generate `plan_id` and inspect compensation boundaries.
3. Step 3 (Dual Approval Gate): Obtain required N-person approvals for `HIGH_IMPACT` `plan_id` and retrieve `approval_id` and `nonce` via `enterprise/plans/get`.
4. Step 4 (Live Execute & Monitor): Call `vcf_upgrade_domain` with `dry_run=False`, `plan_id`, `approval_id`, and `nonce`, then track progress via `tasks/get`.

Approval hand-off: the dry run's `how_to_approve` says how the person approves. In personal mode the person who asked approves (chat prompt, local approval link or their own terminal) and you then call the tool again with the SAME arguments plus `plan_id` only; in team mode a separate approver's `approval_id` and `nonce` are needed as well. `vcf_get_plan` shows whether a plan is approved. Never approve a plan on the person's behalf.

## Postconditions
- Durable MCP Task ID is created and tracking native SDDC Manager upgrade task progress.

## Safety Guardrails
- **NEVER**: Never bypass precheck validation or attempt to upgrade a VI domain ahead of the MANAGEMENT domain.
