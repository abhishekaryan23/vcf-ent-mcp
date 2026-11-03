---
name: vcf-automation-cloud-template
description: >-
  [AUTOMATION_OPERATOR | CHANGE] Write, validate and save a VCF Automation (Assembler) cloud template as a DRAFT.
role: AUTOMATION_OPERATOR
risk_class: CHANGE
allowed_tools: [vcf_find_tool, vcf_automation_list, vcf_automation_get, vcf_automation_validate_template, vcf_automation_create_template, vcf_get_plan]
required_capabilities: [automation.catalog.read, automation.template.write]
---

# Create an Assembler cloud template (`vcf-automation-cloud-template`)

## Single-Responsibility Objective
Write, validate and save a VCF Automation (Assembler) cloud template as a DRAFT.

- **Primary VCF Role**: `AUTOMATION_OPERATOR`
- **Risk Class**: `CHANGE`
- **Strict Tool Whitelist**: `vcf_find_tool`, `vcf_automation_list`, `vcf_automation_get`, `vcf_automation_validate_template`, `vcf_automation_create_template`, `vcf_get_plan`

## Input Arguments
- `request` (required): What the template must build.

## Preconditions
- AUTOMATION_OPERATOR role.

## Deterministic SOP Workflow
1. Call `vcf_automation_list` with kind=projects, then images, flavors and networks; use ONLY names that appear there.
2. Write YAML: formatVersion: 1, inputs, resources (Cloud.vSphere.Machine with image, flavor, count, networks; Cloud.Network with constraints - tag: <network tag>).
3. Call `vcf_automation_validate_template`; fix every error and validate again until valid.
4. Call `vcf_automation_create_template` with dry_run=true. Get human approval for the plan (vcf-mcp plans approve <plan_id>); then call the same tool with the SAME arguments plus plan_id, approval_id and nonce (no dry_run).

Approval hand-off: the dry run's `how_to_approve` says how the person approves. In personal mode the person who asked approves (chat prompt, local approval link or their own terminal) and you then call the tool again with the SAME arguments plus `plan_id` only; in team mode a separate approver's `approval_id` and `nonce` are needed as well. `vcf_get_plan` shows whether a plan is approved. Never approve a plan on the person's behalf.

## Postconditions
- The template exists as DRAFT and validates.

## Safety Guardrails
- **NEVER**: Do not invent image, flavor or network names.
- **NEVER**: Do not deploy anything.
