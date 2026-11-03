---
name: vcf-orchestrator-plugin-install
description: >-
  [VCF_PLATFORM_ADMIN | HIGH_IMPACT] Install a Broadcom or vendor Orchestrator plug-in (.vmoapp) verified by SHA-256.
role: VCF_PLATFORM_ADMIN
risk_class: HIGH_IMPACT
allowed_tools: [vcf_find_tool, vcf_orch_about, vcf_orch_list, vcf_orch_install_plugin, vcf_get_plan]
required_capabilities: [automation.orchestrator.integration]
---

# Install an Orchestrator plug-in (`vcf-orchestrator-plugin-install`)

## Single-Responsibility Objective
Install a Broadcom or vendor Orchestrator plug-in (.vmoapp) verified by SHA-256.

- **Primary VCF Role**: `VCF_PLATFORM_ADMIN`
- **Risk Class**: `HIGH_IMPACT`
- **Strict Tool Whitelist**: `vcf_find_tool`, `vcf_orch_about`, `vcf_orch_list`, `vcf_orch_install_plugin`, `vcf_get_plan`

## Input Arguments
- `file_path` (required): Plug-in file in the MCP plug-in folder.
- `sha256` (required): Published SHA-256 of the file.

## Preconditions
- The admin downloaded the plug-in from the vendor and placed it in the MCP plug-in folder.

## Deterministic SOP Workflow
1. Call `vcf_orch_install_plugin` with dry_run=true. Get human approval for the plan (vcf-mcp plans approve <plan_id>); then call the same tool with the SAME arguments plus plan_id, approval_id and nonce (no dry_run).
2. Confirm with `vcf_orch_about` that the plug-in is listed.

Approval hand-off: the dry run's `how_to_approve` says how the person approves. In personal mode the person who asked approves (chat prompt, local approval link or their own terminal) and you then call the tool again with the SAME arguments plus `plan_id` only; in team mode a separate approver's `approval_id` and `nonce` are needed as well. `vcf_get_plan` shows whether a plan is approved. Never approve a plan on the person's behalf.

## Postconditions
- The plug-in is listed in vcf_orch_about.

## Safety Guardrails
- **NEVER**: Never install a file whose SHA-256 does not match.
