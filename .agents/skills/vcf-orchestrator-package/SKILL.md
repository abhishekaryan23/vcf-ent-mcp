---
name: vcf-orchestrator-package
description: >-
  [AUTOMATION_OPERATOR | CHANGE] Export an Orchestrator package to a .package file, or package what the MCP saved, without ever exporting secrets.
role: AUTOMATION_OPERATOR
risk_class: CHANGE
allowed_tools: [vcf_find_tool, vcf_orch_about, vcf_orch_list, vcf_orch_get, vcf_orch_tracked_changes, vcf_orch_export_package, vcf_orch_build_package, vcf_get_plan]
required_capabilities: [automation.catalog.read, automation.orchestrator.author]
---

# Export or build an Orchestrator package (`vcf-orchestrator-package`)

## Single-Responsibility Objective
Export an Orchestrator package to a .package file, or package what the MCP saved, without ever exporting secrets.

- **Primary VCF Role**: `AUTOMATION_OPERATOR`
- **Risk Class**: `CHANGE`
- **Strict Tool Whitelist**: `vcf_find_tool`, `vcf_orch_about`, `vcf_orch_list`, `vcf_orch_get`, `vcf_orch_tracked_changes`, `vcf_orch_export_package`, `vcf_orch_build_package`, `vcf_get_plan`

## Input Arguments
- `package` (required): Package name (com.mcp.<name>) or what to package.

## Preconditions
- AUTOMATION_OPERATOR role.

## Deterministic SOP Workflow
1. To back up an existing package call `vcf_orch_export_package` with package_name (find it with `vcf_orch_list` kind=packages). Report the file path, size and SHA-256 it returns.
2. To package your own work first call `vcf_orch_tracked_changes` to see what the MCP saved.
3. Call `vcf_orch_build_package` with dry_run=true and a name like com.mcp.<name>. Get human approval for the plan (vcf-mcp plans approve <plan_id>); then call the same tool with the SAME arguments plus plan_id, approval_id and nonce (no dry_run).

Approval hand-off: the dry run's `how_to_approve` says how the person approves. In personal mode the person who asked approves (chat prompt, local approval link or their own terminal) and you then call the tool again with the SAME arguments plus `plan_id` only; in team mode a separate approver's `approval_id` and `nonce` are needed as well. `vcf_get_plan` shows whether a plan is approved. Never approve a plan on the person's behalf.

## Postconditions
- The .package file exists in the MCP export folder and its SHA-256 was reported.

## Safety Guardrails
- **NEVER**: Never try to include SecureString values in an export.
- **NEVER**: Never package content outside MCP-Managed/ and com.mcp.* modules.
