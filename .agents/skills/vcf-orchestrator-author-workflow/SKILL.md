---
name: vcf-orchestrator-author-workflow
description: >-
  [AUTOMATION_OPERATOR | CHANGE] Build an Orchestrator workflow from a step list (scripts, actions, decisions, sub-workflows, error handling), save it under MCP-Managed/ after approval.
role: AUTOMATION_OPERATOR
risk_class: CHANGE
allowed_tools: [vcf_find_tool, vcf_orch_about, vcf_orch_list, vcf_orch_get, vcf_orch_validate, vcf_orch_save_workflow, vcf_orch_save_action, vcf_orch_run, vcf_orch_list_executions, vcf_orch_rollback, vcf_orch_tracked_changes, vcf_get_plan]
required_capabilities: [automation.catalog.read, automation.orchestrator.author]
---

# Create or update an Orchestrator workflow (`vcf-orchestrator-author-workflow`)

## Single-Responsibility Objective
Build an Orchestrator workflow from a step list (scripts, actions, decisions, sub-workflows, error handling), save it under MCP-Managed/ after approval.

- **Primary VCF Role**: `AUTOMATION_OPERATOR`
- **Risk Class**: `CHANGE`
- **Strict Tool Whitelist**: `vcf_find_tool`, `vcf_orch_about`, `vcf_orch_list`, `vcf_orch_get`, `vcf_orch_validate`, `vcf_orch_save_workflow`, `vcf_orch_save_action`, `vcf_orch_run`, `vcf_orch_list_executions`, `vcf_orch_rollback`, `vcf_orch_tracked_changes`, `vcf_get_plan`

## Input Arguments
- `request` (required): What the workflow must do.

## Preconditions
- AUTOMATION_OPERATOR role.

## Deterministic SOP Workflow
1. Call `vcf_orch_about`; find reusable actions/workflows with `vcf_orch_list`.
2. Write the spec: name, inputs/outputs/variables (each with a type), steps in order (script | action | decision | workflow | end | error_end) and on_error.
3. Every variable a step reads or writes must be declared in inputs, outputs or variables. Scripts are plain ES5 (no let/const, arrows, template literals). Inputs may carry a default; variables a value.
4. Call `vcf_orch_validate` with workflow=<spec>; fix every error (each says what to change).
5. Call `vcf_orch_save_workflow` with dry_run=true and category MCP-Managed/<team>. Get human approval for the plan (vcf-mcp plans approve <plan_id>); then call the same tool with the SAME arguments plus plan_id, approval_id and nonce (no dry_run).
6. When updating, pass base_changeset_sha from the dry run; if a conflict is reported, dry-run again.

Approval hand-off: the dry run's `how_to_approve` says how the person approves. In personal mode the person who asked approves (chat prompt, local approval link or their own terminal) and you then call the tool again with the SAME arguments plus `plan_id` only; in team mode a separate approver's `approval_id` and `nonce` are needed as well. `vcf_get_plan` shows whether a plan is approved. Never approve a plan on the person's behalf.

## Postconditions
- The workflow is saved, validated by Orchestrator and versioned.

## Safety Guardrails
- **NEVER**: Do not edit workflows outside MCP-Managed/.
- **NEVER**: Do not hand-write Orchestrator schema JSON; use the spec.
