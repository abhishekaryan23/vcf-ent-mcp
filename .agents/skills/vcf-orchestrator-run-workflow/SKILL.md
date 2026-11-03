---
name: vcf-orchestrator-run-workflow
description: >-
  [AUTOMATION_OPERATOR | CHANGE] Find an existing Orchestrator workflow, run it with the right inputs after approval, and report the real result.
role: AUTOMATION_OPERATOR
risk_class: CHANGE
allowed_tools: [vcf_find_tool, vcf_orch_about, vcf_orch_list, vcf_orch_get, vcf_orch_list_executions, vcf_orch_run, vcf_orch_answer, vcf_get_plan]
required_capabilities: [automation.catalog.read, automation.workflow.run]
---

# Run an existing Orchestrator workflow (`vcf-orchestrator-run-workflow`)

## Single-Responsibility Objective
Find an existing Orchestrator workflow, run it with the right inputs after approval, and report the real result.

- **Primary VCF Role**: `AUTOMATION_OPERATOR`
- **Risk Class**: `CHANGE`
- **Strict Tool Whitelist**: `vcf_find_tool`, `vcf_orch_about`, `vcf_orch_list`, `vcf_orch_get`, `vcf_orch_list_executions`, `vcf_orch_run`, `vcf_orch_answer`, `vcf_get_plan`

## Input Arguments
- `request` (required): What should be done.

## Preconditions
- AUTOMATION_OPERATOR role.

## Deterministic SOP Workflow
1. Call `vcf_orch_list` kind=workflows with a name filter to find the workflow id.
2. Call `vcf_orch_get` kind=workflow to read its inputs (names and types).
3. Call `vcf_orch_run` with dry_run=true and inputs={name: value}; SecureString inputs go in secret_inputs as credential references.
4. Get human approval for the plan (vcf-mcp plans approve <plan_id>); then call the same tool with the SAME arguments plus plan_id, approval_id and nonce (no dry_run).
5. If the result state is 'waiting', use `vcf_orch_answer`; if 'failed', report the error message exactly (the result already carries the run logs). Never claim success on a failed run.
6. To see earlier runs of a workflow (for example the failed ones) call `vcf_orch_list_executions`, then `vcf_orch_get` kind=execution for one of them.

Approval hand-off: the dry run's `how_to_approve` says how the person approves. In personal mode the person who asked approves (chat prompt, local approval link or their own terminal) and you then call the tool again with the SAME arguments plus `plan_id` only; in team mode a separate approver's `approval_id` and `nonce` are needed as well. `vcf_get_plan` shows whether a plan is approved. Never approve a plan on the person's behalf.

## Postconditions
- The reported state and outputs come from the execution, not from assumptions.

## Safety Guardrails
- **NEVER**: Never pass a password or token as a plain input.
- **NEVER**: Never work around a failed run by changing the target or forest without asking.
