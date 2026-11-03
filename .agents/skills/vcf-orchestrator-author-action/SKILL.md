---
name: vcf-orchestrator-author-action
description: >-
  [AUTOMATION_OPERATOR | CHANGE] Write an Orchestrator action in plain ES5 (the Rhino engine), save it in a com.mcp.* module after approval, and test it.
role: AUTOMATION_OPERATOR
risk_class: CHANGE
allowed_tools: [vcf_find_tool, vcf_orch_about, vcf_orch_list, vcf_orch_get, vcf_orch_validate, vcf_orch_try_script, vcf_orch_save_action, vcf_orch_run_action, vcf_orch_rollback, vcf_orch_create_environment, vcf_orch_tracked_changes, vcf_get_plan]
required_capabilities: [automation.catalog.read, automation.orchestrator.author]
---

# Create or update an Orchestrator action (`vcf-orchestrator-author-action`)

## Single-Responsibility Objective
Write an Orchestrator action in plain ES5 (the Rhino engine), save it in a com.mcp.* module after approval, and test it.

- **Primary VCF Role**: `AUTOMATION_OPERATOR`
- **Risk Class**: `CHANGE`
- **Strict Tool Whitelist**: `vcf_find_tool`, `vcf_orch_about`, `vcf_orch_list`, `vcf_orch_get`, `vcf_orch_validate`, `vcf_orch_try_script`, `vcf_orch_save_action`, `vcf_orch_run_action`, `vcf_orch_rollback`, `vcf_orch_create_environment`, `vcf_orch_tracked_changes`, `vcf_get_plan`

## Input Arguments
- `request` (required): What the action must do.

## Preconditions
- AUTOMATION_OPERATOR role.

## Deterministic SOP Workflow
1. Call `vcf_orch_about` (version, plug-ins, runtimes, guardrails). If you need plug-in objects, call `vcf_orch_get` kind=scripting_api.
2. Write the script in plain ES5 (Orchestrator runs Rhino): var, function(){}, string + concatenation, indexed for loops. NO let/const, arrow functions, template literals, for...of, class, async/await, ?., ??, spread (...), destructuring, default parameters, Intl, regex u flag; ASCII only; no java.* or Packages.*; no passwords in code.
3. Call `vcf_orch_validate` with the script; fix every error until ok is true.
4. Optionally try the logic first with `vcf_orch_try_script` (dry run, approval, run): it runs the snippet in a temporary action and deletes it.
5. Call `vcf_orch_save_action` with dry_run=true (module must start with com.mcp.). Get human approval for the plan (vcf-mcp plans approve <plan_id>); then call the same tool with the SAME arguments plus plan_id, approval_id and nonce (no dry_run).
6. When updating an existing action, pass base_changeset_sha from the dry run; if a conflict is reported, dry-run again.
7. Optionally test it with `vcf_orch_run_action` (dry run, approval, run).

Approval hand-off: the dry run's `how_to_approve` says how the person approves. In personal mode the person who asked approves (chat prompt, local approval link or their own terminal) and you then call the tool again with the SAME arguments plus `plan_id` only; in team mode a separate approver's `approval_id` and `nonce` are needed as well. `vcf_get_plan` shows whether a plan is approved. Never approve a plan on the person's behalf.

## Postconditions
- The action is saved, versioned, and its script passed validation.

## Safety Guardrails
- **NEVER**: Do not save outside com.mcp.* modules.
- **NEVER**: Do not hard-code credentials.
