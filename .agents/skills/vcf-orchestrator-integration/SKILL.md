---
name: vcf-orchestrator-integration
description: >-
  [SECURITY_ADMIN | SECURITY_SENSITIVE] Add or repair an Orchestrator plug-in endpoint with Broadcom's configuration workflow; credentials only by reference.
role: SECURITY_ADMIN
risk_class: SECURITY_SENSITIVE
allowed_tools: [vcf_find_tool, vcf_orch_about, vcf_orch_list, vcf_orch_add_integration, vcf_orch_set_configuration, vcf_get_plan]
required_capabilities: [automation.orchestrator.integration]
---

# Connect Orchestrator to an endpoint (vCenter, REST, AD, PowerShell, SSH) (`vcf-orchestrator-integration`)

## Single-Responsibility Objective
Add or repair an Orchestrator plug-in endpoint with Broadcom's configuration workflow; credentials only by reference.

- **Primary VCF Role**: `SECURITY_ADMIN`
- **Risk Class**: `SECURITY_SENSITIVE`
- **Strict Tool Whitelist**: `vcf_find_tool`, `vcf_orch_about`, `vcf_orch_list`, `vcf_orch_add_integration`, `vcf_orch_set_configuration`, `vcf_get_plan`

## Input Arguments
- `endpoint` (required): What to connect (kind, host/url).

## Preconditions
- SECURITY_ADMIN role.
- The password is already stored as a credential reference (vcf_setup or 'vcf-mcp credentials add').

## Deterministic SOP Workflow
1. Call `vcf_orch_about` (plug-ins installed, unusable vCenter connections).
2. Call `vcf_orch_add_integration` with dry_run=true, kind, settings (no passwords) and credential_ref. Fix any problem it lists.
3. This change needs TWO human approvers. Get human approval for the plan (vcf-mcp plans approve <plan_id>); then call the same tool with the SAME arguments plus plan_id, approval_id and nonce (no dry_run).
4. Report the run state and the plug-in inventory after the change.

Approval hand-off: the dry run's `how_to_approve` says how the person approves. In personal mode the person who asked approves (chat prompt, local approval link or their own terminal) and you then call the tool again with the SAME arguments plus `plan_id` only; in team mode a separate approver's `approval_id` and `nonce` are needed as well. `vcf_get_plan` shows whether a plan is approved. Never approve a plan on the person's behalf.

## Postconditions
- The endpoint appears as usable in the plug-in inventory.

## Safety Guardrails
- **NEVER**: Never ask the user to type a password into the chat.
- **NEVER**: Never put a password in settings.
