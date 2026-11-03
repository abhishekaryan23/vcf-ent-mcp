---
name: vcf-oncall-troubleshoot
description: >-
  [VCF_VIEWER | READ] Find the root cause of an outage or failure (VCF appliance, NSX routing/firewall/VPC, VM, AD, clustered DB) without changing anything.
role: VCF_VIEWER
risk_class: READ
allowed_tools: [vcf_find_tool, vcf_diagnose, vcf_trace_application, vcf_list_networks, vcf_check_component, vcf_list_failed_tasks, vcf_list_alerts]
required_capabilities: [lifecycle.domain.read]
---

# Find out why a service or application is down (`vcf-oncall-troubleshoot`)

## Single-Responsibility Objective
Find the root cause of an outage or failure (VCF appliance, NSX routing/firewall/VPC, VM, AD, clustered DB) without changing anything.

- **Primary VCF Role**: `VCF_VIEWER`
- **Risk Class**: `READ`
- **Strict Tool Whitelist**: `vcf_find_tool`, `vcf_diagnose`, `vcf_trace_application`, `vcf_list_networks`, `vcf_check_component`, `vcf_list_failed_tasks`, `vcf_list_alerts`

## Input Arguments
- `symptom` (required): What users report, in their words.
- `application` (optional): The affected application, if one is named (e.g. CRM).

## Preconditions
- Read-only access (VCF_VIEWER or similar).

## Deterministic SOP Workflow
1. If ONE named application/service is affected, call `vcf_trace_application` with application={application}; otherwise call `vcf_diagnose` with symptom={symptom}.
2. Read the FIRST finding: title, cause, evidence ids, impact, next_steps. Findings are already ranked.
3. If the first finding does not match the symptom, call the other tool (`vcf_diagnose` or `vcf_trace_application`) once to cross-check.
4. Report: root cause, evidence (names/values), who is affected, next steps, confidence. Mention unrelated findings as unrelated.

## Postconditions
- Nothing was changed; the answer cites evidence ids.

## Safety Guardrails
- **NEVER**: Do not call any tool that changes VCF.
- **NEVER**: Do not guess a cause that no finding or evidence supports.
