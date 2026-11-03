---
name: vcf-network-segment-provision
description: >-
  [NETWORK_ADMIN | CHANGE] Validate non-overlapping subnet CIDR and provision a new NSX logical segment attached to a Tier-1 gateway.
role: NETWORK_ADMIN
risk_class: CHANGE
allowed_tools: [vcf_list_nsx_gateways, vcf_list_nsx_segments, vcf_create_nsx_segment, vcf_get_plan]
required_capabilities: [network.topology.read, network.segment.create]
---

# NSX Tier-1 Logical Overlay Segment Provisioning (`vcf-network-segment-provision`)

## Single-Responsibility Objective
Validate non-overlapping subnet CIDR and provision a new NSX logical segment attached to a Tier-1 gateway.

- **Primary VCF Role**: `NETWORK_ADMIN`
- **Risk Class**: `CHANGE`
- **Strict Tool Whitelist**: `vcf_list_nsx_gateways`, `vcf_list_nsx_segments`, `vcf_create_nsx_segment`, `vcf_get_plan`

## Input Arguments
- `segment_name` (required): Name of the new NSX segment (e.g. seg-app-tier).
- `gateway_id` (required): Target NSX Tier-1 gateway ID (e.g. t1-gw-prod).
- `cidr` (required): Gateway interface CIDR in slash notation (e.g. 192.168.50.1/24).

## Preconditions
- Verify `gateway_id` exists via `vcf_list_nsx_gateways` and verify `cidr` does not overlap existing segments via `vcf_list_nsx_segments`.

## Deterministic SOP Workflow
1. Step 1 (Pre-Check Gateways & Segments): Call `vcf_list_nsx_gateways` and `vcf_list_nsx_segments` to verify `gateway_id={gateway_id}` exists and `cidr={cidr}` is unused.
2. Step 2 (Dry-Run Plan): Call `vcf_create_nsx_segment` with `segment_name={segment_name}`, `gateway_id={gateway_id}`, `cidr={cidr}`, `dry_run=True` to generate `plan_id`.
3. Step 3 (Approval Gate): Obtain approval (`approval_id` and `nonce`) for `plan_id`.
4. Step 4 (Live Execute & Verify): Call `vcf_create_nsx_segment` with `dry_run=False`, `plan_id`, `approval_id`, and `nonce`.

Approval hand-off: the dry run's `how_to_approve` says how the person approves. In personal mode the person who asked approves (chat prompt, local approval link or their own terminal) and you then call the tool again with the SAME arguments plus `plan_id` only; in team mode a separate approver's `approval_id` and `nonce` are needed as well. `vcf_get_plan` shows whether a plan is approved. Never approve a plan on the person's behalf.

## Postconditions
- Verify `segment_id` is provisioned and postcondition check succeeds.

## Safety Guardrails
- **NEVER**: Never provision an NSX segment without first checking existing segments for CIDR overlap.
