---
name: vcf-network-topology-audit
description: >-
  [NETWORK_OPERATOR | READ] Audit NSX Tier-0/Tier-1 logical gateways, overlay segments, and subnet CIDRs in read-only mode.
role: NETWORK_OPERATOR
risk_class: READ
allowed_tools: [vcf_list_nsx_gateways, vcf_list_nsx_segments, vcf_get_health]
required_capabilities: [network.topology.read, lifecycle.domain.read]
---

# NSX Tier-0/Tier-1 Gateway & Logical Segment Topology Audit (`vcf-network-topology-audit`)

## Single-Responsibility Objective
Audit NSX Tier-0/Tier-1 logical gateways, overlay segments, and subnet CIDRs in read-only mode.

- **Primary VCF Role**: `NETWORK_OPERATOR`
- **Risk Class**: `READ`
- **Strict Tool Whitelist**: `vcf_list_nsx_gateways`, `vcf_list_nsx_segments`, `vcf_get_health`

## Input Arguments
- `gateway_id` (optional): Optional Tier-1 gateway ID to filter segments.

## Preconditions
- Caller holds NETWORK_OPERATOR or NETWORK_ADMIN role.

## Deterministic SOP Workflow
1. Call `vcf_list_nsx_gateways` to enumerate Tier-0 and Tier-1 logical routers and their HA states.
2. Call `vcf_list_nsx_segments` (optionally filtered by `gateway_id={gateway_id}`) to list existing overlay segments and CIDRs.
3. Call `vcf_get_health` to confirm NSX Manager cluster and transport node health.

## Postconditions
- Return complete NSX gateway-to-segment topology map and allocated CIDRs.

## Safety Guardrails
- **NEVER**: Do not create or modify NSX segments inside this read-only topology audit skill.
