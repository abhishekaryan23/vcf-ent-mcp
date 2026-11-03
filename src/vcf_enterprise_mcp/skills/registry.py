# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Single-Responsibility Role Skill Registry for Enterprise VCF 9.x Operations.
Each RoleSkillCard encapsulates:
- Exactly 1 primary enterprise role (CapabilityRole)
- Exactly 1 atomic operational task (Single Responsibility Principle)
- A strict tool whitelist (allowed_tools) preventing tool-scope creep
- A deterministic 4-stage Standard Operating Procedure (Discover -> Dry-Run Plan -> Approval -> Execute & Verify)
"""

from __future__ import annotations
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Any, List, Optional

from vcf_enterprise_mcp.policy.models import CapabilityRole, NormalizedCapability, RiskClass


APPROVAL_NOTE = ("Approval hand-off: the dry run's `how_to_approve` says how the person approves. In personal mode the person who asked "
                 "approves (chat prompt, local approval link or their own terminal) and you then call the tool again with the SAME arguments "
                 "plus `plan_id` only; in team mode a separate approver's `approval_id` and `nonce` are needed as well. "
                 "`vcf_get_plan` shows whether a plan is approved. Never approve a plan on the person's behalf.")


@dataclass
class RoleSkillCard:
    """Atomic, role-scoped operational skill definition."""
    name: str
    title: str
    role: CapabilityRole
    additional_allowed_roles: List[CapabilityRole]
    single_task_objective: str
    risk_class: RiskClass
    allowed_tools: List[str]
    required_capabilities: List[NormalizedCapability]
    arguments: List[Dict[str, Any]] = field(default_factory=list)
    preconditions: List[str] = field(default_factory=list)
    sop_steps: List[str] = field(default_factory=list)
    postconditions: List[str] = field(default_factory=list)
    forbidden_actions: List[str] = field(default_factory=list)

    @property
    def all_authorized_roles(self) -> List[CapabilityRole]:
        roles = [self.role] + list(self.additional_allowed_roles)
        if CapabilityRole.VCF_PLATFORM_ADMIN not in roles:
            roles.append(CapabilityRole.VCF_PLATFORM_ADMIN)
        return roles

    def to_mcp_prompt_descriptor(self) -> Dict[str, Any]:
        """Formats the skill as a native MCP 2026-07-28 Prompt descriptor."""
        return {
            "name": self.name,
            "title": self.title,
            "description": f"[{self.role.value} | {self.risk_class.value}] {self.single_task_objective}",
            "arguments": self.arguments,
            "_enterprise_meta": {
                "primary_role": self.role.value,
                "allowed_roles": [r.value for r in self.all_authorized_roles],
                "risk_class": self.risk_class.value,
                "allowed_tools": list(self.allowed_tools),
                "required_capabilities": [c.value for c in self.required_capabilities],
            },
        }

    def render_mcp_prompt_messages(self, arguments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Renders the parameterized skill SOP runbook as MCP prompt messages with tool whitelist."""
        args = arguments or {}
        arg_summary = ", ".join(f"{k}={v}" for k, v in args.items()) if args else "default scope"
        steps_text = "\n".join(f"{idx + 1}. {step}" for idx, step in enumerate(self.sop_steps))
        if "vcf_get_plan" in self.allowed_tools:
            steps_text += "\n\n" + APPROVAL_NOTE
        pre_text = "\n".join(f"- {p}" for p in self.preconditions)
        post_text = "\n".join(f"- {p}" for p in self.postconditions)
        forbid_text = "\n".join(f"- NEVER: {f}" for f in self.forbidden_actions)

        for k, v in args.items():
            steps_text = steps_text.replace(f"{{{k}}}", str(v))
            pre_text = pre_text.replace(f"{{{k}}}", str(v))
            post_text = post_text.replace(f"{{{k}}}", str(v))

        system_instruction = (
            f"# Active Single-Task Role Skill: {self.title} (`{self.name}`)\n"
            f"- **Assigned Enterprise Role**: `{self.role.value}`\n"
            f"- **Risk Classification**: `{self.risk_class.value}`\n"
            f"- **Single-Task Objective**: {self.single_task_objective}\n"
            f"- **Strict Tool Whitelist**: {', '.join(f'`{t}`' for t in self.allowed_tools)}\n"
            f"- **Target Parameters**: {arg_summary}\n\n"
            f"## Preconditions\n{pre_text}\n\n"
            f"## Mandatory Standard Operating Procedure (SOP)\n{steps_text}\n\n"
            f"## Postcondition Verification\n{post_text}\n\n"
            f"## Strict Guardrails & Prohibitions\n{forbid_text}\n"
        )
        return {
            "description": f"[{self.role.value}] {self.single_task_objective}",
            "allowedTools": list(self.allowed_tools),
            "skillMetadata": {
                "skill_name": self.name,
                "role": self.role.value,
                "risk_class": self.risk_class.value,
                "allowed_tools": list(self.allowed_tools),
            },
            "messages": [
                {
                    "role": "user",
                    "content": {
                        "type": "text",
                        "text": system_instruction,
                    },
                }
            ],
        }

    def to_skill_markdown(self) -> str:
        """Generates a portable SKILL.md document with YAML frontmatter for IDE and CLI agents."""
        tools_yaml = ", ".join(self.allowed_tools)
        caps_yaml = ", ".join(c.value for c in self.required_capabilities)
        args_lines = []
        for a in self.arguments:
            req_str = "required" if a.get("required") else "optional"
            args_lines.append(f"- `{a['name']}` ({req_str}): {a.get('description', '')}")
        args_md = "\n".join(args_lines) if args_lines else "- None required."
        pre_md = "\n".join(f"- {p}" for p in self.preconditions)
        steps_md = "\n".join(f"{idx + 1}. {s}" for idx, s in enumerate(self.sop_steps))
        if "vcf_get_plan" in self.allowed_tools:
            steps_md += "\n\n" + APPROVAL_NOTE
        post_md = "\n".join(f"- {p}" for p in self.postconditions)
        forbid_md = "\n".join(f"- **NEVER**: {f}" for f in self.forbidden_actions)

        return (
            f"---\n"
            f"name: {self.name}\n"
            f"description: >-\n"
            f"  [{self.role.value} | {self.risk_class.value}] {self.single_task_objective}\n"
            f"role: {self.role.value}\n"
            f"risk_class: {self.risk_class.value}\n"
            f"allowed_tools: [{tools_yaml}]\n"
            f"required_capabilities: [{caps_yaml}]\n"
            f"---\n\n"
            f"# {self.title} (`{self.name}`)\n\n"
            f"## Single-Responsibility Objective\n"
            f"{self.single_task_objective}\n\n"
            f"- **Primary VCF Role**: `{self.role.value}`\n"
            f"- **Risk Class**: `{self.risk_class.value}`\n"
            f"- **Strict Tool Whitelist**: {', '.join(f'`{t}`' for t in self.allowed_tools)}\n\n"
            f"## Input Arguments\n"
            f"{args_md}\n\n"
            f"## Preconditions\n"
            f"{pre_md}\n\n"
            f"## Deterministic SOP Workflow\n"
            f"{steps_md}\n\n"
            f"## Postconditions\n"
            f"{post_md}\n\n"
            f"## Safety Guardrails\n"
            f"{forbid_md}\n"
        )


ALL_ROLE_SKILLS: List[RoleSkillCard] = [
    # 1. VCF_VIEWER — Inventory Summary
    RoleSkillCard(
        name="vcf-viewer-inventory-summary",
        title="VCF Workload Domain, Cluster & VM Inventory Summary",
        role=CapabilityRole.VCF_VIEWER,
        additional_allowed_roles=[CapabilityRole.COMPUTE_OPERATOR, CapabilityRole.VCF_AUDITOR],
        single_task_objective="Enumerate VCF workload domains, compute clusters, and virtual machines in read-only mode.",
        risk_class=RiskClass.READ,
        allowed_tools=["vcf_list_domains", "vcf_list_clusters", "vcf_list_vms"],
        required_capabilities=[
            NormalizedCapability.LIFECYCLE_DOMAIN_READ,
            NormalizedCapability.COMPUTE_CLUSTER_READ,
            NormalizedCapability.COMPUTE_VM_READ,
        ],
        arguments=[
            {"name": "cluster_id", "description": "Optional cluster id from vcf_list_clusters; omit to cover every cluster in every vCenter.", "required": False},
        ],
        preconditions=[
            "Caller holds at least VCF_VIEWER read clearance for the target tenant and environment.",
        ],
        sop_steps=[
            "Call `vcf_list_domains` to list active SDDC Manager management and VI workload domains.",
            "Call `vcf_list_clusters` to inspect compute clusters and host counts.",
            "Call `vcf_list_vms` (add `cluster_id` only if the user named a cluster) to summarize running and powered-off VMs.",
        ],
        postconditions=[
            "Report domain, cluster, and VM counts with zero infrastructure mutations.",
        ],
        forbidden_actions=[
            "Do not invoke any L2_OPERATIONAL or L3_WORKFLOW mutating tools.",
        ],
    ),
    # 2. VCF_VIEWER — Health & Alarm Triage
    RoleSkillCard(
        name="vcf-viewer-health-triage",
        title="VCF Subsystem Health & Alarm Triage",
        role=CapabilityRole.VCF_VIEWER,
        additional_allowed_roles=[CapabilityRole.VCF_AUDITOR, CapabilityRole.COMPUTE_OPERATOR],
        single_task_objective="Inspect SDDC Manager, vCenter, and NSX subsystem health scores and active alarms.",
        risk_class=RiskClass.READ,
        allowed_tools=["vcf_get_health", "vcf_query_telemetry"],
        required_capabilities=[
            NormalizedCapability.LIFECYCLE_DOMAIN_READ,
            NormalizedCapability.TELEMETRY_READ,
        ],
        arguments=[
            {"name": "datacenter_id", "description": "Target datacenter ID (default: dc1).", "required": False},
            {"name": "cluster_id", "description": "Target cluster ID for telemetry check.", "required": False},
        ],
        preconditions=[
            "Caller is authenticated with read visibility into the target datacenter.",
        ],
        sop_steps=[
            "Call `vcf_get_health` for `datacenter_id={datacenter_id}` to retrieve consolidated status across SDDC Manager, vCenter, and NSX.",
            "If any subsystem is DEGRADED or has active alarms, call `vcf_query_telemetry` for `cluster_id={cluster_id}` to inspect CPU and memory utilization.",
        ],
        postconditions=[
            "Produce a structured summary of healthy vs degraded components and active alarms.",
        ],
        forbidden_actions=[
            "Do not attempt automated remediation or VM power/resize operations during health triage.",
        ],
    ),
    # 3. VCF_AUDITOR — Cryptographic Audit Chain Verification
    RoleSkillCard(
        name="vcf-auditor-chain-verification",
        title="SOC2 Tamper-Evident Audit Chain Verification",
        role=CapabilityRole.VCF_AUDITOR,
        additional_allowed_roles=[CapabilityRole.SECURITY_ADMIN],
        single_task_objective="Verify the SHA-256 cryptographic hash chain of the MCP control plane audit log and review recent events.",
        risk_class=RiskClass.READ,
        allowed_tools=["vcf_verify_audit_chain", "vcf_get_health"],
        required_capabilities=[
            NormalizedCapability.AUDIT_LOG_VERIFY,
            NormalizedCapability.LIFECYCLE_DOMAIN_READ,
        ],
        arguments=[
            {"name": "limit", "description": "Maximum number of recent audit records to inspect (default: 25).", "required": False},
        ],
        preconditions=[
            "Caller holds VCF_AUDITOR, SECURITY_ADMIN, or VCF_PLATFORM_ADMIN role.",
        ],
        sop_steps=[
            "Call `vcf_verify_audit_chain` with `limit={limit}` to validate every SHA-256 hash link (`prev_hash` -> `current_hash`) in durable storage.",
            "Inspect returned `recent_events` for any `DENIED` or `FAILED` tool executions and report their trace IDs and actors.",
        ],
        postconditions=[
            "Confirm `integrity_verified == True` or immediately escalate tamper evidence.",
        ],
        forbidden_actions=[
            "Auditors must never approve execution plans, modify tasks, or execute infrastructure mutations.",
        ],
    ),
    # 4. COMPUTE_OPERATOR — Single VM Triage
    RoleSkillCard(
        name="vcf-compute-vm-triage",
        title="Compute VM Hardware, State & Telemetry Triage",
        role=CapabilityRole.COMPUTE_OPERATOR,
        additional_allowed_roles=[CapabilityRole.COMPUTE_ADMIN],
        single_task_objective="Diagnose a single virtual machine's power state, CPU/RAM configuration, and cluster utilization.",
        risk_class=RiskClass.READ,
        allowed_tools=["vcf_get_vm", "vcf_list_vms", "vcf_query_telemetry"],
        required_capabilities=[
            NormalizedCapability.COMPUTE_VM_READ,
            NormalizedCapability.TELEMETRY_READ,
        ],
        arguments=[
            {"name": "vm_id", "description": "Target VM MOID (e.g. vm-101) or VM name (e.g. workload-vm-101).", "required": True},
            {"name": "cluster_id", "description": "Cluster ID hosting the VM.", "required": False},
        ],
        preconditions=[
            "Target VM belongs to a cluster within the operator's allowed resource scope.",
        ],
        sop_steps=[
            "Call `vcf_get_vm` with `vm_id={vm_id}` (supports both vSphere MOID and VM name resolution).",
            "Call `vcf_query_telemetry` on the VM's cluster to check `cpu_usage_pct` and `mem_usage_pct`.",
            "Summarize current VM sizing, power state, and cluster headroom.",
        ],
        postconditions=[
            "Return verified VM hardware configuration and telemetry without mutating VM state.",
        ],
        forbidden_actions=[
            "Do not resize or power-cycle the VM inside this triage skill.",
        ],
    ),
    # 5. COMPUTE_OPERATOR — Single VM Power Cycle
    RoleSkillCard(
        name="vcf-compute-vm-power-cycle",
        title="Safe VM Power State Transition (Start / Stop / Restart / Suspend)",
        role=CapabilityRole.COMPUTE_OPERATOR,
        additional_allowed_roles=[CapabilityRole.COMPUTE_ADMIN],
        single_task_objective="Execute a single controlled power action on a target VM using mandatory dry-run planning and postcondition verification.",
        risk_class=RiskClass.SAFE_WRITE,
        allowed_tools=["vcf_get_vm", "vcf_power_vm"],
        required_capabilities=[
            NormalizedCapability.COMPUTE_VM_READ,
            NormalizedCapability.COMPUTE_VM_POWER,
        ],
        arguments=[
            {"name": "vm_id", "description": "Target VM ID or name.", "required": True},
            {"name": "action", "description": "Power action: start, stop, restart, or suspend.", "required": True},
        ],
        preconditions=[
            "Inspect current VM power state via `vcf_get_vm` before generating a dry-run plan.",
        ],
        sop_steps=[
            "Step 1 (Inspect): Call `vcf_get_vm` for `vm_id={vm_id}` to confirm current power state and cluster ownership.",
            "Step 2 (Dry-Run Plan): Call `vcf_power_vm` with `vm_id={vm_id}`, `action={action}`, `dry_run=True` to generate a deterministic `plan_id`.",
            "Step 3 (Approval Gate): Obtain approval for `plan_id` (via `enterprise/plans/approve`, CLI `vcf-mcp plans approve`, or `enterprise/plans/get` handback).",
            "Step 4 (Live Execute & Verify): Call `vcf_power_vm` with `dry_run=False`, `plan_id`, `approval_id`, and `nonce`.",
        ],
        postconditions=[
            "Verify `new_power_state` matches the expected target state from vCenter.",
        ],
        forbidden_actions=[
            "Never call `vcf_power_vm` with `dry_run=False` without a valid `plan_id`, `approval_id`, and `nonce`.",
        ],
    ),
    # 6. COMPUTE_OPERATOR — Single VM Rightsize
    RoleSkillCard(
        name="vcf-compute-vm-rightsize",
        title="Controlled VM CPU & Memory Rightsizing",
        role=CapabilityRole.COMPUTE_OPERATOR,
        additional_allowed_roles=[CapabilityRole.COMPUTE_ADMIN],
        single_task_objective="Rightsize a single VM's CPU core count or memory (GB) with TOCTOU revision binding and postcondition verification.",
        risk_class=RiskClass.CHANGE,
        allowed_tools=["vcf_get_vm", "vcf_query_telemetry", "vcf_resize_vm"],
        required_capabilities=[
            NormalizedCapability.COMPUTE_VM_READ,
            NormalizedCapability.TELEMETRY_READ,
            NormalizedCapability.COMPUTE_VM_RESIZE,
        ],
        arguments=[
            {"name": "vm_id", "description": "Target VM ID or name.", "required": True},
            {"name": "memory_gb", "description": "Target RAM in GB (optional if resizing CPU).", "required": False},
            {"name": "cpu_cores", "description": "Target vCPU core count (optional if resizing RAM).", "required": False},
        ],
        preconditions=[
            "Verify current VM CPU/RAM allocation and cluster capacity telemetry prior to dry-run.",
        ],
        sop_steps=[
            "Step 1 (Baseline): Call `vcf_get_vm` for `vm_id={vm_id}` to capture baseline `cpu_cores` and `memory_gb`.",
            "Step 2 (Dry-Run Plan): Call `vcf_resize_vm` with `vm_id={vm_id}`, target `memory_gb`/`cpu_cores`, and `dry_run=True` to record resource revision and generate `plan_id`.",
            "Step 3 (Approval Handback): Wait for approval or query `enterprise/plans/get` with `plan_id` to retrieve `approval_id` and single-use `nonce`.",
            "Step 4 (Live Execute & Verify): Call `vcf_resize_vm` with `dry_run=False`, `plan_id`, `approval_id`, and `nonce`.",
        ],
        postconditions=[
            "Authoritative vCenter read-back confirms `allocated_memory_gb` and `allocated_cpu_cores` match requested sizing.",
        ],
        forbidden_actions=[
            "Never attempt VMDK disk expansion or NIC reconfiguration through `vcf_resize_vm`.",
        ],
    ),
    # 7. COMPUTE_OPERATOR — Pre-Change VM Snapshot Guard
    RoleSkillCard(
        name="vcf-compute-vm-snapshot-guard",
        title="Pre-Maintenance VM Point-in-Time Snapshot Creation",
        role=CapabilityRole.COMPUTE_OPERATOR,
        additional_allowed_roles=[CapabilityRole.COMPUTE_ADMIN, CapabilityRole.STORAGE_OPERATOR, CapabilityRole.STORAGE_ADMIN],
        single_task_objective="Create a point-in-time VM protection snapshot prior to patching or configuration changes.",
        risk_class=RiskClass.SAFE_WRITE,
        allowed_tools=["vcf_get_vm", "vcf_list_snapshots", "vcf_create_snapshot"],
        required_capabilities=[
            NormalizedCapability.COMPUTE_VM_READ,
            NormalizedCapability.COMPUTE_VM_SNAPSHOT,
        ],
        arguments=[
            {"name": "vm_id", "description": "Target VM ID or name.", "required": True},
            {"name": "snapshot_name", "description": "Descriptive snapshot label (e.g. pre-patch-chg104).", "required": True},
        ],
        preconditions=[
            "Check existing snapshot count via `vcf_list_snapshots` to avoid deep snapshot chains.",
        ],
        sop_steps=[
            "Step 1 (Inspect): Call `vcf_list_snapshots` for `vm_id={vm_id}` to verify existing snapshot chain depth.",
            "Step 2 (Dry-Run Plan): Call `vcf_create_snapshot` with `vm_id={vm_id}`, `snapshot_name={snapshot_name}`, `dry_run=True`.",
            "Step 3 (Approval Gate): Obtain execution authorization (`approval_id` and `nonce`) for `plan_id`.",
            "Step 4 (Live Execute): When lab/VI-JSON snapshots are enabled, execute `vcf_create_snapshot` with `dry_run=False`, `plan_id`, `approval_id`, and `nonce`.",
        ],
        postconditions=[
            "Verify `snapshot_id` is returned and listed in `vcf_list_snapshots`.",
        ],
        forbidden_actions=[
            "Never use VM snapshots as a substitute for long-term backup archives.",
        ],
    ),
    # 8. COMPUTE_ADMIN — Physical ESXi Host & Cluster Audit
    RoleSkillCard(
        name="vcf-compute-host-cluster-audit",
        title="Physical ESXi Hypervisor Host & Cluster Inventory Audit",
        role=CapabilityRole.COMPUTE_ADMIN,
        additional_allowed_roles=[CapabilityRole.VCF_VIEWER],
        single_task_objective="Audit commissioned physical ESXi hypervisor hosts, connection states, and cluster distribution.",
        risk_class=RiskClass.READ,
        allowed_tools=["vcf_list_clusters", "vcf_list_hosts", "vcf_query_telemetry"],
        required_capabilities=[
            NormalizedCapability.COMPUTE_CLUSTER_READ,
            NormalizedCapability.COMPUTE_HOST_READ,
            NormalizedCapability.TELEMETRY_READ,
        ],
        arguments=[
            {"name": "cluster_id", "description": "Optional compute cluster ID filter.", "required": False},
            {"name": "datacenter_id", "description": "Datacenter ID (default: dc1).", "required": False},
        ],
        preconditions=[
            "Caller holds COMPUTE_ADMIN or VCF_VIEWER role.",
        ],
        sop_steps=[
            "Call `vcf_list_clusters` to enumerate compute clusters and host counts.",
            "Call `vcf_list_hosts` with `cluster_id={cluster_id}` to inspect individual ESXi host statuses and versions.",
            "Call `vcf_query_telemetry` to check cluster-level CPU/memory utilization balance.",
        ],
        postconditions=[
            "Identify any disconnected or maintenance-mode ESXi hosts.",
        ],
        forbidden_actions=[
            "Do not execute host decommissioning or domain upgrades inside this audit skill.",
        ],
    ),
    # 9. STORAGE_OPERATOR — Datastore Capacity & vSAN Health Audit
    RoleSkillCard(
        name="vcf-storage-datastore-capacity-audit",
        title="vSAN ESA/OSA & Datastore Capacity Audit",
        role=CapabilityRole.STORAGE_OPERATOR,
        additional_allowed_roles=[CapabilityRole.STORAGE_ADMIN, CapabilityRole.COMPUTE_OPERATOR],
        single_task_objective="Inspect vSAN, VMFS, and NFS datastores for free capacity (GB), utilization ratios, and health status.",
        risk_class=RiskClass.READ,
        allowed_tools=["vcf_list_datastores", "vcf_query_telemetry"],
        required_capabilities=[
            NormalizedCapability.STORAGE_DATASTORE_READ,
            NormalizedCapability.TELEMETRY_READ,
        ],
        arguments=[
            {"name": "cluster_id", "description": "Target cluster ID (e.g. cluster-prod-a).", "required": False},
            {"name": "datacenter_id", "description": "Datacenter ID (default: dc1).", "required": False},
        ],
        preconditions=[
            "Caller holds STORAGE_OPERATOR, STORAGE_ADMIN, or VCF_VIEWER role.",
        ],
        sop_steps=[
            "Call `vcf_list_datastores` for `cluster_id={cluster_id}` to retrieve total and free capacity (GB) across all datastores.",
            "Flag any datastore with less than 20% free capacity as a vSAN slack-space warning.",
        ],
        postconditions=[
            "Return structured datastore capacity table with free percentage calculations.",
        ],
        forbidden_actions=[
            "Never delete datastores or modify VM storage policies during capacity auditing.",
        ],
    ),
    # 10. STORAGE_ADMIN — Snapshot Hygiene & Cleanup
    RoleSkillCard(
        name="vcf-storage-snapshot-hygiene",
        title="VM Snapshot Hygiene & Delta-Disk Consolidation",
        role=CapabilityRole.STORAGE_ADMIN,
        additional_allowed_roles=[CapabilityRole.STORAGE_OPERATOR, CapabilityRole.COMPUTE_ADMIN],
        single_task_objective="Inspect a VM's snapshot chain and safely delete a specific stale snapshot with disk consolidation.",
        risk_class=RiskClass.SAFE_WRITE,
        allowed_tools=["vcf_list_snapshots", "vcf_delete_snapshot"],
        required_capabilities=[
            NormalizedCapability.COMPUTE_VM_READ,
            NormalizedCapability.COMPUTE_VM_SNAPSHOT,
        ],
        arguments=[
            {"name": "vm_id", "description": "Target VM ID.", "required": True},
            {"name": "snapshot_id", "description": "Target snapshot ID to remove.", "required": True},
        ],
        preconditions=[
            "Confirm `snapshot_id` exists on `vm_id` via `vcf_list_snapshots`.",
        ],
        sop_steps=[
            "Step 1 (List): Call `vcf_list_snapshots` with `vm_id={vm_id}` to confirm the target `snapshot_id={snapshot_id}`.",
            "Step 2 (Dry-Run Plan): Call `vcf_delete_snapshot` with `vm_id={vm_id}`, `snapshot_id={snapshot_id}`, `dry_run=True` to generate `plan_id`.",
            "Step 3 (Approval Gate): Obtain approval (`approval_id` and `nonce`) for `plan_id`.",
            "Step 4 (Live Execute): Call `vcf_delete_snapshot` with `dry_run=False`, `plan_id`, `approval_id`, and `nonce`.",
        ],
        postconditions=[
            "Verify snapshot deletion succeeded and delta disks consolidated.",
        ],
        forbidden_actions=[
            "Never delete snapshots without first listing and verifying the exact `snapshot_id`.",
        ],
    ),
    # 11. NETWORK_OPERATOR — NSX Topology & Gateway Audit
    RoleSkillCard(
        name="vcf-network-topology-audit",
        title="NSX Tier-0/Tier-1 Gateway & Logical Segment Topology Audit",
        role=CapabilityRole.NETWORK_OPERATOR,
        additional_allowed_roles=[CapabilityRole.NETWORK_ADMIN],
        single_task_objective="Audit NSX Tier-0/Tier-1 logical gateways, overlay segments, and subnet CIDRs in read-only mode.",
        risk_class=RiskClass.READ,
        allowed_tools=["vcf_list_nsx_gateways", "vcf_list_nsx_segments", "vcf_get_health"],
        required_capabilities=[
            NormalizedCapability.NETWORK_TOPOLOGY_READ,
            NormalizedCapability.LIFECYCLE_DOMAIN_READ,
        ],
        arguments=[
            {"name": "gateway_id", "description": "Optional Tier-1 gateway ID to filter segments.", "required": False},
        ],
        preconditions=[
            "Caller holds NETWORK_OPERATOR or NETWORK_ADMIN role.",
        ],
        sop_steps=[
            "Call `vcf_list_nsx_gateways` to enumerate Tier-0 and Tier-1 logical routers and their HA states.",
            "Call `vcf_list_nsx_segments` (optionally filtered by `gateway_id={gateway_id}`) to list existing overlay segments and CIDRs.",
            "Call `vcf_get_health` to confirm NSX Manager cluster and transport node health.",
        ],
        postconditions=[
            "Return complete NSX gateway-to-segment topology map and allocated CIDRs.",
        ],
        forbidden_actions=[
            "Do not create or modify NSX segments inside this read-only topology audit skill.",
        ],
    ),
    # 12. NETWORK_ADMIN — NSX Overlay Segment Provisioning
    RoleSkillCard(
        name="vcf-network-segment-provision",
        title="NSX Tier-1 Logical Overlay Segment Provisioning",
        role=CapabilityRole.NETWORK_ADMIN,
        additional_allowed_roles=[],
        single_task_objective="Validate non-overlapping subnet CIDR and provision a new NSX logical segment attached to a Tier-1 gateway.",
        risk_class=RiskClass.CHANGE,
        allowed_tools=["vcf_list_nsx_gateways", "vcf_list_nsx_segments", "vcf_create_nsx_segment"],
        required_capabilities=[
            NormalizedCapability.NETWORK_TOPOLOGY_READ,
            NormalizedCapability.NETWORK_SEGMENT_CREATE,
        ],
        arguments=[
            {"name": "segment_name", "description": "Name of the new NSX segment (e.g. seg-app-tier).", "required": True},
            {"name": "gateway_id", "description": "Target NSX Tier-1 gateway ID (e.g. t1-gw-prod).", "required": True},
            {"name": "cidr", "description": "Gateway interface CIDR in slash notation (e.g. 192.168.50.1/24).", "required": True},
        ],
        preconditions=[
            "Verify `gateway_id` exists via `vcf_list_nsx_gateways` and verify `cidr` does not overlap existing segments via `vcf_list_nsx_segments`.",
        ],
        sop_steps=[
            "Step 1 (Pre-Check Gateways & Segments): Call `vcf_list_nsx_gateways` and `vcf_list_nsx_segments` to verify `gateway_id={gateway_id}` exists and `cidr={cidr}` is unused.",
            "Step 2 (Dry-Run Plan): Call `vcf_create_nsx_segment` with `segment_name={segment_name}`, `gateway_id={gateway_id}`, `cidr={cidr}`, `dry_run=True` to generate `plan_id`.",
            "Step 3 (Approval Gate): Obtain approval (`approval_id` and `nonce`) for `plan_id`.",
            "Step 4 (Live Execute & Verify): Call `vcf_create_nsx_segment` with `dry_run=False`, `plan_id`, `approval_id`, and `nonce`.",
        ],
        postconditions=[
            "Verify `segment_id` is provisioned and postcondition check succeeds.",
        ],
        forbidden_actions=[
            "Never provision an NSX segment without first checking existing segments for CIDR overlap.",
        ],
    ),
    # 13. LIFECYCLE_OPERATOR — Domain Upgrade Readiness & Bundle Check
    RoleSkillCard(
        name="vcf-lifecycle-upgrade-readiness",
        title="SDDC Manager Workload Domain Upgrade Readiness & Bundle Audit",
        role=CapabilityRole.LIFECYCLE_OPERATOR,
        additional_allowed_roles=[CapabilityRole.LIFECYCLE_ADMIN],
        single_task_objective="Inspect workload domain status, subsystem health, and applicable SDDC Manager upgrade bundles prior to maintenance.",
        risk_class=RiskClass.READ,
        allowed_tools=["vcf_list_domains", "vcf_list_upgrade_bundles", "vcf_get_health"],
        required_capabilities=[
            NormalizedCapability.LIFECYCLE_DOMAIN_READ,
            NormalizedCapability.LIFECYCLE_BUNDLE_READ,
        ],
        arguments=[
            {"name": "domain_id", "description": "Target workload domain ID (e.g. mgmt-domain or wld-app-a).", "required": True},
            {"name": "target_version", "description": "Target VCF release version (default: 9.1.1).", "required": False},
        ],
        preconditions=[
            "Caller holds LIFECYCLE_OPERATOR or LIFECYCLE_ADMIN role.",
        ],
        sop_steps=[
            "Call `vcf_list_domains` to inspect current status and upgrade state of `domain_id={domain_id}`.",
            "Call `vcf_list_upgrade_bundles` with `domain_id={domain_id}` and `target_version={target_version}` to identify available `bundle_id` packages.",
            "Call `vcf_get_health` to verify zero critical alarms exist before scheduling an upgrade.",
        ],
        postconditions=[
            "Report applicable bundle IDs and domain readiness status without initiating an upgrade.",
        ],
        forbidden_actions=[
            "Do not invoke `vcf_upgrade_domain` with `dry_run=False` in the readiness skill.",
        ],
    ),
    # 14. LIFECYCLE_ADMIN — Workload Domain Lifecycle Upgrade
    RoleSkillCard(
        name="vcf-lifecycle-domain-upgrade",
        title="Coordinated VCF Workload Domain Lifecycle Upgrade",
        role=CapabilityRole.LIFECYCLE_ADMIN,
        additional_allowed_roles=[],
        single_task_objective="Plan and execute a deterministic SDDC Manager workload domain upgrade with two-person approval and durable task tracking.",
        risk_class=RiskClass.HIGH_IMPACT,
        allowed_tools=["vcf_list_domains", "vcf_list_upgrade_bundles", "vcf_upgrade_domain"],
        required_capabilities=[
            NormalizedCapability.LIFECYCLE_DOMAIN_READ,
            NormalizedCapability.LIFECYCLE_BUNDLE_READ,
            NormalizedCapability.LIFECYCLE_DOMAIN_UPGRADE,
        ],
        arguments=[
            {"name": "domain_id", "description": "Target workload domain ID.", "required": True},
            {"name": "target_version", "description": "Target VCF version (e.g. 9.1.1).", "required": True},
            {"name": "bundle_id", "description": "Applicable SDDC Manager upgrade bundle ID.", "required": False},
        ],
        preconditions=[
            "Verify applicable `bundle_id` via `vcf_list_upgrade_bundles` and ensure management domain is upgraded before VI workload domains.",
        ],
        sop_steps=[
            "Step 1 (Verify Bundles): Call `vcf_list_upgrade_bundles` for `domain_id={domain_id}` and `target_version={target_version}`.",
            "Step 2 (Dry-Run Impact Plan): Call `vcf_upgrade_domain` with `domain_id={domain_id}`, `target_version={target_version}`, `dry_run=True` to generate `plan_id` and inspect compensation boundaries.",
            "Step 3 (Dual Approval Gate): Obtain required N-person approvals for `HIGH_IMPACT` `plan_id` and retrieve `approval_id` and `nonce` via `enterprise/plans/get`.",
            "Step 4 (Live Execute & Monitor): Call `vcf_upgrade_domain` with `dry_run=False`, `plan_id`, `approval_id`, and `nonce`, then track progress via `tasks/get`.",
        ],
        postconditions=[
            "Durable MCP Task ID is created and tracking native SDDC Manager upgrade task progress.",
        ],
        forbidden_actions=[
            "Never bypass precheck validation or attempt to upgrade a VI domain ahead of the MANAGEMENT domain.",
        ],
    ),
    # 15. DR_OPERATOR — Isolated Bubble Recovery Drill
    RoleSkillCard(
        name="vcf-dr-bubble-recovery-drill",
        title="Non-Disruptive Site Recovery Test Bubble Drill",
        role=CapabilityRole.DR_OPERATOR,
        additional_allowed_roles=[CapabilityRole.DR_ADMIN],
        single_task_objective="Run a non-disruptive disaster recovery failover test drill in an isolated bubble network.",
        risk_class=RiskClass.SAFE_WRITE,
        allowed_tools=["vcf_get_health", "vcf_recover_site"],
        required_capabilities=[
            NormalizedCapability.LIFECYCLE_DOMAIN_READ,
            NormalizedCapability.DR_REPLICATION_READ,
        ],
        arguments=[
            {"name": "recovery_plan_id", "description": "DR recovery plan name (e.g. rp-prod).", "required": True},
            {"name": "target_site", "description": "Secondary recovery site ID (default: dc2).", "required": False},
        ],
        preconditions=[
            "Verify secondary site health via `vcf_get_health` prior to starting the test bubble drill.",
        ],
        sop_steps=[
            "Step 1 (Health Check): Call `vcf_get_health` to confirm recovery site readiness.",
            "Step 2 (Dry-Run Plan): Call `vcf_recover_site` with `recovery_plan_id={recovery_plan_id}`, `target_site={target_site}`, `dry_run=True` to generate `plan_id`.",
            "Step 3 (Approval Gate): Obtain approval (`approval_id` and `nonce`) for `plan_id`.",
            "Step 4 (Live Drill Execution): Call `vcf_recover_site` with `recovery_plan_id={recovery_plan_id}`, `dry_run=False`, `plan_id`, `approval_id`, and `nonce`.",
        ],
        postconditions=[
            "Confirm test bubble workflow task is running with zero production traffic impact.",
        ],
        forbidden_actions=[
            "Never initiate an unplanned production failover; only isolated test bubble drills are permitted.",
        ],
    ),
    # 16. DR_ADMIN — Cross-Site DR Readiness & Governance
    RoleSkillCard(
        name="vcf-dr-site-failover-governance",
        title="Cross-Site Disaster Recovery Readiness & Drill Governance",
        role=CapabilityRole.DR_ADMIN,
        additional_allowed_roles=[],
        single_task_objective="Audit cross-domain health and govern disaster recovery test bubble drills across primary and secondary sites.",
        risk_class=RiskClass.SAFE_WRITE,
        allowed_tools=["vcf_list_domains", "vcf_get_health", "vcf_recover_site"],
        required_capabilities=[
            NormalizedCapability.LIFECYCLE_DOMAIN_READ,
            NormalizedCapability.DR_REPLICATION_READ,
            NormalizedCapability.DR_FAILOVER_EXECUTE,
        ],
        arguments=[
            {"name": "recovery_plan_id", "description": "DR recovery plan identifier (e.g. rp-cross-dc).", "required": True},
            {"name": "target_site", "description": "Target recovery site (default: dc2).", "required": False},
        ],
        preconditions=[
            "Verify both primary and secondary workload domains are healthy.",
        ],
        sop_steps=[
            "Call `vcf_list_domains` and `vcf_get_health` to validate domain and appliance health.",
            "Execute `vcf_recover_site` with `dry_run=True` to evaluate recovery plan blast radius.",
            "After approval, execute `vcf_recover_site` with `dry_run=False` and monitor task completion via `tasks/get`.",
        ],
        postconditions=[
            "Document drill task ID and isolated test bubble network verification.",
        ],
        forbidden_actions=[
            "Never execute unapproved site failovers.",
        ],
    ),
    # 17. SECURITY_ADMIN — Control Plane Security & Audit Posture
    RoleSkillCard(
        name="vcf-security-posture-audit",
        title="Enterprise VCF Security Posture & Audit Integrity Inspection",
        role=CapabilityRole.SECURITY_ADMIN,
        additional_allowed_roles=[CapabilityRole.VCF_AUDITOR],
        single_task_objective="Inspect control plane cryptographic audit integrity, appliance health, and security posture.",
        risk_class=RiskClass.READ,
        allowed_tools=["vcf_verify_audit_chain", "vcf_get_health", "vcf_list_domains"],
        required_capabilities=[
            NormalizedCapability.AUDIT_LOG_VERIFY,
            NormalizedCapability.LIFECYCLE_DOMAIN_READ,
        ],
        arguments=[
            {"name": "limit", "description": "Number of recent audit events to inspect (default: 50).", "required": False},
        ],
        preconditions=[
            "Caller holds SECURITY_ADMIN, VCF_AUDITOR, or VCF_PLATFORM_ADMIN role.",
        ],
        sop_steps=[
            "Call `vcf_verify_audit_chain` with `limit={limit}` to verify zero tampering in `audit_chain`.",
            "Call `vcf_get_health` and `vcf_list_domains` to inspect subsystem security and domain states.",
        ],
        postconditions=[
            "Produce a security posture report covering audit chain integrity and denied access attempts.",
        ],
        forbidden_actions=[
            "Do not modify workload resources during a security posture audit.",
        ],
    ),
    # 18. VCF_PLATFORM_ADMIN — Execution Plan Review & Approval Governance
    RoleSkillCard(
        name="vcf-platform-approval-governance",
        title="Execution Plan TOCTOU Review & Cryptographic Approval Governance",
        role=CapabilityRole.VCF_PLATFORM_ADMIN,
        additional_allowed_roles=[],
        single_task_objective="Review pending dry-run execution plans, verify target resource state and blast radius, and issue KMS-signed approvals.",
        risk_class=RiskClass.HIGH_IMPACT,
        allowed_tools=["vcf_verify_audit_chain", "vcf_get_health", "vcf_get_vm", "vcf_list_domains"],
        required_capabilities=[
            NormalizedCapability.AUDIT_LOG_VERIFY,
            NormalizedCapability.LIFECYCLE_DOMAIN_READ,
            NormalizedCapability.COMPUTE_VM_READ,
        ],
        arguments=[
            {"name": "plan_id", "description": "Execution plan ID to inspect and approve.", "required": False},
        ],
        preconditions=[
            "Reviewer must be a distinct principal from the plan initiator (unless in non-production laptop lab mode with `VCF_LAB_SELF_APPROVE=true`).",
        ],
        sop_steps=[
            "Step 1 (Discover Pending Plans): Call `enterprise/plans/list` (or CLI `vcf-mcp plans list`) to view `PENDING_APPROVAL` plans.",
            "Step 2 (Inspect Plan Details): Call `enterprise/plans/get` with `plan_id={plan_id}` to inspect `normalized_args`, `resource_revisions`, and `impact_summary`.",
            "Step 3 (Verify Infrastructure State): Call `vcf_get_vm` or `vcf_get_health` to confirm target resource readiness.",
            "Step 4 (Approve): Call `enterprise/plans/approve` with `plan_id={plan_id}` (or CLI `vcf-mcp plans approve {plan_id}`) to mint a KMS-signed `SignedExecutionAuthorization`.",
        ],
        postconditions=[
            "Plan status transitions to `APPROVED` and initiator can retrieve `approval_id` and `nonce` via `enterprise/plans/get`.",
        ],
        forbidden_actions=[
            "Never approve a plan whose resource revisions or arguments do not match the change ticket.",
        ],
    ),
    # ---- Troubleshooting and automation skills (small-model friendly: few tools, explicit order) ----
    RoleSkillCard(
        name="vcf-oncall-troubleshoot",
        title="Find out why a service or application is down",
        role=CapabilityRole.VCF_VIEWER,
        additional_allowed_roles=[CapabilityRole.VCF_AUDITOR, CapabilityRole.COMPUTE_OPERATOR, CapabilityRole.NETWORK_OPERATOR,
                                  CapabilityRole.STORAGE_OPERATOR, CapabilityRole.LIFECYCLE_OPERATOR],
        single_task_objective="Find the root cause of an outage or failure (VCF appliance, NSX routing/firewall/VPC, VM, AD, clustered DB) without changing anything.",
        risk_class=RiskClass.READ,
        allowed_tools=["vcf_find_tool", "vcf_diagnose", "vcf_trace_application", "vcf_list_networks", "vcf_check_component",
                       "vcf_list_failed_tasks", "vcf_list_alerts"],
        required_capabilities=[NormalizedCapability.LIFECYCLE_DOMAIN_READ],
        arguments=[{"name": "symptom", "description": "What users report, in their words.", "required": True},
                   {"name": "application", "description": "The affected application, if one is named (e.g. CRM).", "required": False}],
        preconditions=["Read-only access (VCF_VIEWER or similar)."],
        sop_steps=[
            "If ONE named application/service is affected, call `vcf_trace_application` with application={application}; otherwise call `vcf_diagnose` with symptom={symptom}.",
            "Read the FIRST finding: title, cause, evidence ids, impact, next_steps. Findings are already ranked.",
            "If the first finding does not match the symptom, call the other tool (`vcf_diagnose` or `vcf_trace_application`) once to cross-check.",
            "Report: root cause, evidence (names/values), who is affected, next steps, confidence. Mention unrelated findings as unrelated.",
        ],
        postconditions=["Nothing was changed; the answer cites evidence ids."],
        forbidden_actions=["Do not call any tool that changes VCF.", "Do not guess a cause that no finding or evidence supports."],
    ),
    RoleSkillCard(
        name="vcf-automation-cloud-template",
        title="Create an Assembler cloud template",
        role=CapabilityRole.AUTOMATION_OPERATOR,
        additional_allowed_roles=[],
        single_task_objective="Write, validate and save a VCF Automation (Assembler) cloud template as a DRAFT.",
        risk_class=RiskClass.CHANGE,
        allowed_tools=["vcf_find_tool", "vcf_automation_list", "vcf_automation_get", "vcf_automation_validate_template", "vcf_automation_create_template"],
        required_capabilities=[NormalizedCapability.AUTOMATION_READ, NormalizedCapability.AUTOMATION_TEMPLATE_WRITE],
        arguments=[{"name": "request", "description": "What the template must build.", "required": True}],
        preconditions=["AUTOMATION_OPERATOR role."],
        sop_steps=[
            "Call `vcf_automation_list` with kind=projects, then images, flavors and networks; use ONLY names that appear there.",
            "Write YAML: formatVersion: 1, inputs, resources (Cloud.vSphere.Machine with image, flavor, count, networks; Cloud.Network with constraints - tag: <network tag>).",
            "Call `vcf_automation_validate_template`; fix every error and validate again until valid.",
            "Call `vcf_automation_create_template` with dry_run=true. Get human approval for the plan (vcf-mcp plans approve <plan_id>); then call the same tool with the SAME arguments plus plan_id, approval_id and nonce (no dry_run).",
        ],
        postconditions=["The template exists as DRAFT and validates."],
        forbidden_actions=["Do not invent image, flavor or network names.", "Do not deploy anything."],
    ),
    RoleSkillCard(
        name="vcf-orchestrator-run-workflow",
        title="Run an existing Orchestrator workflow",
        role=CapabilityRole.AUTOMATION_OPERATOR,
        additional_allowed_roles=[],
        single_task_objective="Find an existing Orchestrator workflow, run it with the right inputs after approval, and report the real result.",
        risk_class=RiskClass.CHANGE,
        allowed_tools=["vcf_find_tool", "vcf_orch_about", "vcf_orch_list", "vcf_orch_get", "vcf_orch_list_executions", "vcf_orch_run", "vcf_orch_answer"],
        required_capabilities=[NormalizedCapability.AUTOMATION_READ, NormalizedCapability.AUTOMATION_WORKFLOW_RUN],
        arguments=[{"name": "request", "description": "What should be done.", "required": True}],
        preconditions=["AUTOMATION_OPERATOR role."],
        sop_steps=[
            "Call `vcf_orch_list` kind=workflows with a name filter to find the workflow id.",
            "Call `vcf_orch_get` kind=workflow to read its inputs (names and types).",
            "Call `vcf_orch_run` with dry_run=true and inputs={name: value}; SecureString inputs go in secret_inputs as credential references.",
            "Get human approval for the plan (vcf-mcp plans approve <plan_id>); then call the same tool with the SAME arguments plus plan_id, approval_id and nonce (no dry_run).",
            "If the result state is 'waiting', use `vcf_orch_answer`; if 'failed', report the error message exactly (the result already carries the run logs). Never claim success on a failed run.",
            "To see earlier runs of a workflow (for example the failed ones) call `vcf_orch_list_executions`, then `vcf_orch_get` kind=execution for one of them.",
        ],
        postconditions=["The reported state and outputs come from the execution, not from assumptions."],
        forbidden_actions=["Never pass a password or token as a plain input.", "Never work around a failed run by changing the target or forest without asking."],
    ),
    RoleSkillCard(
        name="vcf-orchestrator-author-action",
        title="Create or update an Orchestrator action",
        role=CapabilityRole.AUTOMATION_OPERATOR,
        additional_allowed_roles=[],
        single_task_objective="Write an Orchestrator action in plain ES5 (the Rhino engine), save it in a com.mcp.* module after approval, and test it.",
        risk_class=RiskClass.CHANGE,
        allowed_tools=["vcf_find_tool", "vcf_orch_about", "vcf_orch_list", "vcf_orch_get", "vcf_orch_validate", "vcf_orch_try_script",
                       "vcf_orch_save_action", "vcf_orch_run_action", "vcf_orch_rollback", "vcf_orch_create_environment",
                       "vcf_orch_tracked_changes"],
        required_capabilities=[NormalizedCapability.AUTOMATION_READ, NormalizedCapability.AUTOMATION_ORCH_AUTHOR],
        arguments=[{"name": "request", "description": "What the action must do.", "required": True}],
        preconditions=["AUTOMATION_OPERATOR role."],
        sop_steps=[
            "Call `vcf_orch_about` (version, plug-ins, runtimes, guardrails). If you need plug-in objects, call `vcf_orch_get` kind=scripting_api.",
            "Write the script in plain ES5 (Orchestrator runs Rhino): var, function(){}, string + concatenation, indexed for loops. NO let/const, arrow functions, template literals, for...of, class, async/await, ?., ??, spread (...), destructuring, default parameters, Intl, regex u flag; ASCII only; no java.* or Packages.*; no passwords in code.",
            "Call `vcf_orch_validate` with the script; fix every error until ok is true.",
            "Optionally try the logic first with `vcf_orch_try_script` (dry run, approval, run): it runs the snippet in a temporary action and deletes it.",
            "Call `vcf_orch_save_action` with dry_run=true (module must start with com.mcp.). Get human approval for the plan (vcf-mcp plans approve <plan_id>); then call the same tool with the SAME arguments plus plan_id, approval_id and nonce (no dry_run).",
            "When updating an existing action, pass base_changeset_sha from the dry run; if a conflict is reported, dry-run again.",
            "Optionally test it with `vcf_orch_run_action` (dry run, approval, run).",
        ],
        postconditions=["The action is saved, versioned, and its script passed validation."],
        forbidden_actions=["Do not save outside com.mcp.* modules.", "Do not hard-code credentials."],
    ),
    RoleSkillCard(
        name="vcf-orchestrator-author-workflow",
        title="Create or update an Orchestrator workflow",
        role=CapabilityRole.AUTOMATION_OPERATOR,
        additional_allowed_roles=[],
        single_task_objective="Build an Orchestrator workflow from a step list (scripts, actions, decisions, sub-workflows, error handling), save it under MCP-Managed/ after approval.",
        risk_class=RiskClass.CHANGE,
        allowed_tools=["vcf_find_tool", "vcf_orch_about", "vcf_orch_list", "vcf_orch_get", "vcf_orch_validate", "vcf_orch_save_workflow",
                       "vcf_orch_save_action", "vcf_orch_run", "vcf_orch_list_executions", "vcf_orch_rollback", "vcf_orch_tracked_changes"],
        required_capabilities=[NormalizedCapability.AUTOMATION_READ, NormalizedCapability.AUTOMATION_ORCH_AUTHOR],
        arguments=[{"name": "request", "description": "What the workflow must do.", "required": True}],
        preconditions=["AUTOMATION_OPERATOR role."],
        sop_steps=[
            "Call `vcf_orch_about`; find reusable actions/workflows with `vcf_orch_list`.",
            "Write the spec: name, inputs/outputs/variables (each with a type), steps in order (script | action | decision | workflow | end | error_end) and on_error.",
            "Every variable a step reads or writes must be declared in inputs, outputs or variables. Scripts are plain ES5 (no let/const, arrows, template literals). Inputs may carry a default; variables a value.",
            "Call `vcf_orch_validate` with workflow=<spec>; fix every error (each says what to change).",
            "Call `vcf_orch_save_workflow` with dry_run=true and category MCP-Managed/<team>. Get human approval for the plan (vcf-mcp plans approve <plan_id>); then call the same tool with the SAME arguments plus plan_id, approval_id and nonce (no dry_run).",
            "When updating, pass base_changeset_sha from the dry run; if a conflict is reported, dry-run again.",
        ],
        postconditions=["The workflow is saved, validated by Orchestrator and versioned."],
        forbidden_actions=["Do not edit workflows outside MCP-Managed/.", "Do not hand-write Orchestrator schema JSON; use the spec."],
    ),
    RoleSkillCard(
        name="vcf-orchestrator-integration",
        title="Connect Orchestrator to an endpoint (vCenter, REST, AD, PowerShell, SSH)",
        role=CapabilityRole.SECURITY_ADMIN,
        additional_allowed_roles=[],
        single_task_objective="Add or repair an Orchestrator plug-in endpoint with Broadcom's configuration workflow; credentials only by reference.",
        risk_class=RiskClass.SECURITY_SENSITIVE,
        allowed_tools=["vcf_find_tool", "vcf_orch_about", "vcf_orch_list", "vcf_orch_add_integration", "vcf_orch_set_configuration"],
        required_capabilities=[NormalizedCapability.AUTOMATION_ORCH_INTEGRATION],
        arguments=[{"name": "endpoint", "description": "What to connect (kind, host/url).", "required": True}],
        preconditions=["SECURITY_ADMIN role.", "The password is already stored as a credential reference (vcf_setup or 'vcf-mcp credentials add')."],
        sop_steps=[
            "Call `vcf_orch_about` (plug-ins installed, unusable vCenter connections).",
            "Call `vcf_orch_add_integration` with dry_run=true, kind, settings (no passwords) and credential_ref. Fix any problem it lists.",
            "This change needs TWO human approvers. " + "Get human approval for the plan (vcf-mcp plans approve <plan_id>); then call the same tool with the SAME arguments plus plan_id, approval_id and nonce (no dry_run).",
            "Report the run state and the plug-in inventory after the change.",
        ],
        postconditions=["The endpoint appears as usable in the plug-in inventory."],
        forbidden_actions=["Never ask the user to type a password into the chat.", "Never put a password in settings."],
    ),
    RoleSkillCard(
        name="vcf-orchestrator-plugin-install",
        title="Install an Orchestrator plug-in",
        role=CapabilityRole.VCF_PLATFORM_ADMIN,
        additional_allowed_roles=[],
        single_task_objective="Install a Broadcom or vendor Orchestrator plug-in (.vmoapp) verified by SHA-256.",
        risk_class=RiskClass.HIGH_IMPACT,
        allowed_tools=["vcf_find_tool", "vcf_orch_about", "vcf_orch_list", "vcf_orch_install_plugin"],
        required_capabilities=[NormalizedCapability.AUTOMATION_ORCH_INTEGRATION],
        arguments=[{"name": "file_path", "description": "Plug-in file in the MCP plug-in folder.", "required": True},
                   {"name": "sha256", "description": "Published SHA-256 of the file.", "required": True}],
        preconditions=["The admin downloaded the plug-in from the vendor and placed it in the MCP plug-in folder."],
        sop_steps=["Call `vcf_orch_install_plugin` with dry_run=true. " + "Get human approval for the plan (vcf-mcp plans approve <plan_id>); then call the same tool with the SAME arguments plus plan_id, approval_id and nonce (no dry_run).", "Confirm with `vcf_orch_about` that the plug-in is listed."],
        postconditions=["The plug-in is listed in vcf_orch_about."],
        forbidden_actions=["Never install a file whose SHA-256 does not match."],
    ),
    RoleSkillCard(
        name="vcf-orchestrator-package",
        title="Export or build an Orchestrator package",
        role=CapabilityRole.AUTOMATION_OPERATOR,
        additional_allowed_roles=[],
        single_task_objective="Export an Orchestrator package to a .package file, or package what the MCP saved, without ever exporting secrets.",
        risk_class=RiskClass.CHANGE,
        allowed_tools=["vcf_find_tool", "vcf_orch_about", "vcf_orch_list", "vcf_orch_get", "vcf_orch_tracked_changes", "vcf_orch_export_package",
                       "vcf_orch_build_package"],
        required_capabilities=[NormalizedCapability.AUTOMATION_READ, NormalizedCapability.AUTOMATION_ORCH_AUTHOR],
        arguments=[{"name": "package", "description": "Package name (com.mcp.<name>) or what to package.", "required": True}],
        preconditions=["AUTOMATION_OPERATOR role."],
        sop_steps=[
            "To back up an existing package call `vcf_orch_export_package` with package_name (find it with `vcf_orch_list` kind=packages). Report the file path, size and SHA-256 it returns.",
            "To package your own work first call `vcf_orch_tracked_changes` to see what the MCP saved.",
            "Call `vcf_orch_build_package` with dry_run=true and a name like com.mcp.<name>. Get human approval for the plan (vcf-mcp plans approve <plan_id>); then call the same tool with the SAME arguments plus plan_id, approval_id and nonce (no dry_run).",
        ],
        postconditions=["The .package file exists in the MCP export folder and its SHA-256 was reported."],
        forbidden_actions=["Never try to include SecureString values in an export.", "Never package content outside MCP-Managed/ and com.mcp.* modules."],
    ),
]


class SkillCatalogRegistry:
    """Registry managing single-responsibility role skills for MCP Prompts, Resources, and SKILL.md export."""

    def __init__(self, skills: Optional[List[RoleSkillCard]] = None):
        self._skills: List[RoleSkillCard] = list(skills or ALL_ROLE_SKILLS)
        self._by_name: Dict[str, RoleSkillCard] = {s.name: s for s in self._skills}

    def list_all_skills(self) -> List[RoleSkillCard]:
        return list(self._skills)

    def get_skill(self, name: str) -> Optional[RoleSkillCard]:
        return self._by_name.get(name)

    def get_skills_for_roles(
        self,
        effective_roles: List[CapabilityRole],
        discovery_only: bool = False,
    ) -> List[RoleSkillCard]:
        """Filters skills visible to a principal's effective RBAC roles and control-plane operating mode."""
        visible: List[RoleSkillCard] = []
        is_platform_admin = CapabilityRole.VCF_PLATFORM_ADMIN in effective_roles
        for skill in self._skills:
            if discovery_only and skill.risk_class != RiskClass.READ:
                continue
            if is_platform_admin or any(r in effective_roles for r in skill.all_authorized_roles):
                visible.append(skill)
        return visible

    def export_skill_markdown_files(self, base_dir: str | Path) -> List[str]:
        """Writes portable `.agents/skills/<skill-name>/SKILL.md` files to disk."""
        root = Path(base_dir)
        written: List[str] = []
        for skill in self._skills:
            skill_dir = root / skill.name
            skill_dir.mkdir(parents=True, exist_ok=True)
            skill_file = skill_dir / "SKILL.md"
            skill_file.write_text(skill.to_skill_markdown(), encoding="utf-8")
            written.append(str(skill_file))
        return written


def _offer_plan_status_to_write_skills(cards: List["RoleSkillCard"]) -> None:
    """Skills that contain a write tool also get the read-only plan status tool (vcf_get_plan)."""
    from vcf_enterprise_mcp.router.catalog import get_tool_card_by_name
    for card in cards:
        writes = any((c := get_tool_card_by_name(t)) is not None and c.risk_class != RiskClass.READ for t in card.allowed_tools)
        if writes and "vcf_get_plan" not in card.allowed_tools:
            card.allowed_tools.append("vcf_get_plan")


_offer_plan_status_to_write_skills(ALL_ROLE_SKILLS)

_DEFAULT_SKILL_REGISTRY: Optional[SkillCatalogRegistry] = None


def get_skill_registry() -> SkillCatalogRegistry:
    global _DEFAULT_SKILL_REGISTRY
    if _DEFAULT_SKILL_REGISTRY is None:
        _DEFAULT_SKILL_REGISTRY = SkillCatalogRegistry()
    return _DEFAULT_SKILL_REGISTRY
