# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Guided-setup knowledge base: what users want to do, which tools that needs, the
least-privilege VCF access each component requires, and which accounts are
over-permissive.

Role and privilege names follow Broadcom documentation for VCF 9.x:
vCenter privilege IDs (Administration > Access Control > Roles), SDDC Manager
roles ADMIN / OPERATOR / VIEWER, NSX built-in roles, and VCF Operations roles.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

COMPONENTS = ("vcenter", "sddc_manager", "nsx", "vcf_operations")

COMPONENT_TITLES = {
    "vcenter": "vCenter",
    "sddc_manager": "SDDC Manager",
    "nsx": "NSX Manager",
    "vcf_operations": "VCF Operations",
}


@dataclass(frozen=True)
class Goal:
    key: str
    title: str
    description: str
    tools: Tuple[str, ...]
    components: Tuple[str, ...]
    implemented_for_real_vcf: bool = True


GOALS: Dict[str, Goal] = {g.key: g for g in [
    Goal(
        "monitor", "Monitor health and inventory (read-only)",
        "List domains, clusters, hosts, VMs, datastores, NSX segments and gateways; read health and alerts.",
        ("vcf_list_domains", "vcf_list_clusters", "vcf_list_hosts", "vcf_list_vms", "vcf_get_vm",
         "vcf_list_datastores", "vcf_list_nsx_segments", "vcf_list_nsx_gateways", "vcf_get_health",
         "vcf_list_snapshots"),
        ("vcenter", "sddc_manager", "nsx", "vcf_operations"),
    ),
    Goal(
        "capacity", "Capacity and performance analysis (read-only)",
        "Query VCF Operations metrics for clusters, hosts and VMs.",
        ("vcf_query_telemetry", "vcf_get_health"),
        ("vcf_operations",),
    ),
    Goal(
        "vm_operations", "Day-2 VM operations",
        "Power VMs on/off, resize CPU and memory, create and delete snapshots. Every change needs a dry run and approval.",
        ("vcf_power_vm", "vcf_resize_vm", "vcf_create_snapshot", "vcf_delete_snapshot", "vcf_list_vms", "vcf_get_vm"),
        ("vcenter",),
    ),
    Goal(
        "network", "NSX network changes",
        "Create overlay segments on Tier-1 gateways.",
        ("vcf_create_nsx_segment", "vcf_list_nsx_segments", "vcf_list_nsx_gateways"),
        ("nsx",),
    ),
    Goal(
        "lifecycle", "Lifecycle and upgrades",
        "Review upgradable bundles and run approved workload-domain upgrades through SDDC Manager.",
        ("vcf_list_upgrade_bundles", "vcf_upgrade_domain", "vcf_list_domains"),
        ("sddc_manager",),
    ),
    Goal(
        "disaster_recovery", "Disaster-recovery drills",
        "Site recovery drills. No VMware Live Recovery provider exists yet, so this is unavailable against real VCF.",
        ("vcf_recover_site",),
        (),
        implemented_for_real_vcf=False,
    ),
]}


@dataclass(frozen=True)
class ToolImpact:
    """How much harm a tool can do, independent of the policy risk label."""
    level: str          # READ | CHANGE | DISRUPTIVE | DESTRUCTIVE
    summary: str


TOOL_IMPACT: Dict[str, ToolImpact] = {
    "vcf_power_vm": ToolImpact("DISRUPTIVE", "Powering off or resetting a VM interrupts its workload immediately."),
    "vcf_resize_vm": ToolImpact("CHANGE", "Changes VM CPU/memory; reducing either requires the VM to be powered off."),
    "vcf_create_snapshot": ToolImpact("CHANGE", "Creates a snapshot; long-lived snapshots grow and degrade performance."),
    "vcf_delete_snapshot": ToolImpact("DESTRUCTIVE", "Deletes a restore point permanently; it cannot be recovered."),
    "vcf_create_nsx_segment": ToolImpact("CHANGE", "Adds a network segment to a Tier-1 gateway; affects routing and firewall scope."),
    "vcf_upgrade_domain": ToolImpact("DESTRUCTIVE", "Upgrades a workload domain; host and firmware steps cannot be rolled back."),
    "vcf_recover_site": ToolImpact("DISRUPTIVE", "Runs recovery-plan actions across sites."),
}

# Groups the user can switch off in one choice during setup.
DESTRUCTIVE_GROUPS: Dict[str, Tuple[str, Tuple[str, ...]]] = {
    "disable_vm_power": ("Block VM power-off / reset / suspend", ("vcf_power_vm",)),
    "disable_snapshot_delete": ("Block snapshot deletion", ("vcf_delete_snapshot",)),
    "disable_vm_reconfigure": ("Block VM CPU/memory changes", ("vcf_resize_vm",)),
    "disable_network_changes": ("Block NSX network changes", ("vcf_create_nsx_segment",)),
    "disable_upgrades": ("Block workload-domain upgrades", ("vcf_upgrade_domain",)),
    "disable_dr": ("Block disaster-recovery actions", ("vcf_recover_site",)),
}

# vCenter privilege IDs needed per tool (vSphere privilege identifiers).
VCENTER_PRIVILEGES: Dict[str, Tuple[str, ...]] = {
    "vcf_power_vm": ("VirtualMachine.Interact.PowerOn", "VirtualMachine.Interact.PowerOff",
                     "VirtualMachine.Interact.Reset", "VirtualMachine.Interact.Suspend"),
    "vcf_resize_vm": ("VirtualMachine.Config.CPUCount", "VirtualMachine.Config.Memory"),
    "vcf_create_snapshot": ("VirtualMachine.State.CreateSnapshot",),
    "vcf_delete_snapshot": ("VirtualMachine.State.RemoveSnapshot",),
}

# Privileges whose presence at the vCenter root indicates an administrator-equivalent account.
VCENTER_ADMIN_MARKERS = (
    "Authorization.ModifyPermissions",
    "VirtualMachine.Inventory.Delete",
    "Host.Inventory.RemoveHostFromCluster",
    "Datastore.Delete",
)

LOCAL_ADMIN_ACCOUNTS: Dict[str, Tuple[str, ...]] = {
    "vcenter": ("administrator@vsphere.local", "root"),
    "sddc_manager": ("admin@local", "root", "vcf"),
    "nsx": ("admin", "root"),
    "vcf_operations": ("admin", "root"),
}

OVER_PERMISSIVE_ROLES: Dict[str, Tuple[str, ...]] = {
    "vcenter": ("Admin", "Administrator"),
    "sddc_manager": ("ADMIN",),
    "nsx": ("enterprise_admin",),
    "vcf_operations": ("Administrator",),
}


@dataclass
class AccessGuide:
    component: str
    role: str
    steps: List[str]
    privileges: List[str] = field(default_factory=list)


def _vcenter_privileges_for(tools: List[str]) -> List[str]:
    privs: List[str] = []
    for tool in tools:
        for p in VCENTER_PRIVILEGES.get(tool, ()):
            if p not in privs:
                privs.append(p)
    return privs


def least_privilege_guides(goal_keys: List[str]) -> Dict[str, AccessGuide]:
    """Per-component instructions for creating the minimum account the selected goals need."""
    goals = [GOALS[g] for g in goal_keys if g in GOALS]
    tools = [t for g in goals for t in g.tools]
    components = {c for g in goals for c in g.components}
    guides: Dict[str, AccessGuide] = {}
    common = "Use a dedicated service account from your identity source (VCF SSO / Identity Broker or AD), not a local account, and rotate its password in your vault."

    if "vcenter" in components:
        privs = _vcenter_privileges_for(tools)
        if privs:
            guides["vcenter"] = AccessGuide(
                "vcenter", "Custom role 'VCF-MCP-Operator' (Read-only plus only the privileges listed)",
                [
                    "vSphere Client > Administration > Access Control > Roles > clone 'Read-only' as 'VCF-MCP-Operator'.",
                    "Add only these privileges: " + ", ".join(privs) + ".",
                    "Assign the role to the service account on the VM folder or cluster it should manage (not the vCenter root), with 'Propagate to children'.",
                    "Assign 'Read-only' as a global permission so inventory reads work everywhere.",
                    common,
                ],
                privs,
            )
        else:
            guides["vcenter"] = AccessGuide(
                "vcenter", "Read-only (global permission)",
                ["vSphere Client > Administration > Access Control > Global Permissions > Add: service account, role 'Read-only', propagate.", common],
            )

    if "sddc_manager" in components:
        lifecycle = "vcf_upgrade_domain" in tools
        role = "OPERATOR" if lifecycle else "VIEWER"
        guides["sddc_manager"] = AccessGuide(
            "sddc_manager", role,
            [
                "SDDC Manager > Administration > Single Sign On > Add User or Group.",
                f"Select the service account and assign the {role} role. ADMIN is only needed for password/credential management, which this MCP never needs.",
                "Do not use the break-glass local account admin@local for automation.",
                common,
            ],
        )

    if "nsx" in components:
        writes = "vcf_create_nsx_segment" in tools
        role = "network_engineer (Network Admin)" if writes else "auditor"
        guides["nsx"] = AccessGuide(
            "nsx", role,
            [
                "NSX Manager > System > User Management > Role Assignment > Add Role for LDAP/VIDM user.",
                f"Assign the service account the '{role}' role; avoid 'enterprise_admin'.",
                "Do not use the local 'admin' account; it cannot be scoped and bypasses role assignment.",
                common,
            ],
        )

    if "vcf_operations" in components:
        guides["vcf_operations"] = AccessGuide(
            "vcf_operations", "ReadOnly",
            [
                "VCF Operations > Administration > Control Panel > Access Control > User Accounts (or import from your identity source).",
                "Assign the 'ReadOnly' role with 'Allow access to all objects in the system' only if fleet-wide monitoring is wanted; otherwise scope to the relevant object groups.",
                "Do not use the local 'admin' account.",
                common,
            ],
        )
    return guides


def tools_for_goals(goal_keys: List[str]) -> List[str]:
    out: List[str] = []
    for g in goal_keys:
        for t in GOALS[g].tools if g in GOALS else ():
            if t not in out:
                out.append(t)
    return out


def components_for_goals(goal_keys: List[str]) -> List[str]:
    wanted = {c for g in goal_keys if g in GOALS for c in GOALS[g].components}
    return [c for c in COMPONENTS if c in wanted]


def is_local_admin(component: str, username: Optional[str]) -> bool:
    if not username:
        return False
    name = username.strip().lower()
    for acct in LOCAL_ADMIN_ACCOUNTS.get(component, ()):
        if name == acct or name.split("\\")[-1] == acct:
            return True
    return component == "vcenter" and name.startswith("administrator@")
