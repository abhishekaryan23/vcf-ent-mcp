# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Enterprise Policy Models, Normalized Capabilities, Risk Classes, and Capability Roles.
Decouples authorization from hardcoded roles by establishing:
Native Privileges -> Normalized Capabilities -> Enterprise Policy Overlay -> Effective Permissions.
Includes change-control context (maintenance windows, change tickets) and permission epochs.
"""

from __future__ import annotations
from enum import Enum
from typing import List, Dict, Set, Optional, Any
from dataclasses import dataclass, field


class RiskClass(str, Enum):
    """Operational risk categories for MCP tool actions."""
    READ = "READ"                                  # Non-mutating inventory, telemetry, logs
    SAFE_WRITE = "SAFE_WRITE"                      # Reversible non-disruptive actions (e.g. power-on VM)
    CHANGE = "CHANGE"                              # Standard configuration modifications (resize, snapshot)
    HIGH_IMPACT = "HIGH_IMPACT"                    # Multi-node impact (upgrades, failover drills)
    DESTRUCTIVE = "DESTRUCTIVE"                    # Irreversible data loss (delete VM, decommission host)
    SECURITY_SENSITIVE = "SECURITY_SENSITIVE"      # Credentials, SSO realms, CA certificates


class NormalizedCapability(str, Enum):
    """Normalized atomic capabilities decoupled from underlying appliance vendor syntax."""
    COMPUTE_VM_READ = "compute.vm.read"
    COMPUTE_VM_POWER = "compute.vm.power"
    COMPUTE_VM_RESIZE = "compute.vm.resize.memory"
    COMPUTE_VM_SNAPSHOT = "compute.vm.snapshot"
    COMPUTE_HOST_READ = "compute.host.read"
    COMPUTE_CLUSTER_READ = "compute.cluster.read"
    NETWORK_SEGMENT_READ = "network.segment.read"
    NETWORK_TOPOLOGY_READ = "network.topology.read"
    NETWORK_SEGMENT_CREATE = "network.segment.create"
    STORAGE_DATASTORE_READ = "storage.datastore.read"
    LIFECYCLE_DOMAIN_READ = "lifecycle.domain.read"
    LIFECYCLE_BUNDLE_READ = "lifecycle.bundle.read"
    LIFECYCLE_DOMAIN_UPGRADE = "lifecycle.domain.upgrade"
    DR_REPLICATION_READ = "dr.replication.read"
    DR_SITE_RECOVER = "dr.site.recover"
    DR_FAILOVER_EXECUTE = "dr.failover.execute"
    TELEMETRY_READ = "telemetry.metrics.read"
    AUDIT_LOG_VERIFY = "audit.log.verify"
    SECURITY_IAM_ADMIN = "security.iam.admin"
    AUTOMATION_READ = "automation.catalog.read"
    AUTOMATION_TEMPLATE_WRITE = "automation.template.write"
    AUTOMATION_WORKFLOW_RUN = "automation.workflow.run"
    AUTOMATION_ORCH_AUTHOR = "automation.orchestrator.author"
    AUTOMATION_ORCH_INTEGRATION = "automation.orchestrator.integration"


# Mapping from VMware vCenter / SDDC Manager Native Privileges to Normalized Capabilities
NATIVE_PRIVILEGE_TO_CAPABILITY: Dict[str, NormalizedCapability] = {
    "System.Read": NormalizedCapability.COMPUTE_VM_READ,
    "VirtualMachine.Interact.PowerOn": NormalizedCapability.COMPUTE_VM_POWER,
    "VirtualMachine.Interact.PowerOff": NormalizedCapability.COMPUTE_VM_POWER,
    "VirtualMachine.Interact.Reset": NormalizedCapability.COMPUTE_VM_POWER,
    "VirtualMachine.Config.Memory": NormalizedCapability.COMPUTE_VM_RESIZE,
    "VirtualMachine.State.CreateSnapshot": NormalizedCapability.COMPUTE_VM_SNAPSHOT,
    "Host.Config.Inventory": NormalizedCapability.COMPUTE_HOST_READ,
    "Network.Config.Create": NormalizedCapability.NETWORK_SEGMENT_CREATE,
    "Datastore.Config": NormalizedCapability.STORAGE_DATASTORE_READ,
    "VCF.LCM.Upgrade": NormalizedCapability.LIFECYCLE_DOMAIN_UPGRADE,
    "SRM.RecoveryPlan.Test": NormalizedCapability.DR_REPLICATION_READ,
    "SRM.RecoveryPlan.Execute": NormalizedCapability.DR_SITE_RECOVER,
}


class CapabilityRole(str, Enum):
    """Preset capability role templates granting sets of normalized capabilities."""
    VCF_VIEWER = "VCF_VIEWER"                      # Read-only inventory, health, and metrics
    VCF_AUDITOR = "VCF_AUDITOR"                    # Read + compliance + configuration history
    COMPUTE_OPERATOR = "COMPUTE_OPERATOR"          # VM power, snapshots, safe resize
    COMPUTE_ADMIN = "COMPUTE_ADMIN"                # Provision/delete/migrate VMs and templates
    NETWORK_OPERATOR = "NETWORK_OPERATOR"          # Read NSX, trace flows, inspect BGP
    NETWORK_ADMIN = "NETWORK_ADMIN"                # T0/T1 gateways, segments, firewall rules
    STORAGE_OPERATOR = "STORAGE_OPERATOR"          # Capacity, policies, health alerts
    STORAGE_ADMIN = "STORAGE_ADMIN"                # vSAN lifecycle and data protection
    AUTOMATION_OPERATOR = "AUTOMATION_OPERATOR"    # Cloud Assembly deployments and templates
    DR_OPERATOR = "DR_OPERATOR"                    # DR drill testing, replication sync
    DR_ADMIN = "DR_ADMIN"                          # Actual site recovery failover and reprotect
    LIFECYCLE_OPERATOR = "LIFECYCLE_OPERATOR"      # Upgrade pre-checks, bundle downloads
    LIFECYCLE_ADMIN = "LIFECYCLE_ADMIN"            # Workload domain upgrades and host patching
    SECURITY_ADMIN = "SECURITY_ADMIN"              # Certificates, credentials, SSO realms
    VCF_PLATFORM_ADMIN = "VCF_PLATFORM_ADMIN"      # Full management overlay
    MCP_ADMIN = "MCP_ADMIN"                        # MCP control plane config only


# Role Presets mapping CapabilityRole -> Set of NormalizedCapabilities
ROLE_PRESET_CAPABILITIES: Dict[CapabilityRole, Set[NormalizedCapability]] = {
    CapabilityRole.VCF_VIEWER: {
        NormalizedCapability.COMPUTE_VM_READ,
        NormalizedCapability.COMPUTE_HOST_READ,
        NormalizedCapability.COMPUTE_CLUSTER_READ,
        NormalizedCapability.NETWORK_SEGMENT_READ,
        NormalizedCapability.NETWORK_TOPOLOGY_READ,
        NormalizedCapability.STORAGE_DATASTORE_READ,
        NormalizedCapability.LIFECYCLE_DOMAIN_READ,
        NormalizedCapability.LIFECYCLE_BUNDLE_READ,
        NormalizedCapability.TELEMETRY_READ,
        NormalizedCapability.DR_REPLICATION_READ,
        NormalizedCapability.AUTOMATION_READ,
    },
    CapabilityRole.VCF_AUDITOR: {
        NormalizedCapability.COMPUTE_VM_READ,
        NormalizedCapability.COMPUTE_HOST_READ,
        NormalizedCapability.COMPUTE_CLUSTER_READ,
        NormalizedCapability.NETWORK_SEGMENT_READ,
        NormalizedCapability.NETWORK_TOPOLOGY_READ,
        NormalizedCapability.STORAGE_DATASTORE_READ,
        NormalizedCapability.LIFECYCLE_DOMAIN_READ,
        NormalizedCapability.LIFECYCLE_BUNDLE_READ,
        NormalizedCapability.TELEMETRY_READ,
        NormalizedCapability.DR_REPLICATION_READ,
        NormalizedCapability.AUDIT_LOG_VERIFY,
        NormalizedCapability.AUTOMATION_READ,
    },
    CapabilityRole.COMPUTE_OPERATOR: {
        NormalizedCapability.COMPUTE_VM_READ,
        NormalizedCapability.COMPUTE_HOST_READ,
        NormalizedCapability.COMPUTE_CLUSTER_READ,
        NormalizedCapability.STORAGE_DATASTORE_READ,
        NormalizedCapability.COMPUTE_VM_POWER,
        NormalizedCapability.COMPUTE_VM_RESIZE,
        NormalizedCapability.COMPUTE_VM_SNAPSHOT,
        NormalizedCapability.TELEMETRY_READ,
    },
    CapabilityRole.COMPUTE_ADMIN: {
        NormalizedCapability.COMPUTE_VM_READ,
        NormalizedCapability.COMPUTE_HOST_READ,
        NormalizedCapability.COMPUTE_CLUSTER_READ,
        NormalizedCapability.COMPUTE_VM_POWER,
        NormalizedCapability.COMPUTE_VM_RESIZE,
        NormalizedCapability.COMPUTE_VM_SNAPSHOT,
        NormalizedCapability.STORAGE_DATASTORE_READ,
        NormalizedCapability.TELEMETRY_READ,
    },
    CapabilityRole.NETWORK_OPERATOR: {
        NormalizedCapability.COMPUTE_VM_READ,
        NormalizedCapability.NETWORK_SEGMENT_READ,
        NormalizedCapability.NETWORK_TOPOLOGY_READ,
        NormalizedCapability.LIFECYCLE_DOMAIN_READ,
        NormalizedCapability.TELEMETRY_READ,
    },
    CapabilityRole.NETWORK_ADMIN: {
        NormalizedCapability.COMPUTE_VM_READ,
        NormalizedCapability.NETWORK_SEGMENT_READ,
        NormalizedCapability.NETWORK_TOPOLOGY_READ,
        NormalizedCapability.NETWORK_SEGMENT_CREATE,
        NormalizedCapability.LIFECYCLE_DOMAIN_READ,
        NormalizedCapability.TELEMETRY_READ,
    },
    CapabilityRole.STORAGE_OPERATOR: {
        NormalizedCapability.COMPUTE_VM_READ,
        NormalizedCapability.COMPUTE_HOST_READ,
        NormalizedCapability.COMPUTE_CLUSTER_READ,
        NormalizedCapability.STORAGE_DATASTORE_READ,
        NormalizedCapability.TELEMETRY_READ,
    },
    CapabilityRole.STORAGE_ADMIN: {
        NormalizedCapability.COMPUTE_VM_READ,
        NormalizedCapability.COMPUTE_HOST_READ,
        NormalizedCapability.COMPUTE_CLUSTER_READ,
        NormalizedCapability.STORAGE_DATASTORE_READ,
        NormalizedCapability.COMPUTE_VM_SNAPSHOT,
        NormalizedCapability.TELEMETRY_READ,
    },
    CapabilityRole.AUTOMATION_OPERATOR: {
        NormalizedCapability.COMPUTE_VM_READ,
        NormalizedCapability.COMPUTE_HOST_READ,
        NormalizedCapability.COMPUTE_CLUSTER_READ,
        NormalizedCapability.COMPUTE_VM_POWER,
        NormalizedCapability.COMPUTE_VM_SNAPSHOT,
        NormalizedCapability.NETWORK_SEGMENT_READ,
        NormalizedCapability.NETWORK_TOPOLOGY_READ,
        NormalizedCapability.TELEMETRY_READ,
        NormalizedCapability.AUTOMATION_READ,
        NormalizedCapability.AUTOMATION_TEMPLATE_WRITE,
        NormalizedCapability.AUTOMATION_WORKFLOW_RUN,
        NormalizedCapability.AUTOMATION_ORCH_AUTHOR,
    },
    CapabilityRole.LIFECYCLE_OPERATOR: {
        NormalizedCapability.COMPUTE_VM_READ,
        NormalizedCapability.COMPUTE_HOST_READ,
        NormalizedCapability.COMPUTE_CLUSTER_READ,
        NormalizedCapability.LIFECYCLE_DOMAIN_READ,
        NormalizedCapability.LIFECYCLE_BUNDLE_READ,
        NormalizedCapability.TELEMETRY_READ,
    },
    CapabilityRole.LIFECYCLE_ADMIN: {
        NormalizedCapability.COMPUTE_VM_READ,
        NormalizedCapability.COMPUTE_HOST_READ,
        NormalizedCapability.COMPUTE_CLUSTER_READ,
        NormalizedCapability.LIFECYCLE_DOMAIN_READ,
        NormalizedCapability.LIFECYCLE_BUNDLE_READ,
        NormalizedCapability.LIFECYCLE_DOMAIN_UPGRADE,
        NormalizedCapability.TELEMETRY_READ,
    },
    CapabilityRole.DR_OPERATOR: {
        NormalizedCapability.COMPUTE_VM_READ,
        NormalizedCapability.COMPUTE_HOST_READ,
        NormalizedCapability.LIFECYCLE_DOMAIN_READ,
        NormalizedCapability.DR_REPLICATION_READ,
        NormalizedCapability.TELEMETRY_READ,
    },
    CapabilityRole.DR_ADMIN: {
        NormalizedCapability.COMPUTE_VM_READ,
        NormalizedCapability.LIFECYCLE_DOMAIN_READ,
        NormalizedCapability.DR_REPLICATION_READ,
        NormalizedCapability.DR_SITE_RECOVER,
        NormalizedCapability.DR_FAILOVER_EXECUTE,
        NormalizedCapability.TELEMETRY_READ,
    },
    CapabilityRole.SECURITY_ADMIN: {
        NormalizedCapability.COMPUTE_VM_READ,
        NormalizedCapability.COMPUTE_HOST_READ,
        NormalizedCapability.LIFECYCLE_DOMAIN_READ,
        NormalizedCapability.AUDIT_LOG_VERIFY,
        NormalizedCapability.SECURITY_IAM_ADMIN,
        NormalizedCapability.TELEMETRY_READ,
        NormalizedCapability.AUTOMATION_READ,
        NormalizedCapability.AUTOMATION_ORCH_INTEGRATION,
    },
    CapabilityRole.VCF_PLATFORM_ADMIN: set(NormalizedCapability),
    CapabilityRole.MCP_ADMIN: set(NormalizedCapability),
}


@dataclass
class ChangeControlContext:
    """Operational change management window and ticket metadata."""
    maintenance_window_active: bool = False
    freeze_period_active: bool = False
    change_ticket_id: Optional[str] = None
    is_emergency_change: bool = False

    def is_change_permitted(self, risk_class: RiskClass) -> Tuple[bool, str]:
        if risk_class in [RiskClass.READ, RiskClass.SAFE_WRITE]:
            return True, "Low-risk operation permitted outside maintenance window."

        if self.freeze_period_active and not self.is_emergency_change:
            return False, "Infrastructure change freeze is currently active. Only emergency changes with ticket permitted."

        if risk_class in [RiskClass.HIGH_IMPACT, RiskClass.DESTRUCTIVE]:
            if not self.maintenance_window_active and not self.is_emergency_change:
                return False, f"{risk_class.value} requires an active maintenance window or emergency override."
            if not self.change_ticket_id:
                return False, f"{risk_class.value} requires an approved change ticket ID."

        return True, "Change control criteria satisfied."


@dataclass
class ResourceScope:
    """Multi-dimensional boundaries restricting where a tool action may be applied."""
    domains: List[str] = field(default_factory=list)
    clusters: List[str] = field(default_factory=list)
    datastores: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    sites: List[str] = field(default_factory=list)

    def contains(
        self,
        domain_id: Optional[str] = None,
        cluster_id: Optional[str] = None,
        site_id: Optional[str] = None,
    ) -> bool:
        """Verifies if the target infrastructure coordinates reside within this scope."""
        if self.domains and domain_id and domain_id not in self.domains and "*" not in self.domains:
            return False
        if self.clusters and cluster_id and cluster_id not in self.clusters and "*" not in self.clusters:
            return False
        if self.sites and site_id and site_id not in self.sites and "*" not in self.sites:
            return False
        return True


@dataclass
class PolicyDecision:
    """Result of an evaluation by the Policy Decision Point (PDP)."""
    allow: bool
    reason: str
    approval_required: bool = False
    risk_class: RiskClass = RiskClass.READ
    effective_roles: List[str] = field(default_factory=list)
    effective_capabilities: Set[NormalizedCapability] = field(default_factory=set)
    allowed_scopes: List[str] = field(default_factory=list)
    permission_epoch: int = 100
    tenant_id: str = "tenant-default"
    environment_id: str = "env-prod"
    decision_timestamp: float = field(default=0.0)

    def to_audit_dict(self) -> Dict[str, Any]:
        return {
            "decision": "ALLOW" if self.allow else "DENY",
            "reason": self.reason,
            "approval_required": self.approval_required,
            "risk_class": self.risk_class.value,
            "effective_roles": self.effective_roles,
            "effective_capabilities": [c.value for c in self.effective_capabilities],
            "permission_epoch": self.permission_epoch,
            "tenant_id": self.tenant_id,
            "environment_id": self.environment_id,
        }


@dataclass
class ApprovalPolicy:
    """Configurable N-person approval policy based on operation risk classification."""
    required_approvals: int = 1
    required_roles: tuple[str, ...] = ()
    allow_initiator: bool = False
    distinct_principals: bool = True
    approvals_required: Dict[RiskClass, int] = field(default_factory=lambda: {
        RiskClass.READ: 0,
        RiskClass.SAFE_WRITE: 0,
        RiskClass.CHANGE: 1,
        RiskClass.HIGH_IMPACT: 1,
        RiskClass.DESTRUCTIVE: 2,
        RiskClass.SECURITY_SENSITIVE: 2,
    })
    disallow_self_approval: bool = True
    required_approver_roles: Dict[RiskClass, List[str]] = field(default_factory=lambda: {
        RiskClass.HIGH_IMPACT: ["VCF-Platform-Admins", "VCF-Lifecycle-Admins"],
        RiskClass.DESTRUCTIVE: ["VCF-Platform-Admins", "VCF-Security-Admins"],
        RiskClass.SECURITY_SENSITIVE: ["VCF-Security-Admins"],
    })

    def get_required_approvals(self, risk_class: RiskClass) -> int:
        if self.required_approvals > 1:
            return self.required_approvals
        return self.approvals_required.get(risk_class, self.required_approvals)

    def validate_approver(
        self,
        initiator_id: str,
        approver_id: str,
        approver_groups: List[str] | tuple[str, ...],
        risk_class: RiskClass,
    ) -> Tuple[bool, str]:
        import os
        lab_self_approve = (
            os.environ.get("VCF_MCP_ENV", "").lower() != "production"
            and os.environ.get("VCF_LAB_SELF_APPROVE", "").lower() == "true"
        )
        if not self.allow_initiator and not lab_self_approve and (self.disallow_self_approval and initiator_id == approver_id):
            return False, f"Separation of duties violation: Approver '{approver_id}' cannot approve their own plan."

        # Check top-level required_roles if defined
        if self.required_roles:
            if not any(r in approver_groups for r in self.required_roles) and "*" not in approver_groups:
                return False, f"Approver '{approver_id}' lacks required approval role ({', '.join(self.required_roles)})"

        req_roles = self.required_approver_roles.get(risk_class, [])
        if req_roles and not any(r in approver_groups for r in req_roles) and "*" not in approver_groups:
            return False, f"Approver '{approver_id}' lacks required approval role ({', '.join(req_roles)})"
        return True, "Approver authorized"

