# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Pydantic v2 Schema for the Single-Inventory VCF Digital Twin Configuration (vcf_inventory.yaml).
Supports complex enterprise multi-tenancy, multiple workload domains, and granular infrastructure topologies.
"""

from __future__ import annotations
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class EnvironmentConfig(BaseModel):
    name: str = "Corporate-Production-SDDC-Grid"
    vcf_version: str = "9.1.0.0"
    build_number: str = "24892011"
    organization: str = "Enterprise IT Cloud Services"
    simulated_latency_ms: int = 10
    enforce_strict_auth: bool = True


class SDDCCredentials(BaseModel):
    admin_user: str = "administrator@vsphere.local"
    admin_pass: str = "VMware1!MockPassword"
    role: str = "VCF_SUPER_ADMIN"


class LicenseItem(BaseModel):
    id: str
    product_name: str
    license_key: str
    capacity: int = 512
    units: str = "CORES"
    used: int = 256


class SDDCManagerConfig(BaseModel):
    id: str = "sddc-mgr-prod"
    fqdn: str = "sddc-manager.corp.local"
    ip_address: str = "192.168.10.2"
    credentials: Optional[SDDCCredentials] = None


class IPPoolRange(BaseModel):
    start: str
    end: str


class SubnetConfig(BaseModel):
    network_type: str  # VSAN, GENEVE, MANAGEMENT, VMOTION
    cidr: str
    gateway: str
    vlan_id: int
    ip_pool: Optional[IPPoolRange] = None


class NetworkPoolConfig(BaseModel):
    id: str
    name: str
    subnets: List[SubnetConfig] = Field(default_factory=list)


class ESXiHostConfig(BaseModel):
    id: str
    fqdn: str
    ip: str
    cores: int = 64
    memory_gb: int = 512
    storage_tb: int = 14
    status: str = "ASSIGNED"


class SupervisorVMClass(BaseModel):
    name: str
    cpu: int = 2
    memory_mb: int = 4096
    vgpu_profile: Optional[str] = None


class SupervisorNamespace(BaseModel):
    name: str
    description: str = "Production Workload Namespace"
    storage_limit_gb: int = 1000
    tenant_org: Optional[str] = None


class SupervisorConfig(BaseModel):
    cluster_id: str = "domain-c8"
    config_status: str = "RUNNING"
    kubernetes_status: str = "READY"
    api_endpoint: str = "https://192.168.20.250:6443"
    kubernetes_version: str = "v1.30.2+vmware.1"
    master_nodes: List[str] = Field(default_factory=lambda: ["192.168.20.251", "192.168.20.252"])
    vm_service_classes: List[SupervisorVMClass] = Field(default_factory=list)
    namespaces: List[SupervisorNamespace] = Field(default_factory=list)


class ClusterConfig(BaseModel):
    id: str
    name: str
    primary_datastore_name: str = "vsan-ds01"
    vsphere_supervisor: Optional[SupervisorConfig] = None
    hosts: List[ESXiHostConfig] = Field(default_factory=list)


class VCenterConfig(BaseModel):
    id: str
    fqdn: str
    ip_address: str


class NSXManagerConfig(BaseModel):
    id: str
    vip_fqdn: str
    ip_address: str


class SRMInstanceConfig(BaseModel):
    id: str
    fqdn: str
    site_name: str


class EdgeNodeConfig(BaseModel):
    name: str
    mgmt_ip: str
    tep_ip: str


class EdgeClusterConfig(BaseModel):
    id: str
    name: str
    nodes: List[EdgeNodeConfig] = Field(default_factory=list)


class ManagementDomainConfig(BaseModel):
    id: str = "domain-mgmt-01"
    name: str = "sddc-mgmt-domain"
    vcenter: VCenterConfig
    nsx_manager: NSXManagerConfig
    srm_instance: Optional[SRMInstanceConfig] = None
    cluster: Optional[ClusterConfig] = None
    clusters: List[ClusterConfig] = Field(default_factory=list)


class WorkloadDomainConfig(BaseModel):
    id: str
    name: str
    domain_type: str = "VI"  # VI, TKG, AI_ML
    tenant_organization: Optional[str] = None
    vcenter: VCenterConfig
    nsx_manager: NSXManagerConfig
    srm_instance: Optional[SRMInstanceConfig] = None
    edge_cluster: Optional[EdgeClusterConfig] = None
    clusters: List[ClusterConfig] = Field(default_factory=list)


class TenantOrgConfig(BaseModel):
    id: str
    name: str
    description: str = "Multi-Tenant Business Organization"
    quota_cpu: int = 256
    quota_memory_gb: int = 1024
    quota_storage_tb: int = 50


class VMDiskConfig(BaseModel):
    id: str = "disk-2000"
    label: str = "Hard disk 1"
    capacity_bytes: int = 107374182400  # 100 GB
    capacity_gb: int = 100
    datastore: str = "vsan-wld01-ds01"
    backing_file: str = "[vsan-wld01-ds01] vm/vm.vmdk"
    thin_provisioned: bool = True
    storage_policy: str = "policy-vsan-esa-default"


class VMFilesystemConfig(BaseModel):
    mount_point: str = "/"
    filesystem_type: str = "ext4"  # ext4, xfs, ntfs
    capacity_bytes: int = 107374182400
    free_bytes: int = 64424509440
    used_bytes: int = 42949672960
    percent_free: float = 60.0


class VMNicConfig(BaseModel):
    nic_id: str = "nic-4000"
    label: str = "Network adapter 1"
    mac_address: str = "00:50:56:a1:b2:c3"
    network: str = "seg-wld01-apps"
    ip_addresses: List[str] = Field(default_factory=lambda: ["192.168.110.10"])
    connected: bool = True


class TenantVMConfig(BaseModel):
    id: str
    name: str
    power_state: str = "POWERED_ON"
    cpu_count: int = 4
    memory_size_MiB: int = 16384
    guest_os: str = "RHEL_9_64"
    guest_hostname: Optional[str] = None
    ip_address: str = "192.168.110.10"
    mac_address: Optional[str] = "00:50:56:a1:b2:c3"
    datastore: str = "vsan-wld01-ds01"
    folder: Optional[str] = "Production-Workloads"
    resource_pool: Optional[str] = "Compute-ResourcePool"
    hardware_version: str = "vmx-21"
    tenant_org: Optional[str] = None
    workload_domain_id: Optional[str] = None
    disks: List[VMDiskConfig] = Field(default_factory=list)
    filesystems: List[VMFilesystemConfig] = Field(default_factory=list)
    nics: List[VMNicConfig] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    custom_attributes: Dict[str, str] = Field(default_factory=dict)


class NSXTier0Config(BaseModel):
    id: str
    display_name: str
    ha_mode: str = "ACTIVE_ACTIVE"
    bgp_asn: int = 65001
    tenant_org: Optional[str] = None


class NSXTier1Config(BaseModel):
    id: str
    display_name: str
    tier0_path: str = "/infra/tier-0s/t0-production"
    tenant_org: Optional[str] = None


class NSXSegmentConfig(BaseModel):
    id: str
    display_name: str
    connectivity_path: str = "/infra/tier-1s/t1-production"
    subnets: List[Dict[str, Any]] = Field(default_factory=list)
    tenant_org: Optional[str] = None


class NSXGroupConfig(BaseModel):
    id: str
    display_name: str
    expression: List[Dict[str, Any]] = Field(default_factory=list)
    tenant_org: Optional[str] = None


class NSXSecurityPolicyConfig(BaseModel):
    id: str
    display_name: str
    category: str = "Application"
    scope: List[str] = Field(default_factory=list)
    rules: List[Dict[str, Any]] = Field(default_factory=list)
    tenant_org: Optional[str] = None


class VRProfileConfig(BaseModel):
    id: str
    name: str
    rpo_minutes: int = 5
    description: str = "vSphere Replication Profile"


class VRReplicationConfig(BaseModel):
    id: str
    vm_id: str
    vm_name: str
    rpo_minutes: int = 5
    status: str = "OK"
    health: str = "NORMAL"
    target_datastore: str = "vsan-wld01-ds01"


class ProtectedVMConfig(BaseModel):
    id: str
    name: str
    status: str = "PROTECTED"
    consistency: str = "CONSISTENT"


class ProtectionGroupConfig(BaseModel):
    id: str
    name: str
    type: str = "VSPHERE_REPLICATION"
    rpo_minutes: int = 5
    protected_vms: List[ProtectedVMConfig] = Field(default_factory=list)


class RecoveryPlanConfig(BaseModel):
    id: str
    name: str
    protection_groups: List[str] = Field(default_factory=list)
    status: str = "READY"
    last_test_result: str = "SUCCESSFUL"


class SitePairingConfig(BaseModel):
    id: str
    pairing_name: str
    local_site: Dict[str, Any]
    peer_site: Dict[str, Any]
    status: str = "CONNECTED"
    network_mappings: List[Dict[str, Any]] = Field(default_factory=list)
    protection_groups: List[ProtectionGroupConfig] = Field(default_factory=list)
    recovery_plans: List[RecoveryPlanConfig] = Field(default_factory=list)


class ProtectionAndRecoveryConfig(BaseModel):
    pairings: List[SitePairingConfig] = Field(default_factory=list)
    network_mappings: List[Dict[str, Any]] = Field(default_factory=list)
    protection_groups: List[ProtectionGroupConfig] = Field(default_factory=list)
    recovery_plans: List[RecoveryPlanConfig] = Field(default_factory=list)


class SingleInventoryConfig(BaseModel):
    environment: EnvironmentConfig = Field(default_factory=EnvironmentConfig)
    sddc_manager: SDDCManagerConfig
    licensing: List[LicenseItem] = Field(default_factory=list)
    network_pools: List[NetworkPoolConfig] = Field(default_factory=list)
    management_domain: ManagementDomainConfig
    workload_domains: List[WorkloadDomainConfig] = Field(default_factory=list)
    tenant_organizations: List[TenantOrgConfig] = Field(default_factory=list)
    nsx_tier0s: List[NSXTier0Config] = Field(default_factory=list)
    nsx_tier1s: List[NSXTier1Config] = Field(default_factory=list)
    nsx_segments: List[NSXSegmentConfig] = Field(default_factory=list)
    nsx_groups: List[NSXGroupConfig] = Field(default_factory=list)
    nsx_security_policies: List[NSXSecurityPolicyConfig] = Field(default_factory=list)
    tenant_vms: List[TenantVMConfig] = Field(default_factory=list)
    vr_profiles: List[VRProfileConfig] = Field(default_factory=list)
    vr_replications: List[VRReplicationConfig] = Field(default_factory=list)
    protection_and_recovery: Optional[ProtectionAndRecoveryConfig] = Field(default_factory=ProtectionAndRecoveryConfig)
