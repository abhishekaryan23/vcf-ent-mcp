# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
In-Memory State Graph for Single-Inventory VCF Digital Twin.
Models the exact 1:1 state of an imported multi-tenant, multi-workload-domain VCF 9 environment.
"""

from __future__ import annotations

import os
import uuid
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
import yaml
from digital_twin.schema import SingleInventoryConfig


class DigitalTwinState:
    def __init__(self, config_data: Optional[Dict[str, Any]] = None, config_path: str = "digital_twin/vcf_inventory.yaml"):
        self.config_path = config_path
        if config_data is None:
            if os.path.exists(config_path):
                with open(config_path, "r", encoding="utf-8") as f:
                    config_data = yaml.safe_load(f)
            else:
                config_data = {}

        self.raw_config = config_data
        self.config = SingleInventoryConfig.model_validate(config_data) if config_data else SingleInventoryConfig(
            sddc_manager={"id": "sddc-mgr-prod", "fqdn": "sddc.corp.local", "ip_address": "192.168.10.2"},
            management_domain={
                "id": "domain-mgmt",
                "name": "sddc-mgmt",
                "vcenter": {"id": "vc-mgmt", "fqdn": "vc.corp.local", "ip_address": "192.168.10.10"},
                "nsx_manager": {"id": "nsx-mgmt", "vip_fqdn": "nsx.corp.local", "ip_address": "192.168.10.11"},
            }
        )

        # State Containers
        self.tokens: Dict[str, Dict[str, Any]] = {}
        self.vcenter_sessions: Dict[str, Dict[str, Any]] = {}
        self.srm_sessions: Dict[str, Dict[str, Any]] = {}
        self.hosts: Dict[str, Dict[str, Any]] = {}
        self.vms: Dict[str, Dict[str, Any]] = {}
        self.datastores: Dict[str, Dict[str, Any]] = {}
        self.networks: List[Dict[str, Any]] = []
        self.tenant_orgs: Dict[str, Dict[str, Any]] = {}
        self.nsx_tier0s: Dict[str, Dict[str, Any]] = {}
        self.nsx_tier1s: Dict[str, Dict[str, Any]] = {}
        self.nsx_segments: Dict[str, Dict[str, Any]] = {}
        self.nsx_groups: Dict[str, Dict[str, Any]] = {}
        self.nsx_security_policies: Dict[str, Dict[str, Any]] = {}
        self.supervisor_namespaces: Dict[str, Dict[str, Any]] = {}
        self.supervisor_classes: Dict[str, Dict[str, Any]] = {}
        self.srm_pairings: Dict[str, Dict[str, Any]] = {}
        self.srm_protection_groups: Dict[str, Dict[str, Any]] = {}
        self.srm_recovery_plans: Dict[str, Dict[str, Any]] = {}
        self.srm_executions: List[Dict[str, Any]] = []
        self.vr_profiles: Dict[str, Dict[str, Any]] = {}
        self.vr_replications: Dict[str, Dict[str, Any]] = {}
        self.network_pools: Dict[str, Dict[str, Any]] = {}
        self.certificates: List[Dict[str, Any]] = []

        self._bootstrap_state()

    def _bootstrap_state(self):
        # Clear dynamic dicts
        self.hosts.clear()
        self.vms.clear()
        self.datastores.clear()
        self.networks.clear()
        self.tenant_orgs.clear()
        self.nsx_tier0s.clear()
        self.nsx_tier1s.clear()
        self.nsx_segments.clear()
        self.nsx_groups.clear()
        self.nsx_security_policies.clear()
        self.supervisor_namespaces.clear()
        self.supervisor_classes.clear()
        self.srm_pairings.clear()
        self.srm_protection_groups.clear()
        self.srm_recovery_plans.clear()
        self.srm_executions.clear()
        self.vr_profiles.clear()
        self.vr_replications.clear()
        self.network_pools.clear()
        self.certificates.clear()

        # 1. Network Pools
        for np in self.config.network_pools:
            self.network_pools[np.id] = np.model_dump()

        # 2. Tenant Organizations
        for org in self.config.tenant_organizations:
            self.tenant_orgs[org.id] = org.model_dump()

        # Default standard organizations if none specified
        if not self.tenant_orgs:
            self.tenant_orgs["org-default"] = {"id": "org-default", "name": "Default Infrastructure Org", "description": "Core Tenant Org"}

        # 3. Bootstrap Datastores & Hosts from Management Domain
        mgmt_cluster = self.config.management_domain.cluster
        mgmt_clusters = self.config.management_domain.clusters or ([mgmt_cluster] if mgmt_cluster else [])
        for cl in mgmt_clusters:
            if not cl:
                continue
            mgmt_ds = cl.primary_datastore_name or "vsan-mgmt-ds01"
            self.datastores[mgmt_ds] = {
                "datastore": mgmt_ds,
                "name": mgmt_ds,
                "type": "VSAN",
                "capacity": 8796093022208,
                "free_space": 7500000000000,
                "vsan_esa_enabled": True,
                "cluster_id": cl.id,
            }
            for h in cl.hosts:
                self.hosts[h.id] = {
                    "id": h.id,
                    "fqdn": h.fqdn,
                    "ip": h.ip,
                    "cores": h.cores,
                    "memory_gb": h.memory_gb,
                    "storage_tb": h.storage_tb,
                    "status": "ASSIGNED",
                    "domain_id": self.config.management_domain.id,
                    "cluster_id": cl.id,
                }
            if cl.vsphere_supervisor:
                self._load_supervisor_config(cl.id, cl.vsphere_supervisor)

        # 4. Bootstrap Datastores & Hosts from Workload Domains
        for wld in self.config.workload_domains:
            for cl in wld.clusters:
                wld_ds = cl.primary_datastore_name or f"vsan-{cl.name}-ds01"
                self.datastores[wld_ds] = {
                    "datastore": wld_ds,
                    "name": wld_ds,
                    "type": "VSAN",
                    "capacity": 17592186044416,
                    "free_space": 14000000000000,
                    "vsan_esa_enabled": True,
                    "cluster_id": cl.id,
                    "domain_id": wld.id,
                }
                for h in cl.hosts:
                    self.hosts[h.id] = {
                        "id": h.id,
                        "fqdn": h.fqdn,
                        "ip": h.ip,
                        "cores": h.cores,
                        "memory_gb": h.memory_gb,
                        "storage_tb": h.storage_tb,
                        "status": "ASSIGNED",
                        "domain_id": wld.id,
                        "cluster_id": cl.id,
                    }
                if cl.vsphere_supervisor:
                    self._load_supervisor_config(cl.id, cl.vsphere_supervisor)

        # Supplemental Enterprise Shared Datastores
        self.datastores["fc-san-tier1-ds01"] = {"datastore": "fc-san-tier1-ds01", "name": "fc-san-tier1-ds01", "type": "VMFS", "capacity": 21990232555520, "free_space": 18000000000000}
        self.datastores["nfs-netapp-ontap-ds01"] = {"datastore": "nfs-netapp-ontap-ds01", "name": "nfs-netapp-ontap-ds01", "type": "NFS", "capacity": 27487790694400, "free_space": 22000000000000}

        # 5. Bootstrap Infrastructure & Tenant VMs
        mgmt_ds_key = list(self.datastores.keys())[0] if self.datastores else "vsan-mgmt-ds01"
        self.vms["vm-101"] = {"vm": "vm-101", "name": "sddc-manager-prod", "power_state": "POWERED_ON", "cpu_count": 8, "memory_size_MiB": 32768, "ip_address": self.config.sddc_manager.ip_address, "datastore": mgmt_ds_key}
        self.vms["vm-102"] = {"vm": "vm-102", "name": "vcenter-mgmt-prod", "power_state": "POWERED_ON", "cpu_count": 8, "memory_size_MiB": 24576, "ip_address": self.config.management_domain.vcenter.ip_address, "datastore": mgmt_ds_key}
        self.vms["vm-103"] = {"vm": "vm-103", "name": "nsx-mgmt-mgr-prod", "power_state": "POWERED_ON", "cpu_count": 6, "memory_size_MiB": 24576, "ip_address": self.config.management_domain.nsx_manager.ip_address, "datastore": mgmt_ds_key}

        for wld in self.config.workload_domains:
            self.vms[f"vm-vc-{wld.id}"] = {"vm": f"vm-vc-{wld.id}", "name": wld.vcenter.fqdn, "power_state": "POWERED_ON", "cpu_count": 8, "memory_size_MiB": 24576, "ip_address": wld.vcenter.ip_address, "datastore": mgmt_ds_key, "domain_id": wld.id}
            if wld.edge_cluster:
                for node in wld.edge_cluster.nodes:
                    self.vms[f"vm-{node.name}"] = {"vm": f"vm-{node.name}", "name": node.name, "power_state": "POWERED_ON", "cpu_count": 8, "memory_size_MiB": 32768, "ip_address": node.mgmt_ip, "datastore": mgmt_ds_key, "domain_id": wld.id}

        # Explicit or Default Tenant Workload VMs
        if self.config.tenant_vms:
            for tvm in self.config.tenant_vms:
                self.vms[tvm.id] = {
                    "vm": tvm.id,
                    "name": tvm.name,
                    "power_state": tvm.power_state,
                    "cpu_count": tvm.cpu_count,
                    "memory_size_MiB": tvm.memory_size_MiB,
                    "guest_os": tvm.guest_os,
                    "guest_hostname": tvm.guest_hostname,
                    "ip_address": tvm.ip_address,
                    "mac_address": tvm.mac_address,
                    "datastore": tvm.datastore,
                    "folder": tvm.folder,
                    "resource_pool": tvm.resource_pool,
                    "hardware_version": tvm.hardware_version,
                    "tenant_org": tvm.tenant_org,
                    "workload_domain_id": tvm.workload_domain_id,
                    "disks": [d.model_dump() for d in tvm.disks],
                    "filesystems": [f.model_dump() for f in tvm.filesystems],
                    "nics": [n.model_dump() for n in tvm.nics],
                    "network": tvm.nics[0].network if tvm.nics else "seg-wld01-apps",
                    "tags": tvm.tags,
                    "custom_attributes": tvm.custom_attributes,
                }
        else:
            self.vms["vm-prod-crm-01"] = {"vm": "vm-prod-crm-01", "name": "prod-crm-app01", "power_state": "POWERED_ON", "cpu_count": 4, "memory_size_MiB": 16384, "ip_address": "192.168.110.10", "datastore": "vsan-wld01-ds01", "tenant_org": "Fintech-Org", "network": "seg-wld01-apps"}
            self.vms["vm-prod-db-01"] = {"vm": "vm-prod-db-01", "name": "prod-db-oracle01", "power_state": "POWERED_ON", "cpu_count": 8, "memory_size_MiB": 65536, "ip_address": "192.168.110.20", "datastore": "vsan-wld01-ds01", "tenant_org": "Fintech-Org", "network": "seg-wld01-apps"}
            self.vms["vm-prod-ai-01"] = {"vm": "vm-prod-ai-01", "name": "pai-llm-rag-01", "power_state": "POWERED_ON", "cpu_count": 32, "memory_size_MiB": 131072, "ip_address": "192.168.120.10", "datastore": "vsan-wld01-ds01", "tenant_org": "AI-Analytics-Org", "network": "seg-wld01-ai"}

        # 6. Bootstrap NSX Topology
        if self.config.nsx_tier0s:
            for t0 in self.config.nsx_tier0s:
                self.nsx_tier0s[t0.id] = t0.model_dump()
        else:
            self.nsx_tier0s["t0-production"] = {"id": "t0-production", "display_name": "Tier0-Production-Gateway", "ha_mode": "ACTIVE_ACTIVE", "bgp_asn": 65001}

        if self.config.nsx_tier1s:
            for t1 in self.config.nsx_tier1s:
                self.nsx_tier1s[t1.id] = t1.model_dump()
        else:
            self.nsx_tier1s["t1-production"] = {"id": "t1-production", "display_name": "Tier1-Production-Workloads", "tier0_path": "/infra/tier-0s/t0-production"}

        if self.config.nsx_segments:
            for seg in self.config.nsx_segments:
                self.nsx_segments[seg.id] = seg.model_dump()
        else:
            self.nsx_segments["seg-wld01-apps"] = {"id": "seg-wld01-apps", "display_name": "Apps-Overlay-Segment", "connectivity_path": "/infra/tier-1s/t1-production", "subnets": [{"gateway_address": "192.168.110.1/24"}]}
            self.nsx_segments["seg-wld01-ai"] = {"id": "seg-wld01-ai", "display_name": "Private-AI-Overlay-Segment", "connectivity_path": "/infra/tier-1s/t1-production", "subnets": [{"gateway_address": "192.168.120.1/24"}]}

        if self.config.nsx_groups:
            for grp in self.config.nsx_groups:
                self.nsx_groups[grp.id] = grp.model_dump()
        else:
            self.nsx_groups["grp-prod-workloads"] = {
                "id": "grp-prod-workloads",
                "display_name": "Production Workload VMs",
                "expression": [{"member_type": "VirtualMachine", "key": "Tag", "operator": "EQUALS", "value": "env:prod"}],
            }

        if self.config.nsx_security_policies:
            for sp in self.config.nsx_security_policies:
                self.nsx_security_policies[sp.id] = sp.model_dump()
        else:
            self.nsx_security_policies["sec-pol-microseg-prod"] = {
                "id": "sec-pol-microseg-prod",
                "display_name": "Microsegmentation Zero-Trust Production",
                "category": "Application",
                "scope": ["/infra/domains/default/groups/grp-prod-workloads"],
                "rules": [
                    {
                        "id": "rule-allow-https",
                        "display_name": "Allow HTTPS Inbound",
                        "action": "ALLOW",
                        "source_groups": ["ANY"],
                        "destination_groups": ["/infra/domains/default/groups/grp-prod-workloads"],
                        "services": ["/infra/services/service-https"],
                        "logged": True,
                    }
                ],
            }

        # 7. Bootstrap SRM & VR
        if self.config.protection_and_recovery:
            for pairing in self.config.protection_and_recovery.pairings:
                self.srm_pairings[pairing.id] = pairing.model_dump()
                for pg in pairing.protection_groups:
                    self.srm_protection_groups[pg.id] = pg.model_dump()
                for rp in pairing.recovery_plans:
                    self.srm_recovery_plans[rp.id] = rp.model_dump()

        if self.config.vr_profiles:
            for vp in self.config.vr_profiles:
                self.vr_profiles[vp.id] = vp.model_dump()
        else:
            self.vr_profiles["vr-prof-5min-critical"] = {"id": "vr-prof-5min-critical", "name": "Mission Critical 5-Minute RPO", "rpo_minutes": 5}
            self.vr_profiles["vr-prof-4hr-standard"] = {"id": "vr-prof-4hr-standard", "name": "Standard 4-Hour RPO", "rpo_minutes": 240}

        if self.config.vr_replications:
            for rep in self.config.vr_replications:
                self.vr_replications[rep.id] = rep.model_dump()
        else:
            self.vr_replications["rep-prod-crm-01"] = {
                "id": "rep-prod-crm-01",
                "vm_id": "vm-prod-crm-01",
                "vm_name": "prod-crm-app01",
                "rpo_minutes": 5,
                "status": "OK",
                "health": "NORMAL",
                "target_datastore": "vsan-wld01-ds01",
            }

        # 7. Bootstrap Certificates for All Applications
        self.certificates.clear()
        org_name = self.config.environment.name or "Enterprise IT"

        # SDDC Manager Cert
        self.certificates.append({
            "id": "cert-sddc-manager",
            "domainId": self.config.management_domain.id,
            "resourceType": "SDDC_MANAGER",
            "resourceId": self.config.sddc_manager.id,
            "resourceName": self.config.sddc_manager.fqdn,
            "issuer": f"CN=VCF-Root-CA, O={org_name}",
            "subject": f"CN={self.config.sddc_manager.fqdn}, O={org_name}",
            "san": [self.config.sddc_manager.fqdn, self.config.sddc_manager.ip_address],
            "algorithm": "SHA256withRSA",
            "keySize": 2048,
            "validFrom": "2026-01-01T00:00:00Z",
            "validTo": "2028-01-01T00:00:00Z",
            "daysToExpiry": 500,
            "status": "VALID",
        })

        # Management Domain vCenter & NSX
        self.certificates.append({
            "id": "cert-vc-mgmt",
            "domainId": self.config.management_domain.id,
            "resourceType": "VCENTER",
            "resourceId": self.config.management_domain.vcenter.id,
            "resourceName": self.config.management_domain.vcenter.fqdn,
            "issuer": f"CN=VCF-Subsystem-CA, O={org_name}",
            "subject": f"CN={self.config.management_domain.vcenter.fqdn}, O={org_name}",
            "san": [self.config.management_domain.vcenter.fqdn, self.config.management_domain.vcenter.ip_address],
            "algorithm": "SHA256withRSA",
            "keySize": 2048,
            "validFrom": "2026-01-01T00:00:00Z",
            "validTo": "2028-01-01T00:00:00Z",
            "daysToExpiry": 500,
            "status": "VALID",
        })
        self.certificates.append({
            "id": "cert-nsx-mgmt",
            "domainId": self.config.management_domain.id,
            "resourceType": "NSXT_MANAGER",
            "resourceId": self.config.management_domain.nsx_manager.id,
            "resourceName": self.config.management_domain.nsx_manager.vip_fqdn,
            "issuer": f"CN=VCF-Subsystem-CA, O={org_name}",
            "subject": f"CN={self.config.management_domain.nsx_manager.vip_fqdn}, O={org_name}",
            "san": [self.config.management_domain.nsx_manager.vip_fqdn, self.config.management_domain.nsx_manager.ip_address],
            "algorithm": "SHA256withRSA",
            "keySize": 2048,
            "validFrom": "2026-01-01T00:00:00Z",
            "validTo": "2028-01-01T00:00:00Z",
            "daysToExpiry": 500,
            "status": "VALID",
        })

        # Workload Domains
        for wld in self.config.workload_domains:
            self.certificates.append({
                "id": f"cert-vc-{wld.id}",
                "domainId": wld.id,
                "resourceType": "VCENTER",
                "resourceId": wld.vcenter.id,
                "resourceName": wld.vcenter.fqdn,
                "issuer": f"CN=VCF-Subsystem-CA, O={org_name}",
                "subject": f"CN={wld.vcenter.fqdn}, O={org_name}",
                "san": [wld.vcenter.fqdn, wld.vcenter.ip_address],
                "algorithm": "SHA256withRSA",
                "keySize": 2048,
                "validFrom": "2026-01-01T00:00:00Z",
                "validTo": "2028-01-01T00:00:00Z",
                "daysToExpiry": 500,
                "status": "VALID",
            })
            if wld.nsx_manager:
                self.certificates.append({
                    "id": f"cert-nsx-{wld.id}",
                    "domainId": wld.id,
                    "resourceType": "NSXT_MANAGER",
                    "resourceId": wld.nsx_manager.id,
                    "resourceName": wld.nsx_manager.vip_fqdn,
                    "issuer": f"CN=VCF-Subsystem-CA, O={org_name}",
                    "subject": f"CN={wld.nsx_manager.vip_fqdn}, O={org_name}",
                    "san": [wld.nsx_manager.vip_fqdn, wld.nsx_manager.ip_address],
                    "algorithm": "SHA256withRSA",
                    "keySize": 2048,
                    "validFrom": "2026-01-01T00:00:00Z",
                    "validTo": "2028-01-01T00:00:00Z",
                    "daysToExpiry": 500,
                    "status": "VALID",
                })

        # Aria Suite & SRM Certs
        aria_certs = [
            ("cert-vcf-ops", "VCF_OPERATIONS", "vcf-ops-cluster", "vcf-ops.corp.global"),
            ("cert-vcf-auto", "VCF_AUTOMATION", "vcf-auto-cluster", "vcf-auto.corp.global"),
            ("cert-vcf-vro", "VCF_ORCHESTRATOR", "vcf-vro-appliance", "vcf-vro.corp.global"),
            ("cert-srm-01", "SRM", "srm-appliance-01", "srm.corp.global"),
            ("cert-vr-01", "VR", "vr-appliance-01", "vr.corp.global"),
        ]
        for c_id, r_type, r_id, r_name in aria_certs:
            self.certificates.append({
                "id": c_id,
                "domainId": self.config.management_domain.id,
                "resourceType": r_type,
                "resourceId": r_id,
                "resourceName": r_name,
                "issuer": f"CN=VCF-Aria-CA, O={org_name}",
                "subject": f"CN={r_name}, O={org_name}",
                "san": [r_name],
                "algorithm": "SHA256withRSA",
                "keySize": 2048,
                "validFrom": "2026-01-01T00:00:00Z",
                "validTo": "2028-01-01T00:00:00Z",
                "daysToExpiry": 500,
                "status": "VALID",
            })

    def _load_supervisor_config(self, cluster_id: str, sup):
        for ns in sup.namespaces:
            self.supervisor_namespaces[ns.name] = {
                "namespace": ns.name,
                "cluster": cluster_id,
                "description": ns.description,
                "storage_limit_gb": ns.storage_limit_gb,
                "tenant_org": getattr(ns, "tenant_org", None),
                "config_status": "RUNNING",
                "kubernetes_status": "READY",
            }
        for sc in sup.vm_service_classes:
            self.supervisor_classes[sc.name] = {
                "name": sc.name,
                "cpu": sc.cpu,
                "memory_mb": sc.memory_mb,
                "vgpu_profile": sc.vgpu_profile,
            }

    def reload(self, config_path: Optional[str] = None):
        """Reload configuration from disk."""
        target_path = config_path or self.config_path
        if os.path.exists(target_path):
            with open(target_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            self.raw_config = data
            self.config = SingleInventoryConfig.model_validate(data)
            self._bootstrap_state()
            print(f"[✓] DigitalTwinState reloaded from {target_path}")

    def get_health_status(self) -> Dict[str, Any]:
        return {
            "status": "HEALTHY",
            "version": self.config.environment.vcf_version,
            "buildNumber": self.config.environment.build_number,
            "vcenterHealth": "GREEN",
            "nsxHealth": "GREEN",
            "storageHealth": "HEALTHY",
            "supervisorHealth": "HEALTHY",
            "activeAlerts": [],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
