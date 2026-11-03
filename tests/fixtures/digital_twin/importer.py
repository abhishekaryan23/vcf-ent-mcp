# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
VCF Single-Inventory Importer Pipeline (digital_twin/importer.py).
Transforms a real Broadcom VCF infrastructure export JSON into an active vcf_inventory.yaml Digital Twin.
Supports multi-tenant organizations, multiple workload domains, and complex topologies.
"""

from __future__ import annotations

import json
import os
import sys
import argparse
from typing import Dict, Any, List
import yaml
import httpx


def import_vcf_inventory(export_file_path: str, output_yaml_path: str = "digital_twin/vcf_inventory.yaml") -> Dict[str, Any]:
    print(f"[*] Reading real VCF infrastructure export: {export_file_path}")
    if not os.path.exists(export_file_path):
        print(f"[!] Error: File not found: {export_file_path}")
        raise FileNotFoundError(f"Export file not found: {export_file_path}")

    with open(export_file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Initialize single-inventory configuration schema
    config: Dict[str, Any] = {
        "environment": {
            "name": data.get("name", "Imported-Production-SDDC-Grid"),
            "vcf_version": data.get("vcfVersion", data.get("version", "9.1.0.0")),
            "build_number": str(data.get("buildNumber", "24892011")),
            "organization": data.get("organization", "Enterprise IT Cloud Services"),
            "simulated_latency_ms": 10,
            "enforce_strict_auth": True,
        },
        "sddc_manager": {
            "id": "sddc-mgr-prod",
            "fqdn": data.get("sddcManagerFqdn", "sddc-manager.corp.local"),
            "ip_address": data.get("sddcManagerIp", "192.168.10.2"),
            "credentials": {
                "admin_user": "administrator@vsphere.local",
                "admin_pass": "VMware1!MockPassword",
                "role": "VCF_SUPER_ADMIN",
            },
        },
        "licensing": data.get("licensing", [
            {
                "id": "lic-vcf-core",
                "product_name": "VMware Cloud Foundation 9 Core",
                "license_key": "VCF91-IMPORTED-KEY-XXXXX",
                "capacity": 512,
                "units": "CORES",
                "used": 256,
            }
        ]),
        "network_pools": data.get("networkPools", [
            {
                "id": "netpool-prod-01",
                "name": "Production-Infra-Network-Pool",
                "subnets": [
                    {
                        "network_type": "VSAN",
                        "cidr": "192.168.100.0/24",
                        "gateway": "192.168.100.1",
                        "vlan_id": 100,
                        "ip_pool": {"start": "192.168.100.10", "end": "192.168.100.100"},
                    },
                    {
                        "network_type": "GENEVE",
                        "cidr": "192.168.101.0/24",
                        "gateway": "192.168.101.1",
                        "vlan_id": 101,
                        "ip_pool": {"start": "192.168.101.10", "end": "192.168.101.100"},
                    },
                ],
            }
        ]),
        "tenant_organizations": data.get("tenantOrganizations", []),
        "management_domain": {},
        "workload_domains": [],
        "nsx_tier0s": data.get("nsxTier0s", data.get("nsx_tier0s", [
            {"id": "t0-production", "display_name": "Tier0-Production-Gateway", "ha_mode": "ACTIVE_ACTIVE", "bgp_asn": 65001}
        ])),
        "nsx_tier1s": data.get("nsxTier1s", data.get("nsx_tier1s", [
            {"id": "t1-production", "display_name": "Tier1-Production-Gateway", "tier0_path": "/infra/tier-0s/t0-production"}
        ])),
        "nsx_segments": data.get("nsxSegments", data.get("nsx_segments", [
            {"id": "seg-wld01-apps", "display_name": "Segment-Workload-Apps", "connectivity_path": "/infra/tier-1s/t1-production", "subnets": [{"gateway_address": "192.168.110.1/24"}]},
            {"id": "seg-wld01-ai", "display_name": "Segment-Workload-AI", "connectivity_path": "/infra/tier-1s/t1-production", "subnets": [{"gateway_address": "192.168.120.1/24"}]}
        ])),
        "nsx_groups": data.get("nsxGroups", data.get("nsx_groups", [])),
        "nsx_security_policies": data.get("nsxSecurityPolicies", data.get("nsx_security_policies", [])),
        "tenant_vms": data.get("tenantVms", data.get("tenant_vms", [])),
        "vr_profiles": data.get("vrProfiles", data.get("vr_profiles", [])),
        "vr_replications": data.get("vrReplications", data.get("vr_replications", [])),
        "protection_and_recovery": data.get("protectionAndRecovery", {
            "pairings": [
                {
                    "id": "pair-mgmt-wld01",
                    "pairing_name": "Protected-Mgmt-to-Recovery-WLD01",
                    "local_site": {"name": "Site-Production-Mgmt", "srm_host": "srm-mgmt.corp.local"},
                    "peer_site": {"name": "Site-Production-WLD01", "srm_host": "srm-wld01.corp.local"},
                    "status": "CONNECTED",
                    "network_mappings": [{"source_network": "seg-mgmt-infra", "target_network": "seg-wld01-apps"}],
                    "protection_groups": [
                        {
                            "id": "pg-tier1-core",
                            "name": "PG-Tier1-Core-Services",
                            "type": "VSPHERE_REPLICATION",
                            "rpo_minutes": 5,
                            "protected_vms": [
                                {"id": "vm-prod-crm-01", "name": "prod-crm-app01", "status": "PROTECTED", "consistency": "CONSISTENT"},
                                {"id": "vm-prod-db-01", "name": "prod-db-oracle01", "status": "PROTECTED", "consistency": "CONSISTENT"},
                            ],
                        }
                    ],
                    "recovery_plans": [
                        {
                            "id": "rp-tier1-failover",
                            "name": "RP-Tier1-Failover-Plan",
                            "protection_groups": ["pg-tier1-core"],
                            "status": "READY",
                            "last_test_result": "SUCCESSFUL",
                        }
                    ],
                }
            ],
            "network_mappings": [],
            "protection_groups": [],
            "recovery_plans": [],
        }),
    }

    # Extract Domains (Management vs VI Workload)
    domains_list = data.get("domains", data.get("elements", []))
    for domain in domains_list:
        dom_type = domain.get("type", "VI")
        dom_name = domain.get("name", "sddc-domain")
        dom_spec: Dict[str, Any] = {
            "id": domain.get("id", f"domain-{dom_name}"),
            "name": dom_name,
            "domain_type": dom_type,
            "tenant_organization": domain.get("tenantOrganization", domain.get("tenant_organization")),
            "vcenter": {
                "id": domain.get("vcenter", {}).get("id", f"vc-{dom_name}"),
                "fqdn": domain.get("vcenter", {}).get("fqdn", f"vcenter-{dom_name}.corp.local"),
                "ip_address": domain.get("vcenter", {}).get("ipAddress", domain.get("vcenter", {}).get("ip", "192.168.10.10")),
            },
            "nsx_manager": {
                "id": domain.get("nsxtCluster", {}).get("id", f"nsx-{dom_name}"),
                "vip_fqdn": domain.get("nsxtCluster", {}).get("vipFqdn", f"nsx-{dom_name}.corp.local"),
                "ip_address": domain.get("nsxtCluster", {}).get("vip", domain.get("nsxtCluster", {}).get("ip", "192.168.10.11")),
            },
            "srm_instance": {
                "id": f"srm-{dom_name}",
                "fqdn": f"srm-{dom_name}.corp.local",
                "site_name": f"Site-{dom_name}",
            },
            "clusters": [],
        }

        # Extract Compute Clusters & Hosts
        for cluster in domain.get("clusters", []):
            cl_name = cluster.get("name", "cl01")
            cl_spec: Dict[str, Any] = {
                "id": cluster.get("id", f"cluster-{cl_name}"),
                "name": cl_name,
                "primary_datastore_name": cluster.get("primaryDatastoreName", f"vsan-{cl_name}-ds01"),
                "vsphere_supervisor": cluster.get("vsphereSupervisor", {
                    "cluster_id": "domain-c8",
                    "config_status": "RUNNING",
                    "kubernetes_status": "READY",
                    "api_endpoint": "https://192.168.20.250:6443",
                    "kubernetes_version": "v1.30.2+vmware.1",
                    "master_nodes": ["192.168.20.251", "192.168.20.252"],
                    "vm_service_classes": [
                        {"name": "best-effort-small", "cpu": 2, "memory_mb": 4096},
                        {"name": "guaranteed-large", "cpu": 8, "memory_mb": 32768},
                        {"name": "ai-gpu-quad", "cpu": 32, "memory_mb": 131072, "vgpu_profile": "grid_a100-40c"},
                    ],
                    "namespaces": [
                        {"name": "tkg-system", "description": "Tanzu Core Infrastructure", "storage_limit_gb": 1000},
                        {"name": "prod-apps", "description": "Production Workloads", "storage_limit_gb": 5000},
                        {"name": "ai-models", "description": "Private AI Inference Services", "storage_limit_gb": 10000},
                    ],
                }),
                "hosts": [],
            }

            for host in cluster.get("hosts", []):
                mem_bytes = host.get("memoryBytes", 549755813888)
                mem_gb = host.get("memoryGb") or int(mem_bytes / (1024**3))
                cl_spec["hosts"].append({
                    "id": host.get("id", host.get("fqdn", "esx-01")),
                    "fqdn": host.get("fqdn", "esx-01.corp.local"),
                    "ip": host.get("ipAddress", host.get("ip", "192.168.10.101")),
                    "cores": host.get("cpuCores", host.get("cores", 64)),
                    "memory_gb": mem_gb,
                    "storage_tb": host.get("storageTb", host.get("storage_tb", 14)),
                    "status": "ASSIGNED",
                })

            dom_spec["clusters"].append(cl_spec)

        if dom_type == "MANAGEMENT":
            if dom_spec["clusters"]:
                dom_spec["cluster"] = dom_spec["clusters"][0]
            config["management_domain"] = dom_spec
        else:
            dom_spec["edge_cluster"] = domain.get("edgeCluster", {
                "id": f"edge-cl-{dom_name}",
                "name": f"{dom_name}-edge-cl01",
                "nodes": [
                    {"name": f"edge-node-{dom_name}-01", "mgmt_ip": "192.168.20.21", "tep_ip": "192.168.101.21"},
                    {"name": f"edge-node-{dom_name}-02", "mgmt_ip": "192.168.20.22", "tep_ip": "192.168.101.22"},
                ],
            })
            config["workload_domains"].append(dom_spec)

    # Ensure parent directories exist
    os.makedirs(os.path.dirname(os.path.abspath(output_yaml_path)), exist_ok=True)

    # Save to active inventory file
    with open(output_yaml_path, "w", encoding="utf-8") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)

    print(f"[✓] Active VCF inventory generated successfully: {output_yaml_path}")
    return config


def reload_running_mock_server(server_url: str = "http://localhost:8085") -> bool:
    """Trigger hot-reload on the running digital twin server."""
    try:
        resp = httpx.post(f"{server_url}/vcf/admin/config/reload", timeout=5.0)
        if resp.status_code == 200:
            print("[✓] Digital Twin Mock Server reloaded! Production digital twin is active.")
            return True
    except Exception:
        print(f"[i] Digital Twin Mock Server not currently running at {server_url}.")
    return False


def main():
    parser = argparse.ArgumentParser(description="VCF Single-Inventory Importer Pipeline")
    parser.add_argument("export_file", help="Path to raw VCF export JSON file (e.g. digital_twin/exports/sample_vcf_export.json)")
    parser.add_argument("--output", "-o", default="digital_twin/vcf_inventory.yaml", help="Path to output YAML configuration")
    parser.add_argument("--reload", "-r", action="store_true", help="Trigger hot-reload on running digital twin server")
    parser.add_argument("--server-url", default="http://localhost:8085", help="Digital Twin server URL for reload")
    args = parser.parse_args()

    import_vcf_inventory(args.export_file, args.output)
    if args.reload:
        reload_running_mock_server(args.server_url)


if __name__ == "__main__":
    main()
