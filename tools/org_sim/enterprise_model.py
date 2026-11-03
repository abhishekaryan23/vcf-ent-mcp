# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Northwind Group: a large, messy, simulated VCF 9.x enterprise for troubleshooting and
automation tests. Everything here is fictional.

Topology (one VCF instance, one SDDC Manager, fleet-level VCF Operations and VCF Automation):

| Workload domain | vCenter            | NSX Manager                    | Networking                                         |
| --------------- | ------------------ | ------------------------------ | -------------------------------------------------- |
| mgmt            | vc-mgmt01  9.1.1   | nsx-mgmt01  9.1.1 (dedicated)  | VDS VLAN port groups                               |
| wld-corp        | vc-corp01  9.1.1   | nsx-wld01   9.1.1 (SHARED)     | NSX overlay segments (T1 -> T0, BGP to Cisco Nexus), NSX VLAN segment, VPCs (centralized, via transit gateway) |
| wld-dev         | vc-dev01   9.1.1   | nsx-wld01   9.1.1 (SHARED)     | VPCs with distributed connectivity (no edge)       |
| wld-fin         | vc-fin01   9.0.2   | nsx-fin01   9.0.2 (dedicated)  | NSX overlay, zero-trust DFW, T0 BGP to Cisco Firepower |
| wld-eu          | vc-eu01    8.0.3   | nsx-eu01    4.2.1 (dedicated)  | Imported vSphere 8: VDS VLAN port groups only, NSX distributed security (DFW on VDS), gateway on a Cisco ASA |

Three Active Directory forests (identity, not VCF domains): corp.nwg.lab (corporate and dev),
fin.nwg.local (finance subsidiary) and eu.nwg-retail.net (acquired EU retailer).
Workloads: SQL Server standalone, failover cluster instances (FCI) and Always On availability
groups; Oracle standalone and Oracle Fail Safe clusters; Windows and RHEL web, app and proxy tiers.

`build_state(scenario)` returns the state with that scenario's faults applied.
"""

from __future__ import annotations

import copy
import datetime as dt
from typing import Any, Dict, List

from org_model import VCENTER_SERVICES

NOW = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
SUFFIX = "nwg.lab"


def iso(days: float = 0, hours: float = 0) -> str:
    return (NOW + dt.timedelta(days=days, hours=hours)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def ms(days: float = 0, hours: float = 0, minutes: float = 0) -> int:
    return int((NOW + dt.timedelta(days=days, hours=hours, minutes=minutes)).timestamp() * 1000)


# app key -> (fqdn, port). The key prefix picks the simulator personality (sddc, vc, nsx, ops, vcfa).
APPLIANCES = {
    "sddc": ("sddc01.nwg.lab", 9601), "vc-mgmt": ("vc-mgmt01.nwg.lab", 9611), "vc-corp": ("vc-corp01.nwg.lab", 9612),
    "vc-dev": ("vc-dev01.nwg.lab", 9613), "vc-fin": ("vc-fin01.nwg.lab", 9614), "vc-eu": ("vc-eu01.nwg.lab", 9615),
    "nsx-mgmt": ("nsx-mgmt01.nwg.lab", 9621), "nsx-wld": ("nsx-wld01.nwg.lab", 9622), "nsx-fin": ("nsx-fin01.nwg.lab", 9623),
    "nsx-eu": ("nsx-eu01.nwg.lab", 9624), "ops": ("vcf-ops01.nwg.lab", 9631), "vcfa": ("vcf-auto01.nwg.lab", 9641),
}
PORTS = {k: p for k, (_, p) in APPLIANCES.items()}
FQDN = {k: f for k, (f, _) in APPLIANCES.items()}

FORESTS = {"corp": "corp.nwg.lab", "fin": "fin.nwg.local", "eu": "eu.nwg-retail.net"}
OS = {"w22": "WINDOWS_SERVER_2021", "w19": "WINDOWS_9_SERVER_64", "rhel9": "RHEL_9_64", "rhel8": "RHEL_8_64", "photon": "VMWARE_PHOTON_64"}
OS_NAME = {"w22": "Microsoft Windows Server 2022 (64-bit)", "w19": "Microsoft Windows Server 2019 (64-bit)",
           "rhel9": "Red Hat Enterprise Linux 9 (64-bit)", "rhel8": "Red Hat Enterprise Linux 8 (64-bit)", "photon": "VMware Photon OS (64-bit)"}

# NSX service paths used in DFW rules -> human name
SERVICES = {"/infra/services/HTTPS": "HTTPS 443", "/infra/services/HTTP": "HTTP 80", "/infra/services/MS-SQL-S": "MS-SQL 1433",
            "/infra/services/Oracle": "Oracle 1521", "/infra/services/LDAP": "LDAP 389", "/infra/services/Kerberos": "Kerberos 88",
            "/infra/services/DNS": "DNS 53", "/infra/services/SMB": "SMB 445", "/infra/services/SSH": "SSH 22",
            "/infra/services/Squid-3128": "Proxy 3128", "/infra/services/SQL-AG-Endpoint-5022": "SQL AG endpoint 5022", "ANY": "any"}


# ---- vCenter + workloads ---------------------------------------------------------------------

def _vc(key, domain, version, clusters, vds, networks):
    """clusters: {name: host_count}; networks: list of (name, type, vlan|None, backing) where backing is
    VDS (VLAN port group), NSX (overlay or VLAN segment) or VPC (VPC subnet)."""
    fqdn = FQDN[key]
    short = key.split("-")[1]
    hosts, n = [], 0
    for cname, count in clusters.items():
        for _ in range(count):
            n += 1
            hosts.append({"host": f"host-{short}-{n:02d}", "name": f"esx{n:02d}-{short}.{SUFFIX}", "cluster": cname,
                          "connection_state": "CONNECTED", "power_state": "POWERED_ON"})
    nets = [{"network": f"dvportgroup-{short}-{i + 10}", "name": name, "type": "DISTRIBUTED_PORTGROUP", "vds": vds,
             "vlan": vlan, "backing": backing} for i, (name, _t, vlan, backing) in enumerate(networks)]
    ds = [{"datastore": f"datastore-{short}-{i + 1}", "name": f"vsan-{c}", "type": "VSAN", "capacity": 60 * 1024 ** 4,
           "free_space": int(60 * 1024 ** 4 * 0.38)} for i, c in enumerate(clusters)]
    return {
        "name": key, "fqdn": fqdn, "domain": domain, "version": version,
        "clusters": [{"cluster": f"domain-c{short}{i + 1}", "name": c, "ha_enabled": True, "drs_enabled": True} for i, c in enumerate(clusters)],
        "hosts": hosts, "vms": [], "datastores": ds, "networks": nets,
        "services": {k: {"name_key": f"cis.{k}.ServiceName", "description_key": v, "startup_type": "AUTOMATIC", "state": "STARTED",
                         "health": "HEALTHY", "health_messages": []} for k, v in VCENTER_SERVICES.items()},
        "health": {"system": "green", "storage": "green", "mem": "green", "load": "green", "database": "green"},
        "tls": {"subject_dn": f"CN={fqdn}", "issuer_dn": "CN=NWG Issuing CA 02, O=Northwind Group", "valid_from": iso(-200), "valid_to": iso(500)},
        "ntp": ["ntp1.nwg.lab", "ntp2.nwg.lab"],
        "identity_sources": [],
    }


def _place(vc, vms):
    """Round-robin VMs onto hosts of their cluster; nodes of the same clustered role go on different hosts."""
    by_cluster: Dict[str, List[dict]] = {}
    for h in vc["hosts"]:
        by_cluster.setdefault(h["cluster"], []).append(h)
    counters: Dict[str, int] = {}
    for spec in vms:
        name, os_key, app, tier, role, forest, nets, ip, cluster = spec[:9]
        extra = spec[9] if len(spec) > 9 else {}
        pool = by_cluster[cluster]
        i = counters.get(cluster, 0)
        counters[cluster] = i + 1
        host = pool[i % len(pool)]["host"]
        vm_id = f"vm-{vc['name'].split('-')[1]}-{len(vc['vms']) + 101}"
        nics = {}
        for k, net in enumerate(nets):
            nw = next(x for x in vc["networks"] if x["name"] == net)
            nics[str(4000 + k)] = {"label": f"Network adapter {k + 1}", "state": "CONNECTED", "start_connected": True,
                                   "mac_address": f"00:50:56:{len(vc['vms']) % 256:02x}:{k:02x}:{(hash(name) & 0xff):02x}",
                                   "backing": {"type": "DISTRIBUTED_PORTGROUP", "network": nw["network"]}}
        cpu, mem = extra.get("cpu", 4), extra.get("mem", 16384)
        vc["vms"].append({"vm": vm_id, "name": name, "power_state": "POWERED_ON", "cpu_count": cpu, "memory_size_mib": mem, "host": host,
                          "guest_OS": OS[os_key], "guest_full_name": OS_NAME[os_key], "ip": ip, "hostname": f"{name}.{FORESTS.get(forest, SUFFIX)}",
                          "nics": nics, "tools": "RUNNING", "disks": extra.get("disks", [80]),
                          "tags": {"Application": app, "Tier": tier, "Role": role, "AD-Forest": FORESTS.get(forest, "none"),
                                   **({"Cluster": extra["cluster_name"]} if "cluster_name" in extra else {})}})


def base_org() -> Dict[str, Any]:
    vcenters = {
        "vc-mgmt": _vc("vc-mgmt", "mgmt", "9.1.1.0", {"mgmt-cl01": 4}, "mgmt-vds01", [
            ("mgmt-vm-mgmt", "VDS", 1610, "VDS"), ("mgmt-esx-mgmt", "VDS", 1611, "VDS"), ("mgmt-vmotion", "VDS", 1612, "VDS"),
            ("mgmt-vsan", "VDS", 1613, "VDS"), ("mgmt-host-tep", "VDS", 1614, "VDS")]),
        "vc-corp": _vc("vc-corp", "wld-corp", "9.1.1.0", {"corp-cl01": 6, "corp-cl02": 4}, "corp-vds01", [
            ("corp-esx-mgmt", "VDS", 1711, "VDS"), ("corp-vmotion", "VDS", 1712, "VDS"), ("corp-vsan", "VDS", 1713, "VDS"),
            ("seg-corp-infra", "NSX", None, "NSX"), ("seg-corp-web", "NSX", None, "NSX"), ("seg-corp-app", "NSX", None, "NSX"),
            ("seg-corp-db", "NSX", None, "NSX"), ("seg-corp-dmz-proxy", "NSX", None, "NSX"), ("seg-corp-legacy-vlan120", "NSX", 120, "NSX"),
            ("vpc-ecom/ecom-public", "VPC", None, "VPC"), ("vpc-ecom/ecom-private-app", "VPC", None, "VPC")]),
        "vc-dev": _vc("vc-dev", "wld-dev", "9.1.1.0", {"dev-cl01": 4}, "dev-vds01", [
            ("dev-esx-mgmt", "VDS", 1811, "VDS"), ("vpc-dev-team-a/dev-a-private", "VPC", None, "VPC"),
            ("vpc-dev-team-b/dev-b-private", "VPC", None, "VPC"), ("vpc-dev-team-a/dev-a-public", "VPC", None, "VPC")]),
        "vc-fin": _vc("vc-fin", "wld-fin", "9.0.2.0", {"fin-cl01": 6}, "fin-vds01", [
            ("fin-esx-mgmt", "VDS", 1911, "VDS"), ("seg-fin-infra", "NSX", None, "NSX"), ("seg-fin-web", "NSX", None, "NSX"),
            ("seg-fin-app", "NSX", None, "NSX"), ("seg-fin-db", "NSX", None, "NSX"), ("seg-fin-sql-heartbeat", "NSX", None, "NSX")]),
        "vc-eu": _vc("vc-eu", "wld-eu", "8.0.3.00400", {"eu-cl01": 4}, "eu-vds01", [
            ("pg-eu-mgmt", "VDS", 200, "VDS"), ("pg-eu-dmz", "VDS", 205, "VDS"), ("pg-eu-web", "VDS", 210, "VDS"),
            ("pg-eu-app", "VDS", 220, "VDS"), ("pg-eu-db", "VDS", 230, "VDS"), ("pg-eu-quarantine", "VDS", 999, "VDS")]),
    }
    vcenters["vc-corp"]["identity_sources"] = ["corp.nwg.lab (AD over LDAPS)"]
    vcenters["vc-dev"]["identity_sources"] = ["corp.nwg.lab (AD over LDAPS)"]
    vcenters["vc-fin"]["identity_sources"] = ["fin.nwg.local (AD over LDAPS)"]
    vcenters["vc-eu"]["identity_sources"] = ["eu.nwg-retail.net (Integrated Windows Authentication)"]

    big = {"cpu": 8, "mem": 65536, "disks": [120, 500, 200, 100]}
    _place(vcenters["vc-mgmt"], [
        ("sddc01", "photon", "VCF-Infra", "mgmt", "sddc-manager", "none", ["mgmt-vm-mgmt"], "10.16.10.10", "mgmt-cl01"),
        ("vc-mgmt01", "photon", "VCF-Infra", "mgmt", "vcenter", "none", ["mgmt-vm-mgmt"], "10.16.10.11", "mgmt-cl01"),
        ("vc-corp01", "photon", "VCF-Infra", "mgmt", "vcenter", "none", ["mgmt-vm-mgmt"], "10.16.10.12", "mgmt-cl01"),
        ("vc-dev01", "photon", "VCF-Infra", "mgmt", "vcenter", "none", ["mgmt-vm-mgmt"], "10.16.10.13", "mgmt-cl01"),
        ("vc-fin01", "photon", "VCF-Infra", "mgmt", "vcenter", "none", ["mgmt-vm-mgmt"], "10.16.10.14", "mgmt-cl01"),
        ("nsx-mgmt01a", "photon", "VCF-Infra", "mgmt", "nsx-manager", "none", ["mgmt-vm-mgmt"], "10.16.10.21", "mgmt-cl01"),
        ("nsx-wld01a", "photon", "VCF-Infra", "mgmt", "nsx-manager", "none", ["mgmt-vm-mgmt"], "10.16.10.31", "mgmt-cl01"),
        ("nsx-wld01b", "photon", "VCF-Infra", "mgmt", "nsx-manager", "none", ["mgmt-vm-mgmt"], "10.16.10.32", "mgmt-cl01"),
        ("nsx-wld01c", "photon", "VCF-Infra", "mgmt", "nsx-manager", "none", ["mgmt-vm-mgmt"], "10.16.10.33", "mgmt-cl01"),
        ("nsx-fin01a", "photon", "VCF-Infra", "mgmt", "nsx-manager", "none", ["mgmt-vm-mgmt"], "10.16.10.41", "mgmt-cl01"),
        ("vcf-ops01", "photon", "VCF-Infra", "mgmt", "vcf-operations", "none", ["mgmt-vm-mgmt"], "10.16.10.51", "mgmt-cl01"),
        ("vcf-auto01", "photon", "VCF-Infra", "mgmt", "vcf-automation", "none", ["mgmt-vm-mgmt"], "10.16.10.61", "mgmt-cl01"),
        ("edge-shared-01", "photon", "VCF-Infra", "mgmt", "nsx-edge", "none", ["mgmt-vm-mgmt"], "10.16.10.71", "mgmt-cl01"),
        ("edge-shared-02", "photon", "VCF-Infra", "mgmt", "nsx-edge", "none", ["mgmt-vm-mgmt"], "10.16.10.72", "mgmt-cl01"),
    ])
    corp = [
        ("corp-dc01", "w22", "AD-CORP", "infra", "domain-controller", "corp", ["seg-corp-infra"], "10.20.2.11", "corp-cl01"),
        ("corp-dc02", "w22", "AD-CORP", "infra", "domain-controller", "corp", ["seg-corp-infra"], "10.20.2.12", "corp-cl02"),
    ]
    corp += [(f"corp-web0{i}", "rhel9", "CRM", "web", "nginx-web", "corp", ["seg-corp-web"], f"10.20.10.{10 + i}", "corp-cl01") for i in range(1, 5)]
    corp += [(f"corp-app0{i}", "w22", "CRM", "app", "iis-app", "corp", ["seg-corp-app"], f"10.20.20.{10 + i}", "corp-cl01") for i in range(1, 4)]
    corp += [(f"corp-sqlag0{i}", "w22", "CRM", "db", "sql-ag-replica", "corp", ["seg-corp-db"], f"10.20.30.{10 + i}", "corp-cl01",
              {**big, "cluster_name": "AG-CRM (listener crm-sql.corp.nwg.lab 10.20.30.50)"}) for i in range(1, 4)]
    corp += [
        ("corp-sql01", "w19", "Intranet", "db", "sql-standalone", "corp", ["seg-corp-db"], "10.20.30.21", "corp-cl02", big),
        ("corp-intra-web01", "rhel9", "Intranet", "web", "apache-web", "corp", ["seg-corp-web"], "10.20.10.31", "corp-cl02"),
        ("corp-intra-web02", "rhel9", "Intranet", "web", "apache-web", "corp", ["seg-corp-web"], "10.20.10.32", "corp-cl02"),
        ("corp-ora01", "rhel8", "SupplyChain", "db", "oracle-standalone", "corp", ["seg-corp-legacy-vlan120"], "10.120.0.21", "corp-cl02", big),
        ("corp-scm-app01", "rhel8", "SupplyChain", "app", "tomcat-app", "corp", ["seg-corp-app"], "10.20.20.41", "corp-cl02"),
        ("corp-scm-app02", "rhel8", "SupplyChain", "app", "tomcat-app", "corp", ["seg-corp-app"], "10.20.20.42", "corp-cl02"),
        ("corp-proxy01", "rhel9", "WebProxy", "proxy", "squid-proxy", "corp", ["seg-corp-dmz-proxy"], "10.20.5.11", "corp-cl01"),
        ("corp-proxy02", "rhel9", "WebProxy", "proxy", "squid-proxy", "corp", ["seg-corp-dmz-proxy"], "10.20.5.12", "corp-cl02"),
    ]
    corp += [(f"ecom-web0{i}", "rhel9", "eCommerce", "web", "nginx-web", "corp", ["vpc-ecom/ecom-public"], f"10.80.1.{10 + i}", "corp-cl02") for i in range(1, 4)]
    corp += [(f"ecom-app0{i}", "rhel9", "eCommerce", "app", "java-app", "corp", ["vpc-ecom/ecom-private-app"], f"10.80.2.{10 + i}", "corp-cl02") for i in range(1, 5)]
    _place(vcenters["vc-corp"], corp)
    _place(vcenters["vc-dev"], [
        ("dev-gitlab01", "rhel9", "DevTools", "app", "gitlab", "corp", ["vpc-dev-team-a/dev-a-private"], "10.90.1.11", "dev-cl01"),
        ("dev-build01", "rhel9", "DevTools", "app", "build-agent", "corp", ["vpc-dev-team-a/dev-a-private"], "10.90.1.12", "dev-cl01"),
        ("dev-build02", "rhel9", "DevTools", "app", "build-agent", "corp", ["vpc-dev-team-a/dev-a-private"], "10.90.1.13", "dev-cl01"),
        ("dev-sql01", "w22", "DevTools", "db", "sql-standalone", "corp", ["vpc-dev-team-b/dev-b-private"], "10.91.1.21", "dev-cl01"),
        ("dev-web01", "rhel9", "DevTools", "web", "nginx-web", "corp", ["vpc-dev-team-a/dev-a-public"], "10.90.9.11", "dev-cl01"),
    ])
    fin = [
        ("fin-dc01", "w22", "AD-FIN", "infra", "domain-controller", "fin", ["seg-fin-infra"], "10.30.2.11", "fin-cl01"),
        ("fin-dc02", "w22", "AD-FIN", "infra", "domain-controller", "fin", ["seg-fin-infra"], "10.30.2.12", "fin-cl01"),
        ("fin-sqlfci-n1", "w22", "Ledger", "db", "sql-fci-node", "fin", ["seg-fin-db", "seg-fin-sql-heartbeat"], "10.30.30.11", "fin-cl01",
         {**big, "cluster_name": "FCI-LEDGER (SQL network name ledger-sql.fin.nwg.local 10.30.30.50, shared clustered VMDKs)"}),
        ("fin-sqlfci-n2", "w22", "Ledger", "db", "sql-fci-node", "fin", ["seg-fin-db", "seg-fin-sql-heartbeat"], "10.30.30.12", "fin-cl01",
         {**big, "cluster_name": "FCI-LEDGER (SQL network name ledger-sql.fin.nwg.local 10.30.30.50, shared clustered VMDKs)"}),
        ("fin-app01", "w22", "Ledger", "app", "iis-app", "fin", ["seg-fin-app"], "10.30.20.11", "fin-cl01"),
        ("fin-app02", "w22", "Ledger", "app", "iis-app", "fin", ["seg-fin-app"], "10.30.20.12", "fin-cl01"),
    ]
    fin += [(f"fin-sqlag0{i}", "w22", "Payments", "db", "sql-ag-replica", "fin", ["seg-fin-db"], f"10.30.30.{20 + i}", "fin-cl01",
             {**big, "cluster_name": "AG-PAYMENTS (listener pay-sql.fin.nwg.local 10.30.30.60)"}) for i in range(1, 4)]
    fin += [
        ("fin-pay-app01", "w22", "Payments", "app", "iis-app", "fin", ["seg-fin-app"], "10.30.20.21", "fin-cl01"),
        ("fin-pay-web01", "rhel9", "Payments", "web", "nginx-web", "fin", ["seg-fin-web"], "10.30.10.21", "fin-cl01"),
        ("fin-pay-web02", "rhel9", "Payments", "web", "nginx-web", "fin", ["seg-fin-web"], "10.30.10.22", "fin-cl01"),
        ("fin-orafs-n1", "w19", "Treasury", "db", "oracle-failsafe-node", "fin", ["seg-fin-db", "seg-fin-sql-heartbeat"], "10.30.30.31", "fin-cl01",
         {**big, "cluster_name": "ORAFS-TREASURY (Oracle Fail Safe group treasury-ora.fin.nwg.local)"}),
        ("fin-orafs-n2", "w19", "Treasury", "db", "oracle-failsafe-node", "fin", ["seg-fin-db", "seg-fin-sql-heartbeat"], "10.30.30.32", "fin-cl01",
         {**big, "cluster_name": "ORAFS-TREASURY (Oracle Fail Safe group treasury-ora.fin.nwg.local)"}),
        ("fin-ora01", "rhel8", "Reporting", "db", "oracle-standalone", "fin", ["seg-fin-db"], "10.30.30.41", "fin-cl01", big),
        ("fin-proxy01", "rhel9", "WebProxy", "proxy", "squid-proxy", "fin", ["seg-fin-web"], "10.30.10.5", "fin-cl01"),
    ]
    _place(vcenters["vc-fin"], fin)
    _place(vcenters["vc-eu"], [
        ("eu-dc01", "w19", "AD-EU", "infra", "domain-controller", "eu", ["pg-eu-mgmt"], "10.40.0.11", "eu-cl01"),
        ("eu-dc02", "w19", "AD-EU", "infra", "domain-controller", "eu", ["pg-eu-mgmt"], "10.40.0.12", "eu-cl01"),
        ("eu-web01", "rhel8", "RetailShop", "web", "apache-web", "eu", ["pg-eu-web"], "10.40.10.11", "eu-cl01"),
        ("eu-web02", "rhel8", "RetailShop", "web", "apache-web", "eu", ["pg-eu-web"], "10.40.10.12", "eu-cl01"),
        ("eu-web03", "rhel8", "RetailShop", "web", "apache-web", "eu", ["pg-eu-web"], "10.40.10.13", "eu-cl01"),
        ("eu-app01", "w19", "RetailShop", "app", "iis-app", "eu", ["pg-eu-app"], "10.40.20.11", "eu-cl01"),
        ("eu-app02", "w19", "RetailShop", "app", "iis-app", "eu", ["pg-eu-app"], "10.40.20.12", "eu-cl01"),
        ("eu-sql01", "w19", "RetailShop", "db", "sql-standalone", "eu", ["pg-eu-db"], "10.40.30.11", "eu-cl01", big),
        ("eu-ora01", "rhel8", "RetailERP", "db", "oracle-standalone", "eu", ["pg-eu-db"], "10.40.30.21", "eu-cl01", big),
        ("eu-proxy01", "rhel8", "WebProxy", "proxy", "squid-proxy", "eu", ["pg-eu-dmz"], "10.40.5.11", "eu-cl01"),
    ])

    nsx = {
        "nsx-mgmt": _nsx("nsx-mgmt", ["mgmt"], "9.1.1.0", tier0s=[], segments=[], policies=[], projects=[]),
        "nsx-wld": _nsx("nsx-wld", ["wld-corp", "wld-dev"], "9.1.1.0",
                        tier0s=[_t0("t0-shared", 65001, [("10.50.0.1", 65100, "nx-core-a (Cisco Nexus 9336C-FX2, core switch A)"),
                                                          ("10.50.0.2", 65100, "nx-core-b (Cisco Nexus 9336C-FX2, core switch B)")], "ec-shared")],
                        tier1s=[("t1-corp", "t0-shared"), ("t1-corp-dmz", "t0-shared")],
                        segments=[("seg-corp-infra", "t1-corp", "10.20.2.1/24"), ("seg-corp-web", "t1-corp", "10.20.10.1/24"),
                                  ("seg-corp-app", "t1-corp", "10.20.20.1/24"), ("seg-corp-db", "t1-corp", "10.20.30.1/24"),
                                  ("seg-corp-dmz-proxy", "t1-corp-dmz", "10.20.5.1/24"), ("seg-corp-legacy-vlan120", None, None, 120)],
                        policies=_corp_policies(), projects=_projects()),
        "nsx-fin": _nsx("nsx-fin", ["wld-fin"], "9.0.2.0",
                        tier0s=[_t0("t0-fin", 65010, [("10.60.0.1", 65200, "fw-fin-a (Cisco Secure Firewall 4125 / FTD, managed by FMC fmc01)"),
                                                       ("10.60.0.2", 65200, "fw-fin-b (Cisco Secure Firewall 4125 / FTD, HA peer)")], "ec-fin")],
                        tier1s=[("t1-fin", "t0-fin")],
                        segments=[("seg-fin-infra", "t1-fin", "10.30.2.1/24"), ("seg-fin-web", "t1-fin", "10.30.10.1/24"),
                                  ("seg-fin-app", "t1-fin", "10.30.20.1/24"), ("seg-fin-db", "t1-fin", "10.30.30.1/24"),
                                  ("seg-fin-sql-heartbeat", None, None)],
                        policies=_fin_policies(), projects=[]),
        "nsx-eu": _nsx("nsx-eu", ["wld-eu"], "4.2.1.0", tier0s=[], segments=[], policies=_eu_policies(), projects=[],
                       note="Distributed security only: DFW enforced on VDS port groups; routing on Cisco ASA 5555-X asa-eu-01."),
    }
    domains = [
        {"id": "d-mgmt", "name": "mgmt", "type": "MANAGEMENT", "status": "ACTIVE", "vcenter": "vc-mgmt", "nsx": "nsx-mgmt"},
        {"id": "d-corp", "name": "wld-corp", "type": "VI", "status": "ACTIVE", "vcenter": "vc-corp", "nsx": "nsx-wld"},
        {"id": "d-dev", "name": "wld-dev", "type": "VI", "status": "ACTIVE", "vcenter": "vc-dev", "nsx": "nsx-wld"},
        {"id": "d-fin", "name": "wld-fin", "type": "VI", "status": "ACTIVE", "vcenter": "vc-fin", "nsx": "nsx-fin"},
        {"id": "d-eu", "name": "wld-eu", "type": "VI", "status": "ACTIVE", "vcenter": "vc-eu", "nsx": "nsx-eu", "imported": True},
    ]
    tasks = [
        {"id": "t-101", "name": "Upgrade NSX for wld-corp, wld-dev to 9.1.1", "status": "SUCCESSFUL", "creationTimestamp": iso(-20), "errors": []},
        {"id": "t-102", "name": "Import vCenter vc-eu01.nwg.lab as workload domain wld-eu", "status": "SUCCESSFUL", "creationTimestamp": iso(-60), "errors": []},
        {"id": "t-103", "name": "Rotate passwords for wld-fin", "status": "SUCCESSFUL", "creationTimestamp": iso(-6), "errors": []},
        {"id": "t-104", "name": "Add hosts to cluster corp-cl02", "status": "SUCCESSFUL", "creationTimestamp": iso(-3), "errors": []},
    ]
    certs = []
    for d in domains:
        vc = vcenters[d["vcenter"]]
        certs.append({"domain": d["name"], "resourceName": vc["fqdn"], "issuedTo": vc["fqdn"], "numberOfDaysToExpire": 500, "issuedBy": "NWG Issuing CA 02", "expirationStatus": "ACTIVE",
                      "notAfter": vc["tls"]["valid_to"], "resourceType": "VCENTER"})
        n = nsx[d["nsx"]]
        if not any(c["issuedTo"] == n["fqdn"] and c["domain"] == d["name"] for c in certs):
            certs.append({"domain": d["name"], "resourceName": n["fqdn"], "issuedTo": n["fqdn"], "numberOfDaysToExpire": 450, "issuedBy": "NWG Issuing CA 02", "expirationStatus": "ACTIVE",
                          "notAfter": n["cert"]["not_after"], "resourceType": "NSXT_MANAGER"})
    ops = {"node_status": "ONLINE",
           "collectors": [{"name": "cp-hq-01", "state": "UP"}, {"name": "cp-fin-01", "state": "UP"}, {"name": "cp-eu-01", "state": "UP"}],
           "alerts": [
               {"alertId": "op-1", "alertLevel": "WARNING", "status": "ACTIVE", "alertDefinitionName": "Virtual machine has memory contention",
                "resourceName": "corp-build-tmp", "startTimeUTC": ms(days=-3)},
               {"alertId": "op-2", "alertLevel": "IMMEDIATE", "status": "ACTIVE", "alertDefinitionName": "Guest file system is running out of space",
                "resourceName": "corp-intra-web02", "startTimeUTC": ms(days=-9)},
               {"alertId": "op-3", "alertLevel": "WARNING", "status": "ACTIVE", "alertDefinitionName": "VMware Tools is outdated",
                "resourceName": "eu-app02", "startTimeUTC": ms(days=-40)},
           ]}
    return {"vcf_version": "9.1.1.0", "vcenters": vcenters, "nsx": nsx, "domains": domains, "tasks": tasks, "certificates": certs,
            "credentials": [], "ops": ops, "sddc": {"ntp": ["10.1.1.10", "10.1.1.11"], "dns": ["10.1.1.20", "10.1.1.21"]},
            "automation": _automation(), "forests": FORESTS}


# ---- NSX -------------------------------------------------------------------------------------

def _nsx(key, domains, version, tier0s, segments, policies, projects, tier1s=(), note=""):
    segs = []
    for spec in segments:
        name, t1, gw = spec[:3]
        vlan = spec[3] if len(spec) > 3 else None
        segs.append({"id": name, "display_name": name, "path": f"/infra/segments/{name}",
                     "connectivity_path": f"/infra/tier-1s/{t1}" if t1 else None,
                     "subnets": [{"gateway_address": gw}] if gw else [], "vlan_ids": [str(vlan)] if vlan else None,
                     "transport_zone_path": "/infra/sites/default/enforcement-points/default/transport-zones/" + ("vlan-tz" if vlan else "overlay-tz"),
                     "type": "ROUTED" if t1 else ("EXTENDED" if vlan else "DISCONNECTED"),
                     "_last_modified_time": ms(days=-120), "_last_modified_user": "admin"})
    return {"fqdn": FQDN[key], "domains": domains, "version": version, "nodes": [f"{key}-01", f"{key}-02", f"{key}-03"],
            "offline": [], "control": "STABLE", "alarms": [], "cert": {"display_name": f"{key}-vip", "not_after": iso(450)},
            "tier0s": tier0s, "tier1s": [{"id": a, "display_name": a, "path": f"/infra/tier-1s/{a}", "tier0_path": f"/infra/tier-0s/{b}",
                                          "_last_modified_time": ms(days=-90), "_last_modified_user": "admin"} for a, b in tier1s],
            "segments": segs, "policies": policies, "projects": projects, "note": note}


def _t0(name, local_as, peers, edge_cluster):
    return {"id": name, "display_name": name, "ha_mode": "ACTIVE_ACTIVE", "edge_cluster": edge_cluster, "local_as_num": str(local_as),
            "neighbors": [{"neighbor_address": a, "remote_as_num": str(r), "description": d, "connection_state": "ESTABLISHED",
                           "time_since_established": 86400 * 37, "source_address": f"{a.rsplit('.', 1)[0]}.{10 + i}"}
                          for i, (a, r, d) in enumerate(peers)]}


def _rule(rid, name, src, dst, services, action, seq, days_ago=60, user="netadmin@corp.nwg.lab", disabled=False):
    return {"id": rid, "display_name": name, "source_groups": src, "destination_groups": dst, "services": services, "action": action,
            "sequence_number": seq, "disabled": disabled, "logged": True, "scope": ["ANY"],
            "_create_time": ms(days=-days_ago), "_last_modified_time": ms(days=-days_ago), "_last_modified_user": user}


def _g(name):
    return f"/infra/domains/default/groups/{name}"


def _policy(pid, name, category, seq, rules):
    return {"id": pid, "display_name": name, "category": category, "sequence_number": seq, "rules": rules,
            "_last_modified_time": max(r["_last_modified_time"] for r in rules), "_last_modified_user": rules[-1]["_last_modified_user"]}


def _corp_policies():
    return [
        _policy("infra-core", "Infrastructure services", "Infrastructure", 10, [
            _rule("r-ad", "allow-ad-from-all", ["ANY"], [_g("grp-ad-corp")], ["/infra/services/LDAP", "/infra/services/Kerberos", "/infra/services/DNS", "/infra/services/SMB"], "ALLOW", 10),
        ]),
        _policy("crm", "CRM application", "Application", 100, [
            _rule("r-crm-1", "crm-web-to-app", [_g("grp-crm-web")], [_g("grp-crm-app")], ["/infra/services/HTTPS"], "ALLOW", 10),
            _rule("r-crm-2", "crm-app-to-db", [_g("grp-crm-app")], [_g("grp-crm-db")], ["/infra/services/MS-SQL-S"], "ALLOW", 20),
            _rule("r-crm-3", "crm-ag-replication", [_g("grp-crm-db")], [_g("grp-crm-db")], ["/infra/services/SQL-AG-Endpoint-5022"], "ALLOW", 30),
        ]),
        _policy("scm", "SupplyChain application", "Application", 110, [
            _rule("r-scm-1", "scm-app-to-oracle", [_g("grp-scm-app")], [_g("grp-scm-db")], ["/infra/services/Oracle"], "ALLOW", 10),
        ]),
        _policy("ecom", "eCommerce application", "Application", 120, [
            _rule("r-ecom-1", "ecom-web-to-app", [_g("grp-ecom-web")], [_g("grp-ecom-app")], ["/infra/services/HTTPS"], "ALLOW", 10),
        ]),
        _policy("proxy", "Outbound proxy", "Application", 130, [
            _rule("r-px-1", "clients-to-proxy", ["ANY"], [_g("grp-proxy")], ["/infra/services/Squid-3128"], "ALLOW", 10),
        ]),
        _policy("env", "Dev must not reach prod", "Environment", 50, [
            _rule("r-env-1", "dev-to-prod-block", [_g("grp-dev-all")], [_g("grp-corp-prod")], ["ANY"], "DROP", 10),
        ]),
        _policy("default-layer3-section", "Default Layer3 Section", "Application", 999999, [
            _rule("default-layer3-rule", "Default Layer3 Rule", ["ANY"], ["ANY"], ["ANY"], "ALLOW", 2147483647, days_ago=300, user="admin"),
        ]),
    ]


def _fin_policies():
    return [
        _policy("fin-infra", "Finance infrastructure", "Infrastructure", 10, [
            _rule("r-fad", "allow-ad-fin", ["ANY"], [_g("grp-ad-fin")], ["/infra/services/LDAP", "/infra/services/Kerberos", "/infra/services/DNS"], "ALLOW", 10, user="secops@fin.nwg.local"),
        ]),
        _policy("fin-ledger", "Ledger (PCI)", "Application", 100, [
            _rule("r-led-1", "ledger-app-to-sql", [_g("grp-ledger-app")], [_g("grp-ledger-db")], ["/infra/services/MS-SQL-S"], "ALLOW", 10, user="secops@fin.nwg.local"),
        ]),
        _policy("fin-payments", "Payments (PCI)", "Application", 110, [
            _rule("r-pay-1", "pay-web-to-app", [_g("grp-payments-web")], [_g("grp-payments-app")], ["/infra/services/HTTPS"], "ALLOW", 10, user="secops@fin.nwg.local"),
            _rule("r-pay-2", "pay-app-to-sql", [_g("grp-payments-app")], [_g("grp-payments-db")], ["/infra/services/MS-SQL-S"], "ALLOW", 20, user="secops@fin.nwg.local"),
        ]),
        _policy("fin-treasury", "Treasury Oracle", "Application", 120, [
            _rule("r-tre-1", "treasury-clients-to-oracle", [_g("grp-ad-fin")], [_g("grp-treasury-db")], ["/infra/services/Oracle"], "ALLOW", 10, user="secops@fin.nwg.local"),
        ]),
        _policy("default-layer3-section", "Default Layer3 Section", "Application", 999999, [
            _rule("default-layer3-rule", "Default Layer3 Rule (zero trust)", ["ANY"], ["ANY"], ["ANY"], "DROP", 2147483647, days_ago=400, user="admin"),
        ]),
    ]


def _eu_policies():
    return [
        _policy("eu-retail", "RetailShop", "Application", 100, [
            _rule("r-eu-1", "web-to-app", [_g("grp-retailshop-web")], [_g("grp-retailshop-app")], ["/infra/services/HTTPS"], "ALLOW", 10, user="admin"),
        ]),
        _policy("default-layer3-section", "Default Layer3 Section", "Application", 999999, [
            _rule("default-layer3-rule", "Default Layer3 Rule", ["ANY"], ["ANY"], ["ANY"], "ALLOW", 2147483647, days_ago=500, user="admin"),
        ]),
    ]


# group id -> (Application tag, Tier tag or None); membership is computed from VM tags.
GROUPS = {
    "grp-ad-corp": ("AD-CORP", None), "grp-crm-web": ("CRM", "web"), "grp-crm-app": ("CRM", "app"), "grp-crm-db": ("CRM", "db"),
    "grp-scm-app": ("SupplyChain", "app"), "grp-scm-db": ("SupplyChain", "db"), "grp-ecom-web": ("eCommerce", "web"),
    "grp-ecom-app": ("eCommerce", "app"), "grp-proxy": ("WebProxy", None), "grp-dev-all": ("DevTools", None), "grp-corp-prod": ("CRM", None),
    "grp-ad-fin": ("AD-FIN", None), "grp-ledger-app": ("Ledger", "app"), "grp-ledger-db": ("Ledger", "db"),
    "grp-payments-web": ("Payments", "web"), "grp-payments-app": ("Payments", "app"), "grp-payments-db": ("Payments", "db"),
    "grp-treasury-db": ("Treasury", "db"), "grp-retailshop-web": ("RetailShop", "web"), "grp-retailshop-app": ("RetailShop", "app"),
}


def _subnet(sid, mode, cidr, total, allocated):
    return {"id": sid, "display_name": sid, "access_mode": mode, "ip_addresses": [cidr],
            "pool": {"id": f"{sid}-pool", "total_ids": total, "allocated_ids": allocated}}


def _projects():
    return [
        {"id": "digital", "display_name": "Digital (eCommerce)", "tgw": "tgw-digital", "tgw_connectivity": "CENTRALIZED via t0-shared / edge cluster ec-shared",
         "vpcs": [{"id": "vpc-ecom", "display_name": "vpc-ecom", "connectivity_profile": "centralized-default",
                   "subnets": [_subnet("ecom-public", "Public", "10.80.1.0/26", 61, 14), _subnet("ecom-private-app", "Private", "10.80.2.0/26", 61, 38)]}]},
        {"id": "dev-sandbox", "display_name": "Developer sandbox", "tgw": "tgw-dev", "tgw_connectivity": "DISTRIBUTED (no edge; external via VLAN 1850 on the Cisco Nexus)",
         "vpcs": [{"id": "vpc-dev-team-a", "display_name": "vpc-dev-team-a", "connectivity_profile": "distributed-default",
                   "subnets": [_subnet("dev-a-private", "Private", "10.90.1.0/24", 253, 201), _subnet("dev-a-public", "Public", "10.90.9.0/27", 29, 9)]},
                  {"id": "vpc-dev-team-b", "display_name": "vpc-dev-team-b", "connectivity_profile": "distributed-default",
                   "subnets": [_subnet("dev-b-private", "Private", "10.91.1.0/24", 253, 40)]}]},
    ]


# ---- VCF Automation (VM Apps organization "northwind") ---------------------------------------

def _automation():
    return {
        "tenant": "northwind",
        "projects": [{"id": "proj-fin", "name": "Finance"}, {"id": "proj-digital", "name": "Digital"}, {"id": "proj-eu", "name": "EU-Retail"},
                     {"id": "proj-dev", "name": "Developers"}],
        "images": [{"name": "win2022-sql2022", "osFamily": "WINDOWS", "description": "Windows Server 2022 + SQL Server 2022 Enterprise (sysprepped)"},
                   {"name": "win2022-std", "osFamily": "WINDOWS", "description": "Windows Server 2022 Standard"},
                   {"name": "rhel9-base", "osFamily": "LINUX", "description": "RHEL 9.4 hardened (CIS L1)"},
                   {"name": "rhel8-oracle19c", "osFamily": "LINUX", "description": "RHEL 8.10 with Oracle 19c prerequisites"}],
        "flavors": [{"name": "small", "cpuCount": 2, "memoryInMB": 4096}, {"name": "medium", "cpuCount": 4, "memoryInMB": 16384},
                    {"name": "large", "cpuCount": 8, "memoryInMB": 32768}, {"name": "sql-large", "cpuCount": 8, "memoryInMB": 65536}],
        # Assembler matches Cloud.*.Network constraints (tag:value) against these.
        "networks": [{"name": "seg-fin-db", "cidr": "10.30.30.0/24", "tags": ["net:fin-db", "env:prod", "pci:true"]},
                     {"name": "seg-fin-app", "cidr": "10.30.20.0/24", "tags": ["net:fin-app", "env:prod", "pci:true"]},
                     {"name": "seg-fin-web", "cidr": "10.30.10.0/24", "tags": ["net:fin-web", "env:prod", "pci:true"]},
                     {"name": "vpc-ecom/ecom-public", "cidr": "10.80.1.0/26", "tags": ["net:ecom-public", "env:prod"]},
                     {"name": "vpc-ecom/ecom-private-app", "cidr": "10.80.2.0/26", "tags": ["net:ecom-app", "env:prod"]},
                     {"name": "pg-eu-web", "cidr": "10.40.10.0/24", "tags": ["net:eu-web", "env:prod"]},
                     {"name": "vpc-dev-team-a/dev-a-private", "cidr": "10.90.1.0/24", "tags": ["net:dev", "env:dev"]}],
        "blueprints": [
            {"id": "bp-rhel-web", "name": "RHEL web server", "projectId": "proj-digital", "status": "RELEASED", "createdBy": "automation@corp.nwg.lab",
             "content": "formatVersion: 1\ninputs:\n  count:\n    type: integer\n    default: 2\nresources:\n  web:\n    type: Cloud.vSphere.Machine\n"
                        "    properties:\n      image: rhel9-base\n      flavor: medium\n      count: ${input.count}\n      networks:\n        - network: ${resource.net.id}\n"
                        "  net:\n    type: Cloud.vSphere.Network\n    properties:\n      networkType: existing\n      constraints:\n        - tag: net:ecom-public\n"},
            {"id": "bp-win-std", "name": "Windows member server", "projectId": "proj-fin", "status": "DRAFT", "createdBy": "automation@corp.nwg.lab",
             "content": "formatVersion: 1\nresources:\n  vm:\n    type: Cloud.vSphere.Machine\n    properties:\n      image: win2022-std\n      flavor: medium\n"},
        ],
        "deployments": [
            {"id": "dep-301", "name": "ecom-scaleout-0412", "projectId": "proj-digital", "blueprintId": "bp-rhel-web", "status": "CREATE_SUCCESSFUL",
             "createdAt": iso(-5), "lastRequest": {"status": "SUCCESSFUL", "details": ""}},
        ],
        "workflows": [
            {"id": "wf-expand-disk", "name": "Expand VM disk", "categoryName": "Northwind/Storage",
             "description": "Grow a VM's virtual disk and extend the guest file system (Windows: diskpart; RHEL: growpart + xfs_growfs).",
             "inputs": [{"name": "vmName", "type": "string", "required": True}, {"name": "diskNumber", "type": "number", "required": True},
                        {"name": "addGB", "type": "number", "required": True}],
             "outputs": [{"name": "newSizeGB", "type": "number"}]},
            {"id": "wf-ad-computer", "name": "Create AD computer object", "categoryName": "Northwind/Active Directory",
             "description": "Pre-stage a computer account in the given AD forest/OU (Active Directory plug-in).",
             "inputs": [{"name": "computerName", "type": "string", "required": True}, {"name": "forest", "type": "string", "required": True},
                        {"name": "ouPath", "type": "string", "required": True}],
             "outputs": [{"name": "distinguishedName", "type": "string"}]},
            {"id": "wf-sql-ag-failover", "name": "SQL AG planned failover", "categoryName": "Northwind/SQL",
             "description": "Planned manual failover of an Always On availability group to a synchronized secondary (PowerShell host).",
             "inputs": [{"name": "agName", "type": "string", "required": True}, {"name": "targetReplica", "type": "string", "required": True}],
             "outputs": [{"name": "newPrimary", "type": "string"}]},
            {"id": "wf-nsx-tag", "name": "Apply NSX security tag to VM", "categoryName": "Northwind/Network",
             "description": "Adds a VM to DFW groups by setting NSX tags.",
             "inputs": [{"name": "vmName", "type": "string", "required": True}, {"name": "tag", "type": "string", "required": True}],
             "outputs": [{"name": "groups", "type": "Array/string"}]},
        ],
        # Forests the Active Directory plug-in has a configured connection for.
        "ad_plugin_forests": ["corp.nwg.lab", "fin.nwg.local"],
        "executions": {},
    }


# ---- scenarios -------------------------------------------------------------------------------

def _vm(s, name):
    for vc in s["vcenters"].values():
        for v in vc["vms"]:
            if v["name"] == name:
                return vc, v
    raise KeyError(name)


def f_noise(s):
    s["nsx"]["nsx-wld"]["alarms"].append({"id": "al-w1", "feature_name": "edge_health", "event_type": "edge_cpu_usage_high", "severity": "MEDIUM",
                                          "status": "OPEN", "node_display_name": "edge-shared-02",
                                          "description": "Edge node CPU usage has reached 81%, which is above the high threshold value of 80%.",
                                          "recommended_action": "Review the edge node's workload."})
    s["nsx"]["nsx-fin"]["alarms"].append({"id": "al-f1", "feature_name": "certificates", "event_type": "certificate_expiration_approaching",
                                          "severity": "MEDIUM", "status": "OPEN", "node_display_name": "nsx-fin01",
                                          "description": "Certificate for the NSX Manager node API expires in 58 days.",
                                          "recommended_action": "Plan the certificate replacement."})
    h = s["vcenters"]["vc-corp"]["hosts"][9]
    h["connection_state"], h["maintenance_note"] = "CONNECTED", "in maintenance mode (planned firmware update)"
    s["tasks"].append({"id": "t-190", "name": "Download bundle VCF 9.1.1.1 patch", "status": "FAILED", "creationTimestamp": iso(-12),
                       "errors": [{"errorCode": "BUNDLE_DOWNLOAD_RETRY", "message": "Transient proxy timeout; a later retry succeeded."}],
                       "resolutionStatus": "RESOLVED"})


def f_dfw_blocks_crm_sql(s):
    pol = next(p for p in s["nsx"]["nsx-wld"]["policies"] if p["id"] == "crm")
    pol["rules"].insert(0, _rule("r-crm-tmp", "temp-block-sql-scan", ["ANY"], [_g("grp-crm-db")], ["/infra/services/MS-SQL-S"], "DROP", 5,
                                 days_ago=0, user="m.lee@corp.nwg.lab"))
    pol["rules"][0]["_last_modified_time"] = ms(minutes=-35)
    pol["rules"][0]["_create_time"] = ms(minutes=-35)
    pol["_last_modified_time"], pol["_last_modified_user"] = ms(minutes=-35), "m.lee@corp.nwg.lab"


def f_bgp_down_fin(s):
    t0 = s["nsx"]["nsx-fin"]["tier0s"][0]
    for nb in t0["neighbors"]:
        nb["connection_state"], nb["time_since_established"] = "ACTIVE", 0
    s["nsx"]["nsx-fin"]["alarms"].append({"id": "al-bgp", "feature_name": "routing", "event_type": "bgp_down", "severity": "CRITICAL", "status": "OPEN",
                                          "node_display_name": "edge-fin-01",
                                          "description": "In Router t0-fin, BGP neighbor 10.60.0.1 is down. Reason: Edge is not ready / neighbor not responding.",
                                          "recommended_action": "Check the BGP neighbor's configuration and reachability on the physical side."})


def f_fci_colocated_host_down(s):
    vc = s["vcenters"]["vc-fin"]
    target = vc["hosts"][2]
    for name in ("fin-sqlfci-n1", "fin-sqlfci-n2", "fin-app01"):
        _vm(s, name)[1]["host"] = target["host"]
    target["connection_state"] = "NOT_RESPONDING"
    for name in ("fin-sqlfci-n1", "fin-sqlfci-n2", "fin-app01"):
        _vm(s, name)[1]["tools"] = "NOT_RUNNING"


def f_shared_nsx_cert_expired(s):
    s["nsx"]["nsx-wld"]["cert"]["not_after"] = iso(-2)
    for c in s["certificates"]:
        if c["issuedTo"] == s["nsx"]["nsx-wld"]["fqdn"]:
            c["expirationStatus"], c["notAfter"], c["numberOfDaysToExpire"] = "EXPIRED", iso(-2), -2


def f_vpc_ip_exhausted(s):
    sub = s["nsx"]["nsx-wld"]["projects"][0]["vpcs"][0]["subnets"][1]
    sub["pool"]["allocated_ids"] = sub["pool"]["total_ids"]
    s["automation"]["deployments"] += [
        {"id": f"dep-4{i}", "name": f"ecom-scaleout-{i}", "projectId": "proj-digital", "blueprintId": "bp-rhel-web", "status": "CREATE_FAILED",
         "createdAt": iso(hours=-i), "lastRequest": {"status": "FAILED", "details": "Allocation failed for network 'vpc-ecom/ecom-private-app': "
                                                      "no available IP addresses in IP pool ecom-private-app-pool."}} for i in (1, 2, 3)]


def f_ad_fin_down(s):
    _vm(s, "fin-dc01")[1].update(power_state="POWERED_OFF", tools="NOT_RUNNING")
    nic = _vm(s, "fin-dc02")[1]["nics"]["4000"]
    nic["state"], nic["start_connected"] = "NOT_CONNECTED", False


def f_eu_web_quarantined(s):
    vc = s["vcenters"]["vc-eu"]
    q = next(n for n in vc["networks"] if n["name"] == "pg-eu-quarantine")
    for name in ("eu-web01", "eu-web02", "eu-web03"):
        _vm(s, name)[1]["nics"]["4000"]["backing"]["network"] = q["network"]
    s["ops"]["alerts"].append({"alertId": "op-q", "alertLevel": "WARNING", "status": "ACTIVE",
                               "alertDefinitionName": "Virtual machine network adapter changed port group", "resourceName": "eu-web01",
                               "startTimeUTC": ms(minutes=-80)})


def f_scm_oracle_reject(s):
    pol = next(p for p in s["nsx"]["nsx-wld"]["policies"] if p["id"] == "scm")
    pol["rules"].insert(0, _rule("r-scm-x", "block-legacy-oracle-clients", [_g("grp-scm-app")], [_g("grp-scm-db")], ["/infra/services/Oracle"],
                                 "REJECT", 1, days_ago=0, user="j.patel@corp.nwg.lab"))
    pol["rules"][0]["_last_modified_time"] = pol["rules"][0]["_create_time"] = ms(hours=-3)
    pol["_last_modified_time"], pol["_last_modified_user"] = ms(hours=-3), "j.patel@corp.nwg.lab"
    ds = s["vcenters"]["vc-eu"]["datastores"][0]
    ds["free_space"] = int(ds["capacity"] * 0.12)


def f_proxy_t1_detached(s):
    t1 = next(t for t in s["nsx"]["nsx-wld"]["tier1s"] if t["id"] == "t1-corp-dmz")
    t1["tier0_path"] = None
    t1["_last_modified_time"], t1["_last_modified_user"] = ms(minutes=-50), "contractor-net@corp.nwg.lab"


def _orch(*flags):
    def f(s):
        s["orch_flags"] = list(flags)
    f.__name__ = "orch_" + "_".join(flags or ("default",))
    return f


SCENARIOS = {
    "healthy_noisy": [f_noise],
    # Orchestrator scenarios (see vco_sim.py)
    "orch_default": [f_noise, _orch()],
    "orch_9_1_0": [_orch("version_9_1_0")],
    "orch_role_conflict": [_orch("role_conflict")],
    "orch_vc_unusable": [_orch("vc_unusable")],
    "orch_concurrent_edit": [_orch("concurrent_edit")],
    "dfw_blocks_crm_sql": [f_dfw_blocks_crm_sql, f_noise],
    "bgp_down_fin": [f_bgp_down_fin],
    "fci_colocated_host_down": [f_fci_colocated_host_down],
    "shared_nsx_cert_expired": [f_shared_nsx_cert_expired],
    "vpc_ip_exhausted": [f_vpc_ip_exhausted, f_noise],
    "ad_fin_down": [f_ad_fin_down],
    "eu_web_quarantined": [f_eu_web_quarantined, f_noise],
    "scm_oracle_reject_plus_noise": [f_scm_oracle_reject, f_noise],
    "proxy_t1_detached": [f_proxy_t1_detached],
}


def build_state(scenario: str) -> Dict[str, Any]:
    if scenario not in SCENARIOS:
        raise SystemExit(f"unknown scenario {scenario}; choose from {', '.join(SCENARIOS)}")
    s = copy.deepcopy(base_org())
    for f in SCENARIOS[scenario]:
        f(s)
    s["scenario"] = scenario
    return s
