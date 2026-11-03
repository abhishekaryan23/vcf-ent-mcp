# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Acme Corp: a simulated VCF 9.1 organization for troubleshooting tests.

One VCF instance with a management domain and two workload domains, each with its own
vCenter; two NSX Manager clusters; one SDDC Manager; one VCF Operations. Inventory,
task history, certificates, credentials and background alert noise are realistic.
`build_state(scenario)` returns the full state with that scenario's faults applied.
"""

from __future__ import annotations

import copy
import datetime as dt
from typing import Any, Dict

# Real time, so agents comparing timestamps with today's date see no fake clock skew.
NOW = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)

PORTS = {"sddc": 9501, "vc-mgmt": 9511, "vc-prod": 9512, "vc-dev": 9513, "nsx-mgmt": 9521, "nsx-wld": 9522, "ops": 9531}
FQDN = {"sddc": "sddc-manager.acme.lab", "vc-mgmt": "vc-mgmt.acme.lab", "vc-prod": "vc-prod.acme.lab", "vc-dev": "vc-dev.acme.lab",
        "nsx-mgmt": "nsx-mgmt.acme.lab", "nsx-wld": "nsx-wld.acme.lab", "ops": "vcf-ops.acme.lab"}


def iso(days: float = 0, hours: float = 0) -> str:
    return (NOW + dt.timedelta(days=days, hours=hours)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


VCENTER_SERVICES = {
    # vMon services (GET /api/vcenter/services). AUTOMATIC services are expected to run.
    "vpxd": "VMware vCenter Server", "vsphere-ui": "VMware vSphere Client", "vpostgres": "VMware Postgres",
    "sts": "VMware Security Token Service", "lookupsvc": "VMware Lookup Service", "content-library": "VMware Content Library Service",
    "eam": "VMware ESX Agent Manager", "vlcm": "VMware vSphere Lifecycle Manager", "trustmanagement": "VMware Trust Management Service",
    "certificatemanagement": "VMware Certificate Management Service", "vapi-endpoint": "VMware vAPI Endpoint", "wcp": "Workload Control Plane",
}


def _vcenter(name: str, fqdn: str, domain: str, clusters: Dict[str, int], vm_prefix: str, vms_per_host: int) -> Dict[str, Any]:
    hosts, vms, datastores = [], [], []
    hcount = 0
    for c_i, (cname, nhosts) in enumerate(clusters.items()):
        for h in range(nhosts):
            hcount += 1
            hosts.append({"host": f"host-{1000 + hcount}", "name": f"esx{hcount:02d}-{domain}.acme.lab", "cluster": cname,
                          "connection_state": "CONNECTED", "power_state": "POWERED_ON"})
            for v in range(vms_per_host):
                vms.append({"vm": f"vm-{2000 + len(vms)}", "name": f"{vm_prefix}-{cname.split('-')[-1]}-{len(vms) + 1:03d}",
                            "power_state": "POWERED_ON", "cpu_count": 4, "memory_size_mib": 16384, "host": f"host-{1000 + hcount}"})
        datastores.append({"datastore": f"datastore-{300 + c_i}", "name": f"vsan-{cname}", "type": "VSAN",
                           "capacity": 40 * 1024 ** 4, "free_space": int(40 * 1024 ** 4 * 0.42)})
    return {
        "name": name, "fqdn": fqdn, "domain": domain, "version": "9.1.1.0",
        "clusters": [{"cluster": f"domain-c{10 + i}", "name": c, "ha_enabled": True, "drs_enabled": True} for i, c in enumerate(clusters)],
        "hosts": hosts, "vms": vms, "datastores": datastores,
        "services": {k: {"name_key": f"cis.{k}.ServiceName", "description_key": v, "startup_type": "AUTOMATIC",
                         "state": "STARTED", "health": "HEALTHY", "health_messages": []} for k, v in VCENTER_SERVICES.items()},
        "health": {"system": "green", "storage": "green", "mem": "green", "load": "green", "database": "green"},
        "tls": {"subject_dn": f"CN={fqdn}", "issuer_dn": "CN=Acme Issuing CA 01, O=Acme Corp", "valid_from": iso(-300), "valid_to": iso(430)},
        "ntp": ["ntp1.acme.lab", "ntp2.acme.lab"],
    }


def base_org() -> Dict[str, Any]:
    vcenters = {
        "vc-mgmt": _vcenter("vc-mgmt", "vc-mgmt.acme.lab", "mgmt", {"mgmt-cl01": 4}, "mgmt", 3),
        "vc-prod": _vcenter("vc-prod", "vc-prod.acme.lab", "prod", {"prod-cl01": 6, "prod-cl02": 4}, "app", 4),
        "vc-dev": _vcenter("vc-dev", "vc-dev.acme.lab", "dev", {"dev-cl01": 4}, "dev", 5),
    }
    nsx = {
        "nsx-mgmt": {"fqdn": "nsx-mgmt.acme.lab", "domains": ["mgmt"], "nodes": ["nsx-mgmt-01", "nsx-mgmt-02", "nsx-mgmt-03"],
                     "offline": [], "control": "STABLE", "alarms": [],
                     "cert": {"display_name": "nsx-mgmt-vip", "not_after": iso(400)}},
        "nsx-wld": {"fqdn": "nsx-wld.acme.lab", "domains": ["prod", "dev"], "nodes": ["nsx-wld-01", "nsx-wld-02", "nsx-wld-03"],
                    "offline": [], "control": "STABLE",
                    "alarms": [{"id": "al-n-1", "feature_name": "edge_health", "event_type": "edge_cpu_usage_high", "severity": "MEDIUM",
                                "status": "OPEN", "node_display_name": "edge-prod-02",
                                "description": "Edge node CPU usage has reached 82%, which is above the high threshold value of 80%.",
                                "recommended_action": "Review the edge node's configuration and workload."}],
                    "cert": {"display_name": "nsx-wld-vip", "not_after": iso(380)}},
    }
    domains = [
        {"id": "d-mgmt", "name": "mgmt", "type": "MANAGEMENT", "status": "ACTIVE", "vcenter": "vc-mgmt", "nsx": "nsx-mgmt"},
        {"id": "d-prod", "name": "prod", "type": "VI", "status": "ACTIVE", "vcenter": "vc-prod", "nsx": "nsx-wld"},
        {"id": "d-dev", "name": "dev", "type": "VI", "status": "ACTIVE", "vcenter": "vc-dev", "nsx": "nsx-wld"},
    ]
    tasks = [
        {"id": "t-1001", "name": "Rotate credentials for VCF management components", "type": "CREDENTIALS_ROTATE", "status": "SUCCESSFUL",
         "creationTimestamp": iso(-6), "completionTimestamp": iso(-6, 0.2), "errors": [], "resources": [{"resourceId": "d-mgmt", "type": "DOMAIN"}]},
        {"id": "t-1002", "name": "Backup SDDC Manager", "type": "BACKUP", "status": "SUCCESSFUL",
         "creationTimestamp": iso(-1), "completionTimestamp": iso(-1, 0.1), "errors": [], "resources": []},
        {"id": "t-0990", "name": "Add host esx13-prod.acme.lab", "type": "HOST_COMMISSION", "status": "FAILED",
         "creationTimestamp": iso(-21), "completionTimestamp": iso(-21, 0.5), "resolutionStatus": "RESOLVED",
         "errors": [{"errorCode": "HOST_VALIDATION_FAILED", "message": "Host esx13-prod.acme.lab failed NTP validation. (Resolved: host re-commissioned on a later attempt.)"}],
         "resources": [{"resourceId": "d-prod", "type": "DOMAIN"}]},
    ]
    certificates = []
    for vc in vcenters.values():
        certificates.append({"domain": vc["domain"], "resourceType": "VCENTER", "resourceName": vc["fqdn"], "issuedTo": vc["fqdn"],
                             "notAfter": vc["tls"]["valid_to"], "numberOfDaysToExpire": 430, "expirationStatus": "ACTIVE"})
    for n in nsx.values():
        for d in n["domains"][:1]:
            certificates.append({"domain": d, "resourceType": "NSXT_MANAGER", "resourceName": n["fqdn"], "issuedTo": n["fqdn"],
                                 "notAfter": n["cert"]["not_after"], "numberOfDaysToExpire": 380, "expirationStatus": "ACTIVE"})
    credentials = [
        {"id": f"cr-{i}", "credentialType": "SSO", "accountType": "SERVICE", "username": u,
         "resource": {"resourceName": r, "resourceType": t, "domainName": d},
         "expiry": {"expiryDate": iso(120), "connectivityStatus": "ACTIVE", "status": "ACTIVE"}}
        for i, (u, r, t, d) in enumerate([
            ("svc-vcf-vc-mgmt@vsphere.local", "vc-mgmt.acme.lab", "VCENTER", "mgmt"),
            ("svc-vcf-vc-prod@vsphere.local", "vc-prod.acme.lab", "VCENTER", "prod"),
            ("svc-vcf-vc-dev@vsphere.local", "vc-dev.acme.lab", "VCENTER", "dev"),
            ("admin", "nsx-wld.acme.lab", "NSXT_MANAGER", "prod"),
        ])
    ]
    ops_alerts = [
        {"alertId": f"oa-{i}", "alertDefinitionName": name, "alertLevel": level, "status": "ACTIVE", "resourceName": res,
         "startTimeUTC": 1793000000000 + i * 1000}
        for i, (name, level, res) in enumerate([
            ("Virtual machine has high CPU contention", "WARNING", "dev-cl01-007"),
            ("Virtual machine has high CPU contention", "WARNING", "dev-cl01-012"),
            ("Virtual machine memory is ballooning", "WARNING", "app-cl02-031"),
            ("Snapshot older than 7 days", "INFORMATION", "app-cl01-004"),
            ("Guest file system is running out of disk space", "WARNING", "dev-cl01-019"),
        ])
    ]
    return {
        "org": "Acme Corp", "vcf_version": "9.1.1.0", "vcenters": vcenters, "nsx": nsx, "domains": domains, "tasks": tasks,
        "certificates": certificates, "credentials": credentials,
        "ops": {"alerts": ops_alerts, "node_status": "ONLINE", "collectors": [{"name": "acme-cloud-proxy-01", "state": "UP"}]},
        "sddc": {"ntp": ["ntp1.acme.lab", "ntp2.acme.lab"], "dns": ["10.10.0.10", "10.10.0.11"]},
    }


# ---- fault scenarios ------------------------------------------------------------------

def _svc(state, vc, svc, state_value="STOPPED", health="UNHEALTHY", msg=None):
    s = state["vcenters"][vc]["services"][svc]
    s["state"], s["health"] = state_value, health
    if msg:
        s["health_messages"] = [{"id": f"{svc}.health", "default_message": msg, "args": []}]


def f_vpxd_stopped(s):
    _svc(s, "vc-prod", "vpxd", msg="vpxd is not running; it exited unexpectedly with code 139.")
    s["vcenters"]["vc-prod"]["health"]["system"] = "orange"
    s["tasks"].append({"id": "t-1101", "name": "Add cluster prod-cl03 to domain prod", "type": "CLUSTER_ADD", "status": "FAILED",
                       "creationTimestamp": iso(-0.05), "completionTimestamp": iso(-0.04),
                       "errors": [{"errorCode": "VCENTER_CONNECTION_FAILED", "message": "Unable to connect to vCenter Server vc-prod.acme.lab: Connection refused (vpxd)."}],
                       "resources": [{"resourceId": "d-prod", "type": "DOMAIN"}]})
    s["ops"]["alerts"].append({"alertId": "oa-crit-1", "alertDefinitionName": "vCenter Server service vpxd is not running",
                               "alertLevel": "CRITICAL", "status": "ACTIVE", "resourceName": "vc-prod.acme.lab", "startTimeUTC": 1793100000000})


def f_nsx_cert_expired(s):
    s["nsx"]["nsx-wld"]["cert"]["not_after"] = iso(-2)
    for c in s["certificates"]:
        if c["resourceName"] == "nsx-wld.acme.lab":
            c.update(notAfter=iso(-2), numberOfDaysToExpire=-2, expirationStatus="EXPIRED")
    s["nsx"]["nsx-wld"]["alarms"].append({"id": "al-n-9", "feature_name": "certificates", "event_type": "certificate_expired", "severity": "CRITICAL",
                                         "status": "OPEN", "node_display_name": "nsx-wld-01",
                                         "description": "Certificate nsx-wld-vip has expired. Some services may not be functioning.",
                                         "recommended_action": "Replace the expired certificate with a valid certificate."})


def f_nsx_node_down(s):
    n = s["nsx"]["nsx-wld"]
    n["offline"] = ["nsx-wld-02"]
    n["alarms"].append({"id": "al-n-7", "feature_name": "manager_health", "event_type": "manager_node_down", "severity": "HIGH",
                        "status": "OPEN", "node_display_name": "nsx-wld-02",
                        "description": "Manager node nsx-wld-02 is not reachable from the other cluster members.",
                        "recommended_action": "Check the node's power state, network connectivity and disk space."})


def f_hosts_not_responding(s):
    for h in s["vcenters"]["vc-prod"]["hosts"]:
        if h["name"] in ("esx09-prod.acme.lab", "esx10-prod.acme.lab"):
            h["connection_state"] = "NOT_RESPONDING"
    s["ops"]["alerts"].append({"alertId": "oa-crit-2", "alertDefinitionName": "Host has lost connection to vCenter Server", "alertLevel": "CRITICAL",
                               "status": "ACTIVE", "resourceName": "esx09-prod.acme.lab", "startTimeUTC": 1793100000000})
    s["ops"]["alerts"].append({"alertId": "oa-crit-3", "alertDefinitionName": "Host has lost connection to vCenter Server", "alertLevel": "CRITICAL",
                               "status": "ACTIVE", "resourceName": "esx10-prod.acme.lab", "startTimeUTC": 1793100000000})


def f_depot_unreachable(s):
    s["tasks"].append({"id": "t-1201", "name": "Download bundle VMware Cloud Foundation 9.1.1.0 update", "type": "BUNDLE_DOWNLOAD", "status": "FAILED",
                       "creationTimestamp": iso(-0.2), "completionTimestamp": iso(-0.19),
                       "errors": [{"errorCode": "DEPOT_CONNECTION_FAILED", "message": "Unable to reach the online depot dl.broadcom.com: connect timed out (proxy proxy.acme.lab:3128)."}],
                       "resources": []})
    s["tasks"].append({"id": "t-1202", "name": "Refresh depot metadata", "type": "DEPOT_SYNC", "status": "FAILED",
                       "creationTimestamp": iso(-0.1), "completionTimestamp": iso(-0.09),
                       "errors": [{"errorCode": "DEPOT_CONNECTION_FAILED", "message": "Depot metadata refresh failed: connect timed out."}], "resources": []})


def f_service_account_expired(s):
    for c in s["credentials"]:
        if c["username"] == "svc-vcf-vc-prod@vsphere.local":
            c["expiry"].update(expiryDate=iso(-1), status="EXPIRED", connectivityStatus="ERROR",
                               connectivityErrorDetails="Authentication failed: password expired.")
    s["tasks"].append({"id": "t-1301", "name": "Rotate credentials for vc-prod.acme.lab", "type": "CREDENTIALS_ROTATE", "status": "FAILED",
                       "creationTimestamp": iso(-0.3), "completionTimestamp": iso(-0.29),
                       "errors": [{"errorCode": "CREDENTIAL_ROTATION_FAILED", "message": "Password rotation failed for svc-vcf-vc-prod@vsphere.local: current password has expired."}],
                       "resources": [{"resourceId": "d-prod", "type": "DOMAIN"}]})


def f_vcenter_disk_full(s):
    vc = s["vcenters"]["vc-dev"]
    vc["health"].update(storage="red", system="orange")
    _svc(s, "vc-dev", "vpostgres", msg="vpostgres stopped: could not write to file \"pg_wal\": No space left on device.")
    _svc(s, "vc-dev", "vpxd", msg="vpxd is not running: database vpostgres is unavailable.")
    s["ops"]["alerts"].append({"alertId": "oa-crit-4", "alertDefinitionName": "vCenter Server appliance disk partition /storage/seat is above 95%",
                               "alertLevel": "CRITICAL", "status": "ACTIVE", "resourceName": "vc-dev.acme.lab", "startTimeUTC": 1793100000000})


def f_ops_collector_down(s):
    s["ops"]["collectors"][0]["state"] = "DOWN"
    s["ops"]["node_status"] = "ONLINE"
    s["ops"]["alerts"].append({"alertId": "oa-imm-1", "alertDefinitionName": "Cloud proxy is not sending data", "alertLevel": "IMMEDIATE",
                               "status": "ACTIVE", "resourceName": "acme-cloud-proxy-01", "startTimeUTC": 1793100000000})


def f_vcenter_cert_expired(s):
    s["vcenters"]["vc-prod"]["tls"]["valid_to"] = iso(-1)
    for c in s["certificates"]:
        if c["resourceName"] == "vc-prod.acme.lab":
            c.update(notAfter=iso(-1), numberOfDaysToExpire=-1, expirationStatus="EXPIRED")


def f_datastore_full(s):
    for d in s["vcenters"]["vc-prod"]["datastores"]:
        if d["name"] == "vsan-prod-cl01":
            d["free_space"] = int(d["capacity"] * 0.015)
    s["ops"]["alerts"].append({"alertId": "oa-crit-5", "alertDefinitionName": "vSAN datastore capacity utilization is above 98%",
                               "alertLevel": "CRITICAL", "status": "ACTIVE", "resourceName": "vsan-prod-cl01", "startTimeUTC": 1793100000000})


def f_ntp_missing(s):
    s["vcenters"]["vc-mgmt"]["ntp"] = []
    _svc(s, "vc-mgmt", "sts", state_value="STARTED", health="DEGRADED",
         msg="Token validation failures: clock skew between this vCenter and its clients exceeds 5 minutes.")


def f_noise(s):
    for i in range(12):
        s["ops"]["alerts"].append({"alertId": f"oa-noise-{i}", "alertDefinitionName": "Virtual machine has high CPU contention", "alertLevel": "WARNING",
                                   "status": "ACTIVE", "resourceName": f"dev-cl01-{i + 20:03d}", "startTimeUTC": 1793100000000 + i})
    s["nsx"]["nsx-wld"]["alarms"].append({"id": "al-n-3", "feature_name": "edge_health", "event_type": "edge_memory_usage_high", "severity": "MEDIUM",
                                         "status": "OPEN", "node_display_name": "edge-dev-01", "description": "Edge node memory usage is 81%.",
                                         "recommended_action": "Review the edge node's workload."})


SCENARIOS = {
    "healthy": [],
    "vpxd_stopped": [f_vpxd_stopped],
    "nsx_cert_expired": [f_nsx_cert_expired],
    "nsx_node_down": [f_nsx_node_down],
    "hosts_not_responding": [f_hosts_not_responding],
    "depot_unreachable": [f_depot_unreachable],
    "service_account_expired": [f_service_account_expired],
    "vcenter_disk_full": [f_vcenter_disk_full],
    "ops_collector_down": [f_ops_collector_down],
    "datastore_full": [f_datastore_full, f_noise],
    "ntp_missing_red_herring": [f_ntp_missing, f_noise],
    "multi_cert_and_nsx_node": [f_vcenter_cert_expired, f_nsx_node_down],
}


def build_state(scenario: str) -> Dict[str, Any]:
    if scenario not in SCENARIOS:
        raise KeyError(f"unknown scenario {scenario!r}; choose from {sorted(SCENARIOS)}")
    state = copy.deepcopy(base_org())
    for fault in SCENARIOS[scenario]:
        fault(state)
    return state
