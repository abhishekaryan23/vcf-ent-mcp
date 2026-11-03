# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Workload- and network-level evidence for "why is <application> down?", on top of the
appliance checks in engine.py. Everything is a documented 9.x GET (or a read-only POST of the
vSphere tagging API):

- NSX Policy: Tier-0 BGP neighbor status (the session to the physical network, e.g. Cisco
  switches or firewalls), Tier-1 uplinks, segments, distributed firewall rules (recent DROP or
  REJECT changes, with who and when), VPC subnet IP pools.
- vCenter: VM placement (per host), power state, NIC connection and port group, vSphere tags
  (Application / Tier / Role / AD-Forest / Cluster), so clustered workloads (SQL FCI, Always On,
  Oracle Fail Safe) and domain controllers can be reasoned about.

`correlate_deep` turns that evidence into findings inside engine.correlate.
"""

from __future__ import annotations

import datetime as dt
from collections import defaultdict
from typing import Any, Dict, List

OK, WARN, FAIL, UNKNOWN = "OK", "WARN", "FAIL", "UNKNOWN"
RECENT_HOURS = 24
SERVICE_NAMES = {"HTTPS": "HTTPS 443", "HTTP": "HTTP 80", "MS-SQL-S": "MS-SQL 1433", "Oracle": "Oracle 1521", "LDAP": "LDAP 389",
                 "Kerberos": "Kerberos 88", "DNS": "DNS 53", "SMB": "SMB 445", "SSH": "SSH 22", "Squid-3128": "proxy 3128",
                 "SQL-AG-Endpoint-5022": "SQL AG endpoint 5022"}
CRITICAL_ROLES = ("domain-controller", "sql", "oracle", "web", "app", "proxy")
QUARANTINE_WORDS = ("quarantine", "isolat", "blackhole", "sinkhole")


def _last(path: Any) -> str:
    return str(path).rstrip("/").rsplit("/", 1)[-1] if path else ""


def _svc(path: str) -> str:
    return "any" if path == "ANY" else SERVICE_NAMES.get(_last(path), _last(path))


def _age_minutes(ms: Any, now: dt.datetime) -> float:
    try:
        return (now.timestamp() * 1000 - float(ms)) / 60000.0
    except (TypeError, ValueError):
        return 1e9


def _ago(minutes: float) -> str:
    return f"{int(minutes)} min ago" if minutes < 120 else f"{minutes / 60:.1f} h ago" if minutes < 2880 else f"{minutes / 1440:.0f} days ago"


def _results(c, prov, path, params=None) -> List[Dict[str, Any]]:
    data = c._get(prov, path, params) or {}
    return data.get("results", []) if isinstance(data, dict) else []


# ---- NSX ---------------------------------------------------------------------------------------

def collect_nsx_policy(c, prov, fqdn: str) -> None:
    detail = c.inventory.setdefault("nsx_detail", {}).setdefault(fqdn, {"segments": [], "tier1s": [], "tier0s": [], "rules": [], "subnets": []})
    try:
        detail["segments"] = _results(c, prov, "/policy/api/v1/infra/segments")
        detail["tier1s"] = _results(c, prov, "/policy/api/v1/infra/tier-1s")
    except Exception:
        pass
    # Tier-0 BGP sessions to the physical network.
    try:
        for t0 in _results(c, prov, "/policy/api/v1/infra/tier-0s"):
            t0id = t0.get("id")
            entry = {"id": t0id, "neighbors": []}
            for ls in _results(c, prov, f"/policy/api/v1/infra/tier-0s/{t0id}/locale-services"):
                base = f"/policy/api/v1/infra/tier-0s/{t0id}/locale-services/{ls.get('id')}/bgp/neighbors"
                desc = {n.get("neighbor_address"): n.get("description", "") for n in _results(c, prov, base)}
                for st in _results(c, prov, base + "/status"):
                    addr, state = st.get("neighbor_address"), str(st.get("connection_state", "UNKNOWN")).upper()
                    entry["neighbors"].append({"address": addr, "state": state, "peer": desc.get(addr, ""), "remote_as": st.get("remote_as_number")})
                    c.add("nsx", f"{t0id}/{addr}", "bgp_neighbor", OK if state == "ESTABLISHED" else FAIL,
                          f"Tier-0 {t0id} on {fqdn}: BGP neighbor {addr} (AS {st.get('remote_as_number')}, {desc.get(addr) or 'no description'}) is {state}.",
                          "GET /policy/api/v1/infra/tier-0s/{t0}/locale-services/{ls}/bgp/neighbors/status", nsx=fqdn, tier0=t0id,
                          neighbor=addr, peer=desc.get(addr, ""), state=state)
            detail["tier0s"].append(entry)
    except Exception as exc:
        c.add("nsx", fqdn, "bgp", UNKNOWN, f"Could not read Tier-0 BGP status on {fqdn}: {exc}", "GET /policy/api/v1/infra/tier-0s")
    # Tier-1 gateways that carry segments but have no Tier-0 uplink.
    for t1 in detail["tier1s"]:
        segs = [s.get("display_name") or s.get("id") for s in detail["segments"] if _last(s.get("connectivity_path")) == t1.get("id")]
        if segs and not t1.get("tier0_path"):
            age = _age_minutes(t1.get("_last_modified_time"), c.now)
            c.add("nsx", t1.get("id"), "t1_uplink", FAIL,
                  f"Tier-1 gateway {t1.get('id')} on {fqdn} is NOT connected to a Tier-0 (last changed {_ago(age)} by {t1.get('_last_modified_user')}); "
                  f"segments {', '.join(segs)} have no route to the rest of the network.", "GET /policy/api/v1/infra/tier-1s", nsx=fqdn,
                  segments=segs, changed_minutes_ago=round(age), changed_by=t1.get("_last_modified_user"))
    # Distributed firewall: DROP/REJECT rules changed recently.
    try:
        recent = []
        for pol in _results(c, prov, "/policy/api/v1/infra/domains/default/security-policies"):
            for r in _results(c, prov, f"/policy/api/v1/infra/domains/default/security-policies/{pol.get('id')}/rules"):
                rule = {"policy": pol.get("display_name") or pol.get("id"), "policy_id": pol.get("id"), "category": pol.get("category"),
                        "rule": r.get("display_name") or r.get("id"), "rule_id": r.get("id"), "action": r.get("action"),
                        "sources": [_last(g) if g != "ANY" else "any" for g in r.get("source_groups") or []],
                        "destinations": [_last(g) if g != "ANY" else "any" for g in r.get("destination_groups") or []],
                        "services": [_svc(s) for s in r.get("services") or []], "disabled": r.get("disabled", False),
                        "sequence": r.get("sequence_number"), "changed_by": r.get("_last_modified_user"),
                        "changed_minutes_ago": round(_age_minutes(r.get("_last_modified_time"), c.now))}
                detail["rules"].append(rule)
                if rule["action"] in ("DROP", "REJECT") and not rule["disabled"] and rule["changed_minutes_ago"] <= RECENT_HOURS * 60:
                    recent.append(rule)
        for rule in recent:
            members = []
            for g in rule["destinations"]:
                if g != "any":
                    try:
                        members += [m.get("display_name") for m in _results(c, prov, f"/policy/api/v1/infra/domains/default/groups/{g}/members/virtual-machines")]
                    except Exception:
                        pass
            rule["destination_vms"] = members
            c.add("nsx", rule["rule"], "dfw_recent_block", WARN,
                  f"DFW rule '{rule['rule']}' in policy '{rule['policy']}' on {fqdn} was changed {_ago(rule['changed_minutes_ago'])} by "
                  f"{rule['changed_by']}: {rule['action']} {', '.join(rule['services'])} from {', '.join(rule['sources'])} to "
                  f"{', '.join(rule['destinations'])}" + (f" ({', '.join(members)})" if members else "") + ".",
                  "GET /policy/api/v1/infra/domains/default/security-policies/{policy}/rules", nsx=fqdn, **rule)
        if detail["rules"] and not recent:
            c.add("nsx", fqdn, "dfw", OK, f"No DROP/REJECT firewall rule on {fqdn} changed in the last {RECENT_HOURS} h.",
                  "GET /policy/api/v1/infra/domains/default/security-policies")
    except Exception as exc:
        c.add("nsx", fqdn, "dfw", UNKNOWN, f"Could not read distributed firewall rules on {fqdn}: {exc}", "GET .../security-policies")
    # VPC subnets (NSX 9 projects): IP pool exhaustion.
    try:
        for proj in _results(c, prov, "/policy/api/v1/orgs/default/projects"):
            pid = proj.get("id")
            for vpc in _results(c, prov, f"/policy/api/v1/orgs/default/projects/{pid}/vpcs"):
                vid = vpc.get("id")
                for sub in _results(c, prov, f"/policy/api/v1/orgs/default/projects/{pid}/vpcs/{vid}/subnets"):
                    sid = sub.get("id")
                    for pool in _results(c, prov, f"/policy/api/v1/orgs/default/projects/{pid}/vpcs/{vid}/subnets/{sid}/ip-pools"):
                        u = pool.get("pool_usage") or {}
                        total, used = u.get("total_ids") or 0, u.get("allocated_ids") or 0
                        if not total:
                            continue
                        pct = 100.0 * used / total
                        detail["subnets"].append({"project": pid, "vpc": vid, "subnet": sid, "cidr": (sub.get("ip_addresses") or [""])[0],
                                                  "access_mode": sub.get("access_mode"), "used": used, "total": total})
                        st = FAIL if used >= total else (WARN if pct >= 90 else OK)
                        if st != OK:
                            c.add("nsx", f"{vid}/{sid}", "vpc_ip_pool", st,
                                  f"VPC subnet {vid}/{sid} ({(sub.get('ip_addresses') or [''])[0]}, project {pid}, {fqdn}) has {total - used} of "
                                  f"{total} IP addresses left ({pct:.0f}% used).",
                                  "GET /policy/api/v1/orgs/default/projects/{p}/vpcs/{v}/subnets/{s}/ip-pools", nsx=fqdn, project=pid,
                                  vpc=vid, subnet=sid, used=used, total=total)
    except Exception:
        pass


# ---- vCenter workloads -------------------------------------------------------------------------

def collect_workloads(c, prov, fqdn: str, domain: str, hosts: List[Dict[str, Any]]) -> None:
    vms: Dict[str, Dict[str, Any]] = {}
    try:
        for v in c._get(prov, "/api/vcenter/vm") or []:
            vms[v["vm"]] = {"vm": v["vm"], "name": v.get("name"), "power_state": v.get("power_state"), "vcenter": fqdn, "domain": domain,
                            "host": None, "host_state": None, "tags": {}, "nics": []}
        for h in hosts:
            for v in c._get(prov, "/api/vcenter/vm", {"hosts": h.get("host")}) or []:
                if v["vm"] in vms:
                    vms[v["vm"]].update(host=h.get("name"), host_state=h.get("connection_state"))
    except Exception as exc:
        c.add("vcenter", fqdn, "vm_inventory", UNKNOWN, f"Could not list VMs on {fqdn}: {exc}", "GET /api/vcenter/vm")
        return
    # vSphere tags -> Application / Tier / Role / AD-Forest / Cluster (read-only).
    try:
        cats = {}
        for cid in c._get(prov, "/api/cis/tagging/category") or []:
            cats[cid] = (c._get(prov, f"/api/cis/tagging/category/{cid}") or {}).get("name")
        tag_ids = c._get(prov, "/api/cis/tagging/tag") or []
        names = {}
        for tid in tag_ids:
            t = c._get(prov, f"/api/cis/tagging/tag/{tid}") or {}
            names[tid] = (cats.get(t.get("category_id"), "tag"), t.get("name"))
        if tag_ids:
            resp = prov.request("POST", "/api/cis/tagging/tag-association", params={"action": "list-attached-objects-on-tags"},
                                json_body={"tag_ids": tag_ids}).json() or []
            for entry in resp:
                cat, val = names.get(entry.get("tag_id"), ("tag", "?"))
                for obj in entry.get("object_ids") or []:
                    if obj.get("id") in vms:
                        vms[obj["id"]]["tags"][cat] = val
    except Exception:
        pass
    nets = {}
    try:
        nets = {n.get("network"): n.get("name") for n in c._get(prov, "/api/vcenter/network") or []}
    except Exception:
        pass
    for v in vms.values():
        if not v["tags"]:
            continue
        try:
            d = c._get(prov, f"/api/vcenter/vm/{v['vm']}") or {}
            v["guest_os"] = d.get("guest_OS")
            v["nics"] = [{"label": n.get("label"), "state": n.get("state"), "network": nets.get((n.get("backing") or {}).get("network"),
                                                                                                    (n.get("backing") or {}).get("network"))}
                         for n in (d.get("nics") or {}).values()]
        except Exception:
            pass
    c.inventory.setdefault("vms", []).extend(vms.values())
    for v in vms.values():
        role = str(v["tags"].get("Role", ""))
        if not v["tags"]:
            continue
        label = f"VM {v['name']} ({v['tags'].get('Application', '?')} {role}, {fqdn})"
        if v["power_state"] != "POWERED_ON" and any(k in role for k in CRITICAL_ROLES):
            c.add("vcenter", v["name"], "vm_power", FAIL, f"{label} is {v['power_state']}.", "GET /api/vcenter/vm", vcenter=fqdn, **_vm_detail(v))
        for n in v["nics"]:
            if str(n.get("state", "")).upper() != "CONNECTED" and v["power_state"] == "POWERED_ON":
                c.add("vcenter", v["name"], "vm_nic", FAIL, f"{label} is running but its {n.get('label')} on {n.get('network')} is {n.get('state')} "
                      "(the guest has no network on that adapter).", "GET /api/vcenter/vm/{vm}", vcenter=fqdn, **_vm_detail(v))
            if any(w in str(n.get("network", "")).lower() for w in QUARANTINE_WORDS):
                c.add("vcenter", v["name"], "vm_quarantined", FAIL, f"{label} is connected to port group '{n.get('network')}' instead of its "
                      "application network.", "GET /api/vcenter/vm/{vm}", vcenter=fqdn, network=n.get("network"), **_vm_detail(v))
    # Clustered workloads (SQL FCI / AG, Oracle Fail Safe): nodes sharing one ESXi host defeat the cluster.
    groups = defaultdict(list)
    for v in vms.values():
        if v["tags"].get("Cluster"):
            groups[v["tags"]["Cluster"]].append(v)
    for cname, nodes in groups.items():
        by_host = defaultdict(list)
        for v in nodes:
            by_host[v["host"]].append(v["name"])
        for host, names in by_host.items():
            if host and len(names) > 1:
                c.add("vcenter", cname.split(" ")[0], "cluster_colocation", WARN,
                      f"Clustered workload {cname.split(' ')[0]}: nodes {', '.join(names)} all run on the same ESXi host {host} "
                      "(no DRS anti-affinity rule), so one host failure takes out every node.", "GET /api/vcenter/vm?hosts=",
                      vcenter=fqdn, host=host, nodes=names, cluster_name=cname)


def _vm_detail(v):
    return {"app": v["tags"].get("Application"), "role": v["tags"].get("Role"), "forest": v["tags"].get("AD-Forest"), "host": v.get("host"),
            "domain": v.get("domain")}


# ---- correlation -------------------------------------------------------------------------------

def correlate_deep(items, by, add, Finding, inventory) -> None:
    fails = [e for e in items if e.status == FAIL]
    vms = inventory.get("vms", [])

    # BGP to the physical network.
    per_t0 = defaultdict(list)
    for e in by(check="bgp_neighbor", pool=[x for x in items if x.check == "bgp_neighbor"]):
        per_t0[(e.detail.get("nsx"), e.detail.get("tier0"))].append(e)
    for (nsx, t0), evs in per_t0.items():
        down = [e for e in evs if e.status == FAIL]
        if not down:
            continue
        peers = "; ".join(f"{e.detail.get('neighbor')} = {e.detail.get('peer') or 'unknown peer'} ({e.detail.get('state')})" for e in down)
        alarms = by(component="nsx", check="alarm", pred=lambda a: a.detail.get("nsx") == nsx and "bgp" in str(a.detail.get("event", "")).lower())
        all_down = len(down) == len(evs)
        add(Finding(f"North-south routing {'DOWN' if all_down else 'degraded'} on Tier-0 {t0} ({nsx}): BGP to the physical network is not established",
                    f"BGP session(s) from NSX Tier-0 {t0} to the upstream devices are not ESTABLISHED: {peers}.",
                    ("Every workload behind " + t0 + " is unreachable from outside NSX (users, branches, internet, other sites), while traffic "
                     "between VMs inside NSX still works." if all_down else "One upstream path is gone; traffic still flows but without redundancy."),
                    "CRITICAL" if all_down else "HIGH", "high", "nsx", f"{t0} ({nsx})", [],
                    ["The session state (ACTIVE/IDLE/CONNECT) means TCP 179 is not completing. Check the peer devices listed above (their BGP "
                     "neighbor config, AS numbers, interface/VLAN to the edge uplinks, ACLs for TCP 179, recent changes on those devices).",
                     "From an NSX edge node CLI: 'get bgp neighbor summary' and 'get interfaces' to confirm the uplink is up.",
                     "Nothing in VCF changed if no recent NSX task or alarm exists before the drop: start with the network/firewall team."]), down + alarms)

    # Tier-1 without a Tier-0.
    for e in by(check="t1_uplink", pool=fails):
        segs = e.detail.get("segments") or []
        affected = sorted({v["name"] for v in vms for n in v.get("nics", []) if n.get("network") in segs})
        add(Finding(f"Tier-1 gateway {e.target} was disconnected from its Tier-0", e.summary,
                    f"Workloads on {', '.join(segs)}" + (f" ({', '.join(affected)})" if affected else "") + " cannot reach or be reached from "
                    "other networks (other segments behind other gateways, the physical network, the internet).", "CRITICAL", "high", "nsx", e.target, [],
                    [f"Reconnect {e.target} to its Tier-0 (NSX > Networking > Tier-1 Gateways > {e.target} > Linked Tier-0 Gateway) after confirming the "
                     f"change by {e.detail.get('changed_by')} was not intentional.", "Check route advertisement on the Tier-1 after reconnecting."]), [e])

    # Recently changed DFW DROP/REJECT rules.
    for e in by(check="dfw_recent_block"):
        d = e.detail
        dst_vms = d.get("destination_vms") or []
        apps = sorted({v["tags"].get("Application") for v in vms if v["name"] in dst_vms and v.get("tags")} - {None})
        add(Finding(f"Firewall rule '{d.get('rule')}' {d.get('action')}s {', '.join(d.get('services') or [])} to {', '.join(d.get('destinations') or [])}"
                    f" (changed {_ago(d.get('changed_minutes_ago', 0))})",
                    e.summary + " A DROP/REJECT rule placed above the application's ALLOW rules silently blocks that traffic.",
                    (f"{', '.join(apps)} lose" if apps else "Workloads in the destination group lose") +
                    f" {', '.join(d.get('services') or [])} connectivity" + (f" to {', '.join(dst_vms)}" if dst_vms else "") + ".",
                    "HIGH", "high", "nsx", d.get("rule"), [],
                    [f"Confirm with {d.get('changed_by')} why '{d.get('rule')}' was added to policy '{d.get('policy')}'.",
                     "Disable or remove the rule (NSX > Security > Distributed Firewall), or move it below the application's ALLOW rule.",
                     "Verify with NSX Traceflow between a source and a destination VM."]), [e])

    # VPC IP pools.
    for e in by(check="vpc_ip_pool"):
        dep = by(component="vcf_automation", check="failed_deployment", pred=lambda a: str(e.detail.get("subnet")) in a.summary)
        add(Finding(f"VPC subnet {e.target} is out of IP addresses" if e.status == FAIL else f"VPC subnet {e.target} is almost out of IP addresses",
                    e.summary, "New VMs or scale-out on this subnet fail to get an IP (deployments fail; DHCP/static allocation fails)."
                    + (f" {len(dep)} recent VCF Automation deployment(s) failed for this reason." if dep else ""),
                    "HIGH" if e.status == FAIL else "MEDIUM", "high", "nsx", e.target, [],
                    ["Release IPs of deleted/unused VMs, or add a subnet / enlarge the VPC IP block (NSX > VPCs > subnet > IP allocation).",
                     "Retry the failed deployments after capacity is available."]), [e] + dep)

    # Domain controllers per AD forest.
    dc_problems = defaultdict(list)
    for e in fails:
        if e.check in ("vm_power", "vm_nic", "vm_quarantined") and "domain-controller" in str(e.detail.get("role")):
            dc_problems[e.detail.get("forest")].append(e)
    for forest, evs in dc_problems.items():
        dcs = [v for v in vms if v["tags"].get("Role") == "domain-controller" and v["tags"].get("AD-Forest") == forest]
        bad = {e.target for e in evs}
        all_bad = dcs and all(v["name"] in bad for v in dcs)
        add(Finding(f"{'No' if all_bad else 'Reduced'} reachable domain controller for AD forest {forest}",
                    "; ".join(e.summary for e in evs),
                    (f"Kerberos/LDAP authentication in {forest} fails: user logins, service accounts, SQL/IIS Windows authentication and vCenter "
                     "logins via that identity source break." if all_bad else f"{forest} runs on fewer domain controllers; redundancy is lost."),
                    "CRITICAL" if all_bad else "HIGH", "high", "vcenter", forest, [],
                    ["Power on the domain controller VM(s) that are off (check why they were shut down first: vCenter events/tasks).",
                     "Reconnect the disconnected network adapter (VM > Edit Settings > Network adapter > Connected) and confirm the port group.",
                     "Then check AD replication health (repadmin /replsummary) and time sync on the DCs."]), evs)

    # Clustered workloads on a failed host / co-located.
    for e in by(check="cluster_colocation"):
        host = e.detail.get("host")
        down = by(check="host_connection", pool=fails, pred=lambda h: h.target == host)
        if down:
            add(Finding(f"All nodes of {e.target} were on failed host {host}: the cluster is down",
                        f"{e.summary} That host is {down[0].summary.split(' is ')[-1].rstrip('.')}.",
                        f"{e.target} has no surviving node, so the application using it is down until HA restarts the VMs elsewhere "
                        "(clustered VMs with shared disks may not restart automatically).", "CRITICAL", "high", "vcenter", e.target, [],
                        [f"Bring {host} back (iLO/iDRAC console, power, management network) or let vSphere HA restart the nodes on other hosts.",
                         "Once up, add a DRS VM-VM anti-affinity rule (or VM-Host 'must' rules) so cluster nodes never share a host.",
                         "Check the cluster role / AG state in Windows Failover Cluster Manager after recovery."]), [e] + down)
        else:
            add(Finding(f"{e.target} nodes share one ESXi host (no anti-affinity)", e.summary, "A single host failure would take down every node.",
                        "LOW", "high", "vcenter", e.target, [], ["Add a DRS VM-VM anti-affinity rule for the cluster nodes."]), [e])

    # VMs on a quarantine port group, grouped by application.
    q = defaultdict(list)
    for e in by(check="vm_quarantined", pool=fails):
        if "domain-controller" not in str(e.detail.get("role")):
            q[(e.detail.get("app"), e.detail.get("network"))].append(e)
    for (app, net), evs in q.items():
        add(Finding(f"{len(evs)} {app} VM(s) moved to quarantine port group {net}",
                    "; ".join(e.summary for e in evs), f"{app} is unreachable: its VMs are isolated on {net}.", "CRITICAL" if len(evs) > 1 else "HIGH",
                    "high", "vcenter", f"{app} ({net})", [],
                    [f"Find who changed the network and the PREVIOUS port group in vCenter > VM > Monitor > Events / Tasks (often a "
                     "security-incident tool). The MCP cannot see the old port group: do not guess it from other tiers' networks.",
                     "If the isolation is not an active security response, move the adapters back to the port group named in that event."]), evs)

    # Remaining VM power/NIC problems (non-DC) grouped per VM.
    for e in fails:
        if e.check in ("vm_power", "vm_nic") and "domain-controller" not in str(e.detail.get("role")):
            add(Finding(f"{e.target} ({e.detail.get('app')}) is {'powered off' if e.check == 'vm_power' else 'disconnected from the network'}",
                        e.summary, f"{e.detail.get('app')} loses this {e.detail.get('role')} instance.", "HIGH", "medium", "vcenter", e.target, [],
                        ["Check vCenter events for who/what changed the VM, then power it on / reconnect the adapter."]), [e])
