# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""Runs diagnostics against the platform's configured (real) VCF endpoints."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from vcf_enterprise_mcp.adapter.platform import PlatformMode
from vcf_enterprise_mcp.adapter.providers.vcenter import VCenterProvider
from vcf_enterprise_mcp.diagnostics.engine import Collector, Evidence, correlate


class DiagnosticsUnavailable(Exception):
    pass


def make_collector(platform: Any) -> Collector:
    if getattr(platform, "mode", None) != PlatformMode.REAL_VCF:
        raise DiagnosticsUnavailable(
            "Troubleshooting reads live appliance state, so it needs REAL_VCF mode (a lab, or the Acme organization simulator in "
            "tools/org_sim). The Digital Twin and unit-test modes have no service, certificate or task data to diagnose.")

    def factory(provider_type: str, base_url: str):
        auth = platform.auth_factory(provider_type, base_url) if platform.auth_factory else platform._auth_for(provider_type)
        # VCenterProvider supplies the generic request() used for every component.
        return VCenterProvider(endpoint_url=base_url, transport=platform.transport, auth=auth)

    sddc = platform.registry.resolve("domain.lifecycle").endpoint_url
    try:
        ops = platform.registry.resolve("telemetry.promql").endpoint_url
    except Exception:
        ops = None
    overrides = dict(getattr(platform, "endpoint_overrides", {}) or {})
    automation = None
    if getattr(platform, "automation", None):
        a_url, a_auth = platform.automation
        automation = (lambda: VCenterProvider(endpoint_url=a_url, transport=platform.transport, auth=a_auth), a_url)
    return Collector(factory, sddc, ops, lambda fqdn: overrides.get(fqdn) or f"https://{fqdn}", automation=automation)


def diagnose(platform: Any, symptom: str = "", domain: Optional[str] = None) -> Dict[str, Any]:
    collector = make_collector(platform)
    return correlate(collector.run(), symptom=symptom, domain=domain, inventory=collector.inventory)


def _compact(items: List[Evidence]) -> List[Dict[str, Any]]:
    return [{"id": e.id, "status": e.status, "target": e.target, "check": e.check, "summary": e.summary, "api": e.api} for e in items]


def check_component(platform: Any, component: str, target: Optional[str] = None) -> Dict[str, Any]:
    c = make_collector(platform)
    if component == "sddc_manager":
        c.sddc()
    elif component in ("vcenter", "nsx"):
        c.sddc()  # discovery
        c.items = []
        if component == "vcenter":
            vc_domain = {vc.get("fqdn"): d.get("name") for d in c.inventory["domains"] for vc in d.get("vcenters") or []}
            for vc in c.inventory["vcenters"]:
                if not target or target in vc.get("fqdn", ""):
                    c.vcenter(vc["fqdn"], vc_domain.get(vc["fqdn"], "?"))
        else:
            for n in c.inventory["nsx"]:
                if n.get("vipFqdn") and (not target or target in n["vipFqdn"]):
                    c.nsx(n["vipFqdn"])
    elif component == "vcf_operations":
        c.operations()
    else:
        raise ValueError("component must be one of sddc_manager, vcenter, nsx, vcf_operations")
    items = c.items
    problems = [e for e in items if e.status != "OK"]
    return {
        "component": component,
        "target_filter": target,
        "problems": _compact(problems),
        "ok_checks": [e.summary for e in items if e.status == "OK"],
        "note": "No problems found in these checks." if not problems else f"{len(problems)} problem(s) or unknown check(s).",
    }


def list_failed_tasks(platform: Any) -> Dict[str, Any]:
    c = make_collector(platform)
    c.sddc()
    tasks = [e for e in c.items if e.check in ("failed_task", "failed_tasks")]
    return {"failed_tasks": [{"name": e.target, "summary": e.summary, "task_id": e.detail.get("task_id"),
                              "error_codes": e.detail.get("error_codes"), "created": e.detail.get("created")}
                             for e in tasks if e.status == "FAIL"],
            "note": next((e.summary for e in tasks if e.status != "FAIL"), "")}


def list_alerts(platform: Any, include_warnings: bool = False) -> Dict[str, Any]:
    c = make_collector(platform)
    c.sddc()
    c.items = []
    for n in c.inventory["nsx"]:
        if n.get("vipFqdn"):
            c.nsx(n["vipFqdn"])
    c.operations()
    keep = {"alert", "alarm", "collector", "reachability", "background_alerts", "minor_alarms", "alerts", "node_status"}
    rows = [e for e in c.items if e.check in keep and (include_warnings or e.status != "OK" or e.check in ("background_alerts", "minor_alarms"))]
    return {"alerts": _compact(rows)}


# ---- application view --------------------------------------------------------------------------

def _network_map(c) -> Dict[str, Dict[str, Any]]:
    """network name -> how it is built (NSX overlay/VLAN segment, VPC subnet, or plain VDS port group) and its path out."""
    nsx_for_domain = {d.get("name"): (d.get("nsxtCluster") or {}).get("vipFqdn") for d in c.inventory["domains"]}
    detail = c.inventory.get("nsx_detail", {})
    out: Dict[str, Dict[str, Any]] = {}
    for fqdn, d in detail.items():
        t1s = {t.get("id"): t for t in d["tier1s"]}
        t0s = {t["id"]: t for t in d["tier0s"]}
        doms = [k for k, v in nsx_for_domain.items() if v == fqdn]
        for s in d["segments"]:
            name = s.get("display_name") or s.get("id")
            t1 = t1s.get(str(s.get("connectivity_path") or "").rsplit("/", 1)[-1])
            t0_id = str((t1 or {}).get("tier0_path") or "").rsplit("/", 1)[-1] or None
            t0 = t0s.get(t0_id) if t0_id else None
            kind = ("NSX VLAN-backed segment (VLAN " + ",".join(s.get("vlan_ids")) + ")") if s.get("vlan_ids") else "NSX overlay segment"
            out[name] = {"type": kind, "nsx": fqdn, "domains": doms, "gateway": (s.get("subnets") or [{}])[0].get("gateway_address"),
                         "tier1": (t1 or {}).get("id"), "tier1_has_tier0": bool(t0_id) if t1 else None, "tier0": t0_id,
                         "bgp_to_physical": [f"{n['address']} {n['peer']}: {n['state']}" for n in (t0 or {}).get("neighbors", [])],
                         "north_south": ("routed via " + f"{t1['id']} -> {t0_id} -> BGP" if t1 and t0_id else
                                         f"BROKEN: {t1['id']} has no Tier-0" if t1 else
                                         "none (isolated segment, by design for heartbeat/VLAN)" if not s.get("vlan_ids") else "physical VLAN gateway")}
        for sub in d["subnets"]:
            out[f"{sub['vpc']}/{sub['subnet']}"] = {"type": f"NSX VPC subnet ({sub['access_mode']})", "nsx": fqdn, "domains": doms, "project": sub["project"],
                                                   "vpc": sub["vpc"], "cidr": sub["cidr"], "ip_usage": f"{sub['used']}/{sub['total']}"}
    return out


def _vm_view(v, nets):
    return {"name": v["name"], "vcenter": v["vcenter"], "domain": v["domain"], "host": v.get("host"), "host_state": v.get("host_state"),
            "power_state": v.get("power_state"), "guest_os": v.get("guest_os"), "tags": v.get("tags"),
            "nics": [{"network": n.get("network"), "state": n.get("state"),
                      "network_type": nets.get(n.get("network"), {}).get("type", "vSphere distributed port group (VLAN-backed, no NSX overlay)")}
                     for n in v.get("nics", [])]}


def trace_application(platform: Any, app: str) -> Dict[str, Any]:
    c = make_collector(platform)
    items = c.run()
    needle = app.strip().lower()
    vms = [v for v in c.inventory.get("vms", []) if needle and (
        needle == str(v["tags"].get("Application", "")).lower() or needle in str(v["tags"].get("Cluster", "")).lower()
        or needle in v["name"].lower() or needle == str(v["tags"].get("AD-Forest", "")).lower())]
    if not vms:
        apps = sorted({v["tags"].get("Application") for v in c.inventory.get("vms", []) if v["tags"].get("Application")})
        return {"application": app, "matched_vms": [], "note": "No VM matches that application tag, cluster name, AD forest or VM name.",
                "known_applications": apps}
    nets = _network_map(c)
    used_nets = sorted({n.get("network") for v in vms for n in v.get("nics", []) if n.get("network")})
    names = {v["name"] for v in vms}
    rules = []
    for fqdn, d in c.inventory.get("nsx_detail", {}).items():
        for r in d["rules"]:
            if set(r.get("destination_vms") or []) & names or any(needle in g.lower() for g in r["sources"] + r["destinations"]):
                rules.append({k: r[k] for k in ("policy", "rule", "action", "sources", "destinations", "services", "changed_by", "changed_minutes_ago")} | {"nsx": fqdn})
    result = correlate(items, symptom=app, inventory=c.inventory)
    keys = names | set(used_nets) | {needle} | {v.get("host") for v in vms if v.get("host")}
    keys |= {nets[n].get("tier1") for n in used_nets if nets.get(n, {}).get("tier1")} | {nets[n].get("tier0") for n in used_nets if nets.get(n, {}).get("tier0")}
    keys = {str(k).lower() for k in keys if k}
    related = [f for f in result["findings"] if any(k in json.dumps(f).lower() for k in keys)]
    return {
        "application": app,
        "matched_vms": [_vm_view(v, nets) for v in sorted(vms, key=lambda v: v["name"])],
        "networks": {n: nets.get(n, {"type": "vSphere distributed port group (VLAN-backed, no NSX overlay)"}) for n in used_nets},
        "firewall_rules_touching_app": sorted(rules, key=lambda r: r["changed_minutes_ago"])[:15],
        "problems_affecting_app": related,
        "other_findings_elsewhere": [f["title"] for f in result["findings"] if f not in related][:5],
        "how_to_use": "problems_affecting_app are ranked; each cites evidence. Read-only; nothing was changed.",
    }


def list_networks(platform: Any, domain: Optional[str] = None) -> Dict[str, Any]:
    c = make_collector(platform)
    c.run()
    nets = _network_map(c)
    vc_nets: Dict[str, List[str]] = {}
    for v in c.inventory.get("vms", []):
        for n in v.get("nics", []):
            if n.get("network"):
                vc_nets.setdefault(n["network"], []).append(v["name"])
    rows = []
    for name in sorted(set(nets) | set(vc_nets)):
        info = nets.get(name, {"type": "vSphere distributed port group (VLAN-backed, no NSX overlay)"})
        doms = info.get("domains") or sorted({v["domain"] for v in c.inventory.get("vms", []) if name in [n.get("network") for n in v.get("nics", [])]})
        if domain and domain not in doms:
            continue
        rows.append({"name": name, **info, "domains": doms, "vm_count": len(vc_nets.get(name, []))})
    shared = [{"nsx": (d.get("nsxtCluster") or {}).get("vipFqdn"), "domain": d.get("name")} for d in c.inventory["domains"]]
    by_nsx: Dict[str, List[str]] = {}
    for s in shared:
        by_nsx.setdefault(s["nsx"], []).append(s["domain"])
    return {"nsx_managers": [{"nsx": k, "domains": v, "shared": len(v) > 1} for k, v in by_nsx.items()],
            "vcenters": [{"fqdn": vc.get("fqdn"), "version": vc.get("version")} for vc in c.inventory["vcenters"]],
            "networks": rows}
