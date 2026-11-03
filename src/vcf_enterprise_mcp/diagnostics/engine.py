# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Read-only troubleshooting for VCF 9.x: "why is this service down?"

1. Collect evidence from every appliance through documented 9.x APIs. vCenters and NSX
   clusters are discovered from SDDC Manager, so each workload domain is covered.
2. Correlate it with explicit rules into ranked findings: likely cause, what it breaks,
   the evidence, next steps and KB references.

Everything is a GET: nothing here changes VCF. A check that cannot run is reported as
UNKNOWN with the reason, never as healthy.
"""

from __future__ import annotations

import datetime as dt
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, List, Optional

from vcf_enterprise_mcp.adapter.connectivity import classify_connection_error
from vcf_enterprise_mcp.adapter.providers.base import BaseVCFProvider
from vcf_enterprise_mcp.diagnostics import deep
from vcf_enterprise_mcp.core.errors import SSRFViolationException
from vcf_enterprise_mcp.adapter.transport.errors import (
    TransportException,
    UpstreamAuthException,
    UpstreamResourceNotFoundException,
    UpstreamServerException,
    UpstreamTLSException,
)

OK, WARN, FAIL, UNKNOWN = "OK", "WARN", "FAIL", "UNKNOWN"
VC_CRITICAL_SERVICES = {"vpxd", "vpostgres", "sts", "lookupsvc", "vsphere-ui", "vapi-endpoint", "trustmanagement", "certificatemanagement"}


@dataclass
class Evidence:
    id: str
    component: str      # sddc_manager | vcenter | nsx | vcf_operations
    target: str         # FQDN or object name
    check: str
    status: str         # OK | WARN | FAIL | UNKNOWN
    summary: str
    api: str = ""
    detail: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    title: str
    cause: str
    impact: str
    severity: str       # CRITICAL | HIGH | MEDIUM | LOW | INFO (this MCP's own configuration)
    confidence: str     # high | medium | low
    component: str
    target: str
    evidence: List[str]
    next_steps: List[str]
    references: List[str] = field(default_factory=list)
    score: float = 0.0
    specific: bool = False  # workload/network-level root cause (ranks above generic appliance symptoms)


ProviderFactory = Callable[[str, str], BaseVCFProvider]  # (provider_type, base_url) -> provider with auth


def _parse_ts(value: Any) -> Optional[dt.datetime]:
    if not value:
        return None
    try:
        return dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _is_mcp_policy_block(exc: BaseException) -> bool:
    """True when this MCP's own SSRF/network allowlist refused the destination: not an appliance fault."""
    return isinstance(exc, SSRFViolationException) and classify_connection_error(exc).mcp_config_problem


def _describe_error(exc: Exception) -> str:
    text = str(exc)
    if isinstance(exc, SSRFViolationException):
        problem = classify_connection_error(exc)
        fix = f" Config: {problem.config_key}." if problem.config_key else ""
        label = "MCP configuration problem, not an appliance fault" if problem.mcp_config_problem else "name resolution failed from this machine"
        return f"not contacted ({label}): {problem.summary}{fix}"
    if isinstance(exc, UpstreamTLSException):
        if "expired" in text.lower():
            return "TLS handshake failed: the appliance's certificate has EXPIRED."
        if "hostname" in text.lower() or "doesn't match" in text.lower():
            return "TLS handshake failed: certificate name does not match the appliance FQDN."
        return "TLS handshake failed: certificate is not trusted (check the CA chain)."
    if isinstance(exc, UpstreamAuthException):
        code = exc.details.get("status_code")
        return f"Login/authorization failed (HTTP {code}): wrong or expired service-account password, locked account, or missing role."
    if isinstance(exc, UpstreamServerException):
        return f"Appliance returned HTTP {exc.details.get('status_code')} (service unavailable or failing)."
    return f"Could not reach the appliance ({type(exc).__name__})."


class Collector:
    def __init__(self, factory: ProviderFactory, sddc_url: str, ops_url: Optional[str], endpoint_for: Callable[[str], str],
                 now: Optional[dt.datetime] = None, automation: Optional[tuple] = None):
        self.factory = factory
        self.sddc_url = sddc_url
        self.ops_url = ops_url
        self.endpoint_for = endpoint_for
        self.now = now or dt.datetime.now(dt.timezone.utc)
        self.automation_endpoint = automation  # (provider factory, base_url) for VCF Automation, optional
        self.items: List[Evidence] = []
        self.inventory: Dict[str, Any] = {"domains": [], "vcenters": [], "nsx": []}

    def add(self, component, target, check, status, summary, api="", **detail) -> Evidence:
        ev = Evidence(f"E{len(self.items) + 1}", component, target, check, status, summary, api, detail)
        self.items.append(ev)
        return ev

    def reach_fail(self, component, target, summary, api, **detail) -> Evidence:
        """Records a failed reachability check. When this MCP's own allowlist blocked the call it is a configuration
        problem (check=mcp_config, status UNKNOWN), never a FAIL that would be reported as an appliance fault."""
        exc = detail.pop("_exc", None)
        if exc is not None and _is_mcp_policy_block(exc):
            problem = classify_connection_error(exc, detail.get("url", ""))
            return self.add(component, target, "mcp_config", UNKNOWN, summary, api, cause=problem.cause, config_key=problem.config_key,
                            fix=problem.fix, **{k: v for k, v in detail.items() if k != "url"})
        return self.add(component, target, "reachability", FAIL, summary, api, **{k: v for k, v in detail.items() if k != "url"})

    def _get(self, prov: BaseVCFProvider, path: str, params=None):
        resp = prov.request("GET", path, params=params)
        return resp.json()

    # ---- SDDC Manager -----------------------------------------------------------------

    def sddc(self) -> None:
        target = "sddc-manager"
        try:
            prov = self.factory("sddc_manager", self.sddc_url)
            domains = (self._get(prov, "/v1/domains") or {}).get("elements", [])
        except Exception as exc:
            self.reach_fail("sddc_manager", target, "SDDC Manager: " + _describe_error(exc), "GET /v1/domains", _exc=exc, url=self.sddc_url)
            return
        self.inventory["domains"] = domains
        for d in domains:
            st = str(d.get("status", "")).upper()
            self.add("sddc_manager", d.get("name", d.get("id")), "domain_status", OK if st == "ACTIVE" else FAIL,
                     f"Workload domain {d.get('name')} status {st}.", "GET /v1/domains")
        try:
            self.inventory["vcenters"] = (self._get(prov, "/v1/vcenters") or {}).get("elements", [])
        except Exception as exc:
            self.add("sddc_manager", target, "vcenter_inventory", UNKNOWN, "Could not list vCenters: " + _describe_error(exc), "GET /v1/vcenters")
        try:
            self.inventory["nsx"] = (self._get(prov, "/v1/nsxt-clusters") or {}).get("elements", [])
        except Exception as exc:
            self.add("sddc_manager", target, "nsx_inventory", UNKNOWN, "Could not list NSX clusters: " + _describe_error(exc), "GET /v1/nsxt-clusters")

        try:
            failed = (self._get(prov, "/v1/tasks", {"taskStatus": "FAILED"}) or {}).get("elements", [])
            open_failures = [t for t in failed if str(t.get("resolutionStatus", "")).upper() != "RESOLVED"]
            for t in open_failures[:10]:
                msgs = [e.get("message", "") for e in t.get("errors") or []]
                codes = [e.get("errorCode", "") for e in t.get("errors") or []]
                self.add("sddc_manager", t.get("name", t.get("id")), "failed_task", FAIL,
                         f"SDDC Manager task '{t.get('name')}' FAILED: {'; '.join(msgs) or 'no error message'}",
                         "GET /v1/tasks?taskStatus=FAILED", task_id=t.get("id"), error_codes=codes, messages=msgs,
                         created=t.get("creationTimestamp"))
            if not open_failures:
                self.add("sddc_manager", target, "failed_tasks", OK, "No unresolved failed SDDC Manager tasks.", "GET /v1/tasks?taskStatus=FAILED")
        except Exception as exc:
            self.add("sddc_manager", target, "failed_tasks", UNKNOWN, "Could not read tasks: " + _describe_error(exc), "GET /v1/tasks")

        for d in domains:
            try:
                certs = (self._get(prov, f"/v1/domains/{d['id']}/resource-certificates") or {}).get("elements", [])
            except Exception as exc:
                self.add("sddc_manager", d.get("name"), "certificates", UNKNOWN, "Could not read certificates: " + _describe_error(exc),
                         f"GET /v1/domains/{d.get('id')}/resource-certificates")
                continue
            for c in certs:
                days = c.get("numberOfDaysToExpire")
                status = str(c.get("expirationStatus", "")).upper()
                if status == "EXPIRED" or (isinstance(days, int) and days < 0):
                    st, msg = FAIL, f"Certificate for {c.get('resourceName')} ({c.get('resourceType')}) EXPIRED on {c.get('notAfter')}."
                elif isinstance(days, int) and days < 30:
                    st, msg = WARN, f"Certificate for {c.get('resourceName')} expires in {days} days."
                else:
                    st, msg = OK, f"Certificate for {c.get('resourceName')} valid ({days} days left)."
                self.add("sddc_manager", c.get("resourceName", "?"), "certificate", st, msg,
                         f"GET /v1/domains/{d.get('id')}/resource-certificates", resource_type=c.get("resourceType"), domain=d.get("name"))

        try:
            creds = (self._get(prov, "/v1/credentials") or {}).get("elements", [])
            bad = [c for c in creds if str((c.get("expiry") or {}).get("status", "")).upper() == "EXPIRED"
                   or str((c.get("expiry") or {}).get("connectivityStatus", "")).upper() == "ERROR"]
            for c in bad:
                exp = c.get("expiry") or {}
                self.add("sddc_manager", (c.get("resource") or {}).get("resourceName", "?"), "credential", FAIL,
                         f"Service account {c.get('username')} on {(c.get('resource') or {}).get('resourceName')}: "
                         f"status {exp.get('status')}, connectivity {exp.get('connectivityStatus')}. {exp.get('connectivityErrorDetails') or ''}".strip(),
                         "GET /v1/credentials", username=c.get("username"))
            if not bad:
                self.add("sddc_manager", target, "credentials", OK, "No expired or failing service-account credentials.", "GET /v1/credentials")
        except UpstreamAuthException:
            self.add("sddc_manager", target, "credentials", UNKNOWN,
                     "Credential status not checked: SDDC Manager's credentials API needs the ADMIN role (this account is least-privilege). "
                     "Failed password-rotation tasks above still reveal credential problems.", "GET /v1/credentials")
        except Exception as exc:
            self.add("sddc_manager", target, "credentials", UNKNOWN, "Could not read credentials: " + _describe_error(exc), "GET /v1/credentials")

        try:
            ntp = (self._get(prov, "/v1/system/ntp-configuration") or {}).get("ntpServers", [])
            self.add("sddc_manager", target, "ntp", OK if ntp else WARN,
                     "SDDC Manager NTP servers configured." if ntp else "SDDC Manager has no NTP servers configured.", "GET /v1/system/ntp-configuration")
        except Exception:
            pass

    # ---- vCenter --------------------------------------------------------------------

    def vcenter(self, fqdn: str, domain: str) -> None:
        url = self.endpoint_for(fqdn)
        try:
            prov = self.factory("vcenter", url)
            self._get(prov, "/api/session")
        except Exception as exc:
            self.reach_fail("vcenter", fqdn, f"vCenter {fqdn} (domain {domain}): " + _describe_error(exc), "POST /api/session",
                            _exc=exc, url=url, domain=domain, error=type(exc).__name__)
            return
        self.add("vcenter", fqdn, "reachability", OK, f"vCenter {fqdn} reachable; login OK.", "POST /api/session", domain=domain)
        for part in ("system", "storage", "mem", "load", "database"):
            try:
                level = str(self._get(prov, f"/api/appliance/health/{part}") or "gray").lower()
            except Exception as exc:
                self.add("vcenter", fqdn, f"health_{part}", UNKNOWN, f"{fqdn} {part} health unavailable: {_describe_error(exc)}",
                         f"GET /api/appliance/health/{part}", domain=domain)
                continue
            st = {"green": OK, "yellow": WARN, "orange": FAIL, "red": FAIL}.get(level, UNKNOWN)
            label = {"storage": "disk space", "mem": "memory", "load": "CPU load", "database": "database", "system": "overall system"}[part]
            self.add("vcenter", fqdn, f"health_{part}", st, f"{fqdn} appliance {label} health is {level.upper()}.",
                     f"GET /api/appliance/health/{part}", domain=domain, level=level)
        try:
            services = self._get(prov, "/api/vcenter/services") or {}
            stopped = []
            for name, info in services.items():
                state, health = str(info.get("state", "")).upper(), str(info.get("health", "")).upper()
                msgs = [m.get("default_message", "") for m in info.get("health_messages") or []]
                if str(info.get("startup_type", "")).upper() == "AUTOMATIC" and state != "STARTED":
                    stopped.append(name)
                    self.add("vcenter", fqdn, "service", FAIL if name in VC_CRITICAL_SERVICES else WARN,
                             f"vCenter service '{name}' on {fqdn} is {state}. {' '.join(msgs)}".strip(), "GET /api/vcenter/services",
                             domain=domain, service=name, messages=msgs)
                elif health in ("DEGRADED", "UNHEALTHY"):
                    self.add("vcenter", fqdn, "service", WARN if health == "DEGRADED" else FAIL,
                             f"vCenter service '{name}' on {fqdn} is running but {health}. {' '.join(msgs)}".strip(),
                             "GET /api/vcenter/services", domain=domain, service=name, messages=msgs)
            if not stopped:
                self.add("vcenter", fqdn, "services", OK, f"All automatic vCenter services on {fqdn} are running.", "GET /api/vcenter/services", domain=domain)
        except Exception as exc:
            self.add("vcenter", fqdn, "services", UNKNOWN, f"Could not list services on {fqdn}: {_describe_error(exc)}", "GET /api/vcenter/services", domain=domain)
        try:
            tls = self._get(prov, "/api/vcenter/certificate-management/vcenter/tls") or {}
            valid_to = _parse_ts(tls.get("valid_to"))
            if valid_to:
                days = (valid_to - self.now).days
                st = FAIL if days < 0 else (WARN if days < 30 else OK)
                self.add("vcenter", fqdn, "tls_certificate", st, f"{fqdn} machine SSL certificate {'EXPIRED' if days < 0 else f'valid for {days} days'}.",
                         "GET /api/vcenter/certificate-management/vcenter/tls", domain=domain)
        except Exception:
            pass
        try:
            ntp = self._get(prov, "/api/appliance/ntp") or []
            self.add("vcenter", fqdn, "ntp", OK if ntp else WARN,
                     f"{fqdn} NTP servers: {', '.join(ntp)}." if ntp else f"{fqdn} has NO NTP servers configured: clock drift breaks SSO tokens.",
                     "GET /api/appliance/ntp", domain=domain)
        except Exception:
            pass
        hosts = None
        try:
            hosts = self._get(prov, "/api/vcenter/host") or []
            bad = [h for h in hosts if str(h.get("connection_state", "")).upper() != "CONNECTED"]
            for h in bad:
                self.add("vcenter", h.get("name", "?"), "host_connection", FAIL,
                         f"ESXi host {h.get('name')} in vCenter {fqdn} is {h.get('connection_state')}.", "GET /api/vcenter/host",
                         domain=domain, vcenter=fqdn)
            if hosts and not bad:
                self.add("vcenter", fqdn, "hosts", OK, f"All {len(hosts)} ESXi hosts in {fqdn} are connected.", "GET /api/vcenter/host", domain=domain)
        except UpstreamServerException as exc:
            self.add("vcenter", fqdn, "inventory_api", FAIL, f"{fqdn} inventory API unavailable (HTTP {exc.details.get('status_code')}): "
                     "vCenter cannot serve hosts/VMs/datastores, usually because vpxd is down.", "GET /api/vcenter/host", domain=domain)
            return
        except Exception as exc:
            self.add("vcenter", fqdn, "hosts", UNKNOWN, f"Could not list hosts: {_describe_error(exc)}", "GET /api/vcenter/host", domain=domain)
        try:
            for ds in self._get(prov, "/api/vcenter/datastore") or []:
                cap, free = ds.get("capacity") or 0, ds.get("free_space") or 0
                if not cap:
                    continue
                pct = 100.0 * free / cap
                st = FAIL if pct < 5 else (WARN if pct < 15 else OK)
                if st != OK:
                    self.add("vcenter", ds.get("name", "?"), "datastore_capacity", st,
                             f"Datastore {ds.get('name')} in {fqdn} has only {pct:.1f}% free.", "GET /api/vcenter/datastore",
                             domain=domain, vcenter=fqdn, free_pct=round(pct, 1))
        except Exception:
            pass
        if hosts:
            deep.collect_workloads(self, prov, fqdn, domain, hosts)

    # ---- NSX ----------------------------------------------------------------------------

    def nsx(self, fqdn: str) -> None:
        url = self.endpoint_for(fqdn)
        try:
            prov = self.factory("nsx", url)
            status = self._get(prov, "/api/v1/cluster/status") or {}
        except Exception as exc:
            self.reach_fail("nsx", fqdn, f"NSX Manager {fqdn}: " + _describe_error(exc), "GET /api/v1/cluster/status",
                            _exc=exc, url=url, error=type(exc).__name__)
            return
        mgmt = status.get("mgmt_cluster_status") or {}
        ctrl = status.get("control_cluster_status") or {}
        offline = [n.get("mgmt_cluster_listen_ip_address") or n.get("uuid") for n in mgmt.get("offline_nodes") or []]
        mst, cst = str(mgmt.get("status", "UNKNOWN")).upper(), str(ctrl.get("status", "UNKNOWN")).upper()
        st = OK if mst == "STABLE" and cst == "STABLE" else (WARN if mst == "DEGRADED" else FAIL)
        self.add("nsx", fqdn, "cluster_status", st,
                 f"NSX {fqdn}: management cluster {mst}, control cluster {cst}" + (f"; offline nodes: {', '.join(offline)}." if offline else "."),
                 "GET /api/v1/cluster/status", offline_nodes=offline)
        try:
            alarms = (self._get(prov, "/api/v1/alarms", {"status": "OPEN"}) or {}).get("results", [])
            for a in alarms:
                sev = str(a.get("severity", "")).upper()
                st = FAIL if sev == "CRITICAL" else (WARN if sev == "HIGH" else OK)
                if st != OK:
                    self.add("nsx", a.get("node_display_name", fqdn), "alarm", st,
                             f"NSX {sev} alarm on {a.get('node_display_name')}: {a.get('description')} Recommended: {a.get('recommended_action')}",
                             "GET /api/v1/alarms?status=OPEN", feature=a.get("feature_name"), event=a.get("event_type"), nsx=fqdn)
            minor = [a for a in alarms if str(a.get("severity", "")).upper() not in ("CRITICAL", "HIGH")]
            if minor:
                self.add("nsx", fqdn, "minor_alarms", OK, f"{len(minor)} low/medium NSX alarm(s) on {fqdn} (e.g. {minor[0].get('event_type')}).",
                         "GET /api/v1/alarms?status=OPEN")
        except Exception as exc:
            self.add("nsx", fqdn, "alarms", UNKNOWN, f"Could not read NSX alarms: {_describe_error(exc)}", "GET /api/v1/alarms")
        deep.collect_nsx_policy(self, prov, fqdn)

    # ---- VCF Automation ---------------------------------------------------------------

    def automation(self) -> None:
        if not self.automation_endpoint:
            return
        make, url = self.automation_endpoint
        try:
            deps = (self._get(make(), "/deployment/api/deployments") or {}).get("content", [])
        except Exception as exc:
            self.add("vcf_automation", url, "deployments", UNKNOWN, f"Could not read VCF Automation deployments: {_describe_error(exc)}",
                     "GET /deployment/api/deployments")
            return
        failed = [d for d in deps if "FAILED" in str(d.get("status", "")).upper()
                  and (self.now - (_parse_ts(d.get("createdAt")) or self.now)).total_seconds() < 86400]
        for d in failed:
            self.add("vcf_automation", d.get("name"), "failed_deployment", FAIL,
                     f"VCF Automation deployment {d.get('name')} ({d.get('status')}): {(d.get('lastRequest') or {}).get('details', '')}",
                     "GET /deployment/api/deployments", project=d.get("projectId"))
        if not failed:
            self.add("vcf_automation", url, "deployments", OK, "No failed VCF Automation deployments in the last 24 h.", "GET /deployment/api/deployments")

    # ---- VCF Operations -----------------------------------------------------------------

    def operations(self) -> None:
        if not self.ops_url:
            self.add("vcf_operations", "vcf-operations", "configured", UNKNOWN, "VCF Operations endpoint not configured.")
            return
        try:
            prov = self.factory("vcf_operations", self.ops_url)
            node = self._get(prov, "/suite-api/api/deployment/node/status") or {}
        except Exception as exc:
            self.reach_fail("vcf_operations", "vcf-operations", "VCF Operations: " + _describe_error(exc),
                            "GET /suite-api/api/deployment/node/status", _exc=exc, url=self.ops_url)
            return
        st = str(node.get("status", "")).upper()
        self.add("vcf_operations", "vcf-operations", "node_status", OK if st == "ONLINE" else FAIL, f"VCF Operations node status {st}.",
                 "GET /suite-api/api/deployment/node/status")
        try:
            for c in (self._get(prov, "/suite-api/api/collectors") or {}).get("collector", []):
                if str(c.get("state", "")).upper() != "UP":
                    self.add("vcf_operations", c.get("name", "collector"), "collector", FAIL,
                             f"VCF Operations collector/cloud proxy {c.get('name')} is {c.get('state')}: metrics and alerts for the objects it collects are STALE or missing.",
                             "GET /suite-api/api/collectors")
        except Exception:
            pass
        try:
            alerts = [a for a in (self._get(prov, "/suite-api/api/alerts") or {}).get("alerts", [])
                      if str(a.get("status", "ACTIVE")).upper() == "ACTIVE"]
        except Exception as exc:
            self.add("vcf_operations", "vcf-operations", "alerts", UNKNOWN, f"Could not read alerts: {_describe_error(exc)}", "GET /suite-api/api/alerts")
            return
        noise = []
        for a in alerts:
            lvl = str(a.get("alertLevel", "")).upper()
            if lvl in ("CRITICAL", "IMMEDIATE"):
                self.add("vcf_operations", a.get("resourceName", "?"), "alert", FAIL if lvl == "CRITICAL" else WARN,
                         f"VCF Operations {lvl} alert on {a.get('resourceName')}: {a.get('alertDefinitionName')}.", "GET /suite-api/api/alerts",
                         alert=a.get("alertDefinitionName"))
            else:
                noise.append(a)
        if noise:
            kinds: Dict[str, int] = {}
            for a in noise:
                kinds[a.get("alertDefinitionName", "?")] = kinds.get(a.get("alertDefinitionName", "?"), 0) + 1
            top = ", ".join(f"{k} x{v}" for k, v in sorted(kinds.items(), key=lambda kv: -kv[1])[:3])
            self.add("vcf_operations", "vcf-operations", "background_alerts", OK,
                     f"{len(noise)} WARNING/INFO alerts (background noise, usually unrelated to outages): {top}.", "GET /suite-api/api/alerts")

    # ---- run ------------------------------------------------------------------------------

    def run(self) -> List[Evidence]:
        self.sddc()
        vc_domain = {}
        for d in self.inventory["domains"]:
            for vc in d.get("vcenters") or []:
                vc_domain[vc.get("fqdn")] = d.get("name")
        for vc in self.inventory["vcenters"]:
            self.vcenter(vc.get("fqdn"), vc_domain.get(vc.get("fqdn"), (vc.get("domain") or {}).get("id", "?")))
        for n in self.inventory["nsx"]:
            if n.get("vipFqdn"):
                self.nsx(n["vipFqdn"])
        self.operations()
        self.automation()
        return self.items


# ---- correlation -----------------------------------------------------------------------

KB_DEPOT = "https://knowledge.broadcom.com/external/article/443947"


def correlate(items: List[Evidence], symptom: str = "", domain: Optional[str] = None,
              inventory: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    fails = [e for e in items if e.status == FAIL]
    warns = [e for e in items if e.status == WARN]
    unknown = [e for e in items if e.status == UNKNOWN]
    findings: List[Finding] = []
    used: set = set()

    def by(component=None, check=None, target=None, pred=None, pool=None):
        out = []
        for e in (pool if pool is not None else fails + warns):
            if component and e.component != component:
                continue
            if check and e.check != check:
                continue
            if target and e.target != target:
                continue
            if pred and not pred(e):
                continue
            out.append(e)
        return out

    def add(f: Finding, evs: List[Evidence]):
        f.evidence = [e.id for e in evs]
        used.update(f.evidence)
        findings.append(f)

    # Certificates: an expired cert shows up as a TLS failure plus an EXPIRED inventory entry.
    for e in by(check="reachability", pred=lambda e: "EXPIRED" in e.summary):
        inv = by(component="sddc_manager", check="certificate", target=e.target)
        doms = sorted({i.detail.get("domain") for i in inv if i.detail.get("domain")})
        blast = f" This appliance serves workload domains {', '.join(doms)}: all of them are affected." if len(doms) > 1 else ""
        add(Finding(f"Expired certificate on {e.target}", f"The TLS certificate of {e.target} has expired, so clients (SDDC Manager, vCenter, "
                    "the MCP, browsers) refuse to connect.", f"Everything that talks to {e.target} fails: UI/API logins, integrations and lifecycle tasks.{blast}",
                    "CRITICAL", "high", e.component, e.target, [], [f"Replace the certificate of {e.target} (SDDC Manager > Security > Certificate Management, "
                    "or the component's own certificate tooling).", "Confirm the new certificate chains to the trusted CA and covers the FQDN."]), [e] + inv)
    for e in by(component="sddc_manager", check="certificate", pool=fails):
        if e.id not in used:
            add(Finding(f"Expired certificate on {e.target}", e.summary, f"Connections to {e.target} fail TLS validation.", "CRITICAL", "high",
                        "sddc_manager", e.target, [], [f"Replace the certificate of {e.target}."]), [e])
    for e in by(check="tls_certificate", pool=fails):
        if e.id not in used:
            add(Finding(f"Expired certificate on {e.target}", e.summary, "Clients refuse TLS connections.", "CRITICAL", "high", "vcenter", e.target, [],
                        [f"Renew the machine SSL certificate of {e.target}."]), [e])

    # vCenter disk full -> database -> vpxd chain.
    for disk in by(component="vcenter", check="health_storage", pool=fails):
        chain = by(component="vcenter", target=disk.target, pred=lambda e: e.check in ("service", "health_system", "inventory_api", "health_database"))
        add(Finding(f"vCenter {disk.target} appliance disk is full", f"A partition on the vCenter appliance {disk.target} is out of space; "
                    "services that write to disk (vpostgres, then vpxd) stop.", f"vCenter {disk.target} (domain {disk.detail.get('domain')}) is down or degraded: "
                    "no inventory, provisioning or lifecycle operations in that domain.", "CRITICAL", "high", "vcenter", disk.target, [],
                    ["Check partition usage in the VAMI (https://<vcenter>:5480 > Monitor > Disks) or 'df -h' on the appliance.",
                     "Free space (rotate/delete old logs, core dumps) or extend the disk, then start vpostgres and vpxd (service-control --start --all)."]), [disk] + chain)

    # vCenter critical services stopped (not explained by disk).
    for svc in by(component="vcenter", check="service", pool=fails):
        if svc.id in used:
            continue
        related = by(component="vcenter", target=svc.target, pred=lambda e: e.check in ("inventory_api", "health_system")) + \
            by(component="sddc_manager", check="failed_task", pred=lambda e: svc.target in e.summary)
        name = svc.detail.get("service")
        add(Finding(f"vCenter service '{name}' stopped on {svc.target}", svc.summary,
                    f"vCenter {svc.target} (domain {svc.detail.get('domain')}) cannot serve inventory or management operations; "
                    "SDDC Manager workflows against this domain fail.", "CRITICAL", "high", "vcenter", svc.target, [],
                    [f"Check the service in the VAMI (https://{svc.target}:5480 > Services) or run 'service-control --status {name}' on the appliance.",
                     f"Review /var/log/vmware/{name}/ for the crash reason before restarting ('service-control --start {name}')."]),
            [svc] + related)

    # NSX cluster degraded.
    for e in by(component="nsx", check="cluster_status"):
        alarms = by(component="nsx", check="alarm", pred=lambda a: a.detail.get("nsx") == e.target)
        nodes = ", ".join(e.detail.get("offline_nodes") or []) or "a manager node"
        add(Finding(f"NSX Manager cluster {e.target} degraded", f"NSX manager node(s) {nodes} are offline; the cluster lost redundancy.",
                    "Configuration changes may fail or be slow; a second node failure would make the cluster unavailable.",
                    "HIGH", "high", "nsx", e.target, [], [f"Check power, network and disk of {nodes} (vCenter console, 'get cluster status' on a healthy node).",
                                                          "Do not make NSX changes until the cluster is STABLE again."]), [e] + alarms)

    # ESXi hosts disconnected.
    hosts = by(check="host_connection", pool=fails)
    if hosts:
        vc = hosts[0].detail.get("vcenter")
        on_hosts = sorted(v["name"] for v in (inventory or {}).get("vms", []) if v.get("host") in {h.target for h in hosts})
        alerts = by(component="vcf_operations", check="alert", pred=lambda a: any(h.target == a.target for h in hosts))
        add(Finding(f"{len(hosts)} ESXi host(s) not responding in {vc}", "Hosts " + ", ".join(h.target for h in hosts) + " lost connection to vCenter.",
                    "VMs on these hosts can't be managed; HA may restart them elsewhere; cluster capacity is reduced."
                    + (f" VMs on them: {', '.join(on_hosts)}." if on_hosts else ""), "CRITICAL", "high", "vcenter",
                    ", ".join(h.target for h in hosts), [], ["Check host management network/power (iDRAC/iLO), then reconnect the host in vCenter.",
                                                            "Check 'hostd'/'vpxa' on the host if it is reachable."]), hosts + alerts)

    # Credentials.
    creds = by(component="sddc_manager", check="credential", pool=fails)
    rot = by(component="sddc_manager", check="failed_task",
             pred=lambda e: any("CREDENTIAL" in c for c in e.detail.get("error_codes", [])) or "password" in e.summary.lower())
    if creds or rot:
        tgt = (creds or rot)[0].target
        add(Finding("Service-account password expired or rejected", "A VCF service account's password has expired or no longer works "
                    "(credential rotation failed).", "SDDC Manager and integrations can no longer authenticate to the component; scheduled "
                    "rotations, backups and lifecycle tasks fail.", "HIGH", "high" if creds else "medium", "sddc_manager", tgt, [],
                    ["In SDDC Manager > Security > Password Management, remediate the account (set the current password) or rotate it.",
                     "Then retry the failed task."]), creds + rot)

    # Depot connectivity.
    depot = by(component="sddc_manager", check="failed_task", pred=lambda e: "depot" in e.summary.lower() or any("DEPOT" in c for c in e.detail.get("error_codes", [])))
    if depot:
        add(Finding("SDDC Manager cannot reach the software depot", "Bundle downloads/metadata refresh fail: the online depot is unreachable "
                    "(proxy, firewall or DNS).", "Upgrades and patches cannot be downloaded; lifecycle is blocked (running workloads are not affected).",
                    "MEDIUM", "high", "sddc_manager", "sddc-manager", [], ["Check proxy settings and that dl.broadcom.com is reachable from SDDC Manager.",
                                                                           "Retry the download after fixing connectivity."], [KB_DEPOT]), depot)

    # Other failed tasks.
    for e in by(component="sddc_manager", check="failed_task", pool=fails):
        if e.id not in used:
            add(Finding(f"SDDC Manager task failed: {e.target}", e.summary, "The workflow did not complete.", "MEDIUM", "medium", "sddc_manager",
                        e.target, [], ["Open the task in SDDC Manager > Tasks for sub-task details and retry once the cause is fixed."]), [e])

    # Datastore capacity.
    for e in by(check="datastore_capacity", pool=fails):
        alerts = by(component="vcf_operations", check="alert", target=e.target)
        add(Finding(f"Datastore {e.target} is almost full", e.summary, "New VMs, snapshots and VM power-on with swap files fail; running VMs "
                    "may pause when space runs out.", "CRITICAL", "high", "vcenter", e.target, [],
                    ["Free space (old snapshots, orphaned VMDKs) or add capacity; check vSAN capacity in vCenter > Cluster > Monitor > vSAN."]), [e] + alerts)

    # Monitoring blind spot.
    for e in by(component="vcf_operations", check="collector", pool=fails):
        add(Finding(f"VCF Operations collector {e.target} is down", e.summary, "Dashboards and alerts are stale: problems in the objects it collects "
                    "will NOT raise alerts. The alert list cannot be trusted until it is back.", "HIGH", "high", "vcf_operations", e.target, [],
                    ["Check the cloud proxy VM's power and network; restart collector services from the VCF Operations admin UI."]),
            [e] + by(component="vcf_operations", check="alert", target=e.target))

    # Time sync.
    ntp = by(check="ntp", pool=warns)
    skew = by(check="service", pred=lambda e: "clock skew" in e.summary.lower() or "time" in e.summary.lower() and "sts" in e.summary)
    for n in ntp:
        rel = [s for s in skew if s.target == n.target]
        add(Finding(f"Time synchronization missing on {n.target}", n.summary + (" " + rel[0].summary if rel else ""),
                    "Clock drift breaks SSO token validation: logins and service-to-service authentication fail intermittently.",
                    "HIGH" if rel else "MEDIUM", "high" if rel else "medium", n.component, n.target, [],
                    ["Configure NTP on the appliance (VAMI > Time) using the corporate NTP servers; verify time on all VCF components."]), [n] + rel)

    # Workload- and network-level causes (BGP, Tier-1 uplinks, DFW changes, VPC IPs, DCs, clustered nodes, quarantine).
    before = len(findings)
    deep.correlate_deep(items, by, add, Finding, inventory or {})
    for f in findings[before:]:
        f.specific = True

    # This MCP's own network policy blocked some appliances. Say so plainly: it is not an appliance fault and
    # nothing about those appliances could be checked.
    cfg_blocked = by(check="mcp_config", pool=unknown)
    if cfg_blocked:
        targets = ", ".join(e.target for e in cfg_blocked)
        keys = sorted({e.detail.get("config_key") for e in cfg_blocked if e.detail.get("config_key")})
        fixes = sorted({e.detail.get("fix") for e in cfg_blocked if e.detail.get("fix")})
        add(Finding(f"MCP configuration problem: {len(cfg_blocked)} appliance(s) not contacted", 
                    "This MCP's own network allowlist (not the appliance) refused to contact: " + targets + ". The appliances may be perfectly healthy; "
                    "nothing about them was checked.",
                    "Inventory and troubleshooting results for these appliances are missing, so this diagnosis is incomplete.",
                    "INFO", "high", cfg_blocked[0].component, targets, [],
                    ["Edit the MCP config file (" + (", ".join("vcf." + k.split(".")[-1] for k in keys) or "vcf.allowed_dns_suffixes") + "), or run vcf_setup and answer "
                     "its network question." + ("  Suggested change: " + " | ".join(f.replace(chr(10), ' ') for f in fixes) if fixes else ""),
                     "Names that do not resolve from this machine can be mapped to a reachable address with vcf.endpoint_overrides."]), cfg_blocked)

    # Remaining critical alerts / failures not explained above. An alert on an object that already
    # has a finding is supporting evidence for it, not a separate problem.
    for e in fails + warns:
        if e.id in used or e.check in ("ntp",):
            continue
        if e.component == "vcf_operations" and e.check == "alert":
            owner = next((f for f in findings if e.target and (e.target == f.target or e.target in f.target or e.target in f.cause)), None)
            if owner:
                owner.evidence.append(e.id)
                used.add(e.id)
                continue
        sev = "HIGH" if e.status == FAIL else "LOW"
        add(Finding(e.summary.split(":")[0][:90], e.summary, "See evidence.", sev, "medium" if e.status == FAIL else "low",
                    e.component, e.target, [], ["Investigate this component directly."]), [e])

    # Ranking: severity, confidence, and match with the reported symptom / domain.
    words = {w for w in re.findall(r"[a-z0-9\-\.]+", (symptom or "").lower()) if len(w) > 2}
    sev_w = {"CRITICAL": 40, "HIGH": 30, "MEDIUM": 20, "LOW": 5, "INFO": 1}
    conf_w = {"high": 6, "medium": 3, "low": 0}
    for f in findings:
        text = f"{f.title} {f.cause} {f.impact} {f.target}".lower()
        f.score = sev_w[f.severity] + conf_w[f.confidence] + 2 * sum(1 for w in words if w in text)
        if domain and domain.lower() in text:
            f.score += 8
        if f.specific:
            f.score += 4
    findings.sort(key=lambda f: -f.score)

    checked = len(items)
    healthy = sum(1 for e in items if e.status == OK)
    blind = [e.summary for e in unknown] + [f.cause for f in findings if f.component == "vcf_operations" and "collector" in f.title.lower()]
    if findings and findings[0].severity == "INFO":
        summary = f"{findings[0].title}. {findings[0].cause} No appliance fault was found in the checks that could run."
    elif findings:
        top = findings[0]
        summary = f"Most likely cause: {top.title}. {top.impact}"
    else:
        summary = ("No faults found in the checks that ran." + (" Some checks could not run (see could_not_check), so this is not a clean bill of health."
                                                                 if unknown else ""))
    return {
        "summary": summary,
        "findings": [{k: v for k, v in asdict(f).items() if k not in ("score", "specific")} for f in findings[:8]],
        "could_not_check": [e.summary for e in unknown],
        "monitoring_caveats": blind[len(unknown):],
        "checks_run": checked,
        "checks_ok": healthy,
        "evidence": [asdict(e) for e in items if e.status != OK][:40],
        "how_to_use": "Findings are ranked; the first is the most likely cause. Each lists the evidence ids it is based on. "
                      "Everything was read-only; nothing was changed.",
    }
