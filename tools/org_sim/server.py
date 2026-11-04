# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
HTTPS simulator for a VCF organization model: Acme Corp (org_model.py) or the Northwind
Group enterprise (enterprise_model.py, with VCF Automation).

Each appliance (SDDC Manager, vCenters, NSX Managers, VCF Operations, VCF Automation) listens on
its own localhost port, dual-stack, with its own certificate issued by a throwaway CA.
Faults behave like the real products where it matters for troubleshooting:
- an expired certificate is served for real, so clients fail the TLS handshake;
- with vpxd stopped, vCenter inventory APIs return 503 while appliance APIs still answer;
- SDDC Manager's credential API is ADMIN-only, so a least-privilege account gets 403.

    python3 tools/org_sim/server.py <state-dir> <scenario> [port-offset] [acme|enterprise]

Writes <state-dir>/ca.pem, endpoints.json and requests.jsonl (method, path, status, user;
never passwords or tokens). The password every account accepts is read from
<state-dir>/password.
"""

from __future__ import annotations

import base64
import datetime as dt
import ipaddress
import json
import re
import secrets
import socket
import ssl
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import importlib  # noqa: E402

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID  # noqa: E402

SDDC_ADMINS = {"admin@local", "administrator@vsphere.local"}
VC_ADMINS = {"administrator@vsphere.local", "root"}


class CA:
    def __init__(self, state: Path):
        self.state = state
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Acme Issuing CA 01 (simulated)")])
        now = dt.datetime.now(dt.timezone.utc)
        self.cert = (x509.CertificateBuilder().subject_name(self.name).issuer_name(self.name).public_key(self.key.public_key())
                     .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=400))
                     .not_valid_after(now + dt.timedelta(days=400))
                     .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                     .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True)
                     .add_extension(x509.SubjectKeyIdentifier.from_public_key(self.key.public_key()), critical=False)
                     .sign(self.key, hashes.SHA256()))
        (state / "ca.pem").write_bytes(self.cert.public_bytes(serialization.Encoding.PEM))

    def context_for(self, name: str, fqdn: str, expired: bool) -> ssl.SSLContext:
        now = dt.datetime.now(dt.timezone.utc)
        key = ec.generate_private_key(ec.SECP256R1())
        not_after = now - dt.timedelta(days=1) if expired else now + dt.timedelta(days=380)
        cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, fqdn)]))
                .issuer_name(self.name).public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - dt.timedelta(days=300)).not_valid_after(not_after)
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(fqdn), x509.DNSName("localhost"),
                                                            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                                                            x509.IPAddress(ipaddress.ip_address("::1"))]), critical=False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()), critical=False)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                .sign(self.key, hashes.SHA256()))
        kp, cp = self.state / f"{name}.key", self.state / f"{name}.pem"
        kp.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        kp.chmod(0o600)
        cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cp, kp)
        return ctx


def _slug(text: str) -> str:
    return "".join(c if c.isalnum() else "-" for c in text.lower()).strip("-")[:40]


TAG_CATEGORIES = ("Application", "Tier", "Role", "AD-Forest", "Cluster")


def _orch_dump(o):
    if not o:
        return None
    return {"categories": o["categories"], "workflows": {k: {kk: vv for kk, vv in w.items()} for k, w in o["workflows"].items() if not w.get("builtin")},
            "actions": o["actions"], "configurations": o["configurations"], "environments": o["environments"], "plugins": o["plugins"],
            "inventory": o["inventory"], "executions": o["executions"], "action_runs": o["action_runs"]}


class Sim:
    def __init__(self, state_dir: Path, scenario: str, model):
        self.dir = state_dir
        self.scenario = scenario
        self.model = model
        self.s = model.build_state(scenario)
        self.password = (state_dir / "password").read_text().strip()
        # Optional: vCenters with their own SSO domain (an isolated workload domain), read from <state-dir>/isolated_sso.json
        # as {"<vcenter key>": "<sso domain>"}. Their login accepts only accounts of that domain, as a real one would.
        sso_file = state_dir / "isolated_sso.json"
        self.isolated_sso = json.loads(sso_file.read_text()) if sso_file.exists() else {}
        self.sessions = {}
        self.lock = threading.Lock()
        # VCF Automation identity: service accounts (OAuth clients), device codes, rotating refresh tokens.
        self.vcfa_clients = {}      # client_id -> {"name", "roles"}
        self.vcfa_devices = {}      # device_code -> {"client_id", "user_code", "granted", "expires"}
        self.vcfa_refresh = {}      # refresh token -> {"client_id", "used"}
        self.vcfa_roles = {}        # access-token user -> role names (for the Orchestrator access check)
        self.vcfa_failed_logins = 0  # session logins rejected with 401 (an account locks out after a few)
        self.vcfa_oauth_prefixes = ("", "/tm")  # which of /oauth and /tm/oauth answer (the real one varies by build)
        self.vcfa_auto_grant = True  # False: deviceLookup/grant is refused, the code must be approved in the UI
        self.vcfa_access_ttl = 3600

    def log(self, app, method, path, status, user):
        with self.lock, open(self.dir / "requests.jsonl", "a") as fh:
            fh.write(json.dumps({"t": round(time.time(), 3), "app": app, "method": method, "path": path, "status": status, "user": user}) + "\n")

    def issue(self, user):
        tok = secrets.token_urlsafe(24)
        self.sessions[tok] = user
        return tok

    # ---- routing ------------------------------------------------------------------

    def handle(self, app, h, method):
        url = urllib.parse.urlsplit(h.path)
        path, q = url.path.rstrip("/") or "/", urllib.parse.parse_qs(url.query)
        body = None
        n = int(h.headers.get("Content-Length") or 0)
        if n:
            raw = h.rfile.read(n)
            h._raw_body = raw  # XML / multipart bodies are parsed by the endpoint (tools/org_sim/vco_sim.py)
            if "octet-stream" in h.headers.get("Content-Type", ""):
                body = {"_raw": raw}
            elif "x-www-form-urlencoded" in h.headers.get("Content-Type", ""):
                body = {k: v[0] for k, v in urllib.parse.parse_qs(raw.decode()).items()}
            else:
                try:
                    body = json.loads(raw)
                except ValueError:
                    body = None
        kind = app.split("-")[0]
        try:
            code, obj, user = getattr(self, f"r_{kind}")(app, h, method, path, q, body)
        except Exception as exc:  # a simulator bug must look like a server error, not hang the client
            code, obj, user = 500, {"message": f"simulator error: {type(exc).__name__}: {exc}"}, None
        self.log(app, method, path, code, user)
        raw_resp = obj if hasattr(obj, "raw_bytes") else None  # vco_sim.Raw: explicit bytes, content type and headers
        payload = raw_resp.raw_bytes if raw_resp else (b"" if obj is None else json.dumps(obj).encode())
        h.send_response(code)
        h.send_header("Content-Type", raw_resp.content_type if raw_resp else "application/json")
        for k, v in (raw_resp.headers if raw_resp else {}).items():
            h.send_header(k, v)
        h.send_header("Content-Length", str(len(payload)))
        for name, value in getattr(h, "extra_headers", []):
            h.send_header(name, value)
        h.end_headers()
        h.wfile.write(payload)

    def _basic(self, h):
        a = h.headers.get("Authorization", "")
        if not a.startswith("Basic "):
            return None
        user, _, pw = base64.b64decode(a[6:]).decode().partition(":")
        return user if secrets.compare_digest(pw, self.password) else None

    # ---- SDDC Manager -----------------------------------------------------------------

    def r_sddc(self, app, h, method, path, q, body):
        s = self.s
        if path == "/v1/tokens" and method == "POST":
            b = body or {}
            if secrets.compare_digest(str(b.get("password", "")), self.password):
                return 200, {"accessToken": self.issue(b.get("username")), "refreshToken": {"id": secrets.token_hex(8)}}, b.get("username")
            return 401, {"errorCode": "TOKEN_AUTH_FAILED", "message": "Invalid credentials"}, b.get("username")
        user = self.sessions.get(h.headers.get("Authorization", "").removeprefix("Bearer "))
        if not user:
            return 401, {"errorCode": "UNAUTHORIZED"}, None
        vcs = {v["name"]: v for v in s["vcenters"].values()}
        if path == "/v1/domains":
            return 200, {"elements": [{"id": d["id"], "name": d["name"], "type": d["type"], "status": d["status"],
                                       "vcenters": [{"id": d["vcenter"], "fqdn": vcs[d["vcenter"]]["fqdn"]}],
                                       "nsxtCluster": {"id": d["nsx"], "vipFqdn": s["nsx"][d["nsx"]]["fqdn"],
                                                       "isShareable": len(s["nsx"][d["nsx"]]["domains"]) > 1}} for d in s["domains"]]}, user
        if path == "/v1/vcenters":
            dom_id = {d["vcenter"]: d["id"] for d in s["domains"]}
            return 200, {"elements": [{"id": v["name"], "fqdn": v["fqdn"], "version": v["version"], "status": "ACTIVE",
                                       "domain": {"id": dom_id.get(v["name"], f"d-{v['domain']}")}} for v in s["vcenters"].values()]}, user
        if path == "/v1/nsxt-clusters":
            dom_id = {d["name"]: d["id"] for d in s["domains"]}
            return 200, {"elements": [{"id": k, "vipFqdn": n["fqdn"], "version": n.get("version", "9.1.1.0"), "isShared": len(n["domains"]) > 1,
                                       "domains": [{"id": dom_id.get(d, f"d-{d}"), "name": d} for d in n["domains"]]}
                                      for k, n in s["nsx"].items()]}, user
        if path == "/v1/sddc-managers":
            return 200, {"elements": [{"id": "sddc-01", "fqdn": self.model.FQDN["sddc"], "version": s["vcf_version"]}]}, user
        if path == "/v1/tasks":
            status = (q.get("taskStatus") or [None])[0]
            tasks = [t for t in s["tasks"] if not status or t["status"] == status.upper()]
            return 200, {"elements": sorted(tasks, key=lambda t: t["creationTimestamp"], reverse=True)}, user
        if path.startswith("/v1/tasks/"):
            t = next((t for t in s["tasks"] if t["id"] == path.rsplit("/", 1)[1]), None)
            return (200, t, user) if t else (404, {"errorCode": "TASK_NOT_FOUND"}, user)
        if path.startswith("/v1/domains/") and path.endswith("/resource-certificates"):
            dom = next((d for d in s["domains"] if d["id"] == path.split("/")[3]), None)
            if not dom:
                return 404, {"errorCode": "DOMAIN_NOT_FOUND"}, user
            return 200, {"elements": [c for c in s["certificates"] if c["domain"] == dom["name"]]}, user
        if path.startswith("/v1/upgradables/domains/"):
            dom = next((d for d in s["domains"] if d["id"] == path.rsplit("/", 1)[1]), None)
            if not dom:
                return 404, {"errorCode": "DOMAIN_NOT_FOUND", "message": f"Domain {path.rsplit('/', 1)[1]} not found"}, user
            return 200, {"elements": [], "pageMetadata": {"totalElements": 0}}, user
        if path == "/v1/bundles":
            return 200, {"elements": []}, user
        if path == "/v1/credentials":
            if user not in SDDC_ADMINS:
                return 403, {"errorCode": "ACCESS_DENIED", "message": "The credentials API requires the ADMIN role."}, user
            return 200, {"elements": s["credentials"]}, user
        if path == "/v1/system/ntp-configuration":
            return 200, {"ntpServers": [{"ipAddress": x} for x in s["sddc"]["ntp"]]}, user
        if path == "/v1/system/dns-configuration":
            return 200, {"dnsServers": [{"ipAddress": x, "isPrimary": i == 0} for i, x in enumerate(s["sddc"]["dns"])]}, user
        if path == "/v1/users":
            return (200, {"elements": []}, user) if user in SDDC_ADMINS else (403, {"errorCode": "ACCESS_DENIED"}, user)
        return 404, {"errorCode": "NOT_FOUND", "message": path}, user

    # ---- vCenter ------------------------------------------------------------------

    def _tag_ids(self, vc):
        out = {}
        for vm in vc["vms"]:
            for cat, val in (vm.get("tags") or {}).items():
                out[f"urn:vmomi:InventoryServiceTag:{_slug(cat)}--{_slug(val)}:GLOBAL"] = (cat, val)
        return out

    def r_vc(self, app, h, method, path, q, body):
        vc = self.s["vcenters"][app]
        if path == "/api/session" and method == "POST":
            user = self._basic(h)
            domain = self.isolated_sso.get(app)
            if user and domain and user.rpartition("@")[2].lower() != domain.lower():
                user = None  # an account of another SSO domain does not exist here
            if not user:
                return 401, {"error_type": "UNAUTHENTICATED", "messages": [{"default_message": "Authentication required."}]}, None
            if vc["services"]["sts"]["state"] != "STARTED":
                return 503, {"error_type": "SERVICE_UNAVAILABLE", "messages": [{"default_message": "Security Token Service is unavailable."}]}, user
            return 201, self.issue(user), user
        user = self.sessions.get(h.headers.get("vmware-api-session-id", ""))
        if not user:
            return 401, {"error_type": "UNAUTHENTICATED"}, None
        if path == "/api/session":
            now = self.model.NOW.isoformat()
            return 200, {"user": user, "created_time": now, "last_accessed_time": now}, user
        if path.startswith("/api/appliance/health/"):
            key = path.rsplit("/", 1)[1].replace("database-storage", "database")
            return 200, vc["health"].get(key, "green"), user
        if path == "/api/appliance/ntp":
            return 200, vc["ntp"], user
        if path == "/api/appliance/system/version":
            return 200, {"version": vc["version"], "product": "VMware vCenter Server", "build": "25700000"}, user
        if path == "/api/vcenter/services":
            return 200, vc["services"], user
        if path.startswith("/api/vcenter/services/"):
            svc = vc["services"].get(path.rsplit("/", 1)[1])
            return (200, svc, user) if svc else (404, {"error_type": "NOT_FOUND"}, user)
        if path == "/api/vcenter/certificate-management/vcenter/tls":
            return 200, vc["tls"], user
        # VI/JSON privilege check used by guided setup (AuthorizationManager.HasUserPrivilegeOnEntities).
        if method == "POST" and path.startswith("/sdk/vim25/") and path.endswith("/AuthorizationManager/AuthorizationManager/HasUserPrivilegeOnEntities"):
            b = body or {}
            who = b.get("userName") or user
            admin = who.lower() in VC_ADMINS
            granted = lambda priv: admin or priv in ("System.Anonymous", "System.View", "System.Read") or priv.endswith(".Read")  # noqa: E731
            return 200, [{"entity": ent, "privAvailability": [{"privId": pr, "isGranted": granted(pr)} for pr in b.get("privId", [])]}
                         for ent in b.get("entities", [])], user
        # Inventory goes through vpxd: unavailable when it is not running.
        if (path.startswith("/api/vcenter/") or path.startswith("/api/cis/tagging")) and vc["services"]["vpxd"]["state"] != "STARTED":
            return 503, {"error_type": "SERVICE_UNAVAILABLE", "messages": [{"default_message": "vpxd is not available."}]}, user
        if path == "/api/vcenter/host":
            out = []
            for x in vc["hosts"]:
                if q.get("clusters") and self._cluster_id(vc, x["cluster"]) not in q["clusters"]:
                    continue
                if q.get("connection_states") and x["connection_state"] not in q["connection_states"]:
                    continue
                out.append({k: x[k] for k in ("host", "name", "connection_state", "power_state")})
            return 200, out, user
        if path == "/api/vcenter/cluster":
            return 200, vc["clusters"], user
        if path == "/api/vcenter/vm":
            out = []
            hosts_in_cluster = None
            if q.get("clusters"):
                hosts_in_cluster = {x["host"] for x in vc["hosts"] if self._cluster_id(vc, x["cluster"]) in q["clusters"]}
            for x in vc["vms"]:
                if q.get("hosts") and x.get("host") not in q["hosts"]:
                    continue
                if hosts_in_cluster is not None and x.get("host") not in hosts_in_cluster:
                    continue
                if q.get("names") and x["name"] not in q["names"]:
                    continue
                if q.get("power_states") and x["power_state"] not in q["power_states"]:
                    continue
                out.append({k: x[k] for k in ("vm", "name", "power_state", "cpu_count", "memory_size_mib")})
            return 200, out, user
        if path.startswith("/api/vcenter/vm/"):
            parts = path.split("/")
            vm = next((x for x in vc["vms"] if x["vm"] == parts[4]), None)
            if not vm:
                return 404, {"error_type": "NOT_FOUND", "messages": [{"default_message": f"VM {parts[4]} not found"}]}, user
            if path.endswith("/guest/identity"):
                if vm["power_state"] != "POWERED_ON" or vm.get("tools") != "RUNNING":
                    return 503, {"error_type": "SERVICE_UNAVAILABLE", "messages": [{"default_message": "VMware Tools is not running in the guest."}]}, user
                return 200, {"name": vm.get("guest_OS"), "family": "WINDOWS" if "WINDOWS" in vm.get("guest_OS", "") else "LINUX",
                             "full_name": {"default_message": vm.get("guest_full_name", "")}, "host_name": vm.get("hostname"),
                             "ip_address": vm.get("ip")}, user
            if len(parts) > 5:
                return 404, {"error_type": "NOT_FOUND"}, user
            return 200, {"name": vm["name"], "power_state": vm["power_state"], "guest_OS": vm.get("guest_OS", "OTHER_64"),
                         "cpu": {"count": vm["cpu_count"]}, "memory": {"size_mib": vm["memory_size_mib"]},
                         "nics": vm.get("nics", {}),
                         "disks": {str(2000 + i): {"label": f"Hard disk {i + 1}", "type": "SCSI", "capacity": gb * 1024 ** 3}
                                   for i, gb in enumerate(vm.get("disks", [80]))}}, user
        if path == "/api/vcenter/network":
            nets = vc.get("networks", [])
            if q.get("names"):
                nets = [x for x in nets if x["name"] in q["names"]]
            return 200, [{"network": x["network"], "name": x["name"], "type": x["type"]} for x in nets], user
        if path == "/api/vcenter/datastore":
            return 200, vc["datastores"], user
        if path == "/api/cis/tagging/category":
            return 200, [f"urn:vmomi:InventoryServiceCategory:{_slug(c)}:GLOBAL" for c in TAG_CATEGORIES], user
        if path.startswith("/api/cis/tagging/category/"):
            cid = path.rsplit("/", 1)[1]
            name = next((c for c in TAG_CATEGORIES if f":{_slug(c)}:" in cid), None)
            if not name:
                return 404, {"error_type": "NOT_FOUND"}, user
            return 200, {"id": cid, "name": name, "cardinality": "SINGLE", "associable_types": ["VirtualMachine"], "description": ""}, user
        if path == "/api/cis/tagging/tag":
            return 200, sorted(self._tag_ids(vc)), user
        if path.startswith("/api/cis/tagging/tag/"):
            tid = path.rsplit("/", 1)[1]
            cat_val = self._tag_ids(vc).get(tid)
            if not cat_val:
                return 404, {"error_type": "NOT_FOUND"}, user
            return 200, {"id": tid, "name": cat_val[1], "category_id": f"urn:vmomi:InventoryServiceCategory:{_slug(cat_val[0])}:GLOBAL",
                         "description": ""}, user
        if path == "/api/cis/tagging/tag-association" and method == "POST":
            action = (q.get("action") or [""])[0]
            tags = self._tag_ids(vc)
            if action == "list-attached-objects-on-tags":
                out = []
                for tid in (body or {}).get("tag_ids", []):
                    cv = tags.get(tid)
                    objs = [{"type": "VirtualMachine", "id": v["vm"]} for v in vc["vms"] if cv and (v.get("tags") or {}).get(cv[0]) == cv[1]]
                    out.append({"tag_id": tid, "object_ids": objs})
                return 200, out, user
            if action == "list-attached-tags-on-objects":
                rev = {v: k for k, v in tags.items()}
                out = []
                for obj in (body or {}).get("object_ids", []):
                    vm = next((v for v in vc["vms"] if v["vm"] == obj.get("id")), None)
                    out.append({"object_id": obj, "tag_ids": [rev[(c, val)] for c, val in ((vm or {}).get("tags") or {}).items()]})
                return 200, out, user
            return 400, {"error_type": "INVALID_ARGUMENT", "messages": [{"default_message": f"unsupported action {action}"}]}, user
        return 404, {"error_type": "NOT_FOUND", "messages": [{"default_message": path}]}, user

    def _cluster_id(self, vc, name):
        return next((c["cluster"] for c in vc["clusters"] if c["name"] == name), name)

    # ---- NSX ------------------------------------------------------------------------

    def _nsx_vms(self, n):
        doms = set(n["domains"])
        return [v for vc in self.s["vcenters"].values() if vc["domain"] in doms for v in vc["vms"]]

    def r_nsx(self, app, h, method, path, q, body):
        n = self.s["nsx"][app]
        user = self._basic(h)
        if not user:
            return 401, {"error_code": 403, "error_message": "The credentials were incorrect or the account specified has been locked."}, None
        online = [x for x in n["nodes"] if x not in n["offline"]]
        mgmt = "STABLE" if not n["offline"] else ("DEGRADED" if len(online) >= 2 else "UNSTABLE")
        res = lambda items: (200, {"results": items, "result_count": len(items)}, user)  # noqa: E731
        nf = (404, {"error_code": 600, "error_message": f"The path={path} is invalid or the object was not found."}, user)
        if path == "/api/v1/cluster/status":
            return 200, {"cluster_id": f"{app}-cluster", "overall_status": "STABLE" if mgmt == "STABLE" and n["control"] == "STABLE" else "DEGRADED",
                         "mgmt_cluster_status": {"status": mgmt, "online_nodes": [{"uuid": x, "mgmt_cluster_listen_ip_address": x} for x in online],
                                                 "offline_nodes": [{"uuid": x, "mgmt_cluster_listen_ip_address": x} for x in n["offline"]]},
                         "control_cluster_status": {"status": "DEGRADED" if n["offline"] else n["control"]}}, user
        if path == "/api/v1/alarms":
            status = (q.get("status") or [None])[0]
            return res([a for a in n["alarms"] if not status or a["status"] == status])
        if path == "/api/v1/trust-management/certificates":
            return res([{"id": "c-vip", "display_name": n["cert"]["display_name"], "not_after": n["cert"]["not_after"]}])
        if path == "/api/v1/node/version":
            v = n.get("version", "9.1.1.0")
            return 200, {"node_version": f"{v}.25700001", "product_version": v}, user
        if path == "/api/v1/aaa/user-info":
            role = "enterprise_admin" if user.lower() in ("admin", "root") else "auditor"
            return 200, {"user_name": user, "roles": [{"role": role}]}, user
        if not path.startswith("/policy/api/v1/"):
            return nf
        p = path[len("/policy/api/v1"):]
        if "segments" not in n:  # Acme model: flat segments only
            if p == "/infra/segments":
                return res([{"id": f"seg-{d}-{i}", "display_name": f"{d}-app-{i}"} for d in n["domains"] for i in range(3)])
            if p == "/infra/tier-1s":
                return res([{"id": f"t1-{d}", "display_name": f"t1-{d}", "tier0_path": "/infra/tier-0s/t0-main"} for d in n["domains"]])
            if p == "/infra/tier-0s":
                return res([])
            return nf
        seg = lambda x: {k: v for k, v in x.items() if v is not None}  # noqa: E731
        if p == "/infra/segments":
            return res([seg(x) for x in n["segments"]])
        if p.startswith("/infra/segments/"):
            x = next((x for x in n["segments"] if x["id"] == p.rsplit("/", 1)[1]), None)
            return (200, seg(x), user) if x else nf
        if p == "/infra/tier-1s":
            return res([seg(t) for t in n["tier1s"]])
        if p.startswith("/infra/tier-1s/"):
            t = next((t for t in n["tier1s"] if t["id"] == p.rsplit("/", 1)[1]), None)
            return (200, seg(t), user) if t else nf
        t0s = {t["id"]: t for t in n["tier0s"]}
        if p == "/infra/tier-0s":
            return res([{"id": t["id"], "display_name": t["display_name"], "ha_mode": t["ha_mode"], "path": f"/infra/tier-0s/{t['id']}"}
                        for t in n["tier0s"]])
        if p.startswith("/infra/tier-0s/"):
            parts = p.split("/")
            t = t0s.get(parts[3])
            if not t:
                return nf
            if len(parts) == 4:
                return 200, {"id": t["id"], "display_name": t["display_name"], "ha_mode": t["ha_mode"]}, user
            if p.endswith("/locale-services"):
                return res([{"id": "default", "edge_cluster_path": f"/infra/sites/default/enforcement-points/default/edge-clusters/{t['edge_cluster']}"}])
            if p.endswith("/bgp/neighbors"):
                return res([{"id": f"nb-{i}", "neighbor_address": nb["neighbor_address"], "remote_as_num": nb["remote_as_num"],
                             "description": nb["description"]} for i, nb in enumerate(t["neighbors"])])
            if p.endswith("/bgp/neighbors/status"):
                return res([{"neighbor_address": nb["neighbor_address"], "remote_as_number": nb["remote_as_num"],
                             "connection_state": nb["connection_state"], "source_address": nb["source_address"],
                             "time_since_established": nb["time_since_established"], "local_as_number": t["local_as_num"]}
                            for nb in t["neighbors"]])
            if p.endswith("/bgp"):
                return 200, {"enabled": True, "local_as_num": t["local_as_num"], "ecmp": True}, user
            return nf
        if p == "/infra/domains/default/groups":
            return res([{"id": g, "display_name": g, "path": f"/infra/domains/default/groups/{g}",
                         "expression": [{"resource_type": "Condition", "member_type": "VirtualMachine", "key": "Tag", "operator": "EQUALS",
                                         "value": f"Application|{a}" + (f" AND Tier|{t}" if t else "")}]}
                        for g, (a, t) in self.model.GROUPS.items() if self._group_members(n, g)])
        if p.startswith("/infra/domains/default/groups/") and p.endswith("/members/virtual-machines"):
            g = p.split("/")[5]
            if g not in getattr(self.model, "GROUPS", {}):
                return nf
            return res([{"display_name": v["name"], "external_id": v["vm"], "power_state": "VM_RUNNING" if v["power_state"] == "POWERED_ON" else "VM_STOPPED"}
                        for v in self._group_members(n, g)])
        if p == "/infra/domains/default/security-policies":
            return res([{k: v for k, v in x.items() if k != "rules"} for x in n["policies"]])
        if p.startswith("/infra/domains/default/security-policies/"):
            parts = p.split("/")
            pol = next((x for x in n["policies"] if x["id"] == parts[5]), None)
            if not pol:
                return nf
            if p.endswith("/rules"):
                return res(sorted(pol["rules"], key=lambda r: r["sequence_number"]))
            return 200, pol, user
        if p == "/orgs/default/projects":
            return res([{"id": "default", "display_name": "Default"}] + [{"id": x["id"], "display_name": x["display_name"]} for x in n["projects"]])
        if p.startswith("/orgs/default/projects/"):
            parts = p.split("/")
            proj = next((x for x in n["projects"] if x["id"] == parts[4]), None)
            if parts[4] == "default" and len(parts) == 6 and parts[5] == "vpcs":
                return res([])
            if not proj:
                return nf
            if len(parts) == 6 and parts[5] == "transit-gateways":
                return res([{"id": proj["tgw"], "display_name": proj["tgw"], "description": proj["tgw_connectivity"]}])
            if len(parts) == 6 and parts[5] == "vpc-connectivity-profiles":
                return res([{"id": v["connectivity_profile"], "transit_gateway_path": f"/orgs/default/projects/{proj['id']}/transit-gateways/{proj['tgw']}"}
                            for v in proj["vpcs"]])
            if len(parts) >= 6 and parts[5] == "vpcs":
                if len(parts) == 6:
                    return res([{"id": v["id"], "display_name": v["display_name"], "vpc_connectivity_profile":
                                 f"/orgs/default/projects/{proj['id']}/vpc-connectivity-profiles/{v['connectivity_profile']}"} for v in proj["vpcs"]])
                vpc = next((v for v in proj["vpcs"] if v["id"] == parts[6]), None)
                if not vpc:
                    return nf
                if len(parts) == 8 and parts[7] == "subnets":
                    return res([{k: v for k, v in sb.items() if k != "pool"} for sb in vpc["subnets"]])
                if len(parts) >= 10 and parts[7] == "subnets" and parts[9] == "ip-pools":
                    sb = next((sb for sb in vpc["subnets"] if sb["id"] == parts[8]), None)
                    if not sb:
                        return nf
                    pool = sb["pool"]
                    return res([{"id": pool["id"], "display_name": pool["id"],
                                 "pool_usage": {"total_ids": pool["total_ids"], "allocated_ids": pool["allocated_ids"],
                                                "available_ids": pool["total_ids"] - pool["allocated_ids"]}}])
            return nf
        return nf

    def _group_members(self, n, g):
        app_tag, tier = self.model.GROUPS[g]
        return [v for v in self._nsx_vms(n) if (v.get("tags") or {}).get("Application") == app_tag
                and (tier is None or (v.get("tags") or {}).get("Tier") == tier)]

    # ---- VCF Operations ---------------------------------------------------------------

    def r_ops(self, app, h, method, path, q, body):
        o = self.s["ops"]
        if path == "/suite-api/api/auth/token/acquire" and method == "POST":
            b = body or {}
            if secrets.compare_digest(str(b.get("password", "")), self.password):
                return 200, {"token": self.issue(b.get("username")), "validity": int((time.time() + 3600) * 1000)}, b.get("username")
            return 401, {"message": "Invalid credentials"}, b.get("username")
        user = self.sessions.get(h.headers.get("Authorization", "").removeprefix("OpsToken "))
        if not user:
            return 401, {"message": "Unauthorized"}, None
        if path == "/suite-api/api/alerts":
            return 200, {"alerts": o["alerts"]}, user
        if path == "/suite-api/api/collectors":
            return 200, {"collector": [{"name": c["name"], "state": c["state"], "local": False} for c in o["collectors"]]}, user
        if path == "/suite-api/api/deployment/node/status":
            return 200, {"status": o["node_status"], "systemTime": int(time.time() * 1000)}, user
        if path == "/suite-api/api/versions/current":
            return 200, {"releaseName": "VCF Operations 9.1.1.0", "major": 9, "minor": 1, "minorMinor": 1, "patch": 0}, user
        ops_role = "Administrator" if str(user).lower() in ("admin", "root") else "ReadOnly"
        if path == "/suite-api/api/auth/currentuser":
            return 200, {"username": user, "roleNames": [ops_role]}, user
        if path == "/suite-api/api/auth/currentuser/permissions":
            return 200, {"permissions": [{"roleName": ops_role, "allowAllObjects": True}]}, user
        objects = self._ops_objects()
        if path == "/suite-api/api/resources":
            name = (q.get("name") or [""])[0]
            hits = [r for r in objects if not name or name.lower() in r[1].lower()]
            return 200, {"resourceList": [{"identifier": rid, "resourceKey": {"name": nm, "resourceKindKey": kind, "adapterKindKey": "VMWARE"}}
                                          for rid, nm, kind in hits[:50]], "pageInfo": {"totalCount": len(hits)}}, user
        if path.startswith("/suite-api/api/resources/") and path.endswith("/stats"):
            rid = path.split("/")[4]
            obj = next((r for r in objects if r[0] == rid), None)
            if not obj:
                return 404, {"message": f"Resource {rid} not found"}, user
            seed = sum(map(ord, obj[1]))
            ts = [int(time.time() * 1000) - i * 300000 for i in range(12)][::-1]
            keys = (q.get("statKey") or ["cpu|usage_average", "mem|usage_average"])
            return 200, {"values": [{"resourceId": rid, "stat-list": {"stat": [
                {"statKey": {"key": k}, "timestamps": ts, "data": [round(15 + (seed * (j + 3) + i * 7) % 55, 1) for i in range(12)]}
                for j, k in enumerate(keys)]}}]}, user
        return 404, {"message": path}, user

    def _ops_objects(self):
        out = []
        for vc in self.s["vcenters"].values():
            out += [(f"r-{_slug(c['name'])}-0000-4000-8000-000000000001"[:36], c["name"], "ClusterComputeResource") for c in vc["clusters"]]
            out += [(f"r-{_slug(x['name'])[:18]}-4000-8000-0000000000002"[:36], x["name"], "HostSystem") for x in vc["hosts"]]
            out += [(f"r-{_slug(v['name'])[:18]}-4000-8000-0000000000003"[:36], v["name"], "VirtualMachine") for v in vc["vms"]]
        return out

    # ---- VCF Automation (VM Apps org: Assembler + embedded Orchestrator) ----------------

    def _save_automation(self):
        a = self.s.get("automation") or {}
        (self.dir / "automation_state.json").write_text(json.dumps(
            {"blueprints": a.get("blueprints"), "executions": a.get("executions"), "requests": a.get("requests", []),
             "orchestrator": _orch_dump(self.s.get("orch"))}, indent=2, default=str))

    def r_vcfa(self, app, h, method, path, q, body):
        a = self.s["automation"]
        ident = self._vcfa_identity(h, method, path, body, a)
        if ident is not None:
            return ident
        user = self.sessions.get(h.headers.get("Authorization", "").removeprefix("Bearer "))
        if not user:
            return 401, {"message": "Unauthorized", "statusCode": 401}, None
        page = lambda items: (200, {"content": items, "totalElements": len(items), "numberOfElements": len(items)}, user)  # noqa: E731
        if path == "/iaas/api/projects":
            return page(a["projects"])
        if path == "/iaas/api/images":
            return page(a["images"])
        if path == "/iaas/api/flavors":
            return page(a["flavors"])
        if path == "/iaas/api/fabric-networks":
            return page(a["networks"])
        if path == "/deployment/api/deployments":
            items = a["deployments"]
            if q.get("projects"):
                items = [d for d in items if d["projectId"] in q["projects"]]
            return page(items)
        if path == "/blueprint/api/blueprints" and method == "GET":
            items = [{k: v for k, v in b.items() if k != "content"} for b in a["blueprints"]]
            if q.get("projects"):
                items = [b for b in items if b["projectId"] in q["projects"]]
            return page(items)
        if path.startswith("/blueprint/api/blueprints/") and method == "GET":
            b = next((b for b in a["blueprints"] if b["id"] == path.rsplit("/", 1)[1]), None)
            return (200, b, user) if b else (404, {"message": f"Blueprint {path.rsplit('/', 1)[1]} not found", "statusCode": 404}, user)
        if path == "/blueprint/api/blueprint-validation" and method == "POST":
            b = body or {}
            msgs = self._validate_blueprint(b.get("content", ""), b.get("projectId"))
            return 200, {"valid": not any(m["type"] == "ERROR" for m in msgs), "validationMessages": msgs}, user
        if path == "/blueprint/api/blueprints" and method == "POST":
            b = body or {}
            for f in ("name", "projectId", "content"):
                if not b.get(f):
                    return 400, {"message": f"'{f}' is required", "statusCode": 400}, user
            if not any(p["id"] == b["projectId"] for p in a["projects"]):
                return 400, {"message": f"Project {b['projectId']} not found", "statusCode": 400}, user
            if any(x["name"] == b["name"] and x["projectId"] == b["projectId"] for x in a["blueprints"]):
                return 409, {"message": f"A blueprint named '{b['name']}' already exists in this project", "statusCode": 409}, user
            new = {"id": "bp-" + secrets.token_hex(4), "name": b["name"], "description": b.get("description", ""), "projectId": b["projectId"],
                   "status": "DRAFT", "createdBy": user, "createdAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "content": b["content"],
                   "valid": not any(m["type"] == "ERROR" for m in self._validate_blueprint(b["content"], b["projectId"]))}
            a["blueprints"].append(new)
            self._save_automation()
            return 201, {k: v for k, v in new.items() if k != "content"}, user
        if path.startswith("/vco/api") and user in self.vcfa_roles and not any(r.startswith("Orchestrator") for r in self.vcfa_roles[user]):
            # A service account without an Orchestrator role is a plain user: it sees nothing, not even the library.
            if method == "GET" and path == "/vco/api/workflows":
                return 200, {"link": [], "total": 0}, user
            return 403, {"message": "Forbidden: the account has no Orchestrator role", "statusCode": 403}, user
        if path.startswith("/vco/api"):
            import vco_sim
            return vco_sim.handle(self, h, method, path, q, body, user)
        return 404, {"message": path, "statusCode": 404}, user

    # ---- VCF Automation identity: session login, service accounts, device flow, rotating tokens ----

    VCFA_ROLES = ("Organization Administrator", "Organization Owner", "Orchestrator Administrator", "Orchestrator Designer",
                  "Orchestrator User", "Project Viewer")

    def _vcfa_access_token(self, user, roles, ttl=None):
        tok = self.issue(user)
        self.vcfa_roles[user] = list(roles)
        return {"access_token": tok, "token_type": "Bearer", "expires_in": ttl or self.vcfa_access_ttl}

    def vcfa_approve(self, user_code):
        """Approve a device code the way a person does in the VCF Automation UI (Access Control > Service Accounts)."""
        for d in self.vcfa_devices.values():
            if d["user_code"] == user_code:
                d["granted"] = True
                return True
        return False

    def _vcfa_identity(self, h, method, path, body, a):
        tenant = a["tenant"]
        auth = h.headers.get("Authorization", "")
        bare = path.removeprefix("/tm")
        # 1. session login: POST [/tm]/cloudapi/1.0.0/sessions, HTTP Basic user@org
        if bare == "/cloudapi/1.0.0/sessions" and method == "POST":
            principal = self._basic_principal(h)
            if not principal or principal.rpartition("@")[2].lower() != tenant.lower():
                self.vcfa_failed_logins += 1
                return 401, {"message": "Unauthorized"}, None
            user = principal
            tok = self.issue(user)
            self.vcfa_roles.pop(user, None)
            h.extra_headers = [("x-vmware-vcloud-access-token", tok), ("Set-Cookie", f"vcloud_jwt={tok}; Path=/; HttpOnly; Secure")]
            return 200, {"id": "urn:vcloud:session:" + secrets.token_hex(4), "user": {"name": user.rpartition("@")[0]},
                         "roles": ["Organization Administrator"]}, user
        # 2. register a service account
        m = re.fullmatch(r"/oauth/tenant/([^/]+)/(register|device_authorization)", bare)
        if m and method == "POST" and m.group(1).lower() == tenant.lower():
            if m.group(2) == "register":
                if not self.sessions.get(auth.removeprefix("Bearer ")):
                    return 401, {"message": "Unauthorized"}, None
                b = body or {}
                roles = [urllib.parse.unquote(x.removeprefix("urn:vcloud:role:")) for x in str(b.get("scope", "")).split()]
                bad = [r for r in roles if r not in self.VCFA_ROLES]
                if not b.get("client_name") or not roles or bad:
                    return 400, {"error": "invalid_client_metadata", "error_description":
                                 f"Unable to find the following role(s) in org {tenant}: {', '.join(bad) or '(none given)'}"}, None
                cid = secrets.token_hex(16)
                self.vcfa_clients[cid] = {"name": b["client_name"], "roles": roles}
                return 201, {"client_id": cid, "client_name": b["client_name"], "scope": b.get("scope")}, None
            cid = (body or {}).get("client_id")
            if cid not in self.vcfa_clients:
                return 401, {"error": "invalid_client"}, None
            code = secrets.token_urlsafe(24)
            user_code = secrets.token_hex(2).upper() + "-" + secrets.token_hex(2).upper()
            self.vcfa_devices[code] = {"client_id": cid, "user_code": user_code, "granted": False, "expires": time.time() + 600}
            return 200, {"device_code": code, "user_code": user_code, "expires_in": 600, "interval": 1,
                         "verification_uri": f"https://{h.headers.get('Host', '')}/provider/access-control/service-accounts"}, None
        # 3. grant the device as the logged-in user
        if path == "/tm/cloudapi/1.0.0/deviceLookup/grant" and method == "POST":
            if not self.sessions.get(auth.removeprefix("Bearer ")):
                return 401, {"message": "Unauthorized"}, None
            if not self.vcfa_auto_grant:
                return 403, {"message": "Access to the device lookup is not allowed for this session"}, None
            return (204, None, None) if self.vcfa_approve((body or {}).get("userCode")) else (404, {"message": "Unknown user code"}, None)
        # 4. tokens: refresh_token (rotating) and device_code
        m = re.fullmatch(r"(/tm)?/oauth/(?:tenant/([^/]+)|provider)/token", path)
        if m:
            if (m.group(1) or "") not in self.vcfa_oauth_prefixes:
                return 404, {"message": path}, None
            if method != "POST":
                return 405, {"message": "Method Not Allowed"}, None
            if (m.group(2) or "").lower() != tenant.lower():
                return 404, {"error": "unknown tenant"}, None
            b = body or {}
            grant, cid = b.get("grant_type"), b.get("client_id")
            if grant == "refresh_token":
                rt = str(b.get("refresh_token", ""))
                if secrets.compare_digest(rt, self.password):  # lab token: static, never rotates
                    return 200, self._vcfa_access_token("svc-mcp-automation@corp.nwg.lab", ["Organization Administrator", "Orchestrator Administrator"]), "svc-mcp-automation"
                rec = self.vcfa_refresh.get(rt)
                if not rec or rec["used"]:
                    return 400, {"error": "invalid_grant", "error_description": "Invalid refresh token"}, None
                if cid and cid != rec["client_id"]:
                    return 401, {"error": "invalid_client"}, None
                rec["used"] = True
                client = self.vcfa_clients[rec["client_id"]]
                return 200, self._issue_vcfa_tokens(rec["client_id"], client), client["name"]
            if grant == "urn:ietf:params:oauth:grant-type:device_code":
                dev = self.vcfa_devices.get(b.get("device_code"))
                if cid not in self.vcfa_clients or (dev and dev["client_id"] != cid):
                    return 401, {"error": "invalid_client"}, None
                if not dev or dev["expires"] < time.time():
                    return 400, {"error": "expired_token"}, None
                if not dev["granted"]:
                    return 400, {"error": "authorization_pending"}, None
                del self.vcfa_devices[b["device_code"]]
                client = self.vcfa_clients[cid]
                return 200, self._issue_vcfa_tokens(cid, client), client["name"]
            return 400, {"error": "unsupported_grant_type"}, None
        if path.startswith("/tm/oauth/tenant/") or path.startswith("/oauth/tenant/"):
            return 404, {"error": "unknown tenant"}, None
        return None

    def _issue_vcfa_tokens(self, client_id, client):
        out = self._vcfa_access_token(f"sa-{client['name']}@{self.s['automation']['tenant']}", client["roles"])
        rt = "rt-" + secrets.token_urlsafe(32)
        self.vcfa_refresh[rt] = {"client_id": client_id, "used": False}
        out["refresh_token"] = rt
        return out

    def _basic_principal(self, h):
        a = h.headers.get("Authorization", "")
        if not a.startswith("Basic "):
            return None
        user, _, pw = base64.b64decode(a[6:]).decode().partition(":")
        return user if secrets.compare_digest(pw, self.password) else None

    def _validate_blueprint(self, content, project_id):
        import yaml
        a = self.s["automation"]
        msgs = []
        err = lambda m, p="": msgs.append({"type": "ERROR", "message": m, "path": p})  # noqa: E731
        if project_id and not any(p["id"] == project_id for p in a["projects"]):
            err(f"Project '{project_id}' does not exist.")
        try:
            doc = yaml.safe_load(content) or {}
        except yaml.YAMLError as exc:
            err(f"Invalid YAML: {str(exc).splitlines()[0]}")
            return msgs
        if not isinstance(doc, dict) or doc.get("formatVersion") != 1:
            err("formatVersion: 1 is required at the top level.")
        inputs = (doc.get("inputs") or {}) if isinstance(doc, dict) else {}
        resources = (doc.get("resources") or {}) if isinstance(doc, dict) else {}
        if not resources:
            err("The template has no resources.")
        known = {"Cloud.vSphere.Machine", "Cloud.Machine", "Cloud.vSphere.Network", "Cloud.NSX.Network", "Cloud.Network", "Cloud.vSphere.Disk",
                 "Cloud.Volume", "Cloud.NSX.SecurityGroup", "Cloud.SecurityGroup", "Cloud.LoadBalancer", "Cloud.NSX.LoadBalancer"}
        images, flavors = {i["name"] for i in a["images"]}, {f["name"] for f in a["flavors"]}
        tags = {t for n in a["networks"] for t in n["tags"]}
        text = content if isinstance(content, str) else ""
        for ref in set(re.findall(r"\$\{input\.([A-Za-z0-9_]+)", text)):
            if ref not in inputs:
                err(f"Input '{ref}' is referenced but not declared under inputs.", f"inputs.{ref}")
        for ref in set(re.findall(r"\$\{resource\.([A-Za-z0-9_\-]+)", text)):
            if ref not in resources:
                err(f"Resource '{ref}' is referenced but not defined.", f"resources.{ref}")
        for rname, r in resources.items():
            rtype, props = (r or {}).get("type"), (r or {}).get("properties") or {}
            if rtype not in known:
                err(f"Unknown resource type '{rtype}'.", f"resources.{rname}.type")
                continue
            if rtype in ("Cloud.vSphere.Machine", "Cloud.Machine"):
                img, fl = props.get("image"), props.get("flavor")
                if not img and not props.get("imageRef"):
                    err("Machine needs an image (image mapping name).", f"resources.{rname}.properties.image")
                elif img and "${" not in str(img) and img not in images:
                    err(f"Image mapping '{img}' does not exist. Available: {', '.join(sorted(images))}.", f"resources.{rname}.properties.image")
                if not fl and not (props.get("cpuCount") and props.get("totalMemoryMB")):
                    err("Machine needs a flavor (flavor mapping name) or cpuCount + totalMemoryMB.", f"resources.{rname}.properties.flavor")
                elif fl and "${" not in str(fl) and fl not in flavors:
                    err(f"Flavor mapping '{fl}' does not exist. Available: {', '.join(sorted(flavors))}.", f"resources.{rname}.properties.flavor")
                if not props.get("networks"):
                    msgs.append({"type": "WARNING", "message": "Machine has no networks; it gets the project default network.", "path": f"resources.{rname}"})
            if rtype in ("Cloud.vSphere.Network", "Cloud.NSX.Network", "Cloud.Network"):
                for c in props.get("constraints") or []:
                    t = str((c or {}).get("tag", "")).split(":hard")[0].split(":soft")[0]
                    if t and "${" not in t and t not in tags:
                        err(f"No network matches constraint tag '{t}'. Known network tags: {', '.join(sorted(tags))}.", f"resources.{rname}.properties.constraints")
        return msgs

    def _vm_by_name(self, name):
        for vc in self.s["vcenters"].values():
            for v in vc["vms"]:
                if v["name"] == name:
                    return v
        return None

    def _run_workflow(self, wf, body, user):
        a = self.s["automation"]
        params = {}
        for p in body.get("parameters", []):
            val = p.get("value") or {}
            inner = next(iter(val.values()), {}) if isinstance(val, dict) and val else {}
            params[p.get("name")] = inner.get("value") if isinstance(inner, dict) else inner
        missing = [i["name"] for i in wf["inputs"] if i.get("required") and params.get(i["name"]) in (None, "")]
        if missing:
            return 400, {"status": "Bad Request", "message": f"Missing required input parameter(s): {', '.join(missing)}"}, user
        eid = secrets.token_hex(8)
        state, outputs, exc = "completed", {}, None
        try:
            if wf["id"] == "wf-expand-disk":
                vm = self._vm_by_name(params["vmName"])
                if not vm:
                    raise ValueError(f"VM '{params['vmName']}' not found in any vCenter")
                idx = int(float(params["diskNumber"])) - 1
                if idx < 0 or idx >= len(vm["disks"]):
                    raise ValueError(f"VM '{vm['name']}' has {len(vm['disks'])} disk(s); disk {idx + 1} does not exist")
                add = int(float(params["addGB"]))
                if add <= 0 or add > 2048:
                    raise ValueError("addGB must be between 1 and 2048")
                vm["disks"][idx] += add
                outputs["newSizeGB"] = ("number", vm["disks"][idx])
            elif wf["id"] == "wf-ad-computer":
                forest = str(params["forest"]).lower()
                if forest not in a["ad_plugin_forests"]:
                    raise ValueError(f"No Active Directory plug-in connection is configured for '{params['forest']}'. "
                                     f"Configured: {', '.join(a['ad_plugin_forests'])}.")
                outputs["distinguishedName"] = ("string", f"CN={params['computerName']},{params['ouPath']}")
            elif wf["id"] == "wf-sql-ag-failover":
                nodes = [v for vc in self.s["vcenters"].values() for v in vc["vms"]
                         if str((v.get("tags") or {}).get("Cluster", "")).startswith(str(params["agName"]) + " ")]
                if not nodes:
                    raise ValueError(f"Availability group '{params['agName']}' not found")
                names = [v["name"] for v in nodes]
                if params["targetReplica"] not in names:
                    raise ValueError(f"'{params['targetReplica']}' is not a replica of {params['agName']} (replicas: {', '.join(names)})")
                if params["targetReplica"] == names[0]:
                    raise ValueError(f"'{params['targetReplica']}' is already the primary replica")
                outputs["newPrimary"] = ("string", params["targetReplica"])
            elif wf["id"] == "wf-nsx-tag":
                if not self._vm_by_name(params["vmName"]):
                    raise ValueError(f"VM '{params['vmName']}' not found")
                outputs["groups"] = ("Array/string", [f"grp-{params['tag']}"])
        except (ValueError, KeyError) as e:
            state, exc = "failed", str(e)
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        a["executions"][eid] = {"id": eid, "workflow": wf["id"], "name": wf["name"], "state": state, "started-by": user, "start-date": now,
                                "end-date": now, "input-parameters": [{"name": k, "value": v} for k, v in params.items()],
                                "output-parameters": [{"name": k, "type": t, "value": {t.split("/")[0].lower(): {"value": v}}}
                                                      for k, (t, v) in outputs.items()],
                                **({"content-exception": exc} if exc else {})}
        self._save_automation()
        return 202, {"id": eid, "state": "running", "href": f"/vco/api/workflows/{wf['id']}/executions/{eid}/"}, user


def serve(state_dir: Path, scenario: str, port_offset: int = 0, model_name: str = "acme") -> None:
    model = importlib.import_module({"acme": "org_model", "enterprise": "enterprise_model"}[model_name])
    sim = Sim(state_dir, scenario, model)
    ca = CA(state_dir)
    PORTS, FQDN = model.PORTS, model.FQDN
    now = model.NOW.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    expired = {k for k, vc in sim.s["vcenters"].items() if vc["tls"]["valid_to"] < now}
    expired |= {k for k, n in sim.s["nsx"].items() if n["cert"]["not_after"] < now}

    class V6(ThreadingHTTPServer):
        address_family = socket.AF_INET6

    ports = {a: p + port_offset for a, p in PORTS.items()}
    for app, port in ports.items():
        ctx = ca.context_for(app, FQDN[app], expired=app in expired)

        class H(BaseHTTPRequestHandler):
            server_version, sys_version, _app = "acme-sim", "", app

            def log_message(self, *a):
                return

            def do_GET(self):
                sim.handle(self._app, self, "GET")

            def do_POST(self):
                sim.handle(self._app, self, "POST")

            def do_PATCH(self):
                sim.handle(self._app, self, "PATCH")

            def do_PUT(self):
                sim.handle(self._app, self, "PUT")

            def do_DELETE(self):
                sim.handle(self._app, self, "DELETE")

        for cls, host in ((ThreadingHTTPServer, "127.0.0.1"), (V6, "::1")):
            srv = cls((host, port), H)
            srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
    endpoints = {FQDN[a]: f"https://localhost:{p}" for a, p in ports.items()}
    (state_dir / "endpoints.json").write_text(json.dumps({"endpoints": endpoints}, indent=2))
    print(f"{model_name} simulator ready: scenario={scenario}", flush=True)
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    serve(Path(sys.argv[1]), sys.argv[2], int(sys.argv[3]) if len(sys.argv) > 3 else 0, sys.argv[4] if len(sys.argv) > 4 else "acme")
