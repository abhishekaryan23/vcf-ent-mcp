# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Enterprise VCF MCP Control Plane Server.
Runs as an in-network stdio agent runtime or a remote stateless HTTP/SSE gateway.
"""

from __future__ import annotations
import sys
import os
import json
import asyncio
import copy
import urllib.parse
import uuid
from pathlib import Path
from typing import Optional
from http.server import HTTPServer, BaseHTTPRequestHandler
from vcf_enterprise_mcp.config.settings import EnterpriseSettings, config_file_stamp, get_enterprise_settings, set_enterprise_settings
from vcf_enterprise_mcp.core.protocol import EnterpriseMCPProtocolEngine


MRTR_CAPS_KEY = "io.modelcontextprotocol/clientCapabilities"
ELICITATION_TIMEOUT_SECONDS = 900.0
MAX_ELICITATION_ROUNDS = 25
PAGE_POLL_SECONDS = 0.5


class StdioSession:
    """One stdio connection: reads JSON-RPC from stdin, runs each request as a task, and writes replies to stdout.

    Classic elicitation adapter. Today's clients (Claude Code, LM Studio, the official Python SDK) declare
    `capabilities.elicitation` in `initialize` and answer a server-sent `elicitation/create` request; they do not send the
    2026-07-28 per-request client capabilities. The engine only speaks the 2026-07-28 style (a tools/call RESULT with
    resultType "input_required" and inputRequests, retried with inputResponses + requestState). For a classic client this
    session
      1. remembers the capabilities from `initialize`,
      2. hands them to the engine for each tools/call (as the per-request client capabilities, so URL mode is used only when the
         client declared `url`; a client without elicitation gets the plain NEEDS_INPUT data result),
      3. when the call returns input_required, sends every inputRequest to the client as an `elicitation/create` request on
         stdout (ids "srv-<n>"), keeps reading stdin (other requests are handled concurrently, so nothing deadlocks), and
         re-runs the call with the collected answers exactly as an MRTR retry would, until a final result is produced.
    A `notifications/cancelled` for the pending call aborts it. A client that answers elicitation/create with an error is
    treated as not supporting it: the call is re-run in the plain-data style.
    """

    def __init__(self, engine: EnterpriseMCPProtocolEngine):
        self.engine = engine
        self.client_caps: dict = {}
        self.pending: dict = {}      # server request id -> Future of the client's response
        self.inflight: dict = {}     # client request id -> Task
        self.tasks: set = set()
        self.lock = asyncio.Lock()   # requests run in arrival order; the lock is released only while waiting for the client's answer
        self._counter = 0

    # ---- output -------------------------------------------------------------------------------

    @staticmethod
    def write(obj: dict) -> None:
        sys.stdout.write(json.dumps(obj) + "\n")
        sys.stdout.flush()

    def _flush_notifications(self) -> None:
        for note in self.engine.drain_notifications():
            sys.stdout.write(json.dumps(note) + "\n")
        sys.stdout.flush()

    # ---- input ----------------------------------------------------------------------------------

    async def run(self) -> None:
        loop_tasks = self.tasks
        while True:
            try:
                line = await asyncio.to_thread(sys.stdin.readline)
            except Exception:
                break
            if not line:
                break
            line_str = line.strip()
            if not line_str:
                continue
            try:
                msg = json.loads(line_str)
            except json.JSONDecodeError as e:
                self.write({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": f"Parse error: {e}"}})
                continue
            if not isinstance(msg, dict):
                continue
            if "method" not in msg and msg.get("id") in self.pending:  # the client's answer to one of our requests
                fut = self.pending[msg["id"]]
                if not fut.done():
                    fut.set_result(msg)
                continue
            if msg.get("method") == "notifications/cancelled":
                params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
                task = self.inflight.get(params.get("requestId"))
                if task is not None:
                    task.cancel()
                continue
            task = asyncio.ensure_future(self._handle(msg))
            loop_tasks.add(task)
            if "id" in msg:
                self.inflight[msg["id"]] = task
            def _done(t, rid=msg.get("id")):
                loop_tasks.discard(t)
                if self.inflight.get(rid) is t:
                    self.inflight.pop(rid, None)
            task.add_done_callback(_done)
        for fut in list(self.pending.values()):  # stdin closed: nobody will answer
            if not fut.done():
                fut.set_result({"error": {"code": -32000, "message": "client disconnected"}})
        if loop_tasks:
            await asyncio.gather(*list(loop_tasks), return_exceptions=True)

    # ---- one request ----------------------------------------------------------------------------

    def _auth_header(self, req: dict) -> Optional[str]:
        params = req.get("params") if isinstance(req.get("params"), dict) else {}
        return (
            (params.get("_meta") or {}).get("authorization")
            or (req.get("_meta") or {}).get("authorization")
            or os.environ.get("VCF_MCP_AUTH_TOKEN")
        )

    async def _handle(self, req: dict) -> None:
        async with self.lock:
            await self._handle_locked(req)

    async def _handle_locked(self, req: dict) -> None:
        try:
            params = req.get("params") if isinstance(req.get("params"), dict) else {}
            if req.get("method") == "initialize":
                caps = params.get("capabilities")
                self.client_caps = caps if isinstance(caps, dict) else {}
            auth_header = self._auth_header(req)
            classic = self.client_caps.get("elicitation")
            meta = params.get("_meta")
            if (req.get("method") == "tools/call" and "id" in req and isinstance(classic, dict)
                    and not (isinstance(meta, dict) and MRTR_CAPS_KEY in meta)):
                with_caps = copy.deepcopy(req)
                with_caps.setdefault("params", {}).setdefault("_meta", {})[MRTR_CAPS_KEY] = {"elicitation": classic}
                resp = await self.engine.handle_jsonrpc_request(with_caps, auth_header=auth_header)
                resp = await self._drive_elicitation(req, with_caps, resp, auth_header)
            else:
                resp = await self.engine.handle_jsonrpc_request(req, auth_header=auth_header)
            if resp is not None:  # notifications (no id) never get a reply
                self.write(resp)
            self._flush_notifications()
        except asyncio.CancelledError:
            raise  # cancelled by the client: no response
        except Exception as e:
            self.write({"jsonrpc": "2.0", "id": req.get("id") if isinstance(req, dict) else None,
                        "error": {"code": -32603, "message": str(e)}})

    @staticmethod
    def _input_required(resp: Optional[dict]) -> bool:
        result = (resp or {}).get("result")
        return isinstance(result, dict) and result.get("resultType") == "input_required"

    async def _drive_elicitation(self, original: dict, current: dict, resp: Optional[dict], auth_header: Optional[str]) -> Optional[dict]:
        rounds = 0
        while self._input_required(resp):
            rounds += 1
            if rounds > MAX_ELICITATION_ROUNDS:
                return {"jsonrpc": "2.0", "id": original.get("id"), "result": {
                    "isError": True, "content": [{"type": "text", "text": "Too many question rounds; start again."}]}}
            result = resp["result"]
            answers: dict = {}
            for key, ireq in (result.get("inputRequests") or {}).items():
                answer = await self._ask_client(ireq)
                if answer is None:  # the client cannot elicit after all: plain-data flow
                    return await self.engine.handle_jsonrpc_request(original, auth_header=auth_header)
                answers[key] = answer
            retry = copy.deepcopy(current)
            retry["params"]["inputResponses"] = answers
            if result.get("requestState"):
                retry["params"]["requestState"] = result["requestState"]
            resp = await self.engine.handle_jsonrpc_request(retry, auth_header=auth_header)
        return resp

    async def _ask_client(self, ireq: dict) -> Optional[dict]:
        """Sends one inputRequest to the client as `elicitation/create`; returns {action, content} or None when unsupported."""
        if not isinstance(ireq, dict) or ireq.get("method") != "elicitation/create":
            return None
        params = dict(ireq.get("params") or {})
        declared = self.client_caps.get("elicitation") or {}
        if params.get("mode") == "url":
            if "url" not in declared:
                return None
            params.setdefault("elicitationId", uuid.uuid4().hex)
        self._counter += 1
        rid = f"srv-{self._counter}"
        fut = asyncio.get_running_loop().create_future()
        self.pending[rid] = fut
        self.write({"jsonrpc": "2.0", "id": rid, "method": "elicitation/create", "params": params})
        watcher = None
        if params.get("mode") == "url":  # clients wait for this notice, before or after they answer the URL request
            watcher = asyncio.ensure_future(self._notify_when_page_done(params.get("url") or "", params["elicitationId"]))
        self.lock.release()  # other requests (ping, tools/list, ...) are served while the person answers
        deadline = asyncio.get_running_loop().time() + ELICITATION_TIMEOUT_SECONDS
        try:
            msg = await asyncio.wait_for(fut, timeout=ELICITATION_TIMEOUT_SECONDS)
            accepted = isinstance(msg.get("result"), dict) and msg["result"].get("action") == "accept"
            if watcher is not None and accepted:
                # Accepting a URL request means "I opened the page", not "I finished it": wait for the page here
                # (without blocking other requests), so setup continues the moment the password is saved.
                await asyncio.wait_for(asyncio.shield(watcher), timeout=max(1.0, deadline - asyncio.get_running_loop().time()))
        except asyncio.TimeoutError:
            return {"action": "cancel"}
        finally:
            if watcher is not None:
                watcher.cancel()
            self.pending.pop(rid, None)
            await self.lock.acquire()
        if "error" in msg:
            return None
        res = msg.get("result") if isinstance(msg.get("result"), dict) else {}
        out = {"action": res.get("action") or "cancel"}
        if isinstance(res.get("content"), dict):
            out["content"] = res["content"]
        return out


    def _page_done(self, url: str) -> bool:
        """True once the person has finished the local page behind `url` (password saved, or plan decided)."""
        from urllib.parse import urlsplit
        from vcf_enterprise_mcp.setup.credential_portal import read_approval_ticket, read_ticket
        kind, _, ticket_id = urlsplit(url).path.strip("/").partition("/")
        spool = Path(self.engine.setup_home) / "portal"
        if kind == "credential":
            ticket = read_ticket(spool, ticket_id)
            return ticket is not None and ticket.status == "STORED"
        if kind == "approve":
            ticket = read_approval_ticket(spool, ticket_id)
            return ticket is not None and ticket.status in ("APPROVED", "REJECTED", "RECORDED")
        return False

    async def _notify_when_page_done(self, url: str, elicitation_id: str) -> None:
        while not self._page_done(url):
            await asyncio.sleep(PAGE_POLL_SECONDS)
        self.write({"jsonrpc": "2.0", "method": "notifications/elicitation/complete", "params": {"elicitationId": elicitation_id}})


async def run_stdio_control_plane(settings: Optional[EnterpriseSettings] = None) -> None:
    """Runs the enterprise control plane over standard input/output (stdio JSON-RPC)."""
    os.environ.setdefault("VCF_MCP_PORTAL_MODE", "detached")
    cfg = settings or get_enterprise_settings()
    engine = _build_engine_from_settings(cfg)
    engine.reloader = _make_reloader(cfg)
    engine.config_stamp = config_file_stamp()  # a terminal edit (e.g. `vcf-mcp vcenter add`) is picked up on the next call
    await StdioSession(engine).run()


def _make_reloader(current: EnterpriseSettings):
    """Callable that rebuilds the engine from the config file as it is now (used after guided setup)."""
    keep_insecure = current.vcf.verify_ssl is False  # a server started with --insecure stays that way

    def reload() -> EnterpriseMCPProtocolEngine:
        fresh = EnterpriseSettings.load_from_yaml()
        if keep_insecure:
            fresh.vcf.verify_ssl = False
        set_enterprise_settings(fresh)
        return _build_engine_from_settings(fresh)
    return reload


def _real_vcf_urls(v) -> dict:
    """The configured appliance URLs, each mapped through vcf.endpoint_overrides when its host name is listed there."""
    from vcf_enterprise_mcp.adapter.connectivity import apply_endpoint_override
    overrides = dict(getattr(v, "endpoint_overrides", None) or {})
    urls = {
        "sddc_manager": v.sddc_manager_url or (f"https://{v.sddc_manager_fqdn}" if v.sddc_manager_fqdn else None),
        "vcenter": v.vcenter_url,
        "nsx": v.nsx_url,
        "vcf_operations": v.operations_url,
    }
    return {k: apply_endpoint_override(u, overrides) for k, u in urls.items()}


def _same_endpoint(a: str, b: str) -> bool:
    """Same host and port (443 when not given), so https://vc and https://vc:443 are one vCenter."""
    pa, pb = urllib.parse.urlsplit(a), urllib.parse.urlsplit(b)
    return (pa.hostname or "").lower() == (pb.hostname or "").lower() and (pa.port or 443) == (pb.port or 443)


def _attached_vcenters(v) -> dict:
    """vcf.vcenters as host -> (base URL after vcf.endpoint_overrides, username or None, credential reference or None)."""
    from vcf_enterprise_mcp.adapter.connectivity import apply_endpoint_override
    overrides = dict(getattr(v, "endpoint_overrides", None) or {})
    return {host: (apply_endpoint_override(t.url, overrides), t.username, t.credential_ref)
            for host, t in (getattr(v, "vcenters", None) or {}).items()}


def _build_engine_from_settings(cfg: EnterpriseSettings) -> EnterpriseMCPProtocolEngine:
    """Builds a fully configured protocol engine from EnterpriseSettings."""
    from vcf_enterprise_mcp.config.settings import apply_production_flag
    apply_production_flag(cfg)
    if cfg.server.storage_mode == "ENTERPRISE_HA":
        if not cfg.server.postgres_dsn:
            raise ValueError("ENTERPRISE_HA requires an explicit postgres_dsn.")
        from vcf_enterprise_mcp.state.postgres_store import PostgresDurableStore
        durable_store = PostgresDurableStore(cfg.server.postgres_dsn)
    else:
        from vcf_enterprise_mcp.state.sqlite_store import SQLiteDurableStore
        from vcf_enterprise_mcp.core.paths import default_db_path
        db_path = default_db_path()  # absolute (~/.vcf-mcp/control_plane.db): desktop apps start servers from "/"
        if db_path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(db_path)), mode=0o700, exist_ok=True)
        durable_store = SQLiteDurableStore(db_path)

    from vcf_enterprise_mcp.auth.idp import EnterpriseIdPValidator
    from vcf_enterprise_mcp.auth.jwks import JWKSManager
    jwks_mgr = JWKSManager(default_ttl_seconds=cfg.idp.jwks_cache_ttl_seconds, allow_lab_tokens=bool(cfg.idp.allow_lab_tokens))
    idp_validator = EnterpriseIdPValidator(config=cfg.idp, jwks_manager=jwks_mgr)

    from vcf_enterprise_mcp.policy.engine import PolicyDecisionPoint
    from vcf_enterprise_mcp.policy.enforcement import PolicyEnforcementPoint
    pdp = PolicyDecisionPoint(config=cfg.policy, durable_store=durable_store)
    from vcf_enterprise_mcp.setup.safety_profile import SafetyProfile
    # Operator safety profile written by guided setup; enforced from the first request.
    pep = PolicyEnforcementPoint(pdp=pdp, safety_profile=SafetyProfile.at_home())

    from vcf_enterprise_mcp.adapter.platform import PlatformClient, PlatformMode
    from vcf_enterprise_mcp.adapter.capability_provider import CapabilityProviderRegistry
    mode_map = {
        "production": PlatformMode.REAL_VCF,
        "digital_twin": PlatformMode.DIGITAL_TWIN,
        "testing": PlatformMode.UNIT_TEST,
    }
    plat_mode = mode_map.get(cfg.server.environment.lower(), PlatformMode.REAL_VCF)
    plat_mode = PlatformMode(str(os.environ.get("VCF_PLATFORM_MODE", plat_mode.value)).upper())
    from vcf_enterprise_mcp.adapter.transport.http import HTTPTransport
    setup_mode = False
    if plat_mode == PlatformMode.REAL_VCF and not any(_real_vcf_urls(cfg.vcf).values()):
        # Nothing to talk to yet: start anyway and serve only the setup tools, so the guided setup can create the
        # configuration. A missing config must never end as "server crashed" in the harness.
        setup_mode = True
        platform_client = PlatformClient(registry=CapabilityProviderRegistry(), mode=PlatformMode.REAL_VCF,
                                         transport=HTTPTransport(verify_ssl=cfg.vcf.verify_ssl, ca_cert_path=cfg.vcf.ca_cert_path))
    elif plat_mode == PlatformMode.REAL_VCF:
        platform_client = _build_real_vcf_platform(cfg)
    else:
        transport = HTTPTransport(verify_ssl=cfg.vcf.verify_ssl, ca_cert_path=cfg.vcf.ca_cert_path)
        platform_client = PlatformClient(
            mode=plat_mode,
            transport=transport,
            digital_twin_url=cfg.vcf.gateway_url,
        )

    from vcf_enterprise_mcp.workflows.task_store import TaskStore
    from vcf_enterprise_mcp.audit.recorder import AuditRecorder
    task_store = TaskStore(durable_store=durable_store)
    audit_recorder = AuditRecorder(durable_store=durable_store)

    return EnterpriseMCPProtocolEngine(
        idp_validator=idp_validator,
        pep=pep,
        task_store=task_store,
        audit_recorder=audit_recorder,
        platform_client=platform_client,
        config=cfg,
        setup_mode=setup_mode,
    )


def _build_real_vcf_platform(cfg: EnterpriseSettings):
    """Builds a REAL_VCF platform from configured appliance endpoints and per-component sessions.

    Every component is optional (a team may only run vCenter, or only VCF Operations): tools whose component is
    not configured are not offered. With no component at all it raises instead of silently targeting loopback
    defaults. Credentials are resolved from the secret registry at login time, never stored on the client.
    """
    from vcf_enterprise_mcp.adapter.capability_provider import CapabilityProviderRegistry
    from vcf_enterprise_mcp.adapter.platform import PlatformClient, PlatformMode
    from vcf_enterprise_mcp.adapter.ssrf_guard import SSRFGuard
    from vcf_enterprise_mcp.adapter.transport.http import HTTPTransport
    from vcf_enterprise_mcp.adapter.transport.vcf_sessions import (
        NSXBasicAuth, SDDCManagerTokenAuth, VCenterSessionAuth, VCFOperationsTokenAuth,
    )
    from vcf_enterprise_mcp.adapter.transport.vcfa_wiring import build_automation_auth
    from vcf_enterprise_mcp.secrets.models import SecretValue
    from vcf_enterprise_mcp.auth.credential_broker import CredentialBroker

    v = cfg.vcf
    urls = _real_vcf_urls(v)
    extra_vcenters = _attached_vcenters(v)
    if not urls.get("vcenter") and extra_vcenters:  # only attached vCenters: the first one serves the vCenter tools
        urls["vcenter"] = next(iter(extra_vcenters.values()))[0]
    if not any(urls.values()):
        raise ValueError("REAL_VCF mode needs at least one vcf endpoint URL (sddc_manager_url, vcenter_url, nsx_url or operations_url); "
                         "run guided setup (vcf_setup) to create them")
    urls = {k: u for k, u in urls.items() if u}

    allow_loopback = bool(v.allow_loopback_targets)
    if allow_loopback and os.environ.get("VCF_MCP_ENV", "").lower() == "production":
        raise ValueError("vcf.allow_loopback_targets is a lab-only setting and is refused when VCF_MCP_ENV=production")
    guard = SSRFGuard(
        allowed_dns_suffixes=v.allowed_dns_suffixes or None,
        allowed_cidrs=v.allowed_cidrs or None,
        allow_loopback=allow_loopback,
        enforce_https=True,
        mock_dns={},
        allow_lab_dns_fallback=False,
    )
    from vcf_enterprise_mcp.adapter.transport.http import proxy_from_settings
    transport = HTTPTransport(ssrf_guard=guard, verify_ssl=v.verify_ssl, ca_cert_path=v.ca_cert_path, proxy=proxy_from_settings(v))
    broker = CredentialBroker(config=v)

    def supplier(provider_type: str):
        ref = v.component_credential_refs.get(provider_type, v.credential_ref)

        def resolve():
            material = broker.resolve_material(ref)
            username = (material.username.reveal_for_transport() if material.username
                        else v.component_usernames.get(provider_type, v.sddc_service_user))
            return username, material.reveal_for_transport()
        return resolve

    def account_supplier(ref: str, username: Optional[str]):
        """An attached vCenter's own service account (its password is under ref)."""
        def resolve():
            material = broker.resolve_material(ref)
            return (username or (material.username.reveal_for_transport() if material.username else "")), material.reveal_for_transport()
        return resolve

    timeout = getattr(v, "timeout_seconds", 30.0)

    def vcenter_auth(base_url: str):
        """A vCenter attached with its own account logs in with it; every other vCenter uses the main vCenter account."""
        for target_url, username, ref in extra_vcenters.values():
            if ref and _same_endpoint(target_url, base_url):
                return VCenterSessionAuth(base_url, transport, account_supplier(ref, username), timeout_seconds=timeout)
        return VCenterSessionAuth(base_url, transport, supplier("vcenter"), timeout_seconds=timeout)

    builders = {
        "sddc_manager": lambda: SDDCManagerTokenAuth(urls["sddc_manager"], transport, supplier("sddc_manager"), timeout_seconds=timeout),
        "vcenter": lambda: vcenter_auth(urls["vcenter"]),
        "nsx": lambda: NSXBasicAuth(supplier("nsx")),
        "vcf_operations": lambda: VCFOperationsTokenAuth(urls["vcf_operations"], transport, supplier("vcf_operations"), timeout_seconds=timeout, auth_source=v.operations_auth_source),
    }
    component_auth = {name: build() for name, build in builders.items() if name in urls}
    registry = CapabilityProviderRegistry.create_for_components(
        version=v.active_version,
        sddc_url=urls.get("sddc_manager"),
        vc_url=urls.get("vcenter"),
        nsx_url=urls.get("nsx"),
        ops_url=urls.get("vcf_operations"),
    )
    platform = PlatformClient(
        registry=registry,
        ssrf_guard=guard,
        transport=transport,
        mode=PlatformMode.REAL_VCF,
        component_auth=component_auth,
    )
    configured = dict(urls)
    discovered: dict = {}

    def auth_factory(provider_type: str, base_url: str):
        # Reuse the configured session for the configured endpoint; one session per other appliance.
        if configured.get(provider_type, "").rstrip("/") == base_url.rstrip("/"):
            return component_auth[provider_type]
        key = (provider_type, base_url.rstrip("/"))
        if key not in discovered:
            if provider_type == "vcenter":
                discovered[key] = vcenter_auth(base_url)
            elif provider_type == "sddc_manager":
                discovered[key] = SDDCManagerTokenAuth(base_url, transport, supplier("sddc_manager"), timeout_seconds=timeout)
            elif provider_type == "vcf_operations":
                discovered[key] = VCFOperationsTokenAuth(base_url, transport, supplier("vcf_operations"), timeout_seconds=timeout,
                                                         auth_source=v.operations_auth_source)
            else:
                discovered[key] = NSXBasicAuth(supplier("nsx"))
        return discovered[key]

    platform.auth_factory = auth_factory
    platform.endpoint_overrides = dict(v.endpoint_overrides)
    platform.extra_vcenters = {host: url for host, (url, _, _) in extra_vcenters.items()}
    platform.main_vcenter_name = urllib.parse.urlsplit(v.vcenter_url).hostname if v.vcenter_url else None

    automation_ref = v.component_credential_refs.get("vcf_automation")

    def persist_automation_token(new_token: str) -> None:
        # VCF Automation rotates the service-account refresh token on every use: write the new one back
        # to the same secret-store entry (the local store replaces its file atomically).
        broker.secret_registry.store(automation_ref, SecretValue(new_token),
                                     description="VCF Automation service-account refresh token (rotated automatically)")

    # Without a dedicated vcf_automation reference the credential would be the shared default one, which must
    # never be overwritten with a token: rotation is then kept in memory only.
    automation, orchestrator = build_automation_auth(v, transport, supplier, persist_automation_token if automation_ref else None, timeout)
    if automation:
        platform.automation = automation
    if orchestrator:
        orch_url, orch_auth = orchestrator
        platform.orchestrator = {
            "url": orch_url, "auth": orch_auth,
            "managed_category": v.orchestrator_managed_category, "module_prefix": v.orchestrator_module_prefix,
            "run_allowlist": list(v.orchestrator_run_allowlist), "blocked": list(v.orchestrator_blocked_workflows),
            "repository_allowlist": list(v.orchestrator_repository_allowlist),
            "script_level": v.orchestrator_script_level,
        }

    def resolve_secret(ref: str) -> str:
        # Secrets for Orchestrator SecureString inputs: resolved server-side, never returned to the model.
        return broker.resolve_material(ref).reveal_for_transport()
    platform.resolve_secret = resolve_secret
    return platform


def run_http_control_plane(settings: Optional[EnterpriseSettings] = None, engine: Optional[EnterpriseMCPProtocolEngine] = None) -> None:
    """Runs the enterprise control plane as an HTTP JSON-RPC gateway."""
    cfg = settings or get_enterprise_settings()
    # Personal access mode is for one person over stdio: refuse it for a network listener before anything is served.
    from vcf_enterprise_mcp.auth.personal import resolve_access_mode
    resolve_access_mode(cfg, server_mode="http")
    if engine is None:
        engine = _build_engine_from_settings(cfg)
        engine.reloader = _make_reloader(cfg)
    if getattr(engine, "personal_principal", None) is not None:
        from vcf_enterprise_mcp.core.errors import ConfigurationException
        raise ConfigurationException("server.access_mode: personal cannot be served over HTTP. Set server.access_mode: team.")
    loop = asyncio.new_event_loop()

    from vcf_enterprise_mcp.core.headers import validate_mcp_headers
    from vcf_enterprise_mcp.core.errors import HeaderMismatchException, UnsupportedProtocolVersionException

    class MCPHTTPHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length > 10 * 1024 * 1024:
                err_bytes = json.dumps({"error": "Payload Too Large"}).encode("utf-8")
                self.send_response(413)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(err_bytes)))
                self.end_headers()
                self.wfile.write(err_bytes)
                return

            body = self.rfile.read(content_length)
            auth_header = self.headers.get("Authorization")
            headers_dict = {k: v for k, v in self.headers.items()}
            client_ip = self.client_address[0] if hasattr(self, "client_address") and self.client_address else "127.0.0.1"

            # Parse JSON body
            try:
                req_json = json.loads(body.decode("utf-8"))
            except Exception as e:
                err_bytes = json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": f"Parse error: {str(e)}"}}).encode("utf-8")
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(err_bytes)))
                self.end_headers()
                self.wfile.write(err_bytes)
                return

            # 1. Enforce Origin validation (R08)
            origin = self.headers.get("Origin")
            if origin:
                allowed = False
                if origin in ("http://localhost", "https://localhost", "http://127.0.0.1", "https://127.0.0.1"):
                    allowed = True
                elif origin.startswith("http://localhost:") or origin.startswith("https://localhost:"):
                    allowed = True
                elif origin.startswith("http://127.0.0.1:") or origin.startswith("https://127.0.0.1:"):
                    allowed = True
                elif hasattr(cfg.server, "allowed_origins") and origin in getattr(cfg.server, "allowed_origins", []):
                    allowed = True

                if not allowed:
                    err_bytes = json.dumps({"error": f"Untrusted Origin: {origin}"}).encode("utf-8")
                    self.send_response(403)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(err_bytes)))
                    self.end_headers()
                    self.wfile.write(err_bytes)
                    return

            # 2. Enforce Header/Body Agreement (R08)
            try:
                validate_mcp_headers(headers_dict, req_json)
            except (HeaderMismatchException, UnsupportedProtocolVersionException) as hme:
                err = {"jsonrpc": "2.0", "id": req_json.get("id") if isinstance(req_json, dict) else None, "error": hme.to_rpc_error()}
                err_bytes = json.dumps(err).encode("utf-8")
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(err_bytes)))
                self.end_headers()
                self.wfile.write(err_bytes)
                return

            # 3. Enforce endpoint path validation (R08)
            clean_path = self.path.split("?")[0].rstrip("/")
            if not clean_path:
                clean_path = "/"
            configured_endpoint = getattr(cfg.server, "mcp_endpoint", "/mcp").rstrip("/")
            allowed_paths = {configured_endpoint, "/mcp", "/rpc"}
            if clean_path not in allowed_paths:
                err_bytes = json.dumps({"error": f"Endpoint not found: {self.path}"}).encode("utf-8")
                self.send_response(404)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(err_bytes)))
                self.end_headers()
                self.wfile.write(err_bytes)
                return

            try:
                resp = loop.run_until_complete(
                    engine.handle_jsonrpc_request(
                        req_json,
                        auth_header=auth_header,
                        client_ip=client_ip,
                        headers=headers_dict,
                    )
                )
                if resp is None:  # JSON-RPC notification: accepted, no body
                    self.send_response(202)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                resp_bytes = json.dumps(resp).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp_bytes)))
                self.end_headers()
                self.wfile.write(resp_bytes)
            except Exception as e:
                err = {"jsonrpc": "2.0", "id": req_json.get("id"), "error": {"code": -32603, "message": str(e)}}
                err_bytes = json.dumps(err).encode("utf-8")
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(err_bytes)))
                self.end_headers()
                self.wfile.write(err_bytes)

        def log_message(self, format, *args):
            pass

    server_address = (cfg.server.host, cfg.server.port)
    httpd = HTTPServer(server_address, MCPHTTPHandler)
    print(f"HTTP MCP Control Plane listening on {cfg.server.host}:{cfg.server.port}...")
    try:
        httpd.serve_forever()
    finally:
        loop.close()


def main(mode: Optional[str] = None, insecure: bool = False):
    # First start (or `client-config` never ran): create a starter config so the server can boot into setup mode.
    from vcf_enterprise_mcp.config.starter import ensure_starter_config
    try:
        ensure_starter_config(EnterpriseSettings.config_path())
    except OSError as exc:
        print(f"Warning: could not create a starter config ({exc}); starting with built-in defaults.", file=sys.stderr)
    settings = copy.deepcopy(get_enterprise_settings())
    if insecure:
        settings.vcf.verify_ssl = False
    effective_mode = mode or settings.server.mode
    from vcf_enterprise_mcp.config.settings import apply_production_flag
    from vcf_enterprise_mcp.auth.personal import resolve_access_mode
    from vcf_enterprise_mcp.core.errors import ConfigurationException
    apply_production_flag(settings)
    try:
        resolve_access_mode(settings, server_mode=effective_mode)  # personal is refused for http / production / HA
    except ConfigurationException as exc:
        print(f"Error: {exc.message}", file=sys.stderr)
        raise SystemExit(2)
    if effective_mode in ("http", "remote_gateway"):
        run_http_control_plane(settings)
    else:
        # MCP clients (LM Studio, Claude Desktop) label every stderr line as an error, so the banner is only
        # shown to a person in a terminal (or with VCF_MCP_VERBOSE=1).
        if sys.stderr.isatty() or os.environ.get("VCF_MCP_VERBOSE") == "1":
            print("Starting Enterprise VCF MCP Control Plane in stdio mode...", file=sys.stderr)
        asyncio.run(run_stdio_control_plane(settings))


if __name__ == "__main__":
    main()
