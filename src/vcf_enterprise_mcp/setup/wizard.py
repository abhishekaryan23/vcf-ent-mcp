# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Guided, interactive setup driven from the MCP harness (tool `vcf_setup`).

Flow: goals -> endpoints & usernames -> credentials -> access verification ->
safety choices -> apply. Each step that needs the user returns an MCP
2026-07-28 InputRequiredResult (MRTR) with an `elicitation/create` request:

- form mode for choices, URLs and usernames (non-secret);
- URL mode for passwords/API keys, pointing at the loopback credential page.
  Secrets never enter tool arguments, elicitation content, requestState, the
  model context or this module's return values.

Clients without elicitation get the same questions as structured data plus a
`resume` token; the assistant asks the user in its own UI and calls again.
"""

from __future__ import annotations

import os
import re
import socket
import tempfile
import time
import urllib.parse
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from vcf_enterprise_mcp.adapter.connectivity import DEFAULT_CIDRS, apply_endpoint_override, classify_connection_error, suffix_for_host
from vcf_enterprise_mcp.adapter.ssrf_guard import SSRFGuard
from vcf_enterprise_mcp.adapter.transport.http import HTTPTransport, parse_proxy, proxy_from_settings
from vcf_enterprise_mcp.adapter.transport.vcf_sessions import (
    NSXBasicAuth,
    SDDCManagerTokenAuth,
    VCenterSessionAuth,
    VCFOperationsTokenAuth,
)
from vcf_enterprise_mcp.core.errors import InvalidArgumentException
from vcf_enterprise_mcp.setup.access_guide import (
    COMPONENT_TITLES,
    DESTRUCTIVE_GROUPS,
    GOALS,
    TOOL_IMPACT,
    components_for_goals,
    is_local_admin,
    least_privilege_guides,
    tools_for_goals,
)
from vcf_enterprise_mcp.setup.access_probe import AccessProbe, ComponentAccess, evaluate_tools
from vcf_enterprise_mcp.setup.credential_portal import CredentialPortal
from vcf_enterprise_mcp.setup.request_state import RequestStateCodec
from vcf_enterprise_mcp.setup.safety_profile import SafetyProfile

# Personal access mode: the roles the person acts as are narrowed to what their goals need (least privilege). MCP_ADMIN is always
# kept so setup can be run again, and VCF_VIEWER so the read and troubleshooting tools stay available.
GOAL_ROLES = {
    "monitor": "VCF_VIEWER", "capacity": "VCF_VIEWER", "vm_operations": "COMPUTE_ADMIN", "network": "NETWORK_ADMIN",
    "lifecycle": "LIFECYCLE_ADMIN", "disaster_recovery": "DR_ADMIN",
}


def personal_roles_for(goals: List[str], automation_configured: bool = False) -> List[str]:
    roles = ["MCP_ADMIN", "VCF_VIEWER"] + [GOAL_ROLES[g] for g in goals if g in GOAL_ROLES]
    if automation_configured:
        roles.append("AUTOMATION_OPERATOR")
    return list(dict.fromkeys(roles))


TARGETS = {
    "digital_twin": "Local Digital Twin (simulated VCF, safe to experiment)",
    "lab": "Non-production VCF lab",
    "production": "Production VCF",
}

SECRET_KEY_RE = re.compile(r"pass(word|wd)?|secret|token|api[_-]?key|credential|private[_-]?key", re.IGNORECASE)
REQUEST_BINDING = "tools/call:vcf_setup"
TENANT = "tenant-default"
ENVIRONMENT = "env-prod"

InputRequired = Dict[str, Any]


def credential_reference(component: str) -> str:
    return f"local://{ENVIRONMENT}/vcf-mcp-{component.replace('_', '-')}"


def _contains_secret_keys(value: Any) -> List[str]:
    found: List[str] = []
    if isinstance(value, dict):
        for k, v in value.items():
            if SECRET_KEY_RE.search(str(k)):
                found.append(str(k))
            found.extend(_contains_secret_keys(v))
    elif isinstance(value, list):
        for v in value:
            found.extend(_contains_secret_keys(v))
    return found


class SetupWizard:
    def __init__(
        self,
        home: Path,
        safety_profile: SafetyProfile,
        secret_registry: Any,
        config_path: Optional[Path] = None,
        portal: Optional[CredentialPortal] = None,
        codec: Optional[RequestStateCodec] = None,
        transport_factory: Optional[Callable[[List[str]], Any]] = None,
        current_config: Optional[Any] = None,
        audit: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        wait_seconds: float = 45.0,
    ):
        self.home = Path(home)
        self.safety = safety_profile
        self.secrets = secret_registry
        self.config_path = Path(config_path) if config_path else self.home / "config.yaml"
        self._portal = portal
        self.codec = codec or RequestStateCodec(home=self.home)
        self.transport_factory = transport_factory or self._default_transport
        self.current_config = current_config
        self.audit = audit or (lambda event, details: None)
        self.wait_seconds = wait_seconds

    # ---- infrastructure ------------------------------------------------------------

    @property
    def portal(self) -> CredentialPortal:
        if self._portal is None:
            if os.environ.get("VCF_MCP_PORTAL_MODE") == "detached":
                # stdio clients may restart the server between turns: serve pages from a separate process.
                from vcf_enterprise_mcp.setup.credential_portal import DetachedPortal
                self._portal = DetachedPortal(self.home / "portal")
            else:
                self._portal = CredentialPortal(sink=self._store_secret)
        return self._portal

    def _store_secret(self, reference: str, secret: Any, tenant_id: str, environment_id: str, description: str) -> None:
        self.secrets.store(reference, secret, tenant_id=tenant_id, environment_id=environment_id, description=description)

    def _credential_present(self, component: str) -> bool:
        try:
            value = self.secrets.resolve(credential_reference(component), tenant_id=TENANT, environment_id=ENVIRONMENT)
            return bool(value.reveal_for_transport())
        except Exception:
            return False

    def _vcf(self) -> Any:
        return getattr(self.current_config, "vcf", None)

    def _reload_config(self) -> None:
        """Picks up hand edits to the config file (and our own network fixes) without restarting the server."""
        try:
            from vcf_enterprise_mcp.config.settings import EnterpriseSettings
            if self.config_path.exists():
                self.current_config = EnterpriseSettings.load_from_yaml(str(self.config_path))
        except Exception:
            pass  # keep the settings we have; a broken file is reported when the server reloads

    @staticmethod
    def _suffixes_for(hosts: List[str]) -> List[str]:
        """DNS suffixes to allow for typed hosts: '.corp.example' for vc.corp.example, the exact name for a single
        label (localhost); IP literals yield none (they are checked against allowed_cidrs)."""
        return sorted({x for x in (suffix_for_host(h) for h in hosts if h) if x})

    def _allowlists(self, hosts: List[str]) -> Tuple[List[str], List[str]]:
        vcf = self._vcf()
        suffixes = sorted(set(list(getattr(vcf, "allowed_dns_suffixes", None) or []) + self._suffixes_for(hosts)))
        cidrs = list(getattr(vcf, "allowed_cidrs", None) or [])
        return suffixes, cidrs

    def _default_transport(self, hosts: List[str]) -> HTTPTransport:
        """HTTPS-only transport for the access check. Honours the same settings as the running server: vcf.ca_cert_path
        (added to the system trust store), vcf.verify_ssl, vcf.https_proxy / HTTPS_PROXY, the allowlists, and the lab-only
        vcf.allow_loopback_targets (never in production)."""
        vcf = self._vcf()
        allow_loopback = bool(getattr(vcf, "allow_loopback_targets", False))
        if allow_loopback and os.environ.get("VCF_MCP_ENV", "").lower() == "production":
            raise InvalidArgumentException("vcf.allow_loopback_targets is a lab-only setting and is refused in production.")
        suffixes, cidrs = self._allowlists(hosts)
        guard = SSRFGuard(allowed_dns_suffixes=suffixes or None, allowed_cidrs=cidrs or None, allow_loopback=allow_loopback,
                          enforce_https=True, mock_dns={}, allow_lab_dns_fallback=False)
        return HTTPTransport(ssrf_guard=guard, max_retries=0,
                             verify_ssl=bool(getattr(vcf, "verify_ssl", True)),
                             ca_cert_path=getattr(vcf, "ca_cert_path", None),
                             proxy=proxy_from_settings(vcf))

    # ---- entry point -----------------------------------------------------------------

    def run(self, principal: Any, arguments: Dict[str, Any], meta: Dict[str, Any]) -> Dict[str, Any]:
        arguments = dict(arguments or {})
        submitted = [r.get("content") for r in (meta.get("inputResponses") or {}).values() if isinstance(r, dict)]
        secret_keys = _contains_secret_keys(arguments) + _contains_secret_keys(submitted)
        if secret_keys:
            raise InvalidArgumentException(
                "Never send passwords, API keys or tokens through chat or tool arguments "
                f"(rejected field(s): {', '.join(sorted(set(secret_keys)))}). Setup will give you a private "
                "local link, or you can run 'vcf-mcp credentials add' in your terminal."
            )
        caps = (meta.get("clientCapabilities") or {}).get("elicitation")
        self.form_ok = caps is not None and (caps == {} or "form" in caps)
        self.url_ok = caps is not None and "url" in caps
        self.principal_id = principal.user_id or principal.principal_id
        self._reload_config()

        token = meta.get("requestState") or arguments.pop("resume", None)
        state = self.codec.decode(token, self.principal_id, REQUEST_BINDING) if token else {}
        responses = meta.get("inputResponses") or {}

        if arguments.get("restart"):
            state = {}
        answered = state.setdefault("answered", [])  # questions the person answered in a dialog or private page
        answered.extend(k for k, r in responses.items() if isinstance(r, dict) and r.get("action") == "accept" and k not in answered)
        # Explicit arguments (non-elicitation clients) fill the same fields as forms.
        for key in ("target", "goals"):
            if key in arguments:
                state[key] = arguments[key]
        if "endpoints" in arguments:
            state.setdefault("endpoints", {}).update(arguments["endpoints"])
        if "usernames" in arguments:
            state.setdefault("usernames", {}).update(arguments["usernames"])
        if isinstance(arguments.get("network"), dict):
            state["network_answer"] = dict(arguments["network"])
        if "disable" in arguments:
            state["safety_choice"] = {"groups": list(arguments["disable"]), "read_only": bool(arguments.get("read_only"))}

        for step in (self._step_goals, self._step_environment, self._step_credentials,
                     self._step_verify, self._step_safety):
            out = step(state, responses)
            if out is not None:
                return out
        return self._step_apply(state)

    # ---- response builders -------------------------------------------------------

    def _state(self, state: Dict[str, Any]) -> str:
        return self.codec.encode(self.principal_id, REQUEST_BINDING, state)

    MAX_ASKS = 3  # the same question answered incompletely this many times stops setup instead of looping

    def _ask(self, state: Dict[str, Any], key: str, message: str, schema: Dict[str, Any],
             questions: List[Dict[str, Any]], summary: Dict[str, Any], problem: Optional[str] = None) -> Dict[str, Any]:
        if problem:
            asks = state.setdefault("incomplete_answers", {})
            asks[key] = asks.get(key, 0) + 1
            if asks[key] >= self.MAX_ASKS:
                return self._result({"status": "STOPPED", "step": key,
                                     "message": f"Setup stopped: this question was answered incompletely {asks[key]} times "
                                                f"({problem}). Nothing was changed. Call vcf_setup again to start over."})
            message = f"{problem} {message}"
        token = self._state(state)
        if self.form_ok:
            return {
                "resultType": "input_required",
                "inputRequests": {key: {"method": "elicitation/create", "params": {
                    "mode": "form", "message": message, "requestedSchema": schema}}},
                "requestState": token,
            }
        return self._result({
            "status": "NEEDS_INPUT",
            "step": key,
            "message": message,
            "questions": questions,
            "how_to_continue": "Ask the user these questions with your own question UI, then call vcf_setup again with the answers "
                               "as arguments plus 'resume'. Never ask the user for passwords or API keys in chat.",
            "resume": token,
            **summary,
        })

    @staticmethod
    def _result(payload: Dict[str, Any]) -> Dict[str, Any]:
        return {"structured": payload}

    @staticmethod
    def _accepted(responses: Dict[str, Any], key: str) -> Tuple[Optional[str], Dict[str, Any]]:
        resp = responses.get(key)
        if not isinstance(resp, dict):
            return None, {}
        return resp.get("action"), resp.get("content") or {}

    def _declined(self, step: str) -> Dict[str, Any]:
        self.audit("setup.cancelled", {"step": step})
        return self._result({"status": "CANCELLED", "step": step,
                             "message": "Setup stopped; nothing was changed. Call vcf_setup again any time."})

    # ---- step 1: goals ---------------------------------------------------------------

    def _step_goals(self, state: Dict[str, Any], responses: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        action, content = self._accepted(responses, "goals")
        if action in ("decline", "cancel"):
            return self._declined("goals")
        problem = None
        if action == "accept":
            state["target"] = content.get("target")
            state["goals"] = content.get("goals") or []
            if state["target"] not in TARGETS or not state["goals"]:
                problem = ("Choose what it connects to and at least one goal." if not state["goals"]
                           else "Choose what it connects to.")
        if state.get("target") in TARGETS and state.get("goals"):
            unknown = [g for g in state["goals"] if g not in GOALS]
            if unknown:
                raise InvalidArgumentException(f"Unknown goal(s): {unknown}. Choose from {sorted(GOALS)}.")
            return None
        schema = {
            "type": "object",
            "properties": {
                "target": {"type": "string", "title": "What will this MCP connect to?",
                           "oneOf": [{"const": k, "title": v} for k, v in TARGETS.items()], "default": "digital_twin"},
                "goals": {"type": "array", "title": "What do you want to use it for?", "minItems": 1,
                          "description": "Pick only what you need; each choice decides the access you will be asked to grant.",
                          "items": {"anyOf": [{"const": g.key, "title": g.title} for g in GOALS.values()]},
                          "default": ["monitor"]},
            },
            "required": ["target", "goals"],
        }
        questions = [
            {"field": "target", "question": "What will this MCP connect to?", "options": TARGETS},
            {"field": "goals", "question": "What do you want to use it for? (multi-select)", "multi_select": True,
             "options": {g.key: f"{g.title}: {g.description}" for g in GOALS.values()}},
        ]
        return self._ask(state, "goals",
                         "Welcome to VCF Enterprise MCP setup. This is an unofficial community project (not a Broadcom "
                         "or VMware product) and it is under testing: use the Digital Twin or a non-production lab. "
                         "Tell me what you want to do, and I'll work out the least access needed and walk you through granting it.",
                         schema, questions, {}, problem)

    # ---- step 2: endpoints and usernames ----------------------------------------------

    def _needed_components(self, state: Dict[str, Any]) -> List[str]:
        return components_for_goals(state.get("goals") or [])

    def _step_environment(self, state: Dict[str, Any], responses: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        action, content = self._accepted(responses, "environment")
        if action in ("decline", "cancel"):
            return self._declined("environment")
        if action == "accept":
            for comp in COMPONENT_TITLES:
                if content.get(f"{comp}_url"):
                    state.setdefault("endpoints", {})[comp] = content[f"{comp}_url"].strip()
                if content.get(f"{comp}_username"):
                    state.setdefault("usernames", {})[comp] = content[f"{comp}_username"].strip()
            if content.get("twin_url"):
                state.setdefault("endpoints", {})["digital_twin"] = content["twin_url"].strip()

        if state["target"] == "digital_twin":
            if state.get("endpoints", {}).get("digital_twin"):
                return None
            default_url = getattr(getattr(self.current_config, "vcf", None), "gateway_url", None) or "http://127.0.0.1:8085"
            schema = {"type": "object", "properties": {"twin_url": {
                "type": "string", "format": "uri", "title": "Digital Twin URL", "default": default_url}}, "required": ["twin_url"]}
            return self._ask(state, "environment", "Where is the Digital Twin running? No real credentials are needed for it.",
                             schema, [{"field": "endpoints.digital_twin", "question": "Digital Twin URL", "default": default_url}], {})

        needed = self._needed_components(state)
        endpoints, usernames = state.get("endpoints", {}), state.get("usernames", {})
        missing = [c for c in needed if not endpoints.get(c) or not usernames.get(c)]
        if not missing:
            errors = self._validate_endpoints({c: endpoints[c] for c in needed})
            if errors:
                for c in errors:
                    endpoints.pop(c, None)
                missing = list(errors)
            else:
                return None
        else:
            errors = {}

        props: Dict[str, Any] = {}
        questions = []
        for comp in missing:
            title = COMPONENT_TITLES[comp]
            props[f"{comp}_url"] = {"type": "string", "format": "uri", "title": f"{title} URL",
                                    "description": f"e.g. https://{comp.replace('_', '-')}.example.internal"}
            props[f"{comp}_username"] = {"type": "string", "title": f"{title} service-account username",
                                         "description": "Username only. You will enter the password on a private page, never in chat."}
            questions.append({"field": f"endpoints.{comp}", "question": f"{title} URL (https://...)"})
            questions.append({"field": f"usernames.{comp}", "question": f"{title} service-account username (no password)"})
        msg = "Which appliances should I connect to, and which service account should I use for each? "
        if errors:
            msg += "Please fix: " + "; ".join(f"{COMPONENT_TITLES[c]}: {e}" for c, e in errors.items()) + ". "
        msg += "Passwords are collected separately on a private local page."
        return self._ask(state, "environment", msg,
                         {"type": "object", "properties": props, "required": list(props)}, questions,
                         {"early_warnings": self._username_warnings(state)})

    @staticmethod
    def _validate_endpoints(endpoints: Dict[str, str]) -> Dict[str, str]:
        errors = {}
        for comp, url in endpoints.items():
            parts = urllib.parse.urlsplit(url)
            if parts.scheme != "https" or not parts.hostname:
                errors[comp] = "must be an https:// URL"
            elif parts.username or parts.password:
                errors[comp] = "must not contain credentials"
            elif parts.path not in ("", "/") or parts.query:
                errors[comp] = "use the appliance base URL without a path"
        return errors

    def _username_warnings(self, state: Dict[str, Any]) -> List[str]:
        return [
            f"{COMPONENT_TITLES[c]}: '{u}' looks like a built-in local administrator. That account can do everything, "
            "including destructive actions. A scoped service account is strongly recommended."
            for c, u in (state.get("usernames") or {}).items() if is_local_admin(c, u)
        ]

    # ---- step 3: credentials -----------------------------------------------------------

    def _step_credentials(self, state: Dict[str, Any], responses: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if state["target"] == "digital_twin":
            return None
        needed = self._needed_components(state)
        tickets: Dict[str, str] = state.setdefault("tickets", {})

        for comp in needed:  # declined URL elicitations stop setup
            action, _ = self._accepted(responses, f"login_{comp}")
            if action in ("decline", "cancel"):
                return self._declined(f"login_{comp}")

        # Wait briefly for pages the user is filling in (the spec allows blocking here).
        deadline = time.time() + (self.wait_seconds if tickets else 0)
        while True:
            pending = []
            for comp in needed:
                if self._credential_present(comp):
                    continue
                ticket = self.portal.get(tickets[comp], self.principal_id) if comp in tickets else None
                if ticket is None or ticket.effective_status() in ("EXPIRED", "FAILED"):
                    pending.append((comp, None))
                elif ticket.status != "STORED":
                    pending.append((comp, ticket))
            if not pending:
                return None
            if all(t is None for _, t in pending) or time.time() >= deadline:
                break
            time.sleep(0.5)

        requests: Dict[str, Any] = {}
        links = []
        for comp, ticket in pending:
            if ticket is None:
                host = urllib.parse.urlsplit(state["endpoints"][comp]).hostname
                ticket = self.portal.issue(
                    principal_id=self.principal_id, component=comp, component_title=COMPONENT_TITLES[comp],
                    endpoint_host=host, username=state["usernames"][comp], reference=credential_reference(comp),
                    tenant_id=TENANT, environment_id=ENVIRONMENT,
                )
                tickets[comp] = ticket.ticket_id
            url = self.portal.url_for(ticket)
            # Clients may show only the first line of a message, so the code and the ask come first.
            message = (f"Code {ticket.verification_code}: {COMPONENT_TITLES[ticket.component]} password for '{ticket.username}'. "
                       "Open the private page on this computer, check it shows the same code, and enter the password there. "
                       "It goes straight to the secret store and is never shown to the assistant.")
            requests[f"login_{comp}"] = {"method": "elicitation/create", "params": {"mode": "url", "url": url, "message": message}}
            links.append({"component": comp, "url": url, "verification_code": ticket.verification_code,
                          "cli_alternative": f"vcf-mcp credentials add --name vcf-mcp-{comp.replace('_', '-')} "
                                             f"--username {ticket.username} --provider local --env {ENVIRONMENT} "
                                             f"--reference {credential_reference(comp)}"})

        token = self._state(state)
        if self.url_ok:
            return {"resultType": "input_required", "inputRequests": requests, "requestState": token}
        return self._result({
            "status": "NEEDS_CREDENTIALS",
            "step": "credentials",
            "message": "Each password must be entered outside the chat. Give the user these private local links "
                       "(or the terminal command), wait until they say they are done, then call vcf_setup again with 'resume'.",
            "credential_pages": links,
            "resume": token,
            "warnings": self._username_warnings(state),
        })

    # ---- step 4: verify access --------------------------------------------------------

    def _auth_for(self, comp: str, url: str, username: str, transport: Any):
        def supplier():
            secret = self.secrets.resolve(credential_reference(comp), tenant_id=TENANT, environment_id=ENVIRONMENT)
            return username, secret.reveal_for_transport()
        if comp == "vcenter":
            return VCenterSessionAuth(url, transport, supplier)
        if comp == "sddc_manager":
            return SDDCManagerTokenAuth(url, transport, supplier)
        if comp == "vcf_operations":
            return VCFOperationsTokenAuth(url, transport, supplier)
        return NSXBasicAuth(supplier)

    # ---- network fixes (asked as questions, never applied silently) ----------------------------

    NETWORK_KEYS = ("ca_cert_path", "https_proxy", "no_proxy")

    def _merge_vcf_config(self, changes: Dict[str, Any]) -> None:
        """Writes agreed network settings into the vcf: section of the config file (atomic), then reloads them."""
        import yaml
        data: Dict[str, Any] = {}
        if self.config_path.exists():
            data = yaml.safe_load(self.config_path.read_text(encoding="utf-8")) or {}
        vcf = data.setdefault("vcf", {})
        for key, spec in changes.items():
            if "add" in spec:
                current = list(vcf.get(key) or [])
                if key == "allowed_cidrs" and not current:
                    current = list(DEFAULT_CIDRS)  # a list replaces the defaults, so start from them
                for item in spec["add"]:
                    if item not in current:
                        current.append(item)
                vcf[key] = current
            else:
                vcf[key] = spec["set"]
        self._atomic_write(self.config_path, yaml.safe_dump(data, sort_keys=False))
        self._reload_config()

    def _apply_network_answer(self, state: Dict[str, Any]) -> None:
        answer = state.pop("network_answer", None)
        if not answer:
            return
        changes: Dict[str, Any] = {}
        if answer.get("apply_suggested_changes"):
            for fix in state.get("pending_fixes") or []:
                if fix.get("key") == "allow_loopback_targets" and (state.get("target") == "production"
                                                                  or os.environ.get("VCF_MCP_ENV", "").lower() == "production"):
                    continue  # lab-only switch: never offered or applied for production
                if "add" in fix:
                    changes.setdefault(fix["key"], {"add": []})["add"].append(fix["add"])
                elif "set" in fix:
                    changes[fix["key"]] = {"set": fix["set"]}
        ca = (answer.get("ca_cert_path") or "").strip()
        if ca:
            path = Path(ca).expanduser()
            if not path.is_file():
                raise InvalidArgumentException(f"network.ca_cert_path: '{ca}' is not a readable file on this computer.")
            try:
                import ssl
                ssl.create_default_context().load_verify_locations(cafile=str(path))
            except (ssl.SSLError, OSError) as exc:
                raise InvalidArgumentException(f"network.ca_cert_path: '{ca}' is not a valid PEM CA bundle ({type(exc).__name__}).")
            changes["ca_cert_path"] = {"set": str(path.resolve())}
        proxy = (answer.get("https_proxy") or "").strip()
        if proxy:
            try:
                parse_proxy(proxy)
            except ValueError as exc:
                raise InvalidArgumentException(f"network.https_proxy: {exc}")
            changes["https_proxy"] = {"set": proxy}
        if answer.get("no_proxy"):
            changes["no_proxy"] = {"set": str(answer["no_proxy"]).strip()}
        if changes:
            self._merge_vcf_config(changes)
            self.audit("setup.network_changed", {"keys": sorted(changes)})
            if state.pop("reverify_after_network", False):
                state.pop("access", None)  # probe again with the new settings; saved passwords are reused
        state.pop("pending_fixes", None)

    def _network_questions(self, problems: List[Dict[str, Any]], fixes: List[Dict[str, Any]]):
        causes = {p.get("cause") for p in problems}
        props: Dict[str, Any] = {}
        questions: List[Dict[str, Any]] = []
        if fixes:
            props["apply_suggested_changes"] = {"type": "boolean", "title": "Add the suggested allowlist entries to the MCP config?", "default": False}
            questions.append({"field": "network.apply_suggested_changes", "question": "Add these entries to the MCP config file? "
                              + "; ".join(sorted({f"{f['key']}: {f.get('add', f.get('set'))}" for f in fixes}))})
        if "tls_certificate" in causes:
            props["ca_cert_path"] = {"type": "string", "title": "Path to the CA bundle (PEM) that signed the appliance certificates",
                                     "description": "It is added to the system trust store; nothing is replaced."}
            questions.append({"field": "network.ca_cert_path", "question": "Path to the PEM CA chain that signed the appliance certificates (optional)"})
        if causes & {"timeout", "unreachable", "proxy"}:
            props["https_proxy"] = {"type": "string", "title": "HTTPS proxy (only if this computer needs one), e.g. http://proxy.example.internal:3128"}
            questions.append({"field": "network.https_proxy", "question": "HTTPS proxy URL, if this computer must use one (optional)"})
        return props, questions

    @staticmethod
    def _fixes_from(problems: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen, out = set(), []
        for p in problems:
            change = p.get("change")
            if change and (change["key"], change.get("add", change.get("set"))) not in seen:
                seen.add((change["key"], change.get("add", change.get("set"))))
                out.append(change)
        return out

    def _discover_blocked(self, state: Dict[str, Any], transport: Any, probe: AccessProbe) -> List[Dict[str, Any]]:
        """After SDDC Manager login: list the vCenters and NSX Managers it knows and check that THIS MCP may contact
        each one. Appliance names from SDDC Manager are canonical FQDNs, often different from what was typed."""
        if "sddc_manager" not in self._needed_components(state):
            return []
        user = state["usernames"]["sddc_manager"]
        url = apply_endpoint_override(state["endpoints"]["sddc_manager"], getattr(self._vcf(), "endpoint_overrides", None))
        try:
            prov = probe._provider(url, self._auth_for("sddc_manager", url, user, transport))
            fqdns = [e.get("fqdn") for e in (prov.request("GET", "/v1/vcenters").json() or {}).get("elements", []) if e.get("fqdn")]
            try:
                fqdns += [e.get("vipFqdn") for e in (prov.request("GET", "/v1/nsxt-clusters").json() or {}).get("elements", []) if e.get("vipFqdn")]
            except Exception:
                pass
        except Exception:
            return []  # discovery is best effort here; the runtime reports what it cannot reach
        vcf = self._vcf()
        overrides = dict(getattr(vcf, "endpoint_overrides", None) or {})
        guard = getattr(transport, "ssrf_guard", None)
        out: List[Dict[str, Any]] = []
        for fqdn in sorted(set(fqdns)):
            target = overrides.get(fqdn) or f"https://{fqdn}"
            try:
                guard.resolve_destination(target, allow_unresolved=getattr(transport, "proxy", None) is not None)
            except Exception as exc:
                problem = classify_connection_error(exc, target, vcf).to_dict()
                problem["appliance"] = fqdn
                out.append(problem)
        return out

    # ---- step 4: verify access --------------------------------------------------------

    def _auth_for(self, comp: str, url: str, username: str, transport: Any):
        def supplier():
            secret = self.secrets.resolve(credential_reference(comp), tenant_id=TENANT, environment_id=ENVIRONMENT)
            return username, secret.reveal_for_transport()
        if comp == "vcenter":
            return VCenterSessionAuth(url, transport, supplier)
        if comp == "sddc_manager":
            return SDDCManagerTokenAuth(url, transport, supplier)
        if comp == "vcf_operations":
            return VCFOperationsTokenAuth(url, transport, supplier)
        return NSXBasicAuth(supplier)

    def _step_verify(self, state: Dict[str, Any], responses: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        action, content = self._accepted(responses, "network")
        if action == "accept":
            state["network_answer"] = {k: v for k, v in content.items()}
        elif action in ("decline", "cancel"):
            state.pop("pending_fixes", None)
            state["network_declined"] = True
        self._apply_network_answer(state)
        if "access" in state:
            return None
        if state["target"] == "digital_twin":
            state["access"] = {}
            return None
        needed = self._needed_components(state)
        # A typed name listed in vcf.endpoint_overrides is contacted at its mapped address, as the running server will do.
        overrides = dict(getattr(self._vcf(), "endpoint_overrides", None) or {})
        targets = {c: apply_endpoint_override(state["endpoints"][c], overrides) for c in needed}
        hosts = [urllib.parse.urlsplit(targets[c]).hostname for c in needed]
        transport = self.transport_factory(hosts)
        probe = AccessProbe(transport, vcf_config=self._vcf())
        results: Dict[str, Dict[str, Any]] = {}
        for comp in needed:
            url, user = targets[comp], state["usernames"][comp]
            results[comp] = probe.probe(comp, url, user, self._auth_for(comp, url, user, transport)).to_dict()
        state["access"] = results
        self.audit("setup.access_verified", {c: {k: v for k, v in r.items() if k in ("identity", "roles", "authenticated", "over_permissive")}
                                              for c, r in results.items()})
        failed = [c for c, r in results.items() if not r["authenticated"]]
        if failed:
            # Only a real login rejection (HTTP 401, or 403 while logging in) means the password is wrong. Every other
            # failure (TLS, DNS, firewall, allowlist, proxy) keeps the saved password so it is never typed again.
            rejected = [c for c in failed if results[c].get("login_rejected")]
            kept = [c for c in failed if c not in rejected]
            for c in rejected:
                state.get("tickets", {}).pop(c, None)
                try:
                    self.secrets.delete(credential_reference(c), tenant_id=TENANT, environment_id=ENVIRONMENT)
                except Exception:
                    pass
            access = state.pop("access")
            problems = [dict(access[c]["problem"], component=c) for c in failed if access[c].get("problem")
                        and not access[c].get("login_rejected")]
            fixes = self._fixes_from(problems)
            state["pending_fixes"] = fixes
            state["reverify_after_network"] = True
            payload: Dict[str, Any] = {
                "status": "ACCESS_CHECK_FAILED",
                "step": "verify",
                "components": {c: access[c] for c in failed},
                "problems": problems,
                "passwords_kept": kept,
                "passwords_discarded": rejected,
                "message": "I could not verify: " + ", ".join(COMPONENT_TITLES[c] for c in failed) + ". "
                           + ("Wrong credentials for " + ", ".join(COMPONENT_TITLES[c] for c in rejected) + ": enter the password again. " if rejected else "")
                           + (" ".join(f"{COMPONENT_TITLES[p['component']]}: {p['summary']}" for p in problems) + " " if problems else "")
                           + ("The passwords you entered for " + ", ".join(COMPONENT_TITLES[c] for c in kept) + " were kept; you will not be asked for them again."
                              if kept else ""),
                "resume": self._state(state),
            }
            props, questions = self._network_questions(problems, fixes)
            if problems:
                payload["fix_in_config_file"] = [
                    {"component": p["component"], "cause": p["cause"], "config_key": p.get("config_key"), "yaml": p.get("fix")}
                    for p in problems if p.get("config_key")]
                payload["config_file"] = str(self.config_path)
                payload["how_to_continue"] = ("Ask the user the questions below, then call vcf_setup again with their answers under 'network' plus "
                                              "'resume'. Or they can edit the config file with the YAML above; setup picks the file up on the next call.")
            if props and self.form_ok:
                return self._ask(state, "network", payload["message"], {"type": "object", "properties": props}, questions, {})
            if questions:
                payload["questions"] = questions
            return self._result(payload)

        blocked = [] if state.get("discovery_asked") else self._discover_blocked(state, transport, probe)
        if blocked:
            state["discovery_asked"] = True
            fixes = [f for f in self._fixes_from(blocked) if f.get("key") != "allow_loopback_targets"]
            state["pending_fixes"] = fixes
            state["reverify_after_network"] = False
            state["discovery_blocked"] = [{"appliance": b["appliance"], "cause": b["cause"]} for b in blocked]
            names = ", ".join(b["appliance"] for b in blocked)
            props, questions = self._network_questions(blocked, fixes)
            msg = (f"SDDC Manager knows these appliances, but this MCP's own network settings stop it contacting them: {names}. That is an MCP "
                   "configuration issue, not an appliance fault. " + " ".join(sorted({b["summary"] for b in blocked})))
            if props:
                if self.form_ok:
                    return self._ask(state, "network", msg, {"type": "object", "properties": props}, questions, {})
                return self._result({"status": "NEEDS_INPUT", "step": "network", "message": msg, "questions": questions,
                                     "blocked_appliances": [{k: b.get(k) for k in ("appliance", "cause", "summary", "config_key", "fix")} for b in blocked],
                                     "how_to_continue": "Ask the user, then call vcf_setup again with their answer under 'network' plus 'resume'. "
                                                        "If they decline, call again with network: {} and setup continues with a warning.",
                                     "resume": self._state(state)})
        return None

    # ---- step 5: safety choices -------------------------------------------------------

    def _report(self, state: Dict[str, Any]) -> Dict[str, Any]:
        access = {c: ComponentAccess(**r) for c, r in (state.get("access") or {}).items()}
        goals = state.get("goals") or []
        goal_tools = tools_for_goals(goals)
        reachable_destructive = [t for t in TOOL_IMPACT if t not in goal_tools]
        if state["target"] == "digital_twin":
            tools = {t: {"state": "AVAILABLE", "impact": TOOL_IMPACT[t].level if t in TOOL_IMPACT else "READ",
                         "why": "Digital Twin (simulated)"} for t in goal_tools}
            extra = {}
            unconfirmed = {}
        else:
            tools = evaluate_tools(access, goal_tools, self.safety)
            outside = evaluate_tools(access, reachable_destructive, self.safety)
            extra = {t: v for t, v in outside.items() if v["state"] == "AVAILABLE"}  # confirmed reachable
            unconfirmed = {t: v for t, v in outside.items() if v["state"] == "UNVERIFIED"}  # could not be ruled out
        over = [c for c, a in access.items() if a.over_permissive]
        warnings = []
        for c in over:
            warnings.append(f"{COMPONENT_TITLES[c]}: the account is over-permissive. " + " ".join(access[c].findings))
        if extra:
            warnings.append("These actions are confirmed reachable with the accounts you gave but are outside what you asked for: "
                            + ", ".join(f"{t} ({TOOL_IMPACT[t].level.lower()})" for t in extra) + ".")
        if unconfirmed:
            warnings.append("Could not rule out (the account's privileges at the root were not confirmed; this is normal for a scoped "
                            "least-privilege account): " + ", ".join(f"{t} ({TOOL_IMPACT[t].level.lower()})" for t in unconfirmed) + ".")
        for item in state.get("discovery_blocked") or []:
            warnings.append(f"{item['appliance']} was discovered through SDDC Manager but is blocked by this MCP's network settings "
                            f"({item['cause']}); inventory and troubleshooting will skip it until vcf.allowed_dns_suffixes / vcf.endpoint_overrides "
                            "allow it. This is an MCP configuration issue, not an appliance fault.")
        if any(not GOALS[g].implemented_for_real_vcf for g in goals) and state["target"] != "digital_twin":
            warnings.append("Disaster-recovery drills are not available against real VCF yet.")
        return {
            "goals": [GOALS[g].title for g in goals],
            "components": {c: {k: v for k, v in a.to_dict().items() if k in ("identity", "roles", "authenticated", "local_admin", "over_permissive", "findings")}
                           for c, a in access.items()},
            "what_i_can_do": [{"tool": t, **v} for t, v in tools.items()],
            "also_reachable_outside_your_goals": [{"tool": t, **v} for t, v in extra.items()],
            "could_not_be_excluded": [{"tool": t, **v} for t, v in unconfirmed.items()],
            "warnings": warnings,
            "least_privilege_guide": {c: vars(g) for c, g in least_privilege_guides(goals).items()
                                      if c in over or state["target"] != "digital_twin"},
            "over_permissive_components": over,
        }

    def _step_safety(self, state: Dict[str, Any], responses: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        action, content = self._accepted(responses, "safety")
        if action in ("decline", "cancel"):
            state["safety_choice"] = {"groups": [], "read_only": False}
        elif action == "accept":
            state["safety_choice"] = {"groups": [g for g in DESTRUCTIVE_GROUPS if content.get(g)],
                                      "read_only": bool(content.get("read_only"))}
        if "safety_choice" in state:
            return None

        report = self._report(state)
        goal_tools = set(tools_for_goals(state.get("goals") or []))
        over = bool(report["over_permissive_components"])
        props: Dict[str, Any] = {}
        questions = []
        for key, (title, tools) in DESTRUCTIVE_GROUPS.items():
            outside_goals = not (set(tools) & goal_tools)
            default = outside_goals or over and any(TOOL_IMPACT[t].level == "DESTRUCTIVE" for t in tools)
            props[key] = {"type": "boolean", "title": title, "default": bool(default),
                          "description": "; ".join(TOOL_IMPACT[t].summary for t in tools)
                          + (" Not part of what you asked for." if outside_goals else "")}
            questions.append({"field": f"disable[{key}]", "question": title, "default": bool(default)})
        props["read_only"] = {"type": "boolean", "title": "Read-only mode (block every change)",
                              "default": not (goal_tools & set(TOOL_IMPACT)),
                              "description": "Safest start. Changes stay possible as dry runs only."}
        questions.append({"field": "read_only", "question": "Read-only mode (block every change)?"})
        can = [t["tool"] for t in report["what_i_can_do"] if t["state"] == "AVAILABLE"]
        maybe = [t["tool"] for t in report["what_i_can_do"] if t["state"] == "UNVERIFIED"]
        blocked = [t["tool"] for t in report["what_i_can_do"] if t["state"] not in ("AVAILABLE", "UNVERIFIED")]
        message = ("Choose which actions to block (ticked items are blocked by the server; only the local CLI can unblock them). "
                   + "With this access I can: " + (", ".join(can) or "nothing yet") + ". "
                   + ("Needs confirmation: " + ", ".join(maybe) + ". " if maybe else "")
                   + ("Not possible with this access: " + ", ".join(blocked) + ". " if blocked else "")
                   + (" ".join(report["warnings"]) if report["warnings"] else ""))
        return self._ask(state, "safety", message, {"type": "object", "properties": props}, questions,
                         {"access_report": report, "disable_options": list(DESTRUCTIVE_GROUPS)})

    # ---- step 6: apply --------------------------------------------------------------

    def _step_apply(self, state: Dict[str, Any]) -> Dict[str, Any]:
        choice = state.get("safety_choice") or {}
        groups = [g for g in choice.get("groups", []) if g in DESTRUCTIVE_GROUPS]
        tools = [t for g in groups for t in DESTRUCTIVE_GROUPS[g][1]]
        added = self.safety.tighten(tools, reason="disabled during guided setup", actor=self.principal_id,
                                    read_only=choice.get("read_only"))
        mode = self._write_config(state)
        report = self._report(state)
        answered = state.get("answered") or []
        payload = {
            "status": "COMPLETE",
            "summary": f"Setup saved for {TARGETS[state['target']]}.",
            "your_choices": {
                "connects_to": TARGETS[state["target"]],
                "goals": [GOALS[g].title for g in state.get("goals") or []],
                "read_only": self.safety.read_only,
                "answered_by": (f"you, in {len(answered)} setup question(s) shown by your client" if answered
                                else "the arguments of this tool call (no setup questions were shown)"),
            },
            "access_report": report,
            "safety_profile": self.safety.as_dict(),
            "newly_disabled": added,
            "config_file": str(self.config_path),
            "next_steps": [
                "Restart the MCP server (or reconnect it in your harness) to load the new endpoints.",
                "Ask 'what can you do?' (vcf_access_report) at any time to see current access.",
                "To re-enable a blocked action, run locally: vcf-mcp safety enable <tool>.",
            ],
        }
        if mode == "DISCOVERY_ONLY" and set(tools_for_goals(state.get("goals") or [])) & set(TOOL_IMPACT):
            payload["next_steps"].insert(0, "Changes are still hidden because policy.operating_mode is DISCOVERY_ONLY. When you "
                                            f"are ready, set it to AUDITED_OPERATIONS in {self.config_path} yourself; "
                                            "the assistant cannot widen its own permissions.")
        if state["target"] == "production" and getattr(getattr(self.current_config, "idp", None), "allow_lab_tokens", False):
            payload["next_steps"].insert(0, "This is a production setup but lab tokens are still accepted (idp.allow_lab_tokens: true). Configure your identity "
                                            f"provider (idp.issuer_url, idp.client_id, idp.jwks_uri), then in {self.config_path} set idp.allow_lab_tokens: "
                                            "false and server.production_mode: true.")
        if state["target"] == "digital_twin" and not self._twin_answers(state["endpoints"]["digital_twin"]):
            url = state["endpoints"]["digital_twin"]
            port = urllib.parse.urlsplit(url).port or 8085
            report["warnings"].append(f"Nothing is answering at {url} yet, so VCF questions will fail until the Digital Twin runs.")
            payload["next_steps"].insert(0, f"Start the Digital Twin (nothing answers at {url} yet). In your clone of the repository: "
                                            f"PYTHONPATH=tests/fixtures .venv/bin/python -m digital_twin.run --host 127.0.0.1 --port {port}")
        if report["over_permissive_components"]:
            payload["next_steps"].insert(0, "Replace the over-permissive account(s) with the least-privilege accounts in "
                                            "'least_privilege_guide', then run vcf_setup again.")
        self._write_report(report)
        self.audit("setup.applied", {"target": state["target"], "goals": state.get("goals"), "disabled": added,
                                     "read_only": self.safety.read_only})
        return self._result(payload)

    @staticmethod
    def _twin_answers(url: str) -> bool:
        parts = urllib.parse.urlsplit(url)
        try:
            with socket.create_connection((parts.hostname or "127.0.0.1", parts.port or (443 if parts.scheme == "https" else 80)), timeout=1.5):
                return True
        except OSError:
            return False

    def _atomic_write(self, path: Path, text: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(text)
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise

    def _write_config(self, state: Dict[str, Any]) -> None:
        import yaml
        data: Dict[str, Any] = {}
        if self.config_path.exists():
            data = yaml.safe_load(self.config_path.read_text(encoding="utf-8")) or {}
        server = data.setdefault("server", {})
        vcf = data.setdefault("vcf", {})
        policy = data.setdefault("policy", {})
        if state["target"] == "digital_twin":
            server["environment"] = "digital_twin"
            vcf["gateway_url"] = state["endpoints"]["digital_twin"]
        else:
            server["environment"] = "production"
            keys = {"sddc_manager": "sddc_manager_url", "vcenter": "vcenter_url", "nsx": "nsx_url", "vcf_operations": "operations_url"}
            for comp in self._needed_components(state):
                vcf[keys[comp]] = state["endpoints"][comp]
                vcf.setdefault("component_usernames", {})[comp] = state["usernames"][comp]
                vcf.setdefault("component_credential_refs", {})[comp] = credential_reference(comp)
            # Union with what is already allowed (never drop an entry the operator or a network fix added). IP literals
            # contribute no DNS suffix; a single-label host such as localhost is allowed by name.
            # A name mapped through vcf.endpoint_overrides is contacted at its mapped address, so allow that host too.
            overrides = vcf.get("endpoint_overrides") or {}
            urls = vcf_urls(vcf)
            typed_hosts = [urllib.parse.urlsplit(u).hostname for u in urls + [apply_endpoint_override(u, overrides) for u in urls]]
            suffixes = sorted(set(vcf.get("allowed_dns_suffixes") or []) | set(self._suffixes_for([h for h in typed_hosts if h])))
            if suffixes:
                vcf["allowed_dns_suffixes"] = suffixes
            vcf.setdefault("verify_ssl", True)
        if str(server.get("access_mode") or "").lower() == "personal":
            # Personal mode: act as the narrowest roles the chosen goals need (takes effect when setup reloads the server).
            server["personal_roles"] = personal_roles_for(state.get("goals") or [], bool(vcf.get("automation_url")))
        # Setup through MCP only tightens: it never moves the policy out of DISCOVERY_ONLY.
        policy.setdefault("operating_mode", "DISCOVERY_ONLY")
        self._atomic_write(self.config_path, yaml.safe_dump(data, sort_keys=False))
        return policy["operating_mode"]

    def _write_report(self, report: Dict[str, Any]) -> None:
        import json
        report = dict(report, generated_at=int(time.time()))
        self._atomic_write(self.home / "access_report.json", json.dumps(report, indent=2))


def vcf_urls(vcf: Dict[str, Any]) -> List[str]:
    return [vcf[k] for k in ("sddc_manager_url", "vcenter_url", "nsx_url", "operations_url") if vcf.get(k)]

