# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Guided setup of a VCF Automation 9 service account for the MCP server: `vcf-mcp setup automation`.

The flow, ported from the service-account setup of the community project vcf-orchestrator-mcp
(MIT, imtrinity94) where it was verified on a real VCF Automation 9.1.1:

  1. session login as user@org                POST /cloudapi/1.0.0/sessions (then /tm/cloudapi/...)
  2. register the service account (OAuth)     POST /oauth/tenant/{org}/register
  3. device authorization                     POST /oauth/tenant/{org}/device_authorization
  4. approve the device as the logged-in user POST /tm/cloudapi/1.0.0/deviceLookup/grant
  5. device-code grant -> access + refresh    POST (/tm)/oauth/tenant/{org}/token

The password is used for step 1 only: it is never stored, logged or echoed. The refresh token goes into
the secret store as the ``vcf_automation`` credential; the non-secret client id, URL and org go into
the active config. VCF Automation rotates the refresh token on use; the running server writes every
rotated token back to the same secret-store entry (see VCFAutomationTokenAuth).
"""

from __future__ import annotations

import getpass
import ipaddress
import os
import re
import sys
import tempfile
import time
import urllib.parse
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from vcf_enterprise_mcp.adapter.transport.base import BaseTransport, TransportRequest, TransportResponse
from vcf_enterprise_mcp.adapter.transport.errors import TransportException, UpstreamTLSException
from vcf_enterprise_mcp.adapter.transport.vcf_sessions import automation_token_paths, header_value, send_with_status, short_text

TENANT = "tenant-default"
ENVIRONMENT = "env-prod"
CREDENTIAL_REFERENCE = f"local://{ENVIRONMENT}/vcf-mcp-vcf-automation"
DEVICE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"
SESSION_API_VERSIONS = ("40.0", "9.1.0", "9.0.0")

ROLE_HELP = (
    "Role names come from Access Control > Roles in the VCF Automation org (they differ per org, e.g. "
    "'Organization Owner' instead of 'Organization Administrator').\n"
    "    Least privilege: give the account only the roles the MCP needs. For Orchestrator workflows that is an\n"
    "    Orchestrator role (e.g. 'Orchestrator Administrator'); WITHOUT one, Orchestrator treats the account as a plain\n"
    "    user and shows no workflows or actions at all. Add roles for the Assembler/IaaS API only if you use it."
)


class SetupError(Exception):
    """A setup step failed; the message is safe to print (it never contains a password or token)."""


@dataclass
class SetupOptions:
    url: Optional[str] = None
    org: Optional[str] = None
    user: Optional[str] = None
    name: Optional[str] = None
    role: Optional[str] = None
    password_file: Optional[str] = None
    client_id: Optional[str] = None
    ca_cert: Optional[str] = None
    config_path: Optional[str] = None


def _cookie(headers: Dict[str, str], name: str) -> Optional[str]:
    m = re.search(rf"(?:^|[;,\s]){re.escape(name)}=([^;,\s]+)", header_value(headers, "set-cookie") or "")
    return m.group(1) if m else None


def _error_code(resp: TransportResponse) -> str:
    try:
        data = resp.json()
        if isinstance(data, dict) and isinstance(data.get("error"), str):
            return data["error"]
    except ValueError:
        pass
    m = re.search(r"authorization_pending|slow_down|access_denied|expired_token|invalid_client|invalid_grant", resp.text)
    return m.group(0) if m else ""


def _describe(resp: TransportResponse) -> str:
    return f"HTTP {resp.status_code} {short_text(resp.text, 300)}".strip()


def resolve_config_path(explicit: Optional[str] = None) -> Path:
    """The config file the server will load: --config, VCF_ENTERPRISE_MCP_CONFIG, ~/.vcf-mcp/config.yaml
    (when it exists), the shipped config/enterprise_config.yaml (when it exists), else ~/.vcf-mcp/config.yaml."""
    chosen = explicit or os.environ.get("VCF_ENTERPRISE_MCP_CONFIG")
    if chosen:
        return Path(chosen)
    home_cfg = Path.home() / ".vcf-mcp" / "config.yaml"
    if home_cfg.exists():
        return home_cfg
    shipped = Path("config/enterprise_config.yaml")
    return shipped if shipped.exists() else home_cfg


def _atomic_write(path: Path, text: str) -> None:
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


def build_transport(url: str, ca_cert: Optional[str], config_path: Path) -> BaseTransport:
    """HTTPS-only transport that honours the config's TLS and SSRF settings (vcf.verify_ssl, vcf.ca_cert_path,
    vcf.allowed_dns_suffixes/cidrs, lab-only vcf.allow_loopback_targets). There is no insecure switch:
    for a private CA pass --ca-cert or set vcf.ca_cert_path."""
    import yaml
    from vcf_enterprise_mcp.adapter.ssrf_guard import SSRFGuard
    from vcf_enterprise_mcp.adapter.transport.http import HTTPTransport

    vcf: Dict[str, Any] = {}
    if config_path.exists():
        vcf = (yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}).get("vcf") or {}
    allow_loopback = bool(vcf.get("allow_loopback_targets", False))
    if allow_loopback and os.environ.get("VCF_MCP_ENV", "").lower() == "production":
        raise SetupError("vcf.allow_loopback_targets is a lab-only setting and is refused when VCF_MCP_ENV=production")
    host = urllib.parse.urlsplit(url).hostname or ""
    suffixes = list(vcf.get("allowed_dns_suffixes") or []) + [host]
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if "." in host:
            suffixes.append("." + host.split(".", 1)[1])
    guard = SSRFGuard(allowed_dns_suffixes=suffixes, allowed_cidrs=vcf.get("allowed_cidrs") or None,
                      allow_loopback=allow_loopback, enforce_https=True, mock_dns={}, allow_lab_dns_fallback=False)
    return HTTPTransport(ssrf_guard=guard, max_retries=0, verify_ssl=bool(vcf.get("verify_ssl", True)),
                         ca_cert_path=ca_cert or vcf.get("ca_cert_path"))


class AutomationAccountSetup:
    """Runs the five-step flow. Everything with side effects is injectable so it can be tested end to end.
    ``transport`` is a BaseTransport, or a callable taking the VCF Automation URL and returning one."""

    def __init__(
        self,
        transport: Any,
        *,
        secret_registry: Any = None,
        config_path: Optional[Path] = None,
        out: Callable[[str], None] = print,
        ask: Callable[[str], str] = input,
        ask_secret: Callable[[str], str] = getpass.getpass,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
        min_poll_seconds: float = 2.0,
        max_wait_seconds: Optional[float] = None,
        interactive: Optional[bool] = None,
    ):
        self.transport = transport if isinstance(transport, BaseTransport) else None
        self._transport_factory = None if isinstance(transport, BaseTransport) else transport
        self.secrets = secret_registry
        self.config_path = Path(config_path) if config_path else resolve_config_path()
        self.out = out
        self.ask = ask
        self.ask_secret = ask_secret
        self.sleep = sleep
        self.clock = clock
        self.min_poll_seconds = min_poll_seconds
        self.max_wait_seconds = max_wait_seconds
        self.interactive = sys.stdin.isatty() if interactive is None else interactive

    # ---- http ------------------------------------------------------------------------

    def _call(self, method: str, url: str, headers: Dict[str, str], *, json_body: Any = None,
              form: Optional[Dict[str, str]] = None) -> TransportResponse:
        req = TransportRequest(
            method=method, url=url, json_body=json_body,
            data=urllib.parse.urlencode(form).encode() if form is not None else None,
            headers={"User-Agent": "vcf-mcp-setup", **headers}, timeout_seconds=30.0)
        try:
            return send_with_status(self.transport, req)
        except UpstreamTLSException as exc:
            raise SetupError(f"{exc} Use --ca-cert <file> (or vcf.ca_cert_path) for a private or self-signed certificate "
                             "authority; there is no switch to skip verification.") from None
        except TransportException as exc:
            raise SetupError(f"Cannot reach {url}: {exc}") from None

    # ---- inputs ----------------------------------------------------------------------

    def _read_password(self, principal: str, password_file: Optional[str]) -> str:
        if password_file:
            path = Path(password_file)
            try:
                mode = path.stat().st_mode
                if os.name == "posix" and mode & 0o077:
                    self.out(f"Warning: {path} is readable by other users; restrict it with chmod 600.")
                lines = path.read_text(encoding="utf-8").splitlines()
            except OSError as exc:
                raise SetupError(f"Cannot read --password-file {path}: {exc.strerror or exc}") from None
            password = lines[0] if lines else ""
        else:
            if not self.interactive:
                raise SetupError("No terminal to ask for the password: pass --password-file <file> (first line is the password).")
            password = self.ask_secret(f"Password for {principal} (not shown, never stored): ")
        if not password:
            raise SetupError("No password given.")
        return password

    def _need(self, value: Optional[str], prompt: str, flag: str) -> str:
        if value:
            return value.strip()
        if not self.interactive:
            raise SetupError(f"{flag} is required (no terminal to ask).")
        answer = self.ask(prompt).strip()
        if not answer:
            raise SetupError(f"{flag} is required.")
        return answer

    # ---- entry point -----------------------------------------------------------------

    def run(self, opts: SetupOptions) -> int:
        try:
            self._run(opts)
            return 0
        except SetupError as exc:
            self.out(f"\nSetup failed: {exc}")
            return 1
        except KeyboardInterrupt:
            self.out("\nCancelled. Nothing was stored.")
            return 130

    def _run(self, opts: SetupOptions) -> None:
        url = self._need(opts.url, "VCF Automation URL (e.g. https://auto.example.lab): ", "--url").rstrip("/")
        if not url.lower().startswith("https://"):
            raise SetupError("--url must be an https:// URL.")
        if self.transport is None:
            self.transport = self._transport_factory(url)
        org = self._need(opts.org, "Organization name (the last part of https://<fqdn>/tenant/<name>): ", "--org")
        ui_mode = bool(opts.client_id)
        client_id = opts.client_id
        name = user = role = ""
        session = jwt_cookie = None
        session_roles: List[str] = []
        quoted_org = urllib.parse.quote(org, safe="")

        if not ui_mode:
            user = self._need(opts.user, f"Username (without @{org}): ", "--user")
            name = self._need(opts.name, "Service account name (shown in VCF Automation): ", "--name")
            principal = user if user.lower().endswith(f"@{org.lower()}") else f"{user}@{org}"
            password = self._read_password(principal, opts.password_file)
            session, jwt_cookie, session_roles = self._login(url, org, user, principal, password)
            del password
            role = self._choose_role(opts.role, session_roles)
            client_id, jwt_cookie = self._register(url, quoted_org, name, role, session, jwt_cookie)
        if not client_id:
            raise SetupError("No client ID.")
        device = self._device_authorization(url, quoted_org, client_id)
        bearer = jwt_cookie or session
        granted = self._grant(url, device["user_code"], bearer, org, device.get("verification_uri")) if bearer else False
        if not granted:
            self._explain_manual_approval(org, device)
        tokens, endpoint = self._poll(url, org, client_id, device, bearer, granted)
        self.out(f"5/5 Tokens issued (access token valid {tokens.get('expires_in', '?')}s, refresh token received)")
        self._verify(url, tokens["access_token"])
        reference = self._store(tokens["refresh_token"], name or client_id)
        self._write_config(url, org, client_id, name, reference)
        self._next_steps(url, org, client_id)

    # ---- step 1 ----------------------------------------------------------------------

    def _login(self, url: str, org: str, user: str, principal: str, password: str) -> Tuple[str, Optional[str], List[str]]:
        import base64
        basic = "Basic " + base64.b64encode(f"{principal}:{password}".encode("utf-8")).decode("ascii")
        suffix = "/provider" if org.lower() == "system" else ""
        tried: List[str] = []
        for path in (f"/cloudapi/1.0.0/sessions{suffix}", f"/tm/cloudapi/1.0.0/sessions{suffix}"):
            for version in SESSION_API_VERSIONS:
                resp = self._call("POST", f"{url}{path}", {"Authorization": basic, "Accept": f"application/json;version={version}"})
                token = header_value(resp.headers, "x-vmware-vcloud-access-token")
                if resp.is_success and token:
                    try:
                        data = resp.json() if resp.body else {}
                    except ValueError:
                        data = {}
                    roles = [r for r in (data.get("roles") or []) if isinstance(r, str)] if isinstance(data, dict) else []
                    self.out(f"1/5 Logged in as {principal} ({path}" + (f", role {', '.join(roles)}" if roles else "") + ")")
                    return token, _cookie(resp.headers, "vcloud_jwt"), roles
                tried.append(f"{path} v{version}: {_describe(resp)}")
                if resp.status_code == 401:  # stop: every further attempt counts towards the account lockout
                    raise SetupError(
                        "Login failed:\n  " + "\n  ".join(tried) +
                        f"\n  401 means VCF Automation rejected {principal}: check the password, that '{user}' is a LOCAL user "
                        f"inside org '{org}' (--org is the org name from the tenant URL, not the display name) and that the "
                        "account is not locked. Setup stopped after this one attempt so the account is not locked out."
                        "\n  Users who sign in through SSO / an identity provider cannot log in with a password. Create the service "
                        f"account in the VCF Automation UI (Access Control > Service Accounts) and run:\n    vcf-mcp setup automation "
                        f"--url {url} --org {org} --client-id <its client ID>")
                if resp.status_code in (403, 404):
                    break
        raise SetupError("Login failed:\n  " + "\n  ".join(tried))

    def _choose_role(self, role: Optional[str], session_roles: List[str]) -> str:
        if role:
            return role.strip()
        if not self.interactive:
            raise SetupError("--role is required (no terminal to ask). " + ROLE_HELP)
        own = ", ".join(session_roles)
        self.out("\nWhich role(s) should the service account get? " + ROLE_HELP)
        answer = self.ask(f"Roles, comma separated [{own or 'no default'}]: ").strip() or own
        if not answer:
            raise SetupError("A role is required.")
        return answer

    # ---- step 2 ----------------------------------------------------------------------

    def _register(self, url: str, quoted_org: str, name: str, role: str, session: str, jwt_cookie: Optional[str]) -> Tuple[str, Optional[str]]:
        scopes = " ".join(f"urn:vcloud:role:{urllib.parse.quote(r.strip(), safe='')}" for r in role.split(",") if r.strip())
        headers = {"Accept": "application/json;version=40.0", "Content-Type": "application/json", "Authorization": f"Bearer {session}"}
        if jwt_cookie:
            headers["Cookie"] = f"vcloud_jwt={jwt_cookie}"
        resp = self._call("POST", f"{url}/oauth/tenant/{quoted_org}/register", headers, json_body={
            "client_name": name, "software_id": str(uuid.uuid4()), "software_version": "1.0", "client_uri": "vmware.com", "scope": scopes})
        data = resp.json() if resp.body and resp.is_success else None
        client_id = data.get("client_id") if isinstance(data, dict) else None
        if not resp.is_success or not client_id:
            hint = ""
            if "role" in resp.text.lower():
                hint = "\n  " + ROLE_HELP
            raise SetupError(f"Registering the service account failed: {_describe(resp)}{hint}")
        self.out(f"2/5 Service account '{name}' registered (client_id {client_id}, role {role})")
        return client_id, _cookie(resp.headers, "vcloud_jwt") or jwt_cookie

    # ---- step 3 ----------------------------------------------------------------------

    def _device_authorization(self, url: str, quoted_org: str, client_id: str) -> Dict[str, Any]:
        resp = self._call("POST", f"{url}/oauth/tenant/{quoted_org}/device_authorization",
                          {"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"}, form={"client_id": client_id})
        data = resp.json() if resp.body and resp.is_success else None
        if not isinstance(data, dict) or not data.get("device_code") or not data.get("user_code"):
            raise SetupError(f"Device authorization failed: {_describe(resp)}")
        self.out(f"3/5 Device authorization requested (user code {data['user_code']})")
        return data

    # ---- step 4 ----------------------------------------------------------------------

    def _grant(self, url: str, user_code: str, bearer: str, org: str, verification_uri: Optional[str]) -> bool:
        resp = self._call("POST", f"{url}/tm/cloudapi/1.0.0/deviceLookup/grant", {
            "Accept": "*/*;version=40.0", "Content-Type": "application/json",
            "Authorization": f"Bearer {bearer}", "Cookie": f"vcloud_jwt={bearer}"}, json_body={"userCode": user_code})
        if resp.is_success:
            self.out("4/5 Service account granted")
            return True
        self.out(f"4/5 Automatic grant failed ({_describe(resp)})")
        return False

    def _explain_manual_approval(self, org: str, device: Dict[str, Any]) -> None:
        where = f", or {device['verification_uri']}" if device.get("verification_uri") else ""
        self.out(f"\n    Approve the request in the VCF Automation UI now: sign in to org '{org}', open the service account's access "
                 f"requests (Access Control > Service Accounts > Review Access Requests{where}) and grant code:  {device['user_code']}")

    # ---- step 5 ----------------------------------------------------------------------

    def _poll(self, url: str, org: str, client_id: str, device: Dict[str, Any], bearer: Optional[str], granted: bool) -> Tuple[Dict[str, Any], str]:
        expires_in = float(device.get("expires_in") or 600)
        interval = max(self.min_poll_seconds, float(device.get("interval") or 5))
        budget = 30.0 if granted else expires_in
        if self.max_wait_seconds is not None:
            budget = min(budget, self.max_wait_seconds)
        if not granted:
            self.out(f"    Waiting up to {max(1, round(budget / 60))} minute(s) for the approval...")
        deadline = self.clock() + budget
        paths = list(reversed(automation_token_paths(org)))  # /tm/oauth first, then /oauth (the order verified on 9.1.1)
        last = ""
        form = {"client_id": client_id, "grant_type": DEVICE_GRANT_TYPE, "device_code": device["device_code"]}
        while True:
            for path in paths:
                headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
                if bearer:
                    headers["Cookie"] = f"vcloud_jwt={bearer}"
                resp = self._call("POST", f"{url}{path}", headers, form=form)
                data = resp.json() if resp.body and resp.is_success else None
                if resp.is_success and isinstance(data, dict) and data.get("access_token"):
                    if not data.get("refresh_token"):
                        raise SetupError("The token endpoint returned no refresh token.")
                    return data, path
                if resp.status_code in (404, 405):
                    continue
                code = _error_code(resp)
                last = f"{_describe(resp)}"
                if code in ("access_denied", "expired_token", "invalid_client"):
                    raise SetupError(f"Token request failed: {last}" + (
                        "\n  The request was denied or expired; run setup again." if code != "invalid_client"
                        else "\n  VCF Automation does not know this client id; check --client-id or run setup again."))
                if code == "slow_down":
                    interval += 5
                break  # authorization_pending (or an unexpected status): wait, then ask again
            if self.clock() + interval > deadline:
                raise SetupError("No token before the approval window closed" + (f" (last answer: {last})" if last else "") +
                                 ". Run setup again and approve the code in time.")
            self.sleep(interval)

    # ---- verification ----------------------------------------------------------------

    def _verify(self, url: str, access_token: str) -> None:
        headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/json"}
        vco = self._call("GET", f"{url}/vco/api/workflows?maxResult=1", headers)
        iaas = self._call("GET", f"{url}/iaas/api/projects?$top=1", headers)
        self.out(f"Check: Orchestrator /vco/api -> HTTP {vco.status_code}; VCF Automation IaaS API -> HTTP {iaas.status_code}")
        if vco.status_code in (401, 403):
            self.out("Note: Orchestrator rejected the service account token (HTTP %d). The account needs an Orchestrator role "
                     "(e.g. 'Orchestrator Administrator') under Access Control > Service Accounts; then run setup again or restart "
                     "the MCP so it gets a token with the new role." % vco.status_code)
        elif vco.status_code == 404:
            self.out("Note: no Orchestrator at /vco/api on this host. If Orchestrator is standalone, set vcf.orchestrator_url "
                     "(and vcf.orchestrator_auth) in the config.")
        elif vco.is_success:
            try:
                data = vco.json()
            except ValueError:
                data = None
            if isinstance(data, dict) and not (data.get("link") or data.get("total")):
                self.out("Note: Orchestrator answered but lists no workflows. A service account that is only a plain Orchestrator "
                         "user sees no workflows or actions at all, not even the library. Add an Orchestrator role (e.g. "
                         "'Orchestrator Administrator') to the service account.")
        if iaas.status_code in (401, 403):
            self.out("Note: the IaaS (Assembler) API refused the token (HTTP %d). That is expected when the account has no "
                     "Assembler/IaaS role; it does not affect Orchestrator." % iaas.status_code)

    # ---- persistence -----------------------------------------------------------------

    def _store(self, refresh_token: str, label: str) -> str:
        import yaml
        from vcf_enterprise_mcp.secrets.models import SecretValue
        if self.secrets is None:
            from vcf_enterprise_mcp.secrets.registry import get_default_secret_registry
            self.secrets = get_default_secret_registry()
        reference = CREDENTIAL_REFERENCE
        if self.config_path.exists():
            existing = ((yaml.safe_load(self.config_path.read_text(encoding="utf-8")) or {}).get("vcf") or {}).get("component_credential_refs") or {}
            reference = existing.get("vcf_automation") or reference
        try:
            self.secrets.store(reference, SecretValue(refresh_token), tenant_id=TENANT, environment_id=ENVIRONMENT,
                               description=f"VCF Automation service-account refresh token ({label})")
        except Exception as exc:
            raise SetupError(f"The service account was created, but its refresh token could not be stored at {reference} "
                             f"({type(exc).__name__}: {exc}). The token is not shown; delete the service account in the UI and run "
                             "setup again with a writable secret store (a local:// reference).") from None
        self.out(f"Refresh token stored in the secret store at {reference}")
        return reference

    def _write_config(self, url: str, org: str, client_id: str, name: str, reference: str) -> None:
        import yaml
        data: Dict[str, Any] = {}
        if self.config_path.exists():
            data = yaml.safe_load(self.config_path.read_text(encoding="utf-8")) or {}
        server = data.get("server") or {}
        roles = server.get("personal_roles")
        if str(server.get("access_mode") or "").lower() == "personal" and roles and "AUTOMATION_OPERATOR" not in roles:
            server["personal_roles"] = [*roles, "AUTOMATION_OPERATOR"]  # personal roles were narrowed by guided setup
        vcf = data.setdefault("vcf", {})
        vcf["automation_url"], vcf["automation_org"], vcf["automation_client_id"] = url, org, client_id
        vcf.setdefault("component_credential_refs", {})["vcf_automation"] = reference
        if name:
            vcf.setdefault("component_usernames", {})["vcf_automation"] = name
        host = urllib.parse.urlsplit(url).hostname or ""
        if "." in host and vcf.get("allowed_dns_suffixes"):
            suffix = "." + host.split(".", 1)[1]
            if suffix not in vcf["allowed_dns_suffixes"]:
                vcf["allowed_dns_suffixes"] = [*vcf["allowed_dns_suffixes"], suffix]
        _atomic_write(self.config_path, yaml.safe_dump(data, sort_keys=False))
        self.out(f"Config updated: {self.config_path} (vcf.automation_url, automation_org, automation_client_id)")

    def _next_steps(self, url: str, org: str, client_id: str) -> None:
        self.out("\nNext steps:\n"
                 "  1. Restart your MCP client (or the server) so it picks up the new settings.\n"
                 "  2. The server renews its access token by itself and saves each rotated refresh token to the secret store.\n"
                 "     Do not copy the credential to another machine: whichever machine refreshes first invalidates the other's copy.\n"
                 "     If you ever see 'refresh token already used or revoked', run `vcf-mcp setup automation` again.\n"
                 "  3. Roles added to the service account later take effect after the next token refresh (restart the MCP).")
