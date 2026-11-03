# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Per-component upstream session authentication for VCF 9.x appliances.

Each VCF component authenticates differently. These classes implement the
documented login flows (verified against the official vcf-api-specs 9.0.0.0,
9.1.0.0 and 9.1.1.0 OpenAPI documents):

| Component       | Login                                         | Request header                      |
| --------------- | --------------------------------------------- | ----------------------------------- |
| vCenter         | POST /api/session (HTTP Basic)                | vmware-api-session-id: <id>         |
| SDDC Manager    | POST /v1/tokens {username,password}           | Authorization: Bearer <accessToken> |
|                 | PATCH /v1/tokens/access-token/refresh "<id>"  |                                     |
| VCF Operations  | POST /suite-api/api/auth/token/acquire        | Authorization: OpsToken <token>     |
| NSX Manager     | HTTP Basic on every request (KB 423054)       | Authorization: Basic ...            |
| VCF Automation  | POST /oauth/tenant/{org}/token (then /tm/...) | Authorization: Bearer <access>      |
|                 | (grant_type=refresh_token, rotated)           |                                     |

Credentials are pulled lazily from a ``CredentialSupplier`` at login time so the
password never lives on the auth object. Sessions are cached per instance and
invalidated by ``invalidate()`` when the upstream returns HTTP 401.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import threading
import time
import urllib.parse
from typing import Callable, Optional, Tuple

from vcf_enterprise_mcp.adapter.transport.auth import BaseUpstreamAuth
from vcf_enterprise_mcp.adapter.transport.base import BaseTransport, TransportRequest, TransportResponse
from vcf_enterprise_mcp.adapter.transport.errors import UpstreamAuthException, UpstreamResourceNotFoundException

logger = logging.getLogger(__name__)

# Returns (username, password) at login time; implementations resolve from the secret registry.
CredentialSupplier = Callable[[], Tuple[str, str]]


def _basic_header(supplier: CredentialSupplier) -> str:
    username, password = supplier()
    raw = f"{username}:{password}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")


class _CachedSessionAuth(BaseUpstreamAuth):
    """Shared caching, locking and invalidation for login-based session auth."""

    # Refresh a cached session this many seconds before its stated expiry.
    refresh_margin_seconds = 60.0
    # Lifetime assumed when the upstream does not state one.
    default_ttl_seconds = 15 * 60.0

    def __init__(
        self,
        base_url: str,
        transport: BaseTransport,
        credentials: CredentialSupplier,
        timeout_seconds: float = 30.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.transport = transport
        self.credentials = credentials
        self.timeout_seconds = timeout_seconds
        self._lock = threading.Lock()
        self._token: Optional[str] = None
        self._expires_at: float = 0.0

    def _login(self) -> Tuple[str, float]:
        raise NotImplementedError

    def _header(self, token: str) -> Tuple[str, str]:
        raise NotImplementedError

    def _post(self, path: str, headers: dict, json_body=None, method: str = "POST"):
        req = TransportRequest(
            method=method,
            url=f"{self.base_url}{path}",
            headers={"Accept": "application/json", "Content-Type": "application/json", **headers},
            json_body=json_body,
            timeout_seconds=self.timeout_seconds,
        )
        return self.transport.send(req)

    def _current_token(self) -> str:
        with self._lock:
            if self._token is None or time.time() >= self._expires_at - self.refresh_margin_seconds:
                self._token, self._expires_at = self._login()
            return self._token

    def apply(self, request: TransportRequest) -> TransportRequest:
        name, value = self._header(self._current_token())
        request.headers[name] = value
        return request

    def invalidate(self) -> None:
        with self._lock:
            self._token = None
            self._expires_at = 0.0

    @property
    def has_session(self) -> bool:
        return self._token is not None


class VCenterSessionAuth(_CachedSessionAuth):
    """vCenter Automation API session: POST /api/session with Basic, returns a JSON string id.

    vCenter idle sessions expire (default 30 minutes); a 401 triggers re-login.
    """

    default_ttl_seconds = 25 * 60.0

    def _login(self) -> Tuple[str, float]:
        resp = self._post("/api/session", {"Authorization": _basic_header(self.credentials)})
        session_id = resp.json()
        if isinstance(session_id, dict):
            session_id = session_id.get("value")
        if not resp.is_success or not isinstance(session_id, str) or not session_id:
            raise UpstreamAuthException(f"{self.base_url}/api/session", resp.status_code, "vCenter session was not issued")
        return session_id, time.time() + self.default_ttl_seconds

    def _header(self, token: str) -> Tuple[str, str]:
        return "vmware-api-session-id", token

    def logout(self) -> None:
        """DELETE /api/session releases the vCenter session slot."""
        if self._token is None:
            return
        try:
            self._post("/api/session", {"vmware-api-session-id": self._token}, method="DELETE")
        finally:
            self.invalidate()


class SDDCManagerTokenAuth(_CachedSessionAuth):
    """SDDC Manager token pair: POST /v1/tokens, refresh via PATCH /v1/tokens/access-token/refresh.

    The refresh body is the bare refresh-token id as a JSON string (TokenPair.refreshToken.id).
    An expired/invalid refresh token falls back to a full login.
    """

    default_ttl_seconds = 55 * 60.0

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._refresh_id: Optional[str] = None

    def _login(self) -> Tuple[str, float]:
        if self._refresh_id:
            try:
                resp = self._post("/v1/tokens/access-token/refresh", {}, json_body=self._refresh_id, method="PATCH")
                token = resp.json()
                if isinstance(token, dict):
                    token = token.get("accessToken")
                if resp.is_success and isinstance(token, str) and token:
                    return token, time.time() + self.default_ttl_seconds
            except Exception:
                pass
            self._refresh_id = None

        username, password = self.credentials()
        resp = self._post("/v1/tokens", {}, json_body={"username": username, "password": password})
        pair = resp.json() if resp.is_success else None
        access = pair.get("accessToken") if isinstance(pair, dict) else None
        if not access:
            raise UpstreamAuthException(f"{self.base_url}/v1/tokens", resp.status_code, "SDDC Manager access token was not issued")
        refresh = pair.get("refreshToken")
        self._refresh_id = refresh.get("id") if isinstance(refresh, dict) else None
        return access, time.time() + self.default_ttl_seconds

    def _header(self, token: str) -> Tuple[str, str]:
        return "Authorization", f"Bearer {token}"


class VCFOperationsTokenAuth(_CachedSessionAuth):
    """VCF Operations: POST /suite-api/api/auth/token/acquire returns {token, validity(ms epoch)}."""

    def __init__(self, *args, auth_source: Optional[str] = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.auth_source = auth_source

    def _login(self) -> Tuple[str, float]:
        username, password = self.credentials()
        body = {"username": username, "password": password}
        if self.auth_source:
            body["authSource"] = self.auth_source
        resp = self._post("/suite-api/api/auth/token/acquire", {}, json_body=body)
        data = resp.json() if resp.is_success else None
        token = data.get("token") if isinstance(data, dict) else None
        if not token:
            raise UpstreamAuthException(f"{self.base_url}/suite-api/api/auth/token/acquire", resp.status_code, "VCF Operations token was not issued")
        validity_ms = data.get("validity")
        expires_at = validity_ms / 1000.0 if isinstance(validity_ms, (int, float)) and validity_ms > 0 else time.time() + self.default_ttl_seconds
        return token, expires_at

    def _header(self, token: str) -> Tuple[str, str]:
        return "Authorization", f"OpsToken {token}"


def jwt_expiry(token: str) -> Optional[float]:
    """``exp`` (epoch seconds) of a JWT, or None when the value is not a JWT or has no exp."""
    try:
        part = token.split(".")[1]
        payload = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
        exp = payload.get("exp")
        return float(exp) if isinstance(exp, (int, float)) else None
    except Exception:
        return None


def header_value(headers: Optional[dict], name: str) -> Optional[str]:
    """Case-insensitive response header lookup."""
    low = name.lower()
    for key, value in (headers or {}).items():
        if str(key).lower() == low:
            return value
    return None


def send_with_status(transport: BaseTransport, request: TransportRequest) -> TransportResponse:
    """Send a request and hand back 401/403/404 as responses instead of exceptions.

    The HTTP transport raises for those statuses, but login flows must branch on them (404/405 means
    "try the next endpoint", 401 means "stop, a retry could lock the account")."""
    try:
        return transport.send(request)
    except UpstreamAuthException as exc:
        details = exc.details or {}
        return TransportResponse(status_code=int(details.get("status_code") or 401),
                                 body=str(details.get("upstream_message") or "").encode("utf-8", "replace"))
    except UpstreamResourceNotFoundException:
        return TransportResponse(status_code=404)


def short_text(text: str, limit: int = 200) -> str:
    return " ".join((text or "").split())[:limit]


def automation_token_paths(org: str) -> list:
    """OAuth token endpoints of VCF Automation 9, in the order they are tried.

    Tenant organizations use /oauth/tenant/{org}/token; the System (provider) organization uses
    /oauth/provider/token. The /tm/ prefix is the same API behind the VCF Automation gateway.
    Ported from the community project vcf-orchestrator-mcp (MIT, imtrinity94)."""
    if org.strip().lower() == "system":
        return ["/oauth/provider/token", "/tm/oauth/provider/token"]
    quoted = urllib.parse.quote(org, safe="")
    return [f"/oauth/tenant/{quoted}/token", f"/tm/oauth/tenant/{quoted}/token"]


REFRESH_TOKEN_REUSED = (
    "VCF Automation rejected the service-account refresh token (invalid_grant): it was already used or "
    "revoked. VCF Automation rotates refresh tokens, so a token that was copied to another machine, "
    "replaced by a newer one, or whose service account was deleted stops working. "
    "Run `vcf-mcp setup automation` again to issue a new one."
)


class VCFAutomationTokenAuth(_CachedSessionAuth):
    """VCF Automation 9: exchange a service-account refresh token for a bearer access token.

    Token refresh logic ported from the community project vcf-orchestrator-mcp (MIT, imtrinity94),
    verified there on a real VCF Automation 9.1.1.

    * Endpoint order: the endpoint that worked last time, then /oauth/tenant/{org}/token, then
      /tm/oauth/tenant/{org}/token (System org: /oauth/provider/token, /tm/oauth/provider/token).
      The next endpoint is tried only on HTTP 404/405.
    * ``client_id`` is sent when known (the service account's client id).
    * VCF Automation rotates refresh tokens: when the response carries a different refresh token it is
      handed to ``on_refresh_token`` straight away (the caller persists it in the secret store) and is
      used next time. If persisting fails the new token is kept in memory so this process keeps working,
      and a warning is logged (never including the token).
    * Access-token lifetime: ``expires_in``, else the JWT ``exp``, else the default; refreshed 60 s early.

    The credential supplier returns (username, refresh_token); the username is not sent."""

    def __init__(self, *args, tenant: str, client_id: Optional[str] = None,
                 on_refresh_token: Optional[Callable[[str], None]] = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.tenant = tenant
        self.client_id = client_id or None
        self.on_refresh_token = on_refresh_token
        self._endpoint: Optional[str] = None
        self._rotated: Optional[str] = None       # newest token, only while persisting it failed
        self._rotated_from: Optional[str] = None  # store value that token superseded

    def _select_refresh_token(self, stored: str) -> str:
        if self._rotated and stored == self._rotated_from:
            return self._rotated
        self._rotated = self._rotated_from = None
        return stored

    def _adopt(self, new_token: str, stored: str) -> None:
        if self.on_refresh_token is None:
            self._rotated, self._rotated_from = new_token, stored
            return
        try:
            self.on_refresh_token(new_token)
            self._rotated = self._rotated_from = None
        except Exception as exc:  # keep working in memory; never log the token
            self._rotated, self._rotated_from = new_token, stored
            logger.warning("Could not persist the rotated VCF Automation refresh token (%s). It is kept in memory "
                           "only; after a restart run `vcf-mcp setup automation` again.", type(exc).__name__)

    def _login(self) -> Tuple[str, float]:
        _user, stored = self.credentials()
        refresh_token = self._select_refresh_token(stored)
        paths = automation_token_paths(self.tenant)
        if self._endpoint:
            paths = [self._endpoint] + [p for p in paths if p != self._endpoint]
        tried = []
        for path in paths:
            form = {"grant_type": "refresh_token", "refresh_token": refresh_token}
            if self.client_id:
                form["client_id"] = self.client_id
            req = TransportRequest(
                method="POST",
                url=f"{self.base_url}{path}",
                headers={"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"},
                data=urllib.parse.urlencode(form).encode(),
                timeout_seconds=self.timeout_seconds,
            )
            resp = send_with_status(self.transport, req)
            if resp.status_code in (404, 405):
                tried.append(f"{path} -> HTTP {resp.status_code}")
                continue
            text = resp.text.replace(refresh_token, "[REDACTED]") if refresh_token else resp.text
            try:
                data = resp.json() if resp.body else None
            except ValueError:
                data = None
            access = data.get("access_token") if isinstance(data, dict) else None
            if resp.is_success and access:
                self._endpoint = path
                new_rt = data.get("refresh_token")
                if isinstance(new_rt, str) and new_rt and new_rt != refresh_token:
                    self._adopt(new_rt, stored)
                ttl = data.get("expires_in")
                if isinstance(ttl, (int, float)) and ttl > 0:
                    expires_at = time.time() + float(ttl)
                else:
                    expires_at = jwt_expiry(access) or time.time() + self.default_ttl_seconds
                return access, expires_at
            if "invalid_grant" in text.lower():
                raise UpstreamAuthException(f"{self.base_url}{path}", resp.status_code, REFRESH_TOKEN_REUSED)
            raise UpstreamAuthException(f"{self.base_url}{path}", resp.status_code,
                                        f"VCF Automation access token was not issued: HTTP {resp.status_code} {short_text(text)}")
        raise UpstreamAuthException(self.base_url, 404, "No VCF Automation token endpoint answered for org "
                                    f"'{self.tenant}' ({'; '.join(tried)}). Check vcf.automation_url and vcf.automation_org.")

    def _header(self, token: str) -> Tuple[str, str]:
        return "Authorization", f"Bearer {token}"


class VCFASessionAuth(_CachedSessionAuth):
    """VCF Automation 9 session login (orchestrator_auth: vcfa_session).

    POST /cloudapi/1.0.0/sessions, then /tm/cloudapi/1.0.0/sessions, with HTTP Basic ``user@org`` and
    Accept application/json;version=40.0, 9.1.0, 9.0.0 in turn. The bearer token is returned in the
    x-vmware-vcloud-access-token response header. It stops at the first HTTP 401/403, because every
    further attempt with the same password counts towards the account lockout; HTTP 404 moves to the
    next URL, other errors (e.g. an unsupported API version) to the next version.
    The System org uses /cloudapi/1.0.0/sessions/provider. Ported from vcf-orchestrator-mcp (MIT, imtrinity94).
    The credential supplier returns (username, password)."""

    default_ttl_seconds = 25 * 60.0
    API_VERSIONS = ("40.0", "9.1.0", "9.0.0")

    def __init__(self, *args, tenant: str, **kwargs):
        super().__init__(*args, **kwargs)
        self.tenant = tenant
        self._rejected: Optional[Tuple[str, UpstreamAuthException]] = None  # (credential fingerprint, error)

    def _login(self) -> Tuple[str, float]:
        user, password = self.credentials()
        org = self.tenant or "System"
        principal = user if user.lower().endswith(f"@{org.lower()}") else f"{user}@{org}"
        fingerprint = hashlib.sha256(f"{principal}\0{password}".encode("utf-8")).hexdigest()
        if self._rejected and self._rejected[0] == fingerprint:
            # The same credentials were already rejected: do not count another failed login towards a lockout.
            raise self._rejected[1]
        suffix = "/provider" if org.lower() == "system" else ""
        basic = "Basic " + base64.b64encode(f"{principal}:{password}".encode("utf-8")).decode("ascii")
        tried = []
        for path in (f"/cloudapi/1.0.0/sessions{suffix}", f"/tm/cloudapi/1.0.0/sessions{suffix}"):
            for version in self.API_VERSIONS:
                req = TransportRequest(
                    method="POST", url=f"{self.base_url}{path}",
                    headers={"Authorization": basic, "Accept": f"application/json;version={version}"},
                    timeout_seconds=self.timeout_seconds,
                )
                resp = send_with_status(self.transport, req)
                token = header_value(resp.headers, "x-vmware-vcloud-access-token")
                if resp.is_success and token:
                    return token, jwt_expiry(token) or time.time() + self.default_ttl_seconds
                tried.append(f"{path} v{version}: HTTP {resp.status_code}")
                if resp.status_code in (401, 403):
                    self._rejected = (fingerprint, UpstreamAuthException(
                        f"{self.base_url}{path}", resp.status_code,
                        f"VCF Automation rejected {principal} (HTTP {resp.status_code}); stopped after one attempt so the "
                        "account is not locked out. Check the password, that the user is a local user of the org and "
                        "that the account is not locked. SSO-only users cannot use a password; use orchestrator_auth: "
                        "automation_token instead. Further logins are not attempted until the credential changes."))
                    raise self._rejected[1]
                if resp.status_code == 404:
                    break
        raise UpstreamAuthException(self.base_url, 404, "VCF Automation session login failed: " + "; ".join(tried))

    def _header(self, token: str) -> Tuple[str, str]:
        return "Authorization", f"Bearer {token}"


class NSXBasicAuth(BaseUpstreamAuth):
    """NSX Manager HTTP Basic per request; avoids JSESSIONID/X-XSRF-TOKEN session expiry (HTTP 403)."""

    def __init__(self, credentials: CredentialSupplier):
        self.credentials = credentials

    def apply(self, request: TransportRequest) -> TransportRequest:
        request.headers["Authorization"] = _basic_header(self.credentials)
        return request


class OrchestratorBasicAuth(NSXBasicAuth):
    """HTTP Basic on every request (orchestrator_auth: basic), for a standalone Orchestrator."""
