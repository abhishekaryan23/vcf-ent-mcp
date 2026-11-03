# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""VCF Automation / Orchestrator authentication: rotating refresh tokens, endpoint fallback, session and
basic modes, wiring. Refresh-token and session logic is adapted from vcf-orchestrator-mcp (MIT, imtrinity94)."""

import base64
import json
import logging
import threading
import time
import urllib.parse
from types import SimpleNamespace

import pytest

from vcf_enterprise_mcp.adapter.transport.base import TransportRequest, TransportResponse
from vcf_enterprise_mcp.adapter.transport.errors import UpstreamAuthException
from vcf_enterprise_mcp.adapter.transport.http import HTTPTransport
from vcf_enterprise_mcp.adapter.transport.vcf_sessions import (
    OrchestratorBasicAuth, VCFASessionAuth, VCFAutomationTokenAuth, automation_token_paths,
)
from vcf_enterprise_mcp.adapter.transport.vcfa_wiring import build_automation_auth
from vcf_enterprise_mcp.config.settings import UpstreamVCFConfig
from vcf_enterprise_mcp.secrets.local_encrypted import LocalEncryptedSecretProvider, LocalKeyProtector
from vcf_enterprise_mcp.secrets.models import SecretValue

BASE = "https://vcfa.corp.internal"


def jwt(exp):
    seg = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()  # noqa: E731
    return f"{seg({'alg': 'none'})}.{seg({'exp': exp})}.sig"


class Idp:
    """Mock VCF Automation token endpoint with refresh-token rotation."""

    def __init__(self, paths=("/oauth/tenant/nw/token", "/tm/oauth/tenant/nw/token"), first="rt-0", expires_in=3600, client_id=None):
        self.paths, self.valid, self.n, self.calls, self.expires_in, self.client_id = set(paths), {first}, 0, [], expires_in, client_id
        self.delay = 0.0

    def __call__(self, req: TransportRequest) -> TransportResponse:
        path = req.url.removeprefix(BASE)
        form = {k: v[0] for k, v in urllib.parse.parse_qs(req.data.decode()).items()}
        self.calls.append((path, form))
        if path not in self.paths:
            return TransportResponse(404, body=b"")
        time.sleep(self.delay)
        if form.get("grant_type") != "refresh_token" or form["refresh_token"] not in self.valid:
            return TransportResponse(400, body=b'{"error": "invalid_grant"}')
        self.valid.discard(form["refresh_token"])
        self.n += 1
        new = f"rt-{self.n}"
        self.valid.add(new)
        body = {"access_token": f"at-{self.n}", "refresh_token": new}
        if self.expires_in is not None:
            body["expires_in"] = self.expires_in
        return TransportResponse(200, body=json.dumps(body).encode())


class Store:
    """Stands in for the secret-store entry holding the refresh token."""

    def __init__(self, value):
        self.value, self.writes = value, []

    def read(self):
        return "svc-mcp", self.value

    def write(self, new):
        self.writes.append(new)
        self.value = new


def make_auth(idp, store, org="nw", **kw):
    transport = HTTPTransport(mock_handler=idp, max_retries=0)
    return VCFAutomationTokenAuth(BASE, transport, store.read, tenant=org, on_refresh_token=store.write, **kw)


def force_expiry(auth):
    auth.invalidate()


def test_rotated_refresh_token_is_persisted_and_used_next_time():
    idp, store = Idp(), Store("rt-0")
    auth = make_auth(idp, store)
    assert auth._current_token() == "at-1"
    assert store.writes == ["rt-1"] and store.value == "rt-1"
    force_expiry(auth)
    assert auth._current_token() == "at-2"
    assert [c[1]["refresh_token"] for c in idp.calls] == ["rt-0", "rt-1"]
    assert store.value == "rt-2"


def test_rotation_survives_a_restart_through_the_real_local_secret_store(tmp_path):
    protector = LocalKeyProtector(str(tmp_path / "master.key"))
    protector.set_master_key(bytes(range(32)))
    provider = LocalEncryptedSecretProvider(storage_path=str(tmp_path / "credentials.json"), key_protector=protector)
    ref = "local://env-prod/vcf-mcp-vcf-automation"
    provider.store(ref, SecretValue("rt-0"))

    def supplier():
        return "svc", provider.resolve(ref).reveal_for_transport()

    persist = lambda new: provider.store(ref, SecretValue(new))  # noqa: E731
    idp = Idp()
    transport = HTTPTransport(mock_handler=idp, max_retries=0)
    VCFAutomationTokenAuth(BASE, transport, supplier, tenant="nw", on_refresh_token=persist)._current_token()
    # a new process: fresh provider object reading the file, fresh auth object
    provider2 = LocalEncryptedSecretProvider(storage_path=str(tmp_path / "credentials.json"), key_protector=protector)
    assert provider2.resolve(ref).reveal_for_transport() == "rt-1"
    assert not list(tmp_path.glob("*.tmp")), "atomic write must not leave temp files"
    auth2 = VCFAutomationTokenAuth(BASE, transport, lambda: ("svc", provider2.resolve(ref).reveal_for_transport()), tenant="nw")
    assert auth2._current_token() == "at-2"


def test_invalid_grant_gives_a_clear_error_without_the_token():
    idp, store = Idp(), Store("rt-stale")
    auth = make_auth(idp, store)
    with pytest.raises(UpstreamAuthException) as err:
        auth._current_token()
    text = str(err.value)
    assert "already used or revoked" in text and "vcf-mcp setup automation" in text
    assert "rt-stale" not in text


def test_endpoint_order_404_405_fallback_and_cached_endpoint():
    idp, store = Idp(paths=("/tm/oauth/tenant/nw/token",)), Store("rt-0")
    auth = make_auth(idp, store)
    auth._current_token()
    assert [c[0] for c in idp.calls] == ["/oauth/tenant/nw/token", "/tm/oauth/tenant/nw/token"]
    idp.calls.clear()
    force_expiry(auth)
    auth._current_token()
    assert [c[0] for c in idp.calls] == ["/tm/oauth/tenant/nw/token"], "the working endpoint is tried first next time"

    calls = []

    def handler(req):
        calls.append(req.url.removeprefix(BASE))
        if len(calls) == 1:
            return TransportResponse(405, body=b"")
        return TransportResponse(200, body=b'{"access_token": "ok", "expires_in": 60}')

    auth = VCFAutomationTokenAuth(BASE, HTTPTransport(mock_handler=handler, max_retries=0), lambda: ("u", "r"), tenant="nw")
    assert auth._current_token() == "ok" and len(calls) == 2


def test_only_404_and_405_move_to_the_next_endpoint():
    calls = []

    def handler(req):
        calls.append(req.url)
        return TransportResponse(400, body=b'{"error": "invalid_request"}')

    auth = VCFAutomationTokenAuth(BASE, HTTPTransport(mock_handler=handler, max_retries=0), lambda: ("u", "r"), tenant="nw")
    with pytest.raises(UpstreamAuthException):
        auth._current_token()
    assert len(calls) == 1


def test_no_endpoint_found_names_the_attempts():
    auth = VCFAutomationTokenAuth(BASE, HTTPTransport(mock_handler=lambda r: TransportResponse(404), max_retries=0),
                                  lambda: ("u", "r"), tenant="nw")
    with pytest.raises(UpstreamAuthException) as err:
        auth._current_token()
    assert "/oauth/tenant/nw/token -> HTTP 404" in str(err.value) and "vcf.automation_org" in str(err.value)


def test_system_org_uses_provider_endpoints():
    assert automation_token_paths("System") == ["/oauth/provider/token", "/tm/oauth/provider/token"]
    assert automation_token_paths("system")[0] == "/oauth/provider/token"
    assert automation_token_paths("My Org") == ["/oauth/tenant/My%20Org/token", "/tm/oauth/tenant/My%20Org/token"]


def test_client_id_is_sent_when_known_and_only_then():
    idp = Idp()
    make_auth(idp, Store("rt-0"), client_id="client-abc")._current_token()
    assert idp.calls[0][1]["client_id"] == "client-abc"
    idp2 = Idp()
    make_auth(idp2, Store("rt-0"))._current_token()
    assert "client_id" not in idp2.calls[0][1]


def test_concurrent_callers_refresh_once():
    idp, store = Idp(), Store("rt-0")
    idp.delay = 0.05
    auth = make_auth(idp, store)
    results, errors = [], []

    def worker():
        try:
            results.append(auth._current_token())
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(12)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert not errors and set(results) == {"at-1"}
    assert len(idp.calls) == 1 and store.writes == ["rt-1"]


def test_expiry_uses_expires_in_then_jwt_exp_then_default_and_refreshes_a_minute_early(monkeypatch):
    now = [1_000_000.0]
    monkeypatch.setattr(time, "time", lambda: now[0])
    idp, store = Idp(expires_in=600), Store("rt-0")
    auth = make_auth(idp, store)
    auth._current_token()
    assert auth._expires_at == now[0] + 600
    now[0] += 539
    auth._current_token()
    assert len(idp.calls) == 1, "still valid 61 s before expiry"
    now[0] += 2
    auth._current_token()
    assert len(idp.calls) == 2, "refreshed inside the 60 s margin"

    body = {"access_token": jwt(now[0] + 1234)}
    auth = VCFAutomationTokenAuth(BASE, HTTPTransport(mock_handler=lambda r: TransportResponse(200, body=json.dumps(body).encode()), max_retries=0),
                                  lambda: ("u", "r"), tenant="nw")
    auth._current_token()
    assert auth._expires_at == now[0] + 1234

    auth = VCFAutomationTokenAuth(BASE, HTTPTransport(mock_handler=lambda r: TransportResponse(200, body=b'{"access_token": "opaque"}'), max_retries=0),
                                  lambda: ("u", "r"), tenant="nw")
    auth._current_token()
    assert auth._expires_at == now[0] + auth.default_ttl_seconds


def test_persist_failure_keeps_the_new_token_in_memory_and_never_logs_it(caplog):
    idp, store = Idp(), Store("rt-0")
    transport = HTTPTransport(mock_handler=idp, max_retries=0)

    def broken(new):
        raise OSError(f"disk full while writing {new}")

    auth = VCFAutomationTokenAuth(BASE, transport, store.read, tenant="nw", on_refresh_token=broken)
    with caplog.at_level(logging.DEBUG):
        auth._current_token()
        force_expiry(auth)
        assert auth._current_token() == "at-2", "second refresh must use the in-memory rotated token"
    assert [c[1]["refresh_token"] for c in idp.calls] == ["rt-0", "rt-1"]
    assert "Could not persist" in caplog.text
    assert "rt-1" not in caplog.text and "rt-0" not in caplog.text
    # someone re-ran setup and stored a different token: it wins over the in-memory one
    idp.valid.add("rt-new")
    store.value = "rt-new"
    force_expiry(auth)
    auth._current_token()
    assert idp.calls[-1][1]["refresh_token"] == "rt-new"


def test_401_on_an_api_call_relogs_in_once_with_the_rotated_token():
    from vcf_enterprise_mcp.adapter.providers.vcenter import VCenterProvider
    idp, store = Idp(), Store("rt-0")
    issued = []

    def handler(req):
        if "/oauth/" in req.url:
            resp = idp(req)
            issued.append(json.loads(resp.body)["access_token"])
            return resp
        return TransportResponse(401) if req.headers["Authorization"] == "Bearer at-1" else TransportResponse(200, body=b'{"link": []}')

    transport = HTTPTransport(mock_handler=handler, max_retries=0)
    auth = VCFAutomationTokenAuth(BASE, transport, store.read, tenant="nw", on_refresh_token=store.write)
    prov = VCenterProvider(endpoint_url=BASE, transport=transport, auth=auth)
    assert prov.request("GET", "/vco/api/workflows").status_code == 200
    assert issued == ["at-1", "at-2"] and [c[1]["refresh_token"] for c in idp.calls] == ["rt-0", "rt-1"]


# ---- orchestrator_auth modes ------------------------------------------------------------------


def test_basic_mode_sends_http_basic_on_every_request():
    auth = OrchestratorBasicAuth(lambda: ("orchadmin", "pw"))
    for _ in range(2):
        req = auth.apply(TransportRequest("GET", "https://vro.corp.internal/vco/api/workflows"))
        assert req.headers["Authorization"] == "Basic " + base64.b64encode(b"orchadmin:pw").decode()


class SessionHost:
    def __init__(self, statuses, token="sess-token"):
        self.statuses, self.token, self.calls = dict(statuses), token, []

    def __call__(self, req):
        path = req.url.removeprefix(BASE)
        version = req.headers["Accept"].split("version=")[1]
        self.calls.append((path, version, req.headers["Authorization"]))
        status = self.statuses.get((path, version), self.statuses.get(path, 200))
        if status == 200:
            return TransportResponse(200, headers={"X-VMWARE-VCLOUD-ACCESS-TOKEN": self.token}, body=b"{}")
        return TransportResponse(status, body=b"")


def session_auth(host, user="admin", org="nw", password="pw"):
    return VCFASessionAuth(BASE, HTTPTransport(mock_handler=host, max_retries=0), lambda: (user, password), tenant=org)


def test_vcfa_session_login_uses_user_at_org_and_reads_the_token_header():
    host = SessionHost({})
    auth = session_auth(host)
    assert auth._header(auth._current_token()) == ("Authorization", "Bearer sess-token")
    assert host.calls == [("/cloudapi/1.0.0/sessions", "40.0", "Basic " + base64.b64encode(b"admin@nw:pw").decode())]
    assert session_auth(host, user="admin@nw")._current_token() == "sess-token"
    assert host.calls[-1][2] == host.calls[0][2], "a user that already ends in @org is not suffixed twice"


def test_vcfa_session_tries_versions_then_the_tm_url_and_stops_at_the_first_401():
    host = SessionHost({"/cloudapi/1.0.0/sessions": 404})
    assert session_auth(host)._current_token() == "sess-token"
    assert [c[0] for c in host.calls] == ["/cloudapi/1.0.0/sessions", "/tm/cloudapi/1.0.0/sessions"]

    host = SessionHost({("/cloudapi/1.0.0/sessions", "40.0"): 400, ("/cloudapi/1.0.0/sessions", "9.1.0"): 400})
    assert session_auth(host)._current_token() == "sess-token"
    assert [c[1] for c in host.calls] == ["40.0", "9.1.0", "9.0.0"]

    host = SessionHost({"/cloudapi/1.0.0/sessions": 401})
    auth = session_auth(host)
    with pytest.raises(UpstreamAuthException) as err:
        auth._current_token()
    assert len(host.calls) == 1, "a 401 must stop immediately (account lockout)"
    assert "SSO" in str(err.value)
    with pytest.raises(UpstreamAuthException):
        auth._current_token()
    assert len(host.calls) == 1, "the same rejected credential is not sent again"
    host.statuses.clear()
    auth.credentials = lambda: ("admin", "new-password")
    assert auth._current_token() == "sess-token"


def test_vcfa_session_for_the_system_org_uses_provider_sessions():
    host = SessionHost({})
    session_auth(host, org="System")._current_token()
    assert host.calls[0][0] == "/cloudapi/1.0.0/sessions/provider"


# ---- wiring ------------------------------------------------------------------------------------


def wire(**vcf):
    cfg = UpstreamVCFConfig(**vcf)
    suppliers = []

    def supplier(kind):
        suppliers.append(kind)
        return lambda: (cfg.component_usernames.get(kind, "u"), f"secret-for-{kind}")

    transport = HTTPTransport(mock_handler=lambda r: TransportResponse(200), max_retries=0)
    return build_automation_auth(cfg, transport, supplier, lambda t: None, 30.0), suppliers


def test_standalone_orchestrator_gets_the_org_and_shares_the_token_chain():
    (automation, orchestrator), _ = wire(automation_url=BASE, automation_org="nw", automation_client_id="cid",
                                         orchestrator_url="https://vro.corp.internal")
    assert orchestrator[0] == "https://vro.corp.internal"
    assert orchestrator[1] is automation[1], "one refresh-token chain: two instances would burn each other's token"
    assert automation[1].tenant == "nw" and automation[1].base_url == BASE and automation[1].client_id == "cid"

    (automation, orchestrator), _ = wire(orchestrator_url="https://vro.corp.internal", automation_org="nw")
    assert automation is None
    assert orchestrator[1].tenant == "nw" and orchestrator[1].base_url == "https://vro.corp.internal"

    with pytest.raises(ValueError, match="automation_org"):
        wire(orchestrator_url="https://vro.corp.internal")


def test_embedded_orchestrator_shares_the_automation_auth():
    (automation, orchestrator), _ = wire(automation_url=BASE, automation_org="nw")
    assert orchestrator == (BASE, automation[1])


def test_orchestrator_auth_modes_are_selected_by_setting():
    (_, orch), suppliers = wire(orchestrator_url="https://vro.corp.internal", orchestrator_auth="basic",
                                component_credential_refs={"vcf_orchestrator": "local://env-prod/x"})
    assert isinstance(orch[1], OrchestratorBasicAuth) and suppliers == ["vcf_orchestrator"]
    (_, orch), _ = wire(automation_url=BASE, automation_org="nw", orchestrator_auth="vcfa_session")
    assert isinstance(orch[1], VCFASessionAuth) and orch[1].base_url == BASE and orch[1].tenant == "nw"
    with pytest.raises(ValueError, match="orchestrator_auth"):
        wire(automation_url=BASE, automation_org="nw", orchestrator_auth="magic")


def test_basic_mode_falls_back_to_the_automation_credential_and_user():
    (_, orch), suppliers = wire(orchestrator_url="https://vro.corp.internal", orchestrator_auth="basic",
                                component_usernames={"vcf_automation": "orch-svc"})
    req = orch[1].apply(TransportRequest("GET", "https://vro.corp.internal/vco/api/about"))
    assert req.headers["Authorization"] == "Basic " + base64.b64encode(b"orch-svc:secret-for-vcf_automation").decode()
