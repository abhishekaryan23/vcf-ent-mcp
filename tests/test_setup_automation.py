# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""`vcf-mcp setup automation` against the organization simulator's VCF Automation identity service
(session login, service-account registration, device flow, rotating refresh tokens). The flow is adapted from
vcf-orchestrator-mcp (MIT, imtrinity94)."""

import json
import logging
import os
import stat

import pytest
import yaml

from tests.fixtures.vcfa_sim import PASSWORD, URL, SimTransport, make_sim
from vcf_enterprise_mcp.adapter.transport.errors import UpstreamAuthException
from vcf_enterprise_mcp.adapter.transport.vcfa_wiring import build_automation_auth
from vcf_enterprise_mcp.config.settings import UpstreamVCFConfig
from vcf_enterprise_mcp.secrets.models import SecretValue
from vcf_enterprise_mcp.setup.automation_account import (
    CREDENTIAL_REFERENCE, AutomationAccountSetup, SetupOptions,
)


class FakeRegistry:
    def __init__(self):
        self.data = {}

    def store(self, ref, secret, *, tenant_id, environment_id, description=None):
        self.data[ref] = secret.reveal_for_transport()

    def resolve(self, ref, **kw):
        return SecretValue(self.data[ref])


class Clock:
    def __init__(self):
        self.t, self.on_sleep, self.sleeps = 0.0, None, []

    def now(self):
        return self.t

    def sleep(self, seconds):
        self.t += seconds
        self.sleeps.append(seconds)
        if self.on_sleep:
            self.on_sleep(len(self.sleeps))


@pytest.fixture
def env(tmp_path):
    sim = make_sim(tmp_path)
    pw = tmp_path / "pw"
    pw.write_text(PASSWORD + "\n")
    os.chmod(pw, 0o600)
    out = []
    clock = Clock()
    registry = FakeRegistry()
    config = tmp_path / "config.yaml"

    holder = SimpleEnv(sim, None, None, out, clock, registry, config, pw)

    def make(**kw):
        holder.transport = SimTransport(sim)
        return AutomationAccountSetup(holder.transport, secret_registry=registry, config_path=config, out=out.append,
                                      sleep=clock.sleep, clock=clock.now, min_poll_seconds=0.0, interactive=False, **kw)
    opts = SetupOptions(url=URL, org="northwind", user="admin", name="mcp-svc", role="Orchestrator Administrator",
                        password_file=str(pw))
    holder.make, holder.opts = make, opts
    return holder


class SimpleEnv:
    def __init__(self, sim, make, opts, out, clock, registry, config, pw):
        self.sim, self.make, self.opts, self.out, self.clock, self.registry, self.config, self.pw = sim, make, opts, out, clock, registry, config, pw

    @property
    def text(self):
        return "\n".join(self.out)


def refresh_token(env):
    return env.registry.data[CREDENTIAL_REFERENCE]


def test_full_flow_registers_grants_stores_the_token_and_writes_the_config(env):
    assert env.make().run(env.opts) == 0
    text = env.text
    for marker in ("1/5 Logged in as admin@northwind", "2/5 Service account 'mcp-svc' registered", "3/5 Device authorization",
                   "4/5 Service account granted", "5/5 Tokens issued", "Orchestrator /vco/api -> HTTP 200", "Next steps"):
        assert marker in text, marker
    # the sim logged the documented sequence
    paths = [(m, p) for m, p, _ in env.transport.requests]
    assert paths[:4] == [("POST", "/cloudapi/1.0.0/sessions"), ("POST", "/oauth/tenant/northwind/register"),
                         ("POST", "/oauth/tenant/northwind/device_authorization"), ("POST", "/tm/cloudapi/1.0.0/deviceLookup/grant")]
    client_id = next(iter(env.sim.vcfa_clients))
    assert env.sim.vcfa_clients[client_id] == {"name": "mcp-svc", "roles": ["Orchestrator Administrator"]}
    cfg = yaml.safe_load(env.config.read_text())["vcf"]
    assert cfg["automation_url"] == URL and cfg["automation_org"] == "northwind" and cfg["automation_client_id"] == client_id
    assert cfg["component_credential_refs"]["vcf_automation"] == CREDENTIAL_REFERENCE
    assert refresh_token(env).startswith("rt-")
    assert stat.S_IMODE(env.config.stat().st_mode) == 0o600


def test_stored_token_then_works_in_the_server_and_rotation_is_persisted(env):
    setup = env.make()
    assert setup.run(env.opts) == 0
    cfg = UpstreamVCFConfig(**yaml.safe_load(env.config.read_text())["vcf"])
    first = refresh_token(env)
    transport = SimTransport(env.sim)
    persisted = []

    def persist(new):
        env.registry.data[CREDENTIAL_REFERENCE] = new
        persisted.append(new)

    def supplier(kind):
        return lambda: ("mcp-svc", env.registry.resolve(CREDENTIAL_REFERENCE).reveal_for_transport())

    automation, orchestrator = build_automation_auth(cfg, transport, supplier, persist, 30.0)
    auth = automation[1]
    assert auth.client_id == cfg.automation_client_id
    token = auth._current_token()
    assert persisted and persisted[0] != first and refresh_token(env) == persisted[0]
    auth.invalidate()
    auth._current_token()
    assert len(persisted) == 2 and persisted[1] != persisted[0]
    assert ("POST", "/oauth/tenant/northwind/token", 200) in transport.requests
    # the access token really works against the simulator's Orchestrator and IaaS API
    from vcf_enterprise_mcp.adapter.transport.base import TransportRequest
    req = orchestrator[1].apply(TransportRequest("GET", f"{URL}/vco/api/workflows?maxResult=1", headers={"Accept": "application/json"}))
    assert transport.send(req).status_code == 200 and token
    # an old, already-rotated token is rejected with the actionable message
    env.registry.data[CREDENTIAL_REFERENCE] = first
    auth.invalidate()
    with pytest.raises(UpstreamAuthException) as err:
        auth._current_token()
    assert "already used or revoked" in str(err.value) and "vcf-mcp setup automation" in str(err.value)


def test_token_endpoint_fallback_when_only_one_oauth_prefix_exists(env):
    env.sim.vcfa_oauth_prefixes = ("",)          # /tm/oauth answers 404
    assert env.make().run(env.opts) == 0          # device-code polling falls back from /tm/oauth to /oauth
    env.sim.vcfa_oauth_prefixes = ("/tm",)       # /oauth answers 404
    env.registry.data.clear()
    env.out.clear()
    assert env.make().run(env.opts) == 0 and "5/5 Tokens issued" in env.text


def test_auto_grant_failure_prints_the_code_and_waits_for_approval(env):
    env.sim.vcfa_auto_grant = False
    env.clock.on_sleep = lambda n: env.sim.vcfa_approve(user_code()) if n == 2 else None

    def user_code():
        return next(iter(env.sim.vcfa_devices.values()))["user_code"]

    assert env.make(max_wait_seconds=60).run(env.opts) == 0
    text = env.text
    assert "Automatic grant failed" in text and "Approve the request in the VCF Automation UI" in text
    code = text.split("grant code:  ")[1].split()[0]
    assert code and "Waiting up to" in text and "5/5 Tokens issued" in text
    assert len(env.clock.sleeps) >= 2


def test_unapproved_request_times_out_with_a_clear_message_and_stores_nothing(env):
    env.sim.vcfa_auto_grant = False
    assert env.make(max_wait_seconds=10).run(env.opts) == 1
    assert "approval window closed" in env.text and "run setup again" in env.text.lower()
    assert not env.registry.data and not env.config.exists()


def test_wrong_password_stops_after_one_attempt_and_explains_sso(env, tmp_path):
    env.pw.write_text("not-the-password\n")
    assert env.make().run(env.opts) == 1
    assert env.sim.vcfa_failed_logins == 1, "exactly one failed login so the account is not locked out"
    text = env.text
    assert "401" in text and "SSO" in text and "--client-id" in text and "--org is the org name" in text
    assert not env.registry.data


def test_client_id_flow_needs_no_password_and_waits_for_ui_approval(env):
    cid = "ui-created-client"
    env.sim.vcfa_clients[cid] = {"name": "ui-svc", "roles": ["Orchestrator Administrator"]}
    env.clock.on_sleep = lambda n: env.sim.vcfa_approve(next(iter(env.sim.vcfa_devices.values()))["user_code"]) if n == 1 else None
    opts = SetupOptions(url=URL, org="northwind", client_id=cid)
    assert env.make(max_wait_seconds=60).run(opts) == 0
    assert not env.sim.vcfa_failed_logins and "Logged in" not in env.text
    assert "Approve the request in the VCF Automation UI" in env.text
    assert yaml.safe_load(env.config.read_text())["vcf"]["automation_client_id"] == cid


def test_account_without_an_orchestrator_role_is_explained(env):
    env.opts.role = "Project Viewer"
    assert env.make().run(env.opts) == 0
    assert "lists no workflows" in env.text and "Orchestrator Administrator" in env.text


def test_unknown_role_is_reported_with_guidance(env):
    env.opts.role = "Made Up Role"
    assert env.make().run(env.opts) == 1
    assert "Unable to find the following role(s)" in env.text and "Access Control > Roles" in env.text


def test_role_is_asked_when_interactive_and_required_otherwise(env):
    env.opts.role = None
    assert env.make().run(env.opts) == 1 and "--role is required" in env.text
    env.out.clear()
    asked = []
    setup = env.make()
    setup.interactive = True
    setup.ask = lambda prompt: asked.append(prompt) or "Orchestrator User"
    assert setup.run(env.opts) == 0
    assert "Access Control > Roles" in env.text and "[Organization Administrator]" in asked[0]
    assert next(iter(env.sim.vcfa_clients.values()))["roles"] == ["Orchestrator User"]


def test_existing_credential_reference_and_config_are_kept(env):
    env.config.write_text(yaml.safe_dump({"vcf": {"credential_ref": "local://prod/sddc-service", "verify_ssl": True,
                                                  "component_credential_refs": {"vcf_automation": "local://env-prod/my-vcfa", "nsx": "local://x"}}}))
    assert env.make().run(env.opts) == 0
    cfg = yaml.safe_load(env.config.read_text())["vcf"]
    assert "local://env-prod/my-vcfa" in env.registry.data and CREDENTIAL_REFERENCE not in env.registry.data
    assert cfg["credential_ref"] == "local://prod/sddc-service" and cfg["component_credential_refs"]["nsx"] == "local://x"


def test_no_password_or_token_appears_in_output_or_logs(env, caplog, capsys):
    with caplog.at_level(logging.DEBUG):
        assert env.make().run(env.opts) == 0
        env.pw.write_text("another-wrong-password-value\n")
        env.make().run(env.opts)
    captured = capsys.readouterr()
    everything = env.text + caplog.text + captured.out + captured.err
    token = refresh_token(env)
    for secret in (PASSWORD, "another-wrong-password-value", token):
        assert secret not in everything
    assert token not in json.dumps(yaml.safe_load(env.config.read_text()))
    for access in env.sim.sessions:
        assert access not in everything


def test_password_prompt_is_not_echoed_and_never_stored(env, capsys):
    asked = []
    setup = env.make()
    setup.interactive = True
    setup.ask_secret = lambda prompt: asked.append(prompt) or PASSWORD
    env.opts.password_file = None
    assert setup.run(env.opts) == 0
    assert asked and PASSWORD not in asked[0] and PASSWORD not in env.text
    assert PASSWORD not in env.config.read_text()


def test_cli_subcommand_end_to_end(env, monkeypatch, capsys):
    from vcf_enterprise_mcp import cli
    from vcf_enterprise_mcp.setup import automation_account as module
    monkeypatch.setattr(module, "build_transport", lambda url, ca, cfg: SimTransport(env.sim))
    monkeypatch.setattr("vcf_enterprise_mcp.secrets.registry.get_default_secret_registry", lambda: env.registry)
    monkeypatch.setattr("sys.stdin.isatty", lambda: False, raising=False)
    rc = cli.main(["setup", "automation", "--url", URL, "--org", "northwind", "--user", "admin", "--name", "cli-svc",
                   "--role", "Orchestrator Administrator", "--password-file", str(env.pw), "--config", str(env.config)])
    captured = capsys.readouterr()
    assert rc == 0
    assert PASSWORD not in captured.out + captured.err and refresh_token(env) not in captured.out + captured.err
    assert "5/5 Tokens issued" in captured.out and yaml.safe_load(env.config.read_text())["vcf"]["automation_org"] == "northwind"
    # the legacy `vcf-mcp setup` options still parse
    args = cli.build_parser().parse_args(["setup", "--target", "digital_twin"])
    assert args.command == "setup" and args.setup_action is None


def test_plain_http_url_is_refused(env):
    env.opts.url = "http://vcfa.example.lab"
    assert env.make().run(env.opts) == 1 and "https" in env.text
