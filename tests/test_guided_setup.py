# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Guided, interactive and secure setup (vcf_setup / vcf_access_report).

Covers MRTR elicitation (form + URL mode), the loopback credential page, access
discovery with local-admin / over-permissive warnings, operator safety choices
enforced server-side, the no-elicitation fallback, and that secrets never reach
tool arguments, responses, requestState, config, reports or audit.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import tempfile
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from vcf_enterprise_mcp.adapter.transport.base import TransportResponse
from vcf_enterprise_mcp.adapter.transport.http import HTTPTransport
from vcf_enterprise_mcp.auth.lab_auth import mint_lab_jwt_token, register_lab_key_in_jwks
from vcf_enterprise_mcp.core.protocol import EnterpriseMCPProtocolEngine
from vcf_enterprise_mcp.secrets.base import MissingCredentialException
from vcf_enterprise_mcp.setup.credential_portal import CredentialPortal
from vcf_enterprise_mcp.setup.request_state import InvalidRequestStateException, RequestStateCodec
from vcf_enterprise_mcp.setup.safety_profile import SafetyProfile
from vcf_enterprise_mcp.setup.wizard import SetupWizard, credential_reference
from vcf_enterprise_mcp.state.sqlite_store import SQLiteDurableStore
from vcf_enterprise_mcp.workflows.task_store import TaskStore

PASSWORD = "Lab-Only-Test-Value-7f3a"  # appears only in the simulated browser submit
FORM_AND_URL = {"io.modelcontextprotocol/clientCapabilities": {"elicitation": {"form": {}, "url": {}}}}
ENDPOINTS = {
    "vcenter": "https://vcenter.corp.internal",
    "sddc_manager": "https://sddc-manager.corp.internal",
    "nsx": "https://nsx.corp.internal",
    "vcf_operations": "https://vcf-ops.corp.internal",
}


class MemorySecrets:
    def __init__(self):
        self.data = {}

    def store(self, reference, secret, tenant_id="tenant-default", environment_id="env-prod", description=None):
        self.data[(reference, tenant_id, environment_id)] = secret

    def resolve(self, reference, tenant_id="tenant-default", environment_id="env-prod"):
        try:
            return self.data[(reference, tenant_id, environment_id)]
        except KeyError:
            raise MissingCredentialException(f"missing {reference}")

    def delete(self, reference, tenant_id="tenant-default", environment_id="env-prod"):
        self.data.pop((reference, tenant_id, environment_id), None)


def fake_vcf(seen_auth):
    """Official-shape responses for an environment configured with local admin accounts."""
    import base64

    def handler(req):
        host, path = urllib.parse.urlsplit(req.url).hostname, urllib.parse.urlsplit(req.url).path
        if host == "vcenter.corp.internal":
            if path == "/api/session" and req.method == "POST":
                seen_auth.append(base64.b64decode(req.headers["Authorization"].split()[1]).decode())
                return TransportResponse(201, body=b'"vc-session"')
            if path == "/api/session":
                return TransportResponse(200, body=b'{"user": "Administrator@VSPHERE.LOCAL", "created_time": "x", "last_accessed_time": "x"}')
            if path.endswith("/HasUserPrivilegeOnEntities"):
                privs = [{"privId": p, "isGranted": True} for p in req.json_body["privId"]]
                return TransportResponse(200, body=json.dumps([{"entity": req.json_body["entities"][0], "privAvailability": privs}]).encode())
        if host == "sddc-manager.corp.internal":
            if path == "/v1/tokens":
                seen_auth.append(f"{req.json_body['username']}:{req.json_body['password']}")
                return TransportResponse(200, body=b'{"accessToken": "acc", "refreshToken": {"id": "r"}}')
            if path == "/v1/domains":
                return TransportResponse(200, body=b'{"elements": []}')
            if path == "/v1/users":
                return TransportResponse(200, body=b'{"elements": []}')  # ADMIN only
        if host == "nsx.corp.internal" and path == "/api/v1/aaa/user-info":
            return TransportResponse(200, body=b'{"user_name": "admin", "roles": [{"role": "enterprise_admin"}]}')
        if host == "vcf-ops.corp.internal":
            if path == "/suite-api/api/auth/token/acquire":
                return TransportResponse(200, body=b'{"token": "ops", "validity": 9999999999999}')
            if path == "/suite-api/api/auth/currentuser":
                return TransportResponse(200, body=b'{"username": "admin", "roleNames": ["Administrator"]}')
            if path == "/suite-api/api/auth/currentuser/permissions":
                return TransportResponse(200, body=b'{"permissions": [{"roleName": "Administrator", "allowAllObjects": true}]}')
        return TransportResponse(404)
    return handler


def browser_submit(url, password=PASSWORD, csrf_override=None, host_override=None, origin=None):
    """Simulates the user's browser: load the page, then POST the form."""
    page = urllib.request.urlopen(url, timeout=5).read().decode()
    csrf = page.split("name=csrf value='")[1].split("'")[0]
    data = urllib.parse.urlencode({"csrf": csrf_override or csrf, "secret": password}).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    if host_override:
        req.add_header("Host", host_override)
    if origin:
        req.add_header("Origin", origin)
    return urllib.request.urlopen(req, timeout=5)


class GuidedSetupBase(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        os.environ["VCF_MCP_HOME"] = str(self.home)
        self.secrets = MemorySecrets()
        self.portal = CredentialPortal(sink=lambda ref, s, t, e, d: self.secrets.store(ref, s, t, e, d))
        self.profile = SafetyProfile.at_home(self.home)
        self.seen_auth = []
        self.wizard = SetupWizard(
            home=self.home, safety_profile=self.profile, secret_registry=self.secrets,
            config_path=self.home / "config.yaml", portal=self.portal,
            codec=RequestStateCodec(home=self.home),
            transport_factory=lambda hosts: HTTPTransport(mock_handler=fake_vcf(self.seen_auth), max_retries=0),
            wait_seconds=0.2,
        )
        durable = SQLiteDurableStore(os.path.join(self.tmp.name, "cp.db"))
        self.engine = EnterpriseMCPProtocolEngine(task_store=TaskStore(durable_store=durable), setup_wizard=self.wizard)
        self.engine.pep.safety_profile = self.profile
        self.engine.pep.pdp.config.operating_mode = "AUDITED_OPERATIONS"
        self.engine.idp.config.allow_lab_tokens = True  # lab tokens are opt-in (F7)
        key = os.path.join(self.tmp.name, "lab.pem")
        register_lab_key_in_jwks(self.engine.idp.jwks_manager, custom_path=key)
        self.admin = mint_lab_jwt_token(user_id="mcp-admin@corp.com", role="MCP_ADMIN", custom_key_path=key)["authorization_header"]
        self.viewer = mint_lab_jwt_token(user_id="viewer@corp.com", role="VCF_VIEWER", custom_key_path=key)["authorization_header"]
        self.operator = mint_lab_jwt_token(user_id="op@corp.com", role="COMPUTE_OPERATOR", custom_key_path=key)["authorization_header"]
        self._ids = 0
        self.responses = []

    def tearDown(self):
        self.portal.shutdown()
        os.environ.pop("VCF_MCP_HOME", None)
        self.tmp.cleanup()

    def call(self, name, arguments=None, bearer=None, **extra):
        self._ids += 1
        params = {"name": name, "arguments": arguments or {}, **extra}
        resp = asyncio.run(self.engine.handle_jsonrpc_request(
            {"jsonrpc": "2.0", "id": self._ids, "method": "tools/call", "params": params}, bearer or self.admin))
        self.responses.append(json.dumps(resp))
        return resp

    def rpc(self, method, params=None, bearer=None):
        self._ids += 1
        return asyncio.run(self.engine.handle_jsonrpc_request(
            {"jsonrpc": "2.0", "id": self._ids, "method": method, "params": params or {}}, bearer or self.admin))

    def retry(self, previous, responses, name="vcf_setup"):
        return self.call(name, {}, _meta=FORM_AND_URL, inputResponses=responses, requestState=previous["result"]["requestState"])


class TestGuidedSetupFlow(GuidedSetupBase):

    def test_full_interactive_flow_with_local_admin_accounts(self):
        r = self.call("vcf_setup", {}, _meta=FORM_AND_URL)
        res = r["result"]
        self.assertEqual(res["resultType"], "input_required")
        form = res["inputRequests"]["goals"]["params"]
        self.assertEqual(form["mode"], "form")
        self.assertIn("goals", form["requestedSchema"]["properties"])

        r = self.retry(r, {"goals": {"action": "accept", "content": {"target": "lab", "goals": ["monitor", "vm_operations"]}}})
        env_form = r["result"]["inputRequests"]["environment"]["params"]
        props = env_form["requestedSchema"]["properties"]
        self.assertIn("vcenter_username", props)
        self.assertFalse(any("pass" in k for k in props), "form mode must never ask for passwords")

        content = {}
        for comp, url in ENDPOINTS.items():
            content[f"{comp}_url"] = url
            content[f"{comp}_username"] = {"vcenter": "administrator@vsphere.local", "sddc_manager": "admin@local"}.get(comp, "admin")
        r = self.retry(r, {"environment": {"action": "accept", "content": content}})

        # Passwords: one URL-mode elicitation per component, pointing at the loopback page.
        reqs = r["result"]["inputRequests"]
        self.assertEqual(set(reqs), {f"login_{c}" for c in ENDPOINTS})
        for req in reqs.values():
            self.assertEqual(req["params"]["mode"], "url")
            self.assertTrue(req["params"]["url"].startswith("http://127.0.0.1:"))
        for req in reqs.values():
            self.assertEqual(browser_submit(req["params"]["url"]).status, 200)
        r = self.retry(r, {k: {"action": "accept"} for k in reqs})

        # Access verified -> safety form with warnings and defaults that block destructive actions.
        safety = r["result"]["inputRequests"]["safety"]["params"]
        self.assertIn("over-permissive", safety["message"])
        self.assertIn("built-in local administrator", safety["message"])
        schema = safety["requestedSchema"]["properties"]
        self.assertTrue(schema["disable_snapshot_delete"]["default"])  # destructive + over-permissive
        self.assertTrue(schema["disable_upgrades"]["default"])         # outside the selected goals
        self.assertFalse(schema["disable_vm_power"]["default"])        # requested goal, not destructive

        choice = {k: v["default"] for k, v in schema.items() if k != "read_only"}
        r = self.retry(r, {"safety": {"action": "accept", "content": {**choice, "read_only": False}}})
        done = r["result"]["structuredContent"]
        self.assertEqual(done["status"], "COMPLETE")
        self.assertIn("vcf_delete_snapshot", done["newly_disabled"])
        self.assertEqual(set(done["access_report"]["over_permissive_components"]), set(ENDPOINTS))
        self.assertIn("vcenter", done["access_report"]["least_privilege_guide"])
        self.assertTrue(any("least-privilege" in s for s in done["next_steps"]))

        # The browser-submitted password was used for the real logins...
        self.assertIn(f"administrator@vsphere.local:{PASSWORD}", self.seen_auth)
        self.assertIn(f"admin@local:{PASSWORD}", self.seen_auth)
        # ...but never appears in any MCP response, config, report or audit record.
        for blob in self.responses + [(self.home / "config.yaml").read_text(), (self.home / "access_report.json").read_text(),
                                      json.dumps([vars(a) for a in self.engine.audit.records], default=str)]:
            self.assertNotIn(PASSWORD, blob)
        cfg = (self.home / "config.yaml").read_text()
        self.assertIn("vcenter_url: https://vcenter.corp.internal", cfg)
        self.assertIn(credential_reference("vcenter"), cfg)
        self.assertEqual(oct((self.home / "config.yaml").stat().st_mode & 0o777), "0o600")

        # Disabled tools vanish from tools/list and are refused at execution, even for an entitled operator.
        tools = [t["name"] for t in self.rpc("tools/list", bearer=self.operator)["result"]["tools"]]
        self.assertNotIn("vcf_delete_snapshot", tools)
        self.assertIn("vcf_power_vm", tools)
        denied = self.call("vcf_delete_snapshot", {"vm_id": "vm-101", "snapshot_id": "s1"}, bearer=self.operator)
        self.assertIn("safety profile", json.dumps(denied))

        # "What can you do?" for any principal.
        report = self.call("vcf_access_report", bearer=self.viewer)["result"]["structuredContent"]
        self.assertTrue(report["setup_complete"])
        self.assertIn("warning", report)
        self.assertIn("vcf_delete_snapshot", report["switched_off_by_operator"]["disabled_tools"])

    def test_digital_twin_needs_no_credentials(self):
        r = self.call("vcf_setup", {}, _meta=FORM_AND_URL)
        r = self.retry(r, {"goals": {"action": "accept", "content": {"target": "digital_twin", "goals": ["monitor"]}}})
        r = self.retry(r, {"environment": {"action": "accept", "content": {"twin_url": "http://127.0.0.1:9080"}}})
        safety = r["result"]["inputRequests"]["safety"]["params"]["requestedSchema"]["properties"]
        self.assertTrue(safety["read_only"]["default"])  # read-only goals -> suggest read-only mode
        r = self.retry(r, {"safety": {"action": "accept", "content": {"read_only": True}}})
        done = r["result"]["structuredContent"]
        self.assertEqual(done["status"], "COMPLETE")
        self.assertTrue(self.profile.read_only)
        self.assertIn("environment: digital_twin", (self.home / "config.yaml").read_text())
        self.assertEqual(done["your_choices"]["answered_by"], "you, in 3 setup question(s) shown by your client")
        self.assertIn("Start the Digital Twin", done["next_steps"][0])  # nothing listens on 9080 in the tests

    def test_running_digital_twin_gets_no_start_hint(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0)); listener.listen(1)
        url = f"http://127.0.0.1:{listener.getsockname()[1]}"
        try:
            r = self.call("vcf_setup", {"target": "digital_twin", "goals": ["monitor"], "endpoints": {"digital_twin": url}, "disable": []})
        finally:
            listener.close()
        done = r["result"]["structuredContent"]
        self.assertEqual(done["status"], "COMPLETE")
        self.assertFalse(any("Start the Digital Twin" in s for s in done["next_steps"]))
        self.assertIn("no setup questions were shown", done["your_choices"]["answered_by"])

    def test_decline_stops_without_changes(self):
        r = self.call("vcf_setup", {}, _meta=FORM_AND_URL)
        r = self.retry(r, {"goals": {"action": "decline"}})
        self.assertEqual(r["result"]["structuredContent"]["status"], "CANCELLED")
        self.assertFalse((self.home / "config.yaml").exists())


class TestGuidedSetupSecurity(GuidedSetupBase):

    def test_setup_tool_visibility_and_authorization(self):
        self.engine.pep.pdp.config.operating_mode = "DISCOVERY_ONLY"
        admin_tools = [t["name"] for t in self.rpc("tools/list")["result"]["tools"]]
        self.assertIn("vcf_setup", admin_tools)  # visible even in DISCOVERY_ONLY
        viewer_tools = [t["name"] for t in self.rpc("tools/list", bearer=self.viewer)["result"]["tools"]]
        self.assertNotIn("vcf_setup", viewer_tools)
        self.assertIn("vcf_access_report", viewer_tools)
        self.assertIn("error", json.dumps(self.call("vcf_setup", {}, bearer=self.viewer)))
        init = self.rpc("initialize")["result"]
        self.assertIn("vcf_setup", init["instructions"])
        self.assertIn("UNOFFICIAL", init["instructions"])
        self.assertIn("UNDER TESTING", init["instructions"])
        prompts = [p["name"] for p in self.rpc("prompts/list")["result"]["prompts"]]
        self.assertIn("vcf_guided_setup", prompts)

    def test_secrets_in_arguments_are_rejected(self):
        for args in ({"password": "x"}, {"usernames": {"vcenter": "svc"}, "api_key": "x"}, {"endpoints": {"vcenter_token": "x"}}):
            resp = json.dumps(self.call("vcf_setup", args))
            self.assertIn("Never send passwords", resp)
            self.assertNotIn('"x"', resp)

    def test_request_state_is_bound_and_tamper_proof(self):
        r = self.call("vcf_setup", {}, _meta=FORM_AND_URL)
        token = r["result"]["requestState"]
        codec = self.wizard.codec
        with self.assertRaises(InvalidRequestStateException):
            codec.decode(token, "someone-else", "tools/call:vcf_setup")
        with self.assertRaises(InvalidRequestStateException):
            codec.decode(token[:-2] + ("A" if token[-2] != "A" else "B") + token[-1], "mcp-admin@corp.com", "tools/call:vcf_setup")
        with self.assertRaises(InvalidRequestStateException):
            codec.decode(token, "mcp-admin@corp.com", "tools/call:other")
        # A different principal presenting the token is refused end to end.
        other = self.call("vcf_setup", {}, bearer=self.viewer, requestState=token)
        self.assertIn("error", json.dumps(other))

    def test_setup_can_only_tighten_safety(self):
        self.profile.tighten(["vcf_power_vm"], reason="test", actor="local")
        # Nothing in vcf_setup's schema can re-enable; an empty disable list leaves it disabled.
        r = self.call("vcf_setup", {"target": "digital_twin", "goals": ["monitor"],
                                    "endpoints": {"digital_twin": "http://127.0.0.1:9080"}, "disable": []})
        self.assertEqual(r["result"]["structuredContent"]["status"], "COMPLETE")
        self.assertTrue(self.profile.is_tool_disabled("vcf_power_vm"))
        self.assertNotIn("enable", json.dumps(EnterpriseMCPProtocolEngine.SETUP_TOOL_DEFINITIONS[0]["inputSchema"]))

    def test_portal_rejects_wrong_host_bad_csrf_and_reuse(self):
        t = self.portal.issue(principal_id="p", component="vcenter", component_title="vCenter", endpoint_host="vc",
                              username="svc", reference="local://env-prod/x", tenant_id="tenant-default", environment_id="env-prod")
        url = self.portal.url_for(t)
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            browser_submit(url, host_override="attacker.example:80")
        self.assertEqual(ctx.exception.code, 421)
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            browser_submit(url, csrf_override="forged")
        self.assertEqual(ctx.exception.code, 403)
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            browser_submit(url, origin="https://attacker.example")
        self.assertEqual(ctx.exception.code, 403)
        # Real browsers send the page's own Origin on the form POST; it must be accepted.
        page = urllib.request.urlopen(url, timeout=5)
        self.assertEqual(page.headers["Referrer-Policy"], "same-origin")
        origin = "http://" + urllib.parse.urlsplit(url).netloc
        self.assertEqual(browser_submit(url, origin=origin).status, 200)
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            browser_submit(url)
        self.assertEqual(ctx.exception.code, 410)
        self.assertIsNone(self.portal.get(t.ticket_id, "another-principal"))
        self.assertEqual(self.secrets.resolve("local://env-prod/x").reveal_for_transport(), PASSWORD)


    def test_cli_loosening_requires_interactive_confirmation(self):
        from unittest import mock
        from vcf_enterprise_mcp.cli import main as cli_main
        self.assertEqual(cli_main(["safety", "disable", "vcf_power_vm"]), 0)
        with mock.patch("sys.stdin.isatty", return_value=False):
            self.assertEqual(cli_main(["safety", "enable", "vcf_power_vm"]), 1)
        self.assertTrue(SafetyProfile.at_home(self.home).is_tool_disabled("vcf_power_vm"))
        self.assertEqual(cli_main(["safety", "enable", "vcf_power_vm", "--yes"]), 0)
        self.assertFalse(SafetyProfile.at_home(self.home).is_tool_disabled("vcf_power_vm"))


class TestGuidedSetupWithoutElicitation(GuidedSetupBase):

    def test_fallback_returns_questions_and_resume_token(self):
        r = self.call("vcf_setup", {})
        out = r["result"]["structuredContent"]
        self.assertEqual(out["status"], "NEEDS_INPUT")
        self.assertEqual({q["field"] for q in out["questions"]}, {"target", "goals"})
        self.assertIn("Never ask the user for passwords", out["how_to_continue"])

        r = self.call("vcf_setup", {"resume": out["resume"], "target": "lab", "goals": ["monitor"],
                                    "endpoints": {"vcenter": ENDPOINTS["vcenter"], "sddc_manager": ENDPOINTS["sddc_manager"],
                                                  "nsx": ENDPOINTS["nsx"], "vcf_operations": ENDPOINTS["vcf_operations"]},
                                    "usernames": {"vcenter": "svc-mcp@corp.internal", "sddc_manager": "svc-mcp@corp.internal",
                                                  "nsx": "svc-mcp@corp.internal", "vcf_operations": "svc-mcp@corp.internal"}})
        creds = r["result"]["structuredContent"]
        self.assertEqual(creds["status"], "NEEDS_CREDENTIALS")
        self.assertEqual(len(creds["credential_pages"]), 4)
        self.assertTrue(all("credentials add" in p["cli_alternative"] for p in creds["credential_pages"]))
        self.assertTrue(all("--password" not in p["cli_alternative"] for p in creds["credential_pages"]))

    def test_rejects_plain_http_endpoints_for_real_vcf(self):
        r = self.call("vcf_setup", {"target": "lab", "goals": ["capacity"],
                                    "endpoints": {"vcf_operations": "http://vcf-ops.corp.internal"},
                                    "usernames": {"vcf_operations": "svc"}})
        out = r["result"]["structuredContent"]
        self.assertEqual(out["status"], "NEEDS_INPUT")
        self.assertIn("https://", out["message"])


if __name__ == "__main__":
    unittest.main()


class IncompleteAnswerTests(GuidedSetupBase):

    def test_incomplete_goals_answer_explains_and_stops_instead_of_looping(self):
        r = self.call("vcf_setup", {}, _meta=FORM_AND_URL)
        for attempt in range(1, 4):
            r = self.retry(r, {"goals": {"action": "accept", "content": {"target": "lab", "goals": []}}})
            res = r["result"]
            if attempt < 3:
                self.assertIn("at least one goal", res["inputRequests"]["goals"]["params"]["message"])
            else:
                self.assertEqual(res["structuredContent"]["status"], "STOPPED")
                self.assertIn("Nothing was changed", res["structuredContent"]["message"])
