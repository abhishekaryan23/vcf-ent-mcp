# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Several vCenters on one server.

- vCenters that SDDC Manager reports and vCenters attached in vcf.vcenters are all read by the inventory tools, each
  with its own login (an attached vCenter may have its own service account).
- A VM change goes to the vCenter that holds the VM; the dry run pins that vCenter into the plan.
- A VM ID found in two vCenters is refused until the caller names the vCenter.
- vcf_add_vcenter and `vcf-mcp vcenter add` log in and check the account before saving; passwords only go through the
  private page or a hidden prompt, and reusing the main account needs the person's own confirmation.
"""

from __future__ import annotations

import asyncio
import base64
import io
import json
import os
import tempfile
import unittest
import urllib.parse
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import yaml

from vcf_enterprise_mcp.adapter.ssrf_guard import SSRFGuard
from vcf_enterprise_mcp.adapter.transport import http as http_module
from vcf_enterprise_mcp.adapter.transport.base import TransportResponse
from vcf_enterprise_mcp.adapter.transport.http import HTTPTransport
from vcf_enterprise_mcp.config.settings import EnterpriseSettings, VCenterTarget, config_file_stamp
from vcf_enterprise_mcp.core import server
from vcf_enterprise_mcp.core.errors import AmbiguousResourceException, InvalidArgumentException, UnverifiedAPIContractException
from vcf_enterprise_mcp.core.protocol import EnterpriseMCPProtocolEngine
from vcf_enterprise_mcp.secrets.models import SecretValue
from vcf_enterprise_mcp.secrets.registry import get_default_secret_registry
from vcf_enterprise_mcp.setup.vcenters import vcenter_reference
from vcf_enterprise_mcp.state.sqlite_store import SQLiteDurableStore
from vcf_enterprise_mcp.workflows.task_store import TaskStore

from tests.test_guided_setup import FORM_AND_URL, PASSWORD, GuidedSetupBase, browser_submit

MGMT, WLD = "vc-mgmt.corp.internal", "vc-wld01.corp.internal"
MAIN_USER, WLD_USER = "svc-mcp@vsphere.local", "svc-mcp@wld01.local"
MAIN_PASSWORD = "Main-Lab-Value-91c2"


class Estate:
    """SDDC Manager plus two vCenters. Both vCenters have a VM 'vm-101' (IDs are only unique inside one vCenter)."""

    def __init__(self, sddc_lists=(MGMT,), accounts=None):
        self.sddc_lists = list(sddc_lists)
        self.accounts = accounts or {MGMT: (MAIN_USER, MAIN_PASSWORD), WLD: (WLD_USER, PASSWORD)}
        self.vms = {MGMT: {"vm-101": ["mgmt-db", "POWERED_OFF"], "vm-150": ["mgmt-ops", "POWERED_ON"]},
                    WLD: {"vm-101": ["wld-web", "POWERED_OFF"], "vm-202": ["wld-app", "POWERED_OFF"]}}
        self.logins, self.power_calls = [], []

    def __call__(self, req):
        parts = urllib.parse.urlsplit(req.url)
        host, path = parts.hostname, parts.path
        query = dict(urllib.parse.parse_qsl(parts.query), **(req.params or {}))
        if host == "sddc.corp.internal":
            if path == "/v1/tokens":
                return TransportResponse(200, body=b'{"accessToken": "acc", "refreshToken": {"id": "r"}}')
            if path == "/v1/vcenters":
                return TransportResponse(200, body=json.dumps({"elements": [{"fqdn": f} for f in self.sddc_lists]}).encode())
            return TransportResponse(404)
        if host not in self.vms:
            return TransportResponse(404)
        if path == "/api/session" and req.method == "POST":
            user, password = base64.b64decode(req.headers["Authorization"].split()[1]).decode().split(":", 1)
            self.logins.append((host, user))
            if (user, password) != self.accounts.get(host):
                return TransportResponse(401)
            return TransportResponse(201, body=json.dumps(f"session-{host}").encode())
        if path == "/api/session":
            return TransportResponse(200, body=json.dumps({"user": self.accounts[host][0]}).encode())
        if path.endswith("/HasUserPrivilegeOnEntities"):
            privs = [{"privId": p, "isGranted": True} for p in req.json_body["privId"]]
            return TransportResponse(200, body=json.dumps([{"entity": req.json_body["entities"][0], "privAvailability": privs}]).encode())
        vms = self.vms[host]
        if path == "/api/vcenter/vm":
            return TransportResponse(200, body=json.dumps([{"vm": i, "name": n, "power_state": s} for i, (n, s) in vms.items()]).encode())
        segs = path.split("/")
        if len(segs) >= 5 and segs[1:4] == ["api", "vcenter", "vm"]:
            vm = vms.get(segs[4])
            if vm is None:
                return TransportResponse(404)
            if len(segs) == 6 and segs[5] == "power":
                if req.method == "POST":
                    self.power_calls.append((host, segs[4], query.get("action")))
                    vm[1] = "POWERED_ON" if query.get("action") in ("start", "reset") else "POWERED_OFF"
                    return TransportResponse(204)
                return TransportResponse(200, body=json.dumps({"state": vm[1]}).encode())
            return TransportResponse(200, body=json.dumps({"name": vm[0], "power_state": vm[1]}).encode())
        return TransportResponse(404)


class EstatePatch:
    """Routes the server's own transport to the fake estate (no DNS, no sockets)."""

    def __init__(self, estate):
        self.estate = estate
        handler = estate

        class _Transport(HTTPTransport):
            def __init__(self, *a, **kw):
                kw.pop("proxy", None)
                super().__init__(*a, mock_handler=handler, max_retries=0, **kw)
        self.patches = [mock.patch.object(http_module, "HTTPTransport", _Transport),
                        mock.patch.object(SSRFGuard, "resolve_destination", lambda self, url, allow_unresolved=False: None)]

    def __enter__(self):
        for p in self.patches:
            p.start()
        return self

    def __exit__(self, *exc):
        for p in self.patches:
            p.stop()


class MultiVCenterPlatformTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["VCF_MCP_HOME"] = self.tmp.name
        secrets = get_default_secret_registry()
        secrets.store("local://env-prod/vcf-mcp-vcenter", SecretValue(MAIN_PASSWORD), tenant_id="tenant-default", environment_id="env-prod")
        secrets.store("local://env-prod/vcf-mcp-sddc-manager", SecretValue(MAIN_PASSWORD), tenant_id="tenant-default", environment_id="env-prod")
        secrets.store(vcenter_reference(WLD), SecretValue(PASSWORD), tenant_id="tenant-default", environment_id="env-prod")
        self.estate = Estate()
        self.patch = EstatePatch(self.estate).__enter__()

    def tearDown(self):
        self.patch.__exit__(None, None, None)
        os.environ.pop("VCF_MCP_HOME", None)
        self.tmp.cleanup()

    def settings(self, attach=True, sddc=True):
        cfg = EnterpriseSettings()
        v = cfg.vcf
        v.vcenter_url = f"https://{MGMT}"
        v.component_usernames = {"vcenter": MAIN_USER, "sddc_manager": MAIN_USER}
        v.component_credential_refs = {"vcenter": "local://env-prod/vcf-mcp-vcenter", "sddc_manager": "local://env-prod/vcf-mcp-sddc-manager"}
        if sddc:
            v.sddc_manager_url = "https://sddc.corp.internal"
        if attach:
            v.vcenters = {WLD: VCenterTarget(url=f"https://{WLD}", username=WLD_USER, credential_ref=vcenter_reference(WLD))}
        return cfg

    def test_inventory_reads_every_vcenter_each_with_its_own_account(self):
        platform = server._build_real_vcf_platform(self.settings())
        vms = {(v["vcenter"], v["vm"]) for v in platform.get_vms()}
        self.assertEqual(vms, {(MGMT, "vm-101"), (MGMT, "vm-150"), (WLD, "vm-101"), (WLD, "vm-202")})
        self.assertIn((MGMT, MAIN_USER), self.estate.logins)
        self.assertIn((WLD, WLD_USER), self.estate.logins)  # the attached vCenter's own account, not the main one
        self.assertNotIn((WLD, MAIN_USER), self.estate.logins)

    def test_attached_vcenter_without_sddc_manager(self):
        platform = server._build_real_vcf_platform(self.settings(sddc=False))
        self.assertEqual({v["vcenter"] for v in platform.get_vms()}, {MGMT, WLD})

    def test_a_vm_id_in_two_vcenters_is_refused_until_the_vcenter_is_named(self):
        platform = server._build_real_vcf_platform(self.settings())
        with self.assertRaises(AmbiguousResourceException) as ctx:
            platform.get_vm("vm-101")
        self.assertIn(MGMT, str(ctx.exception))
        self.assertIn(WLD, str(ctx.exception))
        vm = platform.get_vm("vm-101", vcenter=WLD)
        self.assertEqual((vm["name"], vm["vcenter"]), ("wld-web", WLD))
        self.assertEqual(platform.get_vm("vm-202")["vcenter"], WLD)  # unique: found without naming the vCenter

    def test_changes_go_to_the_named_vcenter_only(self):
        platform = server._build_real_vcf_platform(self.settings())
        platform.power_vm("vm-101", "start", vcenter=WLD)
        self.assertEqual(self.estate.power_calls, [(WLD, "vm-101", "start")])
        self.assertEqual(self.estate.vms[MGMT]["vm-101"][1], "POWERED_OFF")  # the other vm-101 is untouched
        with self.assertRaises(InvalidArgumentException):
            platform.power_vm("vm-101", "start", vcenter="vc-unknown.corp.internal")

    def test_snapshot_listing_and_deletion_refuse_instead_of_faking_a_result(self):
        platform = server._build_real_vcf_platform(self.settings())
        with self.assertRaises(UnverifiedAPIContractException):
            platform.get_snapshots("vm-202")
        with self.assertRaises(UnverifiedAPIContractException):
            platform.delete_snapshot("vm-202", "snap-1")

    def test_dry_run_pins_the_vcenter_and_the_change_goes_there(self):
        platform = server._build_real_vcf_platform(self.settings())
        durable = SQLiteDurableStore(os.path.join(self.tmp.name, "cp.db"))
        engine = EnterpriseMCPProtocolEngine(task_store=TaskStore(durable_store=durable), platform_client=platform)
        engine.pep.pdp.config.operating_mode = "AUDITED_OPERATIONS"
        tool = engine.tool_instances["vcf_power_vm"]
        from vcf_enterprise_mcp.auth.identity import Principal
        from vcf_enterprise_mcp.policy.models import CapabilityRole
        op = Principal(principal_id="op", user_id="op@corp.com", roles=(CapabilityRole.COMPUTE_OPERATOR.value,),
                       tenant_id="tenant-default", allowed_domains=["*"], allowed_clusters=["*"])

        with self.assertRaises(AmbiguousResourceException):
            asyncio.run(tool.execute(op, {"vm_id": "vm-101", "action": "start", "dry_run": True}))
        args = {"vm_id": "vm-202", "action": "start"}
        plan = asyncio.run(tool.execute(op, dict(args, dry_run=True)))
        stored = tool.plan_manager.get_plan(plan["plan_id"], op)
        self.assertEqual(stored["normalized_args"].get("vcenter"), WLD)  # the approved plan names the vCenter
        self.assertEqual(self.estate.power_calls, [])
        approver = Principal(principal_id="lead", user_id="lead@corp.com", roles=(CapabilityRole.COMPUTE_ADMIN.value,),
                             tenant_id="tenant-default", allowed_domains=["*"], allowed_clusters=["*"])
        signed = tool.plan_manager.approve_plan(plan["plan_id"], approver)
        asyncio.run(tool.execute(op, dict(args, plan_id=plan["plan_id"], approval_id=signed.approval_id, nonce=signed.nonce)))
        self.assertEqual(self.estate.power_calls, [(WLD, "vm-202", "start")])


class AddVCenterToolTests(GuidedSetupBase):

    def setUp(self):
        super().setUp()
        self.estate = Estate()
        self.wizard.transport_factory = lambda hosts: HTTPTransport(mock_handler=self.estate, max_retries=0)
        (self.home / "config.yaml").write_text(yaml.safe_dump({"vcf": {
            "vcenter_url": f"https://{MGMT}", "component_usernames": {"vcenter": MAIN_USER},
            "component_credential_refs": {"vcenter": "local://env-prod/vcf-mcp-vcenter"}}}))
        self.secrets.store("local://env-prod/vcf-mcp-vcenter", SecretValue(MAIN_PASSWORD))

    def config(self):
        return yaml.safe_load((self.home / "config.yaml").read_text())["vcf"]

    def add(self, arguments, **extra):
        return self.call("vcf_add_vcenter", arguments, _meta=extra.pop("meta", FORM_AND_URL), **extra)

    def structured(self, resp):
        return resp["result"]["structuredContent"]

    def test_own_account_password_on_private_page_then_checked_and_saved(self):
        first = self.add({"url": f"https://{WLD}", "username": WLD_USER})["result"]
        self.assertEqual(first["resultType"], "input_required")
        page = first["inputRequests"]["login_vcenter"]["params"]
        self.assertEqual(page["mode"], "url")
        self.assertTrue(page["message"].startswith("Code "))
        browser_submit(page["url"])
        done = self.structured(self.retry({"result": first}, {"login_vcenter": {"action": "accept"}}, name="vcf_add_vcenter"))
        self.assertEqual(done["status"], "COMPLETE")
        self.assertIn((WLD, WLD_USER), self.estate.logins)
        self.assertEqual(self.config()["vcenters"][WLD], {"url": f"https://{WLD}", "username": WLD_USER, "credential_ref": vcenter_reference(WLD)})
        self.assertIn(".corp.internal", self.config()["allowed_dns_suffixes"])
        self.assertNotIn(PASSWORD, "".join(self.responses))
        self.assertNotIn(PASSWORD, (self.home / "config.yaml").read_text())

    def test_wrong_password_saves_nothing_and_discards_it(self):
        self.estate.accounts[WLD] = (WLD_USER, "something-else")
        first = self.add({"url": f"https://{WLD}", "username": WLD_USER})["result"]
        browser_submit(first["inputRequests"]["login_vcenter"]["params"]["url"])
        out = self.structured(self.retry({"result": first}, {"login_vcenter": {"action": "accept"}}, name="vcf_add_vcenter"))
        self.assertEqual(out["status"], "ACCESS_CHECK_FAILED")
        self.assertTrue(out["password_discarded"])
        self.assertNotIn("vcenters", self.config())
        self.assertNotIn((vcenter_reference(WLD), "tenant-default", "env-prod"), self.secrets.data)

    def test_main_account_needs_the_persons_confirmation(self):
        first = self.add({"url": WLD})["result"]  # a bare host name means HTTPS
        self.assertEqual(first["resultType"], "input_required")
        form = first["inputRequests"]["confirm_main_account"]["params"]
        self.assertIn(MAIN_USER, form["message"])
        self.estate.accounts[WLD] = (MAIN_USER, MAIN_PASSWORD)  # this vCenter shares the main SSO domain
        done = self.structured(self.retry({"result": first}, {"confirm_main_account": {"action": "accept", "content": {"use_main_account": True}}},
                                          name="vcf_add_vcenter"))
        self.assertEqual(done["status"], "COMPLETE")
        self.assertEqual(self.config()["vcenters"][WLD], {"url": f"https://{WLD}"})  # no own account stored

    def test_main_account_declined_or_unconfirmable_changes_nothing(self):
        first = self.add({"url": f"https://{WLD}"})["result"]
        out = self.structured(self.retry({"result": first}, {"confirm_main_account": {"action": "accept", "content": {"use_main_account": False}}},
                                         name="vcf_add_vcenter"))
        self.assertEqual(out["status"], "CANCELLED")
        no_forms = {"io.modelcontextprotocol/clientCapabilities": {}}
        out = self.structured(self.add({"url": f"https://{WLD}"}, meta=no_forms))
        self.assertEqual(out["status"], "NEEDS_CONFIRMATION")
        self.assertIn("vcf-mcp vcenter add", out["command"])
        self.assertNotIn("vcenters", self.config())
        self.assertEqual(self.estate.logins, [])  # the main password was never sent

    def test_known_vcenters_and_passwords_in_arguments_are_refused(self):
        out = self.structured(self.add({"url": f"https://{MGMT}"}))
        self.assertEqual(out["status"], "ALREADY_ATTACHED")
        resp = self.add({"url": f"https://{WLD}", "username": WLD_USER, "password": "x"})
        self.assertTrue(resp["result"]["isError"])
        self.assertIn("Never send passwords", resp["result"]["content"][0]["text"])

    def test_viewer_cannot_attach_a_vcenter(self):
        resp = self.call("vcf_add_vcenter", {"url": f"https://{WLD}"}, bearer=self.viewer, _meta=FORM_AND_URL)
        self.assertTrue(resp["result"]["isError"])


class VCenterCliTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.env = mock.patch.dict(os.environ, {"VCF_MCP_HOME": self.tmp.name, "VCF_ENTERPRISE_MCP_CONFIG": str(self.home / "config.yaml")})
        self.env.start()
        (self.home / "config.yaml").write_text(yaml.safe_dump({"vcf": {
            "vcenter_url": f"https://{MGMT}", "component_usernames": {"vcenter": MAIN_USER},
            "component_credential_refs": {"vcenter": "local://env-prod/vcf-mcp-vcenter"}}}))
        get_default_secret_registry().store("local://env-prod/vcf-mcp-vcenter", SecretValue(MAIN_PASSWORD),
                                            tenant_id="tenant-default", environment_id="env-prod")
        self.estate = estate = Estate()
        from vcf_enterprise_mcp.setup.wizard import SetupWizard
        self.transport = mock.patch.object(SetupWizard, "_default_transport",
                                           lambda self, hosts: HTTPTransport(mock_handler=estate, max_retries=0))
        self.transport.start()

    def tearDown(self):
        self.transport.stop()
        self.env.stop()
        self.tmp.cleanup()

    def cli(self, *argv):
        from vcf_enterprise_mcp.cli import main
        out = io.StringIO()
        with redirect_stdout(out):
            code = main(list(argv))
        return code, out.getvalue()

    def test_add_with_own_account_list_and_remove(self):
        with mock.patch("sys.stdin.isatty", return_value=True), mock.patch("getpass.getpass", return_value=PASSWORD):
            code, out = self.cli("vcenter", "add", f"https://{WLD}", "--username", WLD_USER)
        self.assertEqual(code, 0, out)
        self.assertIn("is attached", out)
        self.assertIn((WLD, WLD_USER), self.estate.logins)
        code, out = self.cli("vcenter", "list")
        self.assertIn(WLD, out)
        self.assertIn(WLD_USER, out)
        code, out = self.cli("vcenter", "remove", WLD)
        self.assertEqual(code, 0)
        self.assertEqual(yaml.safe_load((self.home / "config.yaml").read_text())["vcf"].get("vcenters"), {})
        with self.assertRaises(Exception):
            get_default_secret_registry().resolve(vcenter_reference(WLD), tenant_id="tenant-default", environment_id="env-prod")

    def test_main_account_without_a_terminal_needs_yes(self):
        with mock.patch("sys.stdin.isatty", return_value=False):
            code, _ = self.cli("vcenter", "add", f"https://{WLD}")
        self.assertEqual(code, 1)
        self.assertEqual(self.estate.logins, [])
        self.estate.accounts[WLD] = (MAIN_USER, MAIN_PASSWORD)
        code, out = self.cli("vcenter", "add", f"https://{WLD}", "--yes")
        self.assertEqual(code, 0, out)

    def test_client_config_keeps_the_state_folder(self):
        code, out = self.cli("client-config", "claude-code")
        self.assertEqual(code, 0)
        self.assertIn(f"VCF_MCP_HOME={self.tmp.name}", out)


class ConfigEditReloadTests(unittest.TestCase):

    def test_an_outside_config_edit_reloads_the_running_server(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.yaml"
            path.write_text("vcf: {}\n")
            with mock.patch.dict(os.environ, {"VCF_ENTERPRISE_MCP_CONFIG": str(path), "VCF_MCP_HOME": tmp}):
                durable = SQLiteDurableStore(os.path.join(tmp, "cp.db"))
                engine = EnterpriseMCPProtocolEngine(task_store=TaskStore(durable_store=durable))
                fresh = EnterpriseMCPProtocolEngine(task_store=TaskStore(durable_store=durable))
                fresh.marker = "rebuilt"
                engine.reloader = lambda: fresh
                engine.config_stamp = config_file_stamp()
                asyncio.run(engine.handle_jsonrpc_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}))
                self.assertFalse(hasattr(engine, "marker"))  # unchanged file: no reload
                stamp = path.stat().st_mtime_ns
                os.utime(path, ns=(stamp + 2_000_000_000, stamp + 2_000_000_000))
                asyncio.run(engine.handle_jsonrpc_request({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}))
                self.assertEqual(getattr(engine, "marker", None), "rebuilt")
                self.assertEqual(engine.config_stamp, config_file_stamp())


if __name__ == "__main__":
    unittest.main()
