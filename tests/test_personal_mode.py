# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""Personal access mode: one person on their own machine. No token, the local user is the caller, and that person confirms each
change themselves (chat prompt, local page, own terminal). Team mode is covered by the existing suites and stays unchanged."""

import asyncio
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

import pytest

from vcf_enterprise_mcp.auth.personal import local_user_id, resolve_access_mode
from vcf_enterprise_mcp.auth.kms import LocalKMSKeyManager
from vcf_enterprise_mcp.config.settings import EnterpriseSettings
from vcf_enterprise_mcp.core.errors import ConfigurationException
from vcf_enterprise_mcp.core.protocol import EnterpriseMCPProtocolEngine
from vcf_enterprise_mcp.policy.models import RiskClass
from vcf_enterprise_mcp.setup.credential_portal import CredentialPortal, list_approval_tickets
from vcf_enterprise_mcp.state.sqlite_store import SQLiteDurableStore
from vcf_enterprise_mcp.workflows.task_store import TaskStore

FORM = {"io.modelcontextprotocol/clientCapabilities": {"elicitation": {"form": {}}}}
SECRET = "personal-test-kms-secret"


class Env:
    def __init__(self, tmp_path, monkeypatch, config_text=None, **engine_cfg):
        self.tmp = tmp_path
        self.home = tmp_path / "home"
        monkeypatch.setenv("VCF_MCP_HOME", str(self.home))
        monkeypatch.setenv("VCF_KMS_MASTER_SECRET", SECRET)
        self.cfg_file = tmp_path / "config.yaml"
        self.cfg_file.write_text(config_text or "server: {mode: stdio, access_mode: personal}\npolicy: {operating_mode: AUDITED_OPERATIONS}\n")
        monkeypatch.setenv("VCF_ENTERPRISE_MCP_CONFIG", str(self.cfg_file))
        self.db = str(tmp_path / "cp.db")
        self.store = SQLiteDurableStore(self.db)
        self.settings = EnterpriseSettings.load_from_yaml()
        self.engine = EnterpriseMCPProtocolEngine(config=self.settings, task_store=TaskStore(durable_store=self.store))
        self.engine.pep.pdp.config.operating_mode = "AUDITED_OPERATIONS"
        self.engine.plan_manager.kms = LocalKMSKeyManager()
        self.portal = CredentialPortal(sink=lambda *a: None, spool_dir=self.home / "portal")
        if self.engine.personal_approval is not None:
            self.engine.personal_approval._portal = self.portal
        self.user = local_user_id(self.settings)
        self._id = 0

    def rpc(self, method, params=None, **kw):
        self._id += 1
        req = {"jsonrpc": "2.0", "id": self._id, "method": method, "params": params or {}}
        return asyncio.run(self.engine.handle_jsonrpc_request(req, **kw))

    def call(self, name, args, **params):
        res = self.rpc("tools/call", {"name": name, "arguments": args, **params})["result"]
        if res.get("resultType") == "input_required":
            return res, None
        text = res["content"][0]["text"]
        try:
            return res, json.loads(text)
        except ValueError:
            return res, text

    def dry_run(self, name="vcf_power_vm", args=None, **params):
        args = args or {"vm_id": "vm-101", "action": "stop"}
        res, body = self.call(name, {**args, "dry_run": True}, **params)
        assert not res["isError"], body
        return args, body

    def audit(self):
        return [e["payload"] for e in self.store.list_audit_events("tenant-default", "env-prod", 100) if e["payload"].get("tool") == "plan_approval"]


@pytest.fixture
def pe(tmp_path, monkeypatch):
    e = Env(tmp_path, monkeypatch)
    yield e
    e.portal.shutdown()


# ---- identity -------------------------------------------------------------------------------------------------------

def test_no_token_needed_and_the_caller_is_the_local_os_user(pe):
    init = pe.rpc("initialize", {"protocolVersion": "2026-07-28"})["result"]
    assert "ACCESS MODE personal" in init["instructions"] and pe.user in init["instructions"]
    assert "AUTHENTICATION PROBLEM" not in init["instructions"]
    assert init["capabilities"]["experimental"]["enterpriseAuth"]["accessMode"] == "personal"
    listing = pe.rpc("tools/list")["result"]
    assert listing["principal"] == pe.user and re.fullmatch(r"[^@]+@[^@.]+", pe.user)
    names = {t["name"] for t in listing["tools"]}
    assert {"vcf_power_vm", "vcf_get_plan", "vcf_setup"} <= names
    assert "personal" in json.dumps(pe.rpc("tools/call", {"name": "vcf_access_report", "arguments": {}})["result"])


def test_personal_user_and_roles_come_from_the_config(tmp_path, monkeypatch):
    e = Env(tmp_path, monkeypatch, "server: {mode: stdio, access_mode: personal, personal_user: me@laptop, personal_roles: [VCF_VIEWER]}\n"
                                   "policy: {operating_mode: AUDITED_OPERATIONS}\n")
    listing = e.rpc("tools/list")["result"]
    assert listing["principal"] == "me@laptop"
    names = {t["name"] for t in listing["tools"]}
    assert "vcf_list_vms" in names and "vcf_power_vm" not in names and "vcf_setup" not in names
    bad = EnterpriseSettings(server={"access_mode": "personal", "personal_roles": ["NOT_A_ROLE"]})
    with pytest.raises(ConfigurationException):
        EnterpriseMCPProtocolEngine(config=bad, task_store=TaskStore(durable_store=SQLiteDurableStore(str(tmp_path / "x.db"))))


def test_a_supplied_token_is_validated_and_network_requests_never_get_the_personal_identity(pe):
    init = pe.rpc("initialize", {}, auth_header="Bearer not.a.jwt")["result"]
    assert "Remove VCF_MCP_AUTH_TOKEN" in init["instructions"]
    out = pe.rpc("tools/list", {"_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}},
                 headers={"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/list"})  # headers present = HTTP: no implicit identity
    assert "error" in out and "Authorization" in json.dumps(out)


@pytest.mark.parametrize("server, env, why", [
    ({"mode": "http"}, {}, "network listener"),
    ({"mode": "remote_gateway"}, {}, "network listener"),
    ({"mode": "stdio", "production_mode": True}, {}, "production_mode"),
    ({"mode": "stdio"}, {"VCF_MCP_ENV": "production"}, "VCF_MCP_ENV=production"),
    ({"mode": "stdio", "storage_mode": "ENTERPRISE_HA"}, {}, "ENTERPRISE_HA"),
])
def test_personal_mode_is_refused_where_more_than_one_person_could_be_involved(server, env, why, monkeypatch):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    with pytest.raises(ConfigurationException) as err:
        resolve_access_mode(EnterpriseSettings(server={**server, "access_mode": "personal"}))
    assert why in err.value.message and "team" in err.value.message


def test_absent_access_mode_is_team_and_the_cli_override_for_http_is_refused(tmp_path, monkeypatch):
    assert resolve_access_mode(EnterpriseSettings(server={"mode": "http"})) == "team"
    assert resolve_access_mode(EnterpriseSettings(server={"access_mode": "team", "mode": "http"})) == "team"
    with pytest.raises(ConfigurationException):
        resolve_access_mode(EnterpriseSettings(server={"access_mode": "bogus"}))
    from vcf_enterprise_mcp.core import server
    cfg = tmp_path / "c.yaml"
    cfg.write_text("server: {mode: stdio, access_mode: personal}\n")
    monkeypatch.setenv("VCF_ENTERPRISE_MCP_CONFIG", str(cfg))
    monkeypatch.setenv("VCF_MCP_HOME", str(tmp_path / "h"))
    monkeypatch.setattr(server, "get_enterprise_settings", lambda: EnterpriseSettings.load_from_yaml())
    with pytest.raises(SystemExit):
        server.main(mode="http")  # `--mode http` on a personal config


def test_the_starter_config_is_personal(tmp_path):
    import yaml
    from vcf_enterprise_mcp.config.starter import ensure_starter_config
    path = tmp_path / "s" / "config.yaml"
    assert ensure_starter_config(path)
    data = yaml.safe_load(path.read_text())
    assert data["server"]["access_mode"] == "personal" and resolve_access_mode(EnterpriseSettings(**data)) == "personal"


# ---- the dry run and vcf_get_plan -----------------------------------------------------------------------------------

def test_dry_run_gives_the_page_and_the_terminal_command_when_the_client_cannot_elicit(pe):
    _, plan = pe.dry_run()
    how = plan["how_to_approve"]
    assert how["mode"] == "personal" and how["approvals_required"] == 1
    assert re.fullmatch(r"http://127\.0\.0\.1:\d+/approve/[\w-]{40,}", how["approval_url"])
    assert how["command"].startswith(f"vcf-mcp plans approve {plan['plan_id']}") and "plan_id only" in " ".join(how["steps"])
    status = pe.call("vcf_get_plan", {"plan_id": plan["plan_id"]})[1]
    assert status["status"] == "PENDING_APPROVAL" and status["ready_to_execute"] is False and status["approvals_required"] == 1
    assert status["how_to_approve"]["approval_url"] == how["approval_url"]  # the same one-time ticket, not a new one
    assert pe.call("vcf_get_plan", {"plan_id": "plan_nope"})[0]["isError"]


def test_dry_run_for_an_eliciting_client_points_at_the_chat_prompt_and_needs_no_page(pe):
    _, plan = pe.dry_run(_meta=FORM)
    how = plan["how_to_approve"]
    assert "approval_url" not in how and "confirmation prompt" in " ".join(how["steps"]) and how["command"]
    assert list_approval_tickets(pe.home / "portal") == []


def test_calling_live_with_a_plan_but_no_approval_says_how_to_approve(pe):
    args, plan = pe.dry_run()
    res, _ = pe.call("vcf_power_vm", {**args, "plan_id": plan["plan_id"]})
    text = res["content"][0]["text"]
    assert res["isError"] and "has not been approved" in text and "plan_id only" in text and plan["how_to_approve"]["approval_url"] in text
    assert res["structuredContent"]["error"]["data"]["how_to_approve"]["command"]


# ---- in-client approval: MCP elicitation -------------------------------------------------------------------------------

def ask(pe, args, plan_id, name="vcf_power_vm"):
    res, _ = pe.call(name, {**args, "plan_id": plan_id}, _meta=FORM)
    assert res["resultType"] == "input_required"
    return res


def answer(pe, args, plan_id, prev, action="accept", content=None, name="vcf_power_vm"):
    return pe.call(name, {**args, "plan_id": plan_id}, _meta=FORM, requestState=prev["requestState"],
                   inputResponses={"approve_plan": {"action": action, **({"content": content} if content is not None else {})}})


def test_elicitation_approve_executes_in_the_same_call_and_audits_the_channel(pe):
    args, plan = pe.dry_run(_meta=FORM)
    first = ask(pe, args, plan["plan_id"])
    req = first["inputRequests"]["approve_plan"]
    assert req["method"] == "elicitation/create" and req["params"]["mode"] == "form"
    msg = req["params"]["message"]
    assert "vcf_power_vm" in msg and "vm-101" in msg and "SAFE_WRITE" in msg and "simulated_state: POWERED_OFF" in msg
    assert req["params"]["requestedSchema"]["properties"]["decision"]["oneOf"][0]["const"] == "approve"
    assert "confirm" not in req["params"]["requestedSchema"]["properties"]  # not destructive: no typing needed
    res, done = answer(pe, args, plan["plan_id"], first, content={"decision": "approve"})
    assert not res["isError"] and done["status"] == "SUCCESS" and done["new_power_state"] == "POWERED_OFF"
    rec = [a for a in pe.audit() if a["arguments"]["outcome"] == "APPROVED"][0]["arguments"]
    assert rec["channel"] == "in_client" and rec["mode"] == "personal" and rec["approver"] == pe.user
    assert rec["plan_hash"] == plan["canonical_plan_hash"]


@pytest.mark.parametrize("action, content", [("accept", {"decision": "reject"}), ("decline", None), ("cancel", None)])
def test_elicitation_reject_decline_cancel_are_not_approvals(pe, action, content):
    args, plan = pe.dry_run(_meta=FORM)
    first = ask(pe, args, plan["plan_id"])
    res, _ = answer(pe, args, plan["plan_id"], first, action=action, content=content)
    assert res["isError"] and "NOT APPROVED" in res["content"][0]["text"]
    assert pe.call("vcf_get_plan", {"plan_id": plan["plan_id"]})[1]["ready_to_execute"] is False
    assert [a for a in pe.audit() if a["arguments"]["outcome"] == "REJECTED"]


def test_the_model_cannot_answer_for_the_person(pe):
    """The answer lives in params.inputResponses (written by the client), never in the tool arguments."""
    args, plan = pe.dry_run(_meta=FORM)
    res, _ = pe.call("vcf_power_vm", {**args, "plan_id": plan["plan_id"], "inputResponses": {"approve_plan": {"action": "accept"}}})
    assert res["isError"]
    forged = pe.call("vcf_power_vm", {**args, "plan_id": plan["plan_id"]}, _meta=FORM, requestState="x.y",
                     inputResponses={"approve_plan": {"action": "accept", "content": {"decision": "approve"}}})[0]
    assert forged["isError"] and pe.call("vcf_get_plan", {"plan_id": plan["plan_id"]})[1]["approvals_recorded"] == 0


def test_a_destructive_change_needs_the_target_name_typed(pe):
    args = {"vm_id": "vm-101", "snapshot_id": "snap-1"}
    _, plan = pe.dry_run("vcf_delete_snapshot", args, _meta=FORM)
    first = ask(pe, args, plan["plan_id"], "vcf_delete_snapshot")
    props = first["inputRequests"]["approve_plan"]["params"]["requestedSchema"]["properties"]
    assert "vm-101" in props["confirm"]["title"]
    # wrong text: asked again (nothing approved), then the right text approves and runs
    res, again = answer(pe, args, plan["plan_id"], first, content={"decision": "approve", "confirm": "wrong"}, name="vcf_delete_snapshot")
    assert again is None and res["resultType"] == "input_required" and "did not match" in res["inputRequests"]["approve_plan"]["params"]["message"]
    assert pe.call("vcf_get_plan", {"plan_id": plan["plan_id"]})[1]["approvals_recorded"] == 0
    res, done = answer(pe, args, plan["plan_id"], res, content={"decision": "approve", "confirm": "vm-101"}, name="vcf_delete_snapshot")
    assert not res["isError"] and done["status"] == "SUCCESS"


def test_three_wrong_confirmations_end_the_attempt(pe):
    args = {"vm_id": "vm-101", "snapshot_id": "snap-1"}
    _, plan = pe.dry_run("vcf_delete_snapshot", args, _meta=FORM)
    state = ask(pe, args, plan["plan_id"], "vcf_delete_snapshot")
    for _ in range(2):
        state, _ = answer(pe, args, plan["plan_id"], state, content={"decision": "approve", "confirm": "nope"}, name="vcf_delete_snapshot")
        assert state["resultType"] == "input_required"
    res, _ = answer(pe, args, plan["plan_id"], state, content={"decision": "approve", "confirm": "nope"}, name="vcf_delete_snapshot")
    assert res["isError"] and "NOT APPROVED" in res["content"][0]["text"]


def test_no_single_target_means_the_plan_code_is_typed(pe):
    """A workflow plan over several resources has no single target name: the person types the plan's short code."""
    args = {"domain_id": "wld-app-a", "target_version": "9.1.1"}
    _, plan = pe.dry_run("vcf_upgrade_domain", args, _meta=FORM)
    first = ask(pe, args, plan["plan_id"], "vcf_upgrade_domain")
    props = first["inputRequests"]["approve_plan"]["params"]["requestedSchema"]["properties"]
    code = re.search(r"Plan code: (\w{6})", first["inputRequests"]["approve_plan"]["params"]["message"]).group(1)
    assert code in props["confirm"]["title"]
    res, done = answer(pe, args, plan["plan_id"], first, content={"decision": "approve", "confirm": code.lower()}, name="vcf_upgrade_domain")
    assert not res["isError"], done


# ---- approval on the local page -----------------------------------------------------------------------------------------

def get(url, **kw):
    try:
        r = urllib.request.urlopen(urllib.request.Request(url, **kw), timeout=10)
        return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def post(url, fields, origin=True):
    base = f"http://127.0.0.1:{urllib.parse.urlsplit(url).port}"
    return get(url, data=urllib.parse.urlencode(fields).encode(), method="POST", headers={"Origin": base} if origin else {})


def page_of(plan):
    url = plan["how_to_approve"]["approval_url"]
    code, html = get(url)
    assert code == 200
    return url, html, re.search(r"name=csrf value='([^']+)'", html).group(1)


def test_page_approval_then_plan_id_only_executes_once(pe):
    args, plan = pe.dry_run()
    url, html, csrf = page_of(plan)
    assert "vcf_power_vm" in html and "vm-101" in html and "Approve</button>" in html and "Reject</button>" in html and pe.user in html
    assert pe.call("vcf_get_plan", {"plan_id": plan["plan_id"]})[1]["ready_to_execute"] is False
    code, _ = post(url, {"csrf": csrf, "decision": "approve"})
    assert code == 200
    status = pe.call("vcf_get_plan", {"plan_id": plan["plan_id"]})[1]
    assert status["status"] == "APPROVED" and status["ready_to_execute"] is True and "nonce" not in status
    res, done = pe.call("vcf_power_vm", {**args, "plan_id": plan["plan_id"]})   # only plan_id: the server consumes the approval
    assert not res["isError"] and done["status"] == "SUCCESS"
    again = pe.call("vcf_power_vm", {**args, "plan_id": plan["plan_id"]})[0]     # exactly once
    assert again["isError"] and "already used" in again["content"][0]["text"]
    assert pe.call("vcf_get_plan", {"plan_id": plan["plan_id"]})[1]["status"] == "EXECUTED"
    rec = [a for a in pe.audit() if a["arguments"]["outcome"] == "APPROVED"][0]["arguments"]
    assert rec["channel"] == "page" and rec["mode"] == "personal" and rec["approver"] == pe.user


def test_page_reject_is_final(pe):
    args, plan = pe.dry_run()
    url, _, csrf = page_of(plan)
    assert post(url, {"csrf": csrf, "decision": "reject"})[0] == 200
    res, _ = pe.call("vcf_power_vm", {**args, "plan_id": plan["plan_id"]})
    assert res["isError"] and "rejected" in res["content"][0]["text"]
    assert get(url)[0] == 410 and pe.call("vcf_get_plan", {"plan_id": plan["plan_id"]})[1]["status"] == "REJECTED"


def test_page_token_csrf_origin_host_expiry_and_reuse(pe):
    args, plan = pe.dry_run()
    url, _, csrf = page_of(plan)
    port = urllib.parse.urlsplit(url).port
    assert get(f"http://127.0.0.1:{port}/approve/" + "A" * 43)[0] == 404                       # unguessable token: wrong one
    assert get(f"http://127.0.0.1:{port}/approve/../credential/x")[0] in (404, 421)
    assert post(url, {"csrf": "wrong", "decision": "approve"})[0] == 403                       # CSRF
    assert post(url, {"decision": "approve"})[0] == 403
    code, _ = get(url, data=urllib.parse.urlencode({"csrf": csrf, "decision": "approve"}).encode(), method="POST",
                  headers={"Origin": "http://evil.example"})
    assert code == 403                                                                          # cross-origin
    code, _ = get(url, headers={"Host": "evil.example"})
    assert code == 421                                                                          # DNS rebinding
    assert pe.call("vcf_get_plan", {"plan_id": plan["plan_id"]})[1]["approvals_recorded"] == 0
    assert post(url, {"csrf": csrf, "decision": "approve"})[0] == 200
    assert post(url, {"csrf": csrf, "decision": "approve"})[0] == 410                          # reused
    assert get(url)[0] == 410
    # expiry: a ticket past its time is refused
    args2, plan2 = pe.dry_run(args={"vm_id": "vm-102", "action": "stop"})
    url2, _, csrf2 = page_of(plan2)
    t = [t for t in list_approval_tickets(pe.home / "portal") if t.plan_id == plan2["plan_id"]][0]
    from vcf_enterprise_mcp.setup.credential_portal import write_approval_ticket
    t.expires_at = time.time() - 1
    write_approval_ticket(pe.home / "portal", t)
    assert post(url2, {"csrf": csrf2, "decision": "approve"})[0] == 410 and get(url2)[0] == 410


def test_page_destructive_needs_the_typed_target_and_locks_after_five_misses(pe):
    args = {"vm_id": "vm-101", "snapshot_id": "snap-1"}
    _, plan = pe.dry_run("vcf_delete_snapshot", args)
    url, html, csrf = page_of(plan)
    assert "name=confirm" in html and "vm-101" in html
    code, body = post(url, {"csrf": csrf, "decision": "approve", "confirm": "nope"})
    assert code == 400 and "did not match" in body
    assert pe.call("vcf_get_plan", {"plan_id": plan["plan_id"]})[1]["approvals_recorded"] == 0
    assert post(url, {"csrf": csrf, "decision": "approve", "confirm": "vm-101"})[0] == 200
    res, done = pe.call("vcf_delete_snapshot", {**args, "plan_id": plan["plan_id"]})
    assert not res["isError"] and done["status"] == "SUCCESS"
    _, plan2 = pe.dry_run("vcf_delete_snapshot", {"vm_id": "vm-102", "snapshot_id": "s"})
    url2, _, csrf2 = page_of(plan2)
    codes = [post(url2, {"csrf": csrf2, "decision": "approve", "confirm": "x"})[0] for _ in range(5)]
    assert codes == [400, 400, 400, 400, 403] and get(url2)[0] == 410


def test_a_page_ticket_is_tied_to_its_plan_arguments(pe):
    args, plan = pe.dry_run()
    url, _, csrf = page_of(plan)
    post(url, {"csrf": csrf, "decision": "approve"})
    res, _ = pe.call("vcf_power_vm", {**args, "action": "start", "plan_id": plan["plan_id"]})  # different arguments than the plan
    assert res["isError"] and "differ" in res["content"][0]["text"]
    assert not pe.call("vcf_power_vm", {**args, "plan_id": plan["plan_id"]})[0]["isError"]


# ---- approval in the person's own terminal ---------------------------------------------------------------------------------

def cli_env(pe):
    return {"PATH": os.environ.get("PATH", ""), "HOME": str(pe.tmp), "VCF_MCP_HOME": str(pe.home), "VCF_KMS_MASTER_SECRET": SECRET,
            "VCF_ENTERPRISE_MCP_CONFIG": str(pe.cfg_file), "PYTHONPATH": os.path.abspath("src")}


def run_in_pty(pe, plan_id, typed):
    import pty
    import select
    master, slave = pty.openpty()
    p = subprocess.Popen([sys.executable, "-m", "vcf_enterprise_mcp.cli", "plans", "approve", plan_id, "--db", pe.db],
                         stdin=slave, stdout=slave, stderr=slave, env=cli_env(pe), close_fds=True)
    os.close(slave)
    out, pending = "", list(typed)
    deadline = time.time() + 30
    while time.time() < deadline:
        if select.select([master], [], [], 0.2)[0]:
            try:
                chunk = os.read(master, 4096).decode(errors="replace")
            except OSError:
                break
            if not chunk:
                break
            out += chunk
        if pending and out.rstrip().endswith((":",)) and re.search(r"(cancels\)|confirm): $", out.replace("\r", "")):
            first = pending.pop(0)
            text = first(out) if callable(first) else first
            os.write(master, (text + "\n").encode())
            out += "\n"
        if p.poll() is not None and not select.select([master], [], [], 0.2)[0]:
            break
    p.wait(timeout=20)
    os.close(master)
    return p.returncode, out.replace("\r", "")


def code_on_screen(out):
    return re.search(r"Plan code: (\w{6})", out).group(1)


def test_cli_refuses_a_non_interactive_shell_such_as_an_assistants_tool(pe):
    _, plan = pe.dry_run()
    try:
        p = subprocess.run([sys.executable, "-m", "vcf_enterprise_mcp.cli", "plans", "approve", plan["plan_id"], "--db", pe.db],
                           capture_output=True, text=True, env=cli_env(pe), stdin=subprocess.DEVNULL, timeout=60)
        assert p.returncode == 1
        assert "approve in your own terminal, in the chat prompt, or at http://127.0.0.1:" in p.stderr
        assert pe.call("vcf_get_plan", {"plan_id": plan["plan_id"]})[1]["approvals_recorded"] == 0
    finally:
        try:
            os.kill(int((pe.home / "portal" / "service.pid").read_text()), 15)
        except (OSError, ValueError):
            pass


def test_cli_in_a_real_terminal_with_the_right_code_approves_and_the_model_then_executes(pe):
    args, plan = pe.dry_run()
    rc, out = run_in_pty(pe, plan["plan_id"], [lambda screen: code_on_screen(screen)])
    assert rc == 0, out
    assert "vcf_power_vm" in out and "vm-101" in out and "approved by" in out and "approval_id" not in out and "nonce" not in out
    status = pe.call("vcf_get_plan", {"plan_id": plan["plan_id"]})[1]
    assert status["ready_to_execute"] is True and status["approvers"] == [pe.user]
    res, done = pe.call("vcf_power_vm", {**args, "plan_id": plan["plan_id"]})
    assert not res["isError"] and done["status"] == "SUCCESS"
    rec = [a for a in pe.audit() if a["arguments"]["outcome"] == "APPROVED"][0]["arguments"]
    assert rec["channel"] == "cli" and rec["mode"] == "personal"


def test_cli_with_a_wrong_code_refuses(pe):
    _, plan = pe.dry_run()
    rc, out = run_in_pty(pe, plan["plan_id"], ["ZZZZZZ"])
    assert rc == 1 and "code did not match" in out
    assert pe.call("vcf_get_plan", {"plan_id": plan["plan_id"]})[1]["approvals_recorded"] == 0


def test_cli_destructive_asks_for_the_target_name_too(pe):
    args = {"vm_id": "vm-101", "snapshot_id": "snap-1"}
    _, plan = pe.dry_run("vcf_delete_snapshot", args)
    rc, out = run_in_pty(pe, plan["plan_id"], [lambda s: code_on_screen(s), "not-the-vm"])
    assert rc == 1 and "did not match the target" in out
    rc, out = run_in_pty(pe, plan["plan_id"], [lambda s: code_on_screen(s), "vm-101"])
    assert rc == 0, out


def test_team_mode_cli_still_needs_the_approvers_own_token(tmp_path, monkeypatch, capsys):
    from vcf_enterprise_mcp.cli import main
    e = Env(tmp_path, monkeypatch, "server: {mode: stdio}\nidp: {allow_lab_tokens: true}\n")  # no access_mode key = team
    monkeypatch.delenv("VCF_MCP_APPROVER_TOKEN", raising=False)
    assert e.engine.personal_principal is None
    plan = e.engine.plan_manager.create_dry_run_plan(
        __import__("vcf_enterprise_mcp.auth.identity", fromlist=["Principal"]).Principal(user_id="a@b"), "vcf_upgrade_domain",
        {"domain_id": "d"}, {}, ["d"], RiskClass.HIGH_IMPACT)
    assert main(["plans", "approve", plan["plan_id"], "--db", e.db]) == 1
    assert "VCF_MCP_APPROVER_TOKEN" in capsys.readouterr().err
    assert "approval_url" not in plan["how_to_approve"] and "approver_must_differ_from" in plan["how_to_approve"]


# ---- the rest of the contract ----------------------------------------------------------------------------------------------------

def test_setup_never_needs_an_approval(pe):
    res = pe.rpc("tools/call", {"name": "vcf_setup", "arguments": {}})["result"]
    assert not res.get("isError") and "NEEDS_INPUT" in res["content"][0]["text"]
    assert pe.rpc("tools/call", {"name": "vcf_setup", "arguments": {}, "_meta": FORM})["result"]["resultType"] == "input_required"
    assert pe.store.list_execution_plans("tenant-default", "env-prod") == []  # no plan, no approval: setup is handled by the protocol
    risk = EnterpriseMCPProtocolEngine.SETUP_TOOL_DEFINITIONS[0]["_enterprise_meta"]
    assert risk["control_plane_setup"] and "plan_id" not in json.dumps(EnterpriseMCPProtocolEngine.SETUP_TOOL_DEFINITIONS[0]["inputSchema"])


def test_enterprise_plans_approve_rpc_is_refused_in_personal_mode(pe):
    _, plan = pe.dry_run()
    out = pe.rpc("enterprise/plans/approve", {"plan_id": plan["plan_id"]})
    assert "error" in out and "approves plans themselves" in out["error"]["message"]


def test_vcf_get_plan_is_in_the_catalog_find_tool_and_write_skills(pe):
    from vcf_enterprise_mcp.router.catalog import get_tool_card_by_name
    from vcf_enterprise_mcp.skills.registry import get_skill_registry
    from vcf_enterprise_mcp.tools.find_tool import rank
    assert get_tool_card_by_name("vcf_get_plan").risk_class == RiskClass.READ
    assert rank("has the plan been approved yet")[0]["tool"] == "vcf_get_plan"
    assert rank("what is the plan status")[0]["tool"] == "vcf_get_plan"
    skill = get_skill_registry().get_skill("vcf-compute-vm-power-cycle")
    assert "vcf_get_plan" in skill.allowed_tools and "plan_id` only" in skill.to_skill_markdown()
    assert "vcf_get_plan" not in get_skill_registry().get_skill("vcf-viewer-inventory-summary").allowed_tools


def test_idempotent_retry_of_a_finished_call_does_not_ask_again(pe):
    args, plan = pe.dry_run(args={"vm_id": "vm-101", "action": "stop", "idempotency_key": "k1"})
    url, _, csrf = page_of(plan)
    post(url, {"csrf": csrf, "decision": "approve"})
    first = pe.call("vcf_power_vm", {**args, "plan_id": plan["plan_id"]})
    assert not first[0]["isError"]
    second = pe.call("vcf_power_vm", {**args, "plan_id": plan["plan_id"]}, _meta=FORM)
    assert second[0].get("resultType") != "input_required" and not second[0]["isError"]


def test_team_get_plan_hands_the_initiator_the_approval_after_a_different_person_approves(tmp_path, monkeypatch):
    """README 'No plan-status tool' limitation: the initiator can read the approval via vcf_get_plan (team mode)."""
    from tests.fixtures.test_tokens import ADMIN_BEARER
    from vcf_enterprise_mcp.auth.identity import Principal
    e = Env(tmp_path, monkeypatch, "idp: {allow_lab_tokens: true}\n")
    e.engine.pep.pdp.config.operating_mode = "FULL_ENFORCEMENT"
    initiator = e.engine.idp.validate_bearer_token(ADMIN_BEARER)
    req = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "vcf_upgrade_domain", "arguments": {"domain_id": "wld-app-a", "target_version": "9.1.1", "dry_run": True}}}
    plan = json.loads(asyncio.run(e.engine.handle_jsonrpc_request(req, auth_header=ADMIN_BEARER))["result"]["content"][0]["text"])
    get_plan = lambda: json.loads(asyncio.run(e.engine.handle_jsonrpc_request(
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "vcf_get_plan", "arguments": {"plan_id": plan["plan_id"]}}},
        auth_header=ADMIN_BEARER))["result"]["content"][0]["text"])
    before = get_plan()
    assert before["approval_mode"] == "team" and not before["ready_to_execute"] and "approver_must_differ_from" in before["how_to_approve"]
    bob = Principal(user_id="bob@corp.com", roles=("VCF_PLATFORM_ADMIN",), corporate_groups=["VCF-Platform-Admins"])
    e.engine.plan_manager.approve_plan(plan["plan_id"], bob)
    after = get_plan()
    assert after["ready_to_execute"] and after["approval_id"].startswith("appr_") and after["nonce"]
    assert initiator.user_id != "bob@corp.com"
