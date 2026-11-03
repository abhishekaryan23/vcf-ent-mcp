# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Classic MCP elicitation over real stdio, with the official MCP Python SDK ClientSession.

Today's clients (Claude Code, LM Studio, the SDK) declare `capabilities.elicitation` in `initialize` and answer an
`elicitation/create` request that the SERVER sends while a tools/call is pending. The stdio transport adapts the engine's
2026-07-28 input_required results to that flow (core/server.py, StdioSession). These tests drive a real server process:
full guided setup (form answers, URL-mode password pages submitted like a browser, safety form, COMPLETE) against mock
appliances, in-client approval in personal mode (accept / reject), and the plain-data fallback for a client without elicitation.
Skipped when the `mcp` SDK is not installed.
"""

import json
import os
import re
import sys
import textwrap
import urllib.parse
import urllib.request

import pytest

mcp = pytest.importorskip("mcp")
from mcp import ClientSession, StdioServerParameters, types  # noqa: E402
from mcp.client.stdio import stdio_client  # noqa: E402

REPO = os.path.abspath(".")
PASSWORD = "Lab-Only-Test-Value-7f3a"
ENDPOINTS = {"vcenter": "https://vcenter.corp.internal", "sddc_manager": "https://sddc-manager.corp.internal",
             "nsx": "https://nsx.corp.internal", "vcf_operations": "https://vcf-ops.corp.internal"}

LAUNCHER = textwrap.dedent('''
    import sys
    sys.path.insert(0, {repo!r})
    if {mock!r}:
        from tests.test_guided_setup import fake_vcf
        from vcf_enterprise_mcp.adapter.transport.http import HTTPTransport
        from vcf_enterprise_mcp.setup.wizard import SetupWizard
        SetupWizard._default_transport = lambda self, hosts: HTTPTransport(mock_handler=fake_vcf([]), max_retries=0)
    from vcf_enterprise_mcp.core.server import main
    main()
''')


def server(tmp_path, config, mock=False, token=None):
    cfg = tmp_path / "config.yaml"
    cfg.write_text(config)
    launcher = tmp_path / "launch.py"
    launcher.write_text(LAUNCHER.format(repo=REPO, mock=mock))
    env = {"HOME": str(tmp_path), "PATH": os.environ.get("PATH", ""), "VCF_ENTERPRISE_MCP_CONFIG": str(cfg), "VCF_MCP_HOME": str(tmp_path / "state"),
           "VCF_MCP_DB_PATH": str(tmp_path / "cp.db"), "VCF_MCP_CREDENTIALS_PATH": str(tmp_path / "creds.json"),
           "VCF_MCP_MASTER_KEY_PATH": str(tmp_path / "master.key"), "VCF_MCP_KMS_KEY_PATH": str(tmp_path / "kms.key"),
           "VCF_MCP_LAB_JWT_KEY_PATH": str(tmp_path / "jwt.pem"),
           "PYTHONPATH": os.pathsep.join([os.path.abspath("src"), REPO])}
    return StdioServerParameters(command=sys.executable, args=[str(launcher)], env=env, cwd=str(tmp_path))


def text_of(res):
    return res.content[0].text


def browser_submit(url, password=PASSWORD):
    page = urllib.request.urlopen(url, timeout=10).read().decode()
    csrf = re.search(r"name=csrf value='([^']+)'", page).group(1)
    data = urllib.parse.urlencode({"csrf": csrf, "secret": password}).encode()
    return urllib.request.urlopen(urllib.request.Request(url, data=data, method="POST"), timeout=10).status


def kill_portal(tmp_path):
    try:
        os.kill(int((tmp_path / "state" / "portal" / "service.pid").read_text()), 15)
    except (OSError, ValueError):
        pass


PERSONAL_SETUP = "server: {mode: stdio, access_mode: personal}\npolicy: {operating_mode: DISCOVERY_ONLY}\n"
PERSONAL_OPS = ("server: {mode: stdio, environment: testing, storage_mode: LOCAL_LAB, access_mode: personal}\n"
                "policy: {operating_mode: AUDITED_OPERATIONS}\n")


@pytest.mark.anyio
async def test_full_guided_setup_over_classic_elicitation(tmp_path):
    """Form answers, one URL-mode password page per appliance, safety form, COMPLETE; no token, no MRTR."""
    import asyncio
    log = []
    completed = {}  # elicitation id -> event set by notifications/elicitation/complete
    background, waited = [], []

    async def on_message(message):
        note = getattr(message, "root", message)
        if isinstance(note, types.ElicitCompleteNotification):
            completed.setdefault(note.params.elicitation_id, asyncio.Event()).set()

    async def on_elicit(ctx, params):
        if isinstance(params, types.ElicitRequestURLParams):
            assert params.url.startswith("http://127.0.0.1:") and params.elicitation_id
            log.append(("url", params.url.split("/")[-2]))
            # Like Claude Code: answer "accept" when the page is opened, then wait for the server's notice that it is done.
            done = completed.setdefault(params.elicitation_id, asyncio.Event())
            async def person_fills_the_page():
                await asyncio.sleep(0.3)
                assert await asyncio.to_thread(browser_submit, params.url) == 200  # typed in the browser, never in chat
                await asyncio.wait_for(done.wait(), timeout=15)
                waited.append(params.elicitation_id)
            background.append(asyncio.ensure_future(person_fills_the_page()))
            return types.ElicitResult(action="accept")
        props = params.requested_schema["properties"]
        log.append(("form", sorted(props)))
        assert not any("pass" in k for k in props), "forms never ask for passwords"
        if "goals" in props:
            return types.ElicitResult(action="accept", content={"target": "lab", "goals": ["monitor", "vm_operations"]})
        if "vcenter_url" in props:
            content = {}
            for comp, url in ENDPOINTS.items():
                content[f"{comp}_url"] = url
                content[f"{comp}_username"] = {"vcenter": "administrator@vsphere.local", "sddc_manager": "admin@local"}.get(comp, "admin")
            return types.ElicitResult(action="accept", content=content)
        if "read_only" in props:  # the safety form: accept the suggested defaults
            return types.ElicitResult(action="accept", content={**{k: v["default"] for k, v in props.items() if k != "read_only"}, "read_only": False})
        raise AssertionError(f"unexpected form {sorted(props)}")

    try:
        async with stdio_client(server(tmp_path, PERSONAL_SETUP, mock=True)) as (read, write):
            async with ClientSession(read, write, elicitation_callback=on_elicit, message_handler=on_message) as session:
                init = await session.initialize()
                assert "ACCESS MODE personal" in init.instructions and "AUTHENTICATION PROBLEM" not in init.instructions
                assert {"vcf_setup", "vcf_access_report", "vcf_get_plan"} - {t.name for t in (await session.list_tools()).tools} == {"vcf_get_plan"}
                res = await session.call_tool("vcf_setup", {}, read_timeout_seconds=120.0)
                assert not res.is_error, text_of(res)
                done = json.loads(text_of(res))
                assert done["status"] == "COMPLETE" and done["reloaded"] is True
                assert PASSWORD not in text_of(res)
                await asyncio.gather(*background)
                assert len(waited) == 4  # every page was confirmed complete by the server
                kinds = [k for k, _ in log]
                assert kinds.count("url") == 4 and kinds.count("form") == 3 and kinds[0] == "form"  # goals, environment, 4 passwords, safety
                names = {t.name for t in (await session.list_tools()).tools}
                assert "vcf_list_vms" in names  # the server applied the new endpoints without a restart
    finally:
        kill_portal(tmp_path)
    import yaml
    cfg = yaml.safe_load((tmp_path / "config.yaml").read_text())
    assert cfg["vcf"]["vcenter_url"] == ENDPOINTS["vcenter"]
    assert cfg["server"]["personal_roles"] == ["MCP_ADMIN", "VCF_VIEWER", "COMPUTE_ADMIN"]  # narrowed to the chosen goals
    assert PASSWORD not in (tmp_path / "config.yaml").read_text()


@pytest.mark.anyio
async def test_a_client_without_elicitation_gets_the_plain_data_fallback(tmp_path):
    try:
        async with stdio_client(server(tmp_path, PERSONAL_SETUP)) as (read, write):
            async with ClientSession(read, write) as session:  # no elicitation_callback: nothing declared at initialize
                await session.initialize()
                res = await session.call_tool("vcf_setup", {})
                body = json.loads(text_of(res))
                assert body["status"] == "NEEDS_INPUT" and body["resume"] and body["questions"]
    finally:
        kill_portal(tmp_path)


@pytest.mark.anyio
async def test_a_client_that_errors_on_elicitation_create_falls_back_to_plain_data(tmp_path):
    async def refuse(ctx, params):
        return types.ErrorData(code=-32601, message="not supported")

    async with stdio_client(server(tmp_path, PERSONAL_SETUP)) as (read, write):
        async with ClientSession(read, write, elicitation_callback=refuse) as session:
            await session.initialize()
            body = json.loads(text_of(await session.call_tool("vcf_setup", {})))
            assert body["status"] == "NEEDS_INPUT"


async def approval_flow(session, args=None):
    args = args or {"vm_id": "vm-101", "action": "stop"}
    dry = json.loads(text_of(await session.call_tool("vcf_power_vm", {**args, "dry_run": True})))
    return args, dry


@pytest.mark.anyio
async def test_personal_mode_in_client_approval_accept_runs_the_change(tmp_path):
    prompts = []

    async def approve(ctx, params):
        prompts.append(params.message)
        assert params.requested_schema["properties"]["decision"]
        return types.ElicitResult(action="accept", content={"decision": "approve"})

    async with stdio_client(server(tmp_path, PERSONAL_OPS)) as (read, write):
        async with ClientSession(read, write, elicitation_callback=approve) as session:
            await session.initialize()
            args, dry = await approval_flow(session)
            assert "approval_url" not in dry["how_to_approve"]  # the chat prompt is the channel for this client
            res = await session.call_tool("vcf_power_vm", {**args, "plan_id": dry["plan_id"]})
            assert not res.is_error, text_of(res)
            assert json.loads(text_of(res))["new_power_state"] == "POWERED_OFF"
            assert len(prompts) == 1 and "vcf_power_vm" in prompts[0] and "vm-101" in prompts[0]
            status = json.loads(text_of(await session.call_tool("vcf_get_plan", {"plan_id": dry["plan_id"]})))
            assert status["status"] == "EXECUTED"


@pytest.mark.anyio
async def test_personal_mode_in_client_approval_reject_and_decline(tmp_path):
    answers = iter([types.ElicitResult(action="accept", content={"decision": "reject"}), types.ElicitResult(action="decline")])

    async def no(ctx, params):
        return next(answers)

    async with stdio_client(server(tmp_path, PERSONAL_OPS)) as (read, write):
        async with ClientSession(read, write, elicitation_callback=no) as session:
            await session.initialize()
            for _ in range(2):
                args, dry = await approval_flow(session)
                res = await session.call_tool("vcf_power_vm", {**args, "plan_id": dry["plan_id"]})
                assert res.is_error and "NOT APPROVED" in text_of(res)
                status = json.loads(text_of(await session.call_tool("vcf_get_plan", {"plan_id": dry["plan_id"]})))
                assert status["ready_to_execute"] is False


@pytest.mark.anyio
async def test_personal_mode_without_elicitation_gives_the_page_and_the_model_continues_with_plan_id_only(tmp_path):
    try:
        async with stdio_client(server(tmp_path, PERSONAL_OPS)) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                args, dry = await approval_flow(session)
                url = dry["how_to_approve"]["approval_url"]
                pending = await session.call_tool("vcf_power_vm", {**args, "plan_id": dry["plan_id"]})
                assert pending.is_error and url in text_of(pending)
                import asyncio

                def approve_in_browser():
                    page = urllib.request.urlopen(url, timeout=10).read().decode()
                    csrf = re.search(r"name=csrf value='([^']+)'", page).group(1)
                    data = urllib.parse.urlencode({"csrf": csrf, "decision": "approve"}).encode()
                    return urllib.request.urlopen(urllib.request.Request(url, data=data, method="POST"), timeout=10).status
                assert await asyncio.to_thread(approve_in_browser) == 200
                res = await session.call_tool("vcf_power_vm", {**args, "plan_id": dry["plan_id"]})
                assert not res.is_error and json.loads(text_of(res))["status"] == "SUCCESS"
    finally:
        kill_portal(tmp_path)


@pytest.mark.anyio
async def test_other_requests_are_served_while_a_prompt_waits_for_the_person(tmp_path):
    import anyio
    release = anyio.Event()

    async def slow(ctx, params):
        await release.wait()  # the person is still reading the prompt
        return types.ElicitResult(action="accept", content={"decision": "approve"})

    async with stdio_client(server(tmp_path, PERSONAL_OPS)) as (read, write):
        async with ClientSession(read, write, elicitation_callback=slow) as session:
            await session.initialize()
            args, dry = await approval_flow(session)
            results = {}

            async def run_call():
                results["call"] = await session.call_tool("vcf_power_vm", {**args, "plan_id": dry["plan_id"]})
            async with anyio.create_task_group() as tg:
                tg.start_soon(run_call)
                await anyio.sleep(1.5)
                with anyio.fail_after(10):  # would deadlock if the server blocked on the pending prompt
                    assert (await session.list_tools()).tools
                    await session.send_ping()
                assert "call" not in results
                release.set()
            assert not results["call"].is_error
