# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""Plan revision probes: only real infrastructure ids are probed, with real credentials, never on an invented host."""

import asyncio

from tests.orch_sim_support import make_sim
from vcf_enterprise_mcp.adapter.capability_provider import CapabilityProviderRegistry
from vcf_enterprise_mcp.adapter.platform import PlatformClient, PlatformMode
from vcf_enterprise_mcp.adapter.transport.base import BaseTransport, TransportResponse
from vcf_enterprise_mcp.auth.identity import Principal
from vcf_enterprise_mcp.policy.engine import PolicyDecisionPoint
from vcf_enterprise_mcp.policy.enforcement import PolicyEnforcementPoint
from vcf_enterprise_mcp.config.settings import PolicyConfig
from vcf_enterprise_mcp.state.sqlite_store import SQLiteDurableStore
from vcf_enterprise_mcp.tools.orchestrator_tools import VCFOrchSaveWorkflowTool
from vcf_enterprise_mcp.workflows.execution_plans import ExecutionPlanManager

SPEC = {"name": "Probe test", "description": "x", "inputs": [], "outputs": [], "variables": [],
        "steps": [{"id": "s", "type": "script", "script": "System.log('hi');"}]}


def _principal(user, role):
    return Principal(user_id=user, roles=(role,), allowed_domains=["*"], allowed_clusters=["*"])


def test_orchestrator_write_dry_run_and_execution_make_no_vcenter_vm_request(tmp_path):
    sim, transport, plat = make_sim(tmp_path)
    platform = PlatformClient(mode=PlatformMode.REAL_VCF, transport=transport)
    platform.orchestrator = plat.orchestrator
    platform.resolve_secret = plat.resolve_secret
    store = SQLiteDurableStore(str(tmp_path / "cp.db"))
    pdp = PolicyDecisionPoint(config=PolicyConfig(operating_mode="AUDITED_OPERATIONS"), durable_store=store)
    mgr = ExecutionPlanManager(durable_store=store, platform_client=platform)
    tool = VCFOrchSaveWorkflowTool(pep=PolicyEnforcementPoint(pdp=pdp), durable_store=store, plan_manager=mgr, platform_client=platform)
    me = _principal("alice@lab", "AUTOMATION_OPERATOR")
    args = {"workflow": SPEC, "category": "MCP-Managed/Probe"}

    plan = asyncio.run(tool.execute(me, {**args, "dry_run": True}))
    stored = store.get_execution_plan("tenant-default", "env-prod", plan["plan_id"])
    assert stored["resource_revisions"] == {}  # no infrastructure target: nothing to probe
    signed = mgr.approve_plan(plan["plan_id"], _principal("bob@lab", "VCF_PLATFORM_ADMIN"))
    done = asyncio.run(tool.execute(me, {**args, "plan_id": plan["plan_id"], "approval_id": signed.approval_id, "nonce": signed.nonce}))
    assert not done.get("error")
    assert transport.calls(contains="/api/vcenter/vm/") == []


class _Recorder(BaseTransport):
    def __init__(self):
        self.requests = []

    def send(self, request):
        self.requests.append(request)
        return TransportResponse(status_code=200, headers={}, body=b'{"power_state":"POWERED_ON","memory_size_MiB":1024,"cpu":{"count":2}}')

    async def send_async(self, request):
        return self.send(request)


class _SessionAuth:
    def apply(self, request):
        request.headers["Cookie"] = "vmware-api-session-id=abc"
        return request

    def invalidate(self):
        pass


def test_vm_revision_probe_is_authenticated_and_uses_the_configured_vcenter():
    rec = _Recorder()
    registry = CapabilityProviderRegistry.create_for_components(version="9.1.1", sddc_url=None, vc_url="https://vc.lab.example", nsx_url=None, ops_url=None)
    platform = PlatformClient(registry=registry, mode=PlatformMode.REAL_VCF, transport=rec, component_auth={"vcenter": _SessionAuth()})
    rev = platform.get_resource_revision("vm-101")
    assert str(rev.value).startswith("rev-POWERED_ON")
    assert rec.requests and rec.requests[0].url == "https://vc.lab.example/api/vcenter/vm/vm-101"
    assert rec.requests[0].headers.get("Cookie") == "vmware-api-session-id=abc"


def test_no_known_vcenter_means_no_network_call_and_no_invented_host():
    rec = _Recorder()
    platform = PlatformClient(registry=CapabilityProviderRegistry(), mode=PlatformMode.REAL_VCF, transport=rec)
    assert platform.get_resource_revision("vcf_orch_save_workflow").value
    assert platform.get_resource_revision("vm-101").value
    assert rec.requests == []
