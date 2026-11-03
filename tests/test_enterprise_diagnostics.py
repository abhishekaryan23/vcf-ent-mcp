# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""Workload/network root-cause rules (diagnostics/deep.py), VCF Automation auth, multi-line arguments."""

import datetime as dt
import urllib.parse

import pytest

from vcf_enterprise_mcp.adapter.transport.base import TransportResponse
from vcf_enterprise_mcp.adapter.transport.vcf_sessions import VCFAutomationTokenAuth
from vcf_enterprise_mcp.core.errors import InvalidArgumentException
from vcf_enterprise_mcp.core.schema_validator import validate_tool_arguments
from vcf_enterprise_mcp.diagnostics import deep
from vcf_enterprise_mcp.diagnostics.engine import Evidence, correlate

NOW = dt.datetime(2026, 10, 27, 12, 0, tzinfo=dt.timezone.utc)


def ev(i, component, target, check, status, summary, **detail):
    return Evidence(f"E{i}", component, target, check, status, summary, "", detail)


def vm(name, role, app, forest="fin.nwg.local", host="esx01", cluster=None, nics=None):
    tags = {"Role": role, "Application": app, "AD-Forest": forest, **({"Cluster": cluster} if cluster else {})}
    return {"name": name, "tags": tags, "host": host, "power_state": "POWERED_ON", "nics": nics or [], "domain": "wld-fin", "vcenter": "vc"}


def test_all_bgp_neighbors_down_is_critical_north_south_outage():
    items = [ev(1, "nsx", "t0-fin/10.60.0.1", "bgp_neighbor", "FAIL", "down", nsx="nsx-fin", tier0="t0-fin", neighbor="10.60.0.1",
                peer="fw-fin-a (Cisco FTD)", state="ACTIVE"),
             ev(2, "nsx", "t0-fin/10.60.0.2", "bgp_neighbor", "FAIL", "down", nsx="nsx-fin", tier0="t0-fin", neighbor="10.60.0.2",
                peer="fw-fin-b (Cisco FTD)", state="IDLE")]
    top = correlate(items, symptom="branches cannot reach payments", inventory={})["findings"][0]
    assert top["severity"] == "CRITICAL" and "t0-fin" in top["title"] and "fw-fin-a" in top["cause"]


def test_one_bgp_neighbor_down_is_redundancy_loss_only():
    items = [ev(1, "nsx", "a", "bgp_neighbor", "FAIL", "down", nsx="n", tier0="t0", neighbor="a", peer="p", state="ACTIVE"),
             ev(2, "nsx", "b", "bgp_neighbor", "OK", "up", nsx="n", tier0="t0", neighbor="b", peer="p", state="ESTABLISHED")]
    top = correlate(items, inventory={})["findings"][0]
    assert top["severity"] == "HIGH" and "degraded" in top["title"]


def test_recent_dfw_drop_outranks_generic_alerts():
    items = [ev(1, "nsx", "temp-block", "dfw_recent_block", "WARN", "rule changed", rule="temp-block", action="DROP", services=["MS-SQL 1433"],
                destinations=["grp-crm-db"], sources=["any"], changed_by="m.lee", changed_minutes_ago=35, policy="CRM",
                destination_vms=["sql01"]),
             ev(2, "vcf_operations", "web02", "alert", "FAIL", "Guest file system is running out of space")]
    inv = {"vms": [vm("sql01", "sql-ag-replica", "CRM")]}
    top = correlate(items, symptom="CRM database connection errors", inventory=inv)["findings"][0]
    assert "temp-block" in top["title"] and "CRM" in top["impact"]


def test_all_domain_controllers_of_a_forest_unreachable():
    inv = {"vms": [vm("fin-dc01", "domain-controller", "AD-FIN"), vm("fin-dc02", "domain-controller", "AD-FIN")]}
    items = [ev(1, "vcenter", "fin-dc01", "vm_power", "FAIL", "off", role="domain-controller", forest="fin.nwg.local"),
             ev(2, "vcenter", "fin-dc02", "vm_nic", "FAIL", "nic disconnected", role="domain-controller", forest="fin.nwg.local")]
    top = correlate(items, inventory=inv)["findings"][0]
    assert top["severity"] == "CRITICAL" and top["title"].startswith("No reachable domain controller for AD forest fin.nwg.local")


def test_clustered_nodes_on_failed_host():
    items = [ev(1, "vcenter", "FCI-LEDGER", "cluster_colocation", "WARN", "nodes share host", host="esx03", nodes=["n1", "n2"]),
             ev(2, "vcenter", "esx03", "host_connection", "FAIL", "ESXi host esx03 in vCenter vc is NOT_RESPONDING.", vcenter="vc")]
    titles = [f["title"] for f in correlate(items, symptom="Ledger cannot connect to SQL", inventory={})["findings"]]
    assert titles[0].startswith("All nodes of FCI-LEDGER were on failed host esx03")


def test_tier1_without_tier0_lists_affected_vms():
    inv = {"vms": [vm("proxy01", "squid-proxy", "WebProxy", nics=[{"network": "seg-dmz", "state": "CONNECTED"}])]}
    items = [ev(1, "nsx", "t1-dmz", "t1_uplink", "FAIL", "no tier0", segments=["seg-dmz"], changed_by="contractor")]
    top = correlate(items, inventory=inv)["findings"][0]
    assert "t1-dmz" in top["title"] and "proxy01" in top["impact"]


def test_dfw_collection_flags_only_recent_blocking_rules():
    class C:
        now = NOW
        items = []
        inventory = {}

        def add(self, *a, **k):
            self.items.append((a, k))

        def _get(self, prov, path, params=None):
            ms_now = NOW.timestamp() * 1000
            if path.endswith("/security-policies"):
                return {"results": [{"id": "p1", "display_name": "CRM"}]}
            if path.endswith("/p1/rules"):
                return {"results": [
                    {"id": "old", "action": "DROP", "_last_modified_time": ms_now - 90 * 86400000, "source_groups": ["ANY"],
                     "destination_groups": ["ANY"], "services": ["ANY"]},
                    {"id": "new", "action": "REJECT", "_last_modified_time": ms_now - 30 * 60000, "_last_modified_user": "u",
                     "source_groups": ["/infra/domains/default/groups/a"], "destination_groups": ["/infra/domains/default/groups/b"],
                     "services": ["/infra/services/Oracle"]},
                    {"id": "allow", "action": "ALLOW", "_last_modified_time": ms_now, "source_groups": ["ANY"], "destination_groups": ["ANY"],
                     "services": ["ANY"]}]}
            return {"results": []}

    c = C()
    deep.collect_nsx_policy(c, None, "nsx01")
    flagged = [k for a, k in c.items if a[2] == "dfw_recent_block"]
    assert [f["rule_id"] for f in flagged] == ["new"] and flagged[0]["services"] == ["Oracle 1521"]


def test_automation_token_exchange_sends_only_the_api_token():
    sent = {}

    class T:
        def send(self, req):
            sent["url"], sent["body"], sent["ct"] = req.url, req.data.decode(), req.headers["Content-Type"]
            return TransportResponse(status_code=200, body=b'{"access_token": "abc", "expires_in": 3600}')

    auth = VCFAutomationTokenAuth("https://vcfa.lab", T(), lambda: ("svc", "api-token-1"), tenant="northwind")
    assert auth._header(auth._current_token()) == ("Authorization", "Bearer abc")
    assert sent["url"] == "https://vcfa.lab/oauth/tenant/northwind/token" and "x-www-form-urlencoded" in sent["ct"]
    assert urllib.parse.parse_qs(sent["body"]) == {"grant_type": ["refresh_token"], "refresh_token": ["api-token-1"]}


def test_multiline_only_where_schema_allows_it():
    schema = {"type": "object", "properties": {"content": {"type": "string", "maxLength": 1000, "x-multiline": True},
                                               "name": {"type": "string"}}}
    validate_tool_arguments("t", {"content": "formatVersion: 1\nresources:\n\tvm: {}"}, schema)
    with pytest.raises(InvalidArgumentException):
        validate_tool_arguments("t", {"name": "a\nb"}, schema)
