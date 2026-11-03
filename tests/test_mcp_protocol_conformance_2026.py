# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Test Suite: MCP 2026-07-28 Protocol Conformance & Wire Behavior.
Validates:
- Header agreement validation (Mcp-Method, Mcp-Name, Mcp-Param-*)
- W3C Trace Context propagation
- tools/list with cacheScope=private, short TTL, and permission epoch
- tasks/list deliberately omitted (-32601 Method not found)
- tasks/get, tasks/update, tasks/cancel with unguessable IDs and caller authorization
- subscriptions/listen notification support
"""

import unittest
import asyncio
import os
import sys

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC_DIR = os.path.join(BASE_DIR, "src")
sys.path.insert(0, SRC_DIR)
sys.path.insert(0, BASE_DIR)

from vcf_enterprise_mcp.core.protocol import EnterpriseMCPProtocolEngine
from vcf_enterprise_mcp.core.errors import HeaderMismatchException, AuthorizationDeniedException
from vcf_enterprise_mcp.auth.identity import Principal
from vcf_enterprise_mcp.state.durable_store import DurableStore
from vcf_enterprise_mcp.workflows.task_store import TaskStore, WorkflowStep


class TestMCPProtocolConformance2026(unittest.TestCase):

    def setUp(self):
        self.durable = DurableStore(":memory:")
        self.task_store = TaskStore(durable_store=self.durable)
        self.engine = EnterpriseMCPProtocolEngine(task_store=self.task_store)
        from tests.fixtures.test_tokens import ADMIN_BEARER, ALICE_BEARER, BOB_BEARER
        self.admin_auth = ADMIN_BEARER
        self.alice_auth = ALICE_BEARER
        self.bob_auth = BOB_BEARER

    def test_initialize_handshake_with_mcp_2026_and_w3c_trace(self):
        req = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        headers = {"traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"}
        req["params"]["_meta"] = {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}
        headers.update({"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": req["method"]})
        res = asyncio.run(self.engine.handle_jsonrpc_request(req, auth_header=self.admin_auth, headers=headers))

        self.assertNotIn("error", res)
        result = res["result"]
        self.assertEqual(result["protocolVersion"], "2026-07-28")
        # Spec shape: capability flags are objects (strict clients such as LM Studio reject booleans).
        self.assertEqual(result["capabilities"]["tasks"]["cancel"], {})
        self.assertEqual(result["capabilities"]["tasks"]["requests"], {"tools": {"call": {}}})
        self.assertEqual(result["traceContext"]["traceId"], "4bf92f3577b34da6a3ce929d0e0e4736")

    def test_initialize_negotiates_an_older_client_version(self):
        req = {"jsonrpc": "2.0", "id": 9, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}}
        # stdio transport (LM Studio, Claude Desktop): no HTTP headers, version comes from params.
        res = asyncio.run(self.engine.handle_jsonrpc_request(req, auth_header=self.admin_auth))
        self.assertEqual(res["result"]["protocolVersion"], "2025-06-18")

    def test_header_body_agreement_validation(self):
        # Valid agreement
        req = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "vcf_list_vms", "arguments": {"cluster_id": "cluster-prod-a"}},
        }
        valid_headers = {
            "Mcp-Method": "tools/call",
            "Mcp-Name": "vcf_list_vms",
            "Mcp-Param-cluster_id": "cluster-prod-a",
        }
        req["params"]["_meta"] = {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}
        valid_headers["MCP-Protocol-Version"] = "2026-07-28"
        res = asyncio.run(self.engine.handle_jsonrpc_request(req, auth_header=self.alice_auth, headers=valid_headers))
        self.assertNotIn("error", res)

        # Disagreement in Mcp-Method -> HeaderMismatchException
        bad_headers = {**valid_headers, "Mcp-Method": "tools/list"}
        res_bad = asyncio.run(self.engine.handle_jsonrpc_request(req, auth_header=self.alice_auth, headers=bad_headers))
        self.assertIn("error", res_bad)
        self.assertEqual(res_bad["error"]["code"], -32020)

        # Disagreement in Mcp-Name -> HeaderMismatchException
        bad_name_headers = {**valid_headers, "Mcp-Name": "vcf_power_vm"}
        res_bad_name = asyncio.run(self.engine.handle_jsonrpc_request(req, auth_header=self.alice_auth, headers=bad_name_headers))
        self.assertIn("error", res_bad_name)
        self.assertEqual(res_bad_name["error"]["code"], -32020)

    def test_tools_list_cache_scope_private(self):
        req = {"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}}
        res = asyncio.run(self.engine.handle_jsonrpc_request(req, auth_header=self.alice_auth))

        self.assertNotIn("error", res)
        result = res["result"]
        # In strict compliance with MCP 2026-07-28, principal-sensitive tools/list must be private
        self.assertEqual(result["cacheScope"], "private")
        self.assertLessEqual(result["cacheTtl"], 60)
        self.assertIn("permissionEpoch", result)
        self.assertEqual(result["principal"], "alice@corp.com")

    def test_tasks_list_deliberately_omitted_in_2026_spec(self):
        req = {"jsonrpc": "2.0", "id": 4, "method": "tasks/list", "params": {}}
        res = asyncio.run(self.engine.handle_jsonrpc_request(req, auth_header=self.alice_auth))
        # Deliberately removed to prevent cross-caller task enumeration
        self.assertIn("error", res)
        self.assertEqual(res["error"]["code"], -32601)  # Method not found

    def test_tasks_get_update_cancel_lifecycle(self):
        # Create task for Alice
        alice = Principal(user_id="alice@corp.com", corporate_groups=["VCF-Compute-Operators"])
        task = self.task_store.create_task(
            tool_name="vcf_power_vm",
            principal=alice,
            steps=[WorkflowStep("Power on VM", is_reversible=True)],
        )

        # 1. Alice can get her task
        req_get = {"jsonrpc": "2.0", "id": 5, "method": "tasks/get", "params": {"taskId": task.task_id}}
        res_get = asyncio.run(self.engine.handle_jsonrpc_request(req_get, auth_header=self.alice_auth))
        self.assertNotIn("error", res_get)
        self.assertEqual(res_get["result"]["taskId"], task.task_id)

        # 2. Bob (different user) CANNOT get Alice's task -> AuthorizationDenied
        res_bob = asyncio.run(self.engine.handle_jsonrpc_request(req_get, auth_header=self.bob_auth))
        self.assertIn("error", res_bob)
        self.assertEqual(res_bob["error"]["code"], -32001)

        # 3. Update task progress
        req_upd = {
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tasks/update",
            "params": {"taskId": task.task_id, "step": 1, "stepDescription": "Power state confirmed"},
        }
        res_upd = asyncio.run(self.engine.handle_jsonrpc_request(req_upd, auth_header=self.alice_auth))
        self.assertNotIn("error", res_upd)
        self.assertEqual(res_upd["result"]["step"], "1/1: Power state confirmed")

        # 4. Cancel task
        req_cancel = {"jsonrpc": "2.0", "id": 7, "method": "tasks/cancel", "params": {"taskId": task.task_id}}
        res_cancel = asyncio.run(self.engine.handle_jsonrpc_request(req_cancel, auth_header=self.alice_auth))
        self.assertNotIn("error", res_cancel)
        self.assertTrue(res_cancel["result"]["cancelled"])

    def test_subscriptions_listen_registration(self):
        req = {
            "jsonrpc": "2.0",
            "id": 8,
            "method": "subscriptions/listen",
            "params": {"topic": "notifications/tools/list_changed"},
        }
        res = asyncio.run(self.engine.handle_jsonrpc_request(req, auth_header=self.alice_auth))
        self.assertNotIn("error", res)
        self.assertTrue(res["result"]["subscribed"])
        self.assertEqual(res["result"]["topic"], "notifications/tools/list_changed")

    # ---- JSON-RPC / MCP wire rules (independent review F9) ----

    def test_notifications_never_get_a_reply(self):
        for method in ("notifications/initialized", "notifications/cancelled", "notifications/unknown"):
            note = {"jsonrpc": "2.0", "method": method, "params": {}}
            self.assertIsNone(asyncio.run(self.engine.handle_jsonrpc_request(note, auth_header=self.admin_auth)))
        # A request that does carry an id is still answered, including "method not found".
        res = asyncio.run(self.engine.handle_jsonrpc_request({"jsonrpc": "2.0", "id": 0, "method": "nope"}, auth_header=self.admin_auth))
        self.assertEqual(res["error"]["code"], -32601)

    def test_initialize_succeeds_without_a_token_and_says_what_is_wrong(self):
        req = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        for bad in (None, "Bearer not-a-jwt"):
            res = asyncio.run(self.engine.handle_jsonrpc_request(req, auth_header=bad))
            self.assertNotIn("error", res)
            self.assertIn("AUTHENTICATION PROBLEM", res["result"]["instructions"])
            self.assertIn("VCF_MCP_AUTH_TOKEN", res["result"]["instructions"])
        ping = asyncio.run(self.engine.handle_jsonrpc_request({"jsonrpc": "2.0", "id": 2, "method": "ping"}, auth_header=None))
        self.assertEqual(ping["result"], {})

    def test_auth_problems_are_reported_at_tools_list_and_tools_call_with_a_fix(self):
        lst = asyncio.run(self.engine.handle_jsonrpc_request({"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}}, auth_header=None))
        self.assertIn("error", lst)
        self.assertIn("VCF_MCP_AUTH_TOKEN", lst["error"]["message"])
        self.assertIn("token mint", lst["error"]["message"])
        call = asyncio.run(self.engine.handle_jsonrpc_request(
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "vcf_list_vms", "arguments": {}}}, auth_header=None))
        self.assertNotIn("error", call)
        self.assertTrue(call["result"]["isError"])
        self.assertIn("VCF_MCP_AUTH_TOKEN", call["result"]["content"][0]["text"])

    def test_tool_failures_are_call_tool_results_not_jsonrpc_errors(self):
        # Invalid arguments and a missing approval are the model's to correct: isError=true with readable text.
        bad_args = {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                    "params": {"name": "vcf_power_vm", "arguments": {"vm_id": "vm-101", "action": "explode", "dry_run": True}}}
        res = asyncio.run(self.engine.handle_jsonrpc_request(bad_args, auth_header=self.admin_auth))
        self.assertNotIn("error", res)
        self.assertTrue(res["result"]["isError"])
        self.assertTrue(res["result"]["content"][0]["text"])
        # Protocol errors stay JSON-RPC errors.
        unknown = asyncio.run(self.engine.handle_jsonrpc_request({"jsonrpc": "2.0", "id": 6, "method": "tools/frobnicate"}, auth_header=self.admin_auth))
        self.assertEqual(unknown["error"]["code"], -32601)


if __name__ == "__main__":
    unittest.main()
