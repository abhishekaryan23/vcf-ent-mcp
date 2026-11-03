# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""How a human approves a plan: instructions in the dry-run result and an approver identity that is never invented (review F10)."""

import asyncio
import json

import pytest

from tests.fixtures.test_tokens import ADMIN_BEARER
from vcf_enterprise_mcp.auth.lab_auth import mint_lab_jwt_token
from vcf_enterprise_mcp.cli import main
from vcf_enterprise_mcp.core.protocol import EnterpriseMCPProtocolEngine
from vcf_enterprise_mcp.state.sqlite_store import SQLiteDurableStore
from vcf_enterprise_mcp.workflows.task_store import TaskStore


@pytest.fixture()
def env(tmp_path, monkeypatch):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("idp: {allow_lab_tokens: true}\n")
    monkeypatch.setenv("VCF_ENTERPRISE_MCP_CONFIG", str(cfg))
    monkeypatch.setenv("VCF_MCP_LAB_JWT_KEY_PATH", str(tmp_path / "jwt.pem"))
    monkeypatch.delenv("VCF_MCP_APPROVER_TOKEN", raising=False)
    db = str(tmp_path / "cp.db")
    engine = EnterpriseMCPProtocolEngine(task_store=TaskStore(durable_store=SQLiteDurableStore(db)))
    engine.pep.pdp.config.operating_mode = "FULL_ENFORCEMENT"
    initiator = engine.idp.validate_bearer_token(ADMIN_BEARER).user_id

    def dry_run(tool, args):
        req = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": {**args, "dry_run": True}}}
        return json.loads(asyncio.run(engine.handle_jsonrpc_request(req, auth_header=ADMIN_BEARER))["result"]["content"][0]["text"])

    def token_file(user, role):
        t = mint_lab_jwt_token(user_id=user, role=role, custom_key_path=str(tmp_path / "jwt.pem"))["token"]
        path = tmp_path / f"{user}.tok"
        path.write_text(t)
        return str(path)
    def destructive_plan():
        from vcf_enterprise_mcp.policy.models import RiskClass
        who = engine.idp.validate_bearer_token(ADMIN_BEARER)
        return engine.plan_manager.create_dry_run_plan(who, "vcf_delete_snapshot", {"vm_id": "vm-101", "snapshot_id": "s1"}, {}, ["vm-101"], RiskClass.DESTRUCTIVE)

    return dict(db=db, dry_run=dry_run, token_file=token_file, initiator=initiator, destructive_plan=destructive_plan)


def test_every_plan_carries_the_exact_approval_instructions(env):
    plan = env["dry_run"]("vcf_upgrade_domain", {"domain_id": "wld-app-a", "target_version": "9.1.1"})
    how = plan["how_to_approve"]
    assert how["command"] == f"vcf-mcp plans approve {plan['plan_id']} --db {env['db']}"
    assert how["approvals_required"] == 1 and "VCF_PLATFORM_ADMIN" in how["approver_roles_any_of"]
    assert how["approver_must_differ_from"] == env["initiator"]
    text = " ".join(how["steps"])
    assert "VCF_MCP_APPROVER_TOKEN" in text and "approval_id and nonce" in text and "paste" in text.lower()

    destructive = env["destructive_plan"]()
    assert destructive["how_to_approve"]["approvals_required"] == 2
    assert "DIFFERENT approvers" in " ".join(destructive["how_to_approve"]["steps"])
    assert "VCF-Platform-Admins" in destructive["how_to_approve"]["approver_groups_any_of"]


def test_cli_approval_uses_the_approvers_own_token(env, capsys):
    plan_id = env["dry_run"]("vcf_upgrade_domain", {"domain_id": "wld-app-a", "target_version": "9.1.1"})["plan_id"]
    assert main(["plans", "approve", plan_id, "--db", env["db"]]) == 1           # no token: nothing is invented
    assert "VCF_MCP_APPROVER_TOKEN" in capsys.readouterr().err

    viewer = env["token_file"]("viewer@corp.com", "VCF_VIEWER")
    assert main(["plans", "approve", plan_id, "--db", env["db"], "--approver-token-file", viewer]) == 1
    assert "none of the approver roles" in capsys.readouterr().err

    same_person = env["token_file"](env["initiator"], "VCF_PLATFORM_ADMIN")
    assert main(["plans", "approve", plan_id, "--db", env["db"], "--approver-token-file", same_person]) == 1
    assert "own plan" in capsys.readouterr().err                                   # separation of duties still holds

    bob = env["token_file"]("bob@corp.com", "VCF_PLATFORM_ADMIN")
    assert main(["plans", "approve", plan_id, "--db", env["db"], "--approver-token-file", bob]) == 0
    out = capsys.readouterr().out
    assert "approved by bob@corp.com (1/1" in out and "Paste into the chat: approval_id=appr_" in out


def test_two_approver_rule_for_destructive_changes_is_kept(env, capsys):
    plan_id = env["destructive_plan"]()["plan_id"]
    bob = env["token_file"]("bob@corp.com", "VCF_PLATFORM_ADMIN")
    carol = env["token_file"]("carol@corp.com", "SECURITY_ADMIN")
    assert main(["plans", "approve", plan_id, "--db", env["db"], "--approver-token-file", bob]) == 0
    out = capsys.readouterr().out
    assert "(1/2 approvals)" in out and "1 more DIFFERENT approver" in out and "Paste into the chat" not in out
    assert main(["plans", "approve", plan_id, "--db", env["db"], "--approver-token-file", bob]) == 1   # same person twice
    assert "Duplicate approval" in capsys.readouterr().err
    assert main(["plans", "approve", plan_id, "--db", env["db"], "--approver-token-file", carol]) == 0
    out = capsys.readouterr().out
    assert "(2/2 approvals)" in out and "Paste into the chat" in out


def test_plans_show_never_reveals_the_initiators_handback(env, capsys):
    plan_id = env["dry_run"]("vcf_upgrade_domain", {"domain_id": "wld-app-a", "target_version": "9.1.1"})["plan_id"]
    bob = env["token_file"]("bob@corp.com", "VCF_PLATFORM_ADMIN")
    main(["plans", "approve", plan_id, "--db", env["db"], "--approver-token-file", bob])
    capsys.readouterr()
    assert main(["plans", "show", plan_id, "--db", env["db"]]) == 0
    shown = json.loads(capsys.readouterr().out)
    assert shown["status"] == "APPROVED" and "nonce" not in shown and "approval_id" not in shown
