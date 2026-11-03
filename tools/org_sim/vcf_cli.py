# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Minimal MCP client for agents and people: talks to the real vcf-enterprise-mcp server over
stdio as the read-only on-call user, and logs every call to <state>/agent_calls.jsonl.

    vcf_cli.py --state DIR tools
    vcf_cli.py --state DIR call <tool> ['{"json": "arguments"}']
    vcf_cli.py --state DIR approve <plan_id>     # stands in for the human change approver
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_scenario import REPO, server_env  # noqa: E402


def rpc(state: Path, requests: list) -> list:
    token = (state / "viewer.token").read_text().strip()
    lines = []
    for i, (method, params) in enumerate(requests, 1):
        params = dict(params)
        params["_meta"] = {"authorization": token}
        lines.append(json.dumps({"jsonrpc": "2.0", "id": i, "method": method, "params": params}))
    proc = subprocess.run([sys.executable, "-c", "from vcf_enterprise_mcp.core.server import main; main()"], cwd=REPO,
                          env=server_env(state), input="\n".join(lines) + "\n", capture_output=True, text=True, timeout=300)
    return [json.loads(line) for line in proc.stdout.splitlines() if line.strip().startswith("{")]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--state", required=True)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("tools")
    c = sub.add_parser("call")
    c.add_argument("tool")
    c.add_argument("arguments", nargs="?", default="{}")
    ap_ = sub.add_parser("approve")
    ap_.add_argument("plan_id")
    ap_.add_argument("--as", dest="approver", default="change-manager@acme.lab",
                     help="approver identity; changes needing two approvals need a second, different approver")
    a = ap.parse_args()
    state = Path(a.state)
    log = open(state / "agent_calls.jsonl", "a")
    if a.cmd == "approve":
        # `plans approve` takes the approver's own token: mint a lab token for the approver identity (an approver
        # role, signed with this lab's key) and pass it the way a real approver would, in VCF_MCP_APPROVER_TOKEN.
        env = server_env(state)
        os.environ.update({k: v for k, v in env.items() if k.startswith("VCF_")})
        from vcf_enterprise_mcp.auth.lab_auth import mint_lab_jwt_token
        env["VCF_MCP_APPROVER_TOKEN"] = mint_lab_jwt_token(user_id=a.approver, role="VCF_PLATFORM_ADMIN", ttl_seconds=600,
                                                           custom_key_path=str(state / "lab_jwt.pem"))["authorization_header"]
        proc = subprocess.run([sys.executable, "-m", "vcf_enterprise_mcp.cli", "plans", "approve", a.plan_id,
                               "--db", str(state / "control_plane.db")], cwd=REPO, env=env, capture_output=True, text=True, timeout=120)
        out = proc.stdout[proc.stdout.find("{"):] if "{" in proc.stdout else ""
        log.write(json.dumps({"t": time.time(), "cmd": "approve", "plan_id": a.plan_id, "ok": proc.returncode == 0}) + "\n")
        if proc.returncode != 0 or not out:
            print("APPROVAL FAILED: " + (proc.stderr.strip().splitlines() or ["unknown error"])[-1])
            return 1
        signed, _ = json.JSONDecoder().raw_decode(out)  # the CLI prints next steps after the JSON
        print(json.dumps({"approved_by": a.approver, "plan_id": a.plan_id,
                          "approval_id": signed.get("approval_id") or signed.get("authorization_id"), "nonce": signed.get("nonce"),
                          **({"status": signed["status"]} if signed.get("status") else {})}, indent=2))
        return 0
    if a.cmd == "tools":
        resp = rpc(state, [("tools/list", {})])[0]
        tools = resp.get("result", {}).get("tools", [])
        for t in tools:
            props = (t.get("inputSchema") or {}).get("properties", {})
            print(f"- {t['name']}: {t['description']}\n    arguments: {json.dumps(props) if props else '{}'}")
        log.write(json.dumps({"t": time.time(), "cmd": "tools", "count": len(tools)}) + "\n")
        return 0
    try:
        args = json.loads(a.arguments)
    except ValueError as exc:
        print(f"ERROR: arguments must be a JSON object: {exc}")
        log.write(json.dumps({"t": time.time(), "cmd": "call", "tool": a.tool, "ok": False, "error": "bad_json"}) + "\n")
        return 2
    resp = rpc(state, [("tools/call", {"name": a.tool, "arguments": args})])[0]
    if "error" in resp:
        print(f"ERROR {resp['error'].get('code')}: {resp['error'].get('message')}")
        log.write(json.dumps({"t": time.time(), "cmd": "call", "tool": a.tool, "args": args, "ok": False, "error": resp["error"].get("message")}) + "\n")
        return 1
    result = resp.get("result", {})
    text = "".join(c.get("text", "") for c in result.get("content", []))
    print(text)
    log.write(json.dumps({"t": time.time(), "cmd": "call", "tool": a.tool, "args": args, "ok": not result.get("isError")}) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
