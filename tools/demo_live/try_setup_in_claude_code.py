# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Try the guided setup yourself in Claude Code, against a simulated VCF 9 estate.

    python tools/demo_live/try_setup_in_claude_code.py

What it does:
1. starts the Northwind simulator: 12 HTTPS appliances (SDDC Manager, vCenters, NSX Managers, VCF Operations,
   VCF Automation) with their own certificates from the estate's CA;
2. runs `vcf-mcp client-config claude-desktop` in a throwaway state folder, exactly as a new user would, and
   adds a name-to-address map for the simulator's host names (the job DNS does in a real network);
3. opens Claude Code with only this MCP server loaded (`--mcp-config`, `--strict-mcp-config`), so your own
   Claude Code configuration is not changed.

Then it is you and Claude Code: ask it to set up VCF MCP. Claude Code shows the server's questions in its own
dialogs, the passwords go into private pages in your browser, and the server checks what each account can do.
When you leave Claude Code (/exit), the simulator stops and the throwaway folder is deleted.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools" / "org_sim"))

import run_scenario as rs  # noqa: E402
import yaml  # noqa: E402
from enterprise_model import FQDN  # noqa: E402

B, DIM, RST, CYAN, GREEN, YELLOW = "\033[1m", "\033[2m", "\033[0m", "\033[36m", "\033[32m", "\033[33m"


def main() -> int:
    claude = shutil.which("claude")
    if not claude:
        print("Claude Code (the `claude` command) is not installed: https://docs.claude.com/en/docs/claude-code")
        return 1
    root = Path(tempfile.mkdtemp(prefix="vcf-mcp-try-"))
    state, workdir = root / "vcf-mcp-state", root / "workspace"
    workdir.mkdir()
    try:
        endpoints = rs.start_sim(root / "estate", "healthy_noisy", 8200, "enterprise")
        password = (root / "estate" / "password").read_text().strip()
        env = {**os.environ, "VCF_MCP_HOME": str(state), "PYTHONPATH": str(REPO / "src")}
        for k in ("VCF_ENTERPRISE_MCP_CONFIG", "VCF_MCP_DB_PATH", "VCF_MCP_AUTH_TOKEN"):
            env.pop(k, None)
        out = subprocess.run([sys.executable, "-m", "vcf_enterprise_mcp.cli", "client-config", "claude-desktop"], env=env,
                             capture_output=True, text=True, cwd="/", timeout=60, check=True)
        entry = next(iter(json.loads(out.stdout)["mcpServers"].values()))
        entry.setdefault("env", {}).update({"VCF_MCP_HOME": str(state), "PYTHONPATH": str(REPO / "src")})

        cfg_path = state / "config.yaml"
        cfg = yaml.safe_load(cfg_path.read_text()) or {}
        vcf = cfg.setdefault("vcf", {})
        vcf["endpoint_overrides"] = {fq: endpoints[fq] for fq in FQDN.values() if fq in endpoints}  # DNS stand-in
        vcf["allow_loopback_targets"] = True  # the simulator listens on this machine
        cfg_path.write_text(yaml.safe_dump(cfg, sort_keys=False))
        mcp_json = root / "mcp.json"
        mcp_json.write_text(json.dumps({"mcpServers": {"vcf-enterprise": entry}}, indent=2))

        print(f"""
{B}Your simulated VCF 9 estate is running.{RST}  Appliance names to give the assistant when it asks:

  SDDC Manager     {CYAN}https://{FQDN['sddc']}{RST}
  vCenter          {CYAN}https://{FQDN['vc-mgmt']}{RST}   (SDDC Manager also reports the other vCenters)
  NSX Manager      {CYAN}https://{FQDN['nsx-mgmt']}{RST}
  VCF Operations   {CYAN}https://{FQDN['ops']}{RST}
  Service accounts {CYAN}svc-mcp-diag@vsphere.local{RST} (SDDC Manager, vCenter), {CYAN}svc-mcp-diag{RST} (NSX, Operations)
  Password         {CYAN}{password}{RST}   {DIM}(throwaway simulator password: type it only into the private browser pages){RST}
  Estate CA        {CYAN}{root / 'estate' / 'ca.pem'}{RST}   {DIM}(setup asks for it when a certificate is not trusted){RST}

{DIM}MCP entry from `vcf-mcp client-config claude-desktop` (no token): {mcp_json}{RST}

{B}Claude Code starts now with only this MCP server.{RST} Type, for example:  {GREEN}set up VCF MCP{RST}
Allow the vcf-enterprise tool calls when Claude Code asks. Leave with {YELLOW}/exit{RST}; everything here is then removed.
""")
        input(f"{DIM}Press Enter to start Claude Code...{RST}")
        return subprocess.call([claude, "--mcp-config", str(mcp_json), "--strict-mcp-config"], cwd=workdir)
    finally:
        rs.stop(root / "estate")
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
