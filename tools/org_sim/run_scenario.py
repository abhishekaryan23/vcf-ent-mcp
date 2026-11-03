# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Start/stop the Acme organization simulator for one scenario and prepare a real-VCF MCP
configuration pointed at it.

    python tools/org_sim/run_scenario.py start <state-dir> <scenario> [--offset N] [--model acme|enterprise] [--persona oncall|automation]
    python tools/org_sim/run_scenario.py stop <state-dir>

Personas: oncall = read-only VCF_VIEWER in DISCOVERY_ONLY mode (troubleshooting);
automation = AUTOMATION_OPERATOR in AUDITED_OPERATIONS mode (can save cloud templates and
run Orchestrator workflows, each through dry-run -> plan_id).

After `start`, <state-dir>/vcf is a wrapper an agent (or a person) uses to talk to the real
MCP server as a read-only VCF_VIEWER:

    <state-dir>/vcf tools
    <state-dir>/vcf call vcf_diagnose '{"symptom": "users cannot log in to vCenter"}'
"""

from __future__ import annotations

import json
import os
import secrets
import signal
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
HERE = Path(__file__).resolve().parent

DIAG_USERS = {"sddc_manager": "svc-mcp-diag@vsphere.local", "vcenter": "svc-mcp-diag@vsphere.local",
              "nsx": "svc-mcp-diag", "vcf_operations": "svc-mcp-diag", "vcf_automation": "svc-mcp-automation"}
PERSONAS = {"oncall": ("oncall@acme.lab", "VCF_VIEWER", "DISCOVERY_ONLY"),
            "automation": ("automation-eng@acme.lab", "AUTOMATION_OPERATOR", "AUDITED_OPERATIONS"),
            "security": ("sec-admin@acme.lab", "SECURITY_ADMIN", "AUDITED_OPERATIONS"),
            "admin": ("platform-admin@acme.lab", "VCF_PLATFORM_ADMIN", "AUDITED_OPERATIONS")}
# Extra secret references for Orchestrator integration tests: one with the right password, one wrong.
EXTRA_REFS = {"local://env-prod/itsm-rest": True, "local://env-prod/ad-eu-bind": True, "local://env-prod/old-password": False}


def server_env(state: Path) -> dict:
    env = dict(os.environ, PYTHONPATH=str(REPO / "src"), PYTHONDONTWRITEBYTECODE="1",
               VCF_ENTERPRISE_MCP_CONFIG=str(state / "config.yaml"), VCF_MCP_HOME=str(state / "home"),
               VCF_MCP_CREDENTIALS_PATH=str(state / "credentials.json"), VCF_MCP_MASTER_KEY_PATH=str(state / "master.key"),
               VCF_MCP_KMS_KEY_PATH=str(state / "kms.key"), VCF_MCP_DB_PATH=str(state / "control_plane.db"),
               VCF_MCP_LAB_JWT_KEY_PATH=str(state / "lab_jwt.pem"))
    env["VCF_MCP_PLUGIN_DIR"] = str(state / "plugins")
    env.pop("VCF_MCP_AUTH_TOKEN", None)
    return env


def start_sim(mock: Path, scenario: str, port_offset: int = 0, model: str = "acme") -> dict:
    """Start the simulator in `mock` (keeps an existing password, so configured clients stay valid)."""
    mock.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not (mock / "password").exists():
        (mock / "password").write_text(secrets.token_urlsafe(18))
        os.chmod(mock / "password", 0o600)
    (mock / "endpoints.json").unlink(missing_ok=True)
    proc = subprocess.Popen([sys.executable, str(HERE / "server.py"), str(mock), scenario, str(port_offset), model],
                            stdout=subprocess.DEVNULL, stderr=open(mock / "sim.stderr.log", "w"), start_new_session=True)
    (mock / "sim.pid").write_text(str(proc.pid))
    for _ in range(150):
        if (mock / "endpoints.json").exists():
            break
        time.sleep(0.1)
    return json.loads((mock / "endpoints.json").read_text())["endpoints"]


def start(state: Path, scenario: str, port_offset: int = 0, model: str = "acme", persona: str = "oncall") -> None:
    start_sim(state, scenario, port_offset, model)
    configure(state, state, persona, model)


def configure(state: Path, mock: Path, persona: str = "oncall", model: str = "enterprise") -> None:
    """Write an MCP client configuration in `state` for `persona`, pointed at the simulator running in `mock`."""
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    pw = (mock / "password").read_text().strip()
    endpoints = json.loads((mock / "endpoints.json").read_text())["endpoints"]

    env = server_env(state)
    os.environ.update({k: v for k, v in env.items() if k.startswith("VCF_")})
    from vcf_enterprise_mcp.auth.lab_auth import mint_lab_jwt_token
    from vcf_enterprise_mcp.secrets.models import SecretValue
    from vcf_enterprise_mcp.secrets.registry import get_default_secret_registry
    registry = get_default_secret_registry()
    refs = {}
    for comp in DIAG_USERS:
        ref = f"local://env-prod/diag-{comp.replace('_', '-')}"
        registry.store(ref, SecretValue(pw), tenant_id="tenant-default", environment_id="env-prod", description=f"diag {comp}")
        refs[comp] = ref
    for ref, right in EXTRA_REFS.items():
        registry.store(ref, SecretValue(pw if right else "not-the-password-" + secrets.token_hex(4)), tenant_id="tenant-default",
                       environment_id="env-prod", description="orchestrator integration test")
    (state / "plugins").mkdir(exist_ok=True)
    (state / "plugins" / "o11nplugin-snmp-9.1.1.vmoapp").write_bytes(b"PK\x03\x04 simulated snmp plug-in package")
    user_id, role, mode = PERSONAS[persona]
    token = mint_lab_jwt_token(user_id=user_id, role=role, custom_key_path=str(state / "lab_jwt.pem"))["authorization_header"]
    (state / "viewer.token").write_text(token)
    os.chmod(state / "viewer.token", 0o600)

    import yaml
    m = __import__({"acme": "org_model", "enterprise": "enterprise_model"}[model])
    fq = m.FQDN
    vcf = {
        "sddc_manager_url": endpoints[fq["sddc"]], "vcenter_url": endpoints[fq["vc-mgmt"]],
        "nsx_url": endpoints[fq["nsx-mgmt"]], "operations_url": endpoints[fq["ops"]],
        "component_usernames": DIAG_USERS, "component_credential_refs": refs, "credential_ref": refs["sddc_manager"],
        "verify_ssl": True, "ca_cert_path": str(mock / "ca.pem"), "allow_loopback_targets": True,
        "endpoint_overrides": endpoints, "active_version": "9.1.1",
    }
    if "vcfa" in fq:
        vcf.update(automation_url=endpoints[fq["vcfa"]], automation_org="northwind",
                   orchestrator_run_allowlist=["Northwind/*"], orchestrator_blocked_workflows=["SQL AG planned failover"],
                   orchestrator_repository_allowlist=["https://pypi.org/simple"])
    (state / "config.yaml").write_text(yaml.safe_dump({
        "server": {"mode": "stdio", "environment": "production"},
        "policy": {"operating_mode": mode},
        "idp": {"enabled": True, "client_id": "vcf-mcp-client", "allow_lab_tokens": True},
        "vcf": vcf,
    }, sort_keys=False))
    py = REPO.parent / ".venv" / "bin" / "python"
    wrapper = state / "vcf"
    wrapper.write_text(f"#!/bin/sh\nexec '{py if py.exists() else sys.executable}' '{HERE / 'vcf_cli.py'}' --state '{state}' \"$@\"\n")
    os.chmod(wrapper, 0o700)
    print(f"configured {persona} in {state}; use {wrapper}")


def stop(state: Path) -> None:
    pid_file = state / "sim.pid"
    if pid_file.exists():
        try:
            os.killpg(int(pid_file.read_text()), signal.SIGTERM)
        except ProcessLookupError:
            pass
        pid_file.unlink()
    print("stopped")


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("action", choices=["start", "stop", "configure"])
    ap.add_argument("state")
    ap.add_argument("scenario", nargs="?")
    ap.add_argument("offset_pos", nargs="?", type=int, default=0)
    ap.add_argument("--offset", type=int)
    ap.add_argument("--model", default="acme", choices=["acme", "enterprise"])
    ap.add_argument("--persona", default="oncall", choices=list(PERSONAS))
    ap.add_argument("--mock", help="configure: directory of an already running simulator")
    a = ap.parse_args()
    state = Path(a.state).resolve()
    if a.action == "start":
        start(state, a.scenario, a.offset if a.offset is not None else a.offset_pos, a.model, a.persona)
    elif a.action == "configure":
        configure(state, Path(a.mock).resolve(), a.persona, a.model)
    else:
        stop(state)
