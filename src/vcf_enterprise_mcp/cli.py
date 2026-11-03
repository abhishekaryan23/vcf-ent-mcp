# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Enterprise VCF MCP Command-Line Interface (CLI).
Provides administrative commands for managing encrypted credentials, testing provider connectivity,
and starting the enterprise MCP control plane.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import shlex
import shutil
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

from vcf_enterprise_mcp.secrets.models import SecretValue, CredentialPolicy
from vcf_enterprise_mcp.secrets.registry import get_default_secret_registry
from vcf_enterprise_mcp.secrets.base import MissingCredentialException, CredentialPolicyViolationException


def _warn_password_on_command_line(password: Optional[str]) -> None:
    if password:
        print("WARNING: a password passed with --password can be saved in shell history and seen in the process list. "
              "Omit --password to be prompted without echo.", file=sys.stderr)


class _NoPasswordSource(Exception):
    pass


def _read_password(prompt: str, password: Optional[str] = None, password_file: Optional[str] = None,
                   from_stdin: bool = False) -> str:
    """Password from --password, --password-file, stdin pipe (--password-stdin) or a no-echo prompt.
    Raises _NoPasswordSource with a one-line hint when there is no terminal to prompt on (SSH without a tty, CI, containers)."""
    if password:
        return password
    if password_file:
        return Path(password_file).expanduser().read_text(encoding="utf-8").strip()
    if from_stdin:
        return sys.stdin.readline().rstrip("\r\n")
    try:
        return getpass.getpass(prompt)
    except (EOFError, KeyboardInterrupt):
        raise _NoPasswordSource(
            "No terminal to prompt for the password. Run this in an interactive terminal, or pipe it in: "
            "printf '%s' \"$PASSWORD\" | vcf-mcp credentials add ... --password-stdin   (or use --password-file <path>, keep the file mode 600).")


def _prompt_text(label: str) -> str:
    try:
        return input(label).strip()
    except EOFError:
        raise _NoPasswordSource(f"{label.strip().rstrip(':')} is required and there is no terminal to ask; pass it as an option "
                                "(--name, --username, --provider).")


def _cmd_credentials_add(args: argparse.Namespace) -> int:
    registry = get_default_secret_registry()
    try:
        name = args.name or _prompt_text("Credential name: ")
        if not name:
            print("Error: Credential name cannot be empty.", file=sys.stderr)
            return 1

        username = args.username or _prompt_text("Username: ")
        password = args.password
        _warn_password_on_command_line(password)
        password = _read_password("Password: ", password, getattr(args, "password_file", None), getattr(args, "password_stdin", False))
    except _NoPasswordSource as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    if not password:
        print("Error: Password cannot be empty.", file=sys.stderr)
        return 1

    provider_choice = args.provider
    if not provider_choice and not sys.stdin.isatty():
        provider_choice = "local"  # no terminal to ask: the local encrypted store is the default
    if not provider_choice:
        print("\nProvider:")
        print("[1] Local encrypted (local://)")
        print("[2] Environment (env://)")
        print("[3] HashiCorp Vault (vault://)")
        print("[4] Azure Key Vault (azurekv://)")
        print("[5] AWS Secrets Manager (awssecrets://)")
        print("[6] CyberArk Central Credential Provider (cyberark://)")
        choice = input("Select provider [1]: ").strip() or "1"
        provider_map = {
            "1": "local",
            "2": "env",
            "3": "vault",
            "4": "azurekv",
            "5": "awssecrets",
            "6": "cyberark",
        }
        provider_choice = provider_map.get(choice, "local")

    env_id = args.env or "env-prod"
    tenant_id = args.tenant or "tenant-default"

    # Construct standard reference
    if provider_choice == "local":
        reference = f"local://{env_id}/{name}"
    elif provider_choice == "env":
        env_var_name = f"VCF_MCP_{name.upper().replace('-', '_')}_PASSWORD"
        reference = f"env://{env_var_name}"
    elif provider_choice == "vault":
        reference = f"vault://vcf/{env_id}/{name}#password"
    elif provider_choice == "azurekv":
        reference = f"azurekv://vcf-{env_id}/{name}"
    elif provider_choice == "awssecrets":
        reference = f"awssecrets://vcf/{env_id}/{name}"
    elif provider_choice == "cyberark":
        safe = getattr(args, "safe", None) or "Enterprise-PAM"
        reference = f"cyberark://{safe}/{name}"
    else:
        reference = f"local://{env_id}/{name}"

    if args.reference:
        reference = args.reference

    secret_val = SecretValue(password)
    try:
        registry.store(
            reference,
            secret_val,
            tenant_id=tenant_id,
            environment_id=env_id,
            description=f"Credential for {username} ({name})",
        )
        print("\nCredential stored.")
        print(f"Reference:\n{reference}")
        if username:
            print(f"Associated Username: {username}")
        return 0
    except Exception as e:
        print(f"Error storing credential: {e}", file=sys.stderr)
        return 1


def _cmd_credentials_list(args: argparse.Namespace) -> int:
    registry = get_default_secret_registry()
    tenant_id = args.tenant or "tenant-default"
    env_id = args.env or "env-prod"

    records = registry.list_references(tenant_id=tenant_id, environment_id=env_id)
    if not records:
        print(f"No credentials configured for tenant '{tenant_id}' / environment '{env_id}'.")
        return 0

    print(f"{'REFERENCE':<40} {'KEY ID':<15} {'UPDATED':<22} {'DESCRIPTION'}")
    print("-" * 100)
    for r in records:
        updated_str = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(r.updated_at))
        desc = r.description or "-"
        print(f"{r.reference:<40} {r.key_id:<15} {updated_str:<22} {desc}")

    # Explicit audit note: passwords never revealed in list output
    print(f"\nTotal credentials: {len(records)} (passwords are redacted and protected)")
    return 0


def _cmd_credentials_test(args: argparse.Namespace) -> int:
    registry = get_default_secret_registry()
    reference = args.reference
    tenant_id = args.tenant or "tenant-default"
    env_id = args.env or "env-prod"

    print(f"Testing credential resolution for: {reference}")
    try:
        val = registry.resolve(reference, tenant_id=tenant_id, environment_id=env_id)
        if val and len(val) > 0:
            print("Status: SUCCESS (Credential exists and decrypts cleanly)")
            print(f"Value: {val}")  # Reveals [REDACTED], never plain text
            return 0
        else:
            print("Status: FAILURE (Credential resolved to empty value)")
            return 1
    except MissingCredentialException as e:
        print(f"Status: MISSING ({e})")
        return 1
    except CredentialPolicyViolationException as e:
        print(f"Status: POLICY VIOLATION ({e})")
        return 1
    except Exception as e:
        print(f"Status: ERROR ({e})")
        return 1


def _cmd_credentials_rotate(args: argparse.Namespace) -> int:
    registry = get_default_secret_registry()
    reference = args.reference
    tenant_id = args.tenant or "tenant-default"
    env_id = args.env or "env-prod"

    try:
        new_password = _read_password("New Password: ", args.new_password, getattr(args, "password_file", None),
                                      getattr(args, "password_stdin", False))
    except _NoPasswordSource as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    if not new_password:
        print("Error: New password cannot be empty.", file=sys.stderr)
        return 1

    try:
        # Verify old credential exists first
        registry.resolve(reference, tenant_id=tenant_id, environment_id=env_id)
        registry.store(
            reference,
            SecretValue(new_password),
            tenant_id=tenant_id,
            environment_id=env_id,
            description=f"Rotated at {time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime())}",
        )
        print(f"Credential '{reference}' rotated successfully.")
        return 0
    except MissingCredentialException:
        print(f"Error: Credential '{reference}' not found. Cannot rotate non-existent credential.", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error rotating credential: {e}", file=sys.stderr)
        return 1


def _cmd_credentials_delete(args: argparse.Namespace) -> int:
    registry = get_default_secret_registry()
    reference = args.reference
    tenant_id = args.tenant or "tenant-default"
    env_id = args.env or "env-prod"

    try:
        registry.delete(reference, tenant_id=tenant_id, environment_id=env_id)
        print(f"Credential '{reference}' deleted successfully.")
        return 0
    except Exception as e:
        print(f"Error deleting credential: {e}", file=sys.stderr)
        return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vcf-mcp",
        description="Enterprise VMware Cloud Foundation (VCF) MCP Control Plane Administration CLI",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Server command
    server_parser = subparsers.add_parser("server", help="Start the MCP Control Plane server")
    server_parser.add_argument("--mode", default="stdio", choices=["stdio", "http"], help="Server execution mode")
    server_parser.add_argument("--insecure", action="store_true", help="Skip upstream VCF TLS certificate verification and emit a warning (default: verify).")

    # Credentials subcommand group
    cred_parser = subparsers.add_parser("credentials", help="Manage enterprise credentials and secret references")
    cred_subparsers = cred_parser.add_subparsers(dest="cred_action", help="Credential actions")

    # credentials add
    add_parser = cred_subparsers.add_parser("add", help="Add a new credential")
    add_parser.add_argument("--name", help="Logical credential name (e.g. vcenter-prod)")
    add_parser.add_argument("--username", help="Service account username")
    add_parser.add_argument("--password", help="Password (discouraged: visible in shell history; omit to be prompted securely)")
    add_parser.add_argument("--password-file", help="Read the password from this file (keep it mode 600); for hosts without a terminal")
    add_parser.add_argument("--password-stdin", action="store_true", help="Read the password from standard input (pipe it in)")
    add_parser.add_argument("--provider", choices=["local", "env", "vault", "azurekv", "awssecrets", "cyberark"], help="Secret provider")
    add_parser.add_argument("--safe", help="CyberArk Safe name (used with cyberark provider)")
    add_parser.add_argument("--reference", help="Explicit URI reference (overrides automatic generation)")
    add_parser.add_argument("--tenant", default="tenant-default", help="Tenant ID")
    add_parser.add_argument("--env", default="env-prod", help="Environment ID (default env-prod, the one the server and guided setup use)")

    # credentials list
    list_parser = cred_subparsers.add_parser("list", help="List stored credential references without revealing passwords")
    list_parser.add_argument("--tenant", default="tenant-default", help="Tenant ID")
    list_parser.add_argument("--env", default="env-prod", help="Environment ID")

    # credentials test
    test_parser = cred_subparsers.add_parser("test", help="Test resolution and decryption of a credential reference")
    test_parser.add_argument("reference", help="Credential reference URI (e.g. local://prod/vcenter-prod)")
    test_parser.add_argument("--tenant", default="tenant-default", help="Tenant ID")
    test_parser.add_argument("--env", default="env-prod", help="Environment ID")

    # credentials rotate
    rot_parser = cred_subparsers.add_parser("rotate", help="Rotate a credential's secret value")
    rot_parser.add_argument("reference", help="Credential reference URI")
    rot_parser.add_argument("--new-password", help="New password (prompted securely if omitted)")
    rot_parser.add_argument("--password-file", help="Read the new password from this file (keep it mode 600)")
    rot_parser.add_argument("--password-stdin", action="store_true", help="Read the new password from standard input")
    rot_parser.add_argument("--tenant", default="tenant-default", help="Tenant ID")
    rot_parser.add_argument("--env", default="env-prod", help="Environment ID")

    # credentials delete
    del_parser = cred_subparsers.add_parser("delete", help="Delete a stored credential reference")
    del_parser.add_argument("reference", help="Credential reference URI")
    del_parser.add_argument("--tenant", default="tenant-default", help="Tenant ID")
    del_parser.add_argument("--env", default="env-prod", help="Environment ID")

    # certify command
    cert_parser = subparsers.add_parser("certify", help="Run VCF Interoperability Certification")
    cert_parser.add_argument("--profile", default="vcf_9_1_1", help="Profile name (vcf_9_0_0, vcf_9_1_0, vcf_9_1_1)")
    cert_parser.add_argument("--target", default="digital_twin", choices=["digital_twin", "real_vcf"], help="Target test environment")

    # certify-matrix command
    matrix_parser = subparsers.add_parser("certify-matrix", help="Generate full VCF certification matrix report")
    matrix_parser.add_argument("--target", default="digital_twin", choices=["digital_twin", "real_vcf"], help="Target test environment")
    matrix_parser.add_argument("--output", help="Output file path (default prints to stdout)")

    # ga-report command
    subparsers.add_parser("ga-report", help="Generate General Availability (GA) Qualification Audit Report")

    # setup command
    setup_parser = subparsers.add_parser("setup", help="Initialize read-only local configuration")
    setup_parser.add_argument("--target", choices=["digital_twin", "real_vcf"], default="digital_twin")
    setup_parser.add_argument("--gateway-url", default="http://127.0.0.1:8085", help="Digital Twin URL (the bundled simulator listens on 8085)")
    setup_parser.add_argument("--config", help="Configuration file path (default: ~/.vcf-mcp/config.yaml)")
    setup_sub = setup_parser.add_subparsers(dest="setup_action")
    auto_parser = setup_sub.add_parser(
        "automation", help="Create a VCF Automation service account for the MCP (device flow) and store its token",
        description="Guided, one-time setup of a VCF Automation 9 / Orchestrator service account. Logs in as an org user "
                    "(password asked without echo, never stored), registers the service account, approves it and stores the "
                    "refresh token in the secret store. Flow adapted from the community project vcf-orchestrator-mcp (MIT).")
    auto_parser.add_argument("--config", default=argparse.SUPPRESS, help="Configuration file to update (default: the active config)")
    auto_parser.add_argument("--url", help="VCF Automation URL, e.g. https://auto.example.lab")
    auto_parser.add_argument("--org", help="Organization name (the last part of https://<fqdn>/tenant/<name>)")
    auto_parser.add_argument("--user", help="Local org user to log in as (without @org)")
    auto_parser.add_argument("--name", help="Service account name shown in VCF Automation")
    auto_parser.add_argument("--role", help="Role name(s), comma separated, from Access Control > Roles. Least privilege: an "
                                            "Orchestrator role is needed to see workflows. Default: asked.")
    auto_parser.add_argument("--password-file", help="File whose first line is the password (otherwise asked without echo)")
    auto_parser.add_argument("--client-id", help="Client id of a service account you created in the UI (SSO-only orgs): no password; you approve in the UI")
    auto_parser.add_argument("--ca-cert", help="PEM file of the CA that signed the VCF Automation certificate (no --insecure option exists)")

    # local command
    local_parser = subparsers.add_parser("local", help="Run local diagnostic self-check or start local service")
    local_sub = local_parser.add_subparsers(dest="local_action")
    local_start = local_sub.add_parser("start", help="Start local control plane server")
    local_start.add_argument("--mode", default="stdio", choices=["stdio", "http", "remote_gateway"], help="Server transport mode")
    local_start.add_argument("--insecure", action="store_true", help="Skip upstream VCF TLS certificate verification and emit a warning (default: verify).")
    local_sub.add_parser("check", help="Run local diagnostic self-check")

    # support-bundle command
    bundle_parser = subparsers.add_parser("support-bundle", help="Export sanitized forensic support archive")
    bundle_parser.add_argument("--output", help="Output tar.gz path")
    bundle_sub = bundle_parser.add_subparsers(dest="bundle_action")
    bundle_create = bundle_sub.add_parser("create", help="Create forensic support bundle archive")
    bundle_create.add_argument("--output", help="Output tar.gz path")

    # init-lab command (One-command developer laptop / lab bootstrap)
    init_lab_parser = subparsers.add_parser("init-lab", help="One-command setup for developer laptop / lab testing with local credentials and JWT tokens")
    init_lab_parser.add_argument("--vcenter-url", default="https://vcenter.lab.local", help="Lab vCenter URL (not used with --target digital_twin: the Twin is read from vcf.gateway_url, default http://127.0.0.1:8085)")
    init_lab_parser.add_argument("--sddc-url", default="https://sddc-manager.lab.local", help="Lab SDDC Manager URL")
    init_lab_parser.add_argument("--nsx-url", default="https://nsx.lab.local", help="Lab NSX Manager URL")
    init_lab_parser.add_argument("--ops-url", default="https://vcf-ops.lab.local", help="Lab VCF Operations URL")
    init_lab_parser.add_argument("--username", default="administrator@vsphere.local", help="Lab service username")
    init_lab_parser.add_argument("--password", help="Lab password to encrypt in the local store (discouraged: visible in shell history; omit to be prompted, or skip for a Digital Twin)")
    init_lab_parser.add_argument("--role", default="COMPUTE_OPERATOR", help="Primary operator role to mint token for (default: COMPUTE_OPERATOR)")
    init_lab_parser.add_argument("--user", default="operator@lab.local", help="Operator principal email/ID")
    init_lab_parser.add_argument("--tenant", default="tenant-default", help="Tenant ID")
    init_lab_parser.add_argument("--env", default="env-prod", help="Environment ID")
    init_lab_parser.add_argument("--target", choices=["digital_twin", "real_vcf", "testing"], default="testing", help="Target execution mode")
    init_lab_parser.add_argument("--config", help="Output config.yaml path (default: ~/.vcf-mcp/config.yaml)")
    init_lab_parser.add_argument("--password-file", help="Read the lab password from this file (keeps it out of shell history)")
    init_lab_parser.add_argument("--ca-cert", help="PEM CA bundle that signed the lab appliances' certificates (keeps TLS verification on)")
    init_lab_parser.add_argument("--allow-loopback", action="store_true",
                                 help="Lab only: allow appliances on localhost (e.g. a local mock). Refused when VCF_MCP_ENV=production")
    init_lab_parser.add_argument("--endpoints-json", help="JSON file mapping appliance FQDN -> base URL, for appliances whose names do not "
                                                          "resolve (a lab or mock); accepts {\"endpoints\": {...}} or a flat map")
    init_lab_parser.add_argument("--automation-url", help="VCF Automation base URL (Assembler + embedded Orchestrator)")
    init_lab_parser.add_argument("--automation-org", help="VCF Automation organization name")

    # token subcommand group
    token_parser = subparsers.add_parser("token", help="Mint local JWT bearer tokens for laptop lab testing")
    token_sub = token_parser.add_subparsers(dest="token_action", help="Token actions")
    mint_parser = token_sub.add_parser("mint", help="Mint a signed local JWT token for a VCF role")
    mint_parser.add_argument("--role", default="VCF_PLATFORM_ADMIN", help="CapabilityRole (e.g. COMPUTE_OPERATOR, NETWORK_ADMIN, VCF_PLATFORM_ADMIN)")
    mint_parser.add_argument("--user", default="lab-engineer@corp.local", help="Principal user ID / email")
    mint_parser.add_argument("--tenant", default="tenant-default", help="Tenant ID")
    mint_parser.add_argument("--env", default="env-prod", help="Environment ID")
    mint_parser.add_argument("--cluster", action="append", help="Allowed cluster ID (repeatable; defaults to *)")
    mint_parser.add_argument("--domain", action="append", help="Allowed workload domain ID (repeatable; defaults to *)")
    mint_parser.add_argument("--ttl", type=int, default=86400, help="Token validity in seconds (default: 86400)")
    mint_parser.add_argument("--issuer", help="Token issuer (default: the lab issuer urn:vcf-mcp:lab, trusted only with idp.allow_lab_tokens: true)")
    mint_parser.add_argument("--raw", action="store_true", help="Print only the raw JWT string")

    # plans subcommand group
    plans_parser = subparsers.add_parser("plans", help="Inspect and approve dry-run execution plans from the CLI")
    plans_sub = plans_parser.add_subparsers(dest="plans_action", help="Plan actions")
    plans_list = plans_sub.add_parser("list", help="List execution plans in durable store")
    plans_list.add_argument("--status", help="Filter by status (e.g. PENDING_APPROVAL, APPROVED, EXPIRED)")
    plans_list.add_argument("--tenant", default="tenant-default", help="Tenant ID")
    plans_list.add_argument("--env", default="env-prod", help="Environment ID")
    plans_list.add_argument("--db", help="SQLite DB path (default: VCF_MCP_DB_PATH or ~/.vcf-mcp/control_plane.db)")

    plans_show = plans_sub.add_parser("show", help="Show the detailed execution plan (read-only)")
    plans_show.add_argument("plan_id", help="Execution plan ID (e.g. plan_...)")
    plans_show.add_argument("--tenant", default="tenant-default", help="Tenant ID")
    plans_show.add_argument("--env", default="env-prod", help="Environment ID")
    plans_show.add_argument("--db", help="SQLite DB path")

    plans_approve = plans_sub.add_parser("approve", help="Approve a pending execution plan and mint KMS-signed authorization")
    plans_approve.add_argument("plan_id", help="Execution plan ID to approve")
    plans_approve.add_argument("--approver-token", help="The approver's own access token (JWT). Default: VCF_MCP_APPROVER_TOKEN. "
                                                        "Visible in shell history: prefer --approver-token-file or the environment variable")
    plans_approve.add_argument("--approver-token-file", help="File holding the approver's own access token")
    plans_approve.add_argument("--tenant", default="tenant-default", help="Tenant ID")
    plans_approve.add_argument("--env", default="env-prod", help="Environment ID")
    plans_approve.add_argument("--db", help="SQLite DB path")

    # skills subcommand group
    safety_parser = subparsers.add_parser("safety", help="Show or change which actions the MCP may perform (local operator only)")
    safety_sub = safety_parser.add_subparsers(dest="safety_action", help="Safety actions")
    safety_sub.add_parser("show", help="Show disabled actions and read-only mode")
    safety_disable = safety_sub.add_parser("disable", help="Disable one or more tools")
    safety_disable.add_argument("tools", nargs="+", help="Tool names, e.g. vcf_power_vm")
    safety_enable = safety_sub.add_parser("enable", help="Re-enable a tool (asks for confirmation)")
    safety_enable.add_argument("tool", help="Tool name")
    safety_enable.add_argument("--yes", action="store_true", help="Skip the confirmation prompt")
    safety_ro = safety_sub.add_parser("read-only", help="Turn read-only mode on or off")
    safety_ro.add_argument("state", choices=["on", "off"])
    safety_ro.add_argument("--yes", action="store_true", help="Skip the confirmation prompt when turning it off")

    skills_parser = subparsers.add_parser("skills", help="Browse and export Single-Task Role Skills")
    skills_sub = skills_parser.add_subparsers(dest="skills_action", help="Skills actions")
    skills_list = skills_sub.add_parser("list", help="List pre-provided single-task role skills")
    skills_list.add_argument("--role", help="Filter skills by CapabilityRole (e.g. COMPUTE_OPERATOR, NETWORK_ADMIN)")

    skills_show = skills_sub.add_parser("show", help="Display full SKILL.md SOP runbook for a role skill")
    skills_show.add_argument("skill_name", help="Skill name (e.g. vcf-compute-vm-rightsize)")

    skills_export = skills_sub.add_parser("export", help="Export all role skills as SKILL.md files")
    skills_export.add_argument("--dir", default=".agents/skills", help="Output directory (default: .agents/skills)")

    cc_parser = subparsers.add_parser("client-config", help="Print a ready-to-paste MCP client configuration for an AI harness")
    cc_parser.add_argument("harness", choices=list(_HARNESSES))
    cc_parser.add_argument("--config", default=None, help="Path to the server config file (default: VCF_ENTERPRISE_MCP_CONFIG or ~/.vcf-mcp/config.yaml); a starter file is created if missing")
    cc_parser.add_argument("--db", default=None, help="Path to the control-plane database (default: ~/.vcf-mcp/control_plane.db)")
    cc_parser.add_argument("--team", action="store_true", help="Produce the team entry: a VCF_MCP_AUTH_TOKEN (identity-provider or lab token) is required for every call. "
                                                              "Default: personal mode (no token) when the config says server.access_mode: personal")
    cc_parser.add_argument("--token-from-env", action="store_true", help="Team entry: use the current VCF_MCP_AUTH_TOKEN environment variable value instead of a placeholder")

    return parser


_SERVER_NAME = "vcf-enterprise"
_TOKEN_PLACEHOLDER = "Bearer <paste your token>"
_HARNESSES = ("claude-code", "claude-desktop", "cursor", "vscode", "windsurf", "lmstudio", "codex", "gemini", "generic")

# harness -> (file location, how to reload)
_HARNESS_INFO = {
    "claude-code": ("Stored by Claude Code in ~/.claude.json (user scope).",
                    "Run /mcp inside Claude Code to check the server; start a new session if it is not listed."),
    "claude-desktop": ("macOS: ~/Library/Application Support/Claude/claude_desktop_config.json\nWindows: %APPDATA%\\Claude\\claude_desktop_config.json",
                       "Fully quit and restart Claude Desktop."),
    "cursor": ("~/.cursor/mcp.json (or .cursor/mcp.json inside a project).",
               "Open Cursor Settings > MCP and toggle the server, or restart Cursor."),
    "vscode": (".vscode/mcp.json in your workspace.",
               "Run 'MCP: List Servers' from the Command Palette and start or restart vcf-enterprise."),
    "windsurf": ("~/.codeium/windsurf/mcp_config.json",
                 "Press the refresh button in the Cascade MCP panel, or restart Windsurf."),
    "lmstudio": ("~/.lmstudio/mcp.json (or Program tab > Install > Edit mcp.json).",
                 "Save the file; LM Studio reloads it. Check the Program tab for the server."),
    "codex": ("~/.codex/config.toml", "Restart Codex (or start a new codex session)."),
    "gemini": ("~/.gemini/settings.json (user) or .gemini/settings.json (project).",
               "Restart gemini, then run /mcp to check the server."),
    "generic": ("Your client's MCP configuration file.", "Restart the client."),
}


def _vcf_mcp_executable() -> str:
    """Absolute path of the vcf-mcp launcher installed next to the running interpreter."""
    exe_name = "vcf-mcp.exe" if os.name == "nt" else "vcf-mcp"
    candidate = Path(sys.executable).parent / exe_name
    if candidate.exists():
        return str(candidate)
    found = shutil.which("vcf-mcp")
    if found:
        return str(Path(found).absolute())
    return str(candidate)


def _toml_str(value: str) -> str:
    out = []
    for ch in value:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif ord(ch) < 0x20 or ord(ch) == 0x7F:
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def _client_config_text(harness: str, command: str, env: Dict[str, str]) -> str:
    args = ["server", "--mode", "stdio"]
    if harness == "claude-code":
        parts = ["claude", "mcp", "add", _SERVER_NAME, "--scope", "user"]
        for key, value in env.items():
            parts += ["--env", f"{key}={value}"]
        parts += ["--", command] + args
        return " ".join(shlex.quote(p) for p in parts)
    if harness == "codex":
        lines = [f"[mcp_servers.{_SERVER_NAME}]",
                 f"command = {_toml_str(command)}",
                 "args = [" + ", ".join(_toml_str(a) for a in args) + "]",
                 "",
                 f"[mcp_servers.{_SERVER_NAME}.env]"]
        lines += [f"{k} = {_toml_str(v)}" for k, v in env.items()]
        return "\n".join(lines)
    entry: Dict[str, object] = {"command": command, "args": args, "env": env}
    if harness == "vscode":
        return json.dumps({"servers": {_SERVER_NAME: {"type": "stdio", **entry}}}, indent=2)
    if harness == "cursor":
        return json.dumps({"mcpServers": {_SERVER_NAME: {"type": "stdio", **entry}}}, indent=2)
    return json.dumps({"mcpServers": {_SERVER_NAME: entry}}, indent=2)


def _cmd_client_config(args: argparse.Namespace) -> int:
    """Print a ready-to-paste MCP client configuration. Never mints tokens."""
    from vcf_enterprise_mcp.config.starter import ensure_starter_config
    from vcf_enterprise_mcp.core.paths import default_config_path, default_db_path
    explicit_config = args.config or os.environ.get("VCF_ENTERPRISE_MCP_CONFIG")
    config_path = os.path.abspath(os.path.expanduser(explicit_config)) if explicit_config else str(default_config_path())
    db_path = os.path.abspath(os.path.expanduser(args.db)) if args.db else os.path.abspath(default_db_path())
    # Create the state folder and a starter config so the first server start is not "file not found": with no
    # appliance configured the server boots into setup mode and the assistant runs the guided setup.
    created = False
    try:
        created = ensure_starter_config(Path(config_path))
        Path(db_path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    except OSError as exc:
        print(f"Warning: could not prepare {config_path}: {exc}", file=sys.stderr)
    team_entry = args.team or args.token_from_env  # asking for a token means the token-based entry
    personal = False
    if not team_entry:
        try:  # an existing config decides: only a config that says access_mode: personal gets the token-free entry
            from vcf_enterprise_mcp.auth.personal import configured_access_mode
            from vcf_enterprise_mcp.config.settings import EnterpriseSettings
            personal = configured_access_mode(EnterpriseSettings.load_from_yaml(config_path)) == "personal"
        except Exception:
            personal = False
    env = {
        "VCF_ENTERPRISE_MCP_CONFIG": config_path,
        "VCF_MCP_DB_PATH": db_path,
    }
    location, reload_hint = _HARNESS_INFO[args.harness]
    notes = [f"# Where it goes: {location}".replace("\n", "\n#   "), f"# To reload: {reload_hint}"]
    notes.append(f"# Config: {'created a starter config at' if created else 'using'} {config_path} (no appliance is configured until you run the guided setup)")
    if personal:
        from vcf_enterprise_mcp.auth.personal import local_user_id
        notes.append(f"# Access: personal mode. No token is needed: the assistant acts as your local user ({local_user_id()}) and YOU approve each change")
        notes.append("#         yourself (a prompt in the chat, a local approval link, or `vcf-mcp plans approve <plan_id>` in your own terminal).")
        notes.append("#         Next: ask your assistant \"set up VCF MCP\". For shared or production use run: vcf-mcp client-config <harness> --team")
    else:
        token = _TOKEN_PLACEHOLDER
        if args.token_from_env:
            env_token = os.environ.get("VCF_MCP_AUTH_TOKEN")
            if env_token:
                token = env_token
            else:
                print("Note: VCF_MCP_AUTH_TOKEN is not set; using a placeholder.", file=sys.stderr)
        env["VCF_MCP_AUTH_TOKEN"] = token
        if not team_entry:
            notes.append("# Access: this config is in team mode (no server.access_mode: personal), so every call needs a token. For one person on their own")
            notes.append("#         machine set `server.access_mode: personal` under `server:` in the config and print this again: no token is needed.")
        if token == _TOKEN_PLACEHOLDER:
            notes.append("# Token: replace the placeholder. First-time setup needs MCP_ADMIN: vcf-mcp token mint --role MCP_ADMIN --raw")
            notes.append("#        (lab only; the starter config trusts it via idp.allow_lab_tokens). Then ask your assistant: \"set up VCF MCP\".")
            notes.append("#        For daily use mint a narrower role (e.g. VCF_VIEWER) or use a token from your identity provider.")
    # Notes go to stderr so stdout holds only the snippet and can be redirected to a file.
    print("\n".join(notes) + "\n", file=sys.stderr)
    print(_client_config_text(args.harness, _vcf_mcp_executable(), env))
    return 0


def _cmd_safety(args: argparse.Namespace) -> int:
    """Local-only control of the operator safety profile. Loosening asks for confirmation."""
    import json as _json
    from vcf_enterprise_mcp.setup.access_guide import TOOL_IMPACT
    from vcf_enterprise_mcp.setup.safety_profile import SafetyProfile
    profile = SafetyProfile.at_home()
    action = getattr(args, "safety_action", None)

    def confirm(text: str) -> bool:
        if getattr(args, "yes", False):
            return True
        if not sys.stdin.isatty():
            print("Refusing to loosen safety settings without an interactive terminal (use --yes deliberately).", file=sys.stderr)
            return False
        return input(f"{text} Type 'yes' to continue: ").strip().lower() == "yes"

    if action in (None, "show"):
        print(_json.dumps({"profile": str(profile.path), **profile.as_dict()}, indent=2))
        return 0
    if action == "disable":
        added = profile.tighten(args.tools, reason="disabled from local CLI", actor=os.environ.get("USER", "local-operator"))
        print(f"Disabled: {', '.join(added) or 'nothing new'}")
        return 0
    if action == "enable":
        impact = TOOL_IMPACT.get(args.tool)
        warn = f"'{args.tool}' {impact.summary}" if impact else f"Re-enabling '{args.tool}'."
        if not confirm(warn + " The MCP will be able to run it again (subject to roles and approvals)."):
            return 1
        profile.enable(tool=args.tool)
        print(f"Enabled: {args.tool}")
        return 0
    if action == "read-only":
        if args.state == "on":
            profile.tighten([], reason="read-only from local CLI", actor=os.environ.get("USER", "local-operator"), read_only=True)
        else:
            if not confirm("Leaving read-only mode lets the MCP request changes again (subject to roles and approvals)."):
                return 1
            profile.enable(leave_read_only=True)
        print(f"Read-only mode: {args.state}")
        return 0
    return 1


def _cmd_setup(args: argparse.Namespace) -> int:
    from pathlib import Path
    import os
    import yaml
    from vcf_enterprise_mcp.core.paths import default_config_path
    config_file = Path(getattr(args, "config", None) or os.environ.get("VCF_ENTERPRISE_MCP_CONFIG") or default_config_path())
    config_dir = config_file.parent
    config_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if args.target != "digital_twin":
        from vcf_enterprise_mcp.config.starter import ensure_starter_config
        print(f"VCF Enterprise MCP initialized at {config_dir}" if ensure_starter_config(config_file) else f"Existing configuration retained: {config_file}")
        print("Next: add the server to your harness with 'vcf-mcp client-config <harness>', then ask the assistant to \"set up VCF MCP\".")
        return 0
    template = {
        "server": {"host": "127.0.0.1", "port": 8443, "mode": "stdio",
                   "environment": "digital_twin" if args.target == "digital_twin" else "production"},
        "policy": {"operating_mode": "DISCOVERY_ONLY"},
        "idp": {"enabled": True, "allow_lab_tokens": True},
        "vcf": {"gateway_url": args.gateway_url, "verify_ssl": True},
    }
    try:
        fd = os.open(config_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        print(f"Existing configuration retained: {config_file}")
    else:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            yaml.safe_dump(template, f, sort_keys=False)
        print(f"VCF Enterprise MCP initialized at {config_dir}")
    print("Next: add the server to your harness with 'vcf-mcp client-config <harness>', then ask the assistant to \"set up VCF MCP\".")
    print("Digital Twin mode: lab tokens from 'vcf-mcp token mint' need idp.allow_lab_tokens: true in this file (or your own idp settings).")
    return 0


def _cmd_setup_automation(args: argparse.Namespace) -> int:
    from vcf_enterprise_mcp.setup.automation_account import (
        AutomationAccountSetup, SetupOptions, build_transport, resolve_config_path,
    )
    config_path = resolve_config_path(getattr(args, "config", None))
    setup = AutomationAccountSetup(lambda url: build_transport(url, args.ca_cert, config_path), config_path=config_path)
    return setup.run(SetupOptions(url=args.url, org=args.org, user=args.user, name=args.name, role=args.role,
                                  password_file=args.password_file, client_id=args.client_id, ca_cert=args.ca_cert))


def _cmd_local(args: argparse.Namespace) -> int:
    if getattr(args, "local_action", None) == "start":
        from vcf_enterprise_mcp.core.server import main as server_main
        options = {"mode": getattr(args, "mode", None)}
        if getattr(args, "insecure", False):
            options["insecure"] = True
        server_main(**options)
        return 0
    print("Running VCF Enterprise MCP local self-check...")
    from vcf_enterprise_mcp.core.protocol import EnterpriseMCPProtocolEngine
    engine = EnterpriseMCPProtocolEngine()
    tools = engine._build_raw_tool_definitions()
    print(f"Control plane online. Active tools advertised: {len(tools)}")
    return 0


def _cmd_support_bundle(args: argparse.Namespace) -> int:
    import json
    import tarfile
    from io import BytesIO
    out_path = getattr(args, "output", None) or f"vcf_mcp_support_bundle_{int(time.time())}.tar.gz"
    print(f"Generating support bundle: {out_path}...")
    with tarfile.open(out_path, "w:gz") as tar:
        info = json.dumps({
            "timestamp": time.time(),
            "python_version": sys.version,
            "platform": sys.platform,
            "version": "1.0.0",
        }, indent=2).encode("utf-8")
        ti = tarfile.TarInfo(name="system_info.json")
        ti.size = len(info)
        tar.addfile(ti, BytesIO(info))
    print(f"Support bundle written to {out_path}")
    return 0


def _cmd_certify(args: argparse.Namespace) -> int:
    from vcf_enterprise_mcp.certification.runner import CertificationRunner, load_profile
    from vcf_enterprise_mcp.adapter.capability_provider import CapabilityProviderRegistry
    profile = load_profile(args.profile)
    registry = CapabilityProviderRegistry.create_default()
    runner = CertificationRunner(registry=registry)
    result = runner.run_profile(profile, target=args.target)
    print(f"\nCertification Result for {result.profile_name} ({args.target}):")
    print(f"  Level: {result.verification_level.value}")
    print(f"  Operations: {result.total_operations} total, {result.passed_operations} passed, {result.failed_operations} failed")
    print(f"  Skipped: {result.skipped_count} (writes require the signed-plan E2E test)")
    print("  Scope: provider transport checks; not full MCP or production certification")
    print(f"  Pass Rate: {result.pass_rate:.1f}%")
    print(f"  Status: {'PASSED' if result.passed else 'FAILED'}")
    return 0 if result.passed else 1


def _cmd_certify_matrix(args: argparse.Namespace) -> int:
    from pathlib import Path
    from vcf_enterprise_mcp.certification.runner import CertificationRunner
    from vcf_enterprise_mcp.certification.report import CertificationReportGenerator
    from vcf_enterprise_mcp.adapter.capability_provider import CapabilityProviderRegistry
    registry = CapabilityProviderRegistry.create_default()
    runner = CertificationRunner(registry=registry)
    results = runner.run_all_profiles(target=args.target)
    generator = CertificationReportGenerator()
    report = generator.generate_matrix_report(results)
    if args.output:
        p = Path(args.output)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(report, encoding="utf-8")
        print(f"Certification matrix written to {args.output}")
    else:
        print(report)
    return 0


def _cmd_ga_report(args: argparse.Namespace) -> int:
    from vcf_enterprise_mcp.audit.ga_report import main as ga_report_main
    ga_report_main()
    return 0


def _cmd_token_mint(args: argparse.Namespace) -> int:
    from vcf_enterprise_mcp.auth.lab_auth import mint_lab_jwt_token, lab_tokens_allowed
    try:
        # Lab tokens have their own issuer. The server trusts it only when idp.allow_lab_tokens is on.
        issuer = getattr(args, "issuer", None)
        try:
            from vcf_enterprise_mcp.config.settings import get_enterprise_settings
            if not issuer and not lab_tokens_allowed(get_enterprise_settings().idp):
                print("Note: this token is for a lab. The server only accepts it when the config has idp.allow_lab_tokens: true "
                      "(vcf-mcp client-config creates a starter config that sets it).", file=sys.stderr)
        except Exception:
            pass
        info = mint_lab_jwt_token(
            **({"issuer": issuer} if issuer else {}),
            user_id=args.user,
            role=args.role,
            tenant_id=args.tenant,
            environment_id=args.env,
            allowed_clusters=args.cluster or ["*"],
            allowed_domains=args.domain or ["*"],
            ttl_seconds=args.ttl,
        )
    except Exception as e:
        print(f"Error minting token: {e}", file=sys.stderr)
        return 1

    if getattr(args, "raw", False):
        print(info["token"])
        return 0

    print(f"Minted local lab JWT token:")
    print(f"  Principal       : {info['user_id']}")
    print(f"  Role            : {info['role']} ({info['corporate_group']})")
    print(f"  Tenant / Env    : {info['tenant_id']} / {info['environment_id']}")
    print(f"  Allowed Clusters: {', '.join(info['allowed_clusters'])}")
    print(f"  Allowed Domains : {', '.join(info['allowed_domains'])}")
    print(f"  Signing Key     : {info['key_path']}")
    print(f"\nExport for CLI / stdio MCP:")
    print(f"  export VCF_MCP_AUTH_TOKEN=\"Bearer {info['token']}\"")
    return 0


def _cmd_init_lab(args: argparse.Namespace) -> int:
    import json
    import os
    from pathlib import Path
    import yaml
    from vcf_enterprise_mcp.auth.lab_auth import mint_lab_jwt_token
    from vcf_enterprise_mcp.auth.kms import get_kms_manager
    from vcf_enterprise_mcp.skills import get_skill_registry

    print("=== VCF Enterprise MCP — Developer Laptop & Lab Initialization ===")
    tenant_id = args.tenant or "tenant-default"
    env_id = args.env or "env-prod"

    # 1. Initialize KMS signing key & local encrypted secret store
    kms = get_kms_manager()
    registry = get_default_secret_registry()
    from vcf_enterprise_mcp.setup.access_guide import is_local_admin
    _warn_password_on_command_line(args.password)
    if is_local_admin("vcenter", args.username) or is_local_admin("sddc_manager", args.username):
        print(f"WARNING: '{args.username}' is a built-in local administrator. It gives the MCP every destructive "
              "action. Use a scoped service account, or run guided setup (vcf_setup) to see what it can reach.",
              file=sys.stderr)
    lab_password = args.password
    if not lab_password and getattr(args, "password_file", None):
        lab_password = Path(args.password_file).expanduser().read_text(encoding="utf-8").strip()
    if not lab_password and sys.stdin.isatty():
        lab_password = getpass.getpass(f"Password for {args.username} (Enter to skip; add it later with vcf_setup): ")
    cred_ref = "local://prod/sddc-lab"
    if lab_password:
        registry.store(
            cred_ref,
            SecretValue(lab_password),
            tenant_id=tenant_id,
            environment_id="env-prod",  # the environment the server resolves credentials in
            description=f"Lab credential for {args.username}",
        )
    else:
        # Never store a built-in default password. Digital Twin / testing targets need none.
        cred_ref = None

    # 2. Mint Operator and Platform Admin JWT tokens
    # Lab tokens carry the lab issuer; the config below turns on idp.allow_lab_tokens so the server accepts them.
    op_token = mint_lab_jwt_token(
        user_id=args.user,
        role=args.role,
        tenant_id=tenant_id,
        environment_id=env_id,
    )
    admin_token = mint_lab_jwt_token(
        user_id="approver-admin@lab.local",
        role="VCF_PLATFORM_ADMIN",
        tenant_id=tenant_id,
        environment_id=env_id,
    )

    # 3. Write local config.yaml
    from vcf_enterprise_mcp.core.paths import state_dir
    default_cfg_dir = state_dir()
    try:
        default_cfg_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        probe = default_cfg_dir / ".probe"
        probe.write_bytes(b"ok")
        probe.unlink(missing_ok=True)
    except OSError as exc:
        # Never fall back to the working directory: the server would not find the config there.
        print(f"Error: the MCP state folder {default_cfg_dir} is not writable ({exc}). Fix its permissions or set "
              "VCF_MCP_HOME to a private folder you own, then run init-lab again.", file=sys.stderr)
        return 1

    config_file = Path(getattr(args, "config", None) or default_cfg_dir / "config.yaml")
    config_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    cfg_payload = {
        "server": {
            "host": "127.0.0.1",
            "port": 8443,
            "mode": "stdio",
            "environment": args.target,
            "storage_mode": "LOCAL_LAB",
            # init-lab targets labs and teams: tokens for every call and a separate approver. (`client-config` writes the
            # personal-mode starter config for one person on their own machine.)
            "access_mode": "team",
        },
        "policy": {
            "operating_mode": "AUDITED_OPERATIONS",
            "require_approval_for_high_impact": True,
        },
        "idp": {
            "enabled": True,
            "issuer_url": "https://idp.corp.internal",
            "client_id": "vcf-mcp-client",
            "allow_lab_tokens": True,  # lab only: trusts the key made by `vcf-mcp token mint`
        },
        "vcf": {
            "vcenter_url": args.vcenter_url,
            "sddc_manager_url": args.sddc_url,
            "nsx_url": args.nsx_url,
            "operations_url": args.ops_url,
            "sddc_service_user": args.username,
            "verify_ssl": args.target == "real_vcf",
        },
    }
    lab_vcf = cfg_payload["vcf"]
    lab_vcf["component_usernames"] = {c: args.username for c in ("sddc_manager", "vcenter", "nsx", "vcf_operations", "vcf_automation")}
    if getattr(args, "ca_cert", None):
        lab_vcf["ca_cert_path"] = str(Path(args.ca_cert).expanduser().resolve())
        lab_vcf["verify_ssl"] = True
    if getattr(args, "allow_loopback", False):
        lab_vcf["allow_loopback_targets"] = True
    if getattr(args, "endpoints_json", None):
        eps = json.loads(Path(args.endpoints_json).expanduser().read_text(encoding="utf-8"))
        lab_vcf["endpoint_overrides"] = eps.get("endpoints", eps)
    if getattr(args, "automation_url", None):
        lab_vcf["automation_url"] = args.automation_url
        lab_vcf["automation_org"] = args.automation_org or "default"
    db_path = default_cfg_dir / "control_plane.db"
    if cred_ref:
        cfg_payload["vcf"]["credential_ref"] = cred_ref
    config_file.write_text(yaml.safe_dump(cfg_payload, sort_keys=False), encoding="utf-8")
    os.chmod(config_file, 0o600)

    # 4. Export role skills to .agents/skills if in repo
    skill_count = len(get_skill_registry().list_all_skills())

    print(f"[1/4] Local Encrypted Credential Stored : {cred_ref} (User: {args.username})" if cred_ref
          else "[1/4] No credential stored (none entered); run guided setup (vcf_setup) when you connect real appliances")
    print(f"[2/4] Local KMS Signing Key Active      : {kms.active_key_id}")
    print(f"[3/4] Lab Configuration Written         : {config_file}")
    print(f"[4/4] Single-Task Role Skills Ready     : {skill_count} role skills registered")
    print("\n--- Operator Token (" + op_token["role"] + ") ---")
    print(f"export VCF_MCP_AUTH_TOKEN=\"Bearer {op_token['token']}\"")
    print("\n--- Approver Token (VCF_PLATFORM_ADMIN) ---")
    print(f"export VCF_MCP_APPROVER_TOKEN=\"Bearer {admin_token['token']}\"")

    # GUI hosts (LM Studio, Claude Desktop) do not inherit your shell PATH or working directory:
    # use the absolute command and an absolute state database. TLS verification stays on, and
    # self-approval stays off: a human approves plans with `vcf-mcp plans approve`.
    import shutil
    # Prefer the vcf-mcp installed with this interpreter; another copy on PATH may be a different version.
    sibling = Path(sys.executable).parent / "vcf-mcp"
    exe = str(sibling) if sibling.exists() else (shutil.which("vcf-mcp") or str(Path(sys.argv[0]).resolve()))
    server_args = ["server", "--mode", "stdio"] + (["--insecure"] if not cfg_payload["vcf"]["verify_ssl"] else [])
    mcp_json = {
        "mcpServers": {
            "vcf-enterprise-mcp": {
                "command": exe,
                "args": server_args,
                "env": {
                    "VCF_ENTERPRISE_MCP_CONFIG": str(config_file),
                    "VCF_MCP_AUTH_TOKEN": f"Bearer {op_token['token']}",
                    "VCF_MCP_DB_PATH": str(db_path),
                },
            }
        }
    }
    print("\n--- Copy-Paste MCP Client Config (LM Studio mcp.json / Claude Desktop / Cursor) ---")
    print(json.dumps(mcp_json, indent=2))
    print(f"\nApprove a plan the assistant prepared (you are the human approver):\n  vcf-mcp plans approve <plan_id> --db {db_path}")
    return 0


def _approver_from_token(args: argparse.Namespace):
    """The approver is whoever the supplied token says they are; nobody is invented. Returns a Principal or None (after printing why)."""
    token = getattr(args, "approver_token", None)
    token_file = getattr(args, "approver_token_file", None)
    if not token and token_file:
        token = Path(token_file).expanduser().read_text(encoding="utf-8").strip()
    token = token or os.environ.get("VCF_MCP_APPROVER_TOKEN")
    if not token:
        print("Error: approving needs YOUR OWN access token, so the approval is attributed to you and nobody else.\n"
              "  Put it in a file and pass --approver-token-file <file>, or export VCF_MCP_APPROVER_TOKEN='Bearer <jwt>'.\n"
              "  Production: the token from your identity provider.  Lab: vcf-mcp token mint --role VCF_PLATFORM_ADMIN --user you@corp.com --raw",
              file=sys.stderr)
        return None
    if not token.lower().startswith("bearer "):
        token = f"Bearer {token}"
    from vcf_enterprise_mcp.auth.idp import EnterpriseIdPValidator
    from vcf_enterprise_mcp.auth.jwks import JWKSManager
    from vcf_enterprise_mcp.config.settings import EnterpriseSettings
    from vcf_enterprise_mcp.policy.engine import PolicyDecisionPoint
    from vcf_enterprise_mcp.workflows.execution_plans import PLAN_APPROVER_ROLES
    try:
        cfg = EnterpriseSettings.load_from_yaml()
        validator = EnterpriseIdPValidator(config=cfg.idp, jwks_manager=JWKSManager(
            default_ttl_seconds=cfg.idp.jwks_cache_ttl_seconds, allow_lab_tokens=bool(cfg.idp.allow_lab_tokens)))
        principal = validator.validate_bearer_token(token)
    except Exception as e:
        print(f"Error: the approver token was not accepted: {getattr(e, 'message', e)}", file=sys.stderr)
        return None
    roles = PolicyDecisionPoint().get_effective_roles_for_principal(principal)
    if not any(r in roles for r in PLAN_APPROVER_ROLES):
        print(f"Error: '{principal.user_id}' holds none of the approver roles "
              f"({', '.join(r.value for r in PLAN_APPROVER_ROLES)}).", file=sys.stderr)
        return None
    return principal


def _personal_settings():
    """The settings when the config is in personal access mode, None for team mode, "error" (after printing why) when
    personal mode is configured but refused here (production, HA, http)."""
    from vcf_enterprise_mcp.auth.personal import resolve_access_mode
    from vcf_enterprise_mcp.config.settings import EnterpriseSettings
    try:
        cfg = EnterpriseSettings.load_from_yaml()
    except Exception:
        return None  # an unreadable config never loosens approvals: team rules (an approver token) apply
    try:
        return cfg if resolve_access_mode(cfg) == "personal" else None
    except Exception as exc:
        print(f"Error: {getattr(exc, 'message', exc)}", file=sys.stderr)
        return "error"


def _approve_personal(cfg, store, mgr, raw_plan, db_path: str) -> int:
    """Personal access mode: the person who asked approves, in their own interactive terminal. No token; they type the plan's
    6-character code (and the target name for destructive / security-sensitive changes), so the approval is a deliberate
    human act and cannot be scripted by an assistant's shell tool."""
    import time as _time
    from vcf_enterprise_mcp.auth.personal import local_user_id
    from vcf_enterprise_mcp.core.paths import state_dir
    from vcf_enterprise_mcp.workflows.personal_approval import PersonalApproval
    pa = PersonalApproval(durable=store, user_id=local_user_id(cfg), home=state_dir(), plan_manager=mgr, db_path=db_path)
    mgr.enable_personal(pa)
    plan_id = raw_plan["plan_id"]
    if _time.time() > raw_plan["expires_at"]:
        print(f"Error: plan '{plan_id}' has expired. Ask your assistant to make a new dry run.", file=sys.stderr)
        return 1
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        url = None
        try:
            url = pa.approval_url(raw_plan)
        except Exception:
            pass
        print("Error: approve in your own terminal, in the chat prompt, or at " + (url if url else "the approval link in the dry-run result")
              + ". This command needs an interactive terminal where you can type; it will not run from a script or an assistant's shell tool.",
              file=sys.stderr)
        return 1
    info = pa.info(raw_plan)
    print(pa.render(info))
    try:
        typed = input(f"\nTo approve, type the plan code {info.short_code} (anything else cancels): ").strip()
        if typed.upper() != info.short_code:
            print("Not approved: the code did not match. Nothing was changed.", file=sys.stderr)
            return 1
        if info.requires_text and info.expected_text != info.short_code:
            typed = input(f"{info.text_prompt}: ").strip()
            if not pa.confirmation_ok(info, typed):
                print("Not approved: that did not match the target. Nothing was changed.", file=sys.stderr)
                return 1
    except (EOFError, KeyboardInterrupt):
        print("\nNot approved.", file=sys.stderr)
        return 1
    try:
        mgr.approve_plan(plan_id, pa.approver_principal(raw_plan), channel="cli")
    except Exception as e:
        print(f"Error approving plan: {getattr(e, 'message', e)}", file=sys.stderr)
        return 1
    print(f"Plan approved by {pa.user_id}. Tell your assistant to carry on: it only needs to call the tool again with the plan_id.")
    return 0


def _cmd_plans(args: argparse.Namespace) -> int:
    import json
    import os
    from vcf_enterprise_mcp.state.sqlite_store import SQLiteDurableStore
    from vcf_enterprise_mcp.workflows.execution_plans import ExecutionPlanManager
    from vcf_enterprise_mcp.auth.identity import Principal
    from vcf_enterprise_mcp.policy.models import CapabilityRole

    from vcf_enterprise_mcp.core.paths import default_db_path
    db_path = getattr(args, "db", None) or default_db_path()
    store = SQLiteDurableStore(db_path)
    tenant_id = getattr(args, "tenant", "tenant-default") or "tenant-default"
    env_id = getattr(args, "env", "env-prod") or "env-prod"
    mgr = ExecutionPlanManager(durable_store=store, tenant_id=tenant_id, environment_id=env_id)

    action = getattr(args, "plans_action", None)
    if action == "list":
        caller = Principal(
            user_id="cli-inspector@lab.local",
            tenant_id=tenant_id,
            environment_ids=(env_id,),
            roles=[CapabilityRole.VCF_PLATFORM_ADMIN],
            corporate_groups=["VCF-Platform-Admins"],
        )
        plans = mgr.list_plans(caller, status=getattr(args, "status", None))
        if not plans:
            print(f"No execution plans found in {db_path} ({tenant_id}/{env_id}).")
            return 0
        print(f"{'PLAN ID':<28} {'TOOL':<24} {'STATUS':<18} {'INITIATOR':<24} {'APPROVALS'}")
        print("-" * 108)
        for p in plans:
            app_str = f"{p['approvals_recorded']}/{p['approvals_required']}"
            print(f"{p['plan_id']:<28} {p['tool_id']:<24} {p['status']:<18} {p['principal_id']:<24} {app_str}")
        return 0

    elif action == "show":
        raw_plan = store.get_execution_plan(tenant_id, env_id, args.plan_id)
        if not raw_plan:
            print(f"Error: Plan '{args.plan_id}' not found in {db_path}.", file=sys.stderr)
            return 1
        # Read-only view as a local inspector: never as the initiator, so the single-use approval handback stays hidden.
        caller = Principal(
            user_id="cli-inspector@local",
            tenant_id=tenant_id,
            environment_ids=(env_id,),
            roles=[CapabilityRole.VCF_PLATFORM_ADMIN],
            corporate_groups=["VCF-Platform-Admins"],
        )
        details = mgr.get_plan(args.plan_id, caller)
        print(json.dumps(details, indent=2))
        return 0

    elif action == "approve":
        raw_plan = store.get_execution_plan(tenant_id, env_id, args.plan_id)
        if not raw_plan:
            print(f"Error: Plan '{args.plan_id}' not found in {db_path}.", file=sys.stderr)
            return 1
        personal_cfg = _personal_settings()
        if personal_cfg == "error":
            return 1
        if personal_cfg is not None:
            return _approve_personal(personal_cfg, store, mgr, raw_plan, db_path)
        approver = _approver_from_token(args)
        if approver is None:
            return 1
        try:
            signed = mgr.approve_plan(args.plan_id, approver)
        except Exception as e:
            print(f"Error approving plan: {e}", file=sys.stderr)
            return 1
        auth = signed.to_dict()
        summary = next((p for p in mgr.list_plans(approver) if p["plan_id"] == args.plan_id), {})
        recorded, needed = summary.get("approvals_recorded", 1), summary.get("approvals_required", 1)
        print(f"Plan approved by {approver.user_id} ({recorded}/{needed} approvals).")
        print(json.dumps(auth, indent=2))
        if recorded >= needed:
            print(f"\nPaste into the chat: approval_id={auth.get('approval_id')} nonce={auth.get('nonce')}")
        else:
            print(f"\n{needed - recorded} more DIFFERENT approver(s) must run: vcf-mcp plans approve {args.plan_id} --db {db_path}")
        return 0

    print("Specify a plans action: list, show, or approve.", file=sys.stderr)
    return 1


def _cmd_skills(args: argparse.Namespace) -> int:
    from vcf_enterprise_mcp.skills import get_skill_registry
    from vcf_enterprise_mcp.policy.models import CapabilityRole

    reg = get_skill_registry()
    action = getattr(args, "skills_action", None) or "list"
    if action == "list":
        role_filter = getattr(args, "role", None)
        if role_filter:
            role_upper = role_filter.strip().upper()
            if role_upper not in CapabilityRole.__members__:
                print(f"Error: Unknown role '{role_filter}'.", file=sys.stderr)
                return 1
            skills = reg.get_skills_for_roles([CapabilityRole[role_upper]])
        else:
            skills = reg.list_all_skills()
        print(f"{'SKILL NAME':<38} {'PRIMARY ROLE':<20} {'RISK':<12} {'ALLOWED TOOLS'}")
        print("-" * 115)
        for s in skills:
            tools_str = ", ".join(s.allowed_tools)
            print(f"{s.name:<38} {s.role.value:<20} {s.risk_class.value:<12} {tools_str}")
        print(f"\nTotal skills: {len(skills)}")
        return 0

    elif action == "show":
        skill = reg.get_skill(args.skill_name)
        if not skill:
            print(f"Error: Skill '{args.skill_name}' not found.", file=sys.stderr)
            return 1
        print(skill.to_skill_markdown())
        return 0

    elif action == "export":
        written = reg.export_skill_markdown_files(args.dir)
        print(f"Exported {len(written)} SKILL.md files to {args.dir}")
        return 0

    return 1


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "credentials":
        if args.cred_action == "add":
            return _cmd_credentials_add(args)
        elif args.cred_action == "list":
            return _cmd_credentials_list(args)
        elif args.cred_action == "test":
            return _cmd_credentials_test(args)
        elif args.cred_action == "rotate":
            return _cmd_credentials_rotate(args)
        elif args.cred_action == "delete":
            return _cmd_credentials_delete(args)
        else:
            parser.parse_args(["credentials", "--help"])
            return 1
    elif args.command == "setup":
        if getattr(args, "setup_action", None) == "automation":
            return _cmd_setup_automation(args)
        return _cmd_setup(args)
    elif args.command == "local":
        return _cmd_local(args)
    elif args.command == "support-bundle":
        return _cmd_support_bundle(args)
    elif args.command == "certify":
        return _cmd_certify(args)
    elif args.command == "certify-matrix":
        return _cmd_certify_matrix(args)
    elif args.command == "ga-report":
        return _cmd_ga_report(args)
    elif args.command == "init-lab":
        return _cmd_init_lab(args)
    elif args.command == "token":
        if getattr(args, "token_action", None) == "mint":
            return _cmd_token_mint(args)
        parser.parse_args(["token", "--help"])
        return 1
    elif args.command == "plans":
        return _cmd_plans(args)
    elif args.command == "skills":
        return _cmd_skills(args)
    elif args.command == "safety":
        return _cmd_safety(args)
    elif args.command == "client-config":
        return _cmd_client_config(args)
    elif args.command == "server" or args.command is None:
        from vcf_enterprise_mcp.core.server import main as server_main
        options = {"mode": getattr(args, "mode", None)}
        if getattr(args, "insecure", False):
            options["insecure"] = True
        server_main(**options)
        return 0
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
