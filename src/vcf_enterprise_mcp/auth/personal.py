# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Personal access mode: one person on their own machine.

Whoever can start the stdio server as this OS user can already read the lab signing key and the credential store
in the same state folder, so a signed token adds no security for a single local user, and a separate approver
does not exist. Personal mode therefore replaces tokens and separation of duties with:

- identity = the local OS user (`user@host`, or server.personal_user), roles from server.personal_roles;
- approval = one explicit human confirmation per plan (chat prompt, local page or the person's own terminal),
  with the target name or plan code typed for DESTRUCTIVE / SECURITY_SENSITIVE changes.

It is refused wherever more than one person could be involved: http / remote_gateway, production_mode,
VCF_MCP_ENV=production and storage_mode ENTERPRISE_HA. `team` is the default when the key is absent.
"""

from __future__ import annotations

import getpass
import os
import socket
from typing import Any, List, Optional

from vcf_enterprise_mcp.auth.identity import Principal
from vcf_enterprise_mcp.core.errors import ConfigurationException
from vcf_enterprise_mcp.policy.models import CapabilityRole

ACCESS_PERSONAL = "personal"
ACCESS_TEAM = "team"
REMOTE_MODES = ("http", "remote_gateway")


def configured_access_mode(settings: Any) -> str:
    """The access mode written in the config (absent = team). Raises for an unknown value."""
    raw = getattr(getattr(settings, "server", None), "access_mode", None)
    if raw is None or str(raw).strip() == "":
        return ACCESS_TEAM
    mode = str(raw).strip().lower()
    if mode not in (ACCESS_PERSONAL, ACCESS_TEAM):
        raise ConfigurationException(f"server.access_mode must be 'personal' or 'team', not '{raw}'.")
    return mode


def personal_refusals(settings: Any, server_mode: Optional[str] = None) -> List[str]:
    """Why personal mode must not be used with these settings (empty list = allowed)."""
    server = getattr(settings, "server", None)
    reasons: List[str] = []
    mode = (server_mode or getattr(server, "mode", "") or "").lower()
    if mode in REMOTE_MODES:
        reasons.append(f"server.mode is '{mode}' (a network listener)")
    if getattr(server, "production_mode", False):
        reasons.append("server.production_mode is true")
    if os.environ.get("VCF_MCP_ENV", "").lower() == "production":
        reasons.append("VCF_MCP_ENV=production")
    if str(getattr(server, "storage_mode", "") or "").upper() == "ENTERPRISE_HA":
        reasons.append("server.storage_mode is ENTERPRISE_HA (shared database)")
    return reasons


def resolve_access_mode(settings: Any, server_mode: Optional[str] = None) -> str:
    """'personal' or 'team'. Personal is refused (clear error) wherever more than one person could be involved."""
    mode = configured_access_mode(settings)
    if mode == ACCESS_PERSONAL:
        reasons = personal_refusals(settings, server_mode)
        if reasons:
            raise ConfigurationException(
                "server.access_mode: personal is only for one person on their own machine over stdio, and it is refused here because "
                + "; ".join(reasons) + ". Set server.access_mode: team (identity-provider or lab tokens, a separate approver) "
                "in the config file, or remove the shared/production setting.")
    return mode


def local_user_id(settings: Any = None) -> str:
    """The local identity: server.personal_user, else '<os user>@<short hostname>'."""
    explicit = getattr(getattr(settings, "server", None), "personal_user", None)
    if explicit and str(explicit).strip():
        return str(explicit).strip()
    try:
        user = getpass.getuser()
    except Exception:  # no passwd entry (containers): never fail to start
        user = "local-user"
    host = (socket.gethostname() or "localhost").split(".")[0]
    return f"{user}@{host}"


def personal_roles(settings: Any) -> List[CapabilityRole]:
    names = getattr(getattr(settings, "server", None), "personal_roles", None) or ["VCF_PLATFORM_ADMIN"]
    roles: List[CapabilityRole] = []
    for name in names:
        key = str(name).strip().upper()
        if key not in CapabilityRole.__members__:
            raise ConfigurationException(
                f"server.personal_roles has an unknown role '{name}'. Valid roles: {', '.join(CapabilityRole.__members__)}.")
        roles.append(CapabilityRole[key])
    return roles


def personal_principal(settings: Any) -> Principal:
    """The caller in personal mode: the local OS user with the configured roles and the default tenant/environment."""
    user = local_user_id(settings)
    roles = tuple(r.value for r in personal_roles(settings))
    return Principal(
        principal_id=user, user_id=user, display_name=user,
        tenant_id="tenant-default", environment_ids=("env-prod",),
        roles=roles, corporate_roles=list(roles),
        allowed_domains=["*"], allowed_clusters=["*"],
        client_ip="127.0.0.1", token_id="personal-local",
    )
