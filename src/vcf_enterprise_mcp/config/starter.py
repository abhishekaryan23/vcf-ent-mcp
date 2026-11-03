# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Starter configuration: what `vcf-mcp client-config` and a first server start create when no config file exists.

It deliberately names no appliance. With no appliance configured the server starts in setup mode (only the
setup tools are served) and the guided setup (vcf_setup) fills in the real endpoints.
"""

from __future__ import annotations

import os
from pathlib import Path

STARTER_CONFIG = """\
# VCF Enterprise MCP configuration (created automatically; unofficial community project, under testing).
#
# No VCF appliance is configured yet, so the server starts in SETUP MODE: it serves only the setup tools.
# Ask your assistant to "set up VCF MCP" (it calls vcf_setup); setup writes the endpoints here and the
# server applies them without a restart. You can also edit this file by hand; see docs/guided_setup.md.

server:
  mode: stdio
  host: 127.0.0.1              # only used by `vcf-mcp server --mode http` (plain HTTP; put a TLS gateway in front of it)
  port: 8443
  environment: production      # real VCF appliances (use digital_twin for the simulator)
  production_mode: false       # true = strict production: no lab tokens, no loopback targets, no test keys
  # personal = one person on their own machine: no access token is needed (you are your local user) and YOU confirm
  # each change in a chat prompt, on a local page or in your own terminal. Refused for http, production_mode,
  # VCF_MCP_ENV=production and ENTERPRISE_HA. For shared use set `team` (identity-provider tokens, a separate approver).
  access_mode: personal
  # personal_roles: [VCF_PLATFORM_ADMIN]   # who you are acting as; guided setup narrows this to what you asked for

idp:
  # Only used in team mode, or if a client sends a token anyway. LAB ONLY: accept tokens made with
  # `vcf-mcp token mint` (issuer urn:vcf-mcp:lab). For real shared use set idp.issuer_url, idp.client_id and
  # idp.jwks_uri to your IdP, then set allow_lab_tokens: false.
  allow_lab_tokens: true

policy:
  operating_mode: DISCOVERY_ONLY   # read-only until you choose AUDITED_OPERATIONS yourself

vcf: {}
"""


def ensure_starter_config(path: Path) -> bool:
    """Creates the starter config (mode 0600, directory 0700) when the file is missing. True if it was created."""
    path = Path(path)
    if path.exists():
        return False
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return False
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(STARTER_CONFIG)
    return True
