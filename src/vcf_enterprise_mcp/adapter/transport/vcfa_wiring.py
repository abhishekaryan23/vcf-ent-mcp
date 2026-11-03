# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Builds the upstream authentication for VCF Automation and its embedded/standalone Orchestrator from
the ``vcf.*`` settings. Kept out of core/server.py so the wiring is testable on its own.

The service-account refresh token is a secret-store entry (credential component ``vcf_automation``);
VCF Automation rotates it on every use, so each rotated token is written back to the same entry.
"""

from __future__ import annotations

from typing import Any, Callable, Optional, Tuple

from vcf_enterprise_mcp.adapter.transport.base import BaseTransport
from vcf_enterprise_mcp.adapter.transport.vcf_sessions import (
    OrchestratorBasicAuth,
    VCFASessionAuth,
    VCFAutomationTokenAuth,
)

ORCHESTRATOR_AUTH_MODES = ("automation_token", "basic", "vcfa_session")


def build_automation_auth(
    vcf: Any,
    transport: BaseTransport,
    supplier: Callable[[str], Callable[[], Tuple[str, str]]],
    persist_refresh_token: Optional[Callable[[str], None]],
    timeout: float,
):
    """Returns (automation, orchestrator): ``automation`` is (url, auth) or None; ``orchestrator`` is
    (url, auth) or None. Raises ValueError with an actionable message for an unusable configuration."""
    mode = getattr(vcf, "orchestrator_auth", "automation_token") or "automation_token"
    if mode not in ORCHESTRATOR_AUTH_MODES:
        raise ValueError(f"vcf.orchestrator_auth must be one of {', '.join(ORCHESTRATOR_AUTH_MODES)} (got '{mode}')")
    automation_url = vcf.automation_url
    org = vcf.automation_org
    orch_url = vcf.orchestrator_url or automation_url

    token_auth = None
    if automation_url:
        if not org:
            raise ValueError("vcf.automation_url needs vcf.automation_org (the VCF Automation organization name)")
        token_auth = VCFAutomationTokenAuth(
            automation_url, transport, supplier("vcf_automation"), timeout_seconds=timeout, tenant=org,
            client_id=getattr(vcf, "automation_client_id", None), on_refresh_token=persist_refresh_token)
    automation = (automation_url, token_auth) if token_auth else None
    if not orch_url:
        return automation, None

    # Credential for the Orchestrator login: a dedicated one when configured, else the VCF Automation one.
    refs = vcf.component_credential_refs
    cred_key = "vcf_orchestrator" if "vcf_orchestrator" in refs else "vcf_automation"
    base_supplier = supplier(cred_key)

    def orch_credentials() -> Tuple[str, str]:
        user, secret = base_supplier()
        if cred_key not in vcf.component_usernames and vcf.component_usernames.get("vcf_automation"):
            user = vcf.component_usernames["vcf_automation"]
        return user, secret

    if mode == "basic":
        return automation, (orch_url, OrchestratorBasicAuth(orch_credentials))
    if mode == "vcfa_session":
        if not org:
            raise ValueError("vcf.orchestrator_auth: vcfa_session needs vcf.automation_org (the organization to log in to)")
        return automation, (orch_url, VCFASessionAuth(vcf.automation_url or orch_url, transport, orch_credentials,
                                                      timeout_seconds=timeout, tenant=org))
    # automation_token: the token is issued by VCF Automation, whatever host Orchestrator is on, so a
    # standalone orchestrator_url shares the VCF Automation token auth (and its single refresh-token chain).
    if token_auth is not None:
        return automation, (orch_url, token_auth)
    if not org:
        raise ValueError("vcf.orchestrator_url without vcf.automation_url needs vcf.automation_org (the organization "
                         "that issues the token), or set vcf.orchestrator_auth: basic")
    return automation, (orch_url, VCFAutomationTokenAuth(
        orch_url, transport, supplier("vcf_automation"), timeout_seconds=timeout, tenant=org,
        client_id=getattr(vcf, "automation_client_id", None), on_refresh_token=persist_refresh_token))
