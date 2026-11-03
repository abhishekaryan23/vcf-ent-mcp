# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Background credential and approval pages for stdio MCP servers (see DetachedPortal in credential_portal.py).

    python -m vcf_enterprise_mcp.setup.portal_service <spool-dir>

Serves the one-time password pages for tickets in <spool-dir>/tickets, writes each secret to
the configured secret store (same environment as the server that started it), and exits when
no ticket has been pending for a minute, or after 30 minutes at most.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

from vcf_enterprise_mcp.setup.credential_portal import CredentialPortal, list_approval_tickets, read_ticket

IDLE_EXIT_SECONDS = 60
MAX_LIFETIME_SECONDS = 1800


def _sink(reference, secret, tenant_id, environment_id, description):
    from vcf_enterprise_mcp.secrets.registry import get_default_secret_registry
    get_default_secret_registry().store(reference, secret, tenant_id=tenant_id, environment_id=environment_id, description=description)


def _pending(spool: Path) -> bool:
    approvals = list_approval_tickets(spool)
    for t in approvals:
        if time.time() - t.expires_at > 6 * 3600:
            (spool / "approvals" / f"{t.ticket_id}.json").unlink(missing_ok=True)  # tidy old approval tickets
    if any(t.effective_status() == "PENDING" for t in approvals):
        return True
    for f in (spool / "tickets").glob("*.json"):
        t = read_ticket(spool, f.stem)
        if t is None:
            continue
        if t.effective_status() == "PENDING":
            return True
        if t.status in ("STORED", "EXPIRED", "FAILED") and time.time() - t.expires_at > 3600:
            f.unlink(missing_ok=True)  # tidy old tickets
    return False


def main(spool: Path) -> None:
    portal = CredentialPortal(sink=_sink, spool_dir=spool)
    port = portal.port
    (spool / "service.port").write_text(str(port))
    (spool / "service.pid").write_text(str(os.getpid()))
    started = last_pending = time.time()
    try:
        while time.time() - started < MAX_LIFETIME_SECONDS:
            if _pending(spool):
                last_pending = time.time()
            elif time.time() - last_pending > IDLE_EXIT_SECONDS:
                break
            time.sleep(2)
    finally:
        portal.shutdown()
        for name in ("service.port", "service.pid"):
            try:
                if name == "service.pid" and (spool / name).read_text().strip() != str(os.getpid()):
                    continue
                (spool / name).unlink()
            except OSError:
                pass


if __name__ == "__main__":
    main(Path(sys.argv[1]))
