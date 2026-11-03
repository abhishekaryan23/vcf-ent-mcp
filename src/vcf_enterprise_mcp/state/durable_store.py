# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Durable State Store for Enterprise VCF MCP Control Plane.
Supports dual deployment profiles:
- MODE A — Appliance MCP: Local SQLite WAL (single appliance / edge / single-node).
- MODE B — Enterprise HA: Real SQL Persistence with ACID transactions, outbox, and row-level locking.

Re-exports core store interfaces and classes from modular state components.
"""

from __future__ import annotations
import os
from typing import Optional, Dict, Any

from vcf_enterprise_mcp.state.base_store import DurableStore as _BaseDurableStore, ResourceLease
from vcf_enterprise_mcp.state.sqlite_store import SQLiteDurableStore
from vcf_enterprise_mcp.state.postgres_store import PostgresDurableStore


class DurableStore(_BaseDurableStore):
    """
    Abstract interface for enterprise durable control plane state.
    Instantiating DurableStore(...) directly yields SQLiteDurableStore for backward compatibility.
    """

    def __new__(cls, *args, **kwargs):
        if cls is DurableStore:
            # Check operating mode from environment if not explicitly specified
            mode = os.environ.get("VCF_STORAGE_MODE", "APPLIANCE").upper()
            if mode == "ENTERPRISE_HA":
                dsn = os.environ.get("VCF_POSTGRES_DSN")
                if not dsn:
                    raise ValueError(
                        "Missing required environment variable 'VCF_POSTGRES_DSN' for ENTERPRISE_HA mode. "
                        "Fallback database passwords are forbidden in production."
                    )
                return PostgresDurableStore(connection_uri=dsn)
            return SQLiteDurableStore(*args, **kwargs)
        return super().__new__(cls)


def get_durable_store(profile: str = "appliance", **kwargs) -> _BaseDurableStore:
    """Factory helper returning appropriate durable store instance based on deployment profile."""
    if profile.lower() in ("enterprise_ha", "ha", "postgres"):
        pool = kwargs.get("pool")
        uri = kwargs.get("connection_uri") or os.environ.get("VCF_POSTGRES_DSN")
        if not pool and not uri:
            raise ValueError(
                "Missing required 'VCF_POSTGRES_DSN' or connection_uri for Enterprise HA PostgreSQL store."
            )
        return PostgresDurableStore(connection_uri=uri or "postgresql://localhost/mock", pool=pool)
    return SQLiteDurableStore(db_path=kwargs.get("db_path", ":memory:"))


__all__ = [
    "DurableStore",
    "ResourceLease",
    "SQLiteDurableStore",
    "PostgresDurableStore",
    "get_durable_store",
]
