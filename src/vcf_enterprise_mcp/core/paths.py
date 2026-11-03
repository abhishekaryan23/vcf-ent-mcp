# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
One state directory for everything the MCP keeps on disk: ~/.vcf-mcp (override with VCF_MCP_HOME).

Holds config.yaml, control_plane.db, safety_profile.json, access_report.json, the encrypted credential
store (master.key, credentials.json), the KMS signing secret (kms.key) and the lab token key.

Earlier versions used ~/.vcf_mcp for some of these files. When the default directory is in use and the old
one exists, missing files are copied across once (never overwritten, permissions kept), so nothing is lost.
"""

from __future__ import annotations

import logging
import os
import shutil
from pathlib import Path

logger = logging.getLogger(__name__)

LEGACY_DIR_NAME = ".vcf_mcp"
DIR_NAME = ".vcf-mcp"
_migrated = False


def state_dir() -> Path:
    """The state directory (created on demand by writers, not here)."""
    explicit = os.environ.get("VCF_MCP_HOME")
    if explicit:
        return Path(explicit).expanduser()
    new = Path.home() / DIR_NAME
    _migrate_legacy(new)
    return new


def state_path(name: str) -> str:
    return str(state_dir() / name)


LEGACY_DB_NAME = "vcf_control_plane.db"  # versions before 2026-11 created this in the working directory


def default_db_path() -> str:
    """Absolute default for the control-plane database, so servers launched from any working directory agree."""
    explicit = os.environ.get("VCF_MCP_DB_PATH")
    if explicit:
        return explicit
    path = state_path("control_plane.db")
    _adopt_legacy_db(path)
    return path


def _adopt_legacy_db(path: str) -> None:
    """Older versions wrote ./vcf_control_plane.db wherever the server was started. Copy that file (with its
    plans and audit chain) once into the state folder, so upgrading never loses history; the old file is left
    in place and is no longer used."""
    legacy = Path.cwd() / LEGACY_DB_NAME
    target = Path(path)
    if target.exists() or not legacy.is_file():
        return
    try:
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        for suffix in ("", "-wal", "-shm"):
            src = Path(str(legacy) + suffix)
            if src.is_file():
                shutil.copy2(src, str(target) + suffix)
        os.chmod(target, 0o600)
        logger.info("Copied the old %s from %s to %s; the old file is no longer used.", LEGACY_DB_NAME, legacy.parent, target)
    except OSError:
        pass  # best effort: the server starts with a fresh database


def default_config_path() -> Path:
    return state_dir() / "config.yaml"


def _migrate_legacy(new: Path) -> None:
    global _migrated
    legacy = Path.home() / LEGACY_DIR_NAME
    if _migrated or not legacy.is_dir():
        _migrated = True
        return
    _migrated = True
    try:
        new.mkdir(parents=True, exist_ok=True, mode=0o700)
        for item in legacy.iterdir():
            target = new / item.name
            if item.is_file() and not target.exists():
                shutil.copy2(item, target)
    except OSError:
        pass  # best effort: an unreadable legacy dir must never stop the server
