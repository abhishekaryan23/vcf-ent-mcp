# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Remembers every workflow and action saved through the MCP, per Orchestrator URL, in
~/.vcf-mcp/orch_changes.json (VCF_MCP_HOME or VCF_MCP_ORCH_CHANGES_FILE override the location).

Ported from changes.ts in vcf-orchestrator-mcp by imtrinity94 (MIT), see THIRD_PARTY_NOTICES.md.
The file is written atomically with mode 0600. It holds names, ids and versions only: no
scripts, no secrets. Failing to write it never fails a save.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


def default_path() -> Path:
    override = os.environ.get("VCF_MCP_ORCH_CHANGES_FILE")
    if override:
        return Path(override).expanduser()
    return Path(os.environ.get("VCF_MCP_HOME") or (Path.home() / ".vcf-mcp")) / "orch_changes.json"


class ChangeTracker:
    def __init__(self, host: str, path: Optional[Path] = None):
        self.host = host.rstrip("/").lower()
        self.path = Path(path) if path else default_path()

    def _read(self) -> Dict[str, List[Dict[str, Any]]]:
        try:
            data = json.loads(self.path.read_text())
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _write(self, data: Dict[str, Any]) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd, tmp = tempfile.mkstemp(prefix=self.path.name + ".", suffix=".tmp", dir=str(self.path.parent))
            try:
                with os.fdopen(fd, "w") as fh:
                    json.dump(data, fh, indent=2)
                os.chmod(tmp, 0o600)
                os.replace(tmp, self.path)
            except Exception:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise
        except OSError:
            pass  # tracking is a convenience; never fail a save because of it

    def list(self) -> List[Dict[str, Any]]:
        return list(self._read().get(self.host, []))

    def record(self, kind: str, item_id: str, name: str, version: Optional[str] = None, folder: Optional[str] = None,
               changeset_sha: Optional[str] = None) -> None:
        data = self._read()
        items = [x for x in data.get(self.host, []) if not (x.get("kind") == kind and x.get("id") == item_id)]
        entry = {"kind": kind, "id": item_id, "name": name, "saved_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        for k, v in (("version", version), ("folder", folder), ("changeset_sha", changeset_sha)):
            if v:
                entry[k] = v
        items.append(entry)
        data[self.host] = items
        self._write(data)

    def forget(self, ids: Optional[List[str]] = None) -> None:
        data = self._read()
        data[self.host] = [x for x in data.get(self.host, []) if ids is not None and x.get("id") not in ids]
        self._write(data)
