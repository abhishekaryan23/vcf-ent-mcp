# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Operator safety profile: tools the operator has switched off for this installation.

Enforced by the PEP on top of identity/role policy, both in tools/list and at
execution. Through MCP (the guided setup tool) the profile can only be
TIGHTENED; re-enabling a tool requires the local CLI
(`vcf-mcp safety enable <tool>`), so a model or prompt injection
cannot widen what the agent is allowed to do.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


def default_home() -> Path:
    from vcf_enterprise_mcp.core.paths import state_dir
    return state_dir()


class SafetyProfile:
    FILE_NAME = "safety_profile.json"

    def __init__(self, path: Optional[Path] = None):
        self.path = Path(path) if path else None
        self._lock = threading.Lock()
        self.disabled_tools: Dict[str, Dict[str, Any]] = {}
        self.read_only: bool = False
        if self.path and self.path.exists():
            self._load()

    @classmethod
    def at_home(cls, home: Optional[Path] = None) -> "SafetyProfile":
        return cls((home or default_home()) / cls.FILE_NAME)

    def _load(self) -> None:
        data = json.loads(self.path.read_text(encoding="utf-8"))
        self.disabled_tools = dict(data.get("disabled_tools", {}))
        self.read_only = bool(data.get("read_only", False))

    def _save(self) -> None:
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        payload = json.dumps({"read_only": self.read_only, "disabled_tools": self.disabled_tools}, indent=2, sort_keys=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".safety-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(payload)
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise

    # ---- queries -----------------------------------------------------------------

    def is_tool_disabled(self, tool_name: str, risk_class: Optional[str] = None) -> bool:
        if tool_name in self.disabled_tools:
            return True
        return self.read_only and risk_class not in (None, "READ")

    def disabled_reason(self, tool_name: str) -> Optional[str]:
        entry = self.disabled_tools.get(tool_name)
        if entry:
            return entry.get("reason")
        return "installation is in read-only mode" if self.read_only else None

    def as_dict(self) -> Dict[str, Any]:
        return {"read_only": self.read_only, "disabled_tools": dict(self.disabled_tools)}

    # ---- mutation ----------------------------------------------------------------

    def tighten(self, tools: Iterable[str], reason: str, actor: str, read_only: Optional[bool] = None) -> List[str]:
        """Disable tools (and optionally enter read-only mode). Never re-enables anything."""
        added: List[str] = []
        with self._lock:
            for tool in tools:
                if tool not in self.disabled_tools:
                    self.disabled_tools[tool] = {"reason": reason, "by": actor, "at": int(time.time())}
                    added.append(tool)
            if read_only:
                self.read_only = True
            self._save()
        return added

    def enable(self, tool: Optional[str] = None, leave_read_only: bool = False) -> None:
        """Local-CLI only: re-enable a tool, or leave read-only mode."""
        with self._lock:
            if tool:
                self.disabled_tools.pop(tool, None)
            if leave_read_only:
                self.read_only = False
            self._save()
