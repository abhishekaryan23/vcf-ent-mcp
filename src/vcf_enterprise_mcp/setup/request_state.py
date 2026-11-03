# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Integrity-protected MRTR requestState (MCP 2026-07-28 basic/patterns/mrtr).

The client echoes requestState back verbatim, so it is attacker-controlled input.
Per the spec it is HMAC-SHA256 protected and binds the authenticated principal,
a short expiry, and the originating request (method + tool). It carries only
non-secret wizard answers; secrets never enter it.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from pathlib import Path
from typing import Any, Dict, Optional

from vcf_enterprise_mcp.core.errors import VCFEnterpriseException


class InvalidRequestStateException(VCFEnterpriseException):
    def __init__(self, reason: str):
        super().__init__(f"Setup request state rejected: {reason}. Restart setup.", error_code=-32602)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class RequestStateCodec:
    KEY_FILE = "setup_state.key"

    def __init__(self, key: Optional[bytes] = None, home: Optional[Path] = None, ttl_seconds: int = 900):
        self.ttl_seconds = ttl_seconds
        self._key = key or self._load_or_create_key(home)

    @classmethod
    def _load_or_create_key(cls, home: Optional[Path]) -> bytes:
        if home is None:
            return os.urandom(32)  # process-local; states do not survive restarts
        path = Path(home) / cls.KEY_FILE
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            key = path.read_bytes()
            if len(key) != 32:
                raise InvalidRequestStateException(f"key file {path} is corrupt")
            return key
        key = os.urandom(32)
        with os.fdopen(fd, "wb") as fh:
            fh.write(key)
        return key

    def encode(self, principal_id: str, request_binding: str, data: Dict[str, Any]) -> str:
        payload = {
            "sub": principal_id,
            "req": request_binding,
            "exp": int(time.time()) + self.ttl_seconds,
            "data": data,
        }
        body = _b64(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        sig = _b64(hmac.new(self._key, body.encode("ascii"), hashlib.sha256).digest())
        return f"{body}.{sig}"

    def decode(self, token: str, principal_id: str, request_binding: str) -> Dict[str, Any]:
        try:
            body, sig = token.split(".", 1)
        except (AttributeError, ValueError):
            raise InvalidRequestStateException("malformed")
        expected = _b64(hmac.new(self._key, body.encode("ascii"), hashlib.sha256).digest())
        if not hmac.compare_digest(expected, sig):
            raise InvalidRequestStateException("integrity check failed")
        payload = json.loads(_unb64(body))
        if payload.get("sub") != principal_id:
            raise InvalidRequestStateException("issued to a different principal")
        if payload.get("req") != request_binding:
            raise InvalidRequestStateException("issued for a different request")
        if int(payload.get("exp", 0)) < time.time():
            raise InvalidRequestStateException("expired")
        return payload.get("data") or {}
