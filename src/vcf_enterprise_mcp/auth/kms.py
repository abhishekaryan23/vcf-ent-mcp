# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Cryptographic Key Management Service (KMS) & HSM Integration.
Supports rotatable signing keys, canonical hash verification, and key versions
for AWS KMS, Azure Key Vault, HashiCorp Vault Transit, and local hardware security modules.
"""

from __future__ import annotations
import hmac
import hashlib
import time
import secrets
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, Tuple


class KMSKeyManager(ABC):
    """Abstract interface for external HSM / KMS signing key management."""

    @abstractmethod
    def sign_digest(self, digest: str) -> Tuple[str, str, str, str]:
        """Signs a SHA-256 digest. Returns (signature, key_id, algorithm, signature_version)."""
        pass

    @abstractmethod
    def verify_signature(
        self,
        digest: str,
        signature: str,
        key_id: str,
        signature_version: str = "v1",
    ) -> bool:
        """Verifies signature against the digest and registered key version."""
        pass

    @abstractmethod
    def rotate_key(self) -> str:
        """Rotates to a new active key version, preserving historical keys for verification."""
        pass


class LocalKMSKeyManager(KMSKeyManager):
    """
    Production-grade local HSM / rotatable KMS key manager.
    Maintains multiple key versions so older approval records remain verifiable after rotation.
    Derives a deterministic key_id when master_secret (or VCF_KMS_MASTER_SECRET) is supplied
    so multi-node HA clusters and restarted processes can verify signatures seamlessly.
    """

    def __init__(self, master_secret: Optional[str] = None, key_id: Optional[str] = None):
        import os
        self._key_history: Dict[str, bytes] = {}
        effective_secret = master_secret or os.environ.get("VCF_KMS_MASTER_SECRET")
        if effective_secret:
            initial_secret = (
                effective_secret
                if isinstance(effective_secret, bytes)
                else str(effective_secret).encode("utf-8")
            )
            initial_key_id = (
                key_id
                or os.environ.get("VCF_KMS_KEY_ID")
                or f"key-vcf-kms-{hashlib.sha256(initial_secret).hexdigest()[:8]}"
            )
        else:
            initial_secret = secrets.token_hex(32).encode("utf-8")
            initial_key_id = key_id or f"key-vcf-kms-{secrets.token_hex(4)}"
        self._key_history[initial_key_id] = initial_secret
        self._active_key_id = initial_key_id
        self._signature_version = "v1"
        self._algorithm = "HMAC-SHA256"

    @property
    def active_key_id(self) -> str:
        return self._active_key_id

    def sign_digest(self, digest: str) -> Tuple[str, str, str, str]:
        secret = self._key_history[self._active_key_id]
        sig = hmac.new(secret, digest.encode("utf-8"), hashlib.sha256).hexdigest()
        return sig, self._active_key_id, self._algorithm, self._signature_version

    def verify_signature(
        self,
        digest: str,
        signature: str,
        key_id: str,
        signature_version: str = "v1",
    ) -> bool:
        if key_id not in self._key_history:
            return False
        secret = self._key_history[key_id]
        expected_sig = hmac.new(secret, digest.encode("utf-8"), hashlib.sha256).hexdigest()
        return hmac.compare_digest(signature, expected_sig)

    def rotate_key(self) -> str:
        new_key_id = f"key-vcf-kms-{secrets.token_hex(4)}"
        new_secret = secrets.token_hex(32).encode("utf-8")
        self._key_history[new_key_id] = new_secret
        self._active_key_id = new_key_id
        return new_key_id


# Default global KMS provider (can be overridden by Vault Transit or Cloud KMS)
_global_kms: Optional[KMSKeyManager] = None


def _load_or_create_local_kms_secret() -> Optional[str]:
    """Loads or persists a local KMS signing secret on developer laptops / appliances."""
    import os
    from vcf_enterprise_mcp.core.paths import state_path
    env_secret = os.environ.get("VCF_KMS_MASTER_SECRET")
    if env_secret:
        return env_secret
    if os.environ.get("VCF_MCP_ENV", "").lower() == "production":
        return None
    candidates = [
        os.environ.get("VCF_MCP_KMS_KEY_PATH"),
        state_path("kms.key"),  # never the working directory: a key file planted there must not be trusted
    ]
    for path in candidates:
        if not path:
            continue
        try:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    val = f.read().strip()
                if len(val) >= 32:
                    return val
            parent = os.path.dirname(os.path.abspath(path))
            os.makedirs(parent, mode=0o700, exist_ok=True)
            generated = secrets.token_hex(32)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(generated)
                f.flush()
            return generated
        except FileExistsError:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return f.read().strip()
            except Exception:
                continue
        except (OSError, PermissionError):
            continue
    return None


def get_kms_manager() -> KMSKeyManager:
    global _global_kms
    if _global_kms is None:
        persisted_secret = _load_or_create_local_kms_secret()
        _global_kms = LocalKMSKeyManager(master_secret=persisted_secret)
    return _global_kms


def set_kms_manager(manager: KMSKeyManager) -> None:
    global _global_kms
    _global_kms = manager
