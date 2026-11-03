# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Local Encrypted Secret Provider.
Implements authenticated encryption (AES-256-GCM) with key protection
for developer workstations, customer lab environments, Digital Twin, and PoCs.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
import threading
import time
from typing import Any, Dict, List, Optional

from vcf_enterprise_mcp.core.paths import state_path
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)

from vcf_enterprise_mcp.core.errors import ConfigurationException
from vcf_enterprise_mcp.secrets.base import (
    SecretProvider,
    MissingCredentialException,
    CredentialDecryptionException,
    CredentialPolicyViolationException,
)
from vcf_enterprise_mcp.secrets.models import (
    SecretValue,
    SecretProviderHealth,
    SecretMetadata,
)



def _state_dir_error(path: str, exc: BaseException) -> str:
    return (f"The MCP state folder {path} is not writable ({exc.__class__.__name__}: {exc}). "
            "Fix its permissions, or point VCF_MCP_HOME at a private folder you own, then start the server again.")

class LocalKeyProtector:
    """
    Manages the master key used to encrypt and decrypt local secrets.
    Ensures master key is never stored in plaintext adjacent to credentials.db.
    """

    def __init__(self, key_file_path: Optional[str] = None):
        default_key = os.environ.get("VCF_MCP_MASTER_KEY_PATH")
        if not default_key:
            home_key = state_path("master.key")
            try:
                os.makedirs(os.path.dirname(home_key), exist_ok=True)
                # Verify read/write access to home_key or its parent directory
                if os.path.exists(home_key):
                    with open(home_key, "rb") as _f:
                        _f.read(1)
                elif not os.access(os.path.dirname(home_key), os.R_OK | os.W_OK):
                    raise PermissionError("Home .vcf-mcp directory is not readable/writable.")
                default_key = home_key
            except (OSError, PermissionError) as exc:
                raise PermissionError(_state_dir_error(os.path.dirname(home_key), exc)) from exc
        self._key_file_path = key_file_path or default_key
        self._master_key: Optional[bytes] = None
        self._source: str = "UNINITIALIZED"
        self._key_id: str = "machine-key-v1"

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def source(self) -> str:
        return self._source

    def set_master_key(self, key: bytes, source: str = "MANUAL", key_id: str = "custom-key-v1") -> None:
        """Sets master key in memory."""
        if len(key) != 32:
            raise ValueError(f"AES-256 requires 32-byte key, got {len(key)} bytes.")
        self._master_key = key
        self._source = source
        self._key_id = key_id

    def get_master_key(self, environment_name: str = "lab") -> bytes:
        """
        Retrieves or derives the 32-byte master encryption key.
        Refuses to generate an unprotected plaintext key in production environments.
        """
        if self._master_key is not None:
            return self._master_key

        # 1. Environment variable fallback (explicitly marked LAB_ONLY)
        env_key = os.environ.get("VCF_LOCAL_MASTER_KEY")
        if env_key:
            # Decode hex, base64, or derive via sha256
            if len(env_key) == 64:
                try:
                    self._master_key = bytes.fromhex(env_key)
                except ValueError:
                    self._master_key = hashlib.sha256(env_key.encode("utf-8")).digest()
            else:
                try:
                    raw = base64.b64decode(env_key)
                    if len(raw) == 32:
                        self._master_key = raw
                    else:
                        self._master_key = hashlib.sha256(env_key.encode("utf-8")).digest()
                except Exception:
                    self._master_key = hashlib.sha256(env_key.encode("utf-8")).digest()

            self._source = "LAB_ONLY_ENV"
            self._key_id = f"env-key-{hashlib.sha256(self._master_key).hexdigest()[:8]}"
            return self._master_key

        # 2. Check protected file store
        if os.path.exists(self._key_file_path):
            try:
                # Verify file permissions on POSIX
                if hasattr(os, "stat"):
                    st = os.stat(self._key_file_path)
                    # Enforce strict 0600 on POSIX
                    if hasattr(st, "st_mode") and (st.st_mode & 0o077) != 0:
                        raise ConfigurationException(
                            f"Insecure permissions on master key file '{self._key_file_path}': must be restricted to 0600."
                        )
                with open(self._key_file_path, "rb") as f:
                    data = f.read()
                if len(data) == 32:
                    self._master_key = data
                else:
                    raise ConfigurationException("Master key file must contain exactly 32 binary bytes.")
                self._source = "PROTECTED_KEY_FILE"
                self._key_id = f"file-key-{hashlib.sha256(self._master_key).hexdigest()[:8]}"
                return self._master_key
            except Exception as e:
                if isinstance(e, ConfigurationException):
                    raise
                raise ConfigurationException("Cannot read local master key file.") from e

        # 3. Production safety gate
        if environment_name.lower() == "production":
            raise ConfigurationException(
                "Production safety failure: Unprotected local encryption key generation is forbidden. "
                "Configure a secure master key or connect an enterprise secret manager (Vault, Azure Key Vault, AWS Secrets Manager)."
            )

        # 4. Ephemeral / Lab generation: cryptographically random 256-bit key (F09, R06)
        # Predictable derivation from hostname/user is strictly eliminated
        random_key = secrets.token_bytes(32)
        target_path = self._key_file_path
        try:
            os.makedirs(os.path.dirname(os.path.abspath(target_path)), mode=0o700, exist_ok=True)
            # Never overwrite an existing key, including during concurrent startup.
            fd = os.open(target_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(random_key)
                f.flush()
                os.fsync(f.fileno())
        except FileExistsError:
            return self.get_master_key(environment_name)
        except OSError as e:
            raise ConfigurationException("Cannot persist local master key; credentials were not encrypted.") from e
        self._master_key = random_key
        self._source = "PROTECTED_KEY_FILE"
        self._key_id = f"file-key-{hashlib.sha256(random_key).hexdigest()[:8]}"

        return self._master_key


class LocalEncryptedSecretProvider:
    """
    Self-contained local encrypted credential provider using authenticated AES-256-GCM.
    Supports reference format: local://environment/subsystem or local://prod/vcenter
    """

    provider_name: str = "local_encrypted"

    def __init__(
        self,
        storage_path: Optional[str] = None,
        key_protector: Optional[LocalKeyProtector] = None,
        in_memory_only: bool = False,
    ):
        default_path = os.environ.get("VCF_MCP_CREDENTIALS_PATH")
        if not default_path:
            home_path = state_path("credentials.json")
            try:
                os.makedirs(os.path.dirname(home_path), mode=0o700, exist_ok=True)
                if os.path.exists(home_path):
                    with open(home_path, "r", encoding="utf-8") as _f:
                        _f.read(1)
                elif not os.access(os.path.dirname(home_path), os.R_OK | os.W_OK):
                    raise PermissionError("Home .vcf-mcp directory is not readable/writable.")
                default_path = home_path
            except (OSError, PermissionError) as exc:
                raise PermissionError(_state_dir_error(os.path.dirname(home_path), exc)) from exc
        self._storage_path = storage_path or default_path
        self._key_protector = key_protector or LocalKeyProtector()
        self._in_memory_only = in_memory_only
        self._lock = threading.Lock()
        self._store: Dict[str, Dict[str, Any]] = {}
        if not in_memory_only and os.path.exists(self._storage_path):
            self._load_from_disk()

    def _normalize_ref(self, reference: str) -> str:
        ref = reference.strip()
        if not ref.startswith("local://"):
            raise ValueError(f"Invalid reference scheme for LocalEncryptedSecretProvider: {reference}")
        return ref

    def _load_from_disk(self) -> None:
        try:
            self._disk_mtime = os.path.getmtime(self._storage_path)
            with open(self._storage_path, "r", encoding="utf-8") as f:
                self._store = json.load(f)
        except Exception:
            self._store = {}

    def _refresh_if_changed(self) -> None:
        """Pick up credentials another process added (e.g. `vcf-mcp credentials add` while the server runs)."""
        if self._in_memory_only:
            return
        try:
            mtime = os.path.getmtime(self._storage_path)
        except OSError:
            return
        if mtime != getattr(self, "_disk_mtime", None):
            self._load_from_disk()

    def _write_atomic(self, path: str) -> None:
        """Write the store to a private temp file, fsync it, then rename over the target, so a crash or a
        concurrent reader never sees a truncated file (rotated refresh tokens depend on this)."""
        dirname = os.path.dirname(os.path.abspath(path))
        os.makedirs(dirname, mode=0o700, exist_ok=True)
        tmp = f"{path}.{os.getpid()}.{threading.get_ident()}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self._store, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def _save_to_disk(self) -> None:
        if self._in_memory_only:
            return
        try:
            self._write_atomic(self._storage_path)
            self._disk_mtime = os.path.getmtime(self._storage_path)
        except (OSError, PermissionError) as exc:
            # Never fall back to the working directory: secrets would end up split across folders.
            raise PermissionError(_state_dir_error(os.path.dirname(os.path.abspath(self._storage_path)), exc)) from exc

    def resolve(
        self,
        reference: str,
        *,
        tenant_id: str = "tenant-default",
        environment_id: str = "env-prod",
        request_context: Optional[Any] = None,
        **kwargs: Any,
    ) -> SecretValue:
        """
        Resolves and decrypts a local secret reference using AES-256-GCM.
        Validates authentication tag, tenant boundary, and reference integrity.
        """
        norm_ref = self._normalize_ref(reference)
        with self._lock:
            self._refresh_if_changed()
            record = self._store.get(norm_ref)
            if not record:
                raise MissingCredentialException(
                    f"Local encrypted credential '{norm_ref}' not found in secret store."
                )

        stored_tenant = record.get("tenant_id")
        stored_env = record.get("environment_id")
        if stored_tenant and stored_tenant != tenant_id:
            raise CredentialPolicyViolationException(
                f"Cross-tenant access violation: Secret '{norm_ref}' is owned by tenant '{stored_tenant}', caller requested as '{tenant_id}'."
            )
        if stored_env and stored_env != environment_id:
            raise CredentialPolicyViolationException(
                f"Cross-environment access violation: Secret '{norm_ref}' is bound to environment '{stored_env}', caller requested as '{environment_id}'."
            )

        # Retrieve key and decrypt
        master_key = self._key_protector.get_master_key(environment_id)
        aesgcm = AESGCM(master_key)

        try:
            nonce = base64.b64decode(record["nonce"])
            ciphertext = base64.b64decode(record["ciphertext"])
            associated_data = f"{norm_ref}:{stored_tenant or tenant_id}:{stored_env or environment_id}".encode("utf-8")

            # AES-GCM decrypt validates the 16-byte authentication tag and tenant binding
            plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, associated_data)
            plaintext = plaintext_bytes.decode("utf-8")
            return SecretValue(plaintext)
        except InvalidTag:
            raise CredentialDecryptionException(
                f"Decryption failed for '{norm_ref}': Authentication tag mismatch, wrong tenant context, or ciphertext was tampered with."
            )
        except Exception as e:
            if isinstance(e, (CredentialPolicyViolationException, CredentialDecryptionException)):
                raise
            raise CredentialDecryptionException(
                f"Failed to decrypt credential '{norm_ref}': {str(e)}"
            )

    def store(
        self,
        reference: str,
        secret: SecretValue,
        *,
        tenant_id: str = "tenant-default",
        environment_id: str = "env-prod",
        description: Optional[str] = None,
    ) -> None:
        """
        Encrypts a secret using AES-256-GCM and persists the record with tenant-bound AAD.
        """
        norm_ref = self._normalize_ref(reference)
        master_key = self._key_protector.get_master_key(environment_id)
        key_id = self._key_protector.key_id
        aesgcm = AESGCM(master_key)

        nonce = os.urandom(12)  # 96-bit standard AES-GCM nonce
        plaintext_bytes = secret.reveal().encode("utf-8")
        associated_data = f"{norm_ref}:{tenant_id}:{environment_id}".encode("utf-8")
        ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, associated_data)

        now = time.time()
        record: Dict[str, Any] = {
            "version": 1,
            "reference": norm_ref,
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "created_at": now,
            "updated_at": now,
            "key_id": key_id,
            "tenant_id": tenant_id,
            "environment_id": environment_id,
            "description": description or f"Local encrypted secret for {norm_ref}",
        }

        with self._lock:
            self._refresh_if_changed()  # never drop a credential another process just added
            self._store[norm_ref] = record
            self._save_to_disk()

    def delete(
        self,
        reference: str,
        *,
        tenant_id: str = "tenant-default",
        environment_id: str = "env-prod",
    ) -> None:
        """Deletes a secret record with strict tenant and environment ownership checks (Finding F02 / R07)."""
        norm_ref = self._normalize_ref(reference)
        with self._lock:
            rec = self._store.get(norm_ref)
            if rec:
                rec_tenant = rec.get("tenant_id")
                rec_env = rec.get("environment_id")
                if rec_tenant and rec_tenant != tenant_id and tenant_id != "*":
                    return
                if rec_env and rec_env != environment_id and environment_id != "*":
                    return

                del self._store[norm_ref]
                self._save_to_disk()

    def list_references(
        self,
        *,
        tenant_id: str = "tenant-default",
        environment_id: str = "env-prod",
    ) -> List[SecretMetadata]:
        """Lists metadata of stored secrets scoped strictly by tenant and environment (Finding F02 / R07)."""
        with self._lock:
            records = [
                r for r in self._store.values()
                if (r.get("tenant_id") == tenant_id or tenant_id == "*")
                and (r.get("environment_id") == environment_id or environment_id == "*")
            ]

        results: List[SecretMetadata] = []
        for r in records:
            results.append(
                SecretMetadata(
                    reference=r["reference"],
                    version=r.get("version", 1),
                    key_id=r.get("key_id", "default"),
                    created_at=r.get("created_at", 0.0),
                    updated_at=r.get("updated_at", 0.0),
                    tenant_id=r.get("tenant_id", tenant_id),
                    environment_id=r.get("environment_id", environment_id),
                    description=r.get("description"),
                )
            )
        return results

    def health_check(self) -> SecretProviderHealth:
        """Performs encryption/decryption round-trip self-test."""
        try:
            test_val = SecretValue("health-check-probe")
            test_ref = "local://__internal_health_check__"
            self.store(test_ref, test_val)
            resolved = self.resolve(test_ref)
            self.delete(test_ref)
            is_ok = resolved == test_val
            return SecretProviderHealth(
                status="HEALTHY" if is_ok else "UNHEALTHY",
                provider_name=self.provider_name,
                details={
                    "key_id": self._key_protector.key_id,
                    "key_source": self._key_protector.source,
                    "total_stored_secrets": len(self._store),
                },
            )
        except Exception as e:
            return SecretProviderHealth(
                status="UNHEALTHY",
                provider_name=self.provider_name,
                details={"error": str(e)},
            )
