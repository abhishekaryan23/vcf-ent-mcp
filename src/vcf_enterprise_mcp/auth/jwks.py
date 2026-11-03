# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
JSON Web Key Set (JWKS) Manager for Enterprise IdP Token Validation.
Fetches, caches, rotates, and indexes public signing keys by issuer and key ID (kid).
Enforces:
- Cache by issuer with configurable TTL
- Refresh on unknown kid
- Fail closed if JWKS unavailable or key unresolvable
- Zero trust for token-supplied jwks_uri (only administrator-configured endpoints used)
"""

from __future__ import annotations
import json
import time
import threading
from typing import Dict, Any, Optional, List, Tuple
import jwt
from jwt.algorithms import RSAAlgorithm, ECAlgorithm
from vcf_enterprise_mcp.core.errors import AuthorizationDeniedException


class JWKSManager:
    """Thread-safe manager for JWKS caching, key lookup, and cryptographic public key resolution."""

    _test_harness_keys: Dict[Tuple[str, str], Any] = {}

    @classmethod
    def register_test_harness_key(cls, issuer: str, kid: str, key_or_jwk: Any) -> None:
        """Registers a signing key for test harness suites only. Refuses in production."""
        import os
        if os.environ.get("VCF_MCP_ENV", "").lower() == "production":
            raise AuthorizationDeniedException("Cannot register test harness keys in production environment.")
        cls._test_harness_keys[(issuer, kid)] = cls._coerce_to_public_key(key_or_jwk)

    @classmethod
    def clear_test_harness_keys(cls) -> None:
        cls._test_harness_keys.clear()

    def __init__(self, default_ttl_seconds: float = 3600.0, allow_lab_tokens: bool = False):
        import os
        self.default_ttl = default_ttl_seconds
        self._lock = threading.RLock()
        # issuer -> {"keys": {kid: public_key}, "expires_at": timestamp, "jwks_uri": uri}
        self._cache: Dict[str, Dict[str, Any]] = {}
        # Pre-configured static public keys for offline / test environments: (issuer, kid) -> key
        self._static_keys: Dict[Tuple[str, str], Any] = {}
        is_prod = os.environ.get("VCF_MCP_ENV", "").lower() == "production"
        if not is_prod:
            self._static_keys.update(self._test_harness_keys)
            # The key file written by `vcf-mcp token mint` is trusted only when lab tokens are switched on
            # explicitly (idp.allow_lab_tokens / VCF_MCP_ALLOW_LAB_TOKENS), and only under the lab issuer.
            if allow_lab_tokens or os.environ.get("VCF_MCP_ALLOW_LAB_TOKENS", "").strip().lower() in ("1", "true", "yes", "on"):
                try:
                    from vcf_enterprise_mcp.auth.lab_auth import load_existing_lab_public_key, LAB_ISSUER, LAB_JWT_KID
                    lab_pub = load_existing_lab_public_key()
                    if lab_pub is not None:
                        self._static_keys[(LAB_ISSUER, LAB_JWT_KID)] = lab_pub
                except Exception:
                    pass

    def register_static_key(self, issuer: str, kid: str, key_or_jwk: Any) -> None:
        """Registers a known signing key (e.g. from enterprise config, test runner, or vault)."""
        import os
        is_prod = os.environ.get("VCF_MCP_ENV", "").lower() == "production"
        if is_prod and ("test" in kid.lower() or kid in ("test-key-01", "test-harness-key-01")):
            raise AuthorizationDeniedException("Cannot register test keys in production environment.")
        with self._lock:
            pub_key = self._coerce_to_public_key(key_or_jwk)
            self._static_keys[(issuer, kid)] = pub_key
            # Also add to cache under issuer
            if issuer not in self._cache:
                self._cache[issuer] = {"keys": {}, "expires_at": time.time() + 86400 * 365, "jwks_uri": None}
            self._cache[issuer]["keys"][kid] = pub_key

    def get_signing_key(
        self,
        issuer: str,
        kid: Optional[str],
        trusted_jwks_uri: Optional[str] = None,
    ) -> Any:
        """
        Retrieves public signing key for the given issuer and kid.
        If unknown kid is encountered, attempts one refresh against trusted_jwks_uri.
        Fails closed with AuthorizationDeniedException if key cannot be resolved.
        """
        import os
        is_prod = os.environ.get("VCF_MCP_ENV", "").lower() == "production"
        if is_prod:
            if kid and ("test" in kid.lower() or "lab-jwt" in kid.lower() or kid in ("test-key-01", "test-harness-key-01", "test-prod-key-01", "lab-jwt-key-01")):
                raise AuthorizationDeniedException(f"Production environment rejects test key ID '{kid}'.")
            if "common/v2.0" in issuer or "example.com" in issuer:
                raise AuthorizationDeniedException(f"Production environment rejects test or unconstrained issuer '{issuer}'.")

        now = time.time()

        with self._lock:
            # Check static pre-registered keys first
            if kid and (issuer, kid) in self._static_keys:
                return self._static_keys[(issuer, kid)]
            if not is_prod and kid and (issuer, kid) in self._test_harness_keys:
                return self._test_harness_keys[(issuer, kid)]

            cache_entry = self._cache.get(issuer)
            if cache_entry and cache_entry["expires_at"] > now:
                keys = cache_entry["keys"]
                if kid and kid in keys:
                    return keys[kid]
                if not kid and len(keys) == 1:
                    return next(iter(keys.values()))

            # If cache missed or kid not found, and trusted_jwks_uri is available, refresh
            if trusted_jwks_uri:
                self._fetch_and_cache_jwks(issuer, trusted_jwks_uri)
                cache_entry = self._cache.get(issuer)
                if cache_entry:
                    keys = cache_entry["keys"]
                    if kid and kid in keys:
                        return keys[kid]
                    if not kid and len(keys) == 1:
                        return next(iter(keys.values()))

            # Fail closed
            kid_str = f"'{kid}'" if kid else "<none>"
            raise AuthorizationDeniedException(
                f"Unknown signing key {kid_str} for issuer '{issuer}'. Key not found in trusted JWKS."
            )

    def _fetch_and_cache_jwks(self, issuer: str, jwks_uri: str) -> None:
        """Fetches remote JWKS over HTTP and caches parsed public keys."""
        try:
            import httpx
            with httpx.Client(timeout=10.0) as client:
                resp = client.get(jwks_uri)
                resp.raise_for_status()
                jwks_data = resp.json()
        except Exception as e:
            # If fetch fails and no valid cached key exists, fail closed
            if issuer not in self._cache or not self._cache[issuer]["keys"]:
                raise AuthorizationDeniedException(
                    f"Unable to fetch JWKS from trusted URI '{jwks_uri}' for issuer '{issuer}': {e}"
                )
            return

        keys_dict: Dict[str, Any] = {}
        for key_dict in jwks_data.get("keys", []):
            kid = key_dict.get("kid")
            if not kid:
                continue
            try:
                pub_key = self._coerce_to_public_key(key_dict)
                keys_dict[kid] = pub_key
            except Exception:
                continue

        self._cache[issuer] = {
            "keys": keys_dict,
            "expires_at": time.time() + self.default_ttl,
            "jwks_uri": jwks_uri,
        }

    @staticmethod
    def _coerce_to_public_key(key_or_jwk: Any) -> Any:
        """Coerces JWK dict, PEM string, or public key object to cryptography public key."""
        if isinstance(key_or_jwk, dict):
            kty = key_or_jwk.get("kty", "")
            if kty == "RSA":
                return RSAAlgorithm.from_jwk(json.dumps(key_or_jwk))
            elif kty == "EC":
                return ECAlgorithm.from_jwk(json.dumps(key_or_jwk))
            else:
                raise ValueError(f"Unsupported JWK kty: {kty}")
        elif isinstance(key_or_jwk, str):
            if "BEGIN" in key_or_jwk:
                from cryptography.hazmat.primitives import serialization
                return serialization.load_pem_public_key(key_or_jwk.encode("utf-8"))
            elif "{" in key_or_jwk:
                return JWKSManager._coerce_to_public_key(json.loads(key_or_jwk))
        return key_or_jwk
