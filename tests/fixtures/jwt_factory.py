# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
JWT Test Factory for Enterprise MCP Test Suites.
Dynamically generates ephemeral cryptographic keypairs and mints signed tokens
matching enterprise personas, tenants, and edge cases.
"""

from __future__ import annotations
import time
from typing import Dict, Any, List, Optional
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa


class JWTTestFactory:
    """Factory for minting test JWTs and managing test signing keys."""

    def __init__(
        self,
        issuer: str = "https://login.microsoftonline.com/common/v2.0",
        audience: str = "vcf-mcp-control-plane-client",
        kid: str = "test-factory-key-01",
    ):
        self.issuer = issuer
        self.audience = audience
        self.kid = kid
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()

        # Rogue keypair for forging signatures in attack tests
        self.rogue_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.rogue_public_key = self.rogue_private_key.public_key()

    def register_with_jwks(self, jwks_manager) -> None:
        """Registers the factory's public key in the specified JWKSManager."""
        jwks_manager.register_static_key(self.issuer, self.kid, self.public_key)

    def create_token(
        self,
        user_id: str,
        groups: List[str],
        roles: Optional[List[str]] = None,
        tenant_id: str = "tenant-default",
        allowed_clusters: Optional[List[str]] = None,
        allowed_domains: Optional[List[str]] = None,
        expires_in: int = 3600,
        nbf_offset: int = -10,
        issuer: Optional[str] = None,
        audience: Optional[str] = None,
        kid: Optional[str] = None,
        algorithm: str = "RS256",
        extra_claims: Optional[Dict[str, Any]] = None,
        use_rogue_key: bool = False,
    ) -> str:
        now = time.time()
        payload = {
            "sub": user_id,
            "preferred_username": user_id,
            "name": user_id.split("@")[0].title(),
            "iss": issuer or self.issuer,
            "aud": audience or self.audience,
            "tid": tenant_id,
            "groups": groups,
            "roles": roles or [],
            "vcf_clusters": allowed_clusters or [],
            "vcf_domains": allowed_domains or [],
            "iat": int(now),
            "exp": int(now + expires_in),
            "nbf": int(now + nbf_offset),
        }
        if extra_claims:
            payload.update(extra_claims)

        headers = {"kid": kid or self.kid, "alg": algorithm}
        signing_key = self.rogue_private_key if use_rogue_key else self.private_key
        return jwt.encode(payload, signing_key, algorithm=algorithm, headers=headers)

    def mint_alice(self, tenant_id: str = "tenant-default") -> str:
        return self.create_token(
            user_id="alice@corp.com",
            groups=["VCF-Compute-Operators", "VCF-Prod-ReadOnly"],
            roles=["COMPUTE_OPERATOR"],
            tenant_id=tenant_id,
            allowed_clusters=["cluster-prod-a"],
            allowed_domains=["wld-app-a"],
        )

    def mint_bob(self, tenant_id: str = "tenant-default") -> str:
        return self.create_token(
            user_id="bob@corp.com",
            groups=["VCF-Network-Operators"],
            roles=["NETWORK_OPERATOR"],
            tenant_id=tenant_id,
            allowed_clusters=["cluster-prod-a", "cluster-prod-b"],
            allowed_domains=["wld-app-a", "wld-edge-01"],
        )

    def mint_admin(self, tenant_id: str = "tenant-default") -> str:
        return self.create_token(
            user_id="admin@corp.com",
            groups=["VCF-Platform-Admins", "VCF-Security-Admins"],
            roles=["VCF_PLATFORM_ADMIN"],
            tenant_id=tenant_id,
            allowed_clusters=["*"],
            allowed_domains=["*"],
        )
