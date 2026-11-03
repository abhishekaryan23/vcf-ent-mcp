# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Standard Cryptographic JWT Test Token Fixture for Enterprise MCP Test Suites.
Mints genuine RSA-signed JWTs matching corporate directory personas for testing only.
DO NOT IMPORT OR SHIP IN PRODUCTION PACKAGES.
"""

from __future__ import annotations
import time
from typing import Optional, List, Dict, Any
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

# Generate deterministic shared RSA test key for test harness
_TEST_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
TEST_PUBLIC_KEY = _TEST_PRIVATE_KEY.public_key()
TEST_KID = "test-harness-key-01"
TEST_ISSUER = "https://login.microsoftonline.com/common/v2.0"
TEST_AUDIENCE = "vcf-mcp-control-plane-client"


def register_test_keys(jwks_manager=None) -> None:
    """Registers test signing key in the JWKS manager or the test harness registry."""
    from vcf_enterprise_mcp.auth.jwks import JWKSManager
    if jwks_manager is not None:
        jwks_manager.register_static_key(TEST_ISSUER, TEST_KID, TEST_PUBLIC_KEY)
    else:
        JWKSManager.register_test_harness_key(TEST_ISSUER, TEST_KID, TEST_PUBLIC_KEY)


def create_signed_token(
    user_id: str,
    groups: list[str],
    roles: list[str] | None = None,
    tenant_id: str = "tenant-default",
    allowed_clusters: list[str] | None = None,
    allowed_domains: list[str] | None = None,
    expires_in: int = 3600,
    issuer: str = TEST_ISSUER,
    audience: str = TEST_AUDIENCE,
    kid: str = TEST_KID,
    extra_claims: dict | None = None,
) -> str:
    now = time.time()
    payload = {
        "sub": user_id,
        "preferred_username": user_id,
        "name": user_id.split("@")[0].title(),
        "iss": issuer,
        "aud": audience,
        "tid": tenant_id,
        "groups": groups,
        "roles": roles or [],
        "vcf_clusters": allowed_clusters or [],
        "vcf_domains": allowed_domains or [],
        "iat": int(now),
        "exp": int(now + expires_in),
        "nbf": int(now - 10),
    }
    if extra_claims:
        payload.update(extra_claims)

    headers = {"kid": kid, "alg": "RS256"}
    return jwt.encode(payload, _TEST_PRIVATE_KEY, algorithm="RS256", headers=headers)


def get_alice_token(tenant_id: str = "tenant-default") -> str:
    return create_signed_token(
        user_id="alice@corp.com",
        groups=["VCF-Compute-Operators", "VCF-Prod-ReadOnly"],
        roles=["COMPUTE_OPERATOR"],
        tenant_id=tenant_id,
        allowed_clusters=["cluster-prod-a"],
        allowed_domains=["wld-app-a"],
    )


def get_bob_token(tenant_id: str = "tenant-default") -> str:
    return create_signed_token(
        user_id="bob@corp.com",
        groups=["VCF-Network-Operators"],
        roles=["NETWORK_OPERATOR"],
        tenant_id=tenant_id,
        allowed_clusters=["cluster-prod-a", "cluster-prod-b"],
        allowed_domains=["wld-app-a", "wld-edge-01"],
    )


def get_admin_token(tenant_id: str = "tenant-default") -> str:
    return create_signed_token(
        user_id="admin@corp.com",
        groups=["VCF-Platform-Admins", "VCF-Security-Admins"],
        roles=["VCF_PLATFORM_ADMIN"],
        tenant_id=tenant_id,
        allowed_clusters=["*"],
        allowed_domains=["*"],
    )


ALICE_BEARER = f"Bearer {get_alice_token()}"
BOB_BEARER = f"Bearer {get_bob_token()}"
ADMIN_BEARER = f"Bearer {get_admin_token()}"

# Auto-register with test harness when imported by tests
register_test_keys()
