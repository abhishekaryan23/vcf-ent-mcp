# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Developer Laptop & Lab Authentication Helper (Non-Production Only).
Manages a persistent local RSA-2048 signing keypair (~/.vcf-mcp/lab_jwt_key.pem)
and mints standards-compliant RS256 JWT tokens for any VCF CapabilityRole so engineers
can test against a local Digital Twin or non-production VCF lab from their laptop
without deploying an external OIDC Identity Provider.

Trust model: lab tokens carry their own issuer (LAB_ISSUER) that is never a real identity provider.
The server trusts the lab key only when it is switched on explicitly (config idp.allow_lab_tokens: true,
or VCF_MCP_ALLOW_LAB_TOKENS=1) and never in production mode, so a leftover key file cannot mint
tokens that pass as corporate SSO tokens.
"""

from __future__ import annotations
import os
import time
import uuid
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from vcf_enterprise_mcp.auth.jwks import JWKSManager
from vcf_enterprise_mcp.core.errors import AuthorizationDeniedException
from vcf_enterprise_mcp.core.paths import state_dir
from vcf_enterprise_mcp.policy.models import CapabilityRole


LAB_JWT_KID = "lab-jwt-key-01"
LAB_ISSUER = "urn:vcf-mcp:lab"
DEFAULT_LAB_ISSUER = LAB_ISSUER
ALT_LAB_ISSUERS = (LAB_ISSUER,)


def lab_tokens_allowed(idp_config=None) -> bool:
    """True when this process may trust the lab key: switched on in config or env, and not production."""
    if os.environ.get("VCF_MCP_ENV", "").lower() == "production":
        return False
    if os.environ.get("VCF_MCP_ALLOW_LAB_TOKENS", "").strip().lower() in ("1", "true", "yes", "on"):
        return True
    return bool(getattr(idp_config, "allow_lab_tokens", False))
DEFAULT_LAB_AUDIENCE = "vcf-mcp-client"
DEFAULT_RESOURCE_INDICATOR = "urn:mcp:vcf-control-plane"

ROLE_TO_DEFAULT_GROUP: Dict[str, str] = {
    CapabilityRole.VCF_VIEWER.value: "VCF-Viewers",
    CapabilityRole.VCF_AUDITOR.value: "VCF-Auditors",
    CapabilityRole.COMPUTE_OPERATOR.value: "VCF-Compute-Operators",
    CapabilityRole.COMPUTE_ADMIN.value: "VCF-Compute-Admins",
    CapabilityRole.NETWORK_OPERATOR.value: "VCF-Network-Operators",
    CapabilityRole.NETWORK_ADMIN.value: "VCF-Network-Admins",
    CapabilityRole.STORAGE_OPERATOR.value: "VCF-Storage-Operators",
    CapabilityRole.STORAGE_ADMIN.value: "VCF-Storage-Admins",
    CapabilityRole.AUTOMATION_OPERATOR.value: "VCF-Automation-Operators",
    CapabilityRole.LIFECYCLE_OPERATOR.value: "VCF-Lifecycle-Operators",
    CapabilityRole.LIFECYCLE_ADMIN.value: "VCF-Lifecycle-Admins",
    CapabilityRole.DR_OPERATOR.value: "VCF-DR-Operators",
    CapabilityRole.DR_ADMIN.value: "VCF-DR-Admins",
    CapabilityRole.SECURITY_ADMIN.value: "VCF-Security-Admins",
    CapabilityRole.VCF_PLATFORM_ADMIN.value: "VCF-Platform-Admins",
    CapabilityRole.MCP_ADMIN.value: "VCF-MCP-Admins",
}


def _resolve_lab_key_path(custom_path: Optional[str] = None) -> Path:
    if custom_path:
        return Path(custom_path)
    env_path = os.environ.get("VCF_MCP_LAB_JWT_KEY_PATH")
    if env_path:
        return Path(env_path)
    for base in (state_dir(), Path.cwd() / ".vcf-mcp"):
        try:
            base.mkdir(parents=True, exist_ok=True, mode=0o700)
            candidate = base / "lab_jwt_key.pem"
            if candidate.exists():
                candidate.read_bytes()
                return candidate
            probe = base / ".write_probe_jwt"
            probe.write_bytes(b"ok")
            probe.unlink(missing_ok=True)
            return candidate
        except OSError:
            continue
    return Path.cwd() / ".vcf-mcp" / "lab_jwt_key.pem"


def ensure_lab_rsa_keypair(custom_path: Optional[str] = None) -> Tuple[Any, Any, Path]:
    """
    Loads or generates a persistent RSA-2048 private/public keypair on disk (0600)
    for local lab JWT signing and verification. Refuses in production.
    """
    if os.environ.get("VCF_MCP_ENV", "").lower() == "production":
        raise AuthorizationDeniedException("Local lab JWT keypair generation is forbidden in production.")

    key_path = _resolve_lab_key_path(custom_path)
    if key_path.exists():
        pem_bytes = key_path.read_bytes()
        private_key = serialization.load_pem_private_key(pem_bytes, password=None)
        public_key = private_key.public_key()
        return private_key, public_key, key_path

    key_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    fd = os.open(str(key_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem_bytes)
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass
    return private_key, private_key.public_key(), key_path


def load_existing_lab_public_key(custom_path: Optional[str] = None) -> Optional[Any]:
    """Loads the local lab public key if a key file already exists on disk."""
    if os.environ.get("VCF_MCP_ENV", "").lower() == "production":
        return None
    for candidate in (
        Path(custom_path) if custom_path else None,
        Path(os.environ["VCF_MCP_LAB_JWT_KEY_PATH"]) if os.environ.get("VCF_MCP_LAB_JWT_KEY_PATH") else None,
        state_dir() / "lab_jwt_key.pem",
        Path.cwd() / ".vcf-mcp" / "lab_jwt_key.pem",
    ):
        if candidate is None:
            continue
        try:
            if candidate.exists():
                priv = serialization.load_pem_private_key(candidate.read_bytes(), password=None)
                return priv.public_key()
        except Exception:
            continue
    return None


def register_lab_key_in_jwks(
    jwks_manager: Optional[JWKSManager] = None,
    issuer: str = DEFAULT_LAB_ISSUER,
    custom_path: Optional[str] = None,
) -> Path:
    """Ensures the local lab RSA keypair exists and registers its public key in JWKSManager."""
    _, pub_key, key_path = ensure_lab_rsa_keypair(custom_path=custom_path)
    JWKSManager.register_test_harness_key(issuer, LAB_JWT_KID, pub_key)
    if jwks_manager is not None:
        jwks_manager.register_static_key(issuer, LAB_JWT_KID, pub_key)
    return key_path


def mint_lab_jwt_token(
    user_id: str = "lab-engineer@corp.local",
    role: str = "VCF_PLATFORM_ADMIN",
    tenant_id: str = "tenant-default",
    environment_id: str = "env-prod",
    allowed_clusters: Optional[List[str]] = None,
    allowed_domains: Optional[List[str]] = None,
    ttl_seconds: int = 86400,
    issuer: str = DEFAULT_LAB_ISSUER,
    audience: str = DEFAULT_LAB_AUDIENCE,
    custom_key_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Mints a cryptographically signed RS256 JWT token for local lab / developer laptop testing.
    Automatically registers the public key with JWKSManager.
    """
    if os.environ.get("VCF_MCP_ENV", "").lower() == "production":
        raise AuthorizationDeniedException("Cannot mint local lab JWT tokens in production environment.")

    role_upper = role.strip().upper()
    if role_upper not in CapabilityRole.__members__:
        valid_roles = ", ".join(CapabilityRole.__members__.keys())
        raise ValueError(f"Unknown role '{role}'. Valid roles: {valid_roles}")

    priv_key, pub_key, key_path = ensure_lab_rsa_keypair(custom_path=custom_key_path)
    JWKSManager.register_test_harness_key(issuer, LAB_JWT_KID, pub_key)

    corp_group = ROLE_TO_DEFAULT_GROUP.get(role_upper, "VCF-Viewers")
    clusters = allowed_clusters if allowed_clusters is not None else ["*"]
    domains = allowed_domains if allowed_domains is not None else ["*"]

    now = int(time.time())
    exp = now + int(ttl_seconds)
    claims = {
        "iss": issuer,
        "sub": user_id,
        "preferred_username": user_id,
        "aud": [audience, DEFAULT_RESOURCE_INDICATOR],
        "resource": DEFAULT_RESOURCE_INDICATOR,
        "iat": now,
        "nbf": now - 5,
        "exp": exp,
        "jti": f"lab-jwt-{uuid.uuid4().hex[:12]}",
        "tid": tenant_id,
        "tenant_id": tenant_id,
        "environment_ids": [environment_id],
        "groups": [corp_group],
        "roles": [role_upper],
        "vcf_clusters": clusters,
        "clusters": clusters,
        "allowed_clusters": clusters,
        "vcf_domains": domains,
        "domains": domains,
        "allowed_domains": domains,
    }
    token = jwt.encode(
        claims,
        priv_key,
        algorithm="RS256",
        headers={"kid": LAB_JWT_KID, "typ": "JWT"},
    )
    return {
        "token": token,
        "authorization_header": f"Bearer {token}",
        "user_id": user_id,
        "role": role_upper,
        "corporate_group": corp_group,
        "tenant_id": tenant_id,
        "environment_id": environment_id,
        "allowed_clusters": clusters,
        "allowed_domains": domains,
        "expires_at": exp,
        "key_path": str(key_path),
    }
