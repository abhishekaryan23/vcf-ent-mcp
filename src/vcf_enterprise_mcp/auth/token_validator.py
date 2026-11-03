# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
OIDC/OAuth 2.0 JWT Token Validator with Cryptographic Signature Verification.
Complies with RFC 7519 (JWT), RFC 7515 (JWS), RFC 7517 (JWK), and RFC 8707 (Resource Indicators).
Enforces:
- Strict cryptographic signature verification via PyJWT / Cryptography
- Explicit algorithm allowlist (bans alg=none and unapproved algorithms)
- Trusted administrator IdP resolution (never trusts token-supplied jwks_uri)
- Non-forgeable identity and tenant claims extraction
"""

from __future__ import annotations
import json
import time
import hashlib
from typing import Dict, Any, Optional, List
import jwt
from vcf_enterprise_mcp.auth.identity import Principal
from vcf_enterprise_mcp.auth.jwks import JWKSManager
from vcf_enterprise_mcp.config.settings import IdPConfig
from vcf_enterprise_mcp.core.errors import AuthorizationDeniedException


class TokenValidator:
    """Cryptographic JWT validator ensuring all incoming Bearer tokens are signed and authentic."""

    DEFAULT_ALLOWED_ALGORITHMS = ["RS256", "ES256"]

    def __init__(
        self,
        config: Optional[IdPConfig] = None,
        jwks_manager: Optional[JWKSManager] = None,
        expected_resource_indicator: str = "urn:mcp:vcf-control-plane",
    ):
        self.config = config or IdPConfig()
        self.jwks_manager = jwks_manager or JWKSManager()
        self.expected_resource_indicator = expected_resource_indicator
        self.allowed_algorithms = getattr(self.config, "allowed_algorithms", self.DEFAULT_ALLOWED_ALGORITHMS)

    def validate_token(self, auth_header: Optional[str], client_ip: str = "127.0.0.1") -> Principal:
        """
        Parses Authorization header, verifies signature and claims, and constructs authenticated Principal.
        Raises AuthorizationDeniedException on any failure.
        """
        if not auth_header:
            import os
            is_prod = os.environ.get("VCF_MCP_ENV", "").lower() == "production"
            if not is_prod and getattr(self.config, "allow_anonymous", False):
                return Principal(
                    principal_id="anonymous@corp.local",
                    user_id="anonymous@corp.local",
                    tenant_id="tenant-guest",
                    environment_ids=("env-guest",),
                    display_name="Anonymous Guest",
                    corporate_groups=["VCF-Guest-ReadOnly"],
                    groups=("VCF-Guest-ReadOnly",),
                    allowed_domains=[],
                    allowed_clusters=[],
                    client_ip=client_ip,
                    token_id="tok-guest",
                )
            raise AuthorizationDeniedException("Missing required Authorization header.")

        if not auth_header.startswith("Bearer "):
            raise AuthorizationDeniedException("Malformed Authorization header. Must start with 'Bearer '.")

        token = auth_header[7:].strip()
        if not token:
            raise AuthorizationDeniedException("Empty Bearer token provided.")

        # Zero tolerance for backdoor substring matching
        parts = token.split(".")
        if len(parts) != 3:
            raise AuthorizationDeniedException(
                "Invalid Bearer token: JWT must contain exactly 3 dot-separated segments (header.payload.signature)."
            )

        # 1. Inspect unverified header
        try:
            unverified_header = jwt.get_unverified_header(token)
        except Exception as e:
            raise AuthorizationDeniedException(f"Unparseable JWT header: {e}")

        alg = unverified_header.get("alg")
        if not alg or alg.lower() == "none":
            raise AuthorizationDeniedException("Algorithm 'none' is forbidden. Token must be cryptographically signed.")

        if alg not in self.allowed_algorithms:
            raise AuthorizationDeniedException(
                f"Algorithm '{alg}' is not permitted. Allowed algorithms: {self.allowed_algorithms}"
            )

        kid = unverified_header.get("kid")

        # 2. Inspect unverified claims to locate trusted issuer
        try:
            unverified_claims = jwt.decode(token, options={"verify_signature": False})
        except Exception as e:
            raise AuthorizationDeniedException(f"Unparseable JWT payload: {e}")

        iss = unverified_claims.get("iss")
        if not iss:
            raise AuthorizationDeniedException("Token missing mandatory 'iss' claim.")

        # 3. Resolve trusted IdP configuration
        trusted_iss, trusted_aud, trusted_jwks = self._resolve_trusted_idp(iss)

        # 4. Resolve public signing key by kid from trusted JWKS
        signing_key = self.jwks_manager.get_signing_key(
            issuer=trusted_iss,
            kid=kid,
            trusted_jwks_uri=trusted_jwks,
        )

        # 5. Cryptographic signature and claim verification
        leeway = getattr(self.config, "token_leeway_seconds", 60)
        try:
            # We verify signature, exp, nbf, and iss
            claims = jwt.decode(
                token,
                key=signing_key,
                algorithms=[alg],
                issuer=trusted_iss,
                leeway=leeway,
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iss": True,
                    "verify_aud": False,  # Custom multi-audience / resource indicator check below
                    "require": ["exp", "iss"],
                },
            )
        except jwt.MissingRequiredClaimError as e:
            raise AuthorizationDeniedException(f"Token missing mandatory claim: {e}")
        except jwt.ExpiredSignatureError as e:
            raise AuthorizationDeniedException(f"Token has expired: {e}")
        except jwt.ImmatureSignatureError as e:
            raise AuthorizationDeniedException(f"Token is not yet valid (nbf): {e}")
        except jwt.InvalidIssuerError as e:
            raise AuthorizationDeniedException(f"Token issuer mismatch: {e}")
        except jwt.InvalidSignatureError as e:
            raise AuthorizationDeniedException("Cryptographic signature verification failed.")
        except Exception as e:
            raise AuthorizationDeniedException(f"JWT verification failed: {e}")

        # 6. Verify Audience or RFC 8707 Resource Indicator (mandatory)
        self._verify_audience_and_resource(claims, trusted_aud)

        # 7. Extract identity, tenant, and group claims
        return self._principal_from_claims(claims, token, client_ip)

    def _resolve_trusted_idp(self, iss: str) -> tuple[str, str, Optional[str]]:
        """Resolves trusted issuer, audience, and JWKS URI from trusted admin config."""
        # 1. Primary configured issuer
        primary_iss = self.config.issuer_url
        if iss == primary_iss:
            return (
                self.config.issuer_url,
                self.config.client_id,
                getattr(self.config, "jwks_uri", None),
            )

        # Lab tokens: own issuer, accepted only when the operator switched lab tokens on and never in production.
        from vcf_enterprise_mcp.auth.lab_auth import LAB_ISSUER, lab_tokens_allowed
        if iss == LAB_ISSUER:
            if lab_tokens_allowed(self.config):
                return (LAB_ISSUER, "vcf-mcp-client", None)
            raise AuthorizationDeniedException(
                "Lab tokens are not enabled on this server. For a lab or local test set 'idp: {allow_lab_tokens: true}' in the "
                "config file (it is refused in production mode); otherwise use a token from your identity provider."
            )

        # 2. Check multi-provider registry if configured
        trusted_providers = getattr(self.config, "trusted_providers", {})
        if iss in trusted_providers:
            p = trusted_providers[iss]
            return (iss, p.get("audience", self.config.client_id), p.get("jwks_uri"))

        # Issuer not trusted
        raise AuthorizationDeniedException(
            f"Untrusted token issuer '{iss}'. Does not match configured enterprise IdPs."
        )

    def _verify_audience_and_resource(self, claims: Dict[str, Any], trusted_aud: str) -> None:
        aud = claims.get("aud")
        resource = claims.get("resource")

        if not aud and not resource:
            raise AuthorizationDeniedException("Token missing mandatory 'aud' or 'resource' claim.")

        aud_list = []
        if isinstance(aud, list):
            aud_list = aud
        elif isinstance(aud, str):
            aud_list = [aud]

        valid = False
        if trusted_aud in aud_list or self.expected_resource_indicator in aud_list:
            valid = True
        if resource == self.expected_resource_indicator or resource == trusted_aud:
            valid = True

        if not valid:
            raise AuthorizationDeniedException(
                f"Audience/resource rejected. Expected '{trusted_aud}' or '{self.expected_resource_indicator}', got aud={aud}, resource={resource}."
            )

    def _principal_from_claims(self, claims: Dict[str, Any], token: str, client_ip: str) -> Principal:
        user_claim = getattr(self.config, "user_claim", "preferred_username")
        user = (
            claims.get(user_claim)
            or claims.get("sub")
            or claims.get("email")
            or claims.get("upn")
        )
        if not user:
            raise AuthorizationDeniedException("Token missing mandatory subject/identity claim ('sub', 'preferred_username', 'email').")
        name = claims.get("name") or user

        # Extract verified tenant claim (mandatory - no unauthenticated defaults)
        tenant_claim = getattr(self.config, "tenant_claim", "tid")
        tenant_id = claims.get(tenant_claim) or claims.get("tenant_id")
        if not tenant_id:
            raise AuthorizationDeniedException(f"Token missing mandatory tenant identification claim ('{tenant_claim}' or 'tenant_id').")

        groups = claims.get(getattr(self.config, "groups_claim", "groups"), [])
        if isinstance(groups, str):
            groups = [g.strip() for g in groups.split(",")]

        roles = claims.get(getattr(self.config, "roles_claim", "roles"), [])
        if isinstance(roles, str):
            roles = [r.strip() for r in roles.split(",")]

        scopes = claims.get("scp") or claims.get("scope") or []
        if isinstance(scopes, str):
            scopes = [s.strip() for s in scopes.split()]

        # Require at least one authorization attribute (groups, roles, or scopes)
        if not groups and not roles and not scopes and not claims.get("is_system_operator"):
            raise AuthorizationDeniedException("Token missing authorized scopes, roles, or group memberships.")

        roles = claims.get(getattr(self.config, "roles_claim", "roles"), [])
        if isinstance(roles, str):
            roles = [r.strip() for r in roles.split(",")]

        allowed_domains = (
            claims.get("vcf_domains")
            or claims.get("domains")
            or claims.get("allowed_domains")
            or []
        )
        allowed_clusters = (
            claims.get("vcf_clusters")
            or claims.get("clusters")
            or claims.get("allowed_clusters")
            or []
        )
        environment_ids = claims.get("environment_ids") or [claims.get("env", "env-prod")]

        is_sys_op = bool(claims.get("is_system_operator", False))

        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]
        token_id = claims.get("jti") or f"jwt-{token_hash}"

        return Principal(
            principal_id=user,
            tenant_id=tenant_id,
            environment_ids=tuple(environment_ids),
            groups=tuple(groups),
            roles=tuple(roles),
            user_id=user,
            display_name=name,
            corporate_groups=list(groups),
            corporate_roles=list(roles),
            allowed_domains=list(allowed_domains),
            allowed_clusters=list(allowed_clusters),
            client_ip=client_ip,
            token_id=token_id,
            is_system_operator=is_sys_op,
        )
