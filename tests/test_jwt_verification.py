# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
SEC-01 Test Suite: Real JWT Cryptographic Verification & Anti-Backdoor Enforcement.
Verifies:
- Valid signed JWT is accepted and parsed into Principal with verified tenant_id
- Unsigned JWT is rejected (DENY)
- Modified signature is rejected (DENY)
- Wrong issuer is rejected (DENY)
- Wrong audience is rejected (DENY)
- Expired token is rejected (DENY)
- Future nbf token is rejected (DENY)
- Algorithm 'none' is rejected (DENY)
- Unknown signing key (kid) is rejected (DENY)
- String backdoors (Bearer admin, Bearer alice) are strictly rejected (DENY)
"""

from __future__ import annotations
import unittest
import time
import os
import sys

# Ensure src is in sys.path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC_DIR = os.path.join(BASE_DIR, "src")
sys.path.insert(0, SRC_DIR)

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from vcf_enterprise_mcp.auth.idp import EnterpriseIdPValidator
from vcf_enterprise_mcp.auth.jwks import JWKSManager
from vcf_enterprise_mcp.config.settings import IdPConfig
from vcf_enterprise_mcp.core.errors import AuthorizationDeniedException


class TestJWTVerificationSEC01(unittest.TestCase):

    def setUp(self):
        # Generate genuine RSA keypair
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()

        # Alternative key for tampering/unknown key tests
        self.rogue_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        self.issuer = "https://login.microsoftonline.com/common/v2.0"
        self.audience = "vcf-mcp-control-plane-client"
        self.kid = "test-prod-key-01"

        self.config = IdPConfig(
            issuer_url=self.issuer,
            client_id=self.audience,
            tenant_claim="tid",
            allowed_algorithms=["RS256", "ES256"],
        )

        self.jwks = JWKSManager()
        self.jwks.register_static_key(self.issuer, self.kid, self.public_key)

        self.idp = EnterpriseIdPValidator(
            config=self.config,
            expected_resource_indicator="urn:mcp:vcf-control-plane",
            enforce_jwt_claims=True,
            jwks_manager=self.jwks,
        )

    def _create_token(
        self,
        claims: dict | None = None,
        key=None,
        headers: dict | None = None,
        algorithm="RS256",
    ) -> str:
        now = time.time()
        payload = {
            "sub": "alice@corp.com",
            "name": "Alice Smith",
            "iss": self.issuer,
            "aud": self.audience,
            "tid": "tenant-finance-01",
            "groups": ["VCF-Compute-Operators"],
            "roles": ["COMPUTE_OPERATOR"],
            "vcf_clusters": ["cluster-prod-a"],
            "iat": int(now),
            "exp": int(now + 3600),
            "nbf": int(now - 10),
        }
        if claims:
            payload.update(claims)

        token_headers = {"kid": self.kid}
        if headers:
            token_headers.update(headers)

        signing_key = key if key is not None else self.private_key
        return jwt.encode(payload, signing_key, algorithm=algorithm, headers=token_headers)

    def test_valid_signed_jwt_is_accepted(self):
        """Valid cryptographic RSA-signed JWT is accepted and verified claims populate Principal."""
        token = self._create_token()
        principal = self.idp.validate_bearer_token(f"Bearer {token}")
        self.assertEqual(principal.user_id, "alice@corp.com")
        self.assertEqual(principal.principal_id, "alice@corp.com")
        self.assertEqual(principal.tenant_id, "tenant-finance-01")
        self.assertIn("VCF-Compute-Operators", principal.corporate_groups)
        self.assertEqual(principal.allowed_clusters, ["cluster-prod-a"])

    def test_unsigned_jwt_is_rejected(self):
        """Unsigned JWT without valid signature is rejected with DENY."""
        now = time.time()
        payload = {
            "sub": "attacker@corp.com",
            "iss": self.issuer,
            "aud": self.audience,
            "tid": "tenant-evil",
            "exp": int(now + 3600),
        }
        unsigned_token = jwt.encode(payload, key="", algorithm="none")
        with self.assertRaises(AuthorizationDeniedException):
            self.idp.validate_bearer_token(f"Bearer {unsigned_token}")

    def test_modified_signature_is_rejected(self):
        """Token with tampered signature bits is rejected with DENY."""
        token = self._create_token()
        parts = token.split(".")
        # Tamper signature characters
        tampered_sig = parts[2][:-4] + ("AAAA" if parts[2][-4:] != "AAAA" else "BBBB")
        tampered_token = f"{parts[0]}.{parts[1]}.{tampered_sig}"

        with self.assertRaises(AuthorizationDeniedException):
            self.idp.validate_bearer_token(f"Bearer {tampered_token}")

    def test_wrong_issuer_is_rejected(self):
        """Token from unauthorized issuer is rejected with DENY."""
        token = self._create_token(claims={"iss": "https://untrusted-idp.attacker.com/v2.0"})
        with self.assertRaises(AuthorizationDeniedException):
            self.idp.validate_bearer_token(f"Bearer {token}")

    def test_wrong_audience_is_rejected(self):
        """Token with wrong audience/client_id is rejected with DENY."""
        token = self._create_token(claims={"aud": "api://different-service"})
        with self.assertRaises(AuthorizationDeniedException):
            self.idp.validate_bearer_token(f"Bearer {token}")

    def test_expired_token_is_rejected(self):
        """Token where exp < now - leeway is rejected with DENY."""
        now = time.time()
        token = self._create_token(claims={"exp": int(now - 120), "iat": int(now - 7200)})
        with self.assertRaises(AuthorizationDeniedException):
            self.idp.validate_bearer_token(f"Bearer {token}")

    def test_future_nbf_is_rejected(self):
        """Token with nbf far in the future is rejected with DENY."""
        now = time.time()
        token = self._create_token(claims={"nbf": int(now + 3600)})
        with self.assertRaises(AuthorizationDeniedException):
            self.idp.validate_bearer_token(f"Bearer {token}")

    def test_alg_none_is_rejected(self):
        """Tokens attempting alg=none exploit are explicitly rejected."""
        header = {"alg": "none"}
        payload = {"sub": "admin@corp.com", "iss": self.issuer, "exp": int(time.time() + 3600)}
        token = jwt.encode(payload, key="", algorithm="none", headers=header)
        with self.assertRaises(AuthorizationDeniedException):
            self.idp.validate_bearer_token(f"Bearer {token}")

    def test_unknown_signing_key_is_rejected(self):
        """Token signed by untrusted / unknown key is rejected."""
        token = self._create_token(key=self.rogue_private_key, headers={"kid": "unknown-key-999"})
        with self.assertRaises(AuthorizationDeniedException):
            self.idp.validate_bearer_token(f"Bearer {token}")

    def test_bearer_admin_string_is_rejected(self):
        """Legacy backdoor shortcut 'Bearer admin' is strictly rejected with DENY."""
        with self.assertRaises(AuthorizationDeniedException):
            self.idp.validate_bearer_token("Bearer admin")

    def test_bearer_alice_string_is_rejected(self):
        """Legacy backdoor shortcut 'Bearer alice' is strictly rejected with DENY."""
        with self.assertRaises(AuthorizationDeniedException):
            self.idp.validate_bearer_token("Bearer alice")

    def test_old_test_kid_and_issuer_rejected_in_production(self):
        """Old test key ID and unconstrained test issuer are strictly rejected in production mode."""
        old_env = os.environ.get("VCF_MCP_ENV")
        try:
            os.environ["VCF_MCP_ENV"] = "production"
            # Token with test-key-01 or test issuer
            token = self._create_token(headers={"kid": "test-key-01"})
            with self.assertRaises(AuthorizationDeniedException):
                self.idp.validate_bearer_token(f"Bearer {token}")
        finally:
            if old_env is not None:
                os.environ["VCF_MCP_ENV"] = old_env
            else:
                os.environ.pop("VCF_MCP_ENV", None)

    def test_forged_admin_token_rejected(self):
        """Token forged with admin claims but signed with un-registered rogue key is rejected."""
        rogue_token = self._create_token(
            claims={"sub": "admin@corp.com", "roles": ["VCF_PLATFORM_ADMIN"]},
            key=self.rogue_private_key,
        )
        with self.assertRaises(AuthorizationDeniedException):
            self.idp.validate_bearer_token(f"Bearer {rogue_token}")

    def test_missing_and_empty_auth_header_rejected_by_default(self):
        """Missing or empty Authorization header is rejected with 401 AuthorizationDeniedException."""
        with self.assertRaises(AuthorizationDeniedException) as ctx1:
            self.idp.validate_bearer_token(None)
        self.assertIn("Missing required Authorization header", str(ctx1.exception))

        with self.assertRaises(AuthorizationDeniedException) as ctx2:
            self.idp.validate_bearer_token("")
        self.assertIn("Missing required Authorization header", str(ctx2.exception))

        with self.assertRaises(AuthorizationDeniedException) as ctx3:
            self.idp.validate_bearer_token("Bearer ")
        self.assertIn("Empty Bearer token provided", str(ctx3.exception))

    def test_anonymous_tools_list_rejected_in_protocol(self):
        """Unauthenticated caller attempting tools/list over MCP wire receives -32001 authorization denied."""
        import asyncio
        from vcf_enterprise_mcp.core.protocol import EnterpriseMCPProtocolEngine
        engine = EnterpriseMCPProtocolEngine(idp_validator=self.idp)
        req = {"jsonrpc": "2.0", "id": 99, "method": "tools/list", "params": {}}
        res = asyncio.run(engine.handle_jsonrpc_request(req, auth_header=None))
        self.assertIn("error", res)
        self.assertEqual(res["error"]["code"], -32001)

    def test_production_readiness_validation_fails_on_insecure_config(self):
        """EnterpriseSettings.validate_production_readiness rejects allow_anonymous=True and test issuers."""
        from vcf_enterprise_mcp.config.settings import EnterpriseSettings, ServerConfig
        from vcf_enterprise_mcp.core.errors import ConfigurationException

        # 1. allow_anonymous = True in production fails
        insecure_settings = EnterpriseSettings(
            server=ServerConfig(environment="production"),
            idp=IdPConfig(allow_anonymous=True, issuer_url="https://identity.enterprise.corp/oauth2/v1"),
        )
        with self.assertRaises(ConfigurationException) as ctx:
            insecure_settings.validate_production_readiness()
        self.assertIn("allow_anonymous is forbidden in production", str(ctx.exception))

        # 2. Test/unconstrained issuer in production fails
        test_issuer_settings = EnterpriseSettings(
            server=ServerConfig(environment="production"),
            idp=IdPConfig(allow_anonymous=False, issuer_url="https://login.microsoftonline.com/common/v2.0"),
        )
        with self.assertRaises(ConfigurationException) as ctx2:
            test_issuer_settings.validate_production_readiness()
        self.assertIn("forbidden in production", str(ctx2.exception))


if __name__ == "__main__":
    unittest.main()
