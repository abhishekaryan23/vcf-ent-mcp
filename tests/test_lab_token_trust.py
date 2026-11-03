# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""The lab signing key is trusted only when lab tokens are switched on, under its own issuer (review F7)."""

import os
import tempfile
import time
import unittest

import jwt
from cryptography.hazmat.primitives import serialization

from vcf_enterprise_mcp.auth.idp import EnterpriseIdPValidator
from vcf_enterprise_mcp.auth.jwks import JWKSManager
from vcf_enterprise_mcp.auth.lab_auth import (
    LAB_ISSUER, LAB_JWT_KID, ensure_lab_rsa_keypair, lab_tokens_allowed, mint_lab_jwt_token,
)
from vcf_enterprise_mcp.config.settings import EnterpriseSettings, IdPConfig, apply_production_flag
from vcf_enterprise_mcp.core.errors import AuthorizationDeniedException

ENTRA = "https://login.microsoftonline.com/common/v2.0"


class LabTokenTrust(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.key = os.path.join(self.tmp.name, "lab.pem")
        self._env = {k: os.environ.get(k) for k in ("VCF_MCP_ENV", "VCF_MCP_ALLOW_LAB_TOKENS", "VCF_MCP_LAB_JWT_KEY_PATH")}
        os.environ.pop("VCF_MCP_ENV", None)
        os.environ.pop("VCF_MCP_ALLOW_LAB_TOKENS", None)
        os.environ["VCF_MCP_LAB_JWT_KEY_PATH"] = self.key
        self._harness = dict(JWKSManager._test_harness_keys)
        JWKSManager.clear_test_harness_keys()

    def tearDown(self):
        for k, v in self._env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        apply_production_flag(EnterpriseSettings())
        JWKSManager._test_harness_keys.clear()
        JWKSManager._test_harness_keys.update(self._harness)  # other suites registered theirs at import time
        self.tmp.cleanup()

    def _token(self):
        return mint_lab_jwt_token(user_id="lab@corp.com", role="VCF_VIEWER", custom_key_path=self.key)["authorization_header"]

    def _validator(self, **idp):
        # A fresh manager: the key file on disk is the only thing that can make it trust the lab key.
        JWKSManager.clear_test_harness_keys()
        cfg = IdPConfig(**idp)
        return EnterpriseIdPValidator(config=cfg, jwks_manager=JWKSManager(allow_lab_tokens=cfg.allow_lab_tokens))

    def test_lab_tokens_have_their_own_issuer_not_the_entra_one(self):
        token = self._token()[len("Bearer "):]
        self.assertEqual(jwt.decode(token, options={"verify_signature": False})["iss"], LAB_ISSUER)
        self.assertNotEqual(LAB_ISSUER, ENTRA)

    def test_rejected_unless_explicitly_enabled(self):
        header = self._token()
        with self.assertRaises(AuthorizationDeniedException) as ctx:
            self._validator().validate_bearer_token(header)
        self.assertIn("allow_lab_tokens", str(ctx.exception))
        self.assertEqual(self._validator(allow_lab_tokens=True).validate_bearer_token(header).user_id, "lab@corp.com")

    def test_env_flag_enables_it_too(self):
        header = self._token()
        os.environ["VCF_MCP_ALLOW_LAB_TOKENS"] = "1"
        self.assertTrue(lab_tokens_allowed(IdPConfig()))
        JWKSManager.clear_test_harness_keys()
        validator = EnterpriseIdPValidator(config=IdPConfig(), jwks_manager=JWKSManager())
        self.assertEqual(validator.validate_bearer_token(header).user_id, "lab@corp.com")

    def test_lab_key_is_never_trusted_under_the_entra_issuer(self):
        priv, _, _ = ensure_lab_rsa_keypair(self.key)
        now = int(time.time())
        forged = jwt.encode(
            {"iss": ENTRA, "sub": "evil@corp.com", "aud": ["vcf-mcp-control-plane-client"], "exp": now + 600, "tid": "t",
             "roles": ["VCF_PLATFORM_ADMIN"], "groups": ["x"]},
            priv, algorithm="RS256", headers={"kid": LAB_JWT_KID})
        with self.assertRaises(AuthorizationDeniedException):
            self._validator(allow_lab_tokens=True).validate_bearer_token(f"Bearer {forged}")

    def test_production_mode_from_config_refuses_lab_tokens(self):
        header = self._token()
        cfg = EnterpriseSettings(server={"production_mode": True}, idp={"allow_lab_tokens": True})
        apply_production_flag(cfg)
        self.assertEqual(os.environ["VCF_MCP_ENV"], "production")
        self.assertFalse(lab_tokens_allowed(cfg.idp))
        with self.assertRaises(AuthorizationDeniedException):
            self._validator(allow_lab_tokens=True).validate_bearer_token(header)
        apply_production_flag(EnterpriseSettings())  # reload with it switched off undoes the env change
        self.assertNotIn("VCF_MCP_ENV", os.environ)
        self.assertTrue(lab_tokens_allowed(IdPConfig(allow_lab_tokens=True)))
