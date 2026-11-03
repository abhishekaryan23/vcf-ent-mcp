# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Unit Tests for Zero-Trust Credential Broker & Secret Redaction.
Ensures that the LLM client never receives infrastructure credentials, tokens, or private keys.
"""

from __future__ import annotations
import sys
import os
import unittest

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC_DIR = os.path.join(BASE_DIR, "src")
sys.path.insert(0, SRC_DIR)

from vcf_enterprise_mcp.auth.identity import Principal
from vcf_enterprise_mcp.auth.credential_broker import CredentialBroker


class TestCredentialBrokerAndRedaction(unittest.TestCase):
    """Validates the Credential Broker boundary isolating credentials from LLM context."""

    def setUp(self):
        self.broker = CredentialBroker()
        self.principal = Principal(user_id="operator@corp.com", display_name="Test Operator")

    def test_broker_never_fabricates_upstream_tokens(self):
        """Upstream sessions come from real per-component logins (vcf_sessions), never invented strings."""
        self.assertFalse(hasattr(self.broker, "get_upstream_token"))

    def test_secret_redaction_replaces_credentials_with_vault_references(self):
        """Ensures that dictionaries containing passwords/tokens are replaced with vault:// references."""
        raw_output = {
            "vm_id": "vm-102",
            "name": "app-server",
            "administrator_password": "SuperSecretPassword123!",
            "api_token": "bearer-secret-xyz-789",
            "session_cookie": "JSESSIONID=abcdef012345",
            "sddc_manager_url": "https://sddc-manager.corp.internal",
            "nested": {
                "private_token": "secret-nested-tok",
                "cpu_count": 8,
            },
        }

        clean_output = self.broker.redact_secrets_from_data(raw_output)

        # Non-sensitive keys and URLs are preserved
        self.assertEqual(clean_output["vm_id"], "vm-102")
        self.assertEqual(clean_output["name"], "app-server")
        self.assertEqual(clean_output["sddc_manager_url"], "https://sddc-manager.corp.internal")
        self.assertEqual(clean_output["nested"]["cpu_count"], 8)

        # Sensitive keys MUST be replaced with vault:// references
        self.assertEqual(clean_output["administrator_password"], "vault://credentials/subsystem-administrator_password-ref")
        self.assertEqual(clean_output["api_token"], "vault://credentials/subsystem-api_token-ref")
        self.assertEqual(clean_output["session_cookie"], "vault://credentials/subsystem-session_cookie-ref")
        self.assertEqual(clean_output["nested"]["private_token"], "vault://credentials/subsystem-private_token-ref")

    def test_private_key_pem_redaction(self):
        """Ensures that PEM private key strings are stripped."""
        raw_pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----"
        clean = self.broker.redact_secrets_from_data(raw_pem)
        self.assertEqual(clean, "[REDACTED_PRIVATE_KEY]")


if __name__ == "__main__":
    unittest.main()
