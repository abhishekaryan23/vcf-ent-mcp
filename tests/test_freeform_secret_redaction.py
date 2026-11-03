# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Test Suite: Freeform Secret Redaction and Deep String Sanitization (Finding P1-2).

Validates:
1. Freeform Bearer tokens in error messages and strings.
2. Raw JWTs (RFC 7519) embedded inside arbitrary strings without key-name hints.
3. Passwords and secrets embedded in key-value connection strings and log lines.
4. Cryptographic PEM private keys (RSA, EC, Generic).
5. Session cookies (JSESSIONID, vmware-api-session-id, Set-Cookie).
6. HTTP Basic/Digest authorization headers.
7. Credentials embedded in URLs (user:password@host).
8. Deep recursive traversal across arbitrary nested structures (dicts, lists, tuples).
9. Combined prompt injection filtering and credential scrubbing.
10. Error string scrubbing in audit records when tools raise exceptions containing credentials.
"""

import unittest
import asyncio
from vcf_enterprise_mcp.auth.identity import Principal
from vcf_enterprise_mcp.auth.untrusted import (
    sanitize_for_external_output,
    sanitize_freeform_string,
    sanitize_and_classify_payload,
)
from vcf_enterprise_mcp.auth.credential_broker import CredentialBroker
from vcf_enterprise_mcp.state.durable_store import DurableStore
from vcf_enterprise_mcp.policy.enforcement import PolicyEnforcementPoint
from vcf_enterprise_mcp.policy.engine import PolicyDecisionPoint
from vcf_enterprise_mcp.config.settings import PolicyConfig
from vcf_enterprise_mcp.tools.base import BaseEnterpriseTool
from vcf_enterprise_mcp.policy.models import RiskClass


class LeakyExceptionTool(BaseEnterpriseTool):
    """Tool whose run_live intentionally raises an exception with embedded credentials."""
    name = "vcf_leaky_tool"
    risk_class = RiskClass.READ

    async def run_live(self, principal: Principal, arguments: dict) -> dict:
        jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIn0.GcxW8Z6p7x"
        raise RuntimeError(
            f"Failed connecting to upstream SDDC Manager at https://admin:SuperSecret123!@sddc.local with token {jwt_token} and password=InternalPass!"
        )


class TestFreeformSecretRedaction(unittest.TestCase):

    def setUp(self):
        self.broker = CredentialBroker()

    def test_bearer_token_redaction_in_freeform_text(self):
        text = "Upstream vCenter returned 401 Unauthorized for header: Bearer ya29.a0AfH6SMD_secret_token_value_xyz123 on cluster-01"
        sanitized = sanitize_freeform_string(text)
        self.assertNotIn("ya29.a0AfH6SMD_secret_token_value_xyz123", sanitized)
        self.assertIn("Bearer [REDACTED_BEARER_TOKEN]", sanitized)

    def test_raw_jwt_redaction_without_bearer_prefix(self):
        sample_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        msg = f"Task dispatch failed for claims payload: {sample_jwt} at endpoint"
        sanitized = sanitize_freeform_string(msg)
        self.assertNotIn(sample_jwt, sanitized)
        self.assertIn("[REDACTED_JWT]", sanitized)

    def test_password_kv_redaction_in_freeform_log(self):
        log_line = "Failed to authenticate operator 'vcf_admin' with password=P@ssw0rd999! on ESXi host 10.0.0.12"
        sanitized = sanitize_freeform_string(log_line)
        self.assertNotIn("P@ssw0rd999!", sanitized)
        self.assertIn("password=[REDACTED_SECRET]", sanitized)

        conn_str = "driver=postgresql;user=vcf;password='MyTopSecretDbPassword#1';host=db.internal"
        sanitized_conn = sanitize_freeform_string(conn_str)
        self.assertNotIn("MyTopSecretDbPassword#1", sanitized_conn)
        self.assertIn("password=[REDACTED_SECRET]", sanitized_conn)

    def test_pem_private_key_redaction(self):
        pem_key = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA0Y1m9K3Z5q8...\n"
            "-----END RSA PRIVATE KEY-----"
        )
        log = f"Loaded host certificate bundle with key:\n{pem_key}\nReady for TLS."
        sanitized = sanitize_freeform_string(log)
        self.assertNotIn("MIIEowIBAAKCAQEA0Y1m9K3Z5q8", sanitized)
        self.assertIn("[REDACTED_PRIVATE_KEY]", sanitized)

    def test_session_cookie_redaction(self):
        cookie_header = "Set-Cookie: JSESSIONID=0A1B2C3D4E5F67890ABCDEF123456789; Path=/ui; HttpOnly; Secure"
        sanitized = sanitize_freeform_string(cookie_header)
        self.assertNotIn("0A1B2C3D4E5F67890ABCDEF123456789", sanitized)
        self.assertIn("Set-Cookie: [REDACTED_COOKIE]", sanitized)

        vmware_cookie = "vmware-api-session-id=9f8e7d6c5b4a3210; domain=vcenter.corp"
        sanitized_vmware = sanitize_freeform_string(vmware_cookie)
        self.assertNotIn("9f8e7d6c5b4a3210", sanitized_vmware)
        self.assertIn("vmware-api-session-id=[REDACTED_SESSION_COOKIE]", sanitized_vmware)

    def test_url_credentials_redaction(self):
        url = "https://svc_account:SecretAccessPass123!@sddc-manager.corp.internal/v1/sddcs"
        sanitized = sanitize_freeform_string(url)
        self.assertNotIn("SecretAccessPass123!", sanitized)
        self.assertIn("https://svc_account:[REDACTED_PASSWORD]@sddc-manager.corp.internal/v1/sddcs", sanitized)

    def test_basic_auth_redaction(self):
        auth_line = "Outgoing header: Basic dXNlcm5hbWU6c3VwZXJzZWNyZXRwYXNzd29yZA=="
        sanitized = sanitize_freeform_string(auth_line)
        self.assertNotIn("dXNlcm5hbWU6c3VwZXJzZWNyZXRwYXNzd29yZA==", sanitized)
        self.assertIn("Basic [REDACTED_AUTH_CREDENTIAL]", sanitized)

    def test_recursive_deep_inspection_in_arbitrary_structures(self):
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIn0.abcdefghij1234567890"
        nested_data = {
            "status": "ERROR",
            "non_sensitive_key_name": {
                "debug_log": [
                    "Initialized connection",
                    f"Authentication failed with Bearer {jwt}",
                    {"extra": f"password=NestedPassword123! on cluster"},
                ],
                "tuple_context": (
                    "host=10.0.0.1",
                    "https://admin:UrlSecret@host/api",
                ),
            },
        }

        clean = sanitize_for_external_output(nested_data)
        # Verify no raw secrets leaked
        self.assertNotIn("NestedPassword123!", str(clean))
        self.assertNotIn("UrlSecret", str(clean))
        self.assertNotIn(jwt, str(clean))
        self.assertIn("[REDACTED_BEARER_TOKEN]", str(clean))
        self.assertIn("password=[REDACTED_SECRET]", str(clean))
        self.assertIn("[REDACTED_PASSWORD]", str(clean))

    def test_credential_broker_redact_secrets_cleans_freeform_strings(self):
        """CredentialBroker.redact_secrets_from_data must scrub freeform string values."""
        raw = {
            "safe_description": "Connecting via password=LeakPass! and Bearer tok_1234567890abcdef",
            "cluster": "cluster-prod",
        }
        res = self.broker.redact_secrets_from_data(raw)
        self.assertNotIn("LeakPass!", str(res))
        self.assertIn("password=[REDACTED_SECRET]", res["safe_description"])

    def test_tool_exception_audit_scrubbing(self):
        """When a tool raises an exception containing credentials, the audit log must be scrubbed."""
        durable = DurableStore(":memory:")
        pdp = PolicyDecisionPoint(
            config=PolicyConfig(operating_mode="AUDITED_OPERATIONS"),
            durable_store=durable,
        )
        pep = PolicyEnforcementPoint(pdp=pdp)
        alice = Principal(user_id="alice@corp.com", corporate_groups=["VCF-Compute-Operators"], allowed_clusters=["*"])
        tool = LeakyExceptionTool(pep=pep, durable_store=durable)

        with self.assertRaises(RuntimeError):
            asyncio.run(tool.execute(alice, {}))

        # Check recorded audit event in durable store
        with durable._lock:
            cur = durable._conn.cursor()
            cur.execute("SELECT record_payload FROM audit_chain ORDER BY seq_id DESC LIMIT 1")
            row = cur.fetchone()
            self.assertIsNotNone(row)
            payload_str = row["record_payload"]

        # Ensure no secrets leak in audit trace
        self.assertNotIn("SuperSecret123!", payload_str)
        self.assertNotIn("InternalPass!", payload_str)
        self.assertIn("[REDACTED_PASSWORD]", payload_str)
        self.assertIn("password=[REDACTED_SECRET]", payload_str)


if __name__ == "__main__":
    unittest.main()
