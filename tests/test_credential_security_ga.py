# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Mandatory Enterprise Credential Security Test Suite (GA Gate).
Verifies that:
- No default or fallback passwords exist in configuration or providers.
- Missing credentials fail closed immediately.
- Local authenticated encryption (AES-256-GCM) roundtrips cleanly.
- Tampered ciphertext or wrong decryption key is strictly rejected.
- Environment variable credentials work in labs and are rejected by policy in production.
- SecretValue representations and string conversions are always redacted.
- Secret plaintext never leaks into audit records, task logs, tool results, or exceptions.
- Static codebase inspection detects zero unapproved default password patterns.
"""

from __future__ import annotations

import base64
import os
import re
import tempfile
import unittest

from vcf_enterprise_mcp.config.settings import (
    UpstreamVCFConfig,
    EnterpriseSettings,
)
from vcf_enterprise_mcp.core.errors import ConfigurationException, VCFEnterpriseException
from vcf_enterprise_mcp.secrets.models import (
    SecretValue,
    CredentialPolicy,
)
from vcf_enterprise_mcp.secrets.base import (
    MissingCredentialException,
    CredentialPolicyViolationException,
    CredentialDecryptionException,
)
from vcf_enterprise_mcp.secrets.environment import EnvironmentSecretProvider
from vcf_enterprise_mcp.secrets.local_encrypted import (
    LocalEncryptedSecretProvider,
    LocalKeyProtector,
)
from vcf_enterprise_mcp.secrets.registry import (
    SecretProviderRegistry,
)
from vcf_enterprise_mcp.auth.credential_broker import CredentialBroker
from vcf_enterprise_mcp.core.errors import VCFEnterpriseException


class TestCredentialSecurityGA(unittest.TestCase):
    """GA Credential Security and Isolation Verification."""

    def test_no_default_password_exists(self):
        """Verifies that UpstreamVCFConfig contains no default hardcoded plaintext passwords."""
        cfg = UpstreamVCFConfig()
        self.assertIsNone(cfg.sddc_service_secret, "Default sddc_service_secret must be None")
        self.assertTrue(cfg.credential_ref.startswith(("local://", "env://", "vault://")))
        self.assertNotIn("VMware1!", cfg.credential_ref)

    def test_missing_local_secret_fails_closed(self):
        """Verifies that attempting to resolve an unconfigured local secret raises MissingCredentialException."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store_path = os.path.join(tmpdir, "creds.json")
            provider = LocalEncryptedSecretProvider(storage_path=store_path)
            with self.assertRaises(MissingCredentialException):
                provider.resolve("local://prod/non-existent-service")

    def test_local_encrypted_secret_roundtrip(self):
        """Verifies authenticated encryption roundtrip with AES-256-GCM."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store_path = os.path.join(tmpdir, "creds.json")
            kp = LocalKeyProtector()
            key = os.urandom(32)
            kp.set_master_key(key, source="TEST_KEY")
            provider = LocalEncryptedSecretProvider(storage_path=store_path, key_protector=kp)

            secret = SecretValue("SuperSecretEnterprisePassword#2026!")
            ref = "local://prod/vcenter-mgmt"
            provider.store(ref, secret, description="Production vCenter password")

            # Resolve and verify equality
            resolved = provider.resolve(ref)
            self.assertIsInstance(resolved, SecretValue)
            self.assertEqual(resolved.reveal(), "SuperSecretEnterprisePassword#2026!")
            self.assertEqual(resolved, secret)

    def test_local_secret_wrong_key_rejected(self):
        """Verifies that decrypting with the wrong AES-256 key raises CredentialDecryptionException."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store_path = os.path.join(tmpdir, "creds.json")

            # Store with key 1
            kp1 = LocalKeyProtector()
            kp1.set_master_key(os.urandom(32), source="KEY_1")
            provider1 = LocalEncryptedSecretProvider(storage_path=store_path, key_protector=kp1)
            provider1.store("local://prod/vcenter", SecretValue("P@ssword123"))

            # Attempt to resolve with key 2
            kp2 = LocalKeyProtector()
            kp2.set_master_key(os.urandom(32), source="KEY_2")
            provider2 = LocalEncryptedSecretProvider(storage_path=store_path, key_protector=kp2)

            with self.assertRaises(CredentialDecryptionException):
                provider2.resolve("local://prod/vcenter")

    def test_local_secret_ciphertext_tamper_rejected(self):
        """Verifies that tampering with AES-GCM ciphertext or tag raises CredentialDecryptionException."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store_path = os.path.join(tmpdir, "creds.json")
            kp = LocalKeyProtector()
            kp.set_master_key(os.urandom(32), source="KEY_TAMPER")
            provider = LocalEncryptedSecretProvider(storage_path=store_path, key_protector=kp)

            ref = "local://prod/tamper-test"
            provider.store(ref, SecretValue("UnmodifiedSecret"))

            # Mutate ciphertext byte in store
            raw_record = provider._store[ref]
            ct = base64.b64decode(raw_record["ciphertext"])
            # Flip one bit in ciphertext
            tampered_ct = bytes([ct[0] ^ 0x01]) + ct[1:]
            raw_record["ciphertext"] = base64.b64encode(tampered_ct).decode("ascii")

            with self.assertRaises(CredentialDecryptionException):
                provider.resolve(ref)

    def test_environment_secret_provider(self):
        """Verifies resolution and failure behavior of EnvironmentSecretProvider."""
        provider = EnvironmentSecretProvider()
        var_name = "VCF_MCP_TEST_EPHEMERAL_KEY"
        ref = f"env://{var_name}"

        # 1. Unset variable fails closed
        os.environ.pop(var_name, None)
        with self.assertRaises(MissingCredentialException):
            provider.resolve(ref)

        # 2. Configured variable resolves cleanly
        os.environ[var_name] = "EphemeralLabPassword123"
        try:
            resolved = provider.resolve(ref)
            self.assertEqual(resolved.reveal(), "EphemeralLabPassword123")
        finally:
            os.environ.pop(var_name, None)

    def test_production_env_secret_rejected_by_policy(self):
        """Verifies that CredentialPolicy strictly forbids env:// in production."""
        policy = CredentialPolicy.for_environment("production")
        self.assertFalse(policy.allow_environment_secrets)

        reg = SecretProviderRegistry(policy=policy)
        os.environ["VCF_MCP_TEST_VAR"] = "some-pass"
        try:
            with self.assertRaises(CredentialPolicyViolationException):
                reg.resolve("env://VCF_MCP_TEST_VAR", environment_id="production")
        finally:
            os.environ.pop("VCF_MCP_TEST_VAR", None)

    def test_secret_repr_is_redacted(self):
        """Verifies that SecretValue __repr__ and __str__ never expose secret text."""
        raw_pwd = "HighlyConfidentialPassword!99"
        val = SecretValue(raw_pwd)

        self.assertEqual(str(val), "[REDACTED]")
        self.assertEqual(repr(val), "<SecretValue [REDACTED]>")
        self.assertNotIn(raw_pwd, str(val))
        self.assertNotIn(raw_pwd, repr(val))

    def test_secret_never_appears_in_audit(self):
        """Verifies that CredentialBroker redacts SecretValue when formatting audit logs."""
        broker = CredentialBroker()
        raw_pwd = "AuditLeakProbeSecretPassword"
        val = SecretValue(raw_pwd)

        audit_payload = {
            "event": "TOOL_INVOCATION",
            "principal": "alice",
            "credentials": val,
            "nested": {
                "secret_obj": val,
                "password_field": raw_pwd,
            }
        }
        redacted = broker.redact_secrets_from_data(audit_payload)
        redacted_str = str(redacted)

        self.assertNotIn(raw_pwd, redacted_str)
        self.assertEqual(redacted["credentials"], "[REDACTED]")
        self.assertEqual(redacted["nested"]["secret_obj"], "[REDACTED]")

    def test_secret_never_appears_in_task(self):
        """Verifies that task payload formatting strips secrets."""
        broker = CredentialBroker()
        task_info = {
            "task_id": "task-100",
            "status": "RUNNING",
            "auth_context": SecretValue("task-token-12345"),
        }
        clean_task = broker.redact_secrets_from_data(task_info)
        self.assertNotIn("task-token-12345", str(clean_task))
        self.assertEqual(clean_task["auth_context"], "[REDACTED]")

    def test_secret_never_appears_in_tool_result(self):
        """Verifies that tool results scrub SecretValue and sensitive keys."""
        broker = CredentialBroker()
        tool_output = {
            "vm_name": "db-vm-01",
            "status": "POWERED_ON",
            "admin_secret": SecretValue("RootP@ssword1"),
            "token": "sensitive-bearer-token-abcde",
        }
        clean_output = broker.redact_secrets_from_data(tool_output)
        self.assertNotIn("RootP@ssword1", str(clean_output))
        self.assertNotIn("sensitive-bearer-token-abcde", str(clean_output))

    def test_secret_never_appears_in_exception(self):
        """Verifies that formatting an exception containing SecretValue redacts it."""
        broker = CredentialBroker()
        val = SecretValue("ExceptionSecretLeakTest")
        try:
            raise VCFEnterpriseException(f"Connection failed for secret {val}")
        except VCFEnterpriseException as e:
            cleaned_msg = broker.redact_secrets_from_data(str(e))
            self.assertNotIn("ExceptionSecretLeakTest", cleaned_msg)
            self.assertIn("[REDACTED]", cleaned_msg)

    def test_static_source_code_scan_for_forbidden_passwords(self):
        """Static audit verifying no unapproved default passwords exist in src/vcf_enterprise_mcp."""
        src_root = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "src", "vcf_enterprise_mcp")
        )
        forbidden_patterns = [
            re.compile(r'["\']VMware1!MockPassword["\']'),
            re.compile(r'["\']admin123["\']'),
            re.compile(r'default_password\s*='),
        ]

        violations = []
        for root, _, files in os.walk(src_root):
            for fname in files:
                if fname.endswith(".py"):
                    fpath = os.path.join(root, fname)
                    with open(fpath, "r", encoding="utf-8") as f:
                        for line_no, line in enumerate(f, 1):
                            for pat in forbidden_patterns:
                                if pat.search(line):
                                    violations.append(f"{fpath}:{line_no} -> {line.strip()}")

        self.assertEqual(
            violations,
            [],
            f"Found forbidden hardcoded password patterns in production source code:\n" + "\n".join(violations),
        )


if __name__ == "__main__":
    unittest.main()
