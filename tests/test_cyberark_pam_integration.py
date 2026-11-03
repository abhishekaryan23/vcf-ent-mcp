# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Comprehensive unit and integration tests for CyberArk PAM Central Credential Provider (CCP)
integration into VCF Enterprise MCP.

Validates:
- SecretValue and SecretMaterial encapsulation and zero-leakage guarantees
- 'cyberark://' URI reference parsing and query parameter handling
- Central Credential Provider REST client communication, mock handling, and response mapping
- CyberArk AIMWebService error code translation (APPAP004E, APPAP133E, APPAP272E, APPAP330E, etc.)
- Strict fail-closed mTLS authentication and SSLContext configuration
- Pluggable SecretProviderRegistry dispatch and policy enforcement
- CredentialBroker zero-trust resolution and recursive data redaction
- Read-only protection: store() and delete() fail-closed
- Health check verification
"""

import json
import ssl
import tempfile
import unittest
from pathlib import Path
from typing import Dict, Tuple
import urllib.request

from vcf_enterprise_mcp.secrets.models import (
    SecretValue,
    SecretMaterial,
    SecretMetadata,
    SecretReference,
    RequestContext,
    CredentialPolicy,
)
from vcf_enterprise_mcp.secrets.base import (
    SecretProviderException,
    MissingCredentialException,
    CredentialPolicyViolationException,
)
from vcf_enterprise_mcp.secrets.registry import SecretProviderRegistry
from vcf_enterprise_mcp.auth.credential_broker import CredentialBroker
from vcf_enterprise_mcp.secrets.cyberark import (
    CyberArkCCPSecretProvider,
    CyberArkConfig,
    CyberArkOperatingMode,
    CyberArkQueryParams,
    CyberArkAccount,
    CyberArkAuthenticator,
    CyberArkCCPClient,
    CyberArkHealthChecker,
    CyberArkException,
    CyberArkAuthenticationException,
    CyberArkAccountNotFoundException,
    CyberArkSafeNotFoundException,
    CyberArkAccountLockedException,
    CyberArkRateLimitException,
    CyberArkConfigurationException,
)


class TestCyberArkPAMIntegration(unittest.TestCase):

    def setUp(self):
        self.config = CyberArkConfig(
            ccp_url="https://ccp.corp.local/AIMWebService/api/Accounts",
            app_id="VCF-Enterprise-MCP",
            default_safe="Enterprise-PAM",
            verify_ssl=True,
            timeout_seconds=5.0,
        )

    # --------------------------------------------------------------------------
    # 1. SecretValue & SecretMaterial Redaction and Safety Tests
    # --------------------------------------------------------------------------

    def test_secret_value_redaction_and_equality(self):
        secret = SecretValue("CyberArkP@ssw0rd99!")
        # Reveal for transport only
        self.assertEqual(secret.reveal_for_transport(), "CyberArkP@ssw0rd99!")
        self.assertEqual(secret.reveal(), "CyberArkP@ssw0rd99!")

        # Repr and str must be masked
        self.assertEqual(str(secret), "[REDACTED]")
        self.assertEqual(repr(secret), "<SecretValue [REDACTED]>")
        self.assertNotIn("CyberArkP@ssw0rd99!", str(secret))
        self.assertNotIn("CyberArkP@ssw0rd99!", repr(secret))

        # Constant-time comparison
        self.assertEqual(secret, "CyberArkP@ssw0rd99!")
        self.assertEqual(secret, SecretValue("CyberArkP@ssw0rd99!"))
        self.assertNotEqual(secret, "WrongPassword")

    def test_secret_material_username_and_password_encapsulation(self):
        material = SecretMaterial(
            username=SecretValue("administrator@vsphere.local"),
            password=SecretValue("TopSecretVCF2026!"),
            metadata=SecretMetadata(
                reference="cyberark://Enterprise-PAM/vcenter-prod",
                tenant_id="tenant-alpha",
                environment_id="env-prod",
            ),
        )

        # Transport reveals
        self.assertEqual(material.reveal_for_transport(), "TopSecretVCF2026!")
        self.assertIsNotNone(material.username)
        self.assertEqual(material.username.reveal_for_transport(), "administrator@vsphere.local")

        # Repr and str masking
        self.assertEqual(str(material), "[REDACTED]")
        self.assertEqual(repr(material), "<SecretMaterial [REDACTED]>")
        self.assertNotIn("TopSecretVCF2026!", str(material))
        self.assertNotIn("TopSecretVCF2026!", repr(material))
        self.assertNotIn("administrator@vsphere.local", str(material))

        # Duck-type equality on password
        self.assertEqual(material, "TopSecretVCF2026!")

    # --------------------------------------------------------------------------
    # 2. Reference URI Parsing Tests
    # --------------------------------------------------------------------------

    def test_cyberark_reference_uri_parsing(self):
        provider = CyberArkCCPSecretProvider(self.config)

        # Standard safe and object
        safe, obj, qparams, frag = provider.parse_reference("cyberark://VCF-PAM-Safe/vcenter-mgmt")
        self.assertEqual(safe, "VCF-PAM-Safe")
        self.assertEqual(obj, "vcenter-mgmt")
        self.assertEqual(qparams, {})
        self.assertIsNone(frag)

        # With fragment
        safe, obj, qparams, frag = provider.parse_reference("cyberark://VCF-PAM-Safe/vcenter-mgmt#password")
        self.assertEqual(safe, "VCF-PAM-Safe")
        self.assertEqual(obj, "vcenter-mgmt")
        self.assertEqual(frag, "password")

        # With query parameters (override appid, username, address)
        uri = "cyberark://VCF-PAM-Safe/vc01?appid=CustomApp&username=root&address=10.0.0.50"
        safe, obj, qparams, frag = provider.parse_reference(uri)
        self.assertEqual(safe, "VCF-PAM-Safe")
        self.assertEqual(obj, "vc01")
        self.assertEqual(qparams["appid"], "CustomApp")
        self.assertEqual(qparams["username"], "root")
        self.assertEqual(qparams["address"], "10.0.0.50")

        # Invalid reference
        with self.assertRaises(ValueError):
            provider.parse_reference("vault://path/to/secret")

    # --------------------------------------------------------------------------
    # 3. Central Credential Provider REST Client Tests
    # --------------------------------------------------------------------------

    def test_client_get_account_success(self):
        expected_payload = {
            "Content": "SuperSafeCyberArkPass1!",
            "UserName": "admin@vsphere.local",
            "Address": "vc-prod.corp.local",
            "Safe": "Enterprise-PAM",
            "Name": "vcenter-prod",
            "PolicyID": "VMware-vCenter",
            "DeviceType": "Operating System",
        }

        def mock_ccp(req: urllib.request.Request) -> Tuple[int, bytes, Dict[str, str]]:
            self.assertIn("AppID=VCF-Enterprise-MCP", req.full_url)
            self.assertIn("Safe=Enterprise-PAM", req.full_url)
            self.assertIn("Object=vcenter-prod", req.full_url)
            return 200, json.dumps(expected_payload).encode("utf-8"), {"Content-Type": "application/json"}

        client = CyberArkCCPClient(self.config, mock_handler=mock_ccp)
        query = CyberArkQueryParams(
            app_id=self.config.app_id,
            safe="Enterprise-PAM",
            object_name="vcenter-prod",
        )

        account = client.get_account(query)
        self.assertEqual(account.safe, "Enterprise-PAM")
        self.assertEqual(account.object_name, "vcenter-prod")
        self.assertEqual(account.user_name, "admin@vsphere.local")
        self.assertEqual(account.address, "vc-prod.corp.local")
        self.assertEqual(account.content.reveal_for_transport(), "SuperSafeCyberArkPass1!")

    # --------------------------------------------------------------------------
    # 4. CyberArk Error Code Mapping Tests
    # --------------------------------------------------------------------------

    def test_error_mapping_account_not_found(self):
        err_body = json.dumps({"ErrorCode": "APPAP004E", "ErrorMsg": "Password object was not found"}).encode("utf-8")

        def mock_ccp(req: urllib.request.Request) -> Tuple[int, bytes, Dict[str, str]]:
            return 404, err_body, {}

        client = CyberArkCCPClient(self.config, mock_handler=mock_ccp)
        query = CyberArkQueryParams(app_id="VCF", safe="Safe", object_name="nonexistent")

        with self.assertRaises(CyberArkAccountNotFoundException) as ctx:
            client.get_account(query)
        self.assertIn("APPAP004E", str(ctx.exception))
        self.assertIsInstance(ctx.exception, MissingCredentialException)

    def test_error_mapping_unauthorized_app(self):
        err_body = json.dumps({"ErrorCode": "APPAP133E", "ErrorMsg": "Application authentication failed"}).encode("utf-8")

        def mock_ccp(req: urllib.request.Request) -> Tuple[int, bytes, Dict[str, str]]:
            return 401, err_body, {}

        client = CyberArkCCPClient(self.config, mock_handler=mock_ccp)
        query = CyberArkQueryParams(app_id="UnauthApp", safe="Safe", object_name="vc")

        with self.assertRaises(CyberArkAuthenticationException) as ctx:
            client.get_account(query)
        self.assertIn("APPAP133E", str(ctx.exception))

    def test_error_mapping_safe_not_found(self):
        err_body = json.dumps({"ErrorCode": "APPAP272E", "ErrorMsg": "Safe does not exist or user lacks access"}).encode("utf-8")

        def mock_ccp(req: urllib.request.Request) -> Tuple[int, bytes, Dict[str, str]]:
            return 403, err_body, {}

        client = CyberArkCCPClient(self.config, mock_handler=mock_ccp)
        query = CyberArkQueryParams(app_id="VCF", safe="NonExistentSafe", object_name="vc")

        with self.assertRaises(CyberArkSafeNotFoundException) as ctx:
            client.get_account(query)
        self.assertIn("APPAP272E", str(ctx.exception))

    def test_error_mapping_account_locked(self):
        err_body = json.dumps({"ErrorCode": "APPAP330E", "ErrorMsg": "Account is locked by CPM"}).encode("utf-8")

        def mock_ccp(req: urllib.request.Request) -> Tuple[int, bytes, Dict[str, str]]:
            return 409, err_body, {}

        client = CyberArkCCPClient(self.config, mock_handler=mock_ccp)
        query = CyberArkQueryParams(app_id="VCF", safe="Safe", object_name="locked-acc")

        with self.assertRaises(CyberArkAccountLockedException) as ctx:
            client.get_account(query)
        self.assertIn("APPAP330E", str(ctx.exception))

    def test_error_mapping_rate_limited(self):
        err_body = json.dumps({"ErrorCode": "HTTP_429", "ErrorMsg": "Too Many Requests"}).encode("utf-8")

        def mock_ccp(req: urllib.request.Request) -> Tuple[int, bytes, Dict[str, str]]:
            return 429, err_body, {}

        client = CyberArkCCPClient(self.config, mock_handler=mock_ccp)
        query = CyberArkQueryParams(app_id="VCF", safe="Safe", object_name="vc")

        with self.assertRaises(CyberArkRateLimitException):
            client.get_account(query)

    # --------------------------------------------------------------------------
    # 5. SecretProviderRegistry Integration Tests
    # --------------------------------------------------------------------------

    def test_registry_resolve_cyberark_reference(self):
        expected_payload = {
            "Content": "ComplexSecretP@ss2026",
            "UserName": "svc-vcenter",
            "Safe": "Enterprise-PAM",
            "Name": "vcenter-prod",
        }

        def mock_ccp(req: urllib.request.Request) -> Tuple[int, bytes, Dict[str, str]]:
            return 200, json.dumps(expected_payload).encode("utf-8"), {}

        client = CyberArkCCPClient(self.config, mock_handler=mock_ccp)
        provider = CyberArkCCPSecretProvider(self.config, client=client)

        registry = SecretProviderRegistry()
        registry.register_provider("cyberark", provider)

        # Test standard resolve() -> returns SecretMaterial (duck-typing as SecretValue)
        secret = registry.resolve("cyberark://Enterprise-PAM/vcenter-prod")
        self.assertEqual(secret.reveal_for_transport(), "ComplexSecretP@ss2026")
        self.assertEqual(str(secret), "[REDACTED]")

        # Test resolve_material() -> exposes both username and password
        material = registry.resolve_material("cyberark://Enterprise-PAM/vcenter-prod")
        self.assertIsInstance(material, SecretMaterial)
        self.assertIsNotNone(material.username)
        self.assertEqual(material.username.reveal_for_transport(), "svc-vcenter")
        self.assertIsNotNone(material.password)
        self.assertEqual(material.password.reveal_for_transport(), "ComplexSecretP@ss2026")

    def test_credential_policy_enforcement(self):
        # Policy disallowing enterprise secret managers
        strict_policy = CredentialPolicy(allow_enterprise_secret_manager=False)
        registry = SecretProviderRegistry(policy=strict_policy)

        with self.assertRaises(CredentialPolicyViolationException):
            registry.resolve("cyberark://Enterprise-PAM/vcenter-prod", environment_id="env-prod")

    # --------------------------------------------------------------------------
    # 6. CredentialBroker Zero-Trust Redaction Tests
    # --------------------------------------------------------------------------

    def test_credential_broker_redacts_cyberark_material(self):
        expected_payload = {
            "Content": "HiddenPassword!",
            "UserName": "audit-svc",
            "Safe": "Enterprise-PAM",
            "Name": "sddc-manager",
        }

        def mock_ccp(req: urllib.request.Request) -> Tuple[int, bytes, Dict[str, str]]:
            return 200, json.dumps(expected_payload).encode("utf-8"), {}

        client = CyberArkCCPClient(self.config, mock_handler=mock_ccp)
        provider = CyberArkCCPSecretProvider(self.config, client=client)

        registry = SecretProviderRegistry()
        registry.register_provider("cyberark", provider)
        broker = CredentialBroker(secret_registry=registry)

        material = broker.resolve_material("cyberark://Enterprise-PAM/sddc-manager")
        self.assertEqual(material.reveal_for_transport(), "HiddenPassword!")

        # Verify that passing material into arbitrary data structure is scrubbed
        tainted_data = {
            "target": "vc01.corp.local",
            "credentials": {
                "cyberark_obj": material,
                "password": material.password,
            },
            "history": [material],
        }

        cleaned = broker.redact_secrets_from_data(tainted_data)
        self.assertEqual(cleaned["credentials"]["cyberark_obj"], "[REDACTED]")
        self.assertEqual(cleaned["credentials"]["password"], "[REDACTED]")
        self.assertEqual(cleaned["history"][0], "[REDACTED]")

        # Ensure no plaintext secret leaked into any string in cleaned
        cleaned_json = json.dumps(cleaned)
        self.assertNotIn("HiddenPassword!", cleaned_json)

    # --------------------------------------------------------------------------
    # 7. Read-Only Fail-Closed Protection Tests
    # --------------------------------------------------------------------------

    def test_store_and_delete_fail_closed(self):
        provider = CyberArkCCPSecretProvider(self.config)
        with self.assertRaises(SecretProviderException) as ctx_store:
            provider.store("cyberark://Safe/acc", SecretValue("pwd"))
        self.assertIn("read-only", str(ctx_store.exception).lower())

        with self.assertRaises(SecretProviderException) as ctx_del:
            provider.delete("cyberark://Safe/acc")
        self.assertIn("read-only", str(ctx_del.exception).lower())

    # --------------------------------------------------------------------------
    # 8. Health Check Verification Tests
    # --------------------------------------------------------------------------

    def test_health_check_unbound_degraded(self):
        unbound_cfg = CyberArkConfig(ccp_url="")
        checker = CyberArkHealthChecker(unbound_cfg)
        health = checker.check_health()
        self.assertEqual(health.status, "DEGRADED")
        self.assertEqual(health.provider_name, "cyberark")

    def test_authenticator_mtls_validation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            cert_file = tmp_path / "client.crt"
            key_file = tmp_path / "client.key"
            cert_file.write_text("DUMMY CERT", encoding="utf-8")
            key_file.write_text("DUMMY KEY", encoding="utf-8")

            cfg = CyberArkConfig(
                ccp_url="https://ccp.corp.local/AIMWebService/api/Accounts",
                client_cert_path=str(cert_file),
                client_key_path=str(key_file),
                verify_ssl=True,
            )
            auth = CyberArkAuthenticator(cfg)
            # Loading fake cert chain should raise CyberArkConfigurationException
            with self.assertRaises(CyberArkConfigurationException):
                auth.create_ssl_context()


if __name__ == "__main__":
    unittest.main()
