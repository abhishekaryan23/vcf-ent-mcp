# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""Guided setup: why a check failed, and what happens to the saved password (independent review F3, F2, F14)."""

import datetime
import json
import urllib.parse

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from tests.test_guided_setup import GuidedSetupBase, MemorySecrets, browser_submit  # noqa: F401
from vcf_enterprise_mcp.adapter.ssrf_guard import SSRFGuard
from vcf_enterprise_mcp.adapter.transport.base import TransportResponse
from vcf_enterprise_mcp.adapter.transport.errors import UpstreamConnectionException, UpstreamTLSException
from vcf_enterprise_mcp.adapter.transport.http import HTTPTransport
from vcf_enterprise_mcp.core.errors import SSRFViolationException
from vcf_enterprise_mcp.setup.wizard import credential_reference

VC_URL = "https://vcenter.corp.internal"


def _ca_pem(path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Lab CA")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=2))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, hashes.SHA256()))
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return str(path)


def ok_vcenter(req):
    path = urllib.parse.urlsplit(req.url).path
    if path == "/api/session" and req.method == "POST":
        return TransportResponse(201, body=b'"vc-session"')
    if path == "/api/session":
        return TransportResponse(200, body=b'{"user": "svc-mcp@corp.com"}')
    if path.endswith("/HasUserPrivilegeOnEntities"):
        return TransportResponse(200, body=b"[]")
    return TransportResponse(404)


class Failures(GuidedSetupBase):
    def use(self, handler, **guard):
        self.wizard.transport_factory = lambda hosts: HTTPTransport(mock_handler=handler, max_retries=0, **guard)

    def start(self):
        """vCenter-only setup, passwords entered through the portal, up to the verification step."""
        r = self.call("vcf_setup", {"target": "lab", "goals": ["vm_operations"], "endpoints": {"vcenter": VC_URL},
                                    "usernames": {"vcenter": "svc-mcp@corp.com"}})["result"]["structuredContent"]
        self.assertEqual(r["status"], "NEEDS_CREDENTIALS")
        browser_submit(r["credential_pages"][0]["url"])
        return self.call("vcf_setup", {"resume": r["resume"]})["result"]["structuredContent"]

    def has_password(self):
        try:
            self.secrets.resolve(credential_reference("vcenter"))
            return True
        except Exception:
            return False

    def test_a_real_login_rejection_discards_the_password(self):
        self.use(lambda req: TransportResponse(401, body=b"{}"))
        out = self.start()
        self.assertEqual(out["status"], "ACCESS_CHECK_FAILED")
        self.assertEqual(out["passwords_discarded"], ["vcenter"])
        self.assertFalse(self.has_password())
        self.assertIn("enter the password again", out["message"])

    def test_tls_failure_keeps_the_password_and_names_the_config_key(self):
        def handler(req):
            raise UpstreamTLSException(req.url, "[SSL: CERTIFICATE_VERIFY_FAILED] unable to get local issuer certificate")
        self.use(handler)
        out = self.start()
        self.assertEqual(out["status"], "ACCESS_CHECK_FAILED")
        self.assertEqual(out["passwords_kept"], ["vcenter"])
        self.assertEqual(out["passwords_discarded"], [])
        self.assertTrue(self.has_password())
        problem = out["problems"][0]
        self.assertEqual(problem["cause"], "tls_certificate")
        self.assertEqual(problem["config_key"], "vcf.ca_cert_path")
        self.assertIn("ca_cert_path", problem["fix"])
        self.assertIn("were kept", out["message"])
        self.assertTrue(any(q["field"] == "network.ca_cert_path" for q in out["questions"]))

        # The user supplies the CA: it is written to the config, setup re-checks WITHOUT asking for the password again.
        ca = _ca_pem(self.home / "lab-ca.pem")
        self.use(ok_vcenter)
        out = self.call("vcf_setup", {"resume": out["resume"], "network": {"ca_cert_path": ca}})["result"]["structuredContent"]
        self.assertNotEqual(out["status"], "NEEDS_CREDENTIALS")
        self.assertIn(ca, (self.home / "config.yaml").read_text())
        self.assertTrue(self.has_password())

    def test_bad_ca_path_is_refused(self):
        self.use(lambda req: (_ for _ in ()).throw(UpstreamTLSException(req.url, "certificate verify failed")))
        out = self.start()
        bad = self.call("vcf_setup", {"resume": out["resume"], "network": {"ca_cert_path": str(self.home / "nope.pem")}})
        self.assertIn("not a readable file", json.dumps(bad))

    def test_allowlist_block_is_an_mcp_config_problem_with_the_exact_line(self):
        def handler(req):
            raise SSRFViolationException("SSRF violation: Host 'vcenter.corp.internal' does not match allowed enterprise DNS suffixes ([]).")
        self.use(handler)
        out = self.start()
        self.assertTrue(self.has_password())
        problem = out["problems"][0]
        self.assertEqual(problem["cause"], "mcp_allowlist_dns_suffix")
        self.assertTrue(problem["mcp_config_problem"])
        self.assertEqual(problem["config_key"], "vcf.allowed_dns_suffixes")
        self.assertIn(".corp.internal", problem["fix"])
        self.assertEqual(out["fix_in_config_file"][0]["config_key"], "vcf.allowed_dns_suffixes")

    def test_connection_refused_and_proxy_causes(self):
        self.use(lambda req: (_ for _ in ()).throw(UpstreamConnectionException(req.url, "[Errno 61] Connection refused")))
        out = self.start()
        self.assertEqual(out["problems"][0]["cause"], "connection_refused")
        self.assertTrue(self.has_password())
        self.use(lambda req: (_ for _ in ()).throw(UpstreamConnectionException(req.url, "proxy p:3128 refused CONNECT to vc:443: HTTP/1.1 403 Forbidden")))
        out = self.call("vcf_setup", {"resume": out["resume"]})["result"]["structuredContent"]
        self.assertEqual(out["problems"][0]["cause"], "proxy")
        self.assertEqual(out["problems"][0]["config_key"], "vcf.https_proxy")

    def test_authenticated_but_forbidden_nsx_account_keeps_its_password(self):
        r = self.call("vcf_setup", {"target": "lab", "goals": ["network"], "endpoints": {"nsx": "https://nsx.corp.internal"},
                                    "usernames": {"nsx": "svc-nsx"}})["result"]["structuredContent"]
        browser_submit(r["credential_pages"][0]["url"])
        self.use(lambda req: TransportResponse(403, body=b"{}"))
        out = self.call("vcf_setup", {"resume": r["resume"]})["result"]["structuredContent"]
        self.assertEqual(out["status"], "ACCESS_CHECK_FAILED")
        self.assertEqual(out["passwords_kept"], ["nsx"])
        self.assertIn("not permitted", out["components"]["nsx"]["error"])


class DiscoveredAppliances(GuidedSetupBase):
    """SDDC Manager names appliances by canonical FQDN; this MCP's own allowlist may not cover them (F2, F14)."""

    def handler(self, req):
        parts = urllib.parse.urlsplit(req.url)
        if parts.hostname != "sddc-manager.corp.internal":
            return TransportResponse(404)
        if parts.path == "/v1/tokens":
            return TransportResponse(200, body=b'{"accessToken": "acc", "refreshToken": {"id": "r"}}')
        if parts.path == "/v1/domains":
            return TransportResponse(200, body=b'{"elements": []}')
        if parts.path == "/v1/users":
            return TransportResponse(200, body=b'{"elements": [{"name": "svc-lc", "role": {"name": "OPERATOR"}}]}')
        if parts.path == "/v1/vcenters":
            return TransportResponse(200, body=b'{"elements": [{"fqdn": "vc-mgmt01.nwg.lab"}]}')
        if parts.path == "/v1/nsxt-clusters":
            return TransportResponse(200, body=b'{"elements": [{"vipFqdn": "nsx-wld01.nwg.lab"}]}')
        return TransportResponse(404)

    def test_blocked_discovered_appliances_are_offered_as_a_question_not_added_silently(self):
        self.wizard.transport_factory = lambda hosts: HTTPTransport(
            mock_handler=self.handler, max_retries=0,
            ssrf_guard=SSRFGuard(allowed_dns_suffixes=[".corp.internal"], dns_resolver=lambda h, p: ["10.1.1.5"], mock_dns={},
                                 allow_lab_dns_fallback=False, enforce_https=True))
        r = self.call("vcf_setup", {"target": "lab", "goals": ["lifecycle"], "endpoints": {"sddc_manager": "https://sddc-manager.corp.internal"},
                                    "usernames": {"sddc_manager": "svc-lc"}})["result"]["structuredContent"]
        browser_submit(r["credential_pages"][0]["url"])
        asked = self.call("vcf_setup", {"resume": r["resume"]})["result"]["structuredContent"]
        self.assertEqual(asked["status"], "NEEDS_INPUT")
        self.assertEqual(asked["step"], "network")
        self.assertEqual({b["appliance"] for b in asked["blocked_appliances"]}, {"vc-mgmt01.nwg.lab", "nsx-wld01.nwg.lab"})
        self.assertIn("not an appliance fault", asked["message"])
        self.assertFalse((self.home / "config.yaml").exists())  # nothing changed until the user says yes

        done = self.call("vcf_setup", {"resume": asked["resume"], "network": {"apply_suggested_changes": True}})["result"]["structuredContent"]
        # continues to the safety question; answer it to finish
        self.assertIn(done["status"], ("NEEDS_INPUT", "COMPLETE"))
        if done["status"] == "NEEDS_INPUT":
            done = self.call("vcf_setup", {"resume": done["resume"], "disable": [], "read_only": True})["result"]["structuredContent"]
        self.assertEqual(done["status"], "COMPLETE")
        import yaml
        cfg = yaml.safe_load((self.home / "config.yaml").read_text())
        self.assertEqual(cfg["vcf"]["allowed_dns_suffixes"], [".corp.internal", ".nwg.lab"])
        self.assertTrue(done["access_report"]["components"]["sddc_manager"]["roles"] == ["OPERATOR"])

    def test_declining_continues_with_a_warning(self):
        self.wizard.transport_factory = lambda hosts: HTTPTransport(
            mock_handler=self.handler, max_retries=0,
            ssrf_guard=SSRFGuard(allowed_dns_suffixes=[".corp.internal"], dns_resolver=lambda h, p: ["10.1.1.5"], mock_dns={},
                                 allow_lab_dns_fallback=False, enforce_https=True))
        r = self.call("vcf_setup", {"target": "lab", "goals": ["lifecycle"], "endpoints": {"sddc_manager": "https://sddc-manager.corp.internal"},
                                    "usernames": {"sddc_manager": "svc-lc"}})["result"]["structuredContent"]
        browser_submit(r["credential_pages"][0]["url"])
        asked = self.call("vcf_setup", {"resume": r["resume"]})["result"]["structuredContent"]
        out = self.call("vcf_setup", {"resume": asked["resume"], "network": {}, "disable": [], "read_only": True})["result"]["structuredContent"]
        self.assertEqual(out["status"], "COMPLETE")
        self.assertTrue(any("not an appliance fault" in w for w in out["access_report"]["warnings"]))
        import yaml
        self.assertNotIn(".nwg.lab", yaml.safe_load((self.home / "config.yaml").read_text())["vcf"].get("allowed_dns_suffixes", []))

    def test_ip_literals_derive_no_nonsense_suffix(self):
        w = self.wizard
        self.assertEqual(w._suffixes_for(["10.0.0.5", "vc.corp.example", "localhost", "192.168.1.9"]), [".corp.example", "localhost"])
