# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""An appliance this MCP is not allowed to contact is a configuration problem, never an appliance fault (review F2)."""

import json

from vcf_enterprise_mcp.adapter.connectivity import classify_connection_error
from vcf_enterprise_mcp.adapter.transport.errors import UpstreamTLSException, UpstreamConnectionException
from vcf_enterprise_mcp.core.errors import SSRFViolationException
from vcf_enterprise_mcp.diagnostics.engine import Collector, correlate, FAIL, UNKNOWN

BLOCKED = SSRFViolationException(
    "SSRF violation: Host 'vc-mgmt01.nwg.lab' does not match allowed enterprise DNS suffixes (['localhost']).")


class Prov:
    def __init__(self, error=None, data=None):
        self.error, self.data = error, data

    def request(self, method, path, **kw):
        if self.error:
            raise self.error

        class R:
            def json(_):
                return self.data
        return R()


def collector(vc_error):
    def factory(kind, url):
        if kind == "sddc_manager":
            return Prov(data={"elements": []})
        return Prov(error=vc_error)
    return Collector(factory, "https://sddc.corp.example", None, lambda fqdn: f"https://{fqdn}")


def test_allowlist_block_is_unknown_with_the_config_key_not_a_failed_appliance():
    c = collector(BLOCKED)
    c.vcenter("vc-mgmt01.nwg.lab", "mgmt")
    ev = c.items[0]
    assert ev.status == UNKNOWN and ev.check == "mcp_config"
    assert "not an appliance fault" in ev.summary and ev.detail["config_key"] == "vcf.allowed_dns_suffixes"
    result = correlate(c.items)
    top = result["findings"][0]
    assert top["severity"] == "INFO" and top["title"].startswith("MCP configuration problem")
    assert "vcf.allowed_dns_suffixes" in " ".join(top["next_steps"]) and ".nwg.lab" in " ".join(top["next_steps"])
    assert "No appliance fault was found" in result["summary"]
    assert "Could not reach the appliance" not in json.dumps(result)


def test_a_real_appliance_failure_still_ranks_above_the_config_note():
    def factory(kind, url):
        if kind == "sddc_manager":
            return Prov(data={"elements": []})
        return Prov(error=BLOCKED if "nwg.lab" in url else UpstreamConnectionException(url, "Connection refused"))
    c = Collector(factory, "https://s", None, lambda f: f"https://{f}")
    c.vcenter("vc-mgmt01.nwg.lab", "mgmt")
    c.vcenter("vc-real.corp.example", "wld")
    findings = correlate(c.items)["findings"]
    assert findings[0]["severity"] != "INFO" and findings[-1]["severity"] == "INFO"
    assert any(e.status == FAIL and e.target == "vc-real.corp.example" for e in c.items)


def test_classifier_causes_and_exact_fixes():
    class Cfg:
        allowed_dns_suffixes = [".corp.example"]
        allowed_cidrs = []
    p = classify_connection_error(BLOCKED, "https://vc-mgmt01.nwg.lab", Cfg())
    assert p.cause == "mcp_allowlist_dns_suffix" and p.mcp_config_problem
    assert 'allowed_dns_suffixes: [".corp.example", ".nwg.lab"]' in p.fix  # existing entries kept, addition shown

    ip = classify_connection_error(SSRFViolationException("SSRF violation: Host 'vc' (IP: 203.0.113.9) is not in allowed enterprise CIDRs."), "https://vc")
    assert ip.cause == "mcp_allowlist_cidr" and "203.0.113.9/32" in ip.fix and "10.0.0.0/8" in ip.fix  # a list replaces the defaults

    loop = classify_connection_error(SSRFViolationException("SSRF violation: Loopback 'localhost' is prohibited in production mode (IP: 127.0.0.1)."), "https://localhost")
    assert loop.config_key == "vcf.allow_loopback_targets"

    tls = classify_connection_error(UpstreamTLSException("https://x", "certificate verify failed: unable to get local issuer certificate"), "https://x")
    assert tls.cause == "tls_certificate" and tls.config_key == "vcf.ca_cert_path" and not tls.mcp_config_problem
    expired = classify_connection_error(UpstreamTLSException("https://x", "certificate has expired"), "https://x")
    assert "expired" in expired.summary and expired.config_key is None

    dns = classify_connection_error(SSRFViolationException("DNS resolution failed for 'vc.nwg.lab': [Errno 8] nodename nor servname"), "https://vc.nwg.lab")
    assert dns.cause == "dns" and dns.config_key == "vcf.endpoint_overrides" and not dns.mcp_config_problem
    refused = classify_connection_error(UpstreamConnectionException("https://x", "[Errno 61] Connection refused"), "https://x")
    assert refused.cause == "connection_refused"
