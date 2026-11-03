# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Contract guard: every upstream endpoint used by the real-VCF providers and every
spec-verified registry contract must exist in the official vcf-api-specs
(github.com/vmware/vcf-api-specs tags 9.0.0.0, 9.1.0.0, 9.1.1.0).

Broadcom's specifications are not redistributed here. To run the spec-dependent checks, clone
https://github.com/vmware/vcf-api-specs (ideally at tag 9.1.1.0) and point VCF_API_SPECS_DIR at the
clone (or at its `specifications/` folder). Without it those tests skip rather than pass vacuously.
"""

import json
import os
import re
import unittest
from pathlib import Path
from urllib.parse import urlsplit

from vcf_enterprise_mcp.adapter.api_registry import OFFICIAL_BROADCOM_APIS

ROOT = Path(__file__).resolve().parents[1]
SPECS = Path(os.environ["VCF_API_SPECS_DIR"]).expanduser() if os.environ.get("VCF_API_SPECS_DIR") else None
PROVIDERS = ROOT / "src/vcf_enterprise_mcp/adapter/providers"
SESSIONS = ROOT / "src/vcf_enterprise_mcp/adapter/transport/vcf_sessions.py"
PLATFORM = ROOT / "src/vcf_enterprise_mcp/adapter/platform.py"

# Provider files that target real appliances (the Digital Twin provider is excluded).
REAL_PROVIDER_FILES = ["vcenter.py", "sddc.py", "nsx.py", "operations.py"]

CALL_RE = re.compile(r'(?:self\.request|request)\(\s*"(GET|POST|PUT|PATCH|DELETE)",\s*f?"(/[^"]+)"')
GET_JSON_RE = re.compile(r'self\._get_json\(\s*f?"(/[^"]+)"')
SESSION_RE = re.compile(r'self\._post\(\s*"(/[^"]+)"[^)]*?(?:method="(GET|POST|PUT|PATCH|DELETE)")?\)')


def _norm(path: str) -> str:
    return re.sub(r"\{[^}]*\}", "{}", path.split("?")[0]).rstrip("/")


HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}


def _official_index():
    """(METHOD, normalized path) -> spec files, built from every OpenAPI document under VCF_API_SPECS_DIR."""
    import yaml
    loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
    root = SPECS / "specifications" if (SPECS / "specifications").is_dir() else SPECS
    index = {}
    for file in sorted(p for p in root.rglob("*") if p.suffix in (".json", ".yaml", ".yml")):
        try:
            doc = json.loads(file.read_text()) if file.suffix == ".json" else yaml.load(file.read_text(), Loader=loader)
        except Exception:
            continue
        if not isinstance(doc, dict) or not isinstance(doc.get("paths"), dict):
            continue
        base = doc.get("basePath") or (urlsplit(doc["servers"][0]["url"]).path.rstrip("/") if doc.get("servers") else "")
        for path, item in doc["paths"].items():
            if not isinstance(item, dict):
                continue
            for method in item:
                if method in HTTP_METHODS:
                    for candidate in {path, base + path}:
                        index.setdefault((method.upper(), _norm(candidate)), set()).add(file.name)
    return index


@unittest.skipUnless(SPECS and SPECS.exists(), "set VCF_API_SPECS_DIR to a clone of github.com/vmware/vcf-api-specs")
class TestBroadcomContractAlignment(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.index = _official_index()

    def _assert_official(self, method: str, path: str, where: str):
        self.assertIn(
            (method, _norm(path)), self.index,
            f"{where}: {method} {path} is not an operation in the official vcf-api-specs",
        )

    def test_provider_endpoints_exist_in_official_specs(self):
        seen = 0
        for name in REAL_PROVIDER_FILES:
            source = (PROVIDERS / name).read_text()
            for method, path in CALL_RE.findall(source):
                self._assert_official(method, path, name)
                seen += 1
            for path in GET_JSON_RE.findall(source):
                self._assert_official("GET", path, name)
                seen += 1
        self.assertGreater(seen, 20)

    def test_platform_direct_calls_exist_in_official_specs(self):
        for method, path in CALL_RE.findall(PLATFORM.read_text()):
            self._assert_official(method, path, "platform.py")

    def test_session_login_endpoints_exist_in_official_specs(self):
        found = SESSION_RE.findall(SESSIONS.read_text())
        self.assertGreaterEqual(len(found), 4)
        for path, method in found:
            self._assert_official(method or "POST", path, "vcf_sessions.py")

    def test_spec_verified_registry_contracts_exist(self):
        for contract in OFFICIAL_BROADCOM_APIS:
            if contract.spec_verified:
                self._assert_official(contract.method, contract.path, contract.api_id)


class TestContractHygiene(unittest.TestCase):
    """Checks that need no copy of the specifications."""

    def test_unpublished_products_are_flagged(self):
        """Live Site Recovery APIs are not in vcf-api-specs and must not claim verification."""
        srm = [c for c in OFFICIAL_BROADCOM_APIS if c.subsystem == "srm"]
        self.assertTrue(srm)
        self.assertTrue(all(not c.spec_verified for c in srm))

    def test_known_fabricated_paths_are_gone(self):
        sources = "".join((PROVIDERS / n).read_text() for n in REAL_PROVIDER_FILES)
        for bad in ("/v1/system/health\"", "/api/vcenter/vm/{vm_id}/snapshots", "/suite-api/api/telemetry/promql"):
            self.assertNotIn(bad, sources)


if __name__ == "__main__":
    unittest.main()
