# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Unit tests for Dynamic CycloneDX 1.5 JSON Software Bill of Materials (SBOM) Generation.
Verifies runtime environment introspection, component enumeration, purl formatting,
dependency graph construction, cryptographic provenance attestation, and disk export.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import unittest

from vcf_enterprise_mcp.audit.sbom import (
    generate_enterprise_sbom,
    _normalize_package_name,
    _extract_license,
    _compute_distribution_hash,
)


class TestDynamicCycloneDXSBOM(unittest.TestCase):
    """Test suite validating dynamic CycloneDX 1.5 JSON SBOM generation."""

    def test_cyclonedx_top_level_structure(self):
        """Validates that the generated SBOM conforms to CycloneDX 1.5 JSON root schema."""
        sbom = generate_enterprise_sbom(
            component_name="vcf-enterprise-mcp-control-plane",
            version="1.0.0",
        )

        self.assertEqual(sbom["bomFormat"], "CycloneDX")
        self.assertEqual(sbom["specVersion"], "1.5")
        self.assertEqual(sbom["version"], 1)
        self.assertTrue(sbom["serialNumber"].startswith("urn:uuid:"))

        # Metadata
        metadata = sbom["metadata"]
        self.assertIn("timestamp", metadata)
        self.assertIn("tools", metadata)
        self.assertEqual(metadata["tools"][0]["name"], "Enterprise-SBOM-Generator")
        self.assertEqual(metadata["tools"][0]["version"], "1.5.0")

        # Root Component
        root_comp = metadata["component"]
        self.assertEqual(root_comp["type"], "application")
        self.assertEqual(root_comp["name"], "vcf-enterprise-mcp-control-plane")
        self.assertEqual(root_comp["version"], "1.0.0")
        self.assertTrue(root_comp["purl"].startswith("pkg:pypi/"))
        self.assertGreater(len(root_comp["hashes"]), 0)
        self.assertEqual(root_comp["hashes"][0]["alg"], "SHA-256")

    def test_dynamic_runtime_introspection(self):
        """Validates that real installed distributions in the runtime environment are introspected."""
        sbom = generate_enterprise_sbom()
        components = sbom["components"]

        # Environment must contain at least core dependencies
        self.assertGreaterEqual(len(components), 15)

        comp_names = {c["name"] for c in components}
        # Check for installed dependencies
        expected_sample = {"httpx", "pyjwt", "psycopg", "pyyaml"}
        found = expected_sample.intersection(comp_names)
        self.assertGreaterEqual(len(found), 2, f"Expected sample dependencies not found in {comp_names}")

        # Check structure of introspected components
        for comp in components:
            self.assertEqual(comp["type"], "library")
            self.assertTrue(comp["purl"].startswith("pkg:pypi/"))
            self.assertEqual(comp["bom-ref"], comp["purl"])
            self.assertTrue(len(comp["version"]) > 0)
            self.assertIn("licenses", comp)
            self.assertIsInstance(comp["licenses"], list)
            self.assertGreater(len(comp["licenses"]), 0)

            # Check hashes
            self.assertIn("hashes", comp)
            self.assertEqual(comp["hashes"][0]["alg"], "SHA-256")
            self.assertEqual(len(comp["hashes"][0]["content"]), 64)

    def test_dependency_graph_structure(self):
        """Validates that the dependency graph maps root and component relationships."""
        sbom = generate_enterprise_sbom()
        dependencies = sbom["dependencies"]
        self.assertIsInstance(dependencies, list)
        self.assertGreater(len(dependencies), 0)

        # Root dependency entry
        root_dep = dependencies[0]
        self.assertEqual(root_dep["ref"], sbom["metadata"]["component"]["bom-ref"])
        self.assertIsInstance(root_dep["dependsOn"], list)
        self.assertGreater(len(root_dep["dependsOn"]), 0)

        # Each dependency entry has valid ref and dependsOn
        for dep in dependencies:
            self.assertTrue(dep["ref"].startswith("pkg:pypi/"))
            self.assertIsInstance(dep["dependsOn"], list)
            for child_ref in dep["dependsOn"]:
                self.assertTrue(child_ref.startswith("pkg:pypi/"))

    def test_cryptographic_provenance_signature(self):
        """Validates that a cryptographic provenance attestation signature is affixed."""
        sbom = generate_enterprise_sbom()
        self.assertIn("signature", sbom)
        sig = sbom["signature"]
        self.assertEqual(sig["algorithm"], "SHA256withRSA")
        self.assertEqual(sig["keyId"], "key-enterprise-release-signer-2026")
        self.assertTrue(sig["value"].startswith("SIG_PROVENANCE_ATTESTATION:"))

    def test_export_to_disk(self):
        """Validates that exporting the SBOM writes valid CycloneDX 1.5 JSON to the target file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "sbom", "cyclonedx-sbom.json")
            sbom = generate_enterprise_sbom(export_path=out_file)

            self.assertTrue(os.path.exists(out_file))
            with open(out_file, "r", encoding="utf-8") as f:
                loaded = json.load(f)

            self.assertEqual(loaded["bomFormat"], "CycloneDX")
            self.assertEqual(loaded["specVersion"], "1.5")
            self.assertEqual(len(loaded["components"]), len(sbom["components"]))


if __name__ == "__main__":
    unittest.main()
