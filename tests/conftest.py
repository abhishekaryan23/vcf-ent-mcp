# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""Test isolation: nothing a test does may touch the developer's real home directory or ambient VCF_* settings."""

import os

import pytest

_STATE_ENV = ("VCF_MCP_HOME", "VCF_MCP_DB_PATH", "VCF_MCP_CREDENTIALS_PATH", "VCF_MCP_MASTER_KEY_PATH", "VCF_MCP_KMS_KEY_PATH",
              "VCF_MCP_LAB_JWT_KEY_PATH", "VCF_ENTERPRISE_MCP_CONFIG", "VCF_MCP_AUTH_TOKEN", "VCF_MCP_ENV", "VCF_MCP_ALLOW_LAB_TOKENS",
              "HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy")


@pytest.fixture(scope="session", autouse=True)
def _isolated_home(tmp_path_factory):
    """Point HOME at a throwaway directory for the whole session (state dir, key files, config all land there)."""
    home = tmp_path_factory.mktemp("home")
    saved = {k: os.environ.get(k) for k in ("HOME",) + _STATE_ENV}
    os.environ["HOME"] = str(home)
    for key in _STATE_ENV:
        os.environ.pop(key, None)
    yield home
    for key, value in saved.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
