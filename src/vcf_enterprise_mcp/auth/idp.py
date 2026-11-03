# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Enterprise Identity Provider (IdP) Token Validator.
Complies with MCP 2026-07-28 Enterprise-Managed Authorization and OAuth 2.0 with RFC 8707 Resource Indicators.
Enforces:
- Cryptographic JWT Signature Verification
- Strict Algorithm Allowlist (RS256, ES256)
- Trusted Issuer & Audience Matching
- Verified Tenant Isolation Claims
- ZERO substring or hardcoded identity backdoors
"""

from __future__ import annotations
from typing import Dict, Any, Optional, List
from vcf_enterprise_mcp.auth.identity import Principal
from vcf_enterprise_mcp.auth.jwks import JWKSManager
from vcf_enterprise_mcp.auth.token_validator import TokenValidator
from vcf_enterprise_mcp.config.settings import IdPConfig
from vcf_enterprise_mcp.core.errors import AuthorizationDeniedException


class EnterpriseIdPValidator:
    """Validates enterprise identity tokens and maps claims into authenticated Principal context."""

    def __init__(
        self,
        config: Optional[IdPConfig] = None,
        expected_resource_indicator: str = "urn:mcp:vcf-control-plane",
        enforce_jwt_claims: bool = True,
        jwks_manager: Optional[JWKSManager] = None,
    ):
        self.config = config or IdPConfig()
        self.expected_resource_indicator = expected_resource_indicator
        self.enforce_jwt_claims = enforce_jwt_claims
        self.jwks_manager = jwks_manager or JWKSManager()
        self.validator = TokenValidator(
            config=self.config,
            jwks_manager=self.jwks_manager,
            expected_resource_indicator=self.expected_resource_indicator,
        )

    def validate_bearer_token(self, auth_header: Optional[str], client_ip: str = "127.0.0.1") -> Principal:
        """
        Parses Authorization header (Bearer <token>), cryptographically verifies token,
        and constructs authenticated Principal with verified tenant_id and entitlements.
        Bans all substring-based authentication shortcuts.
        """
        return self.validator.validate_token(auth_header, client_ip)
