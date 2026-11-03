# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Data models and schemas for CyberArk PAM Central Credential Provider (CCP) integration.
"""

from __future__ import annotations

import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional

from vcf_enterprise_mcp.secrets.models import SecretValue, SecretMaterial, SecretMetadata


class CyberArkOperatingMode(str, Enum):
    """Supported CyberArk deployment integration modes."""
    CYBERARK_CCP = "CYBERARK_CCP"                      # Central Credential Provider (REST / Self-Hosted & Priv Cloud)
    CYBERARK_PRIVILEGE_CLOUD = "CYBERARK_PRIVILEGE_CLOUD"  # Direct Privilege Cloud REST API (Phase 2)
    CYBERARK_SECRETS_MANAGER = "CYBERARK_SECRETS_MANAGER"  # CyberArk Conjur / Secrets Manager (Phase 2)


@dataclass
class CyberArkQueryParams:
    """Parameters required for querying account credentials via CyberArk CCP AIMWebService."""
    app_id: str
    safe: str
    folder: str = "root"
    object_name: Optional[str] = None
    user_name: Optional[str] = None
    address: Optional[str] = None
    reason: Optional[str] = "VCF Enterprise MCP runtime authentication"
    dual_control_request_id: Optional[str] = None

    def to_dict(self) -> Dict[str, str]:
        params: Dict[str, str] = {
            "AppID": self.app_id,
            "Safe": self.safe,
        }
        if self.folder and self.folder.lower() != "root":
            params["Folder"] = self.folder
        if self.object_name:
            params["Object"] = self.object_name
        if self.user_name:
            params["UserName"] = self.user_name
        if self.address:
            params["Address"] = self.address
        if self.reason:
            params["Reason"] = self.reason
        if self.dual_control_request_id:
            params["DualControlRequestID"] = self.dual_control_request_id
        return params

    def to_query_string(self) -> str:
        return urllib.parse.urlencode(self.to_dict())


@dataclass
class CyberArkAccount:
    """Represents a privileged account record retrieved from CyberArk Central Credential Provider."""
    safe: str
    object_name: str
    content: SecretValue  # Masked password/secret
    user_name: Optional[str] = None
    address: Optional[str] = None
    policy_id: Optional[str] = None
    device_type: Optional[str] = None
    folder: str = "root"
    extra_properties: Dict[str, Any] = field(default_factory=dict)

    def to_secret_material(
        self,
        reference_uri: str,
        tenant_id: str = "tenant-default",
        environment_id: str = "env-prod",
    ) -> SecretMaterial:
        """Converts CyberArk account record into unified SecretMaterial with redaction safeguards."""
        metadata = SecretMetadata(
            reference=reference_uri,
            version=1,
            key_id=f"{self.safe}/{self.object_name}",
            tenant_id=tenant_id,
            environment_id=environment_id,
            description=f"CyberArk account {self.user_name or self.object_name} from safe {self.safe}",
        )
        username_val = SecretValue(self.user_name) if self.user_name else None
        return SecretMaterial(
            username=username_val,
            password=self.content,
            metadata=metadata,
        )
