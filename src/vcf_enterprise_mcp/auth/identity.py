# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Corporate Identity & Principal Representation.
Captures verified caller identity from enterprise IdP tokens and mapped VCF entitlements.
Enforces strict multi-tenant context (tenant_id, environment_ids) and cryptographic lineage.
"""

from __future__ import annotations
import time
from typing import List, Dict, Set, Optional, Any, Tuple
from dataclasses import dataclass, field


@dataclass
class Principal:
    """Authenticated enterprise user identity and native entitlement context."""
    principal_id: str = ""
    tenant_id: str = "tenant-default"
    environment_ids: tuple[str, ...] = ("env-prod",)
    groups: tuple[str, ...] = ()
    roles: tuple[str, ...] = ()
    user_id: str = ""
    display_name: str = ""
    corporate_groups: List[str] = field(default_factory=list)
    corporate_roles: List[str] = field(default_factory=list)
    native_vcf_entitlements: Dict[str, List[str]] = field(default_factory=dict)
    allowed_domains: List[str] = field(default_factory=list)
    allowed_clusters: List[str] = field(default_factory=list)
    allowed_tags: List[str] = field(default_factory=list)
    client_ip: str = "127.0.0.1"
    token_id: str = "tok-anonymous"
    authenticated_at: float = field(default_factory=time.time)
    is_system_operator: bool = False

    def __post_init__(self):
        # Synchronize principal_id and user_id for backward compatibility
        if not self.principal_id and self.user_id:
            self.principal_id = self.user_id
        elif not self.user_id and self.principal_id:
            self.user_id = self.principal_id
        elif not self.principal_id and not self.user_id:
            self.principal_id = "anonymous@corp.local"
            self.user_id = "anonymous@corp.local"

        # Synchronize corporate_groups and groups
        if self.corporate_groups and not self.groups:
            self.groups = tuple(self.corporate_groups)
        elif self.groups and not self.corporate_groups:
            self.corporate_groups = list(self.groups)

        # Synchronize corporate_roles and roles
        if self.corporate_roles and not self.roles:
            self.roles = tuple(self.corporate_roles)
        elif self.roles and not self.corporate_roles:
            self.corporate_roles = list(self.roles)

    def has_group(self, group_name: str) -> bool:
        return group_name in self.corporate_groups or group_name in self.groups

    def has_role(self, role_name: str) -> bool:
        return role_name in self.corporate_roles or role_name in self.roles

    def has_vcf_privilege(self, resource_path: str, privilege: str) -> bool:
        """Checks if principal has a specific native privilege on the given resource path."""
        for res_key, privs in self.native_vcf_entitlements.items():
            if res_key == "*" or res_key == resource_path or resource_path.startswith(res_key):
                if "*" in privs or privilege in privs:
                    return True
        return False

    def is_in_resource_scope(self, domain_id: Optional[str] = None, cluster_id: Optional[str] = None) -> bool:
        """Evaluates whether the given domain/cluster is within the principal's allowed scope."""
        if self.is_system_operator:
            return True

        # Deny empty scope by default
        if not self.allowed_domains and not self.allowed_clusters:
            return False

        # Wildcard scope allows all
        if "*" in self.allowed_domains or "*" in self.allowed_clusters:
            return True

        # If resource coordinates are missing on a scoped principal, fail closed
        if not domain_id and not cluster_id:
            return False

        if cluster_id:
            if self.allowed_clusters and cluster_id in self.allowed_clusters:
                return True
            if not self.allowed_clusters and domain_id and self.allowed_domains and domain_id in self.allowed_domains:
                return True
            return False

        if domain_id:
            return bool(self.allowed_domains and domain_id in self.allowed_domains)

        return False

    def can_access_tenant(self, target_tenant_id: str) -> bool:
        """Enforces tenant boundary: callers can only access their verified tenant unless SYSTEM_OPERATOR."""
        if self.is_system_operator:
            return True
        return self.tenant_id == target_tenant_id

    def to_audit_dict(self) -> Dict[str, Any]:
        return {
            "principal_id": self.principal_id,
            "user_id": self.user_id,
            "tenant_id": self.tenant_id,
            "environment_ids": list(self.environment_ids),
            "display_name": self.display_name,
            "corporate_groups": self.corporate_groups,
            "corporate_roles": self.corporate_roles,
            "allowed_domains": self.allowed_domains,
            "allowed_clusters": self.allowed_clusters,
            "client_ip": self.client_ip,
            "is_system_operator": self.is_system_operator,
        }
