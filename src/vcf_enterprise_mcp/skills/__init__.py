# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Single-Responsibility Role-Based Skills Package for VCF Enterprise MCP Control Plane.
Provides atomic, role-scoped operational runbooks exposed via MCP Prompts, MCP Resources,
and standard SKILL.md agent definitions.
"""

from vcf_enterprise_mcp.skills.registry import (
    RoleSkillCard,
    ALL_ROLE_SKILLS,
    SkillCatalogRegistry,
    get_skill_registry,
)

__all__ = [
    "RoleSkillCard",
    "ALL_ROLE_SKILLS",
    "SkillCatalogRegistry",
    "get_skill_registry",
]
