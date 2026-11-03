# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Strict Schema Validator for Enterprise VCF MCP Tools (Finding F10).
Enforces schema validation, required fields, type safety, bounds checking,
enum validation, and path traversal rejection before any tool dispatch or plan creation.
"""

from __future__ import annotations
import re
from typing import Dict, Any, List, Optional
from vcf_enterprise_mcp.core.errors import InvalidArgumentException

IDENTIFIER_PATTERN = re.compile(r"^[a-zA-Z0-9_\-\.]+$")
CIDR_PATTERN = re.compile(r"^[0-9\.\/]+$")
VERSION_PATTERN = re.compile(r"^[0-9\.]+$")

FRAMEWORK_KEYS = {
    "dry_run",
    "idempotency_key",
    "plan_id",
    "approval_id",
    "nonce",
    "signed_auth",
    "approval_token",
    "approved",
}


def validate_tool_arguments(tool_name: str, arguments: Dict[str, Any], schema: Optional[Dict[str, Any]]) -> None:
    """
    Validates tool input arguments against tool card schema.
    Raises InvalidArgumentException immediately on missing required fields,
    unknown fields, type mismatches, out-of-bounds values, or injection patterns.
    """
    if not isinstance(arguments, dict):
        raise InvalidArgumentException(
            f"Arguments for tool '{tool_name}' must be an object/dict, got {type(arguments).__name__}."
        )

    if not schema:
        return

    properties = schema.get("properties", {})
    required = schema.get("required", [])

    # 1. Check required fields
    for req_key in required:
        if req_key not in arguments or arguments[req_key] is None:
            raise InvalidArgumentException(
                f"Missing required argument '{req_key}' for tool '{tool_name}'."
            )

    # 2. Check for unknown fields (prohibit undeclared parameters)
    allowed_keys = set(properties.keys()) | FRAMEWORK_KEYS
    for k in arguments:
        if k not in allowed_keys:
            raise InvalidArgumentException(
                f"Unknown argument '{k}' is not permitted for tool '{tool_name}'."
            )

    # 2b. Check framework argument types (Finding F10 / R10)
    if "dry_run" in arguments and not isinstance(arguments["dry_run"], bool):
        raise InvalidArgumentException(
            f"Argument 'dry_run' must be a boolean, got {type(arguments['dry_run']).__name__}."
        )
    if "approved" in arguments and not isinstance(arguments["approved"], bool):
        raise InvalidArgumentException(
            f"Argument 'approved' must be a boolean, got {type(arguments['approved']).__name__}."
        )
    for str_key in ("idempotency_key", "plan_id", "approval_id", "nonce", "signed_auth", "approval_token"):
        if str_key in arguments and arguments[str_key] is not None:
            if not isinstance(arguments[str_key], str):
                raise InvalidArgumentException(
                    f"Argument '{str_key}' must be a string, got {type(arguments[str_key]).__name__}."
                )

    # 3. Check property types, bounds, enums, and identifier constraints
    for k, val in arguments.items():
        if k in FRAMEWORK_KEYS or k not in properties:
            continue

        prop_spec = properties[k]
        expected_type = prop_spec.get("type")

        if val is None:
            if k in required:
                raise InvalidArgumentException(f"Argument '{k}' for tool '{tool_name}' cannot be null.")
            continue

        if expected_type == "string":
            if not isinstance(val, str):
                raise InvalidArgumentException(
                    f"Argument '{k}' for tool '{tool_name}' must be a string, got {type(val).__name__}."
                )
            max_len = prop_spec.get("maxLength", 256)
            if len(val) > max_len or (len(val) == 0 and k in required):
                raise InvalidArgumentException(
                    f"Argument '{k}' length ({len(val)}) out of bounds (max {max_len})."
                )
            if "enum" in prop_spec and val not in prop_spec["enum"]:
                raise InvalidArgumentException(
                    f"Argument '{k}' value '{val}' not in permitted enum: {prop_spec['enum']}."
                )
            # Identifier safety constraints: block path traversal, backslashes, unapproved chars
            if k in ("vm_id", "cluster_id", "datacenter_id", "domain_id", "gateway_id", "snapshot_name", "target_site", "segment_name"):
                if not IDENTIFIER_PATTERN.match(val) or ".." in val or "/" in val or "\\" in val:
                    raise InvalidArgumentException(
                        f"Argument '{k}' contains invalid characters or path traversal: '{val}'."
                    )
            elif k == "cidr":
                if not CIDR_PATTERN.match(val) or "/" not in val:
                    raise InvalidArgumentException(f"Argument '{k}' is not a valid CIDR notation: '{val}'.")
            elif k == "target_version":
                if not VERSION_PATTERN.match(val):
                    raise InvalidArgumentException(f"Argument '{k}' is not a valid version string: '{val}'.")
            else:
                # Multi-line fields (e.g. cloud template YAML) may contain newlines and tabs; nothing else non-printable.
                extra = "\n\r\t" if prop_spec.get("x-multiline") else ""
                # Non-ASCII in multi-line code is reported by the script linter, which explains the Orchestrator 9.1 known issue.
                if not all(c.isprintable() or c in extra for c in val) or (not extra and any(ord(c) > 127 for c in val)):
                    raise InvalidArgumentException(f"Argument '{k}' contains invalid or non-printable unicode characters.")

        elif expected_type == "integer":
            if not isinstance(val, int) or isinstance(val, bool):
                raise InvalidArgumentException(
                    f"Argument '{k}' for tool '{tool_name}' must be an integer, got {type(val).__name__}."
                )
            min_val = prop_spec.get("minimum", 1)
            max_val = prop_spec.get("maximum", 1048576)
            if val < min_val or val > max_val:
                raise InvalidArgumentException(
                    f"Argument '{k}' value {val} out of bounds [{min_val}, {max_val}]."
                )

        elif expected_type == "number":
            if not isinstance(val, (int, float)) or isinstance(val, bool):
                raise InvalidArgumentException(
                    f"Argument '{k}' for tool '{tool_name}' must be a number, got {type(val).__name__}."
                )
            min_val = prop_spec.get("minimum", 0)
            max_val = prop_spec.get("maximum", 1048576)
            if val < min_val or val > max_val:
                raise InvalidArgumentException(
                    f"Argument '{k}' value {val} out of bounds [{min_val}, {max_val}]."
                )

        elif expected_type == "boolean":
            if not isinstance(val, bool):
                raise InvalidArgumentException(
                    f"Argument '{k}' for tool '{tool_name}' must be a boolean, got {type(val).__name__}."
                )

        elif expected_type == "object":
            if not isinstance(val, dict):
                raise InvalidArgumentException(
                    f"Argument '{k}' for tool '{tool_name}' must be an object/dict, got {type(val).__name__}."
                )

        elif expected_type == "array":
            if not isinstance(val, list):
                raise InvalidArgumentException(
                    f"Argument '{k}' for tool '{tool_name}' must be an array/list, got {type(val).__name__}."
                )
