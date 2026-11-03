# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Untrusted Input Sanitizer & Multi-Level Data Classification Engine.
Prevents prompt injection from untrusted infrastructure strings (VM names, tags, log lines)
and enforces schema-aware field redaction and freeform credential scrubbing (P1-2).
"""

from __future__ import annotations
import re
from enum import Enum
from typing import Dict, Any, List, Union, Optional


class DataClassification(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    SECRET = "SECRET"
    CREDENTIAL = "CREDENTIAL"


# Suspicious injection patterns found in malicious VM names, annotations, or log messages
PROMPT_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?(previous\s+)?(instructions|rules|directives|constraints)", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(an?\s+)?admin", re.IGNORECASE),
    re.compile(r"system\s*(prompt|instruction)s?\s*:", re.IGNORECASE),
    re.compile(r"<\s*system\s*>", re.IGNORECASE),
    re.compile(r"<\s*instructions\s*>", re.IGNORECASE),
    re.compile(r"bypass\s+all\s+(security|auth|checks)", re.IGNORECASE),
]

# Freeform credential & secret patterns for deep string scanning (P1-2)
PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN\s+([A-Z0-9_-]+\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+([A-Z0-9_-]+\s+)?PRIVATE\s+KEY-----"
)
CERTIFICATE_PATTERN = re.compile(
    r"-----BEGIN\s+CERTIFICATE-----[\s\S]*?-----END\s+CERTIFICATE-----"
)
# Match RFC 7519 JSON Web Tokens (3 base64url segments separated by dots, starting with eyJ)
JWT_PATTERN = re.compile(
    r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b"
)
# Bearer token header or query param
BEARER_PATTERN = re.compile(
    r"(?i)\bBearer\s+[a-zA-Z0-9_\-\.~+/]+=*"
)
# HTTP Basic / Digest authorization credentials
AUTH_HEADER_PATTERN = re.compile(
    r"(?i)\b(Basic|Digest)\s+[a-zA-Z0-9+/=]{16,}"
)
# Passwords and secrets embedded in freeform logs or connection strings (e.g. password=..., secret: ...)
KV_SECRET_PATTERN = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token)\s*([:=])\s*['\"]?([^\s'\",;&]+)['\"]?"
)
# Session cookies (e.g. JSESSIONID=..., vmware-api-session-id=...)
COOKIE_PATTERN = re.compile(
    r"(?i)\b(JSESSIONID|sessionid|vmware-api-session-id|connect\.sid|PHPSESSID)\s*([:=])\s*['\"]?([^\s'\",;&]+)['\"]?"
)
SET_COOKIE_PATTERN = re.compile(
    r"(?i)\bSet-Cookie\s*:\s*([^;\r\n]+)"
)
# Credentials embedded in URLs: http://user:password@host
URL_CREDENTIAL_PATTERN = re.compile(
    r"://([^:\s/@]+):([^@\s/]+)@"
)
# AWS Access Keys
AWS_KEY_PATTERN = re.compile(
    r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b"
)


# Default field classification registry
FIELD_CLASSIFICATIONS: Dict[str, DataClassification] = {
    "password": DataClassification.CREDENTIAL,
    "secret": DataClassification.CREDENTIAL,
    "private_key": DataClassification.CREDENTIAL,
    "token": DataClassification.SECRET,
    "session_id": DataClassification.SECRET,
    "bearer": DataClassification.SECRET,
    "ip_address": DataClassification.INTERNAL,
    "fqdn": DataClassification.INTERNAL,
    "hostname": DataClassification.INTERNAL,
    "vm_name": DataClassification.INTERNAL,
    "cluster_name": DataClassification.INTERNAL,
    "version": DataClassification.PUBLIC,
    "status": DataClassification.PUBLIC,
    "count": DataClassification.PUBLIC,
}


def sanitize_untrusted_string(text: str) -> str:
    """Neutralizes potential prompt injection markers and null bytes inside untrusted VCF data strings."""
    if not isinstance(text, str):
        return text
    sanitized = text.replace("\x00", "")
    for pattern in PROMPT_INJECTION_PATTERNS:
        if pattern.search(sanitized):
            sanitized = pattern.sub("[UNTRUSTED_CONTENT_FILTERED]", sanitized)
    return sanitized


def sanitize_freeform_string(text: str) -> str:
    """
    Scans and redacts freeform strings for prompt injection AND embedded secrets/credentials
    (Bearer tokens, JWTs, passwords, private keys, session cookies, API keys) per Finding P1-2.
    """
    if not isinstance(text, str):
        return text

    # 1. Neutralize prompt injections
    sanitized = sanitize_untrusted_string(text)

    # 2. Redact cryptographic PEM blocks
    sanitized = PRIVATE_KEY_PATTERN.sub("[REDACTED_PRIVATE_KEY]", sanitized)
    sanitized = CERTIFICATE_PATTERN.sub("[REDACTED_CERTIFICATE]", sanitized)

    # 3. Redact Bearer tokens first
    sanitized = BEARER_PATTERN.sub("Bearer [REDACTED_BEARER_TOKEN]", sanitized)

    # 4. Redact standalone JWTs
    sanitized = JWT_PATTERN.sub("[REDACTED_JWT]", sanitized)

    # 5. Redact Basic/Digest auth
    sanitized = AUTH_HEADER_PATTERN.sub(r"\1 [REDACTED_AUTH_CREDENTIAL]", sanitized)

    # 6. Redact URL credentials
    sanitized = URL_CREDENTIAL_PATTERN.sub(r"://\1:[REDACTED_PASSWORD]@", sanitized)

    # 7. Redact key-value password/secret assignments
    sanitized = KV_SECRET_PATTERN.sub(r"\1\2[REDACTED_SECRET]", sanitized)

    # 8. Redact session cookies
    sanitized = COOKIE_PATTERN.sub(r"\1\2[REDACTED_SESSION_COOKIE]", sanitized)
    sanitized = SET_COOKIE_PATTERN.sub("Set-Cookie: [REDACTED_COOKIE]", sanitized)

    # 9. Redact AWS keys
    sanitized = AWS_KEY_PATTERN.sub("[REDACTED_AWS_KEY]", sanitized)

    return sanitized


def sanitize_for_external_output(
    obj: Any,
    field_name: str = "",
    allow_confidential: bool = True,
) -> Any:
    """
    Recursively scans and sanitizes any data structure destined for external / LLM output:
    1. Schema-aware field redaction for dictionary keys (passwords, secrets, tokens).
    2. Deep string inspection for freeform credential patterns (JWTs, Bearer, cookies, PEMs).
    3. Prompt injection filtering across all strings.
    """
    # 1. Check field-level classification if field_name is provided
    if field_name:
        lower_field = field_name.lower()
        classification = FIELD_CLASSIFICATIONS.get(lower_field)
        if not classification:
            if any(k in lower_field for k in ["pass", "secret", "private_key", "pem"]):
                classification = DataClassification.CREDENTIAL
            elif any(k in lower_field for k in ["token", "session", "auth"]):
                classification = DataClassification.SECRET
            else:
                classification = DataClassification.INTERNAL

        if classification == DataClassification.CREDENTIAL:
            return "[REDACTED_CREDENTIAL]"
        if classification == DataClassification.SECRET:
            return "[REDACTED_SECRET]"
        if classification == DataClassification.CONFIDENTIAL and not allow_confidential:
            return "[CONFIDENTIAL_DATA_MASKED]"

    # 2. Recurse into structures
    if isinstance(obj, dict):
        return {
            k: sanitize_for_external_output(v, field_name=k, allow_confidential=allow_confidential)
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [
            sanitize_for_external_output(item, field_name=field_name, allow_confidential=allow_confidential)
            for item in obj
        ]
    if isinstance(obj, tuple):
        return tuple(
            sanitize_for_external_output(item, field_name=field_name, allow_confidential=allow_confidential)
            for item in obj
        )
    if isinstance(obj, str):
        return sanitize_freeform_string(obj)

    return obj


def sanitize_and_classify_payload(
    obj: Any,
    field_name: str = "",
    allow_confidential: bool = True,
) -> Any:
    """
    Recursively classifies and sanitizes data payloads.
    Provides backward compatibility while enforcing freeform secret scrubbing (P1-2).
    """
    return sanitize_for_external_output(
        obj,
        field_name=field_name,
        allow_confidential=allow_confidential,
    )
