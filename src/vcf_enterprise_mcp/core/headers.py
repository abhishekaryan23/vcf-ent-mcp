# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
HTTP Transport Header Agreement & W3C Trace Context Validator.
Enforces agreement between MCP HTTP transport headers (Mcp-Method, Mcp-Name, Mcp-Param-*)
and the JSON-RPC request body, preventing HTTP request smuggling and parameter divergence.
Parses and propagates W3C Trace Context (traceparent, tracestate).
"""

from __future__ import annotations
import re
import base64
import secrets
from contextvars import ContextVar
from typing import Dict, Any, Optional, Tuple
from vcf_enterprise_mcp.core.errors import HeaderMismatchException, UnsupportedProtocolVersionException


TRACEPARENT_REGEX = re.compile(r"^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$")

current_trace_context: ContextVar[Optional[TraceContext]] = ContextVar("current_trace_context", default=None)


def get_current_trace_context() -> Optional[TraceContext]:
    """Retrieves the active W3C TraceContext for the current execution thread/task."""
    return current_trace_context.get()


def set_current_trace_context(ctx: Optional[TraceContext]) -> None:
    """Sets the active W3C TraceContext for the current execution thread/task."""
    current_trace_context.set(ctx)


class TraceContext:
    def __init__(self, trace_id: str, span_id: str, trace_flags: str = "01"):
        self.trace_id = trace_id
        self.span_id = span_id
        self.trace_flags = trace_flags

    @classmethod
    def from_headers(cls, headers: Optional[Dict[str, str]]) -> "TraceContext":
        if headers:
            # Case-insensitive header lookup
            tp = next((v for k, v in headers.items() if k.lower() == "traceparent"), None)
            if tp:
                m = TRACEPARENT_REGEX.match(tp.strip())
                if m:
                    return cls(trace_id=m.group(1), span_id=m.group(2), trace_flags=m.group(3))

        # Generate new trace context
        return cls(
            trace_id=secrets.token_hex(16),
            span_id=secrets.token_hex(8),
            trace_flags="01",
        )

    def to_header(self) -> str:
        return f"00-{self.trace_id}-{self.span_id}-{self.trace_flags}"


def validate_mcp_headers(
    headers: Optional[Dict[str, str]],
    body: Dict[str, Any],
) -> TraceContext:
    """
    Validates that any Mcp-* transport headers strictly agree with the JSON-RPC body.
    Raises HeaderMismatchException on discrepancy. Returns TraceContext.
    """
    trace_ctx = TraceContext.from_headers(headers)
    set_current_trace_context(trace_ctx)
    # None denotes a non-HTTP caller (stdio / internal protocol tests).
    if headers is None:
        return trace_ctx
    if not isinstance(body, dict) or not isinstance(body.get("params", {}), dict):
        raise HeaderMismatchException("Request and params must be objects.")
    lower_headers = {k.lower(): v for k, v in headers.items()}
    params = body.get("params", {})
    meta = params.get("_meta", {})
    if not isinstance(meta, dict):
        raise HeaderMismatchException("Request _meta must be an object.")
    version = lower_headers.get("mcp-protocol-version")
    if not version:
        raise HeaderMismatchException("Missing MCP-Protocol-Version header.")
    if version != "2026-07-28":
        raise UnsupportedProtocolVersionException(version)
    if meta.get("io.modelcontextprotocol/protocolVersion") != version:
        raise HeaderMismatchException("Protocol version header must match params._meta protocol version.")
    if not lower_headers.get("mcp-method") or lower_headers["mcp-method"] != body.get("method"):
        raise HeaderMismatchException("Missing or mismatched Mcp-Method header.")

    def decode(value):
        if value.startswith("=?base64?") and value.endswith("?="):
            try:
                return base64.b64decode(value[9:-2], validate=True).decode("utf-8")
            except (ValueError, UnicodeError):
                raise HeaderMismatchException("Invalid Base64 header value.")
        if value != value.strip() or any(not (32 <= ord(c) <= 126 or c == "\t") for c in value):
            raise HeaderMismatchException("Invalid header characters.")
        return value

    if body.get("method") in ("tools/call", "prompts/get", "resources/read"):
        expected = params.get("uri") if body["method"] == "resources/read" else params.get("name")
        name = lower_headers.get("mcp-name")
        if name is None or decode(name) != expected:
            raise HeaderMismatchException("Missing or mismatched Mcp-Name header.")
    args = params.get("arguments", {})
    if not isinstance(args, dict):
        raise HeaderMismatchException("Tool arguments must be an object.")
    param_source = args if (args or body.get("method") == "tools/call") else params
    for key, value in lower_headers.items():
        if key.startswith("mcp-param-"):
            param = key[len("mcp-param-"):]
            if param not in param_source:
                raise HeaderMismatchException("Header parameter is absent in arguments.")
            arg = param_source[param]
            expected = str(arg).lower() if isinstance(arg, bool) else str(arg)
            if decode(value) != expected:
                raise HeaderMismatchException("Header parameter disagrees with arguments.")
    return trace_ctx
