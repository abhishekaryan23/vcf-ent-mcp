# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Orchestrator REST "typed value" wire format <-> plain Python values.

Ported from values.ts in vcf-orchestrator-mcp by imtrinity94 (MIT), proven on a real VCF Automation
9.1.1 server; see THIRD_PARTY_NOTICES.md. Examples:

    "hello"                 <-> {"string": {"value": "hello"}}
    {"a": 1}  (Properties)  <-> {"properties": {"property": [{"key": "a", "value": {"number": {"value": 1}}}]}}
    "vm-42"   (VC:VirtualMachine) -> {"sdk-object": {"type": "VC:VirtualMachine", "id": "vm-42"}}

Parameters on the wire are {name, type, scope: "local", value: <typed value>} (WsParameter).
SecureString values are built here from a secret already resolved by the caller; they are never
logged or returned by the tools.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

WIRE_KEYS = ("string", "secure-string", "encrypted-string", "number", "boolean", "date", "array", "properties", "sdk-object",
             "composite", "mime-attachment", "regex")

# Built-in inventory types have no "Plugin:" prefix, but on the wire they are sdk-objects like any plug-in type.
BUILTIN_SDK_TYPES = {t.lower() for t in (
    "ResourceElement", "ResourceElementCategory", "ConfigurationElement", "ConfigurationElementCategory", "Workflow",
    "WorkflowCategory", "WorkflowToken", "Action", "Module", "Package", "Task", "Policy", "PolicyTemplate",
    "PolicyTemplateCategory")}


class WireError(ValueError):
    pass


def is_wire_value(v: Any) -> bool:
    return isinstance(v, dict) and len(v) == 1 and next(iter(v)) in WIRE_KEYS


def _infer(v: Any) -> Dict[str, Any]:
    if is_wire_value(v):
        return v
    if v is None:
        return {"string": {"value": ""}}
    if isinstance(v, bool):
        return {"boolean": {"value": v}}
    if isinstance(v, (int, float)):
        return {"number": {"value": v}}
    if isinstance(v, str):
        return {"string": {"value": v}}
    if isinstance(v, (list, tuple)):
        return {"array": {"elements": [_infer(x) for x in v]}}
    if isinstance(v, dict):
        return {"properties": {"property": [{"key": str(k), "value": _infer(x)} for k, x in v.items()]}}
    return {"string": {"value": str(v)}}


def _sdk_object(type_: str, v: Any) -> Dict[str, Any]:
    oid = v.get("id") if isinstance(v, dict) else v
    sdk_type = (v.get("type") if isinstance(v, dict) and v.get("type") else type_)
    if oid in (None, ""):
        raise WireError(f"A {type_} input needs the object's id (a string, or {{id}}); got {v!r}")
    return {"sdk-object": {"type": sdk_type, "id": str(oid)}}


def _as_bool(v: Any) -> bool:
    return v is True or v == 1 or (isinstance(v, str) and v.strip().lower() == "true")


def to_wire(type_: Optional[str], v: Any) -> Dict[str, Any]:
    """Plain value -> typed wire value for a declared Orchestrator type."""
    if is_wire_value(v):
        return v
    t = (type_ or "Any").strip()
    lt = t.lower()
    if lt.startswith("array/"):
        inner = t[6:]
        seq = list(v) if isinstance(v, (list, tuple)) else [v]
        return {"array": {"elements": [to_wire(inner, e) for e in seq]}}
    if lt in ("string", "text"):
        return {"string": {"value": "" if v is None else v if isinstance(v, str) else json.dumps(v)}}
    if lt == "securestring":
        return {"secure-string": {"value": "" if v is None else str(v)}}
    if lt == "encryptedstring":
        return {"encrypted-string": {"value": "" if v is None else str(v)}}
    if lt == "number":
        try:
            n = float(v)
        except (TypeError, ValueError):
            raise WireError(f"A number input needs a number; got {v!r}")
        return {"number": {"value": int(n) if n.is_integer() else n}}
    if lt == "boolean":
        return {"boolean": {"value": _as_bool(v)}}
    if lt == "date":
        return {"date": {"value": _iso(v)}}
    if lt == "properties":
        if isinstance(v, dict):
            return _infer(v)
        if isinstance(v, str):
            try:
                return _infer(json.loads(v))
            except ValueError:
                raise WireError("A Properties input needs an object, e.g. {\"key\": \"value\"}.")
        return _infer({})
    if lt == "any":
        return _infer(v)
    if ":" in t or lt in BUILTIN_SDK_TYPES:
        return _sdk_object(t, v)
    return _infer(v)  # CompositeType(...) or anything else: best effort


def _iso(v: Any) -> str:
    if isinstance(v, datetime):
        d = v if v.tzinfo else v.replace(tzinfo=timezone.utc)
        return d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{d.microsecond // 1000:03d}Z"
    if isinstance(v, (int, float)):
        return _iso(datetime.fromtimestamp(v / 1000.0 if v > 1e11 else v, tz=timezone.utc))
    s = str(v)
    try:
        return _iso(datetime.fromisoformat(s.replace("Z", "+00:00")))
    except ValueError:
        return s  # let the server report what it dislikes


def from_wire(w: Any) -> Any:
    """Typed wire value -> plain value (tolerant of several shapes the API returns)."""
    if isinstance(w, list):
        return [from_wire(x) for x in w]
    if not isinstance(w, dict):
        return w
    keys = list(w.keys())
    if len(keys) != 1 and "objectType" not in keys:
        return w  # already plain, or a parameter wrapper
    k = next((x for x in keys if x != "objectType"), keys[0])
    inner = w[k]
    if k in ("string", "secure-string", "encrypted-string", "number", "boolean", "date", "regex"):
        return inner.get("value") if isinstance(inner, dict) else inner
    if k == "array":
        els = (inner or {}).get("elements") or (inner or {}).get("element") or []
        return [from_wire(x) for x in (els if isinstance(els, list) else [els])]
    if k == "properties":
        lst = (inner or {}).get("property") or (inner or {}).get("properties") or (inner if isinstance(inner, list) else [])
        out: Dict[str, Any] = {}
        for p in lst if isinstance(lst, list) else [lst]:
            if isinstance(p, dict) and "key" in p:
                out[p["key"]] = from_wire(p.get("value"))
        return out
    if k == "sdk-object":
        i = inner or {}
        return {"type": i.get("type"), "id": i.get("id"), "displayValue": i.get("displayValue") or i.get("display-value")}
    if k == "composite":
        out = {}
        for p in (inner or {}).get("property") or (inner or {}).get("CompositeObjectValue") or []:
            out[p.get("id") or p.get("key")] = from_wire(p.get("value"))
        return out
    if k == "mime-attachment":
        i = inner or {}
        return {"name": i.get("name"), "mimeType": i.get("mime-type"), "size": len(i.get("content") or "")}
    return w


def params_to_object(params: Optional[Iterable[Dict[str, Any]]]) -> Dict[str, Any]:
    """[{name, type, value}] -> {name: plain value}. SecureString values are never decoded into the result."""
    out: Dict[str, Any] = {}
    for p in params or []:
        if not isinstance(p, dict) or not p.get("name"):
            continue
        if str(p.get("type", "")).lower() == "securestring" or "secure-string" in (p.get("value") or {}):
            out[p["name"]] = "<hidden>"
            continue
        out[p["name"]] = None if p.get("value") is None else from_wire(p["value"])
    return out


def guess_type(v: Any) -> str:
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, (int, float)):
        return "number"
    if isinstance(v, str):
        return "string"
    if isinstance(v, (list, tuple)):
        return "Array/Any"
    if isinstance(v, dict):
        return "Any" if is_wire_value(v) else "Properties"
    return "string"


def build_parameters(defs: List[Dict[str, Any]], inputs: Dict[str, Any], strict: bool = True) -> List[Dict[str, Any]]:
    """Plain {name: value} + declared [{name, type}] -> REST "parameters" array (scope local)."""
    known = {d["name"]: d for d in defs if d.get("name")}
    out = []
    for name, value in (inputs or {}).items():
        d = known.get(name)
        if not d and strict:
            raise WireError(f"Unknown input '{name}'. Declared inputs: " + (", ".join(f"{k} ({v.get('type')})" for k, v in known.items()) or "none"))
        type_ = (d or {}).get("type") or "Any"
        out.append({"name": name, "type": guess_type(value) if (type_ == "Any" and not d) else type_, "scope": "local", "value": to_wire(type_, value)})
    return out


# ---- workflow XML attribute / default values (schema-workflow, ns2 typed elements) ----------------------------

def _x(s: Any) -> str:
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _xa(s: Any) -> str:
    return _x(s).replace('"', "&quot;")


def xml_value(type_: str, v: Any) -> str:
    """Attribute value in the VCFO 9.x schema XML (<ns2:string>, <ns2:sdk-object .../>, ...); '' when there is none."""
    if v is None:
        return ""
    t = (type_ or "").lower()
    if ":" in type_ and not t.startswith("array/"):
        oid = v.get("id") if isinstance(v, dict) else v
        return f'<ns2:sdk-object type="{_xa(type_)}" id="{_xa(oid)}"/>' if oid else ""
    if t in ("string", "securestring"):
        return f"<ns2:string>{_x(v)}</ns2:string>"
    if t == "number":
        n = float(v)
        return f"<ns2:number>{int(n) if n.is_integer() else n}</ns2:number>"
    if t == "boolean":
        return f"<ns2:boolean>{'true' if _as_bool(v) else 'false'}</ns2:boolean>"
    if t == "array/string" and isinstance(v, (list, tuple)):
        return "<ns2:array>" + "".join(f"<ns2:string>{_x(x)}</ns2:string>" for x in v) + "</ns2:array>"
    return ""


def cdata(s: Any) -> str:
    return "<![CDATA[" + ("" if s is None else str(s)).replace("]]>", "]]]]><![CDATA[>") + "]]>"


def presentation_default(type_: str, v: Any) -> Optional[str]:
    """Input default in the classic presentation encoding (honoured by the generated input form); None if unsupported."""
    if v is None:
        return None
    t = (type_ or "").lower()
    if ":" in type_ and not t.startswith("array/"):
        oid = v.get("id") if isinstance(v, dict) else v
        if oid in (None, ""):
            return None
        return cdata(f"dunes://service.dunes.ch/CustomSDKObject?id='{oid}'&dunesName='{type_}'")
    if t in ("string", "securestring"):
        return cdata(str(v))
    if t == "number":
        n = float(v)
        return cdata(str(int(n) if n.is_integer() else n))
    if t == "boolean":
        return cdata("true" if _as_bool(v) else "false")
    if t == "array/string" and isinstance(v, (list, tuple)):
        esc = lambda x: "".join("\\" + c if c in "#{}" else c for c in str(x))  # noqa: E731
        return cdata("#{" + ";".join("#string#" + esc(x) + "#" for x in v) + "}#")
    return None
