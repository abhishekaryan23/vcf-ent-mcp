# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Static checks for Orchestrator scripts before they are saved.

Script level (setting vcf.orchestrator_script_level):

- "es5" (default): plain ES5 only. let/const, arrow functions, template literals, for...of and
  generators are ERRORS, each with the ES5 replacement. The default is the conservative one
  because it is what a real VCF Automation 9.1.1 server was proven to accept: the community
  project vcf-orchestrator-mcp (same author as the blog below, verified on 9.1.1) requires plain
  ES5 and documents "A script fails with a syntax error on valid-looking JavaScript ...
  Orchestrator runs Rhino (ES5)". A saved action that fails at run time on valid-looking
  modern syntax costs more than a lint error that names the fix.
- "rhino_1_7_15": the Orchestrator 9.x feature results published at cloudblogger.co.in
  ("Orchestrator Rhino engine 8.x vs 9.x", Rhino 1.7.15) are used, so let/const, arrows, template
  literals, for...of and generators pass. Where that article contradicts itself, the per-feature
  test section wins over the summary table, and an unclear feature counts as unsupported.
  Choose it only for a server where those features were tested.

Orchestrator 8.x (Rhino 1.7R4) is ES5 only at every level.

Other rules come from Broadcom documentation:
- 9.1 known issue: scripts with Unicode characters such as emoji show hex-encoded after package
  import and can't be edited -> non-ASCII is rejected.
- Orchestrator restricts JavaScript access to Java classes; widening it "presents potential
  security issues" -> java.*, Packages.* and JavaImporter are rejected.
- 9.1.0 known issue: context.getToken() breaks after token refresh in Python runtimes (fixed 9.1.1).
- KB 447131: the Mail plug-in cannot send attachments before 9.1.0.0401.

The checker tokenizes the script (strings, template literals, comments and regex literals are
recognised), so keywords inside strings or comments are not flagged.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# feature -> (description, supported on 9.x, replacement hint)
FEATURES_9X: Dict[str, Tuple[str, bool, str]] = {
    "class": ("class declarations", False, "use a constructor function and prototype methods"),
    "super": ("super", False, "call the parent constructor function directly"),
    "async_await": ("async / await", False, "write synchronous code; plug-in calls are blocking"),
    "optional_chaining": ("optional chaining ?.", False, "use (a && a.b)"),
    "nullish": ("nullish coalescing ??", False, "use (a !== null && a !== undefined) ? a : b"),
    "logical_assignment": ("logical assignment ||= &&= ??=", False, "write a = a || b"),
    "spread": ("spread / rest ... in arrays, objects or calls", False, "use concat(), Object.assign() or fn.apply()"),
    "destructuring": ("destructuring assignment", False, "assign each property: var a = obj.a"),
    "default_params": ("default parameter values", False, "set defaults in the body: if (x === undefined) x = 1"),
    "regex_u_flag": ("regex u flag", False, "drop the u flag"),
    "intl": ("Intl API", False, "format dates and numbers manually"),
    "modules": ("import / export", False, "use System.getModule('module').action() to call actions"),
    "let_const": ("let / const", True, "declare with var"),
    "arrow": ("arrow functions", True, "use function (x) { return ...; }"),
    "template": ("template literals", True, "build strings with + (e.g. 'a ' + b)"),
    "for_of": ("for...of", True, "use a for (var i = 0; i < arr.length; i++) loop or arr.forEach(function (x) {...})"),
    "generator": ("generators", True, "build the array in a loop and return it"),
}
ES5_ONLY = {"let_const", "arrow", "template", "for_of", "generator"}  # also unsupported on 8.x

SECRET_PATTERNS = [
    (re.compile(r"(?i)(password|passwd|pwd|secret|api[_-]?key|token)\s*[:=]\s*[\"'][^\"']{4,}[\"']"), "a hard-coded credential"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "a private key"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\."), "a JWT"),
]


@dataclass
class LintResult:
    errors: List[Dict[str, str]] = field(default_factory=list)
    warnings: List[Dict[str, str]] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors

    def to_dict(self) -> Dict[str, object]:
        return {"ok": self.ok, "errors": self.errors, "warnings": self.warnings}


def _tokens(src: str) -> List[Tuple[str, str, int]]:
    """Very small JS tokenizer: returns (kind, text, line). kinds: str, tmpl, regex, comment, word, num, punct."""
    out: List[Tuple[str, str, int]] = []
    i, n, line = 0, len(src), 1
    prev_sig = None
    while i < n:
        c = src[i]
        if c == "\n":
            line += 1
            i += 1
            continue
        if c.isspace():
            i += 1
            continue
        if src.startswith("//", i):
            j = src.find("\n", i)
            j = n if j < 0 else j
            out.append(("comment", src[i:j], line))
            i = j
            continue
        if src.startswith("/*", i):
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append(("comment", src[i:j], line))
            line += src.count("\n", i, j)
            i = j
            continue
        if c in "\"'":
            j = i + 1
            while j < n and src[j] != c and src[j] != "\n":
                j += 2 if src[j] == "\\" else 1
            out.append(("str", src[i:j + 1], line))
            i = j + 1
            prev_sig = ("str", "")
            continue
        if c == "`":
            j = i + 1
            while j < n and src[j] != "`":
                j += 2 if src[j] == "\\" else 1
            out.append(("tmpl", src[i:j + 1], line))
            line += src.count("\n", i, j)
            i = j + 1
            prev_sig = ("tmpl", "")
            continue
        if c == "/":
            # Regex literal if the previous significant token cannot end an expression.
            regex_ok = prev_sig is None or (prev_sig[0] == "punct" and prev_sig[1] not in (")", "]", "}")) or \
                (prev_sig[0] == "word" and prev_sig[1] in ("return", "typeof", "case", "in", "of", "new", "delete", "void", "throw"))
            if regex_ok:
                j, in_class = i + 1, False
                while j < n and src[j] != "\n":
                    if src[j] == "\\":
                        j += 2
                        continue
                    if src[j] == "[":
                        in_class = True
                    elif src[j] == "]":
                        in_class = False
                    elif src[j] == "/" and not in_class:
                        break
                    j += 1
                k = j + 1
                while k < n and src[k].isalpha():
                    k += 1
                out.append(("regex", src[i:k], line))
                i = k
                prev_sig = ("regex", "")
                continue
        if c.isalpha() or c in "_$":
            j = i
            while j < n and (src[j].isalnum() or src[j] in "_$"):
                j += 1
            out.append(("word", src[i:j], line))
            prev_sig = ("word", src[i:j])
            i = j
            continue
        if c.isdigit():
            j = i
            while j < n and (src[j].isalnum() or src[j] in "._"):
                j += 1
            out.append(("num", src[i:j], line))
            prev_sig = ("num", "")
            i = j
            continue
        for p in ("...", "??=", "||=", "&&=", "?.", "??", "=>", "===", "!==", "==", "!=", "<=", ">=", "&&", "||", "**"):
            if src.startswith(p, i):
                break
        else:
            p = c
        out.append(("punct", p, line))
        prev_sig = ("punct", p)
        i += len(p)
    return out


def _uses(tokens) -> Dict[str, int]:
    """feature -> first line where it is used."""
    found: Dict[str, int] = {}

    def mark(f, ln):
        found.setdefault(f, ln)

    sig = [t for t in tokens if t[0] != "comment"]
    for idx, (kind, text, ln) in enumerate(sig):
        nxt = sig[idx + 1] if idx + 1 < len(sig) else ("", "", ln)
        prv = sig[idx - 1] if idx > 0 else ("", "", ln)
        if kind == "word":
            if text == "class" and nxt[0] == "word" and prv[1] != ".":
                mark("class", ln)
            elif text == "super" and prv[1] != ".":
                mark("super", ln)
            elif text in ("async", "await") and prv[1] != "." and nxt[0] in ("word", "punct") and nxt[1] not in (".", ":", ",", ")", "="):
                mark("async_await", ln)
            elif text in ("import", "export") and prv[1] != "." and nxt[1] not in ("(", ".", ":"):
                mark("modules", ln)
            elif text in ("let", "const"):
                mark("let_const", ln)
                if nxt[1] in ("{", "["):
                    mark("destructuring", ln)
            elif text == "var" and nxt[1] in ("{", "["):
                mark("destructuring", ln)
            elif text == "of" and prv[0] in ("word",) and any(t[1] == "for" for t in sig[max(0, idx - 4):idx]):
                mark("for_of", ln)
            elif text == "Intl" and nxt[1] == ".":
                mark("intl", ln)
            elif text == "function" and nxt[1] == "*" or (text == "function" and nxt[0] == "word" and idx + 2 < len(sig) and sig[idx + 2][1] == "*"):
                mark("generator", ln)
            if text == "function":
                # default params: '=' at depth 1 inside the parameter list
                j = idx + 1
                while j < len(sig) and sig[j][1] != "(":
                    j += 1
                depth = 0
                while j < len(sig):
                    t = sig[j][1]
                    if t == "(":
                        depth += 1
                    elif t == ")":
                        depth -= 1
                        if depth == 0:
                            break
                    elif t == "=" and depth == 1:
                        mark("default_params", sig[j][2])
                    j += 1
        elif kind == "punct":
            if text == "?.":
                mark("optional_chaining", ln)
            elif text == "??":
                mark("nullish", ln)
            elif text in ("||=", "&&=", "??="):
                mark("logical_assignment", ln)
            elif text == "...":
                mark("spread", ln)
            elif text == "=>":
                mark("arrow", ln)
                # (a = 1) => default param in arrow
                j, depth = idx - 1, 0
                while j >= 0:
                    t = sig[j][1]
                    if t == ")":
                        depth += 1
                    elif t == "(":
                        depth -= 1
                        if depth == 0:
                            break
                    elif t == "=" and depth == 1:
                        mark("default_params", ln)
                    j -= 1
            elif text in ("{", "[") and prv[1] in ("(", ",") and False:
                pass
        elif kind == "tmpl":
            mark("template", ln)
        elif kind == "regex":
            flags = text.rsplit("/", 1)[-1]
            if "u" in flags:
                mark("regex_u_flag", ln)
    # Destructuring assignment / parameters: ({a, b}) => or function ({a}) handled roughly via "({"/"[" after '(' and before '=>'
    return found


SCRIPT_LEVELS = ("es5", "rhino_1_7_15")


def lint_javascript(script: str, version: str = "9.1.1", installed_plugins: Optional[Dict[str, str]] = None,
                    level: str = "es5") -> LintResult:
    if level not in SCRIPT_LEVELS:
        raise ValueError(f"script level must be one of: {', '.join(SCRIPT_LEVELS)}")
    r = LintResult()
    if not isinstance(script, str):
        r.errors.append({"rule": "not_text", "message": "The script must be a string of JavaScript code.",
                         "fix": 'Put the code in "script" as text, e.g. "script": "var x = 1;"'})
        return r
    major = version.split(".")[0] if version else "9"
    try:
        tokens = _tokens(script)
    except Exception as exc:  # pragma: no cover - tokenizer is total, but never crash a save
        r.errors.append({"rule": "parse", "message": f"Could not read the script: {exc}", "fix": "Check quotes and brackets."})
        return r
    for i, ch in enumerate(script):
        if ord(ch) > 127:
            ln = script.count("\n", 0, i) + 1
            r.errors.append({"rule": "non_ascii", "line": str(ln),
                             "message": f"Non-ASCII character {ch!r} (U+{ord(ch):04X}). Orchestrator 9.1 shows such scripts hex-encoded "
                                        "after package import and they can no longer be edited (Broadcom 9.1.1 known issue).",
                             "fix": f"Remove it, or write it as the escape \\u{ord(ch):04X} inside a string."})
            break
    for feat, ln in sorted(_uses(tokens).items(), key=lambda x: x[1]):
        desc, ok9, hint = FEATURES_9X[feat]
        es5_only = major == "8" or level == "es5"
        supported = ok9 and not (es5_only and feat in ES5_ONLY)
        if not supported:
            where = (f"the Orchestrator {major}.x Rhino engine" if feat not in ES5_ONLY or major == "8" else
                     "plain ES5, which is what Orchestrator's Rhino engine is proven to run (script level 'es5')")
            r.errors.append({"rule": f"unsupported_{feat}", "line": str(ln),
                             "message": f"{desc} is not supported by {where}." if feat not in ES5_ONLY or major == "8" else
                                        f"{desc} is not allowed: scripts must be {where}.", "fix": hint})
    if re.search(r"[\"'`](local|vault|cyberark)://", script):
        r.errors.append({"rule": "mcp_reference_in_script", "message": "The script contains an MCP credential reference; Orchestrator scripts "
                         "cannot resolve it.", "fix": "Create a configuration element with vcf_orch_set_configuration (credential_ref) and read "
                         "the SecureString attribute from it in the script."})
    code = " ".join(t[1] for t in tokens if t[0] in ("word", "punct"))
    for pat, what in (("java .", "java.* class access"), ("Packages .", "Packages.* class access"), ("JavaImporter", "JavaImporter")):
        if pat in code:
            r.errors.append({"rule": "java_access", "message": f"{what}: Orchestrator restricts JavaScript access to Java classes and "
                             "Broadcom warns that widening it is a security risk.", "fix": "Use the plug-in scripting API instead (vcf_orch_get kind=scripting_api)."})
    if re.search(r"\beval\s*\(", code) or "new Function (" in code or re.search(r"\bnew Function\b", code):
        r.errors.append({"rule": "dynamic_code", "message": "eval() / new Function() run arbitrary code.", "fix": "Call the logic directly."})
    for t in tokens:
        if t[0] in ("str", "tmpl"):
            for pat, what in SECRET_PATTERNS:
                if pat.search(t[1]) or pat.search(script[max(0, script.find(t[1]) - 40):script.find(t[1]) + len(t[1])]):
                    r.errors.append({"rule": "hardcoded_secret", "line": str(t[2]), "message": f"The script contains {what}.",
                                     "fix": "Store it with vcf_orch_set_configuration (attribute with credential_ref), then read it in the script from that "
                                            "configuration element, or make it a SecureString workflow input. Never put the value or an MCP "
                                            "reference (local://...) in code: scripts cannot resolve MCP references."})
                    break
    if any(r_["rule"] == "hardcoded_secret" for r_ in r.errors):
        # keep one message per line
        seen, uniq = set(), []
        for e in r.errors:
            key = (e["rule"], e.get("line"))
            if key not in seen:
                seen.add(key)
                uniq.append(e)
        r.errors = uniq
    if re.search(r"\bwhile\s*\(\s*true\s*\)", script) and "System.sleep" in script and "break" not in script:
        r.warnings.append({"rule": "unbounded_loop", "message": "while(true) with System.sleep and no break can run forever.",
                           "fix": "Add a maximum number of attempts."})
    if "addAttachment" in script or "MimeAttachment" in script:
        mail = (installed_plugins or {}).get("mail") or (installed_plugins or {}).get("Mail")
        if not mail or _older(mail, "9.1.0.0401"):
            r.warnings.append({"rule": "mail_attachments", "message": "Mail attachments fail on Orchestrator 9.1 with Mail plug-in older than "
                               "9.1.0.0401 (Broadcom KB 447131).", "fix": "Upgrade the Mail plug-in to 9.1.0.0401 or later."})
    return r


def lint_python(script: str, version: str = "9.1.1") -> LintResult:
    r = LintResult()
    for i, ch in enumerate(script):
        if ord(ch) > 127:
            r.errors.append({"rule": "non_ascii", "line": str(script.count("\n", 0, i) + 1),
                             "message": "Non-ASCII character: scripts with Unicode show hex-encoded after package import (9.1 known issue).",
                             "fix": "Remove it or use an escape sequence."})
            break
    if "context.getToken()" in script and version.startswith("9.1.0"):
        r.warnings.append({"rule": "python_get_token", "message": "context.getToken() breaks after token refresh in Python runtimes on 9.1.0 "
                           "(Broadcom known issue, fixed in 9.1.1).", "fix": "Upgrade to 9.1.1, or pass a token as an input."})
    for pat, what in SECRET_PATTERNS:
        if pat.search(script):
            r.errors.append({"rule": "hardcoded_secret", "message": f"The script contains {what}.",
                             "fix": "Use a SecureString input or a configuration element filled with vcf_orch_set_configuration."})
            break
    if re.search(r"\b(eval|exec)\s*\(", script):
        r.errors.append({"rule": "dynamic_code", "message": "eval()/exec() run arbitrary code.", "fix": "Call the logic directly."})
    return r


def _older(v: str, ref: str) -> bool:
    def parts(x):
        return [int(p) for p in re.findall(r"\d+", x)]
    return parts(v) < parts(ref)


def lint_script(script: str, runtime: str = "javascript", version: str = "9.1.1", installed_plugins=None,
                level: str = "es5") -> LintResult:
    rt = (runtime or "javascript").lower()
    if rt.startswith("python"):
        return lint_python(script, version)
    if rt.startswith("node") or rt.startswith("powershell"):
        r = LintResult()
        r.errors += [e for e in lint_python(script, version).errors if e["rule"] in ("non_ascii", "hardcoded_secret")]
        return r
    return lint_javascript(script, version, installed_plugins, level)
