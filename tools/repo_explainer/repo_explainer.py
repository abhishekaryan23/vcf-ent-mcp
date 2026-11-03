#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""Offline, read-only repository explainer. Python standard library only."""

from __future__ import annotations

import argparse
import html
import os
from pathlib import Path
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlsplit


SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "dist", "build", "coverage", "__pycache__", ".next", "target", ".idea"}
CODE_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rs", ".java", ".kt", ".cs", ".rb", ".php"}
MAX_FILES = 3000
MAX_SOURCE_BYTES = 512_000

STAGES = [
    ("Entry", "Where a request enters", ("server", "main", "app", "index", "cli", "handler", "api")),
    ("Identity", "Who is making the request", ("auth", "identity", "token", "session", "idp")),
    ("Decision", "What the caller may do", ("policy", "permission", "authorize", "router", "middleware")),
    ("Action", "What work is performed", ("tool", "workflow", "service", "controller", "usecase", "job")),
    ("Connection", "Which external system is called", ("adapter", "provider", "client", "transport", "integration", "gateway")),
    ("Record", "Where status and evidence live", ("state", "store", "database", "repository", "audit", "log")),
]

VCF_EVIDENCE = [
    ("Entry", "MCP request arrives over HTTP or stdio", "src/vcf_enterprise_mcp/core/server.py", "handle_jsonrpc_request"),
    ("Identity", "Validate the caller's bearer token", "src/vcf_enterprise_mcp/core/protocol.py", "validate_bearer_token"),
    ("Decision", "Filter visible tools and authorize calls", "src/vcf_enterprise_mcp/policy/enforcement.py", "authorize_execution"),
    ("Action", "Run the tool lifecycle or a workflow", "src/vcf_enterprise_mcp/tools/base.py", "async def execute"),
    ("Connection", "Resolve a provider and call the VCF API", "src/vcf_enterprise_mcp/adapter/platform.py", "class PlatformClient"),
    ("Record", "Persist task, plan, lease and audit state", "src/vcf_enterprise_mcp/state/durable_store.py", "class DurableStore"),
]


def scan(root: Path) -> list[Path]:
    """Return bounded, non-symlinked source/config files without running repo code."""
    found: list[Path] = []
    for folder, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not (Path(folder) / d).is_symlink())
        for name in sorted(files):
            path = Path(folder) / name
            if path.is_symlink() or not path.is_file():
                continue
            if path.suffix.lower() in CODE_SUFFIXES or name in {"pyproject.toml", "package.json", "Cargo.toml", "go.mod", "pom.xml", "README.md", "Dockerfile"}:
                found.append(path)
                if len(found) >= MAX_FILES:
                    return found
    return found


def line_for(path: Path, needle: str) -> int:
    try:
        if path.stat().st_size > MAX_SOURCE_BYTES:
            return 1
        with path.open("r", encoding="utf-8", errors="replace") as stream:
            for number, line in enumerate(stream, 1):
                if needle in line:
                    return number
    except OSError:
        pass
    return 1


def pick_generic(root: Path, files: list[Path], hints: tuple[str, ...]) -> tuple[str, int] | None:
    ranked = []
    for path in files:
        if path.suffix.lower() not in CODE_SUFFIXES:
            continue
        rel = path.relative_to(root).as_posix()
        tokens = set(re.split(r"[/_.\-]+", rel.lower()))
        score = sum(3 if hint in tokens else 1 if hint in rel.lower() else 0 for hint in hints)
        if score:
            ranked.append((-score, len(path.parts), rel, path))
    if not ranked:
        return None
    path = sorted(ranked)[0][3]
    return path.relative_to(root).as_posix(), 1


def review_flags(root: Path, files: list[Path], is_vcf: bool) -> list[dict]:
    """Small set of explainable patterns; findings require human confirmation."""
    flags: list[dict] = []
    rules = [
        (r"\bshell\s*=\s*True\b", "Shell command execution", "Input may reach a shell. Check whether arguments can come from a caller and use an argument list where possible."),
        (r"(?<![\w.])(?:eval|exec)\s*\(", "Dynamic code execution", "Check whether untrusted input reaches this call. Prefer parsing a restricted data format."),
        (r"\byaml\.load\s*\(", "YAML loading", "Check the loader used for external input. Prefer safe_load or an explicit safe loader."),
        (r"\b(?:debug|DEBUG)\s*=\s*True\b", "Debug mode enabled", "Check whether this setting can reach a deployed service; debug output can expose internals."),
    ]
    for path in files:
        rel = path.relative_to(root).as_posix()
        if path.suffix.lower() not in CODE_SUFFIXES or path.name.startswith("test_") or any(part in {"tests", "test", "examples", "fixtures", "benchmarks", "audit", "tools", "docs"} for part in path.relative_to(root).parts):
            continue
        try:
            if path.stat().st_size > MAX_SOURCE_BYTES:
                continue
            with path.open("r", encoding="utf-8", errors="replace") as stream:
                for number, raw in enumerate(stream, 1):
                    line = raw.strip()
                    if not line or line.startswith(("#", "//", "*")):
                        continue
                    for pattern, name, impact in rules:
                        if name == "YAML loading" and ("Loader=" in line or "safe_load" in line):
                            continue
                        if re.search(pattern, line):
                            flags.append({"name": name, "impact": impact, "file": rel, "line": number, "confidence": "Pattern match"})
                            break
                    if len(flags) >= 5:
                        break
        except OSError:
            continue
        if len(flags) >= 5:
            break
    if is_vcf:
        settings = root / "src/vcf_enterprise_mcp/config/settings.py"
        server = root / "src/vcf_enterprise_mcp/core/server.py"
        registry = root / "src/vcf_enterprise_mcp/adapter/capability_provider.py"
        if settings.exists() and server.exists():
            settings_text = settings.read_text(encoding="utf-8", errors="replace")
            server_text = server.read_text(encoding="utf-8", errors="replace")
            if 'host: str = "0.0.0.0"' in settings_text and "enable_tls: bool = False" in settings_text and "HTTPServer(server_address" in server_text:
                flags.insert(0, {"name": "HTTP listener defaults", "impact": "The configured HTTP listener binds to all interfaces while the TLS option defaults off. Confirm an approved TLS gateway and network boundary before remote use.", "file": "src/vcf_enterprise_mcp/config/settings.py", "line": line_for(settings, 'host: str = "0.0.0.0"'), "confidence": "Configuration + server path"})
            source_uses = sum(p.read_text(encoding="utf-8", errors="replace").count(".validate_production_readiness(") for p in files if p.suffix == ".py" and p.relative_to(root).parts[0] == "src" and p.stat().st_size < MAX_SOURCE_BYTES)
            if "def validate_production_readiness" in settings_text and source_uses == 0:
                flags.insert(1 if flags else 0, {"name": "Production checks appear uncalled", "impact": "The settings object defines production checks, but no direct call was found in application source. Confirm the deployment path invokes them before accepting traffic.", "file": "src/vcf_enterprise_mcp/config/settings.py", "line": line_for(settings, "def validate_production_readiness"), "confidence": "No direct call found"})
            if registry.exists():
                registry_text = registry.read_text(encoding="utf-8", errors="replace")
                construction = server_text.split("platform_client = PlatformClient(", 1)[-1].split("\n    )", 1)[0]
                if "platform_client = PlatformClient(" in server_text and "registry=" not in construction and "auth=" not in construction and 'vc_url: str = "http://127.0.0.1:9090"' in registry_text:
                    flags.append({"name": "Live provider binding needs review", "impact": "The server constructor does not pass site-specific provider URLs or upstream auth, while registry defaults point to loopback. Confirm live binding before using real-VCF read results as proof.", "file": "src/vcf_enterprise_mcp/core/server.py", "line": line_for(server, "platform_client = PlatformClient("), "confidence": "Server construction + registry defaults"})
    return flags[:5]


def analyze(repo: str) -> dict:
    root = Path(repo).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Repository path must be a directory")
    files = scan(root)
    relative = {p.relative_to(root).as_posix(): p for p in files}
    if not files:
        raise ValueError("No supported source or manifest files found")
    is_vcf = all(rel in relative for _, _, rel, _ in VCF_EVIDENCE[:4])
    stages = []
    for label, generic_desc, hints in STAGES:
        specialized = next((row for row in VCF_EVIDENCE if row[0] == label), None) if is_vcf else None
        if specialized and specialized[2] in relative:
            _, desc, rel, needle = specialized
            evidence = (rel, line_for(relative[rel], needle))
            certainty = "Verified in source"
        else:
            desc = generic_desc
            evidence = pick_generic(root, files, hints)
            certainty = "Likely from filename" if evidence else "Not detected"
        if evidence:
            stages.append({"label": label, "description": desc, "file": evidence[0], "line": evidence[1], "certainty": certainty})
    if not stages:
        first = next((p for p in files if p.suffix.lower() in CODE_SUFFIXES), files[0])
        stages.append({"label": "Source", "description": "Start with this repository file", "file": first.relative_to(root).as_posix(), "line": 1, "certainty": "No entry point detected"})
    suffix_counts = {}
    for p in files:
        if p.suffix.lower() in CODE_SUFFIXES:
            suffix_counts[p.suffix.lower()] = suffix_counts.get(p.suffix.lower(), 0) + 1
    language = {".py": "Python", ".ts": "TypeScript", ".tsx": "TypeScript", ".js": "JavaScript", ".jsx": "JavaScript", ".go": "Go", ".rs": "Rust", ".java": "Java", ".kt": "Kotlin", ".cs": "C#", ".rb": "Ruby", ".php": "PHP"}.get(max(suffix_counts, key=suffix_counts.get), "Unknown") if suffix_counts else "Unknown"
    integrations = []
    if is_vcf:
        for name, rel, meaning in [
            ("SDDC Manager", "src/vcf_enterprise_mcp/adapter/providers/sddc.py", "Domains, clusters and lifecycle"),
            ("vCenter", "src/vcf_enterprise_mcp/adapter/providers/vcenter.py", "VM and compute operations"),
            ("NSX", "src/vcf_enterprise_mcp/adapter/providers/nsx.py", "Network and security operations"),
            ("VCF Operations", "src/vcf_enterprise_mcp/adapter/providers/operations.py", "Inventory and operations data"),
        ]:
            if rel in relative:
                integrations.append({"name": name, "meaning": meaning, "file": rel})
    else:
        for path in files:
            rel = path.relative_to(root).as_posix()
            if any(part in rel.lower() for part in ("/providers/", "/integrations/", "/adapters/")) and path.suffix.lower() in CODE_SUFFIXES:
                integrations.append({"name": path.stem.replace("_", " ").title(), "meaning": "Connection inferred from module name", "file": rel})
            if len(integrations) >= 4:
                break
    return {"root": root, "name": root.name, "language": language, "files": len(files), "is_vcf": is_vcf, "stages": stages, "integrations": integrations, "flags": review_flags(root, files, is_vcf)}


def esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def evidence_link(info: dict, rel: str, line: int, output: Path | None) -> str:
    # Relative paths keep the report usable when output and repo move together.
    target = info["root"] / rel
    href = os.path.relpath(target, output.parent) if output else "/source?" + urlencode({"repo": str(info["root"]), "file": rel, "line": line})
    return f'<a class="evidence" href="{esc(href)}">{esc(rel)}:{line}</a>'


def source_view(repo: str, rel: str, line_number: int) -> str:
    """Show a bounded source excerpt for links in the local browser UI."""
    root = Path(repo).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Repository path must be a directory")
    path = (root / rel).resolve(strict=True)
    if not path.is_relative_to(root) or (path.suffix.lower() not in CODE_SUFFIXES | {".md", ".toml", ".json", ".xml"} and path.name != "Dockerfile") or path.stat().st_size > MAX_SOURCE_BYTES:
        raise ValueError("Source file is outside the supported scan")
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    number = max(1, min(line_number, len(lines) or 1))
    start, end = max(1, number - 6), min(len(lines), number + 6)
    excerpt = "\n".join(f'<div class="{"focus" if i == number else ""}"><span>{i:4}</span> {esc(lines[i-1])}</div>' for i in range(start, end + 1))
    return f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{esc(rel)}:{number}</title><style>body{{margin:0;background:#f8f7f3;color:#142829;font:16px system-ui}}main{{max-width:1100px;margin:5vh auto;padding:25px}}a{{color:#07544f}}h1{{font-size:1.6rem;overflow-wrap:anywhere}}pre{{background:#122c31;color:#e9f4ef;padding:20px;border-radius:14px;overflow:auto;font:13px/1.65 ui-monospace,monospace}}pre div{{white-space:pre}}pre span{{color:#8bb9aa}}.focus{{background:#31584f}}p{{color:#4d6361}}</style><main><a href="/">← Repo Lens</a><h1>{esc(rel)}:{number}</h1><p>Showing lines {start}–{end} from the selected local repository.</p><pre>{excerpt}</pre></main></html>'''


def render(info: dict, output: Path | None = None) -> str:
    """Render a progressively disclosed field guide from source-backed analysis."""
    vcf = info["is_vcf"]
    title = "Understand the VCF control plane" if vcf else f"Understand {info['name']}"
    subtitle = "vRO or another client asks for an operation. This control plane checks the caller, runs work against VCF APIs, and records the result." if vcf else "See how a request moves through this repository, with source evidence at every detected step."
    stage_guidance = {
        "Entry": ("This is the front door. A client sends a structured request; the server dispatches it to the protocol engine.", "MCP JSON-RPC request", "Request accepted for handling"),
        "Identity": ("The caller's token is checked and turned into a principal. Every later decision uses this identity.", "Bearer token", "Verified principal"),
        "Decision": ("The policy layer decides which tools are visible and whether this specific action is allowed.", "Principal + requested tool", "Allow, deny, or require approval"),
        "Action": ("The selected tool validates inputs, handles a dry run or live operation, and manages longer workflows.", "Approved arguments", "Result or task handle"),
        "Connection": ("A provider chooses the downstream VCF endpoint and the transport sends the API call.", "Operation + resource target", "Upstream API response"),
        "Record": ("Plans, tasks, leases and audit events give operators a way to track or reconstruct an operation.", "Operation state", "Durable status and evidence"),
    }
    generic_io = {
        "Entry": ("Incoming request", "Handler response"), "Identity": ("Caller credentials", "Caller context"),
        "Decision": ("Request + context", "Decision"), "Action": ("Validated input", "Work result"),
        "Connection": ("Outbound request", "Dependency response"), "Record": ("State change", "Stored status"),
        "Source": ("Repository file", "Manual inspection"),
    }
    friendly_labels = {"Entry": "Request arrives", "Identity": "Caller verified", "Decision": "Permission checked", "Action": "Work runs", "Connection": "API called", "Record": "Result recorded", "Source": "Start here"}
    journey_tabs = []
    journey_panels = []
    for index, stage in enumerate(info["stages"]):
        label = esc(friendly_labels.get(stage["label"], stage["label"]))
        description = esc(stage["description"])
        guidance = stage_guidance.get(stage["label"], ("Inspect the linked source to confirm this stage.", "Request", "Result"))
        if not vcf:
            generic_input, generic_output = generic_io.get(stage["label"], ("Input", "Output"))
            guidance = ("This stage is inferred from the repository structure. Open the source to verify its runtime role.", generic_input, generic_output)
        journey_tabs.append(f'<button class="journey-tab" type="button" role="tab" data-group="journey" aria-controls="journey-panel-{index}" aria-selected="false"><span class="n">{index+1:02}</span>{label}</button>')
        journey_panels.append(
            f'<article class="journey-detail" id="journey-panel-{index}" role="tabpanel" data-panel-group="journey">'
            f'<div class="detail-count">Step {index+1:02} of {len(info["stages"])} · {esc(stage["certainty"])}</div>'
            f'<h3>{description}</h3><p>{esc(guidance[0])}</p>'
            f'<div class="io"><div><span>Input</span><strong>{esc(guidance[1])}</strong></div><div><span>Output</span><strong>{esc(guidance[2])}</strong></div></div>'
            f'<div class="source"><span>Source evidence</span>{evidence_link(info, stage["file"], stage["line"], output)}</div></article>'
        )
    if vcf:
        situations = [
            ("Read", "Inspect a workload domain", ["Ask for a domain", "Validate caller", "Check read scope", "Call SDDC provider", "Return allowed data"], "The tool catalog and result are scoped to the caller.", "src/vcf_enterprise_mcp/core/protocol.py", 'if method == "tools/list"'),
            ("Change", "Upgrade a domain", ["Request change", "Check permission", "Create dry-run plan", "Obtain approval", "Run workflow", "Verify + audit"], "Treat the task ID and plan as operational records. A successful API response alone is not the end of the change.", "src/vcf_enterprise_mcp/tools/base.py", "async def execute"),
            ("Failure", "VCF API is unavailable", ["Provider call fails", "Transport handles failure", "Task records state", "Operator checks boundary"], "Find the last successful step before retrying. Check desired state and task status first.", "src/vcf_enterprise_mcp/adapter/transport/circuit_breaker.py", "class"),
        ]
        roles = [
            ("Operations engineer", "Where did the request stop? Start with identity, policy decision, task status and the upstream provider."),
            ("Automation engineer", "Treat this as a guarded API for vRO or another client. Start with a read or dry run; track the plan and task for changes."),
            ("Architect / consultant", "Check identity scope, API egress, storage mode, approval ownership and recovery path before rollout."),
        ]
    else:
        situations = [
            ("Read", "Trace a normal request", ["Caller enters", "Check identity", "Choose action", "Read integration", "Return result"], "This path is inferred from source names; confirm it in the linked entry file.", info["stages"][0]["file"] if info["stages"] else "README.md", ""),
            ("Change", "Trace a state change", ["Caller enters", "Authorize", "Execute", "Call dependency", "Record result"], "Look for validation, transactions, retries and audit behavior in source.", info["stages"][-1]["file"] if info["stages"] else "README.md", ""),
        ]
        roles = [
            ("Operator", "Locate the last successful stage and inspect the next boundary."),
            ("Integrator", "Start with the entry contract and follow the connection module."),
            ("Architect", "Check dependencies, persistence and trust boundaries before deployment."),
        ]
    scenario_tabs = []
    scenario_panels = []
    for index, (kind, name, steps, takeaway, rel, needle) in enumerate(situations):
        scenario_tabs.append(f'<button class="scenario-tab" type="button" role="tab" data-group="scenario" aria-controls="scenario-panel-{index}" aria-selected="false">{esc(kind)}</button>')
        timeline = "".join(f'<li><b>{i:02}</b>{esc(step)}</li>' for i, step in enumerate(steps, 1))
        scenario_panels.append(
            f'<article class="scenario-panel" id="scenario-panel-{index}" role="tabpanel" data-panel-group="scenario"><h3>{esc(name)}</h3>'
            f'<p class="summary">Follow the checkpoints left to right. Each is a place to look when the result surprises you.</p>'
            f'<ol class="timeline">{timeline}</ol><p class="takeaway">{esc(takeaway)}</p>'
            f'<div class="source"><span>Start in source</span>{evidence_link(info, rel, line_for(info["root"] / rel, needle) if needle else 1, output)}</div></article>'
        )
    integrations = "".join(
        f'<article class="integration"><div><h3>{esc(x["name"])}</h3><p>{esc(x["meaning"])}</p></div>{evidence_link(info, x["file"], 1, output)}</article>'
        for x in info["integrations"]
    ) or '<p class="muted">No adapter or provider directory was detected. Inspect the entry and action files for external calls.</p>'
    flags = "".join(
        f'<article class="flag"><span class="flag-icon" aria-hidden="true">!</span><div><small>Review candidate · {esc(x["confidence"])}</small><h3>{esc(x["name"])}</h3><p>{esc(x["impact"])}</p>{evidence_link(info, x["file"], x["line"], output)}</div></article>'
        for x in info["flags"]
    ) or '<div class="intro-band">No patterns from this small ruleset were found. This does not assess dependencies, runtime configuration or deployed infrastructure.</div>'
    role_cards = "".join(f'<article class="role"><span>Start here</span><h3>{esc(name)}</h3><p>{esc(message)}</p></article>' for name, message in roles)
    def setup_step(index: int, title: str, description: str, command: str, proof: str, rel: str, needle: str) -> str:
        command_html = f'<pre><code>{esc(command)}</code></pre>' if command else ""
        return (
            f'<article class="setup-step"><span class="number">{index:02}</span><div><h3>{esc(title)}</h3><p>{esc(description)}</p>'
            f'{command_html}<span class="pass"><b>Pass signal:</b> {esc(proof)}</span>'
            f'{evidence_link(info, rel, line_for(info["root"] / rel, needle) if needle else 1, output)}</div></article>'
        )
    def setup_lane(tag: str, title: str, note: str, steps: list[tuple[str, str, str, str, str, str]], open_by_default: bool = False) -> str:
        items = "".join(setup_step(i, *step) for i, step in enumerate(steps, 1))
        opened = " open" if open_by_default else ""
        return f'<details class="setup-lane"{opened}><summary><span class="lane-tag">{esc(tag)}</span>{esc(title)}</summary><div class="lane-body"><p class="lane-note">{esc(note)}</p><div class="setup-steps">{items}</div></div></details>'
    if vcf:
        local_steps = [
            ("Install the CLI", "Run these commands from this repository folder.", "python3 -m venv .venv\n.venv/bin/python -m pip install '.[test]'", "The vcf-mcp command and test dependencies are available.", "docs/local_testing.md", "python3 -m venv"),
            ("Create a safe local profile", "The setup command writes a loopback, discovery-only configuration; it preserves an existing file.", ".venv/bin/vcf-mcp setup --target digital_twin --gateway-url http://127.0.0.1:8085", "~/.vcf-mcp/config.yaml exists with DISCOVERY_ONLY and mode 0600.", "src/vcf_enterprise_mcp/cli.py", "def _cmd_setup"),
            ("Check the local engine", "This checks that the CLI can build and advertise tool definitions; it does not prove IdP or upstream connectivity.", ".venv/bin/vcf-mcp local check", "Output includes 'Control plane online' and an active-tool count.", "src/vcf_enterprise_mcp/cli.py", "def _cmd_local"),
            ("Start the Digital Twin", "The sibling ../digital_twin repository provides a disposable VCF-like API for this lab.", "PYTHONPATH=.. .venv/bin/python -m digital_twin.run --host 127.0.0.1 --port 8085", "The Twin stays running on loopback port 8085.", "docs/local_testing.md", "PYTHONPATH=.."),
            ("Certify read-only provider calls", "In a second terminal, run the profile that matches the local Twin.", ".venv/bin/vcf-mcp certify --target digital_twin --profile vcf_9_1_1", "Status PASSED; executed reads show DIGITAL_TWIN_VERIFIED; writes are skipped.", "docs/local_testing.md", "certify --target digital_twin"),
            ("Exercise the full HTTP path", "The isolated test creates temporary identities and a VM, then checks approval, change, read-back and audit behavior.", "PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q tests/test_local_http_e2e.py", "The end-to-end test passes with no failed assertions.", "tests/test_local_http_e2e.py", "def test_signed_mutations"),
            ("Run the complete test suite", "Use this as the final local regression gate.", "PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q", "The suite exits successfully; investigate any skips or failures.", "docs/local_testing.md", "-m pytest -q"),
        ]
        real_steps = [
            ("Create the site profile", "Choose a protected config path and a VCF release profile that matches the fleet.", ".venv/bin/vcf-mcp setup --target real_vcf --config /secure/path/config.yaml", "The new file is discovery-only, loopback-bound and restricted to its owner.", "src/vcf_enterprise_mcp/cli.py", "def _cmd_setup"),
            ("Fill identity and VCF settings", "Set the site-specific issuer, client ID, JWKS URI, SDDC Manager address, CA bundle and credential reference. Keep upstream TLS verification on.", "", "An authorized operator has checked those values against the deployed IdP, certificates and network path.", "src/vcf_enterprise_mcp/config/settings.py", "class UpstreamVCFConfig"),
            ("Confirm live provider binding", "Current source uses loopback provider defaults and does not pass site URLs or upstream auth from startup. Wire and review this path before live calls.", "", "Effective provider destinations and credentials point to the intended VCF systems, not loopback defaults.", "src/vcf_enterprise_mcp/core/server.py", "platform_client = PlatformClient("),
            ("Resolve the credential reference", "Run this with the intended tenant and environment; it checks secret resolution, not VCF API authorization.", "VCF_ENTERPRISE_MCP_CONFIG=/secure/path/config.yaml .venv/bin/vcf-mcp credentials test <credential_ref>", "Output reports Status: SUCCESS.", "src/vcf_enterprise_mcp/cli.py", "def _cmd_credentials_test"),
            ("Run read-only VCF certification", "After live provider binding is verified, use the profile matching your fleet. This checks only operations actually executed and skips writes.", "VCF_ENTERPRISE_MCP_CONFIG=/secure/path/config.yaml .venv/bin/vcf-mcp certify --target real_vcf --profile vcf_9_1_1", "Status PASSED and REAL_VCF_VERIFIED for executed calls; inspect skipped operations.", "src/vcf_enterprise_mcp/certification/runner.py", "def run_profile"),
            ("Prove the first authenticated read", "With the listener on loopback and a corporate token, use an approved MCP client to request tools/list and one inventory read.", "VCF_ENTERPRISE_MCP_CONFIG=/secure/path/config.yaml .venv/bin/vcf-mcp local start --mode http", "The caller sees scoped read tools, receives real inventory, and a write is denied in DISCOVERY_ONLY.", "src/vcf_enterprise_mcp/core/protocol.py", 'if method == "tools/list"'),
        ]
        setup_content = (
            '<div class="setup-intro"><span>Checklist · not live status</span><span>Install</span><span>Configure</span><span>Connect</span><span>Prove behavior</span><span>Review rollout</span></div>'
            + setup_lane("Lab", "Run the complete local happy path", "The Twin path verifies local behavior without touching a real VCF fleet. Run each step in order; the Twin stays running while certification runs.", local_steps, True)
            + setup_lane("Real VCF", "Live environment acceptance gates", "Use this checklist after the lab passes. Current source requires endpoint/auth binding review before real-VCF certification; lifecycle and destructive writes remain unqualified.", real_steps)
            + '<div class="gate"><b>Production gate:</b> Review the TLS gateway, tenant-specific IdP settings, VCF entitlements, approval separation, durable state and audit export. The repository defines production readiness checks, but the current application startup has no direct call to them.</div>'
        )
    else:
        first = "README.md" if (info["root"] / "README.md").exists() else info["stages"][0]["file"]
        generic_steps = [
            ("Find the entry and install instructions", "Read the project README and package manifest. This scanner does not infer an install command from filenames.", "", "The correct runtime and dependency command have been confirmed by the project owner.", first, ""),
            ("Configure a safe test target", "Use the project's documented non-production environment and credentials.", "", "The target and access scope are explicit before starting the app.", first, ""),
            ("Run tests and a first read", "Use repository-specific test and smoke commands, then verify the output against the target system.", "", "Tests pass and a read request returns expected data.", first, ""),
        ]
        setup_content = setup_lane("Review", "Build a verified setup path", "No executable setup commands were confirmed for this repository. Use its own documentation to fill in the commands and pass signals.", generic_steps, True)
    caveat = "This is a source-backed orientation. Confirm actual security and behavior in the deployed environment." if vcf else "Most stages were inferred from filenames. Confirm the linked source before relying on the flow."
    replacements = {
        "@@TITLE@@": esc(title), "@@REPO@@": esc(info["name"]), "@@LANGUAGE@@": esc(info["language"]),
        "@@SUBTITLE@@": esc(subtitle), "@@FILECOUNT@@": str(info["files"]), "@@CAVEAT@@": esc(caveat),
        "@@DESTINATION@@": "SDDC Manager, vCenter, NSX and VCF Operations." if vcf else "External systems, when the repository has them.",
        "@@GUARD_TITLE@@": "Entry · identity · permission" if vcf else "Entry and checks",
        "@@GUARD_COPY@@": "Who asked, and what may they do?" if vcf else "The detected request boundary and checks.",
        "@@WORK_TITLE@@": "Action · status · evidence" if vcf else "Action and state",
        "@@WORK_COPY@@": "Carry out work and record what happened." if vcf else "Detected work and persistence modules.",
        "@@JOURNEY_TABS@@": "".join(journey_tabs), "@@JOURNEY_PANELS@@": "".join(journey_panels),
        "@@SCENARIO_TABS@@": "".join(scenario_tabs), "@@SCENARIO_PANELS@@": "".join(scenario_panels),
        "@@INTEGRATIONS@@": integrations, "@@FLAGS@@": flags, "@@ROLES@@": role_cards,
        "@@SETUP_CONTENT@@": setup_content,
    }
    page = Path(__file__).with_name("report_template.html").read_text(encoding="utf-8")
    for marker, value in replacements.items():
        page = page.replace(marker, value)
    return page


FORM = '''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Repo Lens</title><style>*{box-sizing:border-box}body{margin:0;background:#f8f7f3;color:#142829;font:16px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}main{max-width:1050px;margin:12vh auto;padding:24px;display:grid;grid-template-columns:1.1fr .9fr;gap:65px;align-items:center}.eyebrow{color:#087c73;font-size:.76rem;font-weight:850;text-transform:uppercase;letter-spacing:.15em}h1{font-size:clamp(3rem,6vw,5rem);letter-spacing:-.06em;line-height:1.03;margin:18px 0}p{font-size:1.1rem;color:#4d6361}.card{background:#fffefa;border:1px solid #dce5df;border-radius:20px;padding:32px;box-shadow:0 18px 50px rgba(17,46,43,.07)}label{display:block;font-weight:800;font-size:.83rem;margin-bottom:9px}input{width:100%;padding:14px;border:1px solid #abc7bc;border-radius:10px;font:inherit}button{width:100%;background:#07544f;color:#fff;border:0;border-radius:10px;padding:14px;font:inherit;font-weight:800;cursor:pointer;margin-top:14px}.fine{font-size:.8rem;color:#5c726c;margin-top:16px}@media(max-width:750px){main{grid-template-columns:1fr;gap:25px;margin:3vh auto}.card{padding:24px}}</style><main><div><div class="eyebrow">Offline repository field guide</div><h1>Make the codebase make sense.</h1><p>Point Repo Lens at a local repository. It creates a short, visual path from request to result, with source evidence and review flags.</p></div><div class="card"><form method="post" action="/generate"><label for="repo">Repository folder</label><input id="repo" name="repo" required placeholder="/path/to/repository" autocomplete="off"><button type="submit">Create walkthrough →</button></form><p class="fine">Read-only scan · no repository code executed · no network requests</p></div></main></html>'''


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlsplit(self.path)
        if parsed.path == "/":
            self.respond(FORM, 200)
        elif parsed.path == "/source":
            params = parse_qs(parsed.query)
            try:
                page = source_view(params.get("repo", [""])[0], params.get("file", [""])[0], int(params.get("line", ["1"])[0]))
                self.respond(page, 200)
            except (OSError, ValueError) as exc:
                self.respond(f"<h1>Source unavailable</h1><p>{esc(exc)}</p>", 400)
        else:
            self.respond("Not found", 404)

    def do_POST(self):
        if self.path != "/generate":
            self.respond("Not found", 404)
            return
        size = int(self.headers.get("Content-Length", "0"))
        if not 0 < size <= 8192:
            self.respond("Invalid request", 400)
            return
        data = parse_qs(self.rfile.read(size).decode("utf-8", errors="replace"))
        try:
            report = render(analyze(data.get("repo", [""])[0]))
            self.respond(report, 200)
        except (OSError, ValueError) as exc:
            self.respond(f"<h1>Could not analyze repository</h1><p>{esc(exc)}</p><a href='/'>Try again</a>", 400)

    def respond(self, body: str, status: int) -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:")
        self.end_headers()
        self.wfile.write(encoded)


def main() -> None:
    parser = argparse.ArgumentParser(description="Create an offline visual explanation of a repository")
    sub = parser.add_subparsers(dest="command", required=True)
    gen = sub.add_parser("generate", help="Write a standalone HTML document")
    gen.add_argument("repo", help="Path to repository")
    gen.add_argument("-o", "--output", required=True, help="HTML output path")
    serve = sub.add_parser("serve", help="Run the local browser UI")
    serve.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    if args.command == "serve":
        server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
        print(f"Open http://127.0.0.1:{args.port}")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            server.server_close()
    else:
        output = Path(args.output).expanduser().resolve()
        info = analyze(args.repo)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(render(info, output), encoding="utf-8")
        print(output)


if __name__ == "__main__":
    main()
