# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
In-process harness for the Northwind Orchestrator simulator (tools/org_sim/vco_sim.py).

SimTransport feeds MCP requests straight into the simulator's real request handler (Sim.handle, body parsing and response
writing included) without sockets or TLS, and applies the same error mapping as the production HTTP transport
(404 / 401 / 403 / 5xx raise), so orchestrator.py runs against the simulator exactly as it would against a server.
"""

from __future__ import annotations

import io
import json
import sys
import urllib.parse
from email.message import Message
from pathlib import Path
from typing import Any, Dict, List, Optional

from vcf_enterprise_mcp.adapter.transport.base import BaseTransport, TransportRequest, TransportResponse
from vcf_enterprise_mcp.adapter.transport.errors import (UpstreamAuthException, UpstreamResourceNotFoundException,
                                                         UpstreamServerException)

SIM_DIR = Path(__file__).resolve().parents[1] / "tools" / "org_sim"
if str(SIM_DIR) not in sys.path:
    sys.path.insert(0, str(SIM_DIR))

import enterprise_model  # noqa: E402
import server as sim_server  # noqa: E402

ORCH_URL = "https://vcf-auto01.nwg.lab"


class _Handler:
    def __init__(self, method: str, path_and_query: str, headers: Dict[str, str], body: bytes):
        self.path = path_and_query
        self.headers = Message()
        for k, v in headers.items():
            self.headers[k] = v
        self.headers["Content-Length"] = str(len(body))
        self.rfile, self.wfile = io.BytesIO(body), io.BytesIO()
        self.status, self.resp_headers = 0, {}

    def send_response(self, code):
        self.status = code

    def send_header(self, k, v):
        self.resp_headers[k] = v

    def end_headers(self):
        pass


class SimTransport(BaseTransport):
    def __init__(self, sim, app: str = "vcfa"):
        self.sim, self.app = sim, app
        self.token = sim.issue("svc-mcp-automation")
        self.requests: List[Dict[str, Any]] = []

    def send(self, request: TransportRequest) -> TransportResponse:
        url = urllib.parse.urlsplit(request.get_full_url())
        headers = {k: v for k, v in request.headers.items()}
        headers["Authorization"] = f"Bearer {self.token}"
        body = request.get_body_bytes() or b""
        if request.json_body is not None:
            headers.setdefault("Content-Type", "application/json")
        h = _Handler(request.method, url.path + ("?" + url.query if url.query else ""), headers, body)
        self.requests.append({"method": request.method, "path": url.path, "query": url.query, "headers": dict(headers), "body": body})
        self.sim.handle(self.app, h, request.method)
        resp = TransportResponse(status_code=h.status, headers=dict(h.resp_headers), body=h.wfile.getvalue())
        if resp.status_code >= 500:
            raise UpstreamServerException(request.url, resp.status_code, resp.text)
        if resp.status_code == 404:
            raise UpstreamResourceNotFoundException("Resource", request.url, request.url)
        if resp.status_code in (401, 403):
            raise UpstreamAuthException(request.url, resp.status_code, resp.text)
        return resp

    async def send_async(self, request: TransportRequest) -> TransportResponse:
        return self.send(request)

    # convenience for assertions
    def calls(self, method: Optional[str] = None, contains: str = "") -> List[Dict[str, Any]]:
        return [r for r in self.requests if (method is None or r["method"] == method) and contains in r["path"]]


class FakeAuth:
    def apply(self, request):
        return request

    def invalidate(self):
        pass


class SimPlatform:
    """The bits of PlatformClient that automation/orchestrator.py reads."""

    def __init__(self, sim, transport, **cfg):
        self.transport = transport
        self.sim = sim
        self.orchestrator = {"url": ORCH_URL, "auth": FakeAuth(), "managed_category": "MCP-Managed", "module_prefix": "com.mcp",
                             "run_allowlist": ["Northwind/*"], "blocked": ["SQL AG planned failover"], "repository_allowlist": ["https://pypi.org/simple"],
                             "script_level": "es5", **cfg}
        self.resolve_secret = lambda ref: sim.password if "right" in ref or "itsm" in ref else "wrong-" + ref


def make_sim(tmp_path, scenario: str = "orch_default", **cfg):
    (tmp_path / "password").write_text("sim-pass-" + scenario)
    sim = sim_server.Sim(tmp_path, scenario, enterprise_model)
    transport = SimTransport(sim)
    return sim, transport, SimPlatform(sim, transport, **cfg)


def parse_json(resp: TransportResponse) -> Any:
    return json.loads(resp.body) if resp.body else None
