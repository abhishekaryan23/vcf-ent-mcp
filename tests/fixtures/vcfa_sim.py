# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""In-process transport onto the VCF Automation part of the organization simulator (tools/org_sim/server.py).

The simulator's request handler is driven directly (no sockets), so tests exercise the real simulator logic:
session login, service-account registration, device flow, rotating refresh tokens, /vco and /iaas access checks.
Like the real HTTP transport, 401/403 and 404 are raised as exceptions.
"""

from __future__ import annotations

import importlib.util
import io
import sys
from pathlib import Path

from vcf_enterprise_mcp.adapter.transport.base import BaseTransport, TransportRequest, TransportResponse
from vcf_enterprise_mcp.adapter.transport.errors import UpstreamAuthException, UpstreamResourceNotFoundException

ORG_SIM = Path(__file__).resolve().parents[2] / "tools" / "org_sim"
PASSWORD = "sim-lab-password-NOT-A-REAL-SECRET"
URL = "https://vcfa.northwind.lab"


def _load_sim_module():
    if str(ORG_SIM) not in sys.path:
        sys.path.insert(0, str(ORG_SIM))
    spec = importlib.util.spec_from_file_location("org_sim_server_under_test", ORG_SIM / "server.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def make_sim(state_dir: Path):
    module = _load_sim_module()
    import enterprise_model  # noqa: E402  (tools/org_sim is on sys.path after _load_sim_module)
    (state_dir / "password").write_text(PASSWORD)
    return module.Sim(state_dir, "orch_default", enterprise_model)


class _Headers(dict):
    def get(self, key, default=None):
        for k, v in self.items():
            if k.lower() == key.lower():
                return v
        return default


class _Handler:
    def __init__(self, path, headers, body):
        self.path = path
        self.headers = _Headers(headers)
        self.rfile = io.BytesIO(body)
        self.wfile = io.BytesIO()
        self.status = None
        self.sent = []

    def send_response(self, code):
        self.status = code

    def send_header(self, name, value):
        self.sent.append((name, value))

    def end_headers(self):
        pass


class SimTransport(BaseTransport):
    def __init__(self, sim, app="vcfa"):
        self.sim, self.app, self.requests = sim, app, []

    def send(self, request: TransportRequest) -> TransportResponse:
        body = request.get_body_bytes() or b""
        headers = dict(request.headers)
        if body:
            headers["Content-Length"] = str(len(body))
            if request.json_body is not None:
                headers.setdefault("Content-Type", "application/json")
        url = request.get_full_url()
        path = url.split("//", 1)[1].split("/", 1)[1]
        headers["Host"] = url.split("//", 1)[1].split("/", 1)[0]
        h = _Handler("/" + path, headers, body)
        self.sim.handle(self.app, h, request.method)
        self.requests.append((request.method, "/" + path.split("?")[0], h.status))
        resp_headers = {k: v for k, v in h.sent}
        resp = TransportResponse(status_code=h.status, headers=resp_headers, body=h.wfile.getvalue())
        if h.status in (401, 403):
            raise UpstreamAuthException(url, h.status, resp.text)
        if h.status == 404:
            raise UpstreamResourceNotFoundException("Resource", url, url)
        return resp

    async def send_async(self, request):
        return self.send(request)
