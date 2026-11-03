# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""Independent regressions for V01/V03/V04/V05/V07/V08; no production endpoints."""
import asyncio
import base64
import contextlib
import json
import os
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

import pytest
from vcf_enterprise_mcp.adapter.ssrf_guard import SSRFGuard
from vcf_enterprise_mcp.adapter.transport.base import TransportRequest
from vcf_enterprise_mcp.adapter.transport.http import HTTPTransport
from vcf_enterprise_mcp.config.settings import EnterpriseSettings, PolicyConfig
from vcf_enterprise_mcp.core.errors import ConfigurationException, HeaderMismatchException, ApprovalRequiredException, AuthorizationDeniedException
from vcf_enterprise_mcp.core.headers import validate_mcp_headers
from vcf_enterprise_mcp.secrets.local_encrypted import LocalKeyProtector
from vcf_enterprise_mcp.policy.engine import PolicyDecisionPoint
from vcf_enterprise_mcp.policy.enforcement import PolicyEnforcementPoint
from vcf_enterprise_mcp.tools.operational_tools import VCFPowerVMTool, VCFResizeVMTool
from vcf_enterprise_mcp.auth.identity import Principal
from tests.fixtures.authorized_execution import execute_authorized


@pytest.mark.parametrize('key', [b' '+bytes(range(31)), bytes(range(31))+b'\n', bytes(range(32)), bytes(range(224,256))])
def test_master_key_exact_bytes_survive_restart(tmp_path, monkeypatch, key):
    monkeypatch.delenv('VCF_LOCAL_MASTER_KEY', raising=False)
    p = tmp_path/'key'
    with patch('vcf_enterprise_mcp.secrets.local_encrypted.secrets.token_bytes', return_value=key):
        first = LocalKeyProtector(str(p)).get_master_key()
    assert first == LocalKeyProtector(str(p)).get_master_key() == key
    assert p.stat().st_mode & 0o777 == 0o600


def test_key_storage_fail_closed(tmp_path, monkeypatch):
    monkeypatch.delenv('VCF_LOCAL_MASTER_KEY', raising=False)
    p = tmp_path/'key'; p.write_bytes(b'invalid'); p.chmod(0o600)
    with pytest.raises(ConfigurationException): LocalKeyProtector(str(p)).get_master_key()
    p.unlink()
    protector = LocalKeyProtector(str(p))
    with patch('os.open', side_effect=PermissionError):
        with pytest.raises(ConfigurationException): protector.get_master_key()
    assert protector._master_key is None


def test_setup_file_precedence_and_bad_configuration(tmp_path, monkeypatch):
    monkeypatch.delenv('VCF_ENTERPRISE_MCP_CONFIG', raising=False)
    monkeypatch.setattr(Path, 'home', lambda: tmp_path)
    config = tmp_path/'.vcf-mcp'/'config.yaml'; config.parent.mkdir()
    config.write_text('server:\n  environment: digital_twin\nvcf:\n  gateway_url: http://127.0.0.1:18085\n')
    assert EnterpriseSettings.load_from_yaml().vcf.gateway_url.endswith(':18085')
    config.write_text('[')
    with pytest.raises(ConfigurationException): EnterpriseSettings.load_from_yaml()
    with pytest.raises(ConfigurationException): EnterpriseSettings.load_from_yaml(str(tmp_path/'missing'))


def request_metadata():
    body = {'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':'test','arguments':{'dry_run':True},'_meta':{'io.modelcontextprotocol/protocolVersion':'2026-07-28'}}}
    headers = {'MCP-Protocol-Version':'2026-07-28','Mcp-Method':'tools/call','Mcp-Name':'test','Mcp-Param-dry_run':'true'}
    return body, headers


@pytest.mark.parametrize('missing', ['MCP-Protocol-Version','Mcp-Method','Mcp-Name'])
def test_missing_required_http_metadata(missing):
    body, headers = request_metadata(); del headers[missing]
    with pytest.raises(HeaderMismatchException) as e: validate_mcp_headers(headers, body)
    assert e.value.error_code == -32020


def test_version_name_and_body_validation():
    body, headers = request_metadata(); validate_mcp_headers(headers, body)
    body['params']['name'] = '工具'
    headers['Mcp-Name'] = '=?base64?' + base64.b64encode('工具'.encode()).decode() + '?='
    validate_mcp_headers(headers, body)
    headers['MCP-Protocol-Version'] = '1900-01-01'
    with pytest.raises(HeaderMismatchException) as e: validate_mcp_headers(headers, body)
    assert e.value.error_code == -32022
    assert e.value.details['supported'] == ['2026-07-28']
    body, headers = request_metadata(); body['params'].pop('_meta')
    with pytest.raises(HeaderMismatchException): validate_mcp_headers(headers, body)


@pytest.mark.parametrize('tool_type,args', [(VCFPowerVMTool, {'vm_id':'vm-101','action':'start'}),(VCFResizeVMTool, {'vm_id':'vm-101','memory_gb':32})])
def test_unsigned_mutations_denied_without_injected_plan_manager(tool_type, args):
    tool = tool_type(pep=PolicyEnforcementPoint(PolicyDecisionPoint(PolicyConfig(operating_mode='AUDITED_OPERATIONS'))))
    principal = Principal(user_id='operator', corporate_groups=['VCF-Platform-Admins'], allowed_clusters=['*'])
    with patch.object(tool.platform, 'power_vm') as power, patch.object(tool.platform, 'resize_vm') as resize:
        with pytest.raises(ApprovalRequiredException): asyncio.run(tool.execute(principal, args))
    power.assert_not_called(); resize.assert_not_called()


def test_kill_switch_at_dispatch_boundary():
    pdp = PolicyDecisionPoint(PolicyConfig(operating_mode='AUDITED_OPERATIONS'))
    tool = VCFPowerVMTool(pep=PolicyEnforcementPoint(pdp))
    principal = Principal(user_id='operator', corporate_groups=['VCF-Platform-Admins'], allowed_clusters=['*'])
    @contextlib.contextmanager
    def revoke(*args, **kwargs):
        pdp.config.operating_mode = 'DISABLED'
        yield
    with patch.object(tool.lease_mgr, 'lease', side_effect=revoke), patch.object(tool.platform, 'power_vm') as power:
        with pytest.raises(AuthorizationDeniedException):
            asyncio.run(execute_authorized(tool, principal, {'vm_id':'vm-101','action':'stop'}))
    power.assert_not_called()


def test_redirect_pins_each_hop_and_strips_credentials():
    seen = []
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append((self.path, dict(self.headers)))
            if self.path == '/first':
                self.send_response(302)
                self.send_header('Location', f'http://second.corp.internal:{self.server.server_port}/second')
            else: self.send_response(200)
            self.end_headers(); self.wfile.write(b'{}')
        def log_message(self, *args): pass
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True); worker.start()
    connected = []; resolutions = []
    real_connect = socket.create_connection
    def resolve(host, port):
        resolutions.append(host); return ['127.0.0.1']
    def connect(address, *args, **kwargs):
        connected.append(address[0]); assert address[0] == '127.0.0.1'
        return real_connect(address, *args, **kwargs)
    try:
        transport = HTTPTransport(ssrf_guard=SSRFGuard(dns_resolver=resolve), max_retries=0)
        with patch('socket.create_connection', side_effect=connect):
            transport.send(TransportRequest('GET', f'http://first.corp.internal:{server.server_port}/first', headers={'vmware-api-session-id':'synthetic-secret'}))
        assert resolutions == ['first.corp.internal','second.corp.internal']
        assert connected == ['127.0.0.1','127.0.0.1']
        assert seen[1][1]['Host'].startswith('second.corp.internal:')
        assert not any(k.lower() == 'vmware-api-session-id' for k in seen[1][1])
    finally:
        server.shutdown(); server.server_close(); worker.join()
