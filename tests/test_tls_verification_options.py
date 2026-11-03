# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""Explicit upstream TLS opt-out, configured startup and real-socket verification."""
import datetime as dt
import io
import logging
import ssl
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from vcf_enterprise_mcp.adapter.ssrf_guard import SSRFGuard
from vcf_enterprise_mcp.adapter.transport.base import TransportRequest
from vcf_enterprise_mcp.adapter.transport.http import HTTPTransport
from vcf_enterprise_mcp.adapter.transport.errors import UpstreamTLSException
from vcf_enterprise_mcp.cli import main as cli_main
from vcf_enterprise_mcp.config.settings import EnterpriseSettings, UpstreamVCFConfig
from vcf_enterprise_mcp.core import server


@pytest.fixture(scope='module')
def certs(tmp_path_factory):
    p = tmp_path_factory.mktemp('tls-options')
    now = dt.datetime.now(dt.timezone.utc)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Temporary test CA')])
    ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
          .public_key(key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now-dt.timedelta(days=1)).not_valid_after(now+dt.timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
          .sign(key, hashes.SHA256()))
    (p/'ca.pem').write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    for case in ['valid', 'expired', 'wrong-host']:
        hostname = 'other.invalid' if case == 'wrong-host' else 'localhost'
        leaf = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
                .issuer_name(name).public_key(leaf.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now-dt.timedelta(days=2))
                .not_valid_after(now+dt.timedelta(days=-1 if case == 'expired' else 1))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
                .sign(key, hashes.SHA256()))
        (p/f'{case}.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (p/f'{case}.key').write_bytes(leaf.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return p


@contextmanager
def tls_server(certs, case):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"ok":true}')
        def log_message(self, *args):
            pass
    s = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certs/f'{case}.pem', certs/f'{case}.key')
    s.socket = ctx.wrap_socket(s.socket, server_side=True)
    thread = threading.Thread(target=s.serve_forever, daemon=True)
    thread.start()
    try:
        yield f'https://localhost:{s.server_port}/'
    finally:
        s.shutdown()
        s.server_close()
        thread.join()


@pytest.mark.parametrize('case,trust,verify,allowed', [
    ('valid', True, True, True),
    ('valid', False, True, False),
    ('expired', True, True, False),
    ('wrong-host', True, True, False),
    ('valid', False, False, True),
    ('expired', False, False, True),
    ('wrong-host', False, False, True),
])
def test_real_tls_policy(certs, case, trust, verify, allowed, caplog):
    guard = SSRFGuard(dns_resolver=lambda host, port: ['127.0.0.1'])
    with caplog.at_level(logging.WARNING):
        transport = HTTPTransport(ssrf_guard=guard, max_retries=0, verify_ssl=verify,
                                  ca_cert_path=str(certs/'ca.pem') if trust else None)
        with tls_server(certs, case) as url:
            if allowed:
                assert transport.send(TransportRequest(method='GET', url=url)).json() == {'ok': True}
            else:
                with pytest.raises(UpstreamTLSException):
                    transport.send(TransportRequest(method='GET', url=url))
    assert ('certificate verification is DISABLED' in caplog.text) == (not verify)
    # Per-instance opt-out must never alter Python's global TLS defaults.
    assert ssl.create_default_context().verify_mode == ssl.CERT_REQUIRED


def test_verification_defaults_and_explicit_environment(tmp_path, monkeypatch):
    (tmp_path/'config.yaml').write_text('{}')
    monkeypatch.delenv('VCF_VERIFY_SSL', raising=False)
    assert UpstreamVCFConfig().verify_ssl is True
    assert EnterpriseSettings.load_from_yaml(str(tmp_path/'config.yaml')).vcf.verify_ssl is True
    monkeypatch.setenv('VCF_VERIFY_SSL', 'false')
    assert EnterpriseSettings.load_from_yaml(str(tmp_path/'config.yaml')).vcf.verify_ssl is False
    monkeypatch.setenv('VCF_VERIFY_SSL', 'typo')
    with pytest.raises(ValueError, match='VCF_VERIFY_SSL'):
        EnterpriseSettings.load_from_yaml(str(tmp_path/'config.yaml'))


@pytest.mark.parametrize('args', [['server', '--insecure'], ['local', 'start', '--insecure']])
def test_cli_manual_opt_out(args):
    with patch('vcf_enterprise_mcp.core.server.main') as start:
        assert cli_main(args) == 0
    start.assert_called_once_with(mode='stdio', insecure=True)


def test_startup_applies_tls_and_preserves_settings(tmp_path, monkeypatch, caplog, capsys):
    cfg = EnterpriseSettings()
    cfg.server.environment = 'testing'
    cfg.policy.operating_mode = 'DISABLED'
    monkeypatch.setenv('VCF_MCP_DB_PATH', str(tmp_path/'state.db'))
    monkeypatch.delenv('VCF_PLATFORM_MODE', raising=False)
    captured = []
    real_builder = server._build_engine_from_settings
    def build(settings):
        engine = real_builder(settings)
        captured.append(engine)
        return engine
    with patch.object(server, 'get_enterprise_settings', return_value=cfg), \
         patch.object(server, '_build_engine_from_settings', side_effect=build), \
         patch.object(server.sys, 'stdin', io.StringIO('')), caplog.at_level(logging.WARNING):
        server.main(mode='stdio', insecure=True)
    assert not captured[0].platform.transport.verify_ssl
    assert captured[0].pep.pdp.config.operating_mode == 'DISABLED'
    assert cfg.vcf.verify_ssl is True
    assert 'certificate verification is DISABLED' in caplog.text
    assert capsys.readouterr().out == ''
    captured[0].task_store.durable._conn.close()


def test_configured_ca_reaches_engine(tmp_path, monkeypatch):
    cfg = EnterpriseSettings()
    cfg.server.environment = 'testing'
    cfg.vcf.ca_cert_path = '/explicit/enterprise-ca.pem'
    monkeypatch.setenv('VCF_MCP_DB_PATH', str(tmp_path/'state.db'))
    engine = server._build_engine_from_settings(cfg)
    assert engine.platform.transport.verify_ssl is True
    assert engine.platform.transport.ca_cert_path == cfg.vcf.ca_cert_path
    engine.task_store.durable._conn.close()


def test_https_redirect_uses_next_hop_hostname_and_same_ca(certs):
    """A redirect changes SNI while retaining the configured CA and pinned socket."""
    with tls_server(certs, 'wrong-host') as second:
        second_port = second.split(':')[-1].rstrip('/')
        class Redirect(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(302)
                self.send_header('Location', f'https://other.invalid:{second_port}/')
                self.end_headers()
            def log_message(self, *args): pass
        first = ThreadingHTTPServer(('127.0.0.1', 0), Redirect)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certs/'valid.pem', certs/'valid.key')
        first.socket = context.wrap_socket(first.socket, server_side=True)
        thread = threading.Thread(target=first.serve_forever, daemon=True); thread.start()
        try:
            guard = SSRFGuard(allowed_dns_suffixes=['localhost', 'other.invalid'], dns_resolver=lambda host, port: ['127.0.0.1'])
            transport = HTTPTransport(ssrf_guard=guard, ca_cert_path=str(certs/'ca.pem'), max_retries=0)
            result = transport.send(TransportRequest(method='GET', url=f'https://localhost:{first.server_port}/'))
            assert result.json() == {'ok': True}
        finally:
            first.shutdown(); first.server_close(); thread.join()
