# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""Real MCP CLI -> JWT/JWKS -> plan/approval -> sibling Twin HTTP -> read-back/audit.
Runs only isolated loopback processes with ephemeral credentials and state.
"""
import json
import os
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import jwt
import pytest
import yaml
from tests.fixtures.jwt_factory import JWTTestFactory

ROOT = Path(__file__).resolve().parents[1]
TWIN_FIXTURE = ROOT/'tests'/'fixtures'/'digital_twin'
TWIN = TWIN_FIXTURE


def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0)); return s.getsockname()[1]


def wait_port(number, process, log_path=None):
    for _ in range(100):
        if process.poll() is not None:
            extra = f"\nLog: {log_path.read_text()}" if log_path and log_path.exists() else ""
            raise AssertionError(f'Local service exited before startup (code {process.poll()}){extra}')
        try:
            with socket.create_connection(('127.0.0.1', number), timeout=.1): return
        except OSError: time.sleep(.05)
    raise AssertionError('Local service did not start')


@contextmanager
def child(command, env, log):
    with log.open('w') as output:
        proc = subprocess.Popen(command, env=env, stdout=output, stderr=output, cwd=ROOT)
        try: yield proc
        finally:
            if proc.poll() is None:
                proc.terminate()
                try: proc.wait(timeout=5)
                except subprocess.TimeoutExpired: proc.kill(); proc.wait()


def request(url, method='GET', body=None, headers=None):
    req = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None,
                                 method=method, headers={'Content-Type':'application/json', **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            raw = response.read(); return response.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as err:
        return err.code, json.loads(err.read())


def test_signed_mutations_through_configured_cli_and_real_twin(tmp_path):
    assert TWIN.exists(), 'Sibling Digital Twin is required for this integration test'
    twin_port, mcp_port = port(), port()
    url = f'http://127.0.0.1:{twin_port}'
    calls = tmp_path/'twin-http.jsonl'
    bootstrap = tmp_path/'twin_server.py'
    bootstrap.write_text(f'''from digital_twin.server import create_digital_twin_app
import uvicorn, json
app = create_digital_twin_app({str(TWIN/'vcf_inventory.yaml')!r})
@app.middleware("http")
async def record(request, call_next):
    with open({str(calls)!r}, "a") as f: f.write(json.dumps({{"method":request.method,"path":request.url.path}})+"\\n")
    return await call_next(request)
uvicorn.run(app, host="127.0.0.1", port={twin_port}, log_level="error")
''')
    factory = JWTTestFactory(issuer='https://local-audit.example', kid='ephemeral-e2e')
    public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(factory.public_key)); public['kid'] = factory.kid
    class JWKS(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200); self.end_headers(); self.wfile.write(json.dumps({'keys':[public]}).encode())
        def log_message(self, *args): pass
    jwks = ThreadingHTTPServer(('127.0.0.1', 0), JWKS)
    thread = threading.Thread(target=jwks.serve_forever, daemon=True); thread.start()
    cfg = tmp_path/'config.yaml'
    cfg.write_text(yaml.safe_dump({'server':{'host':'127.0.0.1','port':mcp_port,'environment':'digital_twin'},
        'vcf':{'gateway_url':url},'policy':{'operating_mode':'FULL_ENFORCEMENT'},
        'idp':{'issuer_url':factory.issuer,'jwks_uri':f'http://127.0.0.1:{jwks.server_port}/jwks'}}))
    env = {**os.environ,'PYTHONDONTWRITEBYTECODE':'1','PYTHONPATH':str(ROOT/'src')+os.pathsep+str(TWIN.parent),
           'VCF_ENTERPRISE_MCP_CONFIG':str(cfg),'VCF_MCP_DB_PATH':str(tmp_path/'mcp.db'),'VCF_MCP_ENV':'testing'}
    env.pop('VCF_PLATFORM_MODE', None); env.pop('VCF_OPERATING_MODE', None); env.pop('VCF_GATEWAY_URL', None)
    initiator = factory.create_token('initiator',['VCF-Platform-Admins'],allowed_clusters=['*'],allowed_domains=['*'])
    approver = factory.create_token('approver',['VCF-Platform-Admins'],allowed_clusters=['*'],allowed_domains=['*'])
    def rpc(method, params, token=initiator, metadata=True):
        params = {**params, '_meta':{'io.modelcontextprotocol/protocolVersion':'2026-07-28'}}
        headers = {'Authorization':'Bearer '+token}
        if metadata:
            headers.update({'MCP-Protocol-Version':'2026-07-28','Mcp-Method':method})
            if method == 'tools/call': headers['Mcp-Name'] = params['name']
        return request(f'http://127.0.0.1:{mcp_port}/mcp','POST',{'jsonrpc':'2.0','id':1,'method':method,'params':params},headers)
    def call(name, args):
        status, response = rpc('tools/call',{'name':name,'arguments':args})
        assert status == 200 and 'error' not in response, response
        assert not response['result'].get('isError'), response
        return json.loads(response['result']['content'][0]['text'])
    def writes(): return [json.loads(x) for x in calls.read_text().splitlines() if json.loads(x)['method'] not in ('GET','HEAD')]
    try:
        with child([os.environ.get('TWIN_PYTHON', sys.executable),str(bootstrap)],env,tmp_path/'twin.log') as twin:
            wait_port(twin_port,twin,tmp_path/'twin.log')
            status, vm = request(url+'/api/vcenter/vm','POST',{'name':'audit-test-vm','cpu':{'count':2},'memory':{'size_MiB':4096}})
            assert status == 201
            with child([sys.executable,'-m','vcf_enterprise_mcp.cli','local','start','--mode','http'],env,tmp_path/'mcp.log') as mcp:
                wait_port(mcp_port,mcp,tmp_path/'mcp.log')
                assert rpc('tools/list',{},metadata=False)[0] == 400
                assert 'error' in rpc('tools/list',{},token='invalid')[1]
                assert 'tools' in rpc('tools/list',{})[1]['result']
                assert call('vcf_get_vm',{'vm_id':vm})['vm_id'] == vm
                clusters = request(url+'/api/vcenter/cluster')[1]
                telemetry = call('vcf_query_telemetry',{'cluster_id':clusters[0]['cluster']})
                assert telemetry['data_points']
                for name, change in [('vcf_resize_vm',{'memory_gb':8,'cpu_cores':4}),('vcf_power_vm',{'action':'start'}),('vcf_power_vm',{'action':'stop'})]:
                    args = {'vm_id':vm,**change,'idempotency_key':name+str(change)}
                    count = len(writes())
                    unsigned = rpc('tools/call',{'name':name,'arguments':args})[1]
                    assert unsigned['result']['isError'] and 'plan_id' in unsigned['result']['content'][0]['text']
                    plan = call(name,{**args,'dry_run':True})
                    assert plan['plan_id'] and len(writes()) == count
                    # Separation of duties is enforced through the real HTTP endpoint.
                    assert 'error' in rpc('enterprise/plans/approve',{'plan_id':plan['plan_id']})[1]
                    approval = rpc('enterprise/plans/approve',{'plan_id':plan['plan_id']},token=approver)[1]
                    assert 'error' not in approval, approval
                    auth = approval['result']; args.update(plan_id=plan['plan_id'],approval_id=auth['approval_id'],nonce=auth['nonce'])
                    result = call(name,args); assert result['status'] == 'SUCCESS'
                    count = len(writes())
                    assert call(name,args) == result
                    assert len(writes()) == count
                state = request(url+f'/api/vcenter/vm/{vm}')[1]
                assert (state['cpu_count'],state['memory_size_MiB'],state['power_state']) == (4,8192,'POWERED_OFF')
                with sqlite3.connect(tmp_path/'mcp.db') as db:
                    assert db.execute('SELECT count(*) FROM audit_chain').fetchone()[0] >= 8
                certification = subprocess.run([sys.executable,'-m','vcf_enterprise_mcp.cli','certify','--target','digital_twin'],env=env,cwd=ROOT,capture_output=True,text=True,timeout=20)
                assert certification.returncode == 0, certification.stdout+certification.stderr
                assert 'DIGITAL_TWIN_VERIFIED' in certification.stdout
                assert len(writes()) == count  # Certification itself never performs ungated writes.
                assert request(url+f'/api/vcenter/vm/{vm}','DELETE')[0] == 204
        offline = subprocess.run([sys.executable,'-m','vcf_enterprise_mcp.cli','certify','--target','digital_twin'],env=env,cwd=ROOT,capture_output=True,text=True,timeout=20)
        assert offline.returncode == 1 and 'DIGITAL_TWIN_VERIFIED' not in offline.stdout
    finally:
        jwks.shutdown(); jwks.server_close(); thread.join()
