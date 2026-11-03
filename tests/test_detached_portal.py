# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""The credential page must outlive the stdio server (MCP clients such as LM Studio restart it between turns)."""

import os
import re
import urllib.error
import urllib.parse
import urllib.request

import pytest

from vcf_enterprise_mcp.setup.credential_portal import DetachedPortal


@pytest.fixture
def portal(tmp_path, monkeypatch):
    for name, value in {"VCF_MCP_CREDENTIALS_PATH": tmp_path / "creds.json", "VCF_MCP_MASTER_KEY_PATH": tmp_path / "master.key"}.items():
        monkeypatch.setenv(name, str(value))
    monkeypatch.setenv("PYTHONPATH", os.pathsep.join(filter(None, [str(os.path.abspath("src")), os.environ.get("PYTHONPATH", "")])))
    p = DetachedPortal(tmp_path / "portal")
    yield p
    try:
        os.kill(int((tmp_path / "portal" / "service.pid").read_text()), 15)
    except (OSError, ValueError):
        pass


def test_page_is_served_by_a_separate_process_and_saves_once(portal, tmp_path):
    t = portal.issue(principal_id="u1", component="vcenter", component_title="vCenter", endpoint_host="vc.lab", username="svc",
                     reference="local://env-prod/test-vc", tenant_id="tenant-default", environment_id="env-prod")
    url = portal.url_for(t)
    assert int((tmp_path / "portal" / "service.pid").read_text()) != os.getpid()
    html = urllib.request.urlopen(url, timeout=10).read().decode()
    assert t.verification_code in html
    csrf = re.search(r"name=csrf value='([^']+)'", html).group(1)
    origin = f"http://127.0.0.1:{urllib.parse.urlsplit(url).port}"
    data = urllib.parse.urlencode({"csrf": csrf, "secret": "lab-pass"}).encode()
    assert urllib.request.urlopen(urllib.request.Request(url, data=data, method="POST", headers={"Origin": origin}), timeout=10).status == 200
    assert portal.get(t.ticket_id, "u1").status == "STORED"
    assert portal.get(t.ticket_id, "someone-else") is None
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(url, timeout=10)
    assert exc.value.code == 410
    assert "lab-pass" not in "".join(p.read_text() for p in (tmp_path / "portal" / "tickets").glob("*.json"))


def test_spool_is_owner_only(portal, tmp_path):
    portal.issue(principal_id="u1", component="nsx", component_title="NSX", endpoint_host="nsx.lab", username="svc",
                 reference="local://env-prod/test-nsx", tenant_id="tenant-default", environment_id="env-prod")
    assert oct(os.stat(tmp_path / "portal").st_mode & 0o777) == "0o700"
    for f in (tmp_path / "portal" / "tickets").glob("*.json"):
        assert oct(os.stat(f).st_mode & 0o777) == "0o600"
