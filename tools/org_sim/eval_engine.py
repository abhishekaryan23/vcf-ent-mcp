# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Deterministic check of vcf_diagnose against every Acme scenario (no model involved).

    python tools/org_sim/eval_engine.py <work-dir> [acme|enterprise]

For each scenario: start the simulator, call the real MCP server's vcf_diagnose, and check
that the top-ranked finding names the injected fault (and that the healthy baseline raises
no CRITICAL/HIGH finding).
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from run_scenario import stop  # noqa: E402


def start(state: Path, scenario: str, model: str = "acme") -> None:
    # A fresh process per scenario: the secret registry is a process-wide singleton bound to one store.
    subprocess.run([sys.executable, str(HERE / "run_scenario.py"), "start", str(state), scenario, "--model", model], check=True,
                   stdout=subprocess.DEVNULL)

# scenario -> (symptom users report, list of keyword groups; each group must match the top finding)
EXPECT = {
    "healthy": ("users say things feel slow in dev", None),
    "vpxd_stopped": ("users cannot open vCenter for the prod domain", [["vpxd"], ["vc-prod"]]),
    "nsx_cert_expired": ("NSX Manager UI for prod/dev is not loading", [["certificate"], ["nsx-wld"]]),
    "nsx_node_down": ("NSX changes are slow and sometimes fail", [["nsx"], ["degraded", "offline"]]),
    "hosts_not_responding": ("some prod VMs show as disconnected", [["not responding"], ["esx09", "esx10"]]),
    "depot_unreachable": ("the VCF upgrade is stuck downloading", [["depot"]]),
    "service_account_expired": ("SDDC Manager says it cannot talk to the prod vCenter", [["password", "service-account", "credential"]]),
    "vcenter_disk_full": ("dev vCenter is down", [["disk", "space"], ["vc-dev"]]),
    "ops_collector_down": ("VCF Operations dashboards stopped updating", [["collector"]]),
    "datastore_full": ("VM deployments in prod are failing", [["datastore"], ["vsan-prod-cl01"]]),
    "ntp_missing_red_herring": ("users get logged out of the management vCenter randomly", [["time", "ntp"], ["vc-mgmt"]]),
    "multi_cert_and_nsx_node": ("prod vCenter API calls fail and NSX is acting up", [["certificate"], ["vc-prod"]]),
}

# Northwind enterprise: app-level symptoms; the root cause is in NSX, vCenter workloads or outside VCF.
EXPECT_ENTERPRISE = {
    "healthy_noisy": ("the intranet feels slow", None),
    "dfw_blocks_crm_sql": ("CRM web app shows database connection errors", [["temp-block-sql-scan"], ["1433"]]),
    "bgp_down_fin": ("branch offices cannot reach the Payments portal, but the servers can talk to each other", [["bgp"], ["t0-fin"], ["cisco", "fw-fin"]]),
    "fci_colocated_host_down": ("the Ledger application cannot connect to its SQL cluster", [["fci-ledger"], ["esx03-fin"]]),
    "shared_nsx_cert_expired": ("NSX UI fails for corp and the dev team says VPC changes fail", [["certificate"], ["nsx-wld01"]]),
    "vpc_ip_exhausted": ("eCommerce scale-out deployments from the catalog keep failing", [["ecom-private-app"], ["ip"]]),
    "ad_fin_down": ("finance users cannot log in to any finance app, AD authentication errors", [["fin.nwg.local"], ["domain controller"]]),
    "eu_web_quarantined": ("the EU retail website is down", [["quarantine"], ["retailshop"]]),
    "scm_oracle_reject_plus_noise": ("SupplyChain app shows Oracle errors since this morning", [["block-legacy-oracle-clients"], ["1521"]]),
    "proxy_t1_detached": ("corporate users lost internet access through the proxy", [["t1-corp-dmz"], ["tier-0"]]),
}


def matches(finding: dict, groups) -> bool:
    text = json.dumps(finding).lower()
    return all(any(k in text for k in g) for g in groups)


def main(work: Path, model: str = "acme") -> int:
    results = []
    for scenario, (symptom, groups) in (EXPECT_ENTERPRISE if model == "enterprise" else EXPECT).items():
        state = work / scenario
        if state.exists():
            subprocess.run(["rm", "-rf", str(state)])
        start(state, scenario, model)
        try:
            t0 = time.time()
            out = subprocess.run([str(state / "vcf"), "call", "vcf_diagnose", json.dumps({"symptom": symptom})],
                                 capture_output=True, text=True, timeout=300).stdout
            secs = time.time() - t0
            r = json.loads(out)
            findings = r.get("findings", [])
            if groups is None:
                serious = [f for f in findings if f["severity"] in ("CRITICAL", "HIGH")]
                ok, top = not serious, (serious[0]["title"] if serious else "no serious findings")
            else:
                ok, top = bool(findings) and matches(findings[0], groups), findings[0]["title"] if findings else "none"
            extra = ""
            if scenario == "multi_cert_and_nsx_node":
                ok = ok and any(matches(f, [["nsx"], ["degraded", "offline"]]) for f in findings[:3])
                extra = " + NSX degraded in top 3" if ok else " (second fault missing from top 3)"
            results.append({"scenario": scenario, "pass": ok, "top": top + extra, "seconds": round(secs, 1)})
            print(f"{'PASS' if ok else 'FAIL'}  {scenario:26} {secs:4.1f}s  top: {top}{extra}")
        finally:
            stop(state)
            time.sleep(0.5)
    (work / f"engine_results_{model}.json").write_text(json.dumps(results, indent=2))
    passed = sum(r["pass"] for r in results)
    print(f"\n{passed}/{len(results)} scenarios diagnosed correctly")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1]).resolve(), sys.argv[2] if len(sys.argv) > 2 else "acme"))
