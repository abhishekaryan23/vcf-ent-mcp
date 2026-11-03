# "Why is this service down?" and VCF Automation: what the MCP does, and how it was tested

> Unofficial project, under testing. Everything below was tested against **simulators**, not a real VCF estate.

## 1. The question

On-call teams on VCF 9.0.x / 9.1.x need to answer "why is X down?" fast, where X is often an
*application* (CRM, Payments, a SQL cluster), not a VCF appliance. They also want to know whether the
MCP can build automation in VCF Automation (Assembler cloud templates, Orchestrator workflows).

## 2. Delta: before vs. now

| Capability | Before this work | Now |
| --- | --- | --- |
| Appliance health (SDDC Manager, every vCenter, every NSX cluster, VCF Operations) | Partly: single vCenter, fabricated defaults in some tools | `vcf_diagnose`: discovers every vCenter and NSX cluster from SDDC Manager; services, appliance health, certificates, hosts, datastores, failed tasks, service accounts, NTP, alerts; ranked findings with evidence and next steps |
| Multi-vCenter inventory | Only the configured vCenter | VMs, hosts, clusters and datastores across all vCenters; unreachable vCenters reported, not hidden |
| Application view ("CRM is down") | None | `vcf_trace_application`: VMs (host, power, NICs, tags), how each network is built (VDS port group, NSX overlay or VLAN segment, VPC subnet), the path out (Tier-1 to Tier-0 to BGP peers), firewall rules touching the app, and ranked problems |
| North-south routing (BGP to Cisco switches/firewalls) | None | Tier-0 BGP neighbor status, with peer descriptions; "all sessions down" is a CRITICAL north-south outage pointing at the physical side |
| Distributed firewall changes | None | DROP/REJECT rules changed in the last 24 h, with who, when, services and destination VMs |
| Tier-1 uplinks | None | Tier-1 gateways that carry segments but lost their Tier-0 link |
| NSX VPCs (9.x) | None | VPC subnet IP-pool exhaustion, linked to failed VCF Automation deployments |
| Windows/AD and clustered workloads | None | Domain controllers per AD forest (powered off, NIC disconnected); SQL FCI / Always On / Oracle Fail Safe nodes sharing one ESXi host, and the failure of that host |
| Port-group mistakes | None | VMs moved to quarantine/isolated port groups, grouped by application |
| Network inventory | Segments/gateways only | `vcf_list_networks`: shared vs. dedicated NSX Managers, vCenter versions, every network by type with path, BGP state and VPC IP usage |
| VCF Automation | None | `vcf_automation_list/get/validate_template/create_template` (VM Apps organization APIs) and the `vcf_orch_*` tools for Orchestrator workflows, actions and runs; writes go through dry run, human approval, then execution |
| Fabricated data | Default IDs such as `cluster-prod-a`, `vm-101`, `mgmt-domain` | Removed in real-VCF mode: missing arguments return the valid choices instead |

### Still missing (honest list)

- **Orchestrator authoring:** now built (actions, workflows, runs, integrations, configuration, environments, plug-ins); see [plan_orchestrator_9_1.md](plan_orchestrator_9_1.md) sections 8 and 9.
- **Releasing or deploying cloud templates.** Templates are saved as DRAFT. Release, catalog publishing and
  `blueprint-requests` (deploy) are not exposed. Deploying VMs would be HIGH_IMPACT and needs a design decision.
- **Guest-level checks** (SQL Server AG health, Windows cluster state, Oracle listener). The MCP sees VM
  state and placement, not inside the guest.
- **VLAN IDs of VDS port groups.** The vSphere Automation REST API does not return them, so the MCP reports
  "VLAN-backed port group" without the VLAN number.
- **NSX Traceflow.** It is a write-like operation (it injects a packet). It is suggested as a next step, not run.
- **DRS rules.** Anti-affinity is inferred from VM placement; rule definitions are not read.
- **Real-environment validation.** All endpoints and payloads follow the official 9.x API specifications,
  but the tests ran against simulators.

## 3. The simulated enterprise (tools/org_sim)

Two organizations, served over real HTTPS with per-appliance certificates from a throwaway CA.

**Acme Corp** (`--model acme`): 3 domains, 12 appliance-level fault scenarios (vpxd down, certificates,
NSX node, hosts, depot, service account, disk full, Ops collector, datastore, NTP red herring, multi-fault).

**Northwind Group** (`--model enterprise`): a deliberately messy estate.

| Domain | vCenter | NSX Manager | Networking |
| --- | --- | --- | --- |
| mgmt | vc-mgmt01 9.1.1 | nsx-mgmt01 9.1.1, dedicated | VDS VLAN port groups |
| wld-corp | vc-corp01 9.1.1 | nsx-wld01 9.1.1, **shared** with wld-dev | NSX overlay segments behind Tier-1 to Tier-0 `t0-shared` (BGP to two Cisco Nexus 9336C core switches), an NSX VLAN segment (VLAN 120, legacy Oracle), VPC `vpc-ecom` with centralized connectivity via a transit gateway |
| wld-dev | vc-dev01 9.1.1 | nsx-wld01, **shared** | VPCs with distributed connectivity (no edge) |
| wld-fin | vc-fin01 **9.0.2** | nsx-fin01 9.0.2, dedicated | NSX overlay, zero-trust DFW (default DROP), Tier-0 `t0-fin` with BGP to a Cisco Secure Firewall 4125 (FTD) HA pair |
| wld-eu | vc-eu01 **8.0.3**, imported | nsx-eu01 4.2.1, dedicated | VDS VLAN port groups only; NSX distributed security (DFW on VDS); gateway on a Cisco ASA |

There are three Active Directory forests: `corp.nwg.lab`, `fin.nwg.local` and `eu.nwg-retail.net`. They are
identity boundaries and are separate from the VCF workload domains.

Workloads, all tagged in vSphere with Application, Tier, Role, AD-Forest and Cluster:
- **SQL Server:** standalone servers, an FCI (`FCI-LEDGER`, shared clustered VMDKs plus a heartbeat segment) and Always On AGs (`AG-CRM`, `AG-PAYMENTS`).
- **Oracle:** standalone servers and an Oracle Fail Safe cluster (`ORAFS-TREASURY`).
- **Windows IIS and RHEL** nginx/Apache/Tomcat/Java app and web tiers, Squid proxies and domain controllers.

VCF Automation (organization `northwind`):
- **Assembler:** 4 projects, image/flavor mappings, tagged networks, templates and deployments.
- **Orchestrator:** 4 workflows: expand disk, AD computer object, SQL AG failover and NSX tag.
- **Built-in failure:** the AD plug-in has no connection for the EU forest.

Northwind fault scenarios:

| Scenario | What the user reports | Root cause in the simulator |
| --- | --- | --- |
| healthy_noisy | "intranet feels slow" | none (only alert noise, a resolved failed task, a medium NSX alarm) |
| dfw_blocks_crm_sql | CRM database errors | new DFW rule DROP MS-SQL 1433 to the AG replicas, 35 min ago |
| bgp_down_fin | branches cannot reach Payments | both BGP sessions from `t0-fin` to the Cisco FTD pair are down |
| fci_colocated_host_down | Ledger cannot reach SQL | both FCI nodes were on one ESXi host, which stopped responding |
| shared_nsx_cert_expired | NSX UI and VPC changes fail | shared NSX Manager certificate expired (two domains affected) |
| vpc_ip_exhausted | eCommerce scale-out fails | VPC private subnet IP pool full; Automation deployments fail |
| ad_fin_down | finance logins fail | one finance DC powered off, the other's NIC disconnected |
| eu_web_quarantined | EU website down | EU web VMs moved to the quarantine port group |
| scm_oracle_reject_plus_noise | SupplyChain Oracle errors | DFW REJECT on Oracle 1521, plus unrelated noise |
| proxy_t1_detached | no internet via proxy | proxy Tier-1 disconnected from its Tier-0 |

## 4. Results

### Deterministic (no model): `vcf_diagnose`, top finding must name the fault
- Acme: **12/12**
- Northwind: **10/10** (each run takes 2 to 5 s against the simulator)

### Sonnet agents, cold start, MCP only
Each case was a separate Claude Sonnet agent with only the ticket text and the `vcf` CLI (no file access,
no hints about the scenario; case names were shuffled and opaque).

| Case | Ticket | Sonnet's answer | Correct | MCP calls | Errors |
| --- | --- | --- | --- | --- | --- |
| 1 | SupplyChain Oracle errors (with noise) | DFW REJECT `block-legacy-oracle-clients` (Oracle 1521), by j.patel 3 h ago; noise ruled out | yes | 3 | 0 |
| 2 | Ledger cannot reach SQL | both FCI-LEDGER nodes on esx03-fin, which is NOT_RESPONDING; no anti-affinity | yes | 1 | 0 |
| 3 | CRM database errors | DFW DROP `temp-block-sql-scan` (1433) above the ALLOW rules, by m.lee 37 min ago | yes | 2 | 0 |
| 4 | NSX UI / dev VPC changes fail | expired certificate on the shared nsx-wld01; both wld-corp and wld-dev affected | yes | 1 | 0 |
| 5 | EU website down | 3 RetailShop web VMs on `pg-eu-quarantine`; app/DB tiers healthy | yes | 2 | 0 |
| 6 | Intranet slow (no fault) | no infrastructure fault; guest-disk alert on corp-intra-web02 as a lead, low confidence | yes | 3 | 0 |
| 7 | No internet via proxy | Tier-1 `t1-corp-dmz` detached from Tier-0, by a contractor 51 min ago | yes | 1 | 0 |
| 8 | Finance logins fail | fin-dc01 powered off, fin-dc02 NIC disconnected: no DC for fin.nwg.local | yes | 1 | 0 |
| 9 | Branches cannot reach Payments | both BGP sessions from t0-fin to the Cisco FTD pair in ACTIVE; firewall team to check | yes | 1 | 0 |
| 10 | eCommerce scale-out fails | VPC subnet ecom-private-app 61/61 IPs; 3 failed Automation deployments | yes | 2 | 0 |
| 11 | Create SQL AG 3-node template (Finance) | template saved: win2022-sql2022, sql-large, count 3, `net:fin-db`, agName input; dry run, approval, create | yes | 11 | 0 |
| 12 | Add 50 GB to fin-ora01 disk 2 | ran "Expand VM disk" after approval; 500 GB to 550 GB, re-read to confirm | yes | 7 | 0 |
| 13 | EU AD account + EU web template | AD workflow failed (no AD plug-in connection for the EU forest), reported honestly with no workaround; template saved (rhel9-base, count 2 to 4, `net:eu-web`) | yes | 14 | 0 |

**13/13 correct, 49 MCP calls, 0 tool errors.** Results were checked against the simulator's own state
(templates, executions, disk sizes), not only the agents' reports. Troubleshooting needed 1 to 3 calls per
incident; the automation tasks took 7 to 14, including the human approval step.

One review note: in case 11 the AG name is a plain machine property (`agName: ${input.agName}`). That is
valid in Assembler, but a real SQL build would hand it to a configuration step (cloud-init, an ABX action or
an Orchestrator subscription), and the MCP does not author those.

## 5. Reproduce

Run these from a clone of the repository, with the project's virtual environment (`pip install '.[test]'`), using any scratch directory for the state folders (`/tmp/...` below). The simulator listens on fixed local ports (9501 and up for `acme`, 9601 and up for `enterprise`); give a second simulator another range with `--offset`, and stop each one when you are done.

```bash
.venv/bin/python tools/org_sim/eval_engine.py /tmp/nw enterprise     # deterministic, all Northwind scenarios
.venv/bin/python tools/org_sim/run_scenario.py start /tmp/c1 bgp_down_fin --model enterprise
/tmp/c1/vcf call vcf_trace_application '{"application": "Payments"}'
.venv/bin/python tools/org_sim/run_scenario.py start /tmp/a1 healthy_noisy --model enterprise --persona automation --offset 100
/tmp/a1/vcf call vcf_orch_list '{"kind": "workflows"}'
.venv/bin/python tools/org_sim/run_scenario.py stop /tmp/c1
.venv/bin/python tools/org_sim/run_scenario.py stop /tmp/a1
```

These runs keep all their state in the given folder (they never touch `~/.vcf-mcp`) and write a lab-only config that trusts lab tokens (`idp.allow_lab_tokens: true`).

## 6. A persistent lab for your own client (LM Studio, Claude Desktop, ...)

```bash
.venv/bin/python tools/org_sim/lab.py start dfw_blocks_crm_sql   # starts the oncall and automation personas
.venv/bin/python tools/org_sim/lab.py switch bgp_down_fin        # change the fault; client config stays valid
.venv/bin/python tools/org_sim/lab.py approve automation <plan_id> [--as security-officer@acme.lab]
.venv/bin/python tools/org_sim/lab.py status
.venv/bin/python tools/org_sim/lab.py stop
```

Each persona has a stdio launcher at `~/.vcf-mcp-lab/<persona>/mcp-server.sh` (a separate folder from `~/.vcf-mcp`; set `VCF_MCP_LAB_HOME` to move it). Point an MCP client at it, for example in LM Studio's `~/.lmstudio/mcp.json`:

```json
{"mcpServers": {"vcf-northwind-oncall": {"command": "/Users/<you>/.vcf-mcp-lab/oncall/mcp-server.sh", "args": []}}}
```


## 7. Orchestrator: verified on a real 9.1.1 server (community project)

Orchestrator authoring follows request shapes a community MCP (vcf-orchestrator-mcp, MIT) proved on a real VCF Automation 9.1.1 server; the
credit and licence are in `THIRD_PARTY_NOTICES.md` and the full list of changes is in
[plan_orchestrator_9_1.md](plan_orchestrator_9_1.md) section 9. In short:

- Workflow content is sent as XML `schema-workflow` (JSON only as a fallback after HTTP 415); inputs can have defaults, variables values.
- Scripts must be plain ES5. Orchestrator runs Rhino, so `let`/`const`, arrow functions, template literals, `for...of` and generators fail with a syntax error even when
  they look valid. `vcf.orchestrator_script_level: rhino_1_7_15` allows them on a server where you tested them.
- Runs and action runs use typed values (strings, numbers, Properties, arrays, plug-in objects by id, SecureString by credential reference);
  failed runs include their logs; `vcf_orch_list_executions` shows the history.
- List calls page with `maxResult`/`startIndex` and report `more`; `queryCount` is never sent (9.1 answers HTTP 400).
- `vcf_orch_export_package` never exports SecureString values; `vcf_orch_try_script` runs a snippet in a temporary scratch action;
  `vcf_orch_tracked_changes` / `vcf_orch_build_package` package what the MCP saved.
