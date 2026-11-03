# Broadcom alignment review: VCF Enterprise MCP

Date: 2026-10-10. Scope: `src/vcf_enterprise_mcp` real-VCF path (providers, auth, platform, workflows, registry), compared with Broadcom's published VCF 9.x API specifications and documentation. No live VCF environment was contacted.

## Verdict

The control-plane design is strong: identity-aware tool pruning, signed single-use approvals, durable idempotency, SSRF pinning and secret redaction. The real-VCF integration underneath it was not trustworthy before this change. That had less to do with missing features than with the code inventing answers when it could not get real ones:

- **Health** reported `GREEN / 98.5 / all HEALTHY` defaults whenever the upstream response lacked those fields. The endpoint it called (`GET /v1/system/health`) does not exist in any 9.x spec, so a real deployment would always have reported healthy.
- **Domain upgrade** and **DR drill** never called VCF in live mode. They created local tasks that reported `RUNNING`, and `resume_in_flight_workflows` advanced them by 25% per pass to `COMPLETED`. An agent would have told an operator an upgrade had finished when nothing had run.
- **Approval plans** shown to humans contained constants (`"prechecks": "PASSED (14/14 checks verified)"`, 64 affected VMs, cluster free capacity from fixed numbers).
- **Power** returned the requested state as the new state without reading it back.
- **Production startup** built the platform with loopback default endpoints and no upstream credentials. The SSRF guard's built-in fake DNS table would have pinned `sddc-manager.corp.internal` to `10.0.0.100`.

All of these are fixed here. Live qualification is still **not** established: every contract below is verified against Broadcom's published specs, not against a running appliance.

## Method and evidence

- **Specs:** official OpenAPI from [github.com/vmware/vcf-api-specs](https://github.com/vmware/vcf-api-specs) (linked from the [Broadcom VCF API specification portal](https://developer.broadcom.com/sdks/vcf-api-specification/latest)). Tags 9.0.0.0, 9.1.0.0 and 9.1.1.0 were used (28,304 operations in the original extraction; the extract is not redistributed here). No 9.0.1/9.0.2 archives exist there. NSX specs appear only from 9.1.0.0.
- **Docs:** Broadcom developer portal, TechDocs, KB and VMware blogs (sources at the end).
- **Regression guard:** `tests/test_broadcom_contract_alignment.py` (set `VCF_API_SPECS_DIR` to your clone of the specs repository; it skips without it) scans every upstream call in the real providers, the session logins and every `spec_verified` registry contract, and fails if any method+path is not an official operation.

## Endpoint truth table (real providers)

| Operation | Before | After | Official operation |
| --- | --- | --- | --- |
| VM power | `POST …/power?action=` (string-built), new state assumed | `POST /api/vcenter/vm/{vm}/power` with `action` param; state read back via `GET …/power` | `Vcenter.Vm.Power_start/stop/reset/suspend`, `Power_get` |
| VM resize | PATCH cpu/memory with no prechecks | Reads power state and hot-add flags first; refuses grow-while-running without hot-add, memory shrink while running, CPU shrink without hot-remove, and steps outside the hot-add increment/limit | `Hardware.Cpu_get/update`, `Hardware.Memory_get/update`; 9.x field `size_mib` (8.0.3 used `size_MiB`) |
| VM snapshot | `POST /api/vcenter/vm/{id}/snapshots` (**does not exist**) | VI/JSON `POST /sdk/vim25/{release}/VirtualMachine/{moId}/CreateSnapshot_Task`, returns the vCenter task moref | `VirtualMachine_CreateSnapshot_Task` (required: name, memory, quiesce) |
| Domain upgrade | `POST /v1/upgrades {domainId,targetVersion}`: schema-invalid; invented task id on failure | `UpgradeSpec {bundleId, resourceType: DOMAIN, resourceUpgradeSpecs}`; refuses without bundle; returns the real `Task.id` | `performUpgrade`; bundles from `getUpgradablesByDomain` |
| Upgrade progress | +25% timer | `GET /v1/tasks/{id}` with status normalization (`In Progress` → `IN_PROGRESS`) | `getTask` |
| Health | `GET /v1/system/health` (**does not exist**) + GREEN defaults | SDDC Manager domain status + active VCF Operations alerts. `UNKNOWN` if Operations is unreachable; `RED` on an active CRITICAL alert | `getDomains`, `getAlerts` |
| NSX segment | `PUT` (create-**or-replace**), raw CIDR as gateway, invented id | Existence check, refuses to replace, validates gateway-IP/prefix, `PATCH`; real id/path; realized-state reader | `ReadInfraSegment`, `PatchInfraSegment`, `ReadIntentStatus` |
| Telemetry | Passed vCenter IDs to Operations | Resolves to an Operations resource UUID (`GET /suite-api/api/resources?name=`), normalizes `stat-list` | `getResources`, `getStatsOfResource` |
| Component versions | Hard-coded (NSX `4.2.1`, wrong for VCF 9, where NSX is 9.x) | Read from each appliance; unreachable reports `None` | `getSddcManagers`, `Appliance.System.Version_get`, `NodeReadNodeVersion`, `getCurrentVersionOfServer` |

Registry corrections (`adapter/api_registry.py`): `/v1/domains/{id}/upgrades` → `/v1/upgrades`; `/v1/upgrades/prechecks` → `/v1/upgrades/{id}/prechecks`; `/v1/hosts/commissions` → `POST /v1/hosts`; guest snapshot path → VI/JSON; `domains/default/` → `domains/{domain_id}/`; `/suite-api/api/resources/health` → `/suite-api/api/resources`; the invented `/suite-api/api/telemetry/promql` → Realtime Metrics `GET /api/v1/query` (9.1+); `/suite-api/api/fleet/iam/roles` → `/suite-api/api/fleet-management/iam/roles`. SRM entries are marked `spec_verified=False`, because Live Site Recovery APIs are not published in vcf-api-specs.

## Upstream authentication

Previously one optional `auth` object was shared by every appliance, nothing in the server created it, and `CredentialBroker.get_upstream_token` returned fabricated `jit-…` strings. Each appliance now gets its documented flow (`adapter/transport/vcf_sessions.py`):

| Component | Login | Header | Lifecycle |
| --- | --- | --- | --- |
| vCenter | `POST /api/session` (Basic) | `vmware-api-session-id` | cached; re-login on 401; `logout()` → `DELETE /api/session` |
| SDDC Manager | `POST /v1/tokens` | `Authorization: Bearer` | refresh via `PATCH /v1/tokens/access-token/refresh` (body: refresh-token id), falls back to login |
| VCF Operations | `POST /suite-api/api/auth/token/acquire` (+ optional `authSource`) | `Authorization: OpsToken` | expiry from `validity` (ms epoch) |
| NSX | HTTP Basic per request ([KB 423054](https://knowledge.broadcom.com/external/article/423054)) | `Authorization: Basic` | avoids JSESSIONID/XSRF expiry (NSX returns 403, not 401) |

The base provider retries **once** after a 401 (the request was rejected before processing, so this is safe even for writes). A 403 is never retried. Credentials are resolved from the secret registry at login time via `vcf.component_credential_refs` and are never stored on the client.

`server.environment: production` now calls `_build_real_vcf_platform`. It fails closed without all four endpoint URLs, uses an HTTPS-only, no-loopback SSRF guard with the configured `allowed_dns_suffixes`/`allowed_cidrs`, and disables the lab DNS table and fallback.

## Files changed

- New: `adapter/transport/vcf_sessions.py`, `tests/test_broadcom_contract_alignment.py`, `tests/test_vcf_session_auth.py`, this document.
- Providers: `vcenter.py`, `sddc.py`, `nsx.py`, `operations.py`, `base.py` (401 re-login); `transport/auth.py` (`invalidate`), `transport/errors.py` (`UpstreamPreconditionException`, -32029).
- `adapter/platform.py` (component auth, observed health and versions, bundle id), `workflows/engine.py` (observed upgrade plan, native task tracking, DR refusal in real mode), `tools/operational_tools.py` (no invented capacity in real mode), `router/catalog.py` (`bundle_id`), `api_registry.py`, `ssrf_guard.py`, `core/server.py`, `config/settings.py`, `config/enterprise_config.yaml`, `certification/runner.py` and the 9.1.1 profile.
- Tests whose mocks encoded the old incorrect contracts now emit official response shapes: `test_upstream_vcf_transport.py`, `test_tool_provider_wiring.py`, `test_vcf_certification_framework.py`.

Results: all tests pass. The intermittent approval-signature failures noted earlier (for example `test_high_risk_execution_gate`) are fixed. They came from the store recomputing a plan's `expires_at` milliseconds after it was signed; a deterministic regression test now covers it.

Unit-test and Digital Twin modes keep their simulated data, now labelled `"data_source": "SIMULATED"`.

## What a trusted VCF agent still needs

Ordered by risk. Items 1–4 come before any live connection.

1. **Lab-validate every contract** on a non-production VCF 9.0.x and 9.1.x instance:
   - Is `size_mib` accepted on 9.0.x vCenter?
   - Does VI/JSON accept the `/api/session` id, or does it need `SessionManager.Login`?
   - What is the correct `{release}` segment?
   - What base path serves Realtime Metrics?
   - What are the real token lifetimes?

   Keep snapshot, NSX and upgrade writes disabled until then.
2. **Least-privilege service accounts per component.** SDDC Manager VIEWER for read, OPERATOR for lifecycle; ADMIN is needed only for the credential APIs, so avoid it. Use a custom vCenter role with only the `VirtualMachine.Interact.*` and `VirtualMachine.Config.*` privileges each tool needs, an NSX auditor or a scoped network-admin role, and Operations read-only. Map these to the existing six-way permission intersection.
3. **Approve only observed plans in production.** Reject approval of any plan whose `data_source` is not `OBSERVED`. For upgrades, the dry run should create an SDDC Manager draft upgrade (`UpgradeSpec.draftMode`) and run `POST /v1/upgrades/{id}/prechecks`, then show the real precheck results. Replace the generic `DOMAIN_UPGRADE_STEPS` with the steps from SDDC Manager.
4. **Respect SDDC Manager concurrency.** SDDC Manager holds instance-level resource locks; a stuck credential task can block every other workflow ([KB 444986](https://knowledge.broadcom.com/external/article/444986)). Run one lifecycle write per VCF instance at a time, and surface lock errors rather than retrying.
5. **Follow the 9.1 lifecycle model.** VCF Operations is upgraded first. 9.1 retires the Fleet Management appliance in favour of the Fleet Lifecycle and SDDC Lifecycle services ([KB 440630](https://knowledge.broadcom.com/external/article/440630), [KB 390634](https://knowledge.broadcom.com/external/article/390634)). Add a `fleet-lcm` provider (`/fleet-lcm/v1/upgrade-plans` with `precheck`/`apply` actions) and select it by observed version, not by the requested target.
6. **Broaden read coverage before writes.** Read-only access is where an agent earns trust. Add SDDC Manager tasks, credential and certificate expiry (read-only), backup status, upgradables and releases; NSX DFW policies and realized state; vSAN health; Operations alerts with symptoms; vCenter datastores, networks and tasks.
7. **Wire the known-issues registry to real KB applicability.** The earlier audit found incorrect citations; see the September 2026 internal audit notes in [docs/audits](audits/README.md).
8. **Consider Broadcom's typed SDK.** The [unified VCF Python SDK](https://developer.broadcom.com/sdks/vcf-python-sdk/9.0) (`pip install vcf-sdk`, covering pyVmomi, vSphere Automation, vSAN and SDDC Manager) would replace hand-rolled request bodies with generated, version-matched bindings.
9. **Position against the native options.** VCF 9.1.1 adds an **AI Assistant for VCF** in VCF Operations (Tech Preview: conversational diagnostics, health correlation) ([blog](https://blogs.vmware.com/cloud-foundation/2026/09/03/new-ai-and-kubernetes-private-cloud-operations-capabilities-in-vmware-cloud-foundation-9-1-1/)). VCF Private AI Services can consume MCP servers through Agent Builder ([TechDocs](https://techdocs.broadcom.com/us/en/vmware-cis/private-ai/foundation-with-nvidia/9-0/private-ai-foundation-9-x/what-is-private-ai-services/adding-mcp-servers-for-real-time-data-access-and-specialized-ai-capabilities.html)). Broadcom does not ship a first-party VCF-management MCP server, so this project's governed, approval-gated MCP fills a real gap and could register as a governed MCP server in Private AI Services.
10. **Carry over open items from earlier audits:** PostgreSQL HA and fencing across real nodes, external KMS/HSM for approval keys, Vault/Azure/AWS providers that are still in-memory mocks, mTLS that is still a placeholder, load/soak testing and deployment packaging.
11. **Fix stale claims in the README.** Badges say "Tests 66/66" and "99.64% Top-1", and the README calls the project "production-grade". Under the repository's own audits the live decision is still NOT LIVE-TEST READY.

## Sources

- [VCF API specification portal](https://developer.broadcom.com/sdks/vcf-api-specification/latest) and [vmware/vcf-api-specs](https://github.com/vmware/vcf-api-specs)
- [vSphere Automation API 9.1.1: Vm Hardware Memory UpdateSpec](https://developer.broadcom.com/xapis/vsphere-automation-api/9.1.1/data-structures/Vcenter%20Vm%20Hardware%20Memory%20UpdateSpec/)
- [SDDC Manager API 9.0: Tokens](https://developer.broadcom.com/xapis/sddc-manager-api/9.0/tokens/)
- [VCF Operations API](https://developer.broadcom.com/xapis/vcf-operations-api/latest/) and [9.1.1 auth-token](https://developer.broadcom.com/xapis/vcf-operations-api/9.1.1/data-structures/auth-token/)
- [KB 423054: HTTP authentication using APIs on NSX](https://knowledge.broadcom.com/external/article/423054)
- [KB 444986: SDDC Manager resource lock acquisition error](https://knowledge.broadcom.com/external/article/444986)
- [KB 440630: VCF 9.1 upgrade sequence](https://knowledge.broadcom.com/external/article/440630/upgrade-sequence-and-related-issues-for.html), [KB 390634: VCF 9.0 update sequence](https://knowledge.broadcom.com/external/article/390634)
- [Unified VCF SDK 9.0 for Python and Java](https://blogs.vmware.com/cloud-foundation/2025/06/24/introducing-a-unified-vcf-sdk-9-0-for-python-and-java)
- [New AI capabilities in VCF 9.1.1](https://blogs.vmware.com/cloud-foundation/2026/09/03/new-ai-and-kubernetes-private-cloud-operations-capabilities-in-vmware-cloud-foundation-9-1-1/)
- [Private AI Services: MCP servers](https://techdocs.broadcom.com/us/en/vmware-cis/private-ai/foundation-with-nvidia/9-0/private-ai-foundation-9-x/what-is-private-ai-services/adding-mcp-servers-for-real-time-data-access-and-specialized-ai-capabilities.html)
