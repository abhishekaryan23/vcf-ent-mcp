# VCF Enterprise MCP (unofficial)

[![Status](https://img.shields.io/badge/status-under%20testing-orange.svg)](#project-status)
[![Unofficial](https://img.shields.io/badge/Broadcom%2FVMware-not%20affiliated-lightgrey.svg)](#disclaimer)
[![MCP Protocol](https://img.shields.io/badge/MCP-2026--07--28-purple.svg)](docs/mcp_spec.md)
[![VCF target](https://img.shields.io/badge/targets-VCF%209.0%20%7C%209.1%20(not%20certified)-blue.svg)](#project-status)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](#license)

**Author:** Abhishek Rai · **Contact:** abhishekaryan2@gmail.com

An MCP (Model Context Protocol) server that lets AI assistants work with VMware Cloud Foundation 9.x (SDDC Manager, vCenter, NSX and VCF Operations; experimental VCF Automation / Orchestrator) **without giving VCF credentials or raw infrastructure APIs to the language model**. It sits between your identity provider and VCF, filters tools per user, requires dry runs and signed approvals for changes, and audits every call.

**Works with MCP clients and harnesses** such as Claude Code, Claude Desktop, Cursor, VS Code (GitHub Copilot), Windsurf, LM Studio, OpenAI Codex CLI and Gemini CLI, which have ready-made configs, and any other client that runs local MCP servers: Zed, JetBrains IDEs, Visual Studio, Cline, Roo Code, Kilo Code, Continue, Kiro, Amazon Q Developer CLI, Goose, OpenCode, Warp, AnythingLLM, Jan, Msty, Cherry Studio, 5ire and LibreChat, plus agent frameworks such as the OpenAI Agents SDK and LangChain. Claude Code and LM Studio are tested end to end; see [supported clients](docs/harnesses.md#supported-clients) for what is tested and what is not.

## Quick start (about five minutes)

Install from a clone (Python 3.10 or newer), in a virtual environment:

```bash
git clone https://github.com/abhishekaryan23/vcf-ent-mcp.git && cd vcf-ent-mcp
python3 -m venv .venv && .venv/bin/pip install .
```

Use `'.[test]'` instead of `.` if you also want the bundled Digital Twin or the tests (they need `fastapi` and `uvicorn`). The Digital Twin lives in the clone (`tests/fixtures/digital_twin`), not in the installed package.

1. **Print the harness setup.** This also creates `~/.vcf-mcp/` and a starter config that names no appliance:

   ```bash
   .venv/bin/vcf-mcp client-config claude-code      # or: cursor, vscode, lmstudio, claude-desktop, windsurf, codex, gemini, generic
   ```

2. **Add the entry to your harness and reload it** as the snippet's notes say. That is all: for one person on their own computer there is **no token** to make. The starter config is in *personal* mode (`server.access_mode: personal`): the assistant acts as your local user (`you@your-machine`), and **you** confirm each change yourself, in a prompt in the chat, on a one-time local page, or in your own terminal. Details and the safety reasoning: [docs/authorization_model.md](docs/authorization_model.md#0-access-modes-personal-and-team).

   *Shared lab, production or an identity provider?* Use team mode: `vcf-mcp client-config <harness> --team` prints the token-based entry, and `vcf-mcp token mint --role MCP_ADMIN --user you@corp.example --raw` makes a lab token (valid 24 hours, `--ttl <seconds>` changes that; production uses your IdP's token).

3. **Ask your assistant to "set up VCF MCP".** With nothing configured the server starts in *setup mode* and offers only the setup tools. The assistant asks what you want to do, collects passwords on a private local page (never in chat), checks what each account can really do, and applies the result without a restart.

   *No lab?* Start the bundled Digital Twin first and answer "Local Digital Twin" when asked what to connect to (no passwords are needed):

   ```bash
   PYTHONPATH=tests/fixtures .venv/bin/python -m digital_twin.run --host 127.0.0.1 --port 8085
   ```

The one launch command used everywhere is `vcf-mcp server --mode stdio` (the snippet from step 1 contains its absolute path, which desktop apps need). In personal mode setup narrows the roles you act as to what you asked for; in team mode `MCP_ADMIN` is enough for setup and day-to-day use takes a narrower role token (for example `VCF_VIEWER`) or your identity provider's token. VCF Automation / Orchestrator is connected afterwards with a separate terminal command, `vcf-mcp setup automation` ([guided_setup.md, section 7](docs/guided_setup.md#7-connect-vcf-automation-and-orchestrator)). Details: [docs/guided_setup.md](docs/guided_setup.md), [docs/harnesses.md](docs/harnesses.md) and [docs/local_testing.md](docs/local_testing.md) (Digital Twin).

## Guided setup in your AI harness

After you add the server to your harness, setup runs in the conversation. The assistant asks what you want to do and collects passwords on a private local page, never in chat. It checks what each account can really do, warns about local-admin and over-permissive accounts, and lets you switch off destructive actions, enforced server-side. When a check fails it names the cause (certificate, DNS, firewall, this MCP's own allowlist, proxy) and the exact config key to change, and it keeps the password you already typed unless the appliance really rejected the login.

### Try it yourself in Claude Code

```bash
python tools/demo_live/try_setup_in_claude_code.py
```

It starts a simulated VCF 9 estate (12 HTTPS appliances with their own certificates), runs `vcf-mcp client-config` in a throwaway folder and opens Claude Code with only this MCP server loaded (your own Claude Code configuration is not changed). Ask it to "set up VCF MCP": the questions appear as Claude Code dialogs sent by the server, the passwords go into private pages in your browser, and the server checks what each account can do. The only lab-only step is a name-to-address map for the simulator's host names, the job DNS does in a real network.

## Project status

| Area | State |
| --- | --- |
| Digital Twin (simulated VCF) | Working end to end; this is the recommended way to try it. It is a test fixture shipped in `tests/fixtures/digital_twin` (see [docs/local_testing.md](docs/local_testing.md)) |
| Upstream API contracts | Checked against Broadcom's published [vcf-api-specs](https://github.com/vmware/vcf-api-specs) 9.0.0/9.1.0/9.1.1 by an automated test; **not validated on live appliances**. VCF Automation / Orchestrator paths are not in those specs and are unverified |
| Real VCF connections | Experimental. See the [Broadcom alignment review](docs/broadcom_alignment_review.md) for what still needs lab validation |
| Writes (power, resize, snapshot, NSX, upgrade) | Gated behind dry runs, signed approvals and the operator safety profile; keep them off outside a lab |
| Disaster recovery | Not implemented against real VCF |
| Troubleshooting (why is X down) | `vcf_diagnose`, `vcf_trace_application`, `vcf_list_networks`: appliance, NSX (BGP, DFW, Tier-1, VPC), VM, AD and clustered-DB checks; tested on two simulated organizations, see [troubleshooting_and_automation.md](docs/troubleshooting_and_automation.md) |
| VCF Automation / Orchestrator 9.1 | Assembler templates; Orchestrator actions, workflows (XML content), runs and executions, script tries, package export and build, integrations, configuration, environments, plug-ins (dry run, human approval, versioned). Scripts are ES5 by default. API shapes checked against the Orchestrator 9.0 OpenAPI document and against the practice of a [community MCP verified on 9.1.1](docs/orchestrator_comparison.md); simulator only. Connect with `vcf-mcp setup automation`. See [plan_orchestrator_9_1.md](docs/plan_orchestrator_9_1.md) |

### Known limitations

Tracked from the [independent review of 2026-11-02](docs/audits/independent_review_2026_11_02.md) and not fixed yet:

- **Multi-NSX inventory (F6):** `vcf_list_nsx_segments` / `vcf_list_nsx_gateways` read only the configured NSX Manager. `vcf_list_networks` and `vcf_diagnose` do fan out to every NSX Manager SDDC Manager knows.
- **Privilege probe on real vCenter (F12):** the setup check for vCenter write privileges uses an API that needs extra rights, so least-privilege accounts show `UNVERIFIED` rather than a confirmed result. The VI/JSON release path is also guessed.
- **Credential binding (F13):** secrets are stored per component, not per endpoint and username. Re-running setup with a different account can reuse the previous password until you delete it (`vcf-mcp credentials delete local://env-prod/vcf-mcp-<component>`, with `<component>` one of `vcenter`, `sddc-manager`, `nsx`, `vcf-operations`; `vcf-mcp credentials list` shows the references).
- **Federated accounts (F21):** NSX Basic auth and the SDDC Manager token call need local or LDAP accounts; accounts that exist only through VCF SSO / Identity Broker federation may not be able to log in through these API flows. Setup does not detect this yet.
- **Setup coverage (F4):** the conversational setup does not ask for the VCF Operations `authSource` (set `vcf.operations_auth_source` in `config.yaml`, see [Configuration](#configuration-reference)), and it offers a CIDR for a non-private management network only after the access check was blocked. Its network questions are CA bundle, proxy and allowlist entries. VCF Automation / Orchestrator credentials are no longer a gap, but they are collected by the separate terminal command `vcf-mcp setup automation`, not in the conversation.
- **Unverified against live VCF:** all appliance behaviour, including auth flows, was developed against simulators and the published specs.

---

## Table of Contents
1. [Quick start](#quick-start-about-five-minutes) · [Project status and known limitations](#project-status)
2. [Executive Summary](#executive-summary--core-value-proposition)
3. [High-Level Architecture](#high-level-architecture)
4. [Zero Credential Exposure & Trust Boundary](#zero-credential-exposure--trust-boundary)
5. [Enterprise Authorization Model](#enterprise-authorization-model) ([roles and risk classes](#16-capability-roles--6-risk-classes))
6. [3-Level Tool Hierarchy](#3-level-tool-hierarchy)
7. [Identity-Aware Routing Pipeline](#identity-aware-5-stage-routing-pipeline) · [Routing benchmark](#routing-benchmark)
8. [Dry runs, approvals and tasks](#dry-runs-approvals-and-tasks)
9. [VCF version adapter](#vcf-version-adapter)
10. [Audit trail](#immutable-audit-trail--observability)
11. [Client integration](#client-integration-guides)
12. [Storage profiles](#dual-storage-profiles--distributed-reliability) · [State correctness](#distributed-state-correctness--fencing-tokens)
13. [Capability providers and circuit breakers](#decoupled-capability-providers--circuit-breakers) · [Broadcom API contract registry](#broadcom-api-contract-registry)
14. [Supply chain and SBOM](#supply-chain-security--cyclonedx-sbom)
15. [Configuration](#configuration-reference) · [Testing](#testing--verification)
16. [License](#license) · [Disclaimer](#disclaimer)

---

## Executive Summary & Core Value Proposition

Enterprises running VMware Cloud Foundation 9.x want the agility and reasoning capabilities of modern LLMs to assist with day-2 operations: capacity triage, VM lifecycle, health diagnostics, firewall microsegmentation, and coordinated workload domain upgrades. However, traditional LLM integrations create catastrophic security risks:
- Giving the LLM direct administrative API keys or passwords.
- Allowing broad mutation scopes without simulation (`dry_run`).
- Bypassing corporate Identity Provider (IdP) directory policies.
- Hallucinating commands or parameters outside the operator's clearance.

The **VCF Enterprise MCP Control Plane** solves this through a strict zero-trust proxy:
* **LLM sits strictly outside the trust boundary**: The model interacts exclusively with normalized, high-level semantic tools. Secrets and passwords are held in an encrypted local store or your enterprise vault (HashiCorp Vault, Azure Key Vault, AWS Secrets Manager, CyberArk) behind a Credential Broker and redacted from model outputs (`[REDACTED]`).
* **Multi-Layer Permission Intersection**: Operators can only see and execute actions at the mathematical intersection of their Corporate IdP claims, Native VCF entitlements, Active Control Plane Mode, Resource Scope, and Risk Policy.
* **Pre-Discovery Tool Pruning**: `tools/list` dynamically filters advertised tools based on the caller's verified identity. A junior operator never sees destructive upgrade tools; a network admin never sees compute resize tools.
* **Deterministic Workflows & Dry-Run Guarantees**: Mutating actions support `dry_run: true`, calculating an exact blast-radius plan before requesting human approval tokens.

---

## High-Level Architecture

```mermaid
graph TD
    subgraph "External Trust Boundary (Untrusted / Scoped)"
        Client["Enterprise LLM Client / Developer UI<br/>(Claude Code, Claude Desktop, Cursor, VS Code,<br/>Windsurf, LM Studio, Codex, Gemini CLI, ...)"]
        IdP["Corporate IdP<br/>(Microsoft Entra ID / Okta / Ping)"]
    end

    subgraph "Enterprise VCF MCP Control Plane"
        Gateway["Stateless MCP Gateway (MCP 2026-07-28)<br/>stdio, or HTTP /mcp behind your TLS gateway"]
        IdPVal["Enterprise IdP Token Validator<br/>(JWT / Claims / Role Mapper)"]
        Router["Identity-Aware Semantic Router<br/>(5-Stage Pipeline & Hard-Negative Separator)"]
        PDP["Policy Decision Point (PDP)<br/>(Six-Way Intersection Formula)"]
        PEP["Policy Enforcement Point (PEP)<br/>(Pre-Discovery Pruner & Execution Guard)"]
        Broker["Credential Broker & Vault<br/>(JIT Ephemeral Tokens & Secret Redactor)"]
        Tasks["MCP Tasks Store & Engine<br/>(Async Workflow Tracker & Approval Tokens)"]
        Audit["Immutable Audit Engine<br/>(CEF Syslog / JSONL / OpenTelemetry)"]
    end

    subgraph "Upstream Enterprise VCF 9.x Infrastructure"
        SDDC["SDDC Manager 9.x<br/>(Domains, Clusters, LCM)"]
        VC["vCenter Server 9.x<br/>(Compute, VMs, Storage)"]
        NSX["NSX Manager 9.x<br/>(Segments, DFW, Routing)"]
        Ops["VCF Operations 9.x<br/>(Health, metrics, alerts)"]
        Auto["VCF Automation / Orchestrator<br/>(Workflows, Blueprints)"]
    end

    Client -->|1. Bearer Token + MCP Call| Gateway
    Gateway -->|2. Validate Claims| IdPVal
    IdPVal -.->|JWKS Key Verification| IdP
    Gateway -->|3. Route Query| Router
    Router -->|4. Authorize Request| PDP
    PDP -->|5. Enforce Policy| PEP
    PEP -->|6. Acquire JIT Credentials| Broker
    PEP -->|7. Execute Workflow / Dry-Run| Tasks
    PEP -->|8. Audit Log Event| Audit
    Tasks -->|9. JIT Upstream API Call| SDDC
    Tasks -->|9. JIT Upstream API Call| VC
    Tasks -->|9. JIT Upstream API Call| NSX
    Tasks -->|9. JIT Upstream API Call| Ops
    Tasks -->|9. JIT Upstream API Call| Auto
    Audit -->|10. RFC5424 CEF Stream| SIEM["Enterprise SIEM / Splunk / Datadog"]
```

---

## Zero Credential Exposure & Trust Boundary

```
[ LLM Client / Agent ]
         │ (Never sees passwords, API keys, or certificates)
         ▼
══════════════════════ TRUST BOUNDARY ══════════════════════
         │
[ VCF Enterprise MCP Control Plane ]
    ├── Secret store (local encrypted / HashiCorp Vault / Azure Key Vault / AWS Secrets Manager / CyberArk)
    ├── Credential Broker (resolves references at login time)
    └── Output Sanitizer (Regex + Key-based Redaction)
         │
         ▼ (HTTPS / service-account credentials)
[ Upstream VCF 9.x Infrastructure ]
```

1. **Model Isolation**: The LLM sends only user identity Bearer tokens (OIDC/JWT) and parameters.
2. **Server-side sessions**: Upstream credentials (SDDC Manager service accounts, vCenter sessions, NSX Basic auth, VCF Operations tokens) are resolved from the secret store by the `CredentialBroker` at login time and used only on the server side.
3. **Recursive Secret Scrubbing**: All responses, error messages, and task payloads are processed through the recursive redaction engine. Passwords, bearer tokens, and RSA/EC private keys (`-----BEGIN PRIVATE KEY-----`) are replaced with `[REDACTED]`.

---

## Enterprise Authorization Model

### Effective Permission Intersection Formula

Authorization is calculated dynamically using a multi-factor mathematical intersection:

$$\text{Effective Permission} = \text{Corporate IdP} \cap \text{Native VCF Entitlement} \cap \text{MCP Mode} \cap \text{Resource Scope} \cap \text{Risk Policy} \cap \text{Operational State}$$

| Dimension | Description | Example |
| :--- | :--- | :--- |
| **Corporate IdP** | Claims extracted from enterprise JWT (`preferred_username`, `groups`, `roles`). | `corp-cloud-admins`, `corp-app-operators` |
| **Native VCF Entitlement** | Permissions synchronized from SDDC Manager, vCenter Global Permissions, and VCF Operations. | `System.Read`, `VirtualMachine.Interact.PowerOff` |
| **MCP Mode** | Global operating safety level of the MCP control plane. | `DISCOVERY_ONLY`, `AUDITED_OPERATIONS`, `FULL_ENFORCEMENT` |
| **Resource Scope** | Allowed domains, clusters, datastores, tags, and sites. | `allowed_clusters: ["cluster-prod-a"]` |
| **Risk Policy** | Role-based maximum permitted risk ceiling. | `COMPUTE_OPERATOR` max risk = `CHANGE` |
| **Operational State** | Real-time infrastructure status (e.g., maintenance mode, blackout windows). | Upgrade blocked if active DR drill in progress |

### Two-Stage Authorization Lifecycle

1. **Pre-Discovery (`tools/list`)**:
   - The caller presents their identity.
   - The Policy Enforcement Point (PEP) runs pre-flight role checks against the catalog.
   - Tools exceeding the principal's role clearance or blocked by the active safety mode are **pruned from the advertised tool list**.
   - *Result*: Zero prompt bloat, zero hallucinated tool calls for forbidden capabilities.
2. **Pre-Execution (`tools/call`)**:
   - When a tool is invoked, the PEP evaluates the target resource against the principal's explicit `ResourceScope` (e.g., target cluster `cluster-prod-b` vs allowed `cluster-prod-a`).
   - For a write, the PEP validates the signed approval presented with the call (`plan_id`, `approval_id` and the single-use `nonce`, see [Dry runs, approvals and tasks](#dry-runs-approvals-and-tasks)).
   - If validation fails, execution is halted immediately with a typed error (for example `AuthorizationDeniedException` or `ApprovalRequiredException`).

### 16 Capability Roles & 6 Risk Classes

#### Risk Classes
* `READ`: Query-only operations; no infrastructure mutation.
* `SAFE_WRITE`: Modifications with a small blast radius (for example VM power actions and snapshot creation).
* `CHANGE`: Operational state modifications (for example VM resize, NSX segment creation, saving an Orchestrator workflow).
* `HIGH_IMPACT`: Workload-affecting operations (for example a workload-domain upgrade or snapshot deletion).
* `DESTRUCTIVE`: Irreversible actions; need two different approvers in team mode (personal mode: your confirmation plus the typed target).
* `SECURITY_SENSITIVE`: Credentials, SSO realms, certificates and Orchestrator integrations (`vcf_orch_add_integration`); need two different approvers in team mode (personal mode: your confirmation plus the typed target). Guided setup (`vcf_setup`) is *not* an approval-gated write: it needs the `MCP_ADMIN` or `VCF_PLATFORM_ADMIN` role and no dry run, plan or approval.

Every write needs a dry run first. The dry run returns a `plan_id` and a `how_to_approve` block that says who approves and how. In team mode that is the exact `vcf-mcp plans approve <plan_id>` command, which roles may approve and how many different approvers are needed, and the tool is then called again with `plan_id`, `approval_id` and `nonce`. In personal mode you approve yourself and the tool is called again with `plan_id` only. `vcf_get_plan` shows a plan's status at any time. See [docs/authorization_model.md](docs/authorization_model.md).

#### The 16 capability roles

These are the exact names accepted by `vcf-mcp token mint --role` and used in IdP `roles` claims.

| Role | Meaning |
| --- | --- |
| `VCF_VIEWER` | Read-only inventory, health and metrics |
| `VCF_AUDITOR` | Read plus compliance and configuration history |
| `COMPUTE_OPERATOR` | VM power, snapshots, safe resize |
| `COMPUTE_ADMIN` | Provision, delete and migrate VMs |
| `NETWORK_OPERATOR` | Read NSX, trace flows, inspect BGP |
| `NETWORK_ADMIN` | Tier-0/1 gateways, segments, firewall rules |
| `STORAGE_OPERATOR` | Capacity, policies, health alerts |
| `STORAGE_ADMIN` | vSAN lifecycle and data protection |
| `AUTOMATION_OPERATOR` | Cloud Assembly / Orchestrator workflows and templates |
| `DR_OPERATOR` | DR drill testing, replication sync (DR is not implemented against real VCF) |
| `DR_ADMIN` | Site recovery failover and reprotect (same caveat) |
| `LIFECYCLE_OPERATOR` | Upgrade pre-checks, bundle downloads |
| `LIFECYCLE_ADMIN` | Workload domain upgrades and host patching |
| `SECURITY_ADMIN` | Certificates, credentials, SSO realms |
| `VCF_PLATFORM_ADMIN` | Full management overlay; may run setup and approve plans |
| `MCP_ADMIN` | Runs guided setup; otherwise reads like `VCF_VIEWER`. It cannot change infrastructure |

---

---

## 3-Level Tool Hierarchy

Tools are strictly partitioned to eliminate ambiguity and prevent model confusion:

| Level | Type | Characteristics | Examples |
| :---: | :--- | :--- | :--- |
| **L1** | **Query & Telemetry** | Idempotent, read-only (`READ`), fast execution (<200ms), zero side effects. | `vcf_list_vms`, `vcf_get_vm`, `vcf_list_hosts`, `vcf_get_health`, `vcf_query_telemetry` |
| **L2** | **Targeted Operational** | Atomic mutations on single resources, supports `dry_run: true`, enforces explicit resource scoping. | `vcf_power_vm`, `vcf_resize_vm`, `vcf_create_snapshot`, `vcf_create_nsx_segment` |
| **L3** | **Deterministic Workflows** | Multi-phase orchestrations, generates asynchronous `MCPTask` handles, requires explicit pre-check dry runs and approved plans. | `vcf_upgrade_domain`, `vcf_recover_site` |

---

## Identity-Aware 5-Stage Routing Pipeline

When a natural language query or intent arrives, the router executes five discrete stages:

```
[ User Prompt / Query ]
         │
         ▼
[ Stage 1: Version Baseline Gate ] ──► (Filter tools invalid for target VCF version)
         │
         ▼
[ Stage 2: Identity & RBAC Filter ] ──► (Filter tools exceeding principal's capability role)
         │
         ▼
[ Stage 3: Resource Scope Evaluator ] ─► (Extract target entities and verify user boundary)
         │
         ▼
[ Stage 4: Domain Partitioning ] ────► (Isolate Compute vs Network vs Storage vs LCM)
         │
         ▼
[ Stage 5: Semantic Scorer & Hard-Negative Separator ]
         │
         ├── Score >= 0.70 ──► [ Matched Tool + Extracted Parameters ]
         └── Score < 0.70  ──► [ Safe ROUTE_UNCERTAIN Abstention ]
```

- **Hard-Negative Separator**: Imposes severe mathematical penalties on commonly confused operations (e.g., physical ESXi hosts vs virtual machines; NSX segments vs vCenter portgroups).
- **Safe Abstention**: Never executes a random tool on ambiguous queries; returns `ROUTE_UNCERTAIN` prompting the user for clarification.

---

## Dry runs, approvals and tasks

### Dry-run protocol
Every mutating tool accepts `dry_run: true`. A dry run:
1. calculates the proposed change and its impact without touching VCF;
2. records an immutable execution plan and returns its `plan_id`, `canonical_plan_hash` and, when approval is needed, `how_to_approve`;
3. changes nothing upstream.

```json
{
  "dry_run": true,
  "plan_id": "plan_...",
  "status": "PENDING_APPROVAL",
  "approval_required": true,
  "approvals_required": 1,
  "how_to_approve": {
    "command": "vcf-mcp plans approve plan_... --db /home/you/.vcf-mcp/control_plane.db",
    "approver_roles_any_of": ["VCF_PLATFORM_ADMIN", "SECURITY_ADMIN", "COMPUTE_ADMIN", "NETWORK_ADMIN", "LIFECYCLE_ADMIN"]
  }
}
```

### Who approves: personal and team mode

`server.access_mode` decides ([docs/authorization_model.md](docs/authorization_model.md#0-access-modes-personal-and-team) explains why personal mode is safe for one person and when to use team):

| | **personal** (the starter config) | **team** (everything else) |
| :--- | :--- | :--- |
| Who the assistant is | your local OS user (`user@host`, or `server.personal_user`); no token | the user in an IdP or lab token, required on every call |
| Who approves | **you**, the person who asked | a different administrator holding an approver role, with their own token |
| How many | one confirmation per plan | one; two different people for `DESTRUCTIVE` and `SECURITY_SENSITIVE` |
| Extra check | `DESTRUCTIVE` / `SECURITY_SENSITIVE` (and snapshot deletion): you type the target name, or the plan code if there is no single target | none |
| After approving | the assistant calls again with `plan_id` only | the approver's `approval_id` and `nonce` are pasted into the chat |

**Personal mode, three channels** (the model can answer none of them):

1. **Chat prompt.** If your client supports MCP elicitation, the call with `plan_id` pops up a form in the chat window with the tool, target, risk and plan summary and an Approve / Reject choice (plus the typed confirmation when required). Approve runs the change in that same call; reject, decline or cancel returns "NOT APPROVED". Clients that declare `elicitation` at `initialize` (Claude Code, LM Studio, the official Python SDK) are served over stdio; the HTTP transport stays 2026-07-28 multi-round-trip only.
2. **Local page.** Without elicitation, the dry run returns `how_to_approve.approval_url`: a page on `127.0.0.1` with a one-time unguessable link that expires with the plan, shows the plan, has Approve / Reject buttons and the confirmation field when required (Host, Origin and CSRF checked).
3. **Your terminal.** `vcf-mcp plans approve <plan_id>` needs no token but must run in an interactive terminal: you type the plan's 6-character code shown on screen (and the target name when required). From a script or an assistant's shell tool it refuses and points at the other two channels.

After the page or the terminal, the assistant calls the tool again with only `plan_id`: the server finds your recorded approval and uses it exactly once (passing `approval_id` and `nonce` still works). Every approval is written to the audit chain with approver, channel (`in_client`, `page`, `cli` or `token`), mode and plan hash.

**Team mode** is unchanged: a human administrator (not the initiator) runs `vcf-mcp plans approve <plan_id>` with **their own** access token (`--approver-token-file`, or `VCF_MCP_APPROVER_TOKEN`), then the printed `approval_id` and `nonce` go back to the assistant (the initiator can also read them with `vcf_get_plan` once the plan is approved). Destructive and security-sensitive plans need two different approvers.

### Asynchronous execution and tasks
Long-running workflows (for example `vcf_upgrade_domain`) return a task handle. Clients track it with `tasks/get`; `tasks/update` and `tasks/cancel` are limited to the task owner or an administrator. `tasks/list` is deliberately not offered, to prevent cross-user enumeration.

---

## VCF version adapter

The adapter picks API shapes per configured release (9.0.0 through 9.1.1) and per component (SDDC Manager, vCenter, NSX, VCF Operations). The feature table in `adapter/version_adapter.py` is the author's working assumption, **not** verified against Broadcom release notes. All SDDC Manager calls use the documented `/v1` API. Discovery of the VCF environment is done at runtime from SDDC Manager (`/v1/domains`, `/v1/vcenters`, `/v1/nsxt-clusters`); there is no separate onboarding wizard beyond guided setup, and the `adapter/discovery.py` module is a model used by tests, not a scanner.

Operating modes (`policy.operating_mode`): `DISCOVERY_ONLY` (default; reads only, changes are refused), `AUDITED_OPERATIONS` (changes allowed with plans and approvals) and `FULL_ENFORCEMENT` (additionally requires approval at the policy layer for `CHANGE`-class tools). `READ_ONLY` and `DISABLED` (an emergency stop) also exist. Setup never moves the policy out of `DISCOVERY_ONLY`; you change it yourself in the config file.

---

## Immutable Audit Trail & Observability

Every tool call is recorded in a hash-chained audit journal in the control-plane database (`vcf_verify_audit_chain` and `vcf-mcp ga-report` check it).
- **Captured attributes**: event id, timestamp, request id, actor (user, groups, client IP), tool, target, risk class, scrubbed parameters, authorization decision, execution status and duration.
- **Formats**: `AuditExporter` renders records as JSON lines or CEF-style syslog strings. It only formats: nothing streams to a SIEM or OpenTelemetry collector yet, and `audit.export_target` / `audit.file_path` in the config are not wired to an exporter.

---

## Client Integration Guides

For ready-to-paste configuration for Claude Code, Claude Desktop, Cursor, VS Code, Windsurf, LM Studio, Codex and Gemini CLI, run `vcf-mcp client-config <harness>`. Other clients use `vcf-mcp client-config generic`. [docs/harnesses.md](docs/harnesses.md#supported-clients) lists every client and how far it has been tested.

### Claude Code, Claude Desktop, Cursor, VS Code, Windsurf, LM Studio, Codex, Gemini CLI and others

Do not hand-write these entries: `vcf-mcp client-config <harness>` prints the exact, ready-to-paste entry with absolute paths (desktop apps start servers from `/` and do not inherit your PATH) and creates the starter config. Every harness uses the same launch command, `vcf-mcp server --mode stdio`.

For a remote harness that speaks Streamable HTTP, start the server with `vcf-mcp server --mode http` (plain HTTP on `server.host`:`server.port`, endpoint `/mcp`; the starter config sets `127.0.0.1:8443`, while a config without `server.host` listens on all interfaces, so set it; put an authenticated TLS gateway in front of it) and send the user's IdP token as `Authorization: Bearer ...` plus the `MCP-Protocol-Version`, `Mcp-Method` and (for tool calls) `Mcp-Name` headers; an MCP client library does that for you.

### Azure OpenAI / LangChain / Multi-Agent

Connect with the standard MCP Python client over Streamable HTTP (start the server with `vcf-mcp server --mode http` and terminate TLS in front of it; the URL below is such a gateway):

```python
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamablehttp_client

async with streamablehttp_client("https://vcf-mcp.example.internal:8443/mcp", headers={
    "Authorization": f"Bearer {operator_jwt_token}"
}) as (read, write, _):
    async with ClientSession(read, write) as session:
        await session.initialize()
        # Discover identity-pruned tools
        tools = await session.list_tools()
        # Execute scoped operational tool
        result = await session.call_tool("vcf_list_vms", arguments={"cluster_id": "cluster-prod-a"})
```

### Local LLMs (LM Studio / Ollama / Gemma 4-e4b)

The tools use compact JSON schemas with explicit types so small local models (4B-8B parameters, for example Gemma 4-e4b) can call them. A long tool list still hurts small models: set `server.default_skill: vcf-oncall-troubleshoot` (any name from `vcf-mcp skills list`) in the config to pre-prune `tools/list` to about 7 tools, or let the client request a skill.

Small and fast models can call `vcf_find_tool` with the request in plain words to get the right tool, example arguments and the matching skill; it also answers "how do I set this up?". A cold evaluation with Claude Haiku is in [plan_orchestrator_9_1.md](docs/plan_orchestrator_9_1.md) section 8.

---

## Dual Storage Profiles & Distributed Reliability

The Control Plane decouples state management through an abstract `DurableStore` interface supporting two production deployment profiles:

```
MODE A — Appliance MCP                MODE B — Enterprise HA
┌───────────────────────────┐         ┌───────────────────────────┐
│ MCP Control Plane Node    │         │ MCP Node 1  │ MCP Node 2  │
│ ┌───────────────────────┐ │         └───┬─────────────┬─────────┘
│ │ In-Process State Mgr  │ │             │             │ (Stateless)
│ └───────────┬───────────┘ │             ▼             ▼
│             ▼             │         ┌───────────────────────────┐
│ SQLite WAL Engine         │         │ PgBouncer Connection Pool │
│ (WAL / synchronous=NORMAL)│         └─────────────┬─────────────┘
└───────────────────────────┘                       ▼
                                      ┌───────────────────────────┐
                                      │ PostgreSQL HA Cluster     │
                                      │ (Patroni / AWS Aurora)    │
                                      └───────────────────────────┘
```

1. **MODE A — Appliance MCP (`SQLiteDurableStore`)**:
   - Single-node virtual appliance, edge deployment, or dev sandbox.
   - Leverages SQLite in Write-Ahead Log (`WAL`) mode with `synchronous=NORMAL` and thread-safe in-process mutexes.
   - Zero external infrastructure dependency; starts in sub-second time.
2. **MODE B — Enterprise HA (`PostgresDurableStore`)**:
   - Multi-node active-active cluster deployment.
   - Backed by PostgreSQL 15+ / Amazon Aurora with connection pooling (PgBouncer).
   - Atomic multi-row transactions with execution outbox guarantees across distributed worker instances.

---

## Distributed State Correctness & Fencing Tokens

To eliminate split-brain mutations during network partitions or process pauses:
* **Monotonic Fencing Tokens**: Every acquired resource lease issues an incrementally higher 64-bit `fencing_token`. Upstream adapters strictly reject requests presenting an outdated or expired token (`-32012 StaleFencingTokenException`).
* **Execution-Intent Outbox**: Multi-step operations persist execution intents to durable store before upstream dispatch (`PREPARE -> EXECUTE -> RECONCILE -> VERIFY`). If a node crashes mid-flight, a surviving node re-reads the outbox and completes idempotent reconciliation.
* **12 First-Class Workflow States**: `PLANNED`, `APPROVAL_PENDING`, `EXECUTING`, `VERIFYING`, `SUCCEEDED`, `FAILED`, `COMPENSATING`, `COMPENSATED`, `RECONCILIATION_REQUIRED`, `CANCEL_REQUESTED`, `CANCELLED`, `MANUAL_INTERVENTION_REQUIRED`.
* **Irreversible Saga Compensation Boundaries**: Steps flagged `irreversible: true` (e.g., physical firmware flashing or hypervisor decommissioning) trip a safety halt upon failure. The workflow enters `MANUAL_INTERVENTION_REQUIRED` to prevent disastrous automated inverse mutations.
* **Canonical RFC 8785 Plan Hashing**: Execution plans are canonicalized and hashed via SHA-256 before approval signing.
* **Rotatable KMS Signatures**: Approvals are cryptographically signed with KMS-managed keys. Key rotations preserve backward verification across historical signatures.
* **Configurable N-Person Approval Policy**: Enterprise security teams can enforce multi-party approval requirements, strict separation of duties (proposer cannot self-approve), and configurable risk-based timeouts.

---

## Routing benchmark

The identity-aware router is measured on a **synthetic, generated** dataset of 10,000 phrasings (`benchmarks/routing/`; re-score it from the repository root with `.venv/bin/python -m benchmarks.routing.runner [--report <path>]`, which writes a Markdown report, by default `docs/audits/routing_benchmark_report.md`). Real user phrasing will differ, and the router is a helper: it abstains (`ROUTE_UNCERTAIN`) instead of guessing.
* **Release gates the runner checks**: zero read-to-mutating dispatches, zero unsupported-to-destructive dispatches, at least 99% correct "no tool" classification, at least 99% Recall@5 on standard queries (currently 100%), p95 routing latency under 15 ms (currently about 0.1 ms).
* **Weaker categories** (see the report): typos (about 65% correct), paraphrases (about 88%) and unsupported requests (about 58%). The safety gates hold; ordinary accuracy on messy input does not reach the earlier marketing numbers.

---

## Decoupled Capability Providers & Circuit Breakers

Capability discovery is fully decoupled from SDDC Manager:
* **Provider Precedence**: Upstream data is ranked by authority (`AUTHORITATIVE` vs `OBSERVED`). vCenter remains authoritative for live VM runtime state, while VCF Operations provides observed historical telemetry.
* **Per-Provider Circuit Breakers**: Components (SDDC Manager, vCenter, NSX, VCF Operations) maintain isolated 3-state circuit breakers (`CLOSED`, `OPEN`, `HALF_OPEN`). A failing component trips its breaker after 3 consecutive failures, shedding load and failing over to secondary providers without exhausting system threads.
* **Admission Control & Backpressure**: Token-bucket rate limiters enforce per-principal read/write budgets (defaults: 300 reads/min, 20 writes/min) and per-component requests-per-second ceilings (defaults: SDDC Manager 20, NSX 25, VCF Operations 40, vCenter 50), returning HTTP 429 (`-32017 RateLimitBudgetExceededException`) under load.
* **MCP Tasks Opt-In Conformance**: In accordance with the MCP specification, long-running workflow tools advertise task metadata only when the client explicitly negotiates `io.modelcontextprotocol/tasks` experimental capabilities during handshake.

---

## Broadcom API Contract Registry

* **Broadcom API Contract Registry**: Maps each tool to the upstream operation it uses. `tests/test_broadcom_contract_alignment.py` fails if any provider or registry endpoint is missing from Broadcom's published specs (9.0.0.0, 9.1.0.0, 9.1.1.0; no public 9.0.1/9.0.2 archives exist).
* **Gap Analysis**: Reports which documented capabilities have no MCP tool yet.
* **Certification Runner**: Runs compatibility checks against the Digital Twin or a lab and reports the HTTP evidence it observed. Passing it is a local test result, not a Broadcom certification.

---

## Supply Chain Security & CycloneDX SBOM

To comply with enterprise software supply-chain standards (NIST SP 800-218 and Executive Order 14028), the repository includes an automated **CycloneDX 1.5 JSON Software Bill of Materials (SBOM)** generator:
* **Cryptographic Hashes**: Every control plane source module is hashed with SHA-256 and SHA-512.
* **License Metadata**: Inventories dependency licenses (an inventory, not a legal review).
* **Provenance Signature**: Signs the SBOM output using the active KMS key for third-party auditor verification.

---

## Configuration Reference

State lives in one directory, `~/.vcf-mcp/` (override with `VCF_MCP_HOME`): `config.yaml`, `control_plane.db`, `safety_profile.json`, `access_report.json`, the encrypted credential store and keys. Files from the older `~/.vcf_mcp/` are copied across once. Guided setup writes `config.yaml`; you can also edit it by hand. [config/enterprise_config.yaml](config/enterprise_config.yaml) is a commented example.

Key settings (YAML path):

| Setting | Default | Meaning |
| :--- | :--- | :--- |
| `server.environment` | `production` | `production` = real VCF appliances, `digital_twin` = simulator, `testing` = in-memory fixtures |
| `server.production_mode` | `false` | Strict production: refuses lab tokens, loopback targets and test keys (same as `VCF_MCP_ENV=production`) |
| `server.host`, `server.port` | `0.0.0.0`, `8443` (the starter config sets `127.0.0.1`) | Listener of `vcf-mcp server --mode http` (plain HTTP; the stdio mode ignores them) |
| `server.storage_mode`, `server.postgres_dsn` | `APPLIANCE` (SQLite), unset | `ENTERPRISE_HA` stores state in PostgreSQL and requires the DSN |
| `server.default_skill` | unset | Role skill that pre-prunes `tools/list` for small models |
| `server.access_mode` | absent = `team` (the starter config sets `personal`) | `personal`: one person on their own machine over stdio, no token, you approve your own changes. `team`: tokens and a separate approver. Personal is **refused** with a clear error for `server.mode` http / remote_gateway, `production_mode: true`, `VCF_MCP_ENV=production` and `storage_mode: ENTERPRISE_HA` |
| `server.personal_user`, `server.personal_roles` | `<os user>@<host>`, `[VCF_PLATFORM_ADMIN]` | Identity and roles in personal mode; guided setup narrows the roles to your goals (keeping `MCP_ADMIN` so you can run setup again) |
| `idp.issuer_url`, `idp.client_id`, `idp.jwks_uri` | Entra placeholders | Your OIDC identity provider |
| `idp.allow_lab_tokens` | `false` (the starter config sets `true`) | Trust the key made by `vcf-mcp token mint` (issuer `urn:vcf-mcp:lab`). Lab only; ignored in production mode |
| `policy.operating_mode` | `DISCOVERY_ONLY` | `DISCOVERY_ONLY`, `AUDITED_OPERATIONS`, `FULL_ENFORCEMENT` |
| `vcf.sddc_manager_url`, `vcenter_url`, `nsx_url`, `operations_url` | unset | Each component is optional; tools for unconfigured components are not offered |
| `vcf.component_usernames`, `component_credential_refs` | written by setup | Service-account names and secret references (never passwords) |
| `vcf.ca_cert_path` | unset | PEM CA chain, **added to** the system trust store |
| `vcf.verify_ssl` | `true` | `false` only for a throwaway lab |
| `vcf.allowed_dns_suffixes`, `vcf.allowed_cidrs` | lab defaults / RFC1918 | SSRF allowlist for appliance addresses; setting a list replaces the default |
| `vcf.endpoint_overrides` | `{}` | Map a discovered appliance FQDN to a reachable URL (load balancer, lab simulator) |
| `vcf.allow_loopback_targets` | `false` | Lab only: allow appliances on localhost |
| `vcf.https_proxy`, `vcf.no_proxy` | unset | Explicit HTTPS proxy (CONNECT); falls back to `HTTPS_PROXY` / `NO_PROXY`. The system proxy is never used implicitly |
| `vcf.automation_url`, `automation_org`, `orchestrator_*` | unset | VCF Automation / Orchestrator (experimental) |
| `vcf.automation_client_id` | unset | Service-account client ID, written by `vcf-mcp setup automation` |
| `vcf.orchestrator_auth` | `automation_token` | `automation_token` (VCF Automation service account), `basic` or `vcfa_session` (standalone Orchestrator) |
| `vcf.orchestrator_script_level` | `es5` | `es5`, or `rhino_1_7_15` to allow `let`/`const`, arrow functions, template literals, `for...of` and generators after you have tested them on your server |

Environment variables: `VCF_ENTERPRISE_MCP_CONFIG` (config path), `VCF_MCP_VERBOSE=1` (start-up banner on stderr), `VCF_MCP_HOME` (state directory), `VCF_MCP_DB_PATH`, `VCF_MCP_AUTH_TOKEN` (the caller's token for stdio; not needed in personal mode, and if set it is validated and used), `VCF_MCP_APPROVER_TOKEN` (for `vcf-mcp plans approve`), `VCF_MCP_ENV=production` (same as `server.production_mode: true`), `VCF_MCP_ALLOW_LAB_TOKENS=1` (same as `idp.allow_lab_tokens`, lab only), `VCF_OPERATING_MODE`, `VCF_VERIFY_SSL`, `VCF_CA_CERT_PATH`, `VCF_GATEWAY_URL`, `VCF_SDDC_MANAGER_FQDN`, `VCF_STORAGE_MODE` / `VCF_POSTGRES_DSN` (HA store).

---

## Testing & Verification

```bash
pip install '.[test]'
python -m pytest -q
```

The suite covers identity and policy enforcement, signed approvals, SSRF and TLS guards, durable workflows, the Digital Twin over real HTTP, the Broadcom spec contract guard, per-component session auth and the guided setup flow. It does **not** exercise live VCF appliances.

### Upstream certificate verification

VCF endpoint certificates are verified by default. To manually ignore certificate trust,
expiry and hostname checks for one server run:

```sh
vcf-mcp server --mode stdio --insecure
```

The server emits a **WARNING** on stderr/logs when verification is disabled. HTTPS
traffic remains encrypted, but the remote server's identity is not verified. This
option applies to upstream VCF/Twin connections only; it does not change IdP/JWKS,
secret-manager TLS, incoming gateway TLS, authentication, approvals or network guards.
There is no automatic retry with verification disabled after a certificate failure.

For persistent configuration, explicitly set `vcf.verify_ssl: false` in the YAML
selected by `VCF_ENTERPRISE_MCP_CONFIG`, or run with `VCF_VERIFY_SSL=false`.
`--insecure` overrides the configured setting for that run. Remove it and set
`VCF_VERIFY_SSL=true` / `vcf.verify_ssl: true` to restore verification.

To trust an organizational CA while keeping verification enabled:

```yaml
vcf:
  verify_ssl: true
  ca_cert_path: /path/to/enterprise-ca-chain.pem
```

`VCF_CA_CERT_PATH` also selects the PEM CA bundle. It is added to the system trust store;
it does not replace it. Certificate bypass is available when explicitly selected.

### Validated local setup and tests

See [Local setup and Digital Twin validation](docs/local_testing.md) for installation,
read-only certification, configured client startup, and the complete signed-plan
HTTP test. Certification reports real HTTP evidence and skipped writes; fixture execution
cannot earn a Twin verification label.

---

## License

[MIT License](LICENSE). Copyright (c) 2026 Abhishek Rai.

You may use, copy, change, merge, publish, distribute, sublicense and sell this software, for personal or commercial work. The one condition is **credit**: keep the copyright notice and the license text in every copy or substantial portion of it.

That condition applies however the code is copied, including when an AI system (a coding assistant, a model trained on or retrieving this repository, or a scraper) reproduces it, and to projects built on top of it. Every source file carries the notice, and [NOTICE](NOTICE) has ready-to-paste credit text:

```text
Based on VCF Enterprise MCP by Abhishek Rai
(https://github.com/abhishekaryan23/vcf-ent-mcp), MIT License.
```

Third-party code included in this project is listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Disclaimer

This is an independent, unofficial project that is under testing. It was developed and tested against simulators (the Digital Twin and the Northwind lab simulation in `tools/org_sim`) and Broadcom's published API specifications, not against a live VCF environment. It is provided "as is", without warranty of any kind. You are responsible for any actions it takes in your environment. Test only against the Digital Twin or non-production labs, with least-privilege accounts.

VMware, VMware Cloud Foundation, VCF, vSphere, vCenter, NSX, vSAN and related marks are trademarks of Broadcom Inc. and/or its subsidiaries. They are used here only to describe compatibility. This project is not affiliated with, sponsored by or endorsed by Broadcom.
