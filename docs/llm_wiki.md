# LLM Context Wiki: Enterprise VCF MCP Control Plane

This document serves as the high-density operational manual and security guardrail guide for LLM agents, automated reasoning copilots, and developers working with the **Enterprise VCF MCP Control Plane**. The project is unofficial and under testing. To install and run it, follow the [README quick start](../README.md#quick-start-about-five-minutes) and [guided_setup.md](guided_setup.md); this file does not repeat those steps.

---

## 1. System Persona & Purpose

* **System Role**: Enterprise Model Context Protocol (MCP) Control Plane acting as a secure, provider-neutral proxy between enterprise AI runtimes (Claude, OpenAI, Azure OpenAI, Gemini, local 4B models) and Broadcom VMware Cloud Foundation (VCF 9.0 and 9.1).
* **Core Security Boundary**: The LLM runtime sits strictly outside the trust boundary. The LLM **never** sees or stores raw infrastructure passwords, vCenter sessions, service-account API keys, or private certificates.
* **Standards Compliance**: Compliant with **MCP 2026-07-28** (stateless, Tasks extension, JSON Schema 2020-12, Enterprise-Managed Authorization).

---

## 2. Repository Layout & File Mapping

```
vcf_enterprise_mcp/
├── pyproject.toml                         # Packaging and installation metadata (console scripts: vcf-mcp, vcf-enterprise-mcp)
├── run_tests.py                           # Test runner (unittest); `python -m pytest -q` is the normal way
├── .agents/skills/                        # One SKILL.md per role skill (also: `vcf-mcp skills export`)
├── config/
│   └── enterprise_config.yaml             # Commented example configuration (the real one is ~/.vcf-mcp/config.yaml)
├── tools/org_sim/                         # Northwind / Acme organization simulators and the persistent lab (docs/troubleshooting_and_automation.md)
├── docs/
│   ├── architecture.md                    # HLD & LLD Mermaid diagrams & trust boundaries
│   ├── guided_setup.md, harnesses.md, local_testing.md   # Setup, per-harness entries, Digital Twin
│   ├── interactive_architecture/          # Self-contained, 100% offline interactive Archify diagrams (HTML/SVG)
│   │   ├── index.html                     # Unified interactive architecture navigation portal
│   │   ├── hld_architecture.html          # High-Level Design (HLD) & Trust Boundaries
│   │   ├── lld_architecture.html          # Low-Level Design (LLD) 6-Layer Architecture
│   │   ├── deployment_topology.html       # Dual Deployment Topologies & High Availability (HA)
│   │   ├── two_stage_execution.html       # Two-Stage Auth & TOCTOU-Safe Execution Sequence
│   │   ├── resumable_workflow.html        # Deterministic Resumable L3 Workflow & Saga Boundary
│   │   ├── workflow_lifecycle.html        # 12-State Workflow Lifecycle & 4-Phase Step Reconciliation
│   │   ├── async_tasks.html               # MCP Tasks Extension & Async Protocol Sequence
│   │   ├── vcf_admin_architecture.html    # VCF Infrastructure & VI Admin Architecture
│   │   └── vcf_ops_flow.html              # VCF Infrastructure Operation Flow (VM Resize)
│   ├── vcf_admin_guide.md                 # Complete VMware / VCF Infrastructure Engineer & Admin Guide
│   ├── authorization_model.md             # Intersection formula, roles, scopes, & PEP/PDP
│   ├── mcp_spec.md                        # MCP 2026-07-28 protocol & tool catalogue spec
│   └── llm_wiki.md                        # LLM context, guardrails, entity schemas (this file)
├── src/
│   └── vcf_enterprise_mcp/
│       ├── cli.py                         # `vcf-mcp` command (server, client-config, token, plans, safety, setup, credentials, skills ...)
│       ├── config/settings.py             # Type-safe settings with Pydantic fallback
│       ├── config/starter.py              # Starter config created by `vcf-mcp client-config` / first start
│       ├── setup/                         # Guided setup: wizard, credential page, access probe, `setup automation`
│       ├── secrets/                       # Secret providers: local encrypted, env, Vault, Azure Key Vault, AWS, CyberArk CCP
│       ├── automation/, diagnostics/      # Orchestrator authoring and runs; vcf_diagnose / vcf_trace_application engines
│       ├── skills/registry.py             # Single-task role skills
│       ├── state/
│       │   ├── durable_store.py           # Abstract DurableStore, SQLite WAL (Mode A), Postgres HA (Mode B)
│       │   └── leases.py                  # ResourceLeaseManager with monotonic fencing tokens
│       ├── core/
│       │   ├── paths.py                   # State folder: ~/.vcf-mcp (VCF_MCP_HOME), default DB and config paths
│       │   ├── protocol.py                # MCP 2026-07-28 stateless protocol & Tasks extension
│       │   ├── headers.py                 # HTTP Mcp-* and W3C traceparent agreement validator
│       │   ├── errors.py                  # Domain & protocol exception definitions (-32001 to -32017)
│       │   ├── admission.py               # AdmissionController (rate budgets & concurrency limits)
│       │   └── server.py                  # In-network stdio & remote HTTPS/SSE gateway
│       ├── auth/
│       │   ├── identity.py                # Principal data structure & verified claims
│       │   ├── idp.py                     # Enterprise IdP token validator (RFC 8707)
│       │   ├── untrusted.py               # Prompt injection defense & 5-tier classification
│       │   ├── lab_auth.py                # Lab token minting/trust (issuer urn:vcf-mcp:lab); lab only
│       │   ├── credential_broker.py       # Zero-trust broker (JIT tokens & secret redactor)
│       │   └── kms.py                     # Rotatable KMS Key Manager for approval signatures
│       ├── policy/
│       │   ├── models.py                  # RiskClass, CapabilityRole, NormalizedCapability, ApprovalPolicy
│       │   ├── engine.py                  # Policy Decision Point (PDP: intersection & fine-grained epochs)
│       │   └── enforcement.py             # Policy Enforcement Point (PEP: pre-route & pre-exec)
│       ├── router/
│       │   ├── catalog.py                 # L1, L2, and L3 EnterpriseToolCards
│       │   ├── identity_router.py         # 5-stage identity-aware routing pipeline
│       │   └── known_issues.py            # KnownIssueRegistry with Broadcom KB provenance
│       ├── adapter/
│       │   ├── capability_provider.py     # Provider precedence, circuit breakers (CLOSED/OPEN/HALF_OPEN)
│       │   ├── platform.py                # PlatformClient with monotonic resource revisions
│       │   ├── ssrf_guard.py              # SSRF guard (cloud metadata & link-local IP block)
│       │   ├── version_adapter.py         # VCF 9.0.0 through 9.1.1 version translation
│       │   ├── api_registry.py            # BroadcomAPIContractRegistry across 5 baselines (9.0.0 to 9.1.1)
│       │   ├── certification.py           # Certification helpers (a local test result, not a Broadcom certification)
│       │   └── discovery.py               # Environment profile / capability matrix model (used by tests; not a live scanner)
│       ├── workflows/
│       │   ├── task_store.py              # Durable MCP Task handle manager (unguessable IDs)
│       │   ├── execution_plans.py         # Dry-run plans, canonical hashing, TOCTOU check
│       │   ├── engine.py                  # Resumable multi-step orchestrator with compensation
│       │   └── enterprise_workflow.py     # 12-state workflow engine with outbox reconciliation
│       ├── audit/
│       │   ├── recorder.py                # Tamper-evident SHA-256 hash-chained audit recorder
│       │   ├── exporters.py               # SIEM / Syslog / OpenTelemetry formatters
│       │   └── sbom.py                    # CycloneDX 1.5 JSON SBOM Generator
│       └── tools/
│           ├── base.py                    # BaseEnterpriseTool (PLAN-AUTH-LEASE-EXEC-VERIFY-AUDIT)
│           ├── query_tools.py             # L1 Query tools (read-only inventory & telemetry)
│           ├── operational_tools.py       # L2 Operational tools (power, resize, snapshot)
│           ├── workflow_tools.py          # L3 Workflow tools (domain upgrade, DR drills)
│           ├── diagnostic_tools.py, automation_tools.py, orchestrator_tools.py, find_tool.py   # troubleshooting, VCF Automation, Orchestrator, vcf_find_tool
└── tests/
    ├── test_mcp_protocol_conformance_2026.py   # MCP 2026-07-28 stateless edge & tasks tests
    ├── test_permission_epochs_and_freshness.py # Epoch bump & cache isolation tests
    ├── test_toctou_approvals_and_plans.py      # Dry-run plans, nonces, & TOCTOU revisions
    ├── test_idempotency_leases_and_postconditions.py # Mutual exclusion & verification tests
    ├── test_durable_resumption_and_compensation.py # Crash recovery & compensation tests
    ├── test_ssrf_and_untrusted_data_sanitization.py # SSRF block & prompt injection tests
    ├── test_tamper_evident_audit_chain.py      # Cryptographic hash chain verification
    ├── test_adversarial_router_benchmark.py    # 650-query routing benchmark suite
    ├── test_identity_and_auth_pdp.py           # IdP claims & intersection formula tests
    ├── test_credential_broker.py               # Zero-trust credential isolation tests
    ├── test_identity_aware_routing.py          # Principal-sensitive discovery & routing
    ├── test_dry_run_and_workflows.py           # Workflow engine tests
    ├── test_onboarding_and_discovery.py        # Discovery-only mode & version tests
    ├── test_digital_twin_chaos_integration.py  # 10 Digital Twin chaos and failure tests
    └── test_large_scale_routing_benchmark.py   # 11,200 query routing & workflow benchmark suite
```

---

## 3. Key Domain Entities & Data Contracts

### 1. `Principal` (`auth.identity.py`)
```python
class Principal:
    user_id: str                          # Corporate username (e.g. alice@corp.com)
    display_name: str                     # Human-readable name
    corporate_groups: List[str]           # Directory groups (e.g. ["VCF-Compute-Operators"])
    allowed_domains: List[str]            # Resource scope: permitted domains
    allowed_clusters: List[str]           # Resource scope: permitted clusters
    client_ip: str                        # Client source IP address
    token_id: str                         # Unique token identifier for audit
```

### 2. `ExecutionPlan` (`workflows.execution_plans.py`)
```python
class ExecutionPlan:
    plan_id: str                          # Unique plan handle (plan-<uuid>)
    initiator_id: str                     # Operator proposing change
    tool_name: str                        # Target tool
    parameters: Dict[str, Any]            # Desired parameters
    target_resource: str                  # Resource identifier (e.g. "vm-102")
    resource_revision: int                # Monotonic revision at plan minting
    impact_analysis: Dict[str, Any]       # Simulation impact summary
    executable: bool                      # Always False upon dry_run creation
```

### 3. `ResourceLease` (`state.durable_store.py`)
```python
class ResourceLease:
    resource_id: str                      # Resource under lock (e.g. "vm-101")
    owner_id: str                         # Task or session holding lease
    fencing_token: int                    # Monotonically increasing 64-bit integer
    acquired_at: float                    # POSIX timestamp
    expires_at: float                     # Lease expiry timestamp
```

### 4. `ExecutionIntent` (`state.durable_store.py`)
```python
class ExecutionIntent:
    intent_id: str                        # Unique execution outbox intent handle
    task_id: str                          # Associated MCP task identifier
    step_id: str                          # Workflow step identifier
    operation: str                        # Operation name (e.g. "reconfigure_vm")
    parameters: Dict[str, Any]            # Target execution parameters
    state: str                            # PREPARE, EXECUTE, RECONCILE, VERIFIED, FAILED
```

### 5. `SignedExecutionAuthorization` (`workflows.execution_plans.py`)
```python
class SignedExecutionAuthorization:
    plan_hash: str                        # SHA-256 canonical hash of execution plan
    approver_ids: List[str]               # List of authorized approvers
    approver_signatures: List[str]        # KMS-backed cryptographic signatures
    key_ids: List[str]                    # KMS key identifiers used for signing
    signature_algorithm: str              # e.g., "HMAC-SHA256" or "RSASSA-PSS"
    nonce: str                            # Single-use cryptographic nonce
```

---

## 4. Active Guardrails & Anti-Exploit Rules

1. **Zero Credential Exposure**:
   - The LLM must NEVER output or request raw passwords, API keys, or certificates.
   - Any sensitive payload must be replaced with `[REDACTED]` or `vault://...`.
2. **Untrusted Infrastructure Data Sanitization**:
   - Infrastructure-originating strings (VM names, notes, alarms) are treated as untrusted data and scrubbed of prompt-injection patterns (`[INJECTION_ATTEMPT_DEFUSED]`).
3. **Multi-Level Data Classification**:
   - Sensitive fields are strictly classified (`PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `SECRET`, `CREDENTIAL`) and redacted at the presentation boundary.
4. **Dual Storage Profiles**:
   - **Mode A (Appliance MCP)**: SQLite WAL with `WAL` journaling, `NORMAL` synchronous mode, and in-process mutexes for single-node appliances.
   - **Mode B (Enterprise HA)**: PostgreSQL HA with external connection pooling and outbox transaction guarantees for active-active multi-node clusters.
5. **Distributed Fencing Tokens**:
   - Every acquired resource lease issues a strictly monotonically increasing `fencing_token`. Upstream adapters reject operations presenting stale or expired fencing tokens (`-32012`).
6. **Outbox Execution Intent Reconciliation**:
   - All mutating steps persist an `ExecutionIntent` to durable store before upstream dispatch (`PREPARE -> EXECUTE -> RECONCILE -> VERIFY`). Mid-flight crashes trigger automatic idempotency reconciliation.
7. **Irreversible Boundaries & Saga Halts**:
   - Steps marked `irreversible: true` cannot be automatically rolled back. If a subsequent step fails, the workflow transitions to `MANUAL_INTERVENTION_REQUIRED` or `RECONCILIATION_REQUIRED` without running unsafe reverse compensations.
8. **Private Dynamic Discovery (`cacheScope: "private"`)**:
   - `tools/list` MUST be filtered dynamically by principal and returned with `cacheScope: "private"` and short TTL (`cacheTtl: 60`).
9. **Fine-Grained Permission Epochs**:
   - `environment_epoch`, `principal_epoch`, and `policy_epoch` track security revisions. Bumping an epoch immediately invalidates cached decisions, active tool catalogs, and outstanding approval tokens.
10. **Canonical Plan Hashing & Rotatable KMS Signatures**:
    - Execution plans are serialized to canonical RFC 8785 JSON and signed using rotatable KMS keys. Historical signatures remain verifiable across key rotations.
11. **Configurable N-Person Approval Policy**:
    - Multi-party approval rules enforce separation of duties (approver != initiator), minimum required signatures, and risk-class timeouts.
12. **Provider Precedence & Circuit Breakers**:
    - Upstream capabilities are routed across prioritized providers (`AUTHORITATIVE` vs `OBSERVED`). Unresponsive providers trip circuit breakers (`CLOSED -> OPEN -> HALF_OPEN`) to prevent resource exhaustion.
13. **Admission Control & Backpressure**:
    - Per-principal read/write budgets and per-component requests-per-second ceilings reject over-limit requests with HTTP 429 (`-32017`).
14. **Tamper-Evident Hash Chaining with WORM Anchoring**:
    - Every operational and security event is recorded into a cryptographic SHA-256 hash chain with external WORM/SIEM checkpoint anchoring.

## Local remediation entry points (2026-09-27)

- Startup: `core.server._build_engine_from_settings` is shared by HTTP and stdio;
  setup configuration is loaded before repository defaults. Invalid explicit config fails.
- `enterprise/plans/approve` in `core.protocol` is an authenticated, tenant-scoped
  enterprise extension for a separate platform administrator.
- `tools.base` requires signed plans for all writes and rechecks policy/permission
  epoch at the provider dispatch boundary; a completed idempotency response can be
  returned without consuming another nonce.
- `tests/test_local_http_e2e.py` launches the actual CLI and sibling Twin processes;
  `tests/test_remaining_audit_fixes.py` covers the independent security regressions.
- Current setup commands and limits: [local_testing.md](local_testing.md).

## Single-Task Role Skills, Tool Catalog & Laptop Lab Mode (updated 2026-11)

- **52 tools: the 50 in `router/catalog.py` plus the two setup tools `vcf_setup` and `vcf_access_report`**. What a caller sees is filtered by role, operating mode, safety profile and configured components (`tools/list`); a fresh install with no appliance shows only `vcf_setup`, `vcf_access_report` and `vcf_find_tool`.
  - **30 L1 read tools**, for example `vcf_list_vms`, `vcf_get_vm` (with VM name-to-MOID resolution), `vcf_list_hosts`, `vcf_get_health`, `vcf_query_telemetry`, `vcf_list_domains`, `vcf_list_clusters`, `vcf_list_datastores`, `vcf_list_nsx_segments`, `vcf_list_nsx_gateways`, `vcf_list_snapshots`, `vcf_list_upgrade_bundles`, `vcf_verify_audit_chain`, the troubleshooting tools (`vcf_diagnose`, `vcf_trace_application`, `vcf_list_networks`, `vcf_check_component`, `vcf_list_failed_tasks`, `vcf_list_alerts`), VCF Automation reads and Orchestrator reads (`vcf_automation_list/get/validate_template`, `vcf_orch_about/list/get/validate/list_executions/export_package/tracked_changes`), and `vcf_find_tool`.
  - **18 L2 operational tools** (all need a dry run and approval): `vcf_power_vm`, `vcf_resize_vm`, `vcf_create_snapshot`, `vcf_delete_snapshot`, `vcf_create_nsx_segment`, `vcf_automation_create_template`, and the Orchestrator writes `vcf_orch_save_action/save_workflow/rollback/run/run_action/answer/add_integration/set_configuration/create_environment/install_plugin/try_script/build_package`.
  - **2 L3 resumable workflow tools**: `vcf_upgrade_domain`, `vcf_recover_site`.
- **16 Populated `CapabilityRole` Presets (`src/vcf_enterprise_mcp/policy/models.py` & `engine.py`)**:
  - Every `CapabilityRole` (`VCF_VIEWER`, `VCF_AUDITOR`, `COMPUTE_OPERATOR`, `COMPUTE_ADMIN`, `NETWORK_OPERATOR`, `NETWORK_ADMIN`, `STORAGE_OPERATOR`, `STORAGE_ADMIN`, `AUTOMATION_OPERATOR`, `LIFECYCLE_OPERATOR`, `LIFECYCLE_ADMIN`, `DR_OPERATOR`, `DR_ADMIN`, `SECURITY_ADMIN`, `VCF_PLATFORM_ADMIN`, `MCP_ADMIN`) has explicit `NormalizedCapability` mappings and risk ceilings.
- **26 Pre-Provided Single-Task Role Skills (`src/vcf_enterprise_mcp/skills/registry.py` & `.agents/skills/*/SKILL.md`)**:
  - Exposed via `.agents/skills/<skill-name>/SKILL.md` AND in-band MCP `prompts/list`, `prompts/get`, `resources/list`, `resources/read`, and `tools/list` (via `params.skill` or `Mcp-Active-Skill` header).
- **In-Band Plan Lifecycle (`src/vcf_enterprise_mcp/core/protocol.py` & `workflows/execution_plans.py`)**:
  - `enterprise/plans/list`, `enterprise/plans/get` (with initiator-only `approval_id`/`nonce` handback; the read tool `vcf_get_plan` returns the same status, and in personal access mode `enterprise/plans/approve` is refused because the person approves via the chat prompt, a local page or their own terminal), and `enterprise/plans/approve`.
  - Deterministic KMS `key_id` derivation (`src/vcf_enterprise_mcp/auth/kms.py`) across multi-node HA clusters and persistent local KMS keys (`~/.vcf-mcp/kms.key`).
- **Developer Laptop & Lab CLI (`src/vcf_enterprise_mcp/cli.py` & `auth/lab_auth.py`)**:
  - `vcf-mcp init-lab`: One-command lab setup storing local encrypted credentials (`local://`), initializing KMS, minting Operator & Approver JWTs, and generating MCP client JSON config. The README quick start (`client-config` + guided setup) is the recommended route.
  - `vcf-mcp token mint --role <ROLE>`: Mints local RS256 JWT tokens (issuer `urn:vcf-mcp:lab`, 24 h) for any of the 16 VCF roles; trusted only with `idp.allow_lab_tokens`.
  - `vcf-mcp plans list|show|approve`: Inspects and approves execution plans from the CLI; `approve` needs the approver's own token (`--approver-token-file`, `--approver-token` or `VCF_MCP_APPROVER_TOKEN`).
  - `vcf-mcp skills list|show|export`: Inspects and exports the 26 single-task role skills.
  - Covered by `tests/test_role_skills_and_lab_workflow.py`.


## Other ports

A Rust port is being explored separately. It is not part of this repository yet; Python is the reference implementation.
