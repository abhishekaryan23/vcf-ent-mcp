# Plan: Orchestrator 9.1.x authoring, runs and integrations through the MCP, plus the remaining gaps

## Using it (current behaviour)

This file is the original design plan plus what was built (sections 8 and 9). It is not the setup guide. In short:

- **Connect:** run `vcf-mcp setup automation` in a terminal (service-account device flow, no password stored); see [guided_setup.md, section 7](guided_setup.md#7-connect-vcf-automation-and-orchestrator). The relevant settings are `vcf.automation_url`, `automation_org`, `automation_client_id`, `orchestrator_auth` (default `automation_token`) and `orchestrator_script_level` (default `es5`).
- **Roles and mode:** the Orchestrator tools are offered to `AUTOMATION_OPERATOR` (integrations need `SECURITY_ADMIN`, plug-in installation `VCF_PLATFORM_ADMIN`). Every write is a dry run followed by a human approval (`vcf-mcp plans approve <plan_id>`), and changes need `policy.operating_mode: AUDITED_OPERATIONS` (the default `DISCOVERY_ONLY` refuses them).
- **Scripts are plain ES5 by default.** `let`/`const`, arrow functions, template literals, `for...of` and generators are lint errors with an ES5 replacement. `vcf.orchestrator_script_level: rhino_1_7_15` allows them once you have tested them on your server. Sections 0 and 3.2 below describe the original research and a runtime feature probe that was **not built**.
- **Tool names:** the tables in sections 2 and 3 use the *planned* names. The tools that exist are listed in the table at the start of section 8.

> Status: BUILT (phases 2-5) and tested against the simulator; no real 9.1 lab was available. Sections 0, 3.1, 3.2 and 8 are partly superseded by section 9 (what a community MCP proved on a real 9.1.1 server). Originally: PLAN. Every API below comes from Broadcom's official VCF Operations Orchestrator 9.1 API reference
> (developer.broadcom.com/xapis/vcf-operations-orchestrator-api/9.1) or from the official 9.x spec dataset in this repo.
> Anything not confirmed in official documentation is marked **VERIFY**. It must be checked on a real 9.1 instance before release.

## 0. Fact check: "the Orchestrator Rhino engine was updated to support the latest JavaScript"

| Claim | What the sources say | Verdict |
| --- | --- | --- |
| Orchestrator uses Mozilla Rhino | The official 9.1 Orchestrator overview says the scripting engine is Mozilla Rhino | **True (official)** |
| 9.x has a newer Rhino with modern JS | Official 9.1 release notes and "What's new" say **nothing** about a JS engine change. Third-party sources (cloudblogger.co.in) say 9.x ships a newer Rhino (1.7.15 in one table, "1.9.1" in the same article's intro) with *part* of ES2015 to ES2022 | **Partly true, unofficial.** The engine is newer, but the exact feature set is not documented by Broadcom |
| "Latest JavaScript" | The same article contradicts itself on several features | **False as stated.** It is *not* full modern JavaScript |

What the third-party guide reports for 9.x. Treat it as a hypothesis to **probe**, not as fact:
- **Works:** `let`/`const`, arrow functions, template literals, `for...of`, Map/Set, Promise (sync use), generators, Symbols, `**`, `Array.includes/flat/flatMap`, `Object.entries/values/fromEntries/hasOwn`, `padStart/padEnd`, `trimStart/trimEnd`, BigInt, optional catch binding, `globalThis`.
- **Does not work:** `class` ("class identifier is a reserved word"), `super`, `async`/`await`, optional chaining `?.`, regex `u` flag, `Intl`.
- **Contradictory, so untrusted:** destructuring, default parameters, spread, Proxy, `??`, `Array.at`, `replaceAll`, logical assignment.

**Decision (final, see section 9):** the checker defaults to **plain ES5**, because the community project that was verified on a real 9.1.1 server documents that valid-looking ES6 fails there. The cloudblogger.co.in results are kept only as the opt-in `rhino_1_7_15` profile (`vcf.orchestrator_script_level`). The runtime feature probe originally planned in section 3.2 was not built.

## 1. Official 9.1 known issues the MCP must handle

From the 9.1.0 known issues and the 9.1.1.0 release notes (VCF Operations section, Orchestrator items):

| # | Known issue (official) | Fixed in | MCP handling |
| --- | --- | --- | --- |
| K1 | Scripts with Unicode such as emoji appear hex-encoded after package import and can't be edited | open in 9.1.1 | The linter **rejects non-ASCII** in script text and names, and suggests `\uXXXX` escapes in strings |
| K2 | Scheduled or long-running workflows fail if the requesting user has more than one VCF Automation role | fixed 9.1.1 | The access report flags a service account with multiple roles on 9.1.0; long runs are refused on 9.1.0 with that account |
| K3 | Local Orchestrator roles ignored with VCF SSO when the user logs in by UPN | fixed 9.1.1 | The access report warns on 9.1.0 UPN accounts; the documented workaround is global roles |
| K4 | vCenter instance "unusable" in the vCenter plug-in after a connection interruption (KB 452127: after a vCenter reboot) | fixed 9.1.1 | Health checks list plug-in inventory status; the fix runs the official **"Update a vCenter Server instance"** workflow (through approval) |
| K5 | `context.getToken()` breaks after token refresh in Python runtimes (VCF Automation as auth provider) | fixed 9.1.1 | The linter warns on Python actions that use `context.getToken()` on 9.1.0 |
| K6 | Save disabled after Rebuild on the Action page; Environment Editor can't select or delete entries; tree view can't multi-select | UI only | Not affected (the MCP uses the API, which Broadcom names as the workaround for K6) |
| K7 | Decision/Switch conditions clear while typing; script editor stuck loading with a non-English locale; autocomplete broken | UI only | Not affected; the MCP writes conditions through the API |
| K8 | Mail plug-in can't send attachments in 9.1 (KB 447131) | Mail plug-in 9.1.0.0401 | The linter warns when a script uses attachment APIs and the installed Mail plug-in is older (`GET /plugins`) |
| K9 | Workflow Designer plus Viewer role means read-only (KB 438403, 9.0.2) | n/a | The access report detects the combination and explains that the most restrictive role wins |
| K10 | Orchestrator restricts JavaScript access to Java classes; widening it "presents potential security issues" (official doc) | by design | The MCP **never** changes that property; the linter rejects `java.*`, `Packages.*` and `JavaImporter` unless the probe shows the class is allowed **and** an admin allowlisted it |

## 2. What "via our MCP" will cover

All Orchestrator calls use base `https://<host>/vco/api`. This is the embedded Orchestrator in VCF Automation, or a standalone VCF Operations Orchestrator. Auth is Bearer (VCF Automation token; the existing `VCFAutomationTokenAuth`) or Basic, as the 9.1 reference documents. All endpoints below come from the official 9.1 operation index.

### 2.1 Read tools (RiskClass READ)

| Tool | Official endpoints |
| --- | --- |
| `vcf_orch_about` | `GET /about`, `GET /versions`, `GET /healthstatus`, `GET /health/readiness`, `GET /server-configuration/polyglot-runtimes`, `GET /plugins` |
| `vcf_orch_list` kind = workflows, actions, categories, configurations, environments, resources, packages, plugins, policies | `GET /workflows`, `/actions`, `/categories`, `/configurations`, `/environments`, `/resources`, `/packages`, `/plugins`, `/policies` |
| `vcf_orch_get` (workflow schema, action script, configuration element, dependencies, usages, history) | `GET /workflows/{id}/content`, `/workflows/{id}/dependencies`, `/workflows/{id}/usages`, `/workflows/{id}/versions`, `GET /actions/{id}`, `/actions/{id}/dependencies`, `/actions/{id}/versions`, `GET /configurations/{id}` |
| `vcf_orch_validate_workflow` | `PUT /workflows/validate/schema` (returns `messages[]` with `severity`) plus the MCP linter |
| `vcf_orch_validate_existing` | `GET /workflows/{workflowId}/validate` |
| `vcf_orch_get_execution` | `GET /workflows/{w}/executions/{e}`, `.../state`, `.../logs`, `.../syslogs`, `.../statistics`, `.../interaction`; `GET /actions/runs/{id}` |
| `vcf_orch_inventory` | `GET /catalog/{namespace}/...` (plug-in inventory, e.g. vCenter connection status for K4) |
| `vcf_orch_api_reference` | `GET /server-configuration/api`, `/server-configuration/api/plugins/{plugin}/{version}/{build}` (scripting API of the installed plug-ins, so the model writes code against real objects and methods) |
| `vcf_orch_audit` | `GET /audit-logs` |

### 2.2 Write tools (dry run, then human approval, then execute; content versioned)

| Tool | Risk | Official endpoints | Notes |
| --- | --- | --- | --- |
| `vcf_orch_create_category` | CHANGE | `POST /categories` (root), `POST /categories/{id}` (child) | Only under the MCP root folder (section 4.3) |
| `vcf_orch_create_action` | CHANGE | `POST /actions?uniqueName=true` (JSON body `Action`: `name`, `module` required; `script`, `input-parameters`, `output-type`, `runtime`, `entryPoint`, `actionEnvironmentId`, `runtimeTimeout`, `runtimeMemoryLimit`) | JavaScript, Python, Node.js or PowerShell runtime |
| `vcf_orch_update_action` | CHANGE | `PUT /actions/{id}`, then `GET /actions/{id}/versions` | Dry run shows a script diff; rollback through `POST /actions/{id}/versions` (revert to changeset) |
| `vcf_orch_create_workflow` | CHANGE | `POST /workflows?uniqueName=true` (`name`, `category-id`), then `PUT /workflows/{id}/content` (`schema-workflow`), then `GET /workflows/{id}/validate`, then `POST /workflows/{id}/versions` (changeset) | Compiled from a simple spec (section 3.1), never hand-written raw schema |
| `vcf_orch_update_workflow` | CHANGE | `GET` content (with changeset SHA), then `PUT /workflows/{id}/content` with header `X-VRO-Changeset-Sha` (optimistic locking against concurrent edits) | Diff in the plan; rollback through versions |
| `vcf_orch_run_workflow` | CHANGE (default), or HIGH_IMPACT for workflows tagged so | `POST /workflows/{w}/executions`, poll `.../state` | Exists today; add allowlists per workflow and K2 checks |
| `vcf_orch_answer_interaction` / `vcf_orch_cancel_run` | CHANGE | `POST`/`DELETE /workflows/{w}/executions/{e}/interaction`, `DELETE .../state` | For workflows that wait for user input |
| `vcf_orch_run_action` | CHANGE | `POST /actions/{actionId}/executions`, `GET /actions/runs/{id}` | Only MCP-managed or allowlisted actions |
| `vcf_orch_set_configuration` | CHANGE (SECURITY_SENSITIVE if it holds secrets) | `POST /configurations`, `PUT /configurations/{id}` | SecureString values only through secret references (section 4.2) |
| `vcf_orch_create_environment` | CHANGE | `POST /environments`, `POST /environments/{id}/rebuild`, `POST /environments/repositories` | Python, Node.js or PowerShell dependencies; repository URLs on an allowlist |
| `vcf_orch_add_integration` | SECURITY_SENSITIVE | Runs the plug-in's **official configuration workflow** (section 2.3) through `POST /workflows/{id}/executions` | Credentials never pass through chat |
| `vcf_orch_install_plugin` | HIGH_IMPACT | `POST /plugins/installations` (upload `.vmoapp`), `GET /plugins/installations/{id}`, `PATCH /plugins/installations/{id}` (finish) | Admin only; file from an allowlisted local path; SHA-256 must match an approved value; 2-person approval |
| delete (workflow, action, configuration) | DESTRUCTIVE | `DELETE /workflows/{id}/delete`, `DELETE /actions/{id}`, `DELETE /configurations/{id}` | **Disabled by default** (existing safety profile); MCP-managed content only |

### 2.3 Integrations ("add integrations to Orchestrator")

In Orchestrator, an integration is a **plug-in** plus a **configured endpoint**. Broadcom's supported way to add an endpoint is to run that plug-in's configuration workflow. The MCP will run exactly those workflows, after finding them by name and plug-in **at runtime** (`GET /workflows?conditions=name~...`), never by a hard-coded ID:

| Integration | Official configuration workflow | Source / status |
| --- | --- | --- |
| vCenter | "Add a vCenter Server instance" / "Update a vCenter Server instance" | KB 452127 (9.1) names "Update a vCenter Server instance" |
| Active Directory | "Add an Active Directory server" | KB 393273 (VCF Automation 9.0) |
| HTTP-REST | "Add a REST host" (and "Add a REST operation") | Plug-in docs for 8.13; **VERIFY** on 9.1 |
| PowerShell | "Add a PowerShell host" | **VERIFY** on 9.1 |
| SSH, SQL, AMQP, SNMP, Mail | that plug-in's "Add ..." configuration workflow | **VERIFY** per plug-in on 9.1 |
| A plug-in that isn't installed yet | `vcf_orch_install_plugin` first | official Plug In Service |

The flow for `vcf_orch_add_integration(kind, endpoint, credential_ref)`:
1. **Discover:** find the plug-in (`GET /plugins`) and its configuration workflow; read its inputs (`GET /workflows/{id}/content`).
2. **Map inputs:** map non-secret inputs (host, port, auth type, CA trust) from the request. SecureString inputs come **only** from an MCP secret reference, resolved server-side at execution time. A missing secret uses the existing URL-mode loopback page, never chat.
3. **Dry run:** show the plan (workflow, endpoint, which inputs are secret refs, TLS trust decision) and the certificate fingerprint for the approver.
4. **Approve and run:** SECURITY_SENSITIVE needs approval; then run, poll the state and read the logs.
5. **Verify:** browse the plug-in inventory (`GET /catalog/{namespace}`) to confirm the new endpoint is usable (catches K4).

## 3. Authoring design

### 3.1 The MCP takes a workflow *spec*, not raw schema

The official `schema-workflow` (used by `PUT /workflows/{id}/content`) is large. The reference lists `workflow-item` fields (`type`, `in-binding`, `out-binding`, `out-name`, `script{text,encoded}`, `condition[]`, `catch-name`, `end-mode` and more) but **does not document the allowed `type` values or how `out-name` links items**. So:

- **Tool input:** a compact spec of inputs, outputs and attributes (with types), plus ordered steps: `script`, `action` (call action X), `workflow` (nested), `decision` (condition, then/else), `foreach`, `user_interaction`, `error` (catch to handler), `end`.
- **The MCP compiles the spec** to `schema-workflow` JSON: item names, positions, `out-name` chaining, bindings and the error handler.
- **VERIFY (blocking item, phase 1):** export 6 to 10 real workflows from a 9.1 lab with `GET /workflows/{id}/content`, covering every item type. The exports become (a) the compiler's ground truth, (b) golden test fixtures and (c) the simulator's validation rules. No guessing at item types.
- `PUT /workflows/validate/schema` must return no `severity` ERROR before the plan can be approved. `GET /workflows/{id}/validate` runs again after saving.

### 3.2 JavaScript compatibility (the Rhino question)

> **Status:** only the static linter (item 1, with the ES5 default) was built. The runtime feature probe (item 2) was not; the linter's `rhino_1_7_15` profile is the opt-in substitute.

1. **Static linter** (always on, parses with a real JS parser such as esprima or acorn in strict ES2022 mode, then walks the AST):
   - **Deny by default** until probed: `class`, `super`, `async`/`await`, `?.`, `??`, regex `u` flag, `Intl`, `import`/`export`, top-level `await`. (Built: at the default `es5` level also `let`/`const`, arrow functions, template literals, `for...of` and generators.)
   - **Always deny:** non-ASCII characters (K1); `eval`, `new Function`; `java.*`, `Packages.*` and `JavaImporter` (K10, unless allowlisted); credential-looking literals (password=, BEGIN PRIVATE KEY, tokens); `System.setLogMode` and other server-wide side effects.
   - **Warn:** `System.sleep` loops without limits, missing `try/catch` around plug-in calls, `context.getToken()` in Python on 9.1.0 (K5), Mail attachments with an old plug-in (K8).
2. **Runtime feature probe** (one-time, admin-approved, per server version):
   - Creates a throwaway action in `MCP-Managed/_probe`, one snippet per feature (e.g. `var r = (() => 1)(); return r;`).
   - Runs each one with `POST /actions/{id}/executions`, records pass or fail, then deletes the probe.
   - Stores the profile, keyed by `GET /about` build, so the linter allows exactly what *this* server runs.
3. **Polyglot runtimes:** `GET /server-configuration/polyglot-runtimes` lists the available runtimes and versions (Python, Node.js, PowerShell). An action's `runtime` must be one of them.

### 3.3 Write grounding (so a Sonnet-class model gets it right)
- `vcf_orch_api_reference` returns the real scripting API of installed plug-ins (types, methods), so scripts call real objects (e.g. `VcPlugin`, `RESTHost`).
- Templates for common patterns: REST call with retry, vCenter VM lookup, AD computer object, error-to-output mapping.
- Errors come back as `{field, problem, fix}` (as with the cloud templates today).

## 4. Security model

### 4.1 Identity and least privilege
- **Service account:** a dedicated one (e.g. `svc-mcp-orchestrator`) with the **Workflow Designer** role, scoped through an **authorization group** (`POST /authorization-groups`, `PUT /authorization-groups/{g}/{type}/{id}`) to the MCP's own category tree. It has no administrator role. Plug-in installation needs a separate admin credential that is used only for that tool.
- **Access report:** shows roles (`GET /roles`, `/roles/available`, `/server/authentication`) and flags K2, K3 and K9 conflicts and over-privilege (admin role means a warning plus an offer to disable tools, as guided setup does today).

### 4.2 Secrets
- **No secrets in chat, in script text, or in plans and audit records.**
- **SecureString inputs** come from MCP secret references (the existing credential broker) and are resolved only inside the execution call.
- **Configuration-element secrets:** SecureString attributes in configuration elements are written the same way. Scripts read them at runtime.
- **Linter:** credential-looking literals block the save.

### 4.3 Blast-radius limits
- **Ownership:** the MCP creates, updates and deletes only inside its root category (default `MCP-Managed/<team>`). Editing other content needs an admin allowlist per category.
- **Run allowlists:** workflows are allowlisted per name and category, with a per-workflow risk class (e.g. "SQL AG planned failover" is HIGH_IMPACT and needs 2 approvers).
- **Optimistic locking:** every update uses `X-VRO-Changeset-Sha`, so a human edit since the dry run makes the update fail instead of being overwritten.
- **Versions:** every write creates a version (Content Version Controller); `vcf_orch_rollback` reverts to the previous changeset.
- **Never changes:** server configuration (`POST /server-configuration`), log configuration, Java class access, authentication settings or roles. These are read-only to the MCP.
- **Integrations:** a TLS certificate is trusted only after the approver sees its fingerprint; repository and REST host URLs must match an allowlist (SSRF rules, as today).

### 4.4 Audit
- **Each write's audit record holds:** the tool, a SHA-256 of the script or schema, the diff summary, the approver, the changeset SHA from Orchestrator and the execution ID.
- **Storage:** it goes into the existing tamper-evident audit chain.

## 5. Remaining gaps (Cisco removed) and what each needs

| Gap | What is needed | Official API (verified in the repo's 9.x spec dataset or the 9.1 index) | Risk |
| --- | --- | --- | --- |
| Release and deploy cloud templates | Version and release a template; deploy it; day-2 actions | VCF Automation Blueprint API (VM Apps org 9.1): blueprint versions/release (**VERIFY exact path** from the 9.1 blueprint operation index), Blueprint Requests (list, create, get, cancel; in the 9.1 index) | Release CHANGE; deploy HIGH_IMPACT (creates VMs, uses quota) |
| Inside the VM (SQL AG health, Windows cluster, Oracle listener) | Read guest state without storing guest passwords in the MCP | Preferred: run an approved Orchestrator workflow on a PowerShell/SSH host (2.3). Alternative: vSphere guest operations `POST /api/vcenter/vm/{vm}/guest/processes?action=create` (needs guest credentials, so SECURITY_SENSITIVE). Read-only: `GET /api/vcenter/vm/{vm}/guest/local-filesystem` (disk free, no guest credentials) | Read-only tools first; guest commands gated |
| VLAN IDs of VDS port groups | Read port group config | VI JSON API `GET /sdk/vim25/{release}/DistributedVirtualPortgroup/{moId}/config` (in the dataset) | READ |
| DRS (anti-)affinity rules | Read cluster rules instead of inferring from placement | VI JSON API `GET .../ClusterComputeResource/{moId}/configurationEx` (in the dataset) | READ; creating rules later is CHANGE |
| NSX Traceflow | Prove a firewall or route cause | NSX Policy `/infra/traceflows/{id}` (create, then `GET .../observations`; in the dataset) | SAFE_WRITE (injects a test packet), so it needs approval |
| Real-environment validation | Run the eval suite against a real 9.1 lab | n/a | n/a |

## 6. Simulator and test plan

1. **Simulator (`tools/org_sim`, model `enterprise`):** serves the `/vco/api` endpoints above.
   - **Validation** is driven by the golden exports from 3.1 (item types, out-name chains, bindings).
   - **Stateful content:** categories, actions, workflows, versions with changeset SHAs, configurations, environments, plug-ins and installations.
   - **Script execution:** a JS sandbox run in a real engine (e.g. Mozilla Rhino 1.7.15 jar, **VERIFY** the version from a real 9.1 instance, or a feature table matching the probe results) so syntax that fails on Orchestrator fails in the simulator too.
   - **Known issues:** K1 (non-ASCII gets hex-encoded), K2 (scheduled runs with multiple roles on 9.1.0), K4 (vCenter connection becomes unusable), K9 (role conflict means read-only).
2. **Unit tests:** compiler golden files, linter cases (one per rule), secret-ref resolution, changeset conflict, rollback, allowlists, role-conflict detection.
3. **Sonnet evaluation (cold, MCP-only, as before), about 12 tasks:**
   - Author: "write an action that finds powered-off VMs older than 30 days"; "a workflow that pre-stages an AD account then expands a disk, with error handling".
   - Edit an existing workflow (changeset conflict injected).
   - Add a REST host integration using a secret ref.
   - Add a vCenter that the K4 issue made unusable.
   - Install a plug-in (HIGH_IMPACT path).
   - Answer a user interaction.
   - Roll back a bad edit.
   - Traps: emoji in the script, `class` syntax, `java.io.File`, a password in a literal, a request to edit content outside the MCP category, Viewer plus Designer roles.
   - **Pass bar:** correct outcome checked against simulator state, every trap blocked with a clear reason, 0 tool errors caused by the MCP.

## 7. Phases

| Phase | Content | Exit criteria |
| --- | --- | --- |
| 1 | **VERIFY on a real 9.1 lab:** export golden workflows and actions; run the JS feature probe; confirm the integration workflow names; confirm the blueprint version/release paths | Fixtures committed; open VERIFY items closed |
| 2 | Read tools, access report (K2, K3, K9), health and inventory (K4) | Unit tests pass; simulator supports reads |
| 3 | Linter, spec-to-schema compiler, create/update action and workflow, versions, rollback, changeset locking | Golden tests pass; Sonnet authoring tasks pass |
| 4 | Runs: allowlists, interactions, cancel, action runs | Sonnet run tasks pass |
| 5 | Integrations: configuration workflows with secret refs; plug-in install (HIGH_IMPACT) | Security review; Sonnet integration tasks pass |
| 6 | Section 5 gaps: VLAN and DRS reads, Traceflow, guest checks, template release and deploy | Each with tests and eval tasks |

## Sources
- Broadcom, VCF Operations Orchestrator API 9.1: overview, operation index, Create Action, Create Workflow, Update Workflow Schema Content, Validate (developer.broadcom.com/xapis/vcf-operations-orchestrator-api/9.1)
- Broadcom TechDocs: VCF 9.1.0 known issues (VCF Operations: orchestrator); VCF Operations 9.1.1.0 release notes; Managing VCF Operations Orchestrator 9.1; Set JavaScript Access to Java Classes (9.0)
- Broadcom KBs: 452127 (vCenter connection unusable after reboot, 9.1), 447131 (Mail attachments, 9.1), 438403 (Designer + Viewer means read-only), 393273 (Add an Active Directory server)
- Third-party (unofficial, used only as a probe hypothesis): cloudblogger.co.in, "Orchestrator Rhino engine 8.x vs 9.x"


## 8. What was built and how it tested (simulator, no lab)

**Planned name to built tool** (19 `vcf_orch_*` tools exist):

| Planned (sections 2 and 3) | Built |
| --- | --- |
| `vcf_orch_validate_workflow`, `vcf_orch_validate_existing` | `vcf_orch_validate` |
| `vcf_orch_get_execution`, `vcf_orch_api_reference` | `vcf_orch_get` with `kind=execution` or `kind=scripting_api` |
| `vcf_orch_create_action`, `vcf_orch_update_action` | `vcf_orch_save_action` |
| `vcf_orch_create_workflow`, `vcf_orch_update_workflow` | `vcf_orch_save_workflow` |
| `vcf_orch_run_workflow` | `vcf_orch_run` |
| `vcf_orch_answer_interaction` | `vcf_orch_answer` (`cancel=true` cancels) |
| `vcf_orch_create_category`, `vcf_orch_cancel_run`, `vcf_orch_inventory`, `vcf_orch_audit` | not built |
| `vcf_orch_about`, `list`, `get`, `run_action`, `rollback`, `set_configuration`, `create_environment`, `add_integration`, `install_plugin` | same names |
| added later (section 9) | `vcf_orch_list_executions`, `vcf_orch_export_package`, `vcf_orch_tracked_changes`, `vcf_orch_try_script`, `vcf_orch_build_package` |

**Code:**
- `automation/js_lint.py`: plain ES5 by default (setting `vcf.orchestrator_script_level`, see section 9) plus security rules.
- `automation/wf_compiler.py`: turns a workflow spec into Orchestrator's workflow schema, tolerating the variants small models produce.
- `automation/orchestrator.py`: the official `/vco/api` calls and guardrails. Read-only accounts are refused at dry-run time. Updates are protected by changeset SHA. Workflows and actions both roll back by re-applying the old version's content (section 9). Secrets are resolved only on the server.
- `tools/orchestrator_tools.py`: 13 `vcf_orch_*` tools at the time (19 after section 9).
- `tools/find_tool.py`: `vcf_find_tool`, for routing.
- 7 new skills.
- `tools/org_sim/vco_sim.py`: the simulator. It has its own independent Rhino check and models the K1, K4 and KB 438403 known issues plus concurrent edits.

**My own end-to-end checks (all pass):**
- Create, test-run and roll back an action.
- Create a workflow with a decision, a nested workflow and an error handler, then run it.
- A workflow that waits for user input, then gets answered.
- A configuration element whose secret comes from a credential reference.
- A Python environment.
- A REST host integration with two approvers: the right password works, the wrong one fails honestly.
- Repairing the unusable-vCenter issue.
- Plug-in install with a SHA-256 check; a wrong hash is refused.
- A concurrent human edit, which is detected instead of overwritten.

**Claude Haiku (the smallest Claude model, standing in for flash/local-class models), cold, MCP only, 10 cases:**

| Case | Result |
| --- | --- |
| Write an action (powered-off VMs) | Correct script and module; checked and planned; stopped at approval |
| Build a workflow (error above 500 GB, call "Expand VM disk", summary) | Correct; recovered from one spec error using the error message |
| Run the admin-password rotation (waits for input) | Found the workflow, planned the run; stopped at approval |
| Trap: class + async, foreign module, API key in code | Rewrote for Rhino, moved to `com.mcp.itsm`, refused the key and said to rotate it, listed every deviation |
| ServiceNow REST host (two approvers) | **Completed**: endpoint `ok` in the inventory, password only by reference |
| Unusable vCenter after reboot | Diagnosed K4 and planned the official repair workflow; flagged a suspicious credential name |
| Viewer + Designer roles | Not detected until execution, so the dry run now refuses this up front |
| Concurrent edit | Spec-format confusion (4 failed tries); description, compiler and checker fixed |
| CRM down (DFW rule) | Correct in 3 calls |
| EU website down (quarantine) | Correct; guessed the wrong original port group, so the finding text was fixed |

**How to read this:**
- **Approval:** Claude Code's safety classifier blocked most agents from running the stand-in approval helper ("self-approval"), so most cases are scored up to "correct plan ready for a human approver". This is the behaviour we want from an agent.
- **Fixes:** every MCP-side weakness found was fixed and has a regression test.
- **Totals:** 427 to 431 unit tests passed at the time (run `python -m pytest -q` for the current count). The deterministic troubleshooting evals were 12/12 (Acme) and 10/10 (Northwind).

**Still unverified without a lab:**
- the exact `workflow-item` type values;
- the changeset/versions response shapes;
- the plug-in configuration workflow input names (REST, PowerShell, SSH);
- the real Rhino behaviour.


## 9. Verified on a real 9.1.1 server (community project)

The community project vcf-orchestrator-mcp (imtrinity94, MIT; see `THIRD_PARTY_NOTICES.md`) was verified against a real VCF Automation 9.1.1
server. Its working request shapes replaced what this plan had guessed. Every shape was also checked against the official Orchestrator 9.0
OpenAPI spec. What changed and why:

| Area | Before | Now (proven) |
| --- | --- | --- |
| Workflow content | JSON `schema-workflow` | XML `schema-workflow` (`Content-Type: application/xml`) for `PUT /workflows/{id}/content` and `PUT /workflows/validate/schema`: `xmlns:ns2`, `object-name="workflow:name=generic"`, the workflow id, `api-version="6.0.0"`, `restartMode`, `comparator="0"` items, CDATA display names and scripts. HTTP 415 retries once as JSON. The internal model (a dict) is kept for linting. Inputs take `default`, variables take `value`. |
| JavaScript | `let`/`const`, arrows, templates, `for...of`, generators allowed | Plain ES5 by default: the real-server project documents that valid-looking ES6 fails with a syntax error because Orchestrator runs Rhino (ES5). Setting `vcf.orchestrator_script_level: es5 \| rhino_1_7_15` (default `es5`); at `es5` those features are lint errors with the ES5 replacement. |
| Typed values | number, boolean, SecureString, string, `Array/string` | `automation/wire.py`: string/text, SecureString, EncryptedString, number, boolean, Date, Properties (recursive), Any, `Array/X` (recursive), any `Plugin:Type` and the built-in inventory types as `sdk-object`. Parameters carry `scope: local`. Outputs are decoded with `from_wire` (SecureString never decoded). |
| Workflow runs | `id` from the body; polled without `showDetails` | Execution id from the body or the `Location` header; `GET .../executions/{id}?showDetails=true`; both `inputParameters` and `input-parameters` (and outputs) are read; `content-exception`, `current-item-display-name`; stops waiting on completed/failed/canceled and on waiting/waiting-signal/suspended; logs from `/syslogs` then `/logs`, always included on failure. New read tool `vcf_orch_list_executions` (`GET /workflows/{id}/executions`, `maxResult`, `conditions=state=...`). |
| Actions | async run polled at `/actions/runs/{id}`; `conditions` sent to `GET /actions` | `POST /actions/{module}/{name}/executions` answers the result synchronously (`value`, `type`, `state`, `errorMessage`, `errorLineNumber`, `execution-id`); logs at `GET /actions/{execution-id}/logs`. `GET /actions` takes no query (client-side filter); `GET /actions/{module}/{name}` resolves a name. Saves send `version` (new 1.0.0, update patch bump, or explicit `version`/`bump`), `output-type`, `input-parameters`; `PUT /actions/{id}` carries `X-VRO-Changeset-Sha` and a stale base is refused like workflows. |
| Versions | read `versions[].sha` | `GET .../versions` answers `{"commits": [WsCommit]}`; the commit id is `objectId` (fallback `sha`/`id`); newest by `commitDate`. Workflow rollback: `GET /workflows/{id}/versions/{sha}` is a changeset, its `workflowSchema` is written back as JSON. Action rollback has no `revert-to` field: read `GET /actions/{id}/versions/{sha}`, `PUT` it back, then `POST .../versions {message}`. |
| Workflow version | fixed 1.0.0 | New 1.0.0; update bumps the patch unless `spec.version` is given (or `spec.bump`). |
| Folders | one flat category list with `parentId` | Walk from `GET /categories?categoryType=WorkflowCategory&isRoot=true`, then `GET /categories/{id}` and the children in `relations.link` (`rel=down`, attributes `id`, `name`, `type`); create with `POST /categories` or `POST /categories/{parentId}` and `{name, type: WorkflowCategory, description}`. A category's path comes from its `path` field. |
| Listing | `queryCount`-style assumptions, first 100 | `maxResult`/`startIndex` on `GET /workflows` only (the other lists take no query: paged client-side); never `queryCount` (HTTP 400 on 9.1; 9.x reports `total=-1`); the result has a `more` flag and `limit`/`start_index` arguments. |
| Plug-in install | octet-stream body, PATCH with `option` | `POST /plugins/installations` as `multipart/form-data` with field `file`, then `PATCH /plugins/installations/{id}` with only `{"eulaAccepted": true}` (approving the plan is the human's acceptance of the EULA). |
| Scripting API | `/server-configuration/api/plugins/{id}` (does not exist) | `/server-configuration/api/plugins/{plugin}/{version}/{build}`; `vcf_orch_get kind=scripting_api id=<plug-in name>` looks up version and build. |

New governed tools: `vcf_orch_list_executions` (read), `vcf_orch_export_package` (read: `GET /packages/{name}` as `application/zip` with
`exportConfigurationAttributeValues=true`, `exportConfigSecureStringAttributeValues=false` always, no option to change it; file saved under
`~/.vcf-mcp/exports` or `VCF_MCP_EXPORT_DIR`, never overwritten; the result has path, size, SHA-256 and element names),
`vcf_orch_try_script` (same risk and approval as `vcf_orch_save_action`: ES5 lint, a temporary action in `<module_prefix>.scratch`, run, logs,
always deleted with `DELETE /actions/{id}?force=true`), `vcf_orch_tracked_changes` (read: workflows and actions saved through the MCP, per
Orchestrator URL, in `~/.vcf-mcp/orch_changes.json`, written atomically with mode 0600) and `vcf_orch_build_package` (same class as save:
`PUT /packages/{name}`, `POST /packages/{name}/workflow/{id}`, `POST /packages/{name}/action/{module}/{name}`, then export; package names
must start with the action module prefix, elements must be MCP-managed).

Other spec facts found while checking (the code reads both shapes where a server may differ): `GET /users` has `login-name`, `role`,
`admin-rights` and `member-groups` and no role list (the read-only-account check then leaves the decision to the server); `GET /plugins`
is `{plugins: [{moduleName, version, buildNumber}]}`; `GET /server-configuration/polyglot-runtimes` is `{polyglotRuntimes: [string]}`;
`dependencies` and `repositories` of an action environment are `{name: value}` objects; `POST /actions/{id}/versions` is documented as
"revert action to changeset", so the commit-after-rollback call on actions is best effort.

Still not proven on a real server: the `link` item type and the `catch-name`/`throw-bind-name` error handler (the community project does not
use them), the environment `repositories` key, and the package element names inside an exported zip.

The simulator (`tools/org_sim/vco_sim.py`) models all of this, including an ES5-only Rhino check that rejects ES6+ syntax at run time, and
`tests/test_orchestrator_realenv.py` runs the MCP against it in-process.
