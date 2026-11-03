# Guided setup from your AI harness

After you add the MCP server to your MCP client (Claude Code, Claude Desktop, Cursor, VS Code, Windsurf, LM Studio, Codex CLI, Gemini CLI or [another one](harnesses.md#supported-clients)), setup happens in the conversation. The assistant asks what you want to do and which appliances and service accounts to use. It then collects passwords somewhere private, checks what those accounts can actually do, warns you about risky accounts, and lets you switch off destructive actions.

## 1. Add the server to your harness

Print the entry for your harness. This creates `~/.vcf-mcp/` and a starter config that names no appliance, and shows the absolute path of the launch command (`vcf-mcp server --mode stdio`):

```bash
vcf-mcp client-config claude-code
```

**No token to make (personal mode).** The starter config sets `server.access_mode: personal`: the assistant acts as your local user, so the printed entry has no `VCF_MCP_AUTH_TOKEN`. Add the entry to your harness, reload it as the printed notes say, then say **"set up VCF MCP"** (or run the `vcf_guided_setup` prompt). The harness page [harnesses.md](harnesses.md) has the per-harness details. Setup itself never needs an approval: it is not a write that goes through a dry run and plan, it needs the `MCP_ADMIN` or `VCF_PLATFORM_ADMIN` role, which you have in personal mode. At the end it narrows the roles you act as (`server.personal_roles`) to what your goals need and keeps `MCP_ADMIN` so you can run setup again.

**Team or shared installs.** Use `vcf-mcp client-config <harness> --team`, which prints the token-based entry, and put a token in it: for a lab the built-in lab signer (`vcf-mcp token mint --role MCP_ADMIN --user you@corp.example --raw`, trusted through `idp.allow_lab_tokens: true`, refused in production mode, valid 24 hours, `--ttl <seconds>` changes that); in production a token from your IdP for a user with the `MCP_ADMIN` (or `VCF_PLATFORM_ADMIN`) role, and set `server.access_mode: team`. An existing config without `server.access_mode` is team mode too. See [authorization_model.md](authorization_model.md#0-access-modes-personal-and-team).

**No lab yet?** Use the bundled Digital Twin: start it from the repository clone (see [local_testing.md](local_testing.md); it needs `pip install '.[test]'`) and answer "Local Digital Twin" when setup asks what to connect to. It needs no passwords.

```bash
PYTHONPATH=tests/fixtures .venv/bin/python -m digital_twin.run --host 127.0.0.1 --port 8085
```

**Setup mode.** With no appliance configured, the server still starts and serves only `vcf_setup`, `vcf_access_report` and `vcf_find_tool`; any other tool answers with a message that points at `vcf_setup`. In team mode, if the token is missing or wrong, the handshake still succeeds and `tools/list` / `tools/call` explain how to fix it. As soon as setup completes, the server reloads its configuration and announces the change (`notifications/tools/list_changed`), so no restart is needed (if your harness does not refresh its tool list by itself, reconnect or start a new chat).

## 2. What the conversation looks like

| Step | You are asked | How it is collected |
| --- | --- | --- |
| Goals | Digital Twin, lab or production; what you want to do (monitoring, capacity, VM operations, NSX changes, lifecycle, DR) | Form (multi-select) |
| Endpoints | Digital Twin: its URL (default `http://127.0.0.1:8085`). Otherwise the HTTPS URL and **service-account username** for each appliance your goals need | Form; usernames only |
| Passwords | One private page per appliance | **URL mode**: a one-time page on `127.0.0.1` in your own browser |
| Access check | Nothing, unless a network question comes up (see below). The server logs in and asks each appliance what the account can do | Read-only API calls |
| Safety | Which actions to switch off, with defaults based on the risk found | Form (checkboxes) |
| Done | A plain summary of what the MCP can and cannot do, warnings, and next steps | Result |

**How the questions reach you.** Over stdio the server speaks the classic MCP flow that today's clients use: your client declares `capabilities.elicitation` (form and, for the password pages, url) at `initialize`, and the server sends `elicitation/create` requests while the `vcf_setup` call is pending; the client shows the form or opens the link, answers `accept`, `decline` or `cancel`, and the server carries on until setup is complete. (Over HTTP only the 2026-07-28 multi-round-trip style is offered, where the call returns an `input_required` result and the client retries it with the answers.) URL mode is used only when the client declared `url`. If your harness doesn't support MCP elicitation forms, the tool returns the same questions with their options, and the assistant asks them in its own UI. Passwords still never go through the chat: you get the private link or a terminal command (`vcf-mcp credentials add …`), which prompts without echo.

### When the access check fails

A failure is not always a wrong password, so setup says which it is:

| Cause | What setup tells you | Config key |
| --- | --- | --- |
| Login rejected (HTTP 401, or 403 while logging in) | Re-enter the password. Only now is the saved password discarded | none |
| Certificate not trusted | Point the MCP at the CA chain; it is **added to** the system trust store | `vcf.ca_cert_path` |
| Name does not resolve / connection refused / timeout | Check DNS, firewall, VPN. A name that cannot resolve from this machine can be mapped to a reachable address (the name you typed, and the appliance names SDDC Manager reports) | `vcf.endpoint_overrides` |
| Blocked by this MCP's own allowlist (not an appliance fault) | Shows the exact line to add | `vcf.allowed_dns_suffixes`, `vcf.allowed_cidrs`, `vcf.allow_loopback_targets` (lab only) |
| Proxy refused the tunnel / proxy needed | Set an explicit proxy | `vcf.https_proxy`, `vcf.no_proxy` (or `HTTPS_PROXY`, `NO_PROXY`) |

For every cause except a rejected login the password you typed is kept: you are not asked for it again. Setup asks the question (CA path, proxy, "add these allowlist entries?") instead of changing anything silently; answer it and setup re-checks. You can also edit `config.yaml` by hand; setup picks the file up on the next call.

After the SDDC Manager login, setup lists the vCenters and NSX Managers SDDC Manager knows about and checks that this MCP may contact them (their canonical names often differ from what you typed). If its own allowlist would block them, it asks whether to add their DNS suffix. If you decline, setup still completes and warns that those appliances will be skipped. `vcf_diagnose` and inventory tools report such a block as an MCP configuration problem with the key to change, never as a failed appliance.

## 3. Why you can trust it with credentials

- **Passwords never enter the chat, tool arguments, the model or the MCP client.** The MCP 2026-07-28 spec forbids form mode for secrets. Setup uses URL-mode elicitation instead, pointing at a page that writes straight to the secret store. Any tool argument that looks like a secret (`password`, `token`, `api_key` …) is rejected.
- **The credential page:**
  - listens only on `127.0.0.1`, on a random port;
  - uses a single-use ticket bound to you, valid for 10 minutes;
  - checks the Host header and a CSRF token;
  - sends `no-store` and a strict CSP, and never logs request bodies;
  - shows a verification code that matches the one in your assistant's message, so you can tell the link is yours.
- **Signed setup state.** `requestState` is HMAC-protected and bound to your identity, the `vcf_setup` call and a 15-minute expiry, as the MRTR spec requires. A tampered, expired or someone-else's token is rejected.
- **Saved files contain no passwords.** Setup writes endpoints, usernames and secret *references* to `~/.vcf-mcp/config.yaml` (mode 0600). Every step is recorded in the tamper-evident audit chain.

## 4. What it tells you about your access

Setup logs in with each account and reads its real permissions through documented, read-only APIs:

| Component | Identity and permissions read from |
| --- | --- |
| vCenter | `GET /api/session`; VI/JSON `AuthorizationManager.HasUserPrivilegeOnEntities` on the root folder |
| SDDC Manager | `GET /v1/domains` (read access); `GET /v1/users`, which only ADMIN may call |
| NSX | `GET /api/v1/aaa/user-info` (user and roles) |
| VCF Operations | `GET /suite-api/api/auth/currentuser` and `/currentuser/permissions` |

Every tool you asked for is then reported as **AVAILABLE**, **UNVERIFIED** (for example, vCenter privileges scoped to a folder rather than the root; outside your goals these are listed as "could not be ruled out", not as reachable), **BLOCKED_BY_VCF_ACCESS**, **NOT_CONFIGURED**, **DISABLED_BY_OPERATOR** or **NOT_IMPLEMENTED**. Ask "what can you do?" at any time and the assistant calls `vcf_access_report`.

### Local admin and over-permissive accounts

Built-in accounts get a prominent warning: `administrator@vsphere.local`, `root`, SDDC Manager `admin@local`, NSX `admin` and VCF Operations `admin`. So do accounts holding administrator roles (vCenter Admin, SDDC Manager ADMIN, NSX `enterprise_admin`, Operations Administrator). The warning explains:

- that the account can't be scoped and gives the MCP every destructive action on that component;
- which destructive actions are reachable even though you didn't ask for them;
- exactly how to create a least-privilege account instead (role names, privileges and where to click).

The safety form then **pre-ticks** blocks for destructive actions and for anything outside your goals.

| Option | Blocks |
| --- | --- |
| `disable_vm_power` | `vcf_power_vm` (power-off/reset interrupts workloads) |
| `disable_snapshot_delete` | `vcf_delete_snapshot` (permanent loss of a restore point) |
| `disable_vm_reconfigure` | `vcf_resize_vm` |
| `disable_network_changes` | `vcf_create_nsx_segment` |
| `disable_upgrades` | `vcf_upgrade_domain` (host/firmware steps are irreversible) |
| `disable_dr` | `vcf_recover_site` |
| `read_only` | every change; dry runs still work |

## 5. Safety controls are enforced server-side, and only you can loosen them

Your choices are saved in `~/.vcf-mcp/safety_profile.json`. The policy enforcement point applies them on top of IdP roles and approvals, for everyone. Disabled tools disappear from `tools/list`, and execution is refused even if a client calls them directly.

Through MCP, setup can only **tighten** this profile. It also never moves the policy out of `DISCOVERY_ONLY`. Loosening is a local, interactive operator action:

```bash
vcf-mcp safety show
```

```bash
vcf-mcp safety enable vcf_power_vm
```

```bash
vcf-mcp safety read-only off
```

`enable` and `read-only off` ask for a typed confirmation, and refuse to run without an interactive terminal unless you pass `--yes` deliberately. A prompt injection therefore can't widen what the agent may do.

## 6. Least-privilege accounts setup recommends

| Goal | vCenter | SDDC Manager | NSX | VCF Operations |
| --- | --- | --- | --- | --- |
| Monitor / capacity | Read-only (global permission) | VIEWER | auditor | ReadOnly |
| VM operations | Custom role: Read-only plus the `VirtualMachine.Interact.*`, `VirtualMachine.Config.CPUCount/Memory` and `VirtualMachine.State.*Snapshot` privileges, on the target folder or cluster | n/a | n/a | n/a |
| NSX changes | n/a | n/a | network_engineer | n/a |
| Lifecycle | n/a | OPERATOR (ADMIN is never needed) | n/a | n/a |

Use service accounts from your identity source (VCF SSO / Identity Broker or AD), one per purpose, with passwords stored in your vault.

## 7. Connect VCF Automation and Orchestrator

VCF Automation 9 (and the Orchestrator embedded in it) is not part of the conversational setup above. It uses an OAuth **service account** instead of a password, which you create once with a terminal command:

```bash
vcf-mcp setup automation --url https://auto.example.lab --org <org-name> --user <local-org-user> --name mcp-svc
```

What it does, step by step (the same flow VCF Automation 9.1.1 documents for service accounts):

1. Logs in as `user@org` with the password you type (hidden; or `--password-file <file>`, first line). The password is used for this one call and is never stored, logged or printed. If the login is rejected (HTTP 401) setup stops after that single attempt, so a typo cannot lock the account.
2. Registers the service account and asks VCF Automation for a device code.
3. Approves the code as the logged-in user. If your user may not do that, setup prints the code and where to approve it (Access Control > Service Accounts > Review Access Requests) and waits.
4. Exchanges the approved code for tokens, then checks `GET /vco/api/workflows` and `GET /iaas/api/projects`.
5. Stores the **refresh token** in the secret store as the `vcf_automation` credential (`local://env-prod/vcf-mcp-vcf-automation`) and writes only non-secret settings to the active config: `vcf.automation_url`, `vcf.automation_org`, `vcf.automation_client_id`, the service-account name under `vcf.component_usernames` and the credential reference under `vcf.component_credential_refs`. If `vcf.allowed_dns_suffixes` is set, the Automation host's suffix is added to it.

The active config is the file named by `VCF_ENTERPRISE_MCP_CONFIG`, else `~/.vcf-mcp/config.yaml`; `--config <file>` picks another. This command runs in your terminal, outside the MCP server, so **restart the MCP server (reload your harness entry) afterwards** to pick up the new settings.

**Roles.** The names come from **Access Control > Roles** in the org and differ per org (for example *Organization Owner* instead of *Organization Administrator*). Give the account the least it needs: an **Orchestrator role** (for example *Orchestrator Administrator*) is required to see and run workflows. Without one, Orchestrator treats the account as a plain user and shows no workflows or actions at all, which setup reports after its check. Add Assembler/IaaS roles only if you use those tools. `--role "Role A,Role B"` skips the question; without it setup asks, and offers your own roles as the default.

**SSO-only orgs.** Users who sign in through an identity provider have no password to log in with. Create the service account in the VCF Automation UI (Access Control > Service Accounts > New, with the roles above), copy its client ID and run:

```bash
vcf-mcp setup automation --url https://auto.example.lab --org <org-name> --client-id <client-id>
```

Setup prints a user code and waits (up to the code's lifetime, about 10 minutes) while you approve it in the UI.

**Token rotation.** VCF Automation issues a **new refresh token each time one is used**, and the old one stops working. The running MCP server saves every rotated token back to the same secret-store entry immediately (the local store replaces its file atomically) and uses it next time; it renews access tokens by itself, one minute before they expire, and once more if a call returns 401. Two consequences: do not copy the stored credential to another machine (whichever machine refreshes first invalidates the other's copy), and if you ever see *"refresh token already used or revoked"* run `vcf-mcp setup automation` again. Role changes reach the MCP at the next token refresh (restart it to be sure).

**TLS.** Setup honours `vcf.verify_ssl` and `vcf.ca_cert_path`; for a private CA pass `--ca-cert <pem>`. There is no switch to skip certificate verification.

**Orchestrator login modes.** `vcf.orchestrator_auth` selects how the MCP logs in to Orchestrator:

| Value | Use when |
| --- | --- |
| `automation_token` (default) | Orchestrator is embedded in VCF Automation, or any Orchestrator that accepts VCF Automation service-account tokens. The token is always issued by `vcf.automation_url` (and needs `vcf.automation_org`), even if `vcf.orchestrator_url` points at another host. |
| `basic` | A standalone Orchestrator that takes HTTP Basic. Uses the `vcf_orchestrator` credential if you add one to `vcf.component_credential_refs`, else `vcf_automation`. |
| `vcfa_session` | An org user with a password: logs in with `/cloudapi/1.0.0/sessions` (then `/tm/...`) as `user@org`, trying API versions 40.0, 9.1.0 and 9.0.0. It stops at the first 401 and does not retry the same rejected password. |

The refresh-token handling and this setup flow are adapted from the community project [vcf-orchestrator-mcp](https://github.com/imtrinity94/vcf-orchestrator-mcp) by imtrinity94 (MIT), whose service-account flow was verified on a real VCF Automation 9.1.1. See THIRD_PARTY_NOTICES.md.

## Limits

- The credential page is loopback-only. If the MCP server runs on a remote host, run `vcf-mcp credentials add` on that host instead (`--password-stdin` or `--password-file` when there is no terminal); setup tells you the exact command.
- The vCenter privilege check through VI/JSON, and SDDC Manager role inference, still need validation on a real lab before you rely on them. When a check can't be confirmed, setup reports **UNVERIFIED** rather than guessing.
- The conversational setup does not ask for the VCF Operations `authSource` (set `vcf.operations_auth_source` in `config.yaml`) and offers a CIDR for a non-private management network only after the access check was blocked; VCF Automation / Orchestrator is connected with `vcf-mcp setup automation` (section 7). Federated (SSO-only) accounts may not be able to log in through the NSX and SDDC Manager API flows; use local or LDAP service accounts. See the README's known limitations.
- Passwords are stored per component, not per username: after switching accounts, delete the old credential first (`vcf-mcp credentials delete local://env-prod/vcf-mcp-<component>`, with `<component>` one of `vcenter`, `sddc-manager`, `nsx`, `vcf-operations`; `vcf-mcp credentials list` shows the references).
