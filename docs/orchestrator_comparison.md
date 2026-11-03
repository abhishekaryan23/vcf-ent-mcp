# Orchestrator: comparison with vcf-orchestrator-mcp

[vcf-orchestrator-mcp](https://github.com/imtrinity94/vcf-orchestrator-mcp) (imtrinity94, MIT) is a community MCP for VCF Operations Orchestrator 9.x, verified by its author on VCF Automation 9.1.1. We have never run against a real Orchestrator, so on 2026-11-02 we checked our implementation against two things from that project:
- what it does on a real server;
- the Orchestrator 9.0 OpenAPI document it ships.

This page records:
- what the two MCPs do;
- where they differ by design;
- what we changed as a result.

## Design difference

| | vcf-orchestrator-mcp | VCF Enterprise MCP |
| --- | --- | --- |
| Scope | Orchestrator only | VCF fleet: SDDC Manager, vCenter, NSX, Operations, Automation, Orchestrator, diagnostics |
| Change control | Full access by design. Limits come from the service account's roles and the client's tool prompts. | Every change is a dry run that produces a plan. A human approves it outside the chat, then it runs. Changes are limited to a managed folder and module prefix. Runs are limited to an allowlist. |
| Secrets | Refresh token in a JSON file | Encrypted secret store. SecureString inputs are passed as references and resolved server side. |
| Generic REST access | `vro_api_call` covers all 303 operations, including writes | None, on purpose: every operation is a reviewed tool |

## Capability check

| Their tool | Ours | Status |
| --- | --- | --- |
| `vro_server_info` | `vcf_orch_about` | Equivalent. Ours also reports known issues that apply to the server version. |
| `vro_find_workflows`, `vro_find_actions` | `vcf_orch_list` | Equivalent. Pagination fixed (see below). |
| `vro_get_workflow`, `vro_get_action` | `vcf_orch_get` | Equivalent |
| `vro_run_workflow`, `vro_get_execution` | `vcf_orch_run`, `vcf_orch_get` | Ours needs approval and the allowlist. Typed inputs and logs fixed (see below). |
| `vro_list_executions` | `vcf_orch_list_executions` | **Added** |
| `vro_run_action` | `vcf_orch_run_action` | Fixed: the result comes back synchronously |
| `vro_save_action`, `vro_save_workflow` | `vcf_orch_save_action`, `vcf_orch_save_workflow` | Ours adds the dry run, diff, conflict check and approval. Fixed: the save format and version bumping. |
| `vro_run_script` | `vcf_orch_try_script` | **Added**, with approval |
| `vro_set_versions` | (none) | Not added: versions are now bumped on every save |
| `vro_delete_workflow` | (none) | Not added: deletion stays a manual step in Orchestrator |
| `vro_export_package` | `vcf_orch_export_package` | **Added**. SecureString values are never exported. |
| `vro_tracked_changes`, `vro_build_package` | `vcf_orch_tracked_changes`, `vcf_orch_build_package` | **Added**. A package can contain only items the MCP manages, and building one needs approval. |
| `vro_sdk_lookup`, `vro_check_script` | `vcf_orch_validate` | Ours checks scripts offline: ES5, secrets, Java access, known issues and plug-in versions. It does not call modernvroapi.in. |
| `vro_api_search`, `vro_api_describe`, `vro_api_call` | (none) | Not added: it conflicts with our change control |
| (none) | `vcf_orch_rollback`, `vcf_orch_answer`, `vcf_orch_add_integration`, `vcf_orch_set_configuration`, `vcf_orch_create_environment`, `vcf_orch_install_plugin` | Only in ours |

## What was wrong in ours, and the fix

Each item was checked against the 9.0 OpenAPI document and the project's real-server code.

| Area | Before | Now |
| --- | --- | --- |
| Script language | Allowed `let`/`const`, arrow functions, template literals, `for...of` and generators on 9.x, based on a blog table | ES5 by default: those are errors with a suggested replacement. The project, by the same author as the blog, requires ES5 on 9.1.1. Rhino 1.7.15 features are opt-in with `vcf.orchestrator_script_level`. |
| Workflow content | JSON `schema-workflow` | XML `schema-workflow`, the format proven on 9.1.1. JSON is the fallback. Supports input defaults and attribute values. |
| Typed values | Only string, number, boolean, SecureString and arrays of strings | All types: Date, Properties, Any, nested arrays, plug-in objects (`VC:VirtualMachine`) and built-in inventory objects (`ResourceElement`, …) sent as `sdk-object` |
| Versions | Read `versions` and `sha` (fields that don't exist) | Reads `commits` and `objectId` |
| Action rollback | Sent `revert-to` (not in the API) | Reads the old version and writes it back with a normal save. The spec's `revertActionToChangeset` endpoint isn't called because its request body is unproven. |
| Concurrent edits | Checked for workflows only | Also checked for actions: an update needs `base_changeset_sha` and sends `X-VRO-Changeset-Sha` |
| Environments | Sent `dependencies` as a list | Sends a `{name: version}` object, as the spec defines |
| Workflow rollback | Wrote the whole changeset as the content | Writes back only the changeset's `workflowSchema` |
| Action runs | Polled `/actions/runs/{id}` | The result comes back in the run call's response; logs come from `/actions/{execution-id}/logs` |
| Workflow runs | Execution ID from the body only; logs from `/logs` only | Execution ID from the body or the `Location` header; logs from `syslogs`, then `logs`, attached automatically on failure |
| Folders | Assumed a flat list with `parentId` | Walks the folder tree from the root folders down |
| Listing | First page only | `maxResult`/`startIndex` paging. Never sends `queryCount`, which 9.1 rejects with 400. Handles `total = -1`. |
| Plug-in upload | Raw `application/octet-stream` | `multipart/form-data` field `file`, then `{eulaAccepted: true}` |
| Scripting-API path | `/server-configuration/api/plugins/{id}` (doesn't exist) | `/server-configuration/api/plugins/{plugin}/{version}/{build}` |
| Item versions | Never changed | New items start at 1.0.0; every update bumps the patch version |
| Automation login | `/tm/oauth/tenant/{org}/token` only. No `client_id`. Rotated refresh tokens were ignored, so the token stopped working after its first use. | Tries `/oauth`, then `/tm/oauth`. Sends `client_id`. Saves each rotated refresh token to the secret store at once. Explains `invalid_grant`. |
| Standalone Orchestrator | Broken: empty organization name | `vcf.orchestrator_auth`: `basic` or `vcfa_session` |
| Setup | You had to create the API token yourself | `vcf-mcp setup automation` creates a service account with the device-authorization flow. The password is used once and never stored. SSO-only organizations use `--client-id`. |

All of this is verified against the simulator and the 9.0 OpenAPI document, not yet against a real server.
