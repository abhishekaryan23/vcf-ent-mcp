# Local setup and Digital Twin validation

The MCP and the Digital Twin simulator (`tests/fixtures/digital_twin`, shipped in this repository) can be tested without a VCF environment.
These checks establish local behavior; they do not certify native VCF API contracts,
production readiness, PostgreSQL HA, or appliance deployment.

## Install and start

From the repository root:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install '.[test]'
.venv/bin/vcf-mcp setup --target digital_twin --gateway-url http://127.0.0.1:8085
PYTHONPATH=tests/fixtures .venv/bin/python -m digital_twin.run --host 127.0.0.1 --port 8085
```

In another terminal, from the same directory:

```sh
.venv/bin/vcf-mcp certify --target digital_twin --profile vcf_9_1_1
```

Certification uses actual HTTP, performs read-only provider checks, reports skipped
writes, and fails if the Twin is unavailable. `DIGITAL_TWIN_VERIFIED` applies only
to the operations actually executed. Unit fixtures are labeled `UNIT_TEST_ONLY`.
It is not a complete MCP or production certification.

Setup creates a mode-0600 `~/.vcf-mcp/config.yaml` in `DISCOVERY_ONLY`. Existing
configuration is retained, so if `vcf-mcp client-config` already created the starter
config (README quick start), `setup --target digital_twin` leaves it unchanged: either
delete that file first, or choose "Local Digital Twin" in the guided setup instead. The config file is the one named by
`VCF_ENTERPRISE_MCP_CONFIG`, else `~/.vcf-mcp/config.yaml` (created with a starter
config on first start). Invalid YAML stops startup.
`setup --config /path/config.yaml` writes elsewhere; select that path with
`VCF_ENTERPRISE_MCP_CONFIG` when starting the server.

To use the Twin from an AI harness (stdio), run `.venv/bin/vcf-mcp client-config <harness>` and
`.venv/bin/vcf-mcp token mint --role VCF_VIEWER --raw` after the `setup` step above; see
[harnesses.md](harnesses.md). The server reads `~/.vcf-mcp/config.yaml`, so it talks to the Twin.

For an authenticated HTTP client, set `idp.issuer_url`, `idp.client_id` and
`idp.jwks_uri` to your identity provider in the configuration (for a laptop test,
`idp.allow_lab_tokens: true` plus `vcf-mcp token mint` is enough), then run:

```sh
.venv/bin/vcf-mcp server --mode http
```

The default listener created by setup is `127.0.0.1:8443`, using plain HTTP for
local testing. Upstream certificate verification is a separate setting; manually
selecting `--insecure` disables it and logs a warning. Prefer `vcf.ca_cert_path`
for an organizational CA. Do not expose the local HTTP listener externally without
an authenticated TLS gateway.

## Automated complete HTTP test

```sh
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q tests/test_local_http_e2e.py
```

The test starts temporary loopback MCP, JWKS, and Twin processes. It generates
short-lived signing keys, creates a disposable VM, tests discovery/telemetry,
rejects unsigned writes and self-approval, then approves and executes CPU/RAM resize
and power operations over the MCP HTTP endpoint. It verifies actual Twin state,
zero dry-run writes, retry without duplicate writes, persisted audit records, and
certification failure with the Twin stopped. It deletes its VM and stops all processes.
No existing credentials or real VCF endpoints are used.

If the Twin dependencies are in another interpreter, set `TWIN_PYTHON=/path/to/python`.
To run the full MCP suite:

```sh
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q
```

## Mutation approval workflow

All mutations, including `SAFE_WRITE`, require an execution plan and signed,
single-use authorization. A dry run returns `plan_id`. In personal access mode (the starter config) you approve your own plan with a chat prompt, a local page or `vcf-mcp plans approve` in your own terminal, and the assistant then calls again with `plan_id` only (see [authorization_model.md](authorization_model.md#0-access-modes-personal-and-team)); the rest of this section is team mode. A separate authenticated
platform administrator can obtain an authorization with `vcf-mcp plans approve <plan_id>`
(using their own token; the dry-run result's `how_to_approve` has the exact command) or the enterprise
JSON-RPC extension `enterprise/plans/approve`, with `params.plan_id`. The extension is not
an official MCP method. It rejects the initiator, wrong tenant/environment, and
read-only/disabled modes. Submit the returned `approval_id` and `nonce` with the
original tool arguments and `plan_id`; include an idempotency key in the original
dry run when retry protection is needed. Retrying a completed request returns the
stored result and performs no additional write.

Modern HTTP requests require `MCP-Protocol-Version: 2026-07-28`, `Mcp-Method`, and
`Mcp-Name` for tool calls, plus matching
`params._meta["io.modelcontextprotocol/protocolVersion"]`. Missing or mismatched
headers return HTTP 400 / `-32020`; unsupported revisions return HTTP 400 /
`-32022` with supported versions. See the
[official transport specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http).

Snapshot execution remains disabled. Native VCF lifecycle, DR, networking, and
other unqualified writes are not approved by these local tests. The Twin's
telemetry is synthetic and its HTTP compatibility does not establish Broadcom support.
