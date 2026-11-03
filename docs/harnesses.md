# Use VCF Enterprise MCP from your AI harness

This project is unofficial and still under testing. Author: Abhishek Rai (abhishekaryan2@gmail.com).

A harness (or MCP client) is the app that talks to the model: Claude Code, Claude Desktop, Cursor, VS Code, Windsurf, LM Studio, Codex CLI, Gemini CLI and many others. This page shows how to connect each one to the VCF Enterprise MCP server.

The command `vcf-mcp client-config <harness>` prints a ready-to-paste setup. It writes the notes (file location, reload tip) to the terminal and the snippet alone to standard output. So you can redirect it to a file if you want.

The snippet always uses the absolute path of `vcf-mcp`. Desktop apps do not inherit your shell PATH, so a bare `vcf-mcp` often fails.

## Supported clients

Any MCP client that runs local (stdio) servers can use VCF Enterprise MCP. The table says how far each one has been checked.

| Support | Clients |
| --- | --- |
| **Tested end to end** | Claude Code, LM Studio, the official MCP Python SDK client |
| **Ready-made config** (`vcf-mcp client-config <name>`) | Claude Desktop (`claude-desktop`), Cursor (`cursor`), VS Code with GitHub Copilot agent mode (`vscode`), Windsurf (`windsurf`), OpenAI Codex CLI (`codex`), Gemini CLI (`gemini`) |
| **Should work, not tested** (paste the `generic` config into the client's MCP settings) | IDEs and coding agents: Zed, JetBrains IDEs (AI Assistant, Junie), Visual Studio with GitHub Copilot, Cline, Roo Code, Kilo Code, Continue, Kiro, Amazon Q Developer CLI, Goose, OpenCode, Warp. Desktop chat apps: AnythingLLM, Jan, Msty, Cherry Studio, 5ire, LibreChat. Agent frameworks: OpenAI Agents SDK, LangChain / LangGraph (`langchain-mcp-adapters`), LlamaIndex, Pydantic AI, Microsoft Semantic Kernel |
| **Not supported yet** | Clients that only connect to remote servers over the internet: ChatGPT connectors, custom connectors on claude.ai, Microsoft Copilot Studio. They need a public HTTPS endpoint with OAuth; this server offers stdio, or plain HTTP that you must put behind your own authenticated TLS gateway |

Local model runners such as Ollama and llama.cpp are not MCP clients themselves. Use them through one of the clients above (for example LM Studio, Goose, Continue or AnythingLLM).

If you try a client from the "Should work" row, please open an issue with the result so the table can be updated.

## Prerequisites

1. Install the package into a virtual environment. This creates the `vcf-mcp` command next to that environment's Python.
2. Run `vcf-mcp client-config <harness>`. It creates `~/.vcf-mcp/` and a starter config if you have none. You do not need to write a config first: with no appliance configured the server starts in setup mode and the guided setup (see [guided_setup.md](guided_setup.md)) creates it. For a lab you can instead run `vcf-mcp init-lab`, which writes a lab config with the appliance URLs you pass (it enables `AUDITED_OPERATIONS`, unlike guided setup) and prints operator and approver tokens; use `--target digital_twin` for the bundled Digital Twin.
3. Nothing else for one person on their own computer: the starter config is in personal mode, so no token is needed (the assistant acts as your local user and you approve each change yourself). For a shared lab or production use team mode (`vcf-mcp client-config <harness> --team`) and have a token: setup needs `MCP_ADMIN`; for a lab, `vcf-mcp token mint --role MCP_ADMIN --raw` (the starter config trusts it via `idp.allow_lab_tokens`; the token is valid for 24 hours, change that with `--ttl <seconds>`); for daily use mint a narrower role (for example `--role VCF_VIEWER`) or use a token from your identity provider. A config that already exists without `server.access_mode` is team mode.

Every harness runs the same command, `vcf-mcp server --mode stdio`, with an absolute path to `vcf-mcp`.

Options for `client-config`:

- `--config PATH` uses a different config file (default: `VCF_ENTERPRISE_MCP_CONFIG` or `~/.vcf-mcp/config.yaml`).
- `--db PATH` uses a different control-plane database (default `~/.vcf-mcp/control_plane.db`, an absolute path).
- `--team` prints the team entry, with a `VCF_MCP_AUTH_TOKEN` placeholder (`Bearer <paste your token>`). The default is the personal entry without any token when the config says `server.access_mode: personal` (an existing config without the key gets the team entry).
- `--token-from-env` (implies the team entry) puts the current `VCF_MCP_AUTH_TOKEN` value in the snippet instead of the placeholder. The command never mints a token.

If you use `--token-from-env`, the token is written in plain text in the client's config file. Protect that file.

## Claude Code

```
vcf-mcp client-config claude-code
```

Run the printed `claude mcp add ...` command in your terminal. It adds the server with user scope. Start a new Claude Code session, then run `/mcp` to see `vcf-enterprise`.

## Claude Desktop

```
vcf-mcp client-config claude-desktop
```

Paste into `claude_desktop_config.json`:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

You can open it from Settings > Developer > Edit Config. If the file already has `mcpServers`, add only the `vcf-enterprise` entry. Quit Claude Desktop fully and start it again.

## Cursor

```
vcf-mcp client-config cursor
```

Paste into `~/.cursor/mcp.json` (all projects) or `.cursor/mcp.json` (one project). Open Cursor Settings > MCP and check the server. Restart Cursor if it does not appear.

## VS Code

```
vcf-mcp client-config vscode
```

Paste into `.vscode/mcp.json` in your workspace. VS Code uses the key `servers` (not `mcpServers`) and needs `"type": "stdio"`. Run `MCP: List Servers` from the Command Palette and start or restart `vcf-enterprise`.

## Windsurf

```
vcf-mcp client-config windsurf
```

Paste into `~/.codeium/windsurf/mcp_config.json`. Press the refresh button in the Cascade MCP panel, or restart Windsurf.

## LM Studio

```
vcf-mcp client-config lmstudio
```

In LM Studio, open the Program tab and choose Install > Edit mcp.json. Paste the snippet. LM Studio uses the same notation as Cursor. The file is usually `~/.lmstudio/mcp.json`. Save, then check the Program tab.

## Codex CLI

```
vcf-mcp client-config codex
```

Add the printed TOML to `~/.codex/config.toml`. Start a new `codex` session.

## Gemini CLI

```
vcf-mcp client-config gemini
```

Paste into `~/.gemini/settings.json` (or `.gemini/settings.json` in a project). Stdio servers only connect in a trusted folder (`gemini trust`). Restart `gemini` and run `/mcp` to check status. Note that Gemini CLI hides some host variables that look like secrets, so keep the token in the `env` block as printed.

## Any other client

```
vcf-mcp client-config generic
```

This prints the common `mcpServers` JSON. Most MCP clients accept it as is; some (Zed, Continue, Goose) use their own file format, so copy the `command`, `args` and `env` values into it. See [Supported clients](#supported-clients).

## Small and local models

Small models struggle with a long tool list. Load a role skill so the model sees only about 7 tools: set `server.default_skill: vcf-oncall-troubleshoot` in the config (works for harnesses that cannot pick a skill), or have the client send `params.skill` / the `Mcp-Active-Skill` header. List skills with `vcf-mcp skills list`, read one with `vcf-mcp skills show <name>`, and export them as `SKILL.md` files with `vcf-mcp skills export` (default folder `.agents/skills` in the current directory; use `--dir <path>` to choose another).

Tell the model to call `vcf_find_tool` first. It searches for the right tool by task, so the model does not need to see every tool at once.

## Troubleshooting

**The server does not start.** Open the client's MCP log. Claude Desktop writes to `~/Library/Logs/Claude` (macOS) or `%APPDATA%\Claude\logs` (Windows); look at `mcp.log` and `mcp-server-vcf-enterprise.log`. Check that every path in the config is absolute and exists. Try running the printed command by hand in a terminal. If it works there but not in the app, the app is probably using a different path or environment.

**"Plugin process exited" in LM Studio.** The server process stopped right after it started. Usual causes: a wrong `command` path, a missing config file, or a bad token. Run the command from the snippet in a terminal and read the error.

**Passwords during setup.** You enter them on a private local page, never in the chat. A small background helper serves that page. It keeps working even if the client restarts the server. If the link does not open, use the `vcf-mcp credentials add ...` command shown next to the link.

**Approvals.** Changes need a signed approval, and every dry-run result contains a `how_to_approve` block that says how.

*Personal mode (the starter config):* you, the person who asked, approve. If your client supports MCP elicitation (Claude Code, LM Studio and the official Python SDK declare it), the assistant's next call with `plan_id` shows you a prompt in the chat window with the tool, target, risk and plan summary and an Approve / Reject choice (for destructive and security-sensitive changes you also type the target name or the plan code); Approve runs the change in that same call. Without elicitation, `how_to_approve.approval_url` is a one-time page on `127.0.0.1` with the same choice, and you can always run this in your **own** terminal (it refuses scripts and assistants' shell tools, and asks you to type the 6-character plan code shown on screen):

```
vcf-mcp plans approve <plan_id> --db ~/.vcf-mcp/control_plane.db
```

Then tell the assistant to carry on: it calls the tool again with only `plan_id`. `vcf_get_plan` shows whether a plan is approved.

*Team mode:* a human administrator (not the person who asked for the change) approves from a terminal with their OWN token:

```
export VCF_MCP_APPROVER_TOKEN='Bearer <your token>'    # or --approver-token-file <file>
vcf-mcp plans approve <plan_id> --db ~/.vcf-mcp/control_plane.db
```

The command prints `approval_id` and `nonce`; paste those into the chat and the assistant repeats the call with them (or reads them with `vcf_get_plan`). Destructive and security-sensitive plans need two different approvers. Use `vcf-mcp plans list` to find the plan id. Add `--tenant` / `--env` if your tokens use other values than the defaults (`tenant-default`, `env-prod`). See [authorization_model.md](authorization_model.md#0-access-modes-personal-and-team).

**"Authentication failed" at tools/list.** In personal mode no token is needed; if you see this, the entry carries a `VCF_MCP_AUTH_TOKEN` that was not accepted (an expired or placeholder value): remove it. In team mode the handshake works without a token, but `tools/list` and `tools/call` need one: set `VCF_MCP_AUTH_TOKEN` in the server entry (lab: `vcf-mcp token mint --role MCP_ADMIN --raw`, and `idp.allow_lab_tokens: true` in the config).
