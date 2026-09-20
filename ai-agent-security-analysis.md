# AI Agent Security & Vulnerability Analysis

**Scope:** monitoring, detecting and analysing attacks against tool-using AI agents, anchored on Claude Code / Claude Agent SDK as the reference implementation.

**Status:** working document, v0.3
**Last updated:** 2026-09-20

---

## How to use this document

Every item carries a stable ID so it can be pulled out and expanded independently:

| Prefix | Section | Meaning |
|---|---|---|
| `T-` | 1 | Threat class |
| `SURF-` | 2 | Instrumentation surface (where you can observe/enforce) |
| `S-` | 3 | Static analysis technique |
| `D-` | 4 | Dynamic analysis technique |
| `SIG-` | 5 | Runtime detection signal |
| `OSS-` | 6 | Open-source tool |
| `STD-` | 7.9 | Rule format / taxonomy / standard |
| `C-` | 6.2 | Cross-server rule (MCPRadar) |
| `LLM-`/`ASI-`/`MCP-`/`AST-`/`ML-` | 7.1–7.5 | OWASP category, native IDs |
| `BM-` | 8 | Benchmark or corpus |
| `GAP-` | 9 | Unsolved problem / research opportunity |

Deep-dive notes for each item go in `deep-dives/<ID>.md`.

---

## 0. Framing

Monitoring a chat model means inspecting text. Monitoring an **agent** means inspecting a **trajectory**: a loop of model decisions, tool invocations and returned data, where the returned data can itself change the model's future decisions.

That feedback edge — *tool output re-enters the prompt* — is the entire vulnerability surface. Every threat below is a consequence of it.

Three corollaries that shape everything downstream:

1. **Tool results are untrusted input.** A file, a web page, an issue body, an MCP response — all of it is attacker-writable in the general case.
2. **Configuration is code.** Hooks, skills, steering files and MCP manifests all steer or execute. They belong in version control and in CI review.
3. **In-band controls are inside the attacker's reach.** Anything the model can see, an injection can talk to. Only host-level controls survive a compromised agent.

---

## 0.5 MCP architecture primer

Most of `§1` is a consequence of how MCP is built. This section states the architecture so the threat model reads as derived rather than asserted.

### Roles

MCP is **client-host-server**, not client-server. Each host runs multiple client instances.

| Role | Responsibility | Example |
|---|---|---|
| **Host** | Container and coordinator. Creates and manages clients, controls connection permissions and lifecycle, **enforces security policies and consent**, handles authorization decisions, coordinates LLM integration and sampling, aggregates context | Claude Code, IDE, agent runtime |
| **Client** | Created by the host, communicates with **exactly one server**. Attaches protocol version and capabilities to requests, routes messages bidirectionally, manages subscriptions, maintains security boundaries between servers | One per connected server |
| **Server** | Exposes resources, tools and prompts. Operates independently with focused responsibility. Requests client input via sampling, elicitation, roots. **Local process or remote service** | filesystem (stdio), Gmail (HTTP) |

### Primitives

Server features, with their control model — the underrated part of the design:

| Primitive | Controlled by | Meaning |
|---|---|---|
| **Tools** | **Model** | Functions the model decides to call. `tools/list`, `tools/call` |
| **Resources** | Application | URI-identified data the host chooses to load |
| **Prompts** | User | Templates the user explicitly invokes (slash commands) |

Client features — note these invert the trust direction:

| Primitive | Meaning | Risk |
|---|---|---|
| **Sampling** | Server asks the client to run an LLM completion | Untrusted server gets indirect model access with content it controls |
| **Elicitation** | Server asks the user for input mid-operation | Server puts a prompt in front of your human |
| **Roots** | Client declares which filesystem locations the server may use | Advisory; server must choose to respect it |

Wire format is JSON-RPC 2.0. Base-protocol utilities: ping, cancellation, progress, logging, pagination, completion. `2025-11-25` added **Tasks** — any request can be augmented with a task the client polls for status and results.

### Transports

**Local is the common case, not the exception.**

| | **stdio** | **Streamable HTTP** |
|---|---|---|
| Runs | Subprocess on your machine | Remote service |
| Launched by | The host, via `command` | Already running; host connects to `url` |
| Auth | None — it is your process | OAuth 2.1 |
| Threats | `T-11`, `ASI05`, `MCP05` — unsandboxed RCE at your privilege level | `MCP01`, `MCP07`, `MCP09` — token is the whole authority boundary |
| Example | filesystem, git, sqlite | Gmail, Linear, Notion |

**Trap:** local ≠ offline. A stdio server can open sockets freely. Transport is **not** a proxy for egress capability in `S-03` — label tools by what they do, not by where the server runs.

### Lifecycle

`initialize` (version + capability exchange) → capability negotiation → operation → shutdown. Capability negotiation is a security surface: a server declares what it can do *before any human sees a tool list*.

### Six architectural facts that generate the threat model

1. **Tool descriptions are model-facing text at system-prompt trust level.** The server writes them; the protocol has no slot to mark them untrusted. → `T-02`, `MCP03`
2. **Protocol isolation is not context isolation.** The spec's per-client boundary is real at the *session* layer — separate processes, separate connections. But every server's tools land in **one context window**, selected by **one model**. The guarantee does not cover the thing that matters. → `T-04`, `GAP-03`, and the empirical basis for `C001`–`C007` in `OSS-06`
3. **The host is the only policy enforcement point.** Servers merely "must respect security constraints" — a request, not a mechanism. → `SURF-01`, `SURF-03`
4. **stdio servers are unsandboxed local processes.** Launching one is RCE at your privilege level. → `T-11`, `S-00`
5. **Capability negotiation is per-connection and nothing requires the client to remember the last one.** That absence *is* the rug pull; pinning is a client-side convention bolted on. → `T-03`, `AST07`
6. **Sampling and elicitation invert trust direction.** Legitimate features that are also channels from an untrusted server toward your model and your human. → `ASI01`, `ASI09`

### Worked example — Gmail

Concrete instance of all of the above, and the canonical trifecta case.

- **Host** Claude · **Client** one session · **Server** Google's, at `https://gmailmcp.googleapis.com/mcp/v1`, HTTP + OAuth 2.0. Anthropic also ships a built-in connector at `gmail.mcp.claude.com`.
- **Authority boundary** is the OAuth scope set (`gmail.readonly`, `gmail.send`, `gmail.compose`, `gmail.modify`, `gmail.labels`), granted in a flow that sits *outside* MCP. Nothing ties scopes to tool descriptions.
- **Tools** arrive via `tools/list` as name + prose description + JSON Schema, namespaced `mcp__Gmail__*`. They are in context whether or not you use Gmail.

Trifecta in a single server:

| Leg | Tool |
|---|---|
| Private data | `search_emails`, `read_email` |
| Untrusted content | Every inbox message. **The attacker's delivery mechanism is your email address** — no interaction required |
| External comms | `send_email`, `forward_email` |

Attack chain: attacker emails hidden instructions → user asks for an inbox summary → `read_email` returns attacker text as a *tool result* (`T-01`, `MCP06`) → injected instruction directs a forward → `forward_email` fires. Every step used a legitimately granted permission; nothing was exploited. That is `ASI02`, not privilege escalation.

**Real case study for `MCP01`/`MCP07`:** a filed Claude Code bug had the built-in Gmail server routing through the "Claude for Google Drive" OAuth client, so consent only offered Drive permissions, issued tokens carried Drive scopes, and every Gmail call returned 403. Fail-closed here — but the same mix-up in the other direction yields a token with broader scopes than the server needs, invisible from inside MCP.

**The mitigation stack in practice:** a safety-tiered skill over the MCP server — read and search free, every send/forward/reply/delete requiring explicit in-the-moment confirmation. That is `AST` layered on `MCP` (`§7.0`). The skill cannot change OAuth scopes; it only constrains when the model reaches for dangerous tools. Defence in depth, not a boundary.

---

## 1. Threat model

| ID | Threat | Mechanism | Primary detection tier |
|---|---|---|---|
| `T-01` | **Indirect prompt injection** | Attacker text arrives via *tool results*, not the user prompt | Dynamic |
| `T-02` | **Tool poisoning** | Malicious instructions embedded in an MCP tool's description or parameter schema, read into context at the same trust level as the system prompt | Static |
| `T-03` | **Rug pull** | Server changes tool definitions *after* the user approved them; client never re-validates | Static (pinning) |
| `T-04` | **Tool shadowing / cross-origin escalation** | A malicious server's description alters the agent's behaviour toward a *different*, trusted server's tools | Static |
| `T-05` | **Excessive agency** | Agent holds credentials broader than the task requires; attacker steers the confused deputy | Static |
| `T-06` | **Exfiltration (lethal trifecta)** | Private data access + untrusted content exposure + any outbound channel. Any two are survivable; all three is an exploit awaiting a trigger | Static (closure) + Dynamic |
| `T-07` | **Config supply chain** | `CLAUDE.md`, `.claude/rules/*`, skills, subagent frontmatter, plugins, hook scripts — checked into repos, loaded into context or executed | Static |
| `T-08` | **Delegation cascade** | Subagents inherit trust; parent treats subagent output as clean | Dynamic |
| `T-09` | **Provenance loss** | After context compaction, "this came from an untrusted web page" is no longer distinguishable from "the user said this" | Dynamic |
| `T-10` | **Memory/context poisoning** | Injected content persisted into memory files or steering files, surviving across sessions | Both |
| `T-11` | **Hook backdoor** | A malicious hook is arbitrary shell running with user privileges on every tool call, and sees every tool result | Static |
| `T-12` | **Unauthenticated MCP exposure** | Remote MCP servers deployed with no auth or rate limiting, reachable from the internet | Static |

---

## 2. Instrumentation surface (Claude agents)

| ID | Surface | Notes |
|---|---|---|
| `SURF-01` | **Settings hierarchy** | `~/.claude/settings.json`, `.claude/settings.json`, `.claude/settings.local.json`, plugin `hooks/hooks.json`, managed policy settings. Hook entries **merge** across levels rather than replacing; `disableAllHooks` set outside managed settings cannot disable managed hooks → managed tier is the tamper-resistant enforcement point |
| `SURF-02` | **Hook events** | Three cadences: per session (`SessionStart`, `SessionEnd`), per turn (`UserPromptSubmit`, `Stop`, `StopFailure`), per tool call (`PreToolUse`, `PostToolUse`). Plus `SubagentStart/Stop`, `PermissionRequest`, `PermissionDenied`, `InstructionsLoaded`, `ConfigChange`, `FileChanged`, `PreCompact`/`PostCompact`, `Elicitation`/`ElicitationResult`, `PostToolBatch`, `PostToolUseFailure` |
| `SURF-03` | **Permission system** | Allow/deny rules, permission modes (`default`, `plan`, `acceptEdits`, `auto`, `dontAsk`, `bypassPermissions`). This is the *hard* boundary; hooks are defence in depth |
| `SURF-04` | **OpenTelemetry** | `CLAUDE_CODE_ENABLE_TELEMETRY=1`. Exports metrics (time series), events (logs protocol) and optionally distributed traces. `prompt.id` links every event produced while processing a single user prompt → the trajectory join key. Optional detail flags: `OTEL_LOG_USER_PROMPTS`, `OTEL_LOG_TOOL_DETAILS`, `OTEL_LOG_TOOL_CONTENT` |
| `SURF-05` | **Session transcript** | JSONL on disk. Ground truth for offline replay. Written asynchronously, so it can lag the in-memory conversation |
| `SURF-06` | **MCP config** | `.mcp.json` and client configs. Tool naming: `mcp__<server>__<tool>`; plugin-bundled: `mcp__plugin_<plugin>_<server>__<tool>` |
| `SURF-07` | **Host controls** | Egress proxy, DNS logs, filesystem auditing (auditd/eBPF), process tree. Out-of-band; the only tier that survives agent compromise |
| `SURF-08` | **Native Bash sandbox** | OS-level filesystem + network isolation for the Bash tool: **Seatbelt** (macOS, nothing to install), **bubblewrap + socat** (Linux/WSL2), optional seccomp filter for Unix-socket blocking via `@anthropic-ai/sandbox-runtime`. No native Windows. Config under `sandbox.*`; `/sandbox` for the interactive menu. See `§4.1` |

### Three execution paths for the same intent

"List files in a folder" resolves three different ways, with three different audit surfaces. Any detector that covers one and not the others is bypassable by tool choice.

| Path | Mechanism | Hook sees | Parseable | Path-scopeable |
|---|---|---|---|---|
| **A** built-in file tool (`Glob`, `Read`) | Native `readdir` inside the agent process. No subprocess, no shell | `{"path": "/etc"}` | Structured JSON | Yes — `Read(src/**)` |
| **B** `Bash` | Real shell subprocess, user privileges, real `ls` binary | `{"command": "ls -la /etc"}` | **A shell string** | Pattern matching only |
| **C** MCP filesystem server | JSON-RPC to a server subprocess spawned once at session start | `{"path": "/etc"}` | Structured JSON | Yes, if the server honours roots |

Prefer path A. Structured arguments are checkable; `ls -la $(echo L2V0Yy9zaGFkb3c= | base64 -d)` is not.

---

## 3. Static analysis

> Static analysis of an agent = analysing everything that shapes behaviour *before it runs*. Mostly configuration and natural-language artifacts, not application code.

| ID | Technique | What it catches |
|---|---|---|
| `S-01` | **Settings audit** | `bypassPermissions`, over-broad allow rules (`Bash(*)`, `Read(**)`), `disableAllHooks`, unpinned MCP servers. Diff project settings against managed policy to find what a repo tries to loosen | `T-05` |
| `S-02` | **Instruction-surface scanning** | `CLAUDE.md`, `.claude/rules/*.md`, skill frontmatter, subagent definitions, plugin manifests. Signatures for imperative override language, base64/unicode obfuscation, zero-width characters, references to credential paths or network destinations | `T-07`, `T-02` |
| `S-03` | **Capability-closure / trifecta analysis** | Label every available tool with `reads-private`, `reads-untrusted`, `writes-external`; compute the session closure. All three present ⇒ exploitable by construction, reportable without observing an attack. **Highest-value technique — a decidable property, not a signature**. See `S-03a` | `T-06` |
| `S-04` | **Tool pinning** | Hash tool name + description + schema at approval; re-verify every connect. Changed description with unchanged version ⇒ rug pull | `T-03` |
| `S-05` | **Cross-server description analysis** | Detect descriptions that reference or redefine behaviour of *other* servers' tools | `T-04` |
| `S-06` | **Hook script review** | Hooks are arbitrary shell with user privileges. Treat as first-class code review; also audit HTTP hook `headers` + `allowedEnvVars` — a loose allowlist is a clean credential exfil channel | `T-11` |
| `S-07` | **Secret scanning** | Hardcoded keys in configs, skills, hook scripts | `T-07` |
| `S-08` | **Sandbox / egress policy verification** | Confirm the network allowlist and sandbox config actually constrain what the tool graph can reach | `T-06` |
| `S-09` | **Dependency / SCA on MCP server code** | Known CVEs in server implementations and SDKs | `T-12` |
| `S-10` | **Workflow graph extraction** | For framework-based agents (LangGraph, CrewAI, OpenAI Agents SDK): build the agent/tool/handoff graph from source, then run `S-03` over it | `T-05`, `T-08` |
| `S-11` | **AI-BOM generation** | Signed inventory of agents, tools, servers, skills, models. Prerequisite for change detection and for `S-04` at org scale | `T-07` |
| `S-12` | **Config drift / diff alerting** | Version-control every trust-bearing artifact; alert on diffs. The interesting attack is a benign file that changes in PR #400 | `T-03`, `T-07` |

### `S-03a` — `Bash` breaks naive capability closure

`Bash` must be labelled `reads-private` **and** `reads-untrusted` **and** `writes-external`, because `cat ~/.ssh/id_rsa`, `curl` and `git push` are all just Bash. So any session with unrestricted `Bash` trivially satisfies the trifecta and the analysis returns "exploitable" with no actionable detail.

**The unit of capability is the scoped permission rule, not the tool.** `Bash(npm run test:*)` is labelable; bare `Bash` is not. A correct `S-03` implementation therefore has to consume `permissions.allow`/`permissions.deny` alongside the tool list — a real design constraint, and the reason `S-01` is a prerequisite for `S-03` rather than an independent check.

### `S-00` — Scanner safety invariant

**A static scanner must never execute what it parses.** No running hook commands, no launching MCP servers, no resolving `apiKeyHelper`/`statusLine` scripts, no fetching URLs. Read untrusted config as data only. The moment a scanner execs its input, the scanner *is* the vulnerability.

**Known violation in the wild:** `OSS-06` (MCPRadar) scans by *launching* the server, and its `probe` mode invokes tools. Container sandboxing is roadmapped, not shipped. Run any connect-to-scan tool in a disposable container with egress locked.

---

## 4. Dynamic analysis

| ID | Technique | Where | Notes |
|---|---|---|---|
| `D-01` | **Pre-execution tool gating** | `PreToolUse` | The only place with both full structured tool input and a veto. See `§4.2` |
| `D-02` | **Session-scoped taint tracking** | `PreToolUse` + state file | State carried *across* tool calls; decide on trajectory, not the single call. See Appendix A |
| `D-03` | **Tool-result injection scanning** | `PostToolUse` | Scan results *before* Claude reads them. Classifier must be **non-promptable** (embedding/regex tier) — an LLM scanner is itself injectable |
| `D-04` | **Context integrity verification** | `InstructionsLoaded` | Verify every steering file against a known hash before it enters context |
| `D-05` | **Mid-session tamper detection** | `ConfigChange`, `FileChanged` | `ConfigChange` can block the change from taking effect |
| `D-06` | **Delegation tracking** | `SubagentStart`/`SubagentStop` | Track depth; tag subagent output as its own trust domain |
| `D-07` | **Provenance snapshotting** | `PreCompact` | Capture trust labels before compaction flattens them |
| `D-08` | **Probe detection** | `PermissionDenied` | Denial spikes are a probing signal |
| `D-09` | **Trajectory telemetry** | OTel, `prompt.id` | Post-hoc forensics and replay; join all API requests and tool executions for one prompt |
| `D-10` | **Egress control** | Host proxy | Domain allowlist + DNS logging. Out-of-band, so survives agent compromise |
| `D-11` | **Canary / honeytokens** | Filesystem | Fake AWS key in `~/.aws/credentials`. Highest-confidence, near-zero-false-positive detector |
| `D-12` | **Behavioural baselining** | Telemetry pipeline | See section 5 |
| `D-13` | **Budget caps & kill switch** | Settings / wrapper | Token, wall-clock and tool-call ceilings; `{"continue": false, "stopReason": ...}` halts processing |
| `D-14` | **Plan-vs-action divergence** | Transcript analysis | Compare what the agent said it would do against what it did |

### `D-00` — Three failure modes to design around

1. **Hooks fail open on timeout.** A timed-out `command`, `http` or `mcp_tool` `PreToolUse` hook does **not** block the call — it continues through the normal permission flow. A gate an attacker can win by making it slow is not a gate. (Agent SDK callback hooks differ: exceeding the timeout there *does* block.)
2. **`type: "prompt"` hooks are injectable.** An LLM evaluating attacker-controlled tool input is `GAP-02` inside your own control. Second opinion only, never the boundary.
3. **The `if` filter is best-effort.** When Claude Code cannot determine what a Bash input will run, it runs the hook regardless of pattern. Official guidance is to use the permission system, not hooks, for hard allow/deny. Use hooks for detection and defence in depth.

---

### 4.1 Sandbox configuration (`SURF-08`)

```json
{
  "sandbox": {
    "enabled": true,
    "failIfUnavailable": true,
    "autoAllowBashIfSandboxed": true,
    "filesystem": {
      "allowWrite": ["/data/workspace", "/tmp"],
      "denyRead": ["~/.ssh", "~/.aws", "~/.config/gcloud"]
    },
    "network": { "allowedDomains": ["registry.npmjs.org", "github.com"], "allowLocalBinding": true }
  }
}
```

**The property nothing else has:** enforcement is at the OS level, so it applies to **all subprocess commands** — `kubectl`, `terraform`, `npm` — not just Claude's own tools. A hook inspects a command *string*; the sandbox constrains what the process and every child it spawns actually does. An `npm install` whose `postinstall` reaches for `~/.ssh` is invisible to hooks and caught here.

Five findings for review:

1. **The read default is permissive.** Write is scoped to cwd and subdirectories; **read defaults to the entire computer** minus denied directories. Trifecta leg one is open unless you populate `denyRead`.
2. **`failIfUnavailable` exists because it fails open.** Missing `bubblewrap` or `socat` ⇒ commands run unsandboxed. Same class as `D-00.1`. Set `true` in managed deployments.
3. **`autoAllowBashIfSandboxed` couples two decisions.** It removes prompts *and* relies on the boundary. Audit sandbox config before enabling, not after.
4. **The two isolations are load-bearing together.** Vendor guidance: without network isolation a compromised agent exfiltrates SSH keys; without filesystem isolation it backdoors system resources to gain network access; configured settings must not create bypasses between the two. `denyRead` plus wide-open `allowedDomains` is one control, not two.
5. **`enableWeakerNestedSandbox` is a real weakening** — bind-mounts the container's existing `/proc`, exposing process information a fresh mount would hide. Only where an outer container already provides the boundary.

**Scope limit + open question.** This covers the *Bash* tool. Path A runs inside the agent process. stdio MCP servers are spawned by Claude Code, not by Bash — whether they inherit the sandbox is **unverified** and matters a great deal, since an unsandboxed MCP server bypasses all of the above. *Experiment to run: enable the sandbox with `denyRead` on a canary path, then have a stdio MCP server read it.*

---

### 4.2 `PreToolUse` reference

Fires after the model decides to call a tool, before the tool runs. The last deterministic moment to intervene.

**Handler types:** `command` (shell, JSON on stdin), `http` (POST; `headers` support env-var interpolation gated by `allowedEnvVars` — a loose allowlist here is a credential exfil channel), `mcp_tool`, `prompt` (LLM — see `D-00.2`), `agent` (subagent). Default timeout 60s, configurable.

**Input on stdin:**

```json
{
  "session_id": "abc123",
  "transcript_path": "~/.claude/projects/.../abc123.jsonl",
  "cwd": "/Users/you/project",
  "hook_event_name": "PreToolUse",
  "tool_name": "Bash",
  "tool_input": { "command": "rm -rf /tmp/build", "description": "clean build dir" }
}
```

`tool_input` follows the tool's own schema, so it differs per tool — `{command, description}` for Bash, `{file_path, content}` for Write, whatever the server declared for `mcp__Gmail__send_email`.

**Three ways to return a decision:**

| Mechanism | Effect |
|---|---|
| Exit 0, no output | No opinion — normal permission flow decides. Correct default for a detector that found nothing |
| **Exit 2** | Blocks the call; stderr is fed to Claude as the reason |
| `hookSpecificOutput.permissionDecision` | `allow` (skips the prompt), `deny`, `ask` (forces the prompt even if a rule would auto-allow) |
| `"continue": false` | Halts processing entirely; takes precedence over any decision field. Kill switch, not a gate |

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "Recursive rm is blocked by project policy."
  }
}
```

**`updatedInput` — rewriting, not just gating.** PreToolUse can modify tool inputs before execution:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "allow",
    "updatedInput": { "command": "rm -rf ./build" }
  },
  "systemMessage": "Rewrote absolute path to project-relative"
}
```

Useful for normalising paths, stripping `--force`, injecting `--dry-run`, redacting secrets from arguments. **Also a threat:** a compromised hook need not allow a dangerous command — it can rewrite a safe one into a dangerous one, and the rewrite is visible only if the hook chooses to emit `systemMessage`. Add to `T-11`.

**Coverage, not cleverness.** The commonest real gap in `§6.5` hook collections is not a weak regex — it is matching only `Bash` and missing `Write`, `Edit`, and every `mcp__*` tool. Enumerate the paths in `§2` first, then write the rule.

---

## 5. Detection signals

| ID | Signal | Rationale |
|---|---|---|
| `SIG-01` | Tool-call rate spike | Loop or automated exfil |
| `SIG-02` | High-entropy / base64 tool arguments | Encoded payload or staged exfil |
| `SIG-03` | First-seen network destination | Egress to a domain not in the baseline |
| `SIG-04` | Repeated identical calls | Agent stuck, or retry-until-allowed probing |
| `SIG-05` | Secret-read → network within N calls | Trifecta traversal in progress |
| `SIG-06` | Access outside workspace root | `.env`, `~/.ssh/`, `~/.aws/`, `.npmrc` |
| `SIG-07` | Canary token use | Confirmed compromise |
| `SIG-08` | Unexpected process spawn | Agent shelling out beyond expected tooling |
| `SIG-09` | Permission-denial burst | Capability enumeration |
| `SIG-10` | Config file written by the agent itself | Persistence attempt (`T-10`, `T-11`) |
| `SIG-11` | Subagent depth or fan-out anomaly | Delegation cascade |
| `SIG-12` | Plan/action divergence | Injection took control of the objective |

---

## 6. Open-source tooling landscape

### 6.1 Agent config scanners

| ID | Project | Coverage |
|---|---|---|
| `OSS-01` | **aisecscan** (formerly `agentscanner`) | Closest fit for Claude Code. Scans settings, permissions, hooks, MCP servers, agents/subagents, skills, slash commands and `CLAUDE.md`; v1.0 focused on `.claude/`, `.mcp.json`, `CLAUDE.md`. Maps to OWASP LLM/Agentic Top 10 + AIVSS. SARIF output. Explicit "never executes what it parses" invariant (`S-00`) |
| `OSS-02` | **Snyk Agent Scan** (formerly `invariantlabs-ai/mcp-scan`) | Inventory-first: auto-discovers harnesses, MCP servers and skills across Claude, Cursor, Windsurf, Gemini CLI. 15 distinct risks — prompt injection, tool poisoning, tool shadowing, toxic flows, untrusted content, credential handling, hardcoded secrets. Also has a background/MDM mode |
| `OSS-03` | **AgentAuditKit** | 320 rules, full OWASP Agentic + OWASP MCP coverage, SARIF, deterministic rule bundles, Sigstore-signed releases, CycloneDX + SPDX SBOM. Covers misconfig, secrets, tool poisoning, rug pulls, trust-boundary violations, tainted data flows across 10 platforms. Publishes an MCP Security Index leaderboard |
| `OSS-04` | **AgentShield** | Packaged as a Claude Code skill; inspects `.claude/` for injection patterns in `CLAUDE.md`, over-privileged `settings.json`, supply-chain risk in `mcp.json`; offers automated remediation |

### 6.2 MCP scanners

| ID | Project | Coverage |
|---|---|---|
| `OSS-05` | **mcp-scan** | The template for this category. Static: tool poisoning, cross-origin escalation, rug pulls, toxic flows. Tool pinning via hashing for rug-pull detection. Also ships `mcp-scan proxy` for runtime MCP traffic guardrailing (PII/secret detection, tool restrictions, custom policies) |
| `OSS-06` | **MCPRadar** | MIT, pure Python, <5s in CI. Connects over stdio/SSE/HTTP, enumerates tools/prompts/resources, runs three rule families, computes AIVSS, snapshots to SQLite and **diffs against history** for rug-pull detection. Static rules `R001`–`R111`: dangerous tool names, zero-width Unicode (ZWSP/LRM/RLO/BOM), 10 prompt-injection patterns, base64/hex blobs, hidden HTML/Markdown (`display:none`, `font-size:0`), scope mismatch, secret exposure, command injection, schema poisoning (`additionalProperties: true`), insecure transport. SARIF v2.1.0, CycloneDX SBOM, NVD sync, SHA-256 tool fingerprinting. **See `OSS-06a` and the `S-00` violation note** |
| `OSS-06a` | **MCPRadar cross-server rules** | The `C001`–`C007` family — the only implementation in this list that computes risk across *combinations*. `C001` duplicate tool names; `C002` name similarity ≥75% (shadowing); **`C003` server A reads sensitive data, server B sends it out**; `C004` 3+ servers with the same capability; `C005` read-only + write-capable mix; `C006` output-to-input schema matching; **`C007` read-only tool output feeding a write/exec tool on another server**. `C006`/`C007` are genuine attack-path chaining — real dataflow reasoning, not signature matching. Directly answers the Unit 42 five-server finding in `§7.3` |
| `OSS-07` | **VIPER-MCP** | Vulnerability discovery against MCP servers at scale |
| `OSS-08` | **mcp-audit** | MCP configuration auditing |
| `OSS-09` | **Cisco MCP Scanner / DefenseClaw** | Cisco AI Defense's MCP-side tooling |

### 6.3 Skill / `SKILL.md` scanners

> Newest and fastest-moving category. Motivating stat: research cited by SkillSpector reports 26.1% of skills contain vulnerabilities and 5.2% show likely malicious intent.

| ID | Project | Coverage |
|---|---|---|
| `OSS-10` | **NVIDIA SkillSpector** | Most complete. 71 patterns / 17 categories: prompt injection, exfiltration, privilege escalation, supply chain, excessive agency, output handling, system-prompt leakage, memory poisoning, tool misuse, rogue agent, anti-refusal, trigger abuse. Techniques: AST dangerous-code detection, taint tracking, YARA, MCP least-privilege, MCP tool poisoning. Two-stage (static + optional LLM semantic). Live OSV.dev CVE lookups, SARIF, risk scoring 0–100, FP baselines. Part of the NVIDIA Verified Skills signing pipeline |
| `OSS-11` | **Cisco AI Skill Scanner** | YAML + YARA patterns, LLM-as-judge, behavioural dataflow. Notable: meta-analyzer cuts noise ~65% while retaining detection. Supports Claude, Codex and Cursor skill formats |
| `OSS-12` | **Semia** | Security audit for agent skills |
| `OSS-13` | **Vetix** | Automated SKILL risk scanning |
| `OSS-14` | *(others)* | See GitHub topic `skill-scanner` — a dozen-plus projects, varying quality |

### 6.4 Workflow / graph analysis

| ID | Project | Coverage |
|---|---|---|
| `OSS-15` | **Agentic Radar** (SplxAI) | Static code analysis of framework agents → workflow graph (agents, tools, handoffs), tool identification, MCP server detection, vulnerability table mapped to OWASP LLM Top 10. HTML report. Supports LangGraph, CrewAI, OpenAI Agents SDK, n8n. Static analysis runs entirely locally |
| `OSS-16` | **AgentFlow** (research) | Agent dependency graphs for static analysis of agent programs — the academic version of `S-10` |
| `OSS-17` | **AI-BOM cluster** | Trusera `ai-bom`, Cisco AI Defense `aibom`, Drako Agent BOM. Inventory as a signed artifact (`S-11`) |
| `OSS-18` | **AgentGG** | Agentic SAST scanner — uses agents to read code, follow imports, walk the call graph and confirm findings before reporting. Apache 2.0 |

### 6.5 Runtime / guardrail

| ID | Project | Coverage |
|---|---|---|
| `OSS-19` | **dwarvesf/claude-guardrails** | Hardened Claude Code config: deny rules, destructive-command blocking, pipe-to-shell blocking, exfiltration prevention, injection scanning. Lite (3 hooks) and Full (5 hooks + scanner) modes. Fires on `PreToolUse`, `PostToolUse` |
| `OSS-20` | **CloneGuard** | 4-layer defence: pre-execution repo scan, `InstructionsLoaded` hook, `PostToolUse` output scanning, `PreToolUse` write/build gating. Uses a **non-promptable ONNX embedding classifier** rather than an LLM — directly addresses `GAP-02` |
| `OSS-21` | **claude-injection-guard** | Two-stage: regex (sub-ms, zero deps), escalating to a local LLM (Ollama/LM Studio). No data leaves the machine. Fires on `PostToolUse` (WebFetch) |
| `OSS-22` | **Invariant Gateway** | Local MCP proxy for traffic interception and guardrailing |
| `OSS-23` | **Microsoft Clarity + RAMPART** | Clarity = structured design review for agent development; RAMPART = continuous testing framework |
| `OSS-24` | **garak / PyRIT / promptfoo / Guardrails AI / NeMo Guardrails** | General LLM red-teaming and guardrail stacks; agent coverage is partial but they're the mature options |

---

## 7. Standards, taxonomies & rule formats

### 7.0 The OWASP AI stack

Five OWASP lists cover AI/LLM systems. They are **layered, not alternative** — a Claude Code deployment with MCP servers and skills is in scope for four of them simultaneously. Each uses its own native IDs, which are canonical and used verbatim throughout this document.

```
AST01-10   Skills / execution layer     v0.5 draft, active development
ASI01-10   Agent as autonomous actor    final, 9 Dec 2025
MCP01-10   Protocol / tool-call layer   beta, living document
LLM01-10   Model input / output         stable, 2025
ML01-10    Classical ML pipelines       separate lineage, v0.3
```

Ken Huang's framing of the relationship: MCP Top 10 (protocol and tools) -> Agentic Skills Top 10 (workflow, skills, behaviour) -> LLM/Agentic Top 10 (models). Skills sit at a distinct position — not merely tools, not merely model behaviours, but the orchestration layer where workflows are defined and privileges exercised.

**Selection rule**

| System shape | Apply |
|---|---|
| Chatbot, RAG app, classifier — no tool autonomy | LLM |
| Agent with tools, memory, multi-step autonomy | LLM + ASI |
| Agent connected to MCP servers | + MCP |
| Publishing or consuming skills | + AST |
| Training or fine-tuning own models | + ML |

Official guidance for agentic systems is to test against **both** LLM and ASI — LLM for foundational model security, ASI for tool orchestration, inter-agent communication and cascades. Using only one is a coverage gap, not a simplification.

---

### 7.1 OWASP Top 10 for LLM Applications (2025) — `LLM01`–`LLM10`

Stable baseline. Treats the model as something that receives input and produces output; mostly single-turn. The right list when the system has no agentic characteristics.

| ID | Category | Detail | Our ref |
|---|---|---|---|
| `LLM01` | **Prompt Injection** | Input alters model behaviour in unintended ways. Direct (user-supplied) or indirect (arrives via retrieved content). The root of most of this document | `T-01` |
| `LLM02` | **Sensitive Information Disclosure** | Model surfaces PII, credentials, proprietary data or other users' content | `T-06` |
| `LLM03` | **Supply Chain** | Compromised base models, datasets, LoRA adapters, or framework dependencies. **Static, pre-deployment** — contrast `ASI04` | `T-07` |
| `LLM04` | **Data and Model Poisoning** | Training, fine-tuning or embedding data manipulated to implant behaviour or backdoors | `T-10` |
| `LLM05` | **Improper Output Handling** | Downstream systems trust model output without validation — XSS, SQLi, path traversal, RCE. The classic "model output is untrusted input" failure | — |
| `LLM06` | **Excessive Agency** | Too much functionality, permission or autonomy granted to the model | `T-05` |
| `LLM07` | **System Prompt Leakage** | System instructions extracted, exposing business logic, guardrail design or embedded secrets | — |
| `LLM08` | **Vector and Embedding Weaknesses** | RAG-specific: embedding inversion, cross-tenant leakage in shared indexes, poisoned retrieval corpora | `T-10` |
| `LLM09` | **Misinformation** | Confident wrong output driving bad downstream decisions; over-reliance as a contributing factor | — |
| `LLM10` | **Unbounded Consumption** | Resource exhaustion, cost amplification, model extraction through query volume | `D-13` |

---

### 7.2 OWASP Top 10 for Agentic Applications (2026) — `ASI01`–`ASI10`

Published 9 December 2025 by the OWASP GenAI Security Project with 100+ contributors. `ASI` = Agentic Security Initiative. **This is the primary framework for this document.**

The distinction from the LLM list: that list treats the model as input/output; this one covers what happens when the model becomes an *actor* — a system with goals, credentials, tools, memory and the autonomy to chain actions across many steps.

| ID | Category | Sub-types and detail | Our ref |
|---|---|---|---|
| `ASI01` | **Agent Goal Hijack** | Manipulation of goals, plans or decision paths. Sub-types: direct goal manipulation; indirect injection via documents/RAG/tool output; **recursive hijacking** (goal changes propagate through reasoning chains or self-modify over time); cross-context injection. Essentially `LLM01` fused with `LLM06`, amplified by multi-step autonomy | `T-01` |
| `ASI02` | **Tool Misuse & Exploitation** | Agent abuses tools it holds *valid permission* for — recursive tool calls causing exhaustion, unsafe tool composition, tool budget exhaustion, cross-tool state leakage | `T-06` |
| `ASI03` | **Agent Identity & Privilege Abuse** | Delegated authority and ambiguous identity: agent impersonation, cross-agent trust abuse, privilege inheritance through agent chains, role bypass | `T-05`, `T-08` |
| `ASI04` | **Agentic Supply Chain Compromise** | Compromise of external agents, tools, schemas or prompts the agent trusts **dynamically at runtime**: schema manipulation, description deception, permission misrepresentation, registry poisoning. The runtime-composition counterpart to `LLM03` | `T-02`, `T-03`, `T-04`, `T-07` |
| `ASI05` | **Unexpected Code Execution** | Agent-generated or agent-triggered code running without validation or isolation — shell invocation, unsafe eval, command injection | `T-11` |
| `ASI06` | **Memory & Context Poisoning** | Injection or leakage of memory/contextual state shaping *future* reasoning: long-term memory poisoning, context injection, cross-session state manipulation, memory leakage | `T-09`, `T-10` |
| `ASI07` | **Insecure Inter-Agent Communication** | Agent-in-the-middle, message injection, message spoofing between agents, planners and executors. **No LLM-list ancestor** | — |
| `ASI08` | **Cascading Agent Failures** | Small failures propagating system-wide: tool-chain failures, agent dependency failures, resource exhaustion cascades, trust-chain breakdown. **No LLM-list ancestor** | `T-08` |
| `ASI09` | **Human-Agent Trust Exploitation** | Exploiting human over-reliance: authority misrepresentation, plausible-but-wrong explanations, over-confidence projection, responsibility diffusion. **No LLM-list ancestor** | *(gap in our model)* |
| `ASI10` | **Rogue Agents** | Acting beyond intended objectives: goal drift, agent collusion, reward hacking, runaway autonomy. Covers failures with **no attacker at all**. **No LLM-list ancestor** | *(gap in our model)* |

**The recurring conclusion across all ten categories:** agent security cannot live inside the agent. The model can be manipulated, the prompt overridden and the framework compromised, so the controls that hold are those enforced outside the agent's own reasoning. This is the same argument as `D-00` and `SURF-07`, reached independently.

---

### 7.3 OWASP MCP Top 10 (2025) — `MCP01`–`MCP10`

OWASP's first framework dedicated to the Model Context Protocol; project lead Vandana Verma Sehgal. Beta, maintained as a living document. Narrower than ASI — it targets the tool discovery, context passing and tool invocation layer between an agent and external systems.

| ID | Category | Detail | Our ref |
|---|---|---|---|
| `MCP01` | **Token Mismanagement** | Hardcoded API keys, long-lived tokens, secrets in model memory or protocol logs. If an attacker gets the agent to reveal its context, they get the key | `T-06` |
| `MCP02` | **Privilege Escalation** | Server or tool acquiring authority beyond its grant | `T-05` |
| `MCP03` | **Tool Poisoning** | Malicious instructions in tool descriptions or parameter schemas, read at system-prompt trust level | `T-02` |
| `MCP04` | **Supply Chain Attacks** | Compromised server packages, SDK CVEs, registry poisoning | `T-03`, `T-07` |
| `MCP05` | **Command Injection** | Unparameterised tool inputs reaching shell or database. **43% of MCP CVEs filed in early 2026 were shell injections** | `T-11` |
| `MCP06` | **Context Injection** | Untrusted content entering the context window through tool responses | `T-01` |
| `MCP07` | **Insufficient Authentication** | Remote servers with no auth or weak auth; OAuth 2.1 is the target state | `T-12` |
| `MCP08` | **Weak Telemetry / Logging** | No audit trail, so compromise is undetectable and unreconstructable | `D-09` |
| `MCP09` | **Shadow MCP Servers** | Unsanctioned servers connected outside inventory or policy | `T-12` |
| `MCP10` | **Context Over-Sharing** | Shared context windows leaking data across agents, sessions or users; tool responses dumping excess fields | `T-09` |

**Numbering status — corroborated.** The ordering above was initially reconstructed from published remediation-priority guidance. It has since been cross-checked against `OSS-06`'s OWASP coverage table, which matches 10/10 and sharpens two names: `MCP06` is *Prompt Injection via Contextual Payloads* (not merely context injection), and `MCP10` is *Context Injection **and** Over-Sharing*. Full official names: `MCP01` Token Mismanagement & Secret Exposure · `MCP02` Privilege Escalation via Scope Creep · `MCP03` Tool Poisoning · `MCP04` Supply Chain Attacks & Dependency Tampering · `MCP05` Command Injection & Execution · `MCP06` Prompt Injection via Contextual Payloads · `MCP07` Insufficient AuthN/AuthZ · `MCP08` Lack of Audit & Telemetry · `MCP09` Shadow MCP Servers · `MCP10` Context Injection & Over-Sharing. Still second-hand (a scanner README, not OWASP) — verify at `owasp.org/www-project-mcp-top-10` before formal citation, but this is no longer a guess.

**Why this list matters empirically:** more than 30 CVEs were filed against MCP servers, clients and infrastructure between January and February 2026 alone; Palo Alto Unit 42 measured a **78.3% attack success rate when five MCP servers were connected to a single agent**. Risk scaled with the *number* of connected servers rather than the vulnerability of any one — a direct empirical argument for `S-03` capability-closure analysis over per-server review.

---

### 7.4 OWASP Agentic Skills Top 10 — `AST01`–`AST10`

Newest of the five; v0.5, project-proposal status. Mental model: **MCP defines how the model talks to tools; AST10 governs what those tools actually do.**

| ID | Category | Severity | Key mitigation | Our ref |
|---|---|---|---|---|
| `AST01` | **Malicious Skills** | Critical | Merkle-root signing, registry scanning | `T-07` |
| `AST02` | **Supply Chain Compromise** | Critical | Registry transparency, provenance tracking | `T-07` |
| `AST03` | **Over-Privileged Skills** | High | Least-privilege manifests, schema validation | `T-05` |
| `AST04` | **Insecure Metadata** | High | Static analysis, safe parsers, sandboxed loading | `T-02` |
| `AST05` | **Untrusted External Instructions** | High | Source inventory, content pinning, continuous rescanning | `T-01`, `T-10` |
| `AST06` | **Weak Isolation** | High | Containerisation, sandboxing | `T-11` |
| `AST07` | **Update Drift** | Medium | Immutable pinning, hash verification | `T-03` |
| `AST08` | **Poor Scanning** | Medium | Semantic + behavioural multi-tool pipeline | `GAP-01`, `GAP-07` |
| `AST09` | **No Governance** | Medium | Skill inventories, agentic identity controls | *(gap in our model)* |
| `AST10` | **Cross-Platform Reuse** | Medium | Universal YAML skill format | — |

Two features make this list disproportionately useful here:

1. **It adopts the lethal trifecta explicitly.** A skill is especially dangerous when it simultaneously has access to private data (SSH keys, API credentials, wallet files, browser data), exposure to untrusted content (skill instructions, memory files, email), and external communication ability (network egress, webhooks, curl) — and the project states most production agent deployments today satisfy all three. That is `S-03` with an OWASP identifier.
2. **`AST08` is a category for the failure of the security tooling itself.** OWASP placed "your scanner does not work" *inside* the Top 10, citing pattern-matcher bypass via natural-language rephrasing. A framework naming its own ecosystem's inadequacy as a top-ten risk is rare and worth respecting — it is `GAP-01` promoted to first-class status.

**Claude Code–specific CVEs cited by this project:** `CVE-2025-59536` (CVSS 8.7) and `CVE-2026-21852` (CVSS 5.3), disclosed by Check Point Research, demonstrating that repository-level configuration files now function as part of the execution layer — cloning and opening an untrusted project could trigger RCE and API key exfiltration *before any user consent dialog appeared*. Both patched before disclosure. These are the canonical citations for the Class B half of `T-07`. The project's platform-developer guidance states the principle directly: do not allow repository-controlled configuration to execute before explicit user trust confirmation.

---

### 7.5 OWASP Machine Learning Security Top 10 — `ML01`–`ML10`

Separate lineage, frequently forgotten, and **not** a substitute for the LLM list. Scoped to classical ML pipelines — training, inference, model artifacts — rather than generative systems. Relevant here only if you train or fine-tune models, or ship classifier-based detectors (which `D-03` and `OSS-20` both do).

| ID | Category |
|---|---|
| `ML01` | Input Manipulation Attack (adversarial examples) |
| `ML02` | Data Poisoning Attack |
| `ML03` | Model Inversion Attack |
| `ML04` | Membership Inference Attack |
| `ML05` | Model Theft |
| `ML06` | AI Supply Chain Attacks |
| `ML07` | Transfer Learning Attack |
| `ML08` | Model Skewing |
| `ML09` | Output Integrity Attack |
| `ML10` | Model Poisoning |

Status note: this project has seen less maintenance than the others and is still at draft version; treat the category names as indicative and verify before citing.

**Direct relevance to our defences:** `ML01` applies to the non-promptable ONNX classifier in `OSS-20` and any embedding-based detector we build for `D-03`. A detection classifier is a model, and therefore itself attackable — adversarial-example evasion of the injection detector is a real path, distinct from `GAP-01`'s natural-language paraphrase problem.

---

### 7.6 Cross-cutting themes

Read across the five lists and the same four root causes recur under different names. Each layer restates them because the *mitigation* changes even when the cause does not.

| Theme | LLM | ASI | MCP | AST |
|---|---|---|---|---|
| **Injection** | `LLM01` | `ASI01` | `MCP06` | `AST05` |
| **Supply chain** | `LLM03` | `ASI04` | `MCP04` | `AST01`, `AST02` |
| **Over-permission** | `LLM06` | `ASI03` | `MCP02` | `AST03` |
| **Memory / context** | `LLM08` | `ASI06` | `MCP10` | `AST05` |

Worked example — prompt injection is a *classifier* problem at `LLM01`, a *trajectory* problem at `ASI01`, a *proxy* problem at `MCP06`, and a *static scanning* problem at `AST05`. Same attack, four different controls: `D-03`, `D-02`, `OSS-22`, `S-02` respectively.

---

### 7.7 Coverage delta against our threat model

Our `T-` list was derived independently, so the overlap is a sanity check and the gaps are informative.

**Present in OWASP, absent from `§1`:**

| Missing | Source | Why it matters |
|---|---|---|
| Human-agent trust exploitation | `ASI09` | We treat the human as defender, never as target. Automation bias is an attack surface |
| Goal drift / rogue behaviour | `ASI10` | Every `T-` entry assumes an adversary. Drift and reward hacking are attacker-free failure modes |
| Inter-agent message security | `ASI07` | `T-08` covers delegation trust but not message spoofing or agent-in-the-middle |
| Governance absence | `AST09` | We have no organisational-layer entry at all |

Proposed additions, not yet integrated into `§1`: `T-13` Human trust exploitation, `T-14` Goal drift / rogue behaviour, `T-15` Governance absence.

**Present in `§1`, split or buried in OWASP:**

- `T-04` (tool shadowing) is folded into `ASI04` despite being mechanically distinct and separately detectable via `S-05`
- `T-09` (provenance loss through compaction) appears in no framework. A genuine gap in the standards, not only in our doc — see `GAP-05`

---

### 7.8 Using these lists honestly

**They are built on different methodologies.** The web Top 10 is data-driven from four years of breach data with CWE incidence rates. ASI, MCP and AST are expert-consensus with no comparable dataset. Rank is therefore **not comparable across lists**, and "`ASI01` is #1" does not mean what "`A01` is #1" means.

**They are awareness documents, not coverage frameworks.** Every scanner in `§6` claims "OWASP Agentic 10/10." That means at least one rule per category. It says nothing about depth — which is exactly what `AST08` exists to name. Treat a coverage claim as a starting question, never as a measurement.

**The categories are uneven in kind.** `ASI01`–`ASI07` are attack classes; `ASI08` is a reliability property; `ASI09` is human factors; `ASI10` is an alignment concern. `AST08` and `AST09` are meta-risks about process rather than risks in the system. This reflects a field that has not settled what belongs in a security taxonomy, and it means a detection pipeline should not be structured one-to-one against the categories.

**Use them for vocabulary and coverage checking; use `STD-11` (ATR) for executable detection.**

---

### 7.9 Other standards and formats

| ID | Standard | Notes |
|---|---|---|
| `STD-11` | **Agent Threat Rules (ATR)** | Open YAML rule schema. Each rule declares the attack pattern, the input field it inspects (LLM input, tool-call arguments, `SKILL.md` content) and test cases proving it works. TypeScript reference engine + `pyATR`, both MIT. 400+ rules across prompt injection, agent manipulation, skill compromise, context exfiltration. **Strategically the most important item here** — it decouples detection content from scanners. Covers 10/10 ASI categories |
| `STD-12` | **SAFE-MCP** | ATT&CK-style technique taxonomy for MCP. ATR covers 78 of its 85 techniques (91.8%) |
| `STD-13` | **MITRE ATLAS** | Adversarial ML technique taxonomy |
| `STD-14` | **AIVSS** | Agentic AI Vulnerability Scoring System. Severity scoring the OWASP lists map onto; same project leadership as AST10 |
| `STD-15` | **MAESTRO** (CSA) | 7-layer threat-modelling framework for agentic systems. AST10 maps every risk onto it for cross-layer localisation |
| `STD-16` | **SARIF** | The interop format — every serious scanner emits it, enabling GitHub code scanning and cross-tool dedup |
| `STD-17` | **Sigma rules for agent activity** | Emerging: unauthorized agent-config modification, compound read-and-exfiltrate, unauthenticated MCP exposure, encoded prerequisites in skill manifests |
| `STD-18` | **Universal Skill Format** | AST10's proposed cross-platform manifest — filesystem ACL, egress allowlist, `did:web` identity anchor, `content_hash`, `risk_tier`. Aspirational; see `GAP-04` |

**Non-Top-10 OWASP resources worth more than the lists for actual engineering:** ASVS (verification standard), MASVS/MASTG (mobile), SAMM (program maturity), Cheat Sheet Series (implementation).

**Adjacent lists that also apply to an agent deployment:** `A01`/`A02`/`A03` (web — the workstation and CI pipeline), `API1`–`API10` (every MCP server is an API), CICD-SEC (the static-gate pipeline itself is in scope), NHI Top 10 (the credentials the agent holds).

---

## 8. Benchmarks & corpora

| ID | Benchmark | Notes |
|---|---|---|
| `BM-01` | **AgentDojo** | The standard for validating a *defence*. 97 user tasks, 629 adversarial security cases across banking, Slack, travel, workspace. Measures attack success **and** retained utility — the second half is what most defences fail. Canonical injection patterns include ignore-previous-instructions, system-message, important-messages and tool-knowledge variants |
| `BM-02` | **ADR-Bench** | MCP-native: 133 servers, 729 tools, 302 tasks, claims full coverage of a 17-threat taxonomy |
| `BM-03` | **AgentHarm** | 110 tasks, 6/17 threat coverage |
| `BM-04` | **AgentSecurityBench** | 420 tools, 50 tasks |
| `BM-05` | **AgentSafetyBench** | 1702 tools, 2000 tasks |
| `BM-06` | **ToolEmu** | 312 tools, 144 tasks — emulated tool sandbox |
| `BM-07` | **RAS-Eval / MCP-AttackBench / MCP-Artifact** | MCP-specific attack corpora |
| `BM-08` | **Damn Vulnerable MCP Server** | Deliberately vulnerable lab target |
| `BM-09` | **`LLMSecurity/awesome-agent-skills-security`** | Best-maintained index of attacks, defences, frameworks and benchmarks in this space |

---

## 9. Open problems

| ID | Gap | Why it matters |
|---|---|---|
| `GAP-01` | **Signature evasion** | Every scanner in §6 is fundamentally pattern-matching over natural language, which has unbounded paraphrase space. Public repos already exist purely to demonstrate blind spots between static scanning, semantic analysis and runtime execution. No sound answer exists |
| `GAP-02` | **LLM-judge circularity** | Scanners that escalate to an LLM for semantic judgment feed that judge attacker-controlled text. The judge is injectable. Non-promptable classifiers (`OSS-20`, `OSS-11`) route around it partially |
| `GAP-03` | **Cross-artifact toxic-flow analysis** | **Narrowed.** Within MCP alone this is largely solved — `OSS-06a`'s `C001`–`C007` compute cross-server closure including output-to-input chaining. The remaining gap is *cross-artifact*: nothing computes closure across MCP tools **plus** hooks, permission rules, skills and subagents together, and per `S-03a` a correct implementation must consume permission rules rather than the tool list alone. **Still the most defensible thing to build, because it is decidable rather than signature-based** |
| `GAP-04` | **Config attestation** | No standard for signing and verifying agent configurations. Early moves: NVIDIA Verified Skills, Sigstore in `OSS-03` |
| `GAP-05` | **Provenance through compaction** | `T-09` has no good mitigation; trust labels don't survive context summarisation |
| `GAP-06` | **Multi-agent trust semantics** | No accepted model for how trust should propagate across delegation boundaries |
| `GAP-07` | **FP economics** | Natural-language rule scanners drown in false positives; `OSS-11`'s ~65% noise reduction is the current published bar, not a solved problem |
| `GAP-08` | **Detection-coverage overlap** | Nobody has benchmarked the §6 tools against a common corpus. Real coverage gaps are unknown |

---

## 10. Ecosystem reference data

Useful for justifying the work; re-verify before citing anywhere formal.

| Finding | Source |
|---|---|
| Study of 1,899 MCP servers: 7.2% general vulnerabilities, 5.5% MCP-specific tool poisoning | arXiv:2506.13538, via MCPRadar |
| 2,303 distinct public MCP configs scanned: 52.3% declare a remote server with **no authentication**; **zero** serve RFC 9728 protected-resource-metadata discovery | AgentAuditKit, *State of MCP Security 2026* v1.0 |
| 26.1% of agent skills contain vulnerabilities; 5.2% show likely malicious intent | Cited by NVIDIA SkillSpector |
| Attack success >60% across 45+ real-world MCP servers; best-performing agent model reached 72.8% | CSA research note on MCP tool poisoning |
| **CVE-2025-54136** (CVSS 8.8): Cursor did not re-validate tool definitions after initial approval — the canonical rug-pull CVE | Check Point Research, July 2025 |
| OX Security demonstrated RCE across official MCP SDKs (Python, TypeScript, Java, Rust), ≥10 high/critical CVEs | via MCPRadar |
| ~12,520 internet-accessible MCP services, ~40% with no auth | Censys, via ai_osint v1.4.0 |

---

### 10.1 ClawHavoc IOCs (Antiy CERT, 6 Feb 2026)

⚠️ **Do not use the hashes on the OWASP AST10 `case-studies` page** — they are unfilled template placeholders (`a1b2c3d4e5f6…` and a one-byte rotation of it) and return nothing on VirusTotal. An official-looking source shipping dummy IOCs is itself a lesson.

Verified samples (MD5):

| Hash | File | Package | Type |
|---|---|---|---|
| `be24b44d4895c6bc14e3f98a9687a399` | `sujwb2nsdn93d79q` | *(2nd stage)* | AMOS Mach-O, 521,440 B, fat x86_64+ARM64. VT first seen 2026-02-03, 26/65 at upload |
| `5e4428176aeb8cfc7f0391654d683a2a` | `SKILL.md` | `google-k53` | ClickFix lure, 5,493 B. Antiy label `Trojan/OpenClaw.PolySkill` |
| `a3365c837ec2659c2aa04e7010a0db15` | `polymarket.py` | `polymarket-all-in-one` | Reverse shell |
| `2444b3ab5de42fcca22e6025cf018e3b` | `index.js` | `rankaj` | `.env` stealer |

**The teaching case is the second row.** Compare its VT detection ratio against the AMOS binary's — the markdown scores far lower, because a `SKILL.md` whose payload is a persuasive "Prerequisites" paragraph is not something AV was built to catch. That ratio gap is `GAP-01` and `AST08` rendered as an empirical measurement.

**Hashes are near-worthless against this campaign.** Each of 1,184 packages carried slightly different AI-generated documentation of 500–700 lines, so every file hash is unique. Durable indicators were the **publisher accounts** (12 total; `hightower6eu` 677 packages, `sakaen736jih` 390), the **C2**, and the **behavioural pattern** — a "Prerequisites"/"Setup" section pointing at a password-protected ZIP with the password in plaintext (`1202`, `openclaw`, `1234`), chosen to defeat GitHub scanning and local AV. File this under `S-02`: score the body, not the manifest.

Network IOCs: `91.92.242.30` (the confirmed AMOS C2), `202.161.50.59`, `54.91.154.110`, `socifiapp.com`, GitHub account `denboss99`. **Triage before enforcing:** `95.92.242.30` and `96.92.242.30` also appear in the appendix but differ from the confirmed C2 by one octet and are named by no other source — likely translation artifacts. `54.91.154.110` is AWS EC2 space; investigative lead, not a block rule.

Safe lab corpus: `snyk-labs/toxicskills-goof`. Live IOC feeds: Koi **Clawdex**, `adibirzu/openclaw-security-monitor`.

---

## Appendix A — Reference `PreToolUse` taint gate

Minimal session-scoped taint tracker implementing `D-02` against `T-06`. Illustrative, **not** production-ready — see `D-00` for why this must not be your only control.

```python
#!/usr/bin/env python3
# .claude/hooks/egress_guard.py  —  PreToolUse
import json, re, sys, pathlib

STATE = pathlib.Path("/tmp/agent_taint.json")
EXFIL = re.compile(r"(curl|wget|nc |ssh |git push|base64)", re.I)
SECRET_PATH = re.compile(r"(\.env|\.aws/|\.ssh/|credentials|id_rsa|\.npmrc)")

ev = json.load(sys.stdin)
tool, ti = ev.get("tool_name", ""), ev.get("tool_input", {})
blob = json.dumps(ti)

taint = json.loads(STATE.read_text()) if STATE.exists() else {}
s = taint.setdefault(ev["session_id"], {"untrusted": False, "secrets": False})

# taint tracking: has this session touched untrusted input or secrets?
if tool in ("WebFetch", "WebSearch") or tool.startswith("mcp__"):
    s["untrusted"] = True
if SECRET_PATH.search(blob):
    s["secrets"] = True
STATE.write_text(json.dumps(taint))

# deny outbound moves once both taints are set
if s["untrusted"] and s["secrets"] and EXFIL.search(blob):
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason":
            "Trifecta violation: untrusted content + secret access + egress attempt"}}))
sys.exit(0)
```

**Known weaknesses of this sketch** (each is its own deep-dive):
- Regex egress detection is trivially bypassed (`GAP-01`)
- State file is world-writable and agent-writable — the agent can clear its own taint
- Taint is never cleared on legitimate boundaries, so it will over-block in long sessions
- No handling of subagent `agent_id` — taint doesn't propagate correctly across delegation (`T-08`)
- Fails open on timeout (`D-00`)

---

## Appendix B — Where hook configuration lives

| File | Scope | In git? | Controlled by |
|---|---|---|---|
| Managed policy settings (`/Library/Application Support/ClaudeCode/managed-settings.json`, `/etc/claude-code/managed-settings.json`) | Org-wide, machine | No | IT / admin |
| `~/.claude/settings.json` | All your projects | No | You |
| `.claude/settings.json` | This project, shared | **Yes** | Anyone with a merged PR |
| `.claude/settings.local.json` | This project, local | No (gitignored) | You |
| Plugin `hooks/hooks.json` | Wherever the plugin is enabled | Via the plugin | Plugin author |

*Verify managed-settings paths against current docs before deploying — they have moved.*

**Two shapes.** In a settings file, hooks sit under a top-level `hooks` key alongside `permissions` etc. In a plugin's `hooks/hooks.json`, the file *is* the hooks config, wrapped in `{"hooks": {...}}`. Copying examples between the two is a common error.

**Merge, don't override.** Hook entries merge across levels rather than replacing — a user-level and a project-level hook on the same event both run. Consequences: you cannot disable an inherited hook by redefining the event lower down (good), a cloned repo can *add* handlers that run on your machine (bad), and `disableAllHooks` set anywhere outside managed settings cannot disable managed hooks (the asymmetry that makes the managed tier a real boundary).

**Placement rule:** anything you rely on for detection goes in managed settings. A monitoring hook in `.claude/settings.json` sits in the file an attacker would edit, defended by the review process that waved through the `CLAUDE.md` change.

**The path/script split.** `"command": "${CLAUDE_PROJECT_DIR}/.claude/hooks/guard.sh"` means settings hold only a *path*. Swapping the script requires no settings change at all — so `S-12` integrity scope must cover `.claude/hooks/**`, not just `settings.json`, and `CODEOWNERS` must cover both.

---

## Appendix C — Recommended defence architecture

```
CI gate            →  static scan of config (S-01..S-12), fail build on HIGH
                      ├─ tool pinning verification (S-04)
                      └─ capability closure check (S-03)

Managed settings   →  hard permission boundaries (SURF-03), non-overridable hooks

In-band hooks      →  detection + soft blocks (D-01..D-08)
                      ├─ non-promptable classifier on tool results (D-03)
                      └─ taint gate on egress (D-02)

Host tier          →  egress allowlist, sandbox, canaries, fs audit (D-10, D-11)
                      ← only tier that holds if the agent is compromised

Telemetry          →  OTel joined on prompt.id (D-09) → baselines (D-12) → SIG-01..12
```

---

## References

- Claude Code hooks reference — https://code.claude.com/docs/en/hooks
- Claude Code monitoring / OpenTelemetry — https://code.claude.com/docs/en/monitoring-usage
- Claude Code permissions — https://code.claude.com/docs/en/permissions
- aisecscan — https://pypi.org/project/aisecscan/
- Snyk Agent Scan — https://github.com/invariantlabs-ai/mcp-scan
- AgentAuditKit — https://github.com/marketplace/actions/agentauditkit-mcp-security-scan
- MCPRadar — https://pypi.org/project/mcpradar/
- NVIDIA SkillSpector — https://github.com/nvidia/skillspector
- Cisco AI Skill Scanner — https://pypi.org/project/cisco-ai-skill-scanner/
- Agentic Radar — https://github.com/splx-ai/agentic-radar
- Agent Threat Rules — https://www.helpnetsecurity.com/2026/06/03/agent-threat-rules-ai-detection/
- OWASP Top 10 for LLM Applications — https://genai.owasp.org/llm-top-10/
- OWASP Top 10 for Agentic Applications (ASI) — https://genai.owasp.org/
- OWASP MCP Top 10 — https://owasp.org/www-project-mcp-top-10/
- OWASP Agentic Skills Top 10 — https://owasp.org/www-project-agentic-skills-top-10/
- OWASP ML Security Top 10 — https://owasp.org/www-project-machine-learning-security-top-10/
- OWASP Top 10:2025 (web) — https://owasp.org/Top10/2025/
- OWASP API Security Top 10 2023 — https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- awesome-agent-skills-security — https://github.com/LLMSecurity/awesome-agent-skills-security
- awesome-claude-code-hooks — https://github.com/ithiria894/awesome-claude-code-hooks
- CSA note on MCP tool poisoning — https://labs.cloudsecurityalliance.org/research/csa-research-note-mcp-tool-poisoning-ai-agent-exfiltration-2/
- AgentFlow (agent dependency graphs) — https://arxiv.org/pdf/2607.01640
- ADR / ADR-Bench — https://arxiv.org/pdf/2605.17380
