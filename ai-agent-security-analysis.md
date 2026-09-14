# AI Agent Security & Vulnerability Analysis

**Scope:** monitoring, detecting and analysing attacks against tool-using AI agents, anchored on Claude Code / Claude Agent SDK as the reference implementation.

**Status:** working document, v0.1
**Last updated:** 2026-09-09

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
| `STD-` | 7 | Rule format / taxonomy / standard |
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
| `SURF-07` | **Host controls** | Egress proxy, DNS logs, filesystem auditing (auditd/eBPF), process tree, sandbox. The only tier that survives agent compromise |

---

## 3. Static analysis

> Static analysis of an agent = analysing everything that shapes behaviour *before it runs*. Mostly configuration and natural-language artifacts, not application code.

| ID | Technique | What it catches |
|---|---|---|
| `S-01` | **Settings audit** | `bypassPermissions`, over-broad allow rules (`Bash(*)`, `Read(**)`), `disableAllHooks`, unpinned MCP servers. Diff project settings against managed policy to find what a repo tries to loosen | `T-05` |
| `S-02` | **Instruction-surface scanning** | `CLAUDE.md`, `.claude/rules/*.md`, skill frontmatter, subagent definitions, plugin manifests. Signatures for imperative override language, base64/unicode obfuscation, zero-width characters, references to credential paths or network destinations | `T-07`, `T-02` |
| `S-03` | **Capability-closure / trifecta analysis** | Label every available tool with `reads-private`, `reads-untrusted`, `writes-external`; compute the session closure. All three present ⇒ exploitable by construction, reportable without observing an attack. **Highest-value technique — a decidable property, not a signature** | `T-06` |
| `S-04` | **Tool pinning** | Hash tool name + description + schema at approval; re-verify every connect. Changed description with unchanged version ⇒ rug pull | `T-03` |
| `S-05` | **Cross-server description analysis** | Detect descriptions that reference or redefine behaviour of *other* servers' tools | `T-04` |
| `S-06` | **Hook script review** | Hooks are arbitrary shell with user privileges. Treat as first-class code review; also audit HTTP hook `headers` + `allowedEnvVars` — a loose allowlist is a clean credential exfil channel | `T-11` |
| `S-07` | **Secret scanning** | Hardcoded keys in configs, skills, hook scripts | `T-07` |
| `S-08` | **Sandbox / egress policy verification** | Confirm the network allowlist and sandbox config actually constrain what the tool graph can reach | `T-06` |
| `S-09` | **Dependency / SCA on MCP server code** | Known CVEs in server implementations and SDKs | `T-12` |
| `S-10` | **Workflow graph extraction** | For framework-based agents (LangGraph, CrewAI, OpenAI Agents SDK): build the agent/tool/handoff graph from source, then run `S-03` over it | `T-05`, `T-08` |
| `S-11` | **AI-BOM generation** | Signed inventory of agents, tools, servers, skills, models. Prerequisite for change detection and for `S-04` at org scale | `T-07` |
| `S-12` | **Config drift / diff alerting** | Version-control every trust-bearing artifact; alert on diffs. The interesting attack is a benign file that changes in PR #400 | `T-03`, `T-07` |

### `S-00` — Scanner safety invariant

**A static scanner must never execute what it parses.** No running hook commands, no launching MCP servers, no resolving `apiKeyHelper`/`statusLine` scripts, no fetching URLs. Read untrusted config as data only. The moment a scanner execs its input, the scanner *is* the vulnerability.

---

## 4. Dynamic analysis

| ID | Technique | Where | Notes |
|---|---|---|---|
| `D-01` | **Pre-execution tool gating** | `PreToolUse` | Returns `permissionDecision` (`allow`/`deny`/`ask`/`defer`) inside `hookSpecificOutput`; exit code 2 blocks regardless of JSON |
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

### `D-00` — Two failure modes to design around

1. **Hooks fail open on timeout.** A timed-out `command`, `http` or `mcp_tool` `PreToolUse` hook does **not** block the call — it continues through the normal permission flow. A gate an attacker can win by making it slow is not a gate. (Agent SDK callback hooks differ: exceeding the timeout there *does* block.)
2. **The `if` filter is best-effort.** When Claude Code cannot determine what a Bash input will run, it runs the hook regardless of pattern. Official guidance is to use the permission system, not hooks, for hard allow/deny. Use hooks for detection and defence in depth.

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
| `OSS-06` | **MCPRadar** | Tool poisoning, prompt injection, supply-chain rug pulls; GitHub Action; OWASP coverage mapping |
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

## 7. Rule formats, taxonomies & standards

| ID | Standard | Notes |
|---|---|---|
| `STD-01` | **Agent Threat Rules (ATR)** | Open YAML rule schema. Each rule declares the attack pattern, the input field it inspects (LLM input, tool-call arguments, `SKILL.md` content) and test cases proving it works. TypeScript reference engine + `pyATR`, both MIT. 400+ rules across prompt injection, agent manipulation, skill compromise, context exfiltration. **Strategically the most important item here** — it decouples detection content from scanners |
| `STD-02` | **SAFE-MCP** | ATT&CK-style technique taxonomy for MCP. ATR covers 78 of its 85 techniques (91.8%) |
| `STD-03` | **OWASP Agentic Top 10** | ATR covers 10/10. The common mapping target for every scanner above |
| `STD-04` | **OWASP Agentic Skills Top 10** | Newer, skill-ecosystem specific |
| `STD-05` | **OWASP Top 10 for LLM Applications** | The older baseline; still the default mapping in Agentic Radar |
| `STD-06` | **MITRE ATLAS** | Adversarial ML technique taxonomy |
| `STD-07` | **AIVSS** | Severity scoring for AI findings |
| `STD-08` | **MAESTRO** (CSA) | Threat-modelling framework for agentic systems |
| `STD-09` | **SARIF** | The interop format — every serious scanner emits it, enabling GitHub code scanning and cross-tool dedup |
| `STD-10` | **Sigma rules for agent activity** | Emerging: unauthorized agent-config modification, compound read-and-exfiltrate, unauthenticated MCP exposure, encoded prerequisites in skill manifests |

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
| `GAP-03` | **Cross-artifact toxic-flow analysis** | Nothing computes capability closure across the *entire* config surface at once — hooks + permissions + MCP tools + skills + subagents together. `S-03` at full scope. **Most defensible thing to build, because it's decidable rather than signature-based** |
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

## Appendix B — Recommended defence architecture

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
- awesome-agent-skills-security — https://github.com/LLMSecurity/awesome-agent-skills-security
- awesome-claude-code-hooks — https://github.com/ithiria894/awesome-claude-code-hooks
- CSA note on MCP tool poisoning — https://labs.cloudsecurityalliance.org/research/csa-research-note-mcp-tool-poisoning-ai-agent-exfiltration-2/
- AgentFlow (agent dependency graphs) — https://arxiv.org/pdf/2607.01640
- ADR / ADR-Bench — https://arxiv.org/pdf/2605.17380
