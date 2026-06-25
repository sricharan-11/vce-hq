# PRD: The Brain - Agent Swarm with Supervisor Orchestration and Blocklist-First Security

> **Module:** The Brain (Agent Orchestration)
> **Version:** B1.2
> **Last Updated:** 2026-06-23
> **Status:** Active
> **Parent PRD:** [PRD_main_vB1.2.md](./PRD_main_vB1.2.md) - Section 4.4
> **Lineage:** Rearchitected from [PRD_Brain_v1.2.md](./PRD_Brain_v1.2.md) (Version A — Allowlist Architecture)

---

## 0. Version B — What Changed in The Brain

> [!IMPORTANT]
> This document rearchitects the command validation pipeline from **allowlist-first** (Version A) to **blocklist-first** (Version B). The agent swarm topology, Supervisor loop, ReAct pattern, and Security Review are **unchanged**. Only the command gatekeeping layer is redesigned.

### The Core Principle

**Version A asks:** "Is this command in our list of approved commands?"
- If YES → allow. If NO → reject.

**Version B asks:** "Is this command in our list of blocked patterns?"
- If YES → reject. If NO → allow (with appropriate security gates based on risk signal).

There is **no master list of approved commands**. There is **no verb-to-tier classification table**. Instead, the system maintains only what it needs to block, and uses lightweight risk signals to route commands through the appropriate security gates.

### Summary of Changes

| Component | Version A | Version B |
|---|---|---|
| **Validation entry gate** | Tiered Allowlist (prefix match) — must match to proceed | Tiered Blocklist (pattern match) — must NOT match to proceed |
| **Risk classification** | Allowlist tier determines risk (which list matched?) | Risk Signal Heuristic — lightweight check for destructive/mutating keywords in the command itself |
| **Unknown commands** | Rejected (`NOT_ALLOWLISTED`) | **Allowed** — pass through blocklist, assessed by Risk Signal Heuristic |
| **Router fallback routing** | Scans full allowlist for alternatives | Understands blocklist constraints, agents are free to try any command |
| **Horizontal API Translation** | Maps script endpoints to allowlist tiers | Maps HTTP methods to risk signals; blocked endpoints are in the blocklist |
| **Maintenance model** | Add new prefixes to allowlist arrays (frequent, every new workload) | Add new patterns to blocklist (rare, only when new dangers emerge) |

---

## 1. Purpose

This PRD defines the detailed design of **The Brain** - the LangGraph-based agent swarm that performs incident analysis and remediation. It extends the architecture defined in `PRD_main_vB1.2.md` Section 4.4 by describing:

1. The **Intent Analyzer** - entry point for smart context via semantic RAG and graceful out-of-scope handling
2. The **Supervisor (Hierarchical Swarm) Pattern** - the Router operates as a cyclic, closed-loop orchestrator with cross-validation
3. The **ReAct (Reason + Act) loop** inside each specialist agent for live diagnostics
4. The **Blocklist-First Security Pipeline** — commands are allowed by default and only stopped by explicit block rules
5. The **OS Engineer's global SSH access** via `gcloud compute ssh`
6. The **Environment Discovery** module for runtime infrastructure probing and self-configuration

### Current Graph Topology

```
Supervisor Router <-> [OS Agent | Cloud Agent | FinOps Agent] (cyclic) -> Security Review -> END
```

The Supervisor Router formulates a theory, delegates one step at a time, reads agent outputs, cross-validates the findings against the original query, identifies gaps, and re-delegates. Agents report raw evidence to the Supervisor.

When agents attempt to execute commands, they go through the **Blocklist-First Security Pipeline**:
- **Stage 1:** Blocklist Gate — check against Global Blocklist + Mode Blocklist. If matched → REJECT.
- **Stage 2:** Risk Signal Heuristic — does the command contain destructive/mutating keywords? Tags a risk level for downstream gates. Does NOT reject.
- **Stage 3:** LLM Pre-Execution Security Gate — commands tagged as elevated risk are reviewed for ADR compliance & blast radius.
- **Stage 4:** HITL Approval — high-risk commands in Mode 3 require human approval.
- If no stage rejects → **EXECUTE**.

---

## 2. Problem This Solves

The original Version A architecture used **tiered allowlists** to classify commands. While effective, this approach:
- Required manual prefix additions for every new CLI tool, cloud service, or subcommand.
- Created a bottleneck where agents couldn't use valid diagnostic commands because they weren't in the allowlist.
- Made the Router's fallback routing dependent on a static, stale reference.
- Forced the team to maintain hundreds of prefix strings across OS, Cloud, and FinOps domains.

**Version B solves this by inverting the model:**
- **No approved-command lists exist.** Agents can formulate any command they believe will help diagnose or remediate.
- **Only dangerous patterns are listed.** The blocklist is the single source of truth for what's forbidden.
- **Risk signals, not classifications, drive security gates.** Instead of looking up a command in a tier table, the system checks for destructive/mutating keywords to decide whether to invoke the LLM Gate or HITL. A command that doesn't trigger any risk signal flows straight to execution.
- **New workloads just work.** A new GCP service, a new `kubectl` plugin, a new AWS CLI command — none of them require validator changes. They pass the blocklist (they're not dangerous) and execute.

---

## 3. Intent Analyzer & Smart Context

As the entry point to the swarm, the Intent Analyzer evaluates user queries to optimize the context window and handle out-of-scope requests gracefully.

### 3.1 Semantic Short-Term Memory (RAG for Conversations)
Instead of passing the entire bloated conversation history to the Supervisor, the Intent Analyzer uses semantic embeddings:
1. Embeds the incoming user query.
2. Performs a semantic search against a `conversation_vectors` table (via `sqlite-vec`) to retrieve the top historical turns.
3. Combines these semantic matches with the immediately preceding turns to ensure chronological continuity.
This approach guarantees relevant older context is retained while minimizing token consumption.

### 3.2 Graceful Irrelevant Query Handling
For queries completely outside the scope of infrastructure operations (`IRRELEVANT` intent), the system does not execute the specialist agents. Instead:
- The Intent Analyzer generates a polite, clarifying question attempting to map the user's query to a valid infrastructure concept.
- The graph routes directly to the Security Review node to output this clarifying question, allowing the user to pivot back to a valid topic.

### 3.3 Entity Resolution (Shorthand Mapping)
To improve operational accuracy, the Intent Analyzer automatically resolves partial or shorthand infrastructure names in user queries (e.g., mapping "abc" to "abc-dev-002-mumbai" or "cart" to "lowerground_cart_app"). It validates these shorthands against the auto-discovered `EnvironmentProfile` and outputs a `resolved_query`. This ensures that downstream agents (Cloud Engineer, OS Engineer) always execute commands against exact, fully qualified resource identifiers without requiring the user to type them perfectly.

## 4. Supervisor Router Architecture

### 4.1 The Supervisor Loop

The Supervisor Router operates as the "brain" of the swarm:
1. **Formulates a theory** about what the query requires
2. **Delegates one step** to the appropriate specialist agent
3. **Reads the agent's output** when it returns
4. **Cross-validates findings** against the original user query — checks for completeness and gaps
5. **Re-delegates** if evidence is incomplete
6. **Delegates to Security Review** only when fully satisfied

### 4.2 Blocklist-Aware Constraint Routing

In Version B, the Router does **not** carry a reference to "available commands" — because **all commands are available** unless blocked. When an agent reports that a command was rejected, the Router reads the rejection reason and understands the constraint:

1. **Global blocklist hit** (e.g., `"blocked: mkfs"`) → The operation is universally forbidden. The Router must find a fundamentally different diagnostic approach.
2. **Mode blocklist hit** (e.g., `"blocked in mode_1: 'restart' is a mutating verb"`) → The agent tried a write operation in read-only mode. The Router reformulates using a read-only approach (e.g., `systemctl status` instead of `systemctl restart`).
3. **Sanitization failure** (e.g., `"shell injection detected: subshell"`) → The Router instructs the agent to reformulate without pipes, subshells, or chaining.

The Router **re-delegates** with an explicit instruction to avoid the blocked pattern. It only finalizes (`security_review`) if there is truly no unblocked alternative.

This is fundamentally different from Version A, where the Router scanned a static allowlist for alternative prefixes. In Version B, the Router doesn't need a list — it just needs to know what's blocked and why.

---

## 5. Specialist Agent Tool Architecture

### 5.1 The ReAct (Reason + Act) Loop

Each specialist agent (OS Engineer, Cloud Engineer, FinOps Agent) operates in a bounded ReAct loop.

```
+---------------------------------------------------------------+
|             SPECIALIST AGENT (OS / Cloud / FinOps)            |
|                                                                |
|  1. RAG Retrieval                                              |
|                                                                |
|  2. LLM Reasoning (iteration 1)                               |
|     * Decision: Do I have enough data to diagnose?             |
|          +---- NO -> Formulate diagnostic command(s)           |
|                    |                                            |
|                    v                                            |
|  3. Blocklist-First Security Pipeline                          |
|     * Stage 1: Blocklist Gate (No LLM)                         |
|        - Check Global Blocklist → REJECT if match              |
|        - Check Mode Blocklist  → REJECT if match               |
|        - No match? → PASS (command is allowed)                 |
|     * Stage 2: Risk Signal Heuristic (No LLM)                  |
|        - Scan for destructive/mutating keywords                |
|        - Tag risk level: NONE / ELEVATED / CRITICAL            |
|        - Does NOT reject — only tags for downstream gates      |
|     * Stage 3: LLM Pre-Execution Security Gate                 |
|        - Risk NONE    → BYPASS (Execute Immediately)           |
|        - Risk ELEVATED → LLM checks ADRs & Blast Radius       |
|        - Risk CRITICAL → LLM checks + flags for HITL           |
|     * Stage 4: HITL (If CRITICAL risk in Mode 3)               |
|        - Pause ReAct loop and prompt user for approval         |
|     * Stage 5: Execute in sandbox & capture stdout/stderr      |
|          |                                                      |
|          v                                                      |
|  4. LLM Reasoning (iteration 2...N)                            |
|     * Analyze outputs -> produce final analysis or re-loop     |
+---------------------------------------------------------------+
```

### 5.2 Token Caching (Context Caching)
To optimize latency and cost, a `CacheManager` intercepts prompt construction for all specialized agents. By leveraging Gemini Context Caching (`langchain-google-genai`), the system caches the bulky, static portions of the prompt — namely the agent's system instructions and the `EnvironmentProfile` context. This ensures that during iterative ReAct loops, the LLM does not need to repeatedly re-process identical infrastructure context strings.

---

## 6. Phased Execution Modes & Blocklist Enforcement

The system runs under a global `VCE_EXECUTION_MODE` (`mode_1`, `mode_2`, `mode_3`).

### 6.1 The Blocklist is the ONLY Gatekeeper

There are no allowlists. There are no verb-to-tier classification tables. The blocklist is the single mechanism that prevents commands from executing. Everything else is about **risk-routing** (deciding which commands get extra scrutiny from the LLM Gate or HITL).

The blocklist has two layers:

1. **Global Blocklist** — patterns blocked in ALL modes, including Mode 3. These are universally dangerous operations that an autonomous agent should never execute.
2. **Mode Blocklist** — patterns blocked in specific modes only. In Mode 1, mutating and destructive verbs are blocked. In Mode 2, destructive verbs are blocked. In Mode 3, only the Global Blocklist applies.

### 6.2 Mode Blocklist — What Each Mode Blocks

#### Mode 1 (Read-Only Advisor) — Blocks mutating + destructive verbs

Any command containing these verbs (as the action verb, not as a substring in a resource name) is **blocked**:

**Mutating verbs (blocked in Mode 1 only):**
`start`, `stop`, `restart`, `update`, `modify`, `scale`, `set`, `apply`, `patch`, `edit`, `enable`, `disable`, `daemon-reload`, `link`, `rollout`, `chmod`, `chown`, `chgrp`

**Destructive verbs (blocked in Mode 1 and Mode 2):**
`create`, `delete`, `terminate`, `destroy`, `rm`, `rmdir`, `kill`, `killall`, `pkill`, `reboot`, `shutdown`, `poweroff`, `unlink`, `install`, `remove`, `purge`, `deallocate`

Any command whose action verb is **not** in either list → **allowed in Mode 1**. This includes all read-only operations AND any novel command the agent formulates, as long as it doesn't use a blocked verb.

#### Mode 2 (Read + Edit) — Blocks destructive verbs only

Only the destructive verb list above is blocked. Mutating verbs are unblocked and pass through to the LLM Gate for review.

#### Mode 3 (Full Access) — No mode-specific blocks

Only the Global Blocklist applies. All verbs (including destructive) are unblocked but must pass the LLM Gate and HITL.

### 6.3 Cloud Engineer — Mode Behavior

| Mode | What's Blocked | What's Allowed | Extra Security |
|------|---------------|---------------|----------------|
| **Mode 1** | Commands with mutating/destructive verbs (`stop`, `delete`, `scale`, etc.) | All read/list/describe/get commands + any novel read command | None — executes immediately |
| **Mode 2** | Commands with destructive verbs (`delete`, `terminate`, `create`, etc.) | All read commands + mutating commands (`stop`, `start`, `update`, etc.) | LLM Gate for mutating commands |
| **Mode 3** | Only Global Blocklist (`gcloud projects delete`, `terraform destroy`, etc.) | Everything except globally blocked patterns | LLM Gate + HITL for destructive commands |

### 6.4 OS Engineer — Mode Behavior

| Mode | What's Blocked | What's Allowed | Extra Security |
|------|---------------|---------------|----------------|
| **Mode 1** | Commands with mutating/destructive verbs + Global Blocklist | `ps`, `df`, `journalctl`, `ss`, any read-only utility | None — executes immediately |
| **Mode 2** | Commands with destructive verbs + Global Blocklist | All read commands + `systemctl restart`, `chmod`, `chown`, etc. | LLM Gate for mutating commands |
| **Mode 3** | Only Global Blocklist (`mkfs`, `fdisk`, `dd`, etc.) | Everything except globally blocked patterns | LLM Gate + HITL for destructive commands |

### 6.5 FinOps Agent — Mode Behavior

FinOps typically operates in Mode 1 (Read Only). In **Mode 3**, FinOps can detect severe consumption violations, but it **does not execute shutdowns directly**. Instead, it passes an instruction to the Supervisor, which delegates the shutdown to the Cloud Engineer (who executes the command through its own security pipeline).

| Mode | What's Blocked | What's Allowed | Extra Security |
|------|---------------|---------------|----------------|
| **Mode 1** | Commands with mutating/destructive verbs | `aws ce *`, `aws pricing *`, `gcloud billing * list/describe`, `az billing *`, `az consumption *`, any novel billing read command | None |
| **Mode 2** | Commands with destructive verbs | All read + `gcloud billing projects link`, etc. | LLM Gate |
| **Mode 3** | Only Global Blocklist | All billing operations including `unlink` | LLM Gate + HITL |

---

## 7. Command Validation Pipeline (Pre-Execution)

```
Agent formulates command
        |
        v
+-----------------------------------------------------+
|  Stage 1: BLOCKLIST GATE (No LLM)                    |
|                                                       |
|  1a. Global Blocklist check                           |
|      Does command match any globally blocked pattern? |
|      YES → REJECT (reason: "globally blocked: <pat>")|
|      NO  → continue                                  |
|                                                       |
|  1b. Mode Blocklist check                             |
|      Does command's action verb appear in the         |
|      current mode's blocked-verb list?                |
|      YES → REJECT (reason: "blocked in <mode>: verb")|
|      NO  → PASS                                      |
+-------+---------------------------------------------+
        |
        | Command is ALLOWED — it passed all blocklists
        v
+-----------------------------------------------------+
|  Stage 2: RISK SIGNAL HEURISTIC (No LLM)             |
|                                                       |
|  Scans the command for risk indicators to decide      |
|  which downstream security gate to invoke.            |
|  This stage NEVER rejects — it only tags.             |
|                                                       |
|  Risk NONE:                                           |
|    No destructive/mutating keywords detected.         |
|    → Skip LLM Gate, execute immediately.              |
|                                                       |
|  Risk ELEVATED:                                       |
|    Mutating keywords detected (start, stop, update,   |
|    chmod, scale, apply, etc.)                         |
|    → Route to LLM Gate.                               |
|                                                       |
|  Risk CRITICAL:                                       |
|    Destructive keywords detected (delete, kill, rm,   |
|    terminate, reboot, etc.) OR unknown binary/tool.   |
|    → Route to LLM Gate + flag for HITL.               |
+-------+---------------------------------------------+
        |
        v
+-----------------------------------------------------+
|  Stage 2.5: HORIZONTAL API TRANSLATION               |
|  (Only for raw scripts: curl, python)                 |
|                                                       |
|  Extracts HTTP methods + endpoints from script body.  |
|  - GET/HEAD/OPTIONS       → Risk NONE                 |
|  - POST (to known read*)  → Risk NONE                 |
|  - POST/PUT/PATCH         → Risk ELEVATED             |
|  - DELETE                 → Risk CRITICAL              |
|  - Endpoints checked against Global Blocklist          |
|                                                       |
|  *Small curated list of read-only POST endpoints      |
|   (e.g., GraphQL queries, Cloud Monitoring queries)   |
+-------+---------------------------------------------+
        |
        v
+-----------------------------------------------------+
|  Stage 3: LLM PRE-EXECUTION SECURITY GATE            |
|                                                       |
|  Risk NONE     → BYPASS (execute immediately)         |
|  Risk ELEVATED → LLM reviews:                         |
|    - Tenant ADR compliance                            |
|    - Blast radius assessment                          |
|    - Cross-service dependency check                   |
|  Risk CRITICAL → LLM reviews (deeper analysis) +     |
|    - Flags `requires_hitl` if in Mode 3               |
+-------+---------------------------------------------+
        |
        v
+-----------------------------------------------------+
|  Stage 4: HITL APPROVAL                               |
|                                                       |
|  Only triggered when:                                 |
|  - Risk CRITICAL + Mode 3 + LLM flags requires_hitl  |
|  Pauses execution, prompts user in chat UI.           |
|  User approves → EXECUTE. User rejects → ABORT.      |
+-------+---------------------------------------------+
        |
        v
     EXECUTE in sandbox, capture stdout/stderr
```

### Key Difference from Version A

In Version A's pipeline, Stage 1 was "Tiered Allowlist Classification" — if the command didn't match an allowlisted prefix, it was **rejected immediately**. The rest of the pipeline never ran.

In Version B, **Stage 1 is pure blocklist**. If the command doesn't match a blocked pattern, it **proceeds**. There is no "not in list → reject" path. The Risk Signal Heuristic (Stage 2) only decides how much scrutiny to apply — it never rejects.

### 7.1 Global Blocklist — Always-Blocked Patterns

These patterns are rejected in **all modes**, including Mode 3. They represent universally dangerous operations that should never be executed by an autonomous agent.

#### OS Domain Global Blocklist
| Pattern | Rationale |
|---|---|
| `mkfs` | Filesystem formatting — irreversible data destruction |
| `fdisk` | Partition table manipulation |
| `parted` | Partition editor |
| `dd ` (with space — avoid matching `add`) | Raw disk I/O — can destroy volumes |
| `vi`, `vim`, `nano`, `emacs`, `ed` | Interactive editors — agents cannot interact with TUI |
| `> /dev/sd*`, `> /dev/nvme*` | Direct writes to block devices |
| `:(){ :|:& };:` and variants | Fork bombs |
| `shred` | Secure file deletion — irreversible |
| `wipefs` | Filesystem signature wiper |
| `crontab -e`, `crontab -r` | Cron manipulation — persistence risk |
| `useradd`, `userdel`, `usermod` | User account manipulation |
| `passwd` | Password changes |
| `visudo`, `sudoers` | Privilege escalation configuration |
| `iptables -F`, `iptables -X`, `nft flush` | Firewall rule flush — network exposure |
| `mount` (as action verb, not in `/proc/mounts` context) | Filesystem mount manipulation |
| `swapoff`, `swapon` | Swap manipulation |

#### Cloud Domain Global Blocklist
| Pattern | Rationale |
|---|---|
| `--force` combined with destructive verbs | Bypasses confirmation prompts |
| `--quiet` combined with destructive verbs | Suppresses safety prompts |
| `--no-wait` combined with destructive verbs | Fire-and-forget destructive ops |
| `gcloud projects delete` | Entire project deletion |
| `aws organizations close-account` | Account closure |
| `az group delete` | Resource group deletion (cascading) |
| `kubectl delete namespace` | Namespace deletion (cascading) |
| `terraform destroy` | Full infrastructure teardown |
| `pulumi destroy` | Full infrastructure teardown |

### 7.2 Risk Signal Heuristic — Implementation

The Risk Signal Heuristic is a **lightweight, deterministic scanner** that tags commands with a risk level. It does NOT reject commands — it only decides how much downstream scrutiny to apply.

**How it works:**

1. **Extract the action verb** from the command by stripping the CLI namespace prefix (`gcloud compute instances`, `aws ec2`, `az vm`, `kubectl`, `systemctl`). The first remaining token is the action verb.
2. **Check against two keyword sets:**
   - **Destructive keywords** → `delete`, `terminate`, `destroy`, `rm`, `rmdir`, `kill`, `killall`, `pkill`, `reboot`, `shutdown`, `poweroff`, `unlink`, `purge`, `deallocate`
   - **Mutating keywords** → `start`, `stop`, `restart`, `update`, `modify`, `scale`, `set`, `apply`, `patch`, `edit`, `enable`, `disable`, `daemon-reload`, `link`, `rollout`, `chmod`, `chown`, `chgrp`, `install`, `remove`, `create`
3. **Tag the risk level:**
   - Verb matches destructive keyword → **Risk CRITICAL**
   - Verb matches mutating keyword → **Risk ELEVATED**
   - Verb matches neither → **Risk NONE** (execute immediately after blocklist pass)
   - Unknown binary/tool (not a recognized CLI framework) → **Risk ELEVATED** (ensures LLM Gate review)

**This is NOT a classification gate.** A command tagged CRITICAL is not rejected — it's routed to the LLM Gate and potentially HITL. The only gate that rejects is the Blocklist (Stage 1).

### 7.3 Horizontal API Translation (Version B)

To handle raw scripts (`curl`, `python`) that bypass CLI verbs, the validator:

1. Extracts HTTP methods and endpoints from the script body.
2. Checks endpoints against the **Global Blocklist** — if an endpoint targets a blocked resource, reject.
3. Maps HTTP methods to risk signals (not tiers):

| HTTP Method | Risk Signal | Rationale |
|---|---|---|
| `GET`, `HEAD`, `OPTIONS` | NONE | Read-only operations |
| `POST` (to known read endpoints*) | NONE | Some APIs use POST for queries |
| `POST`, `PUT`, `PATCH` | ELEVATED | Mutating operations |
| `DELETE` | CRITICAL | Destructive operations |

*A small, curated list of known read-only POST endpoints (e.g., GraphQL queries, Cloud Monitoring `timeSeries.query`) is maintained to prevent false-positives.

### 7.4 Injection Sanitization (Unchanged from Version A)

Shell injection patterns are still blocked by the sanitization layer, regardless of blocklist/risk status:

- Subshell execution: `$(...)`, backticks
- Output redirection: `>`, `>>` (except to `/dev/null`)
- Pipe to write commands: `| bash`, `| python`, `| tee`
- Command chaining: `;`, `&&`, `||`
- Environment manipulation: `export`, `source`, `eval`, `exec`

Safe pipes to read-only filter commands (`grep`, `awk`, `sed`, `sort`, `uniq`, `wc`, `head`, `tail`, `cut`, `tr`, `column`, `jq`) remain allowed.

### 7.5 SSH Inner-Command Validation (Unchanged from Version A)

Remote commands via `gcloud compute ssh --command="..."` are extracted and validated through the full blocklist pipeline. Interactive SSH sessions (no `--command` flag) are blocked.

---

## 8. Decision Traceability & Request Tagging

To ensure complete transparency and observability into the swarm's autonomous reasoning, every individual user chat message or system request must be tagged with a unique identifier (`request_id` or `trace_id`), which works in tandem with the overarching `session_id`.

- **Turn/Request Isolation**: A single session may contain dozens of back-and-forth messages. Generating a unique ID per user request allows developers and tenants to filter the execution logs for that exact query.
- **Chain of Decisions**: Every node in the graph (Router theory, Intent detection, Specialist Agent reasoning, Security Gate approvals, and Terminal output) must tag its payload with the active `request_id`.
- **Audit Pipeline**: This provides a unified "Chain of Decisions" trace, making it trivial to debug why a specific command was chosen or rejected in response to a specific user prompt without parsing the entire `session_id` history.
- **Blocklist Audit Trail**: Every validation result includes:
  - Whether the command was blocked (and by which blocklist — global or mode)
  - The risk signal tag (NONE / ELEVATED / CRITICAL)
  - Whether the LLM Gate was invoked and its verdict
  - Whether HITL was triggered and the user's decision

### 8.1 Backend Trace UI

A dedicated, lightweight backend UI must be provided to visualize this audit pipeline.
- The UI will be served directly by the backend (e.g., `/trace`).
- It allows developers or administrators to input a `request_id` (or select from recent requests) and visually reconstruct the LangGraph execution flow.
- It will display the step-by-step "Chain of Decisions," mapping the Router's initial theory, the chosen agent, the command executions, the security gates passed/failed, and the LLM's raw reasoning.

---

## 9. Security Review (Post-Execution)

The terminal `security_review.py` node remains intact. Its job is to:
1. Provide a mandatory **TLDR**.
2. Audit the execution log: Did the agent attempt blocked commands? Were the actions justified?
3. Redact any sensitive information leaked in standard output before sending it to the user.
4. Provide the final, polished incident post-mortem.

---

## 10. Environment Discovery - The Senses

The Environment Discovery module (`discovery/probe.py`) probes the live GCP infrastructure to build an `EnvironmentProfile`.

- **Auto-Configures SSH:** Decides between `gcloud compute ssh --tunnel-through-iap` or direct SSH.
- **Injected Context:** Inserted into every agent's prompt, negating manual infrastructure mapping.

---

## 11. Configuration

| Setting | Default | Description |
|---|---|---|
| `VCE_EXECUTION_MODE` | `mode_1` | Execution mode setting (`mode_1`, `mode_2`, `mode_3`) |
| `VCE_UNKNOWN_BINARY_RISK` | `ELEVATED` | Risk signal for unrecognized binaries/tools. `ELEVATED` ensures LLM Gate review. |
| `VCE_CMD_MAX_ITERATIONS` | `5` | Maximum ReAct loop iterations per agent |
| `VCE_CMD_MAX_PER_SESSION` | `15` | Maximum total commands across all agents per session |
| `VCE_CMD_TIMEOUT_SECONDS` | `30` | Per-command execution timeout |

---

## 12. Success Metrics (Brain Module)

| Metric | Target |
|---|---|
| **Diagnosis accuracy with commands** | >= 90% |
| **Blocklist false-positive rate** | < 0.5% (legitimate commands incorrectly blocked) |
| **Blocklist escape rate** | 0% (dangerous commands that should be blocked but aren't) |
| **Risk Signal accuracy** | >= 95% (correct NONE/ELEVATED/CRITICAL tagging) |
| **Tier 1 execution latency** | ~0ms overhead (blocklist check + risk signal are pure regex) |
| **LLM Gate validation latency** | < 3 seconds for ELEVATED/CRITICAL commands |
| **Supervisor delegation accuracy** | >= 95% |
| **New workload compatibility** | 100% — no validator changes needed for new CLI tools |
| **Token Usage Visibility** | 100% of reasoning/prompt/completion tokens rendered to the Tenant UI for FinOps tracking |

---

## 13. Security Trade-off Analysis

> [!WARNING]
> **Wider surface area is the explicit trade-off.** Version B allows more commands by default, which increases the attack surface compared to Version A's strict allowlist. This is intentionally compensated by:

| Compensating Control | Description |
|---|---|
| **Comprehensive Global Blocklist** | A curated set of universally dangerous patterns that are always rejected. This covers the highest-risk operations that no agent should ever execute. |
| **Mode Blocklists block write verbs in lower modes** | Mode 1 blocks all mutating + destructive verbs. Mode 2 blocks destructive verbs. This means in the default Mode 1, the system behaves almost identically to Version A for write operations. |
| **Risk Signal routes unknowns to LLM Gate** | Unknown binaries and unrecognized tools are tagged ELEVATED, ensuring LLM Gate review. They're not auto-executed at NONE risk. |
| **Deeper LLM Gate analysis** | With more commands reaching the LLM Gate, the gate's prompt is enhanced to perform more thorough blast-radius analysis, including checking for cascading effects and cross-service dependencies. |
| **Mandatory HITL for CRITICAL risk in Mode 3** | Every destructive command in Mode 3 requires human approval, regardless of how confident the agent or LLM Gate is. |
| **Injection sanitization unchanged** | Shell injection patterns (subshells, redirection, chaining) are still blocked by the sanitization layer. |
| **SSH inner-command validation unchanged** | Remote commands via `gcloud compute ssh --command` are still extracted and validated through the full blocklist pipeline. |
| **Audit trail enhancement** | Every command logs which stage approved/rejected it and the risk signal tag, enabling rapid post-incident analysis. |
