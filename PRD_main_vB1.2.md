# VCE-HQ - Product Requirements Document (Version B — Blocklist Architecture)

> **Version:** B1.2
> **Last Updated:** 2026-06-23
> **Status:** Active
> **Lineage:** Rearchitected from [PRD_main_v1.2.md](./PRD_main_v1.2.md) (Version A — Allowlist Architecture)

---

## 0. Version B — Architectural Rationale

> [!IMPORTANT]
> **Why Version B exists.** Version A's allowlist-first approach requires every new CLI tool, subcommand, and cloud service to be manually whitelisted before agents can use it. This creates constant friction — every new workload (a new GCP service, a new `kubectl` plugin, a new AWS API) is blocked by default until an engineer updates the allowlist arrays. At scale, this becomes the primary bottleneck for platform evolution.
>
> **Version B inverts the security model:** commands are **allowed by default** and only **blocked by explicit dangerous-pattern rules**. A lightweight **Risk Signal Heuristic** scans for destructive/mutating keywords to decide how much downstream scrutiny a command needs (LLM Gate, HITL) — but it never rejects. The blocklist is the only gate that says no.

### Key Differences from Version A

| Aspect | Version A (Allowlist) | Version B (Blocklist) |
|---|---|---|
| **Default posture** | Deny — command must match an allowlisted prefix | Allow — command passes unless it matches a blocklist pattern |
| **New workload onboarding** | Requires manual allowlist update per command prefix | Zero-touch — new CLIs/services work immediately |
| **Risk routing** | Determined by which allowlist tier the prefix lives in | Risk Signal Heuristic scans for destructive/mutating keywords — routes to LLM Gate/HITL but never rejects |
| **Blocklist role** | Secondary check after allowlist match | Primary and **only** gatekeeping layer — the sole mechanism that rejects commands |
| **Router awareness** | Router sees full allowlist for fallback routing | Router sees blocklist constraints only — agents are free to try any command not blocked |
| **Maintenance burden** | Grows linearly with supported services | Grows only when new dangerous patterns are identified |

---

## 1. Executive Summary

VCE-HQ is a multi-tenant, AI-powered infrastructure operations platform that acts as an **autonomous advisor and operator** for cloud and OS-level incidents. It ingests observability signals (webhooks, alerts), routes them through a swarm of specialized LLM agents orchestrated by a **Supervisor Router**, and delivers root-cause analyses and remediation playbooks.

VCE-HQ operates in **Phased Execution Modes**, seamlessly transitioning from a read-only advisor (Mode 1) to a fully autonomous operator (Mode 3) via a **blocklist-first security architecture** featuring:
- A **Global + Mode Blocklist** — the sole gate that rejects commands. No approved-command lists exist.
- A **Risk Signal Heuristic** that scans for destructive/mutating keywords to route commands to downstream security gates — but never rejects.
- An **LLM-Based Pre-Execution Gate** for commands with elevated or critical risk signals.
- **Human-in-the-Loop (HITL)** approval for critical-risk operations.

The system features **runtime Environment Discovery** — at startup, it probes the live GCP infrastructure (IAP configurations, firewall rules, VM inventory, enabled APIs) and injects this context into every agent's prompt, enabling autonomous adaptation to the deployment environment without manual configuration.

Each tenant runs in a fully isolated container with its own local database, credentials vault, and agent context, ensuring zero cross-tenant data leakage.

---

## 2. Problem Statement

Modern infrastructure teams are overwhelmed by a growing volume of alerts from monitoring systems like Datadog, CloudWatch, and Prometheus. Triage is manual, context-switching is constant, and junior engineers lack the institutional knowledge to diagnose complex, cross-layer issues quickly.

**VCE-HQ addresses this by providing:**
- Automated alert triage and root-cause analysis via specialized AI agents.
- A structured decision pipeline orchestrated by a **Supervisor Router** that mirrors how senior SREs think - iteratively formulating theories, gathering evidence from specialist agents, cross-validating findings against the original query, and refining conclusions.
- **Environment-aware intelligence** — the system auto-discovers the deployment infrastructure and adapts its behavior (SSH methods, API availability, network topology) without manual configuration.
- **Progressive Autonomy** — allowing teams to safely graduate the AI from read-only diagnostics to active remediation with strict, LLM-driven security gates and HITL approvals.
- **Frictionless extensibility** — new cloud services, CLI tools, and diagnostic commands work out-of-the-box without allowlist updates. Security is enforced by blocking dangerous patterns, not by maintaining an ever-growing list of permitted prefixes.
- Tenant-isolated execution, so each customer's data and credentials remain strictly sandboxed.

---

## 3. Vision and Core Pillars

The architecture is organized around four conceptual pillars:

| Pillar | Role | Description |
|---|---|---|
| **The Eyes** | Observability Ingestion | Receives webhooks and alert payloads from monitoring platforms (Datadog, CloudWatch, Prometheus, PagerDuty). Normalizes events into a common schema for downstream processing. |
| **The Brain** | LLM Agent Swarm (Supervisor Pattern) | A cyclic graph-based orchestration layer (Supervisor Router <-> OS Agent / Cloud Agent / FinOps Agent -> Security Review) that reasons about incidents, correlates signals, and produces actionable analysis. The Supervisor iteratively delegates tasks, cross-validates findings, and refines theories based on agent outputs. |
| **The Senses** | Environment Discovery | Runtime infrastructure probing layer that inspects the deployment environment (GCP APIs, IAP configuration, firewall rules, VM inventory, network topology) at startup and injects situational awareness into every agent's prompt. Enables self-configuration without manual prompt engineering. |
| **The Vault** | Credential Management | Zero-trust, per-tenant credential storage. Tenants input cloud credentials via a secure web UI; credentials are encrypted at rest and scoped to the tenant's container. |
| **The Hands** | Sandboxed Execution | Isolated Docker (or Firecracker) environments per tenant executing commands across **3 Phased Modes**: Mode 1 (Read-only), Mode 2 (Read+Edit), and Mode 3 (Full Access). Controlled via a **blocklist-first architecture** — commands are allowed by default and only stopped by explicit block rules. A Risk Signal Heuristic routes elevated/critical commands to an LLM security gate and HITL overrides. |

---

## 4. Architecture and Tech Stack

### 4.1 Language and Framework
- **Python 3.12+** as the primary language.
- **LangGraph** for stateful, graph-based agent orchestration with cyclic edges.
- LangChain is explicitly **excluded** - LangGraph is used directly to avoid unnecessary abstraction overhead.

### 4.2 Multi-Tenancy Model
- **Container-per-tenant** isolation. Each tenant receives a dedicated container instance.
- Containers are ephemeral and stateless at the compute layer - all persistence is local to the container's mounted volume.
- No shared databases, no shared credential stores, no shared agent memory across tenants.

### 4.3 Data and Storage
- **SQLite + sqlite-vec** (decentralized, per-container). A single SQLite database per tenant with the `sqlite-vec` extension for native vector similarity search.
  - **Short-term memory (structured):** Active conversation and incident context within a session. Stored as regular relational rows.
  - **Long-term memory (vector-indexed):** Historical incident summaries, root-cause analyses, resolution patterns, and tenant-specific runbooks - embedded and stored as vectors for semantic retrieval.
  - **ADRs and Runbooks (vector-indexed):** Architecture Decision Records, post-mortems, and operational runbooks ingested and embedded so agents can ground their reasoning in the tenant's own documented decisions.
  - **Infrastructure Inventory (vector-indexed):** Ingested descriptions of the tenant's infrastructure topology (services, dependencies, network layout, IAM structure) embedded for deeper contextual understanding during incident analysis.
  - **Token Usage Tracking (structured):** Records per-request LLM usage metadata (prompt, completion, total, reasoning/thinking, and cache tokens) by agent, aggregated per tenant for FinOps billing analysis.
- **Embedding Model:** Google `text-embedding-005` (768 dimensions, supports MRL for flexible sizing down to 256). Chosen for cost efficiency, low latency, and strong English-language retrieval quality.
- No centralized database. Each tenant's data lives and dies with its container volume.

### 4.4 Agent Routing and RAG Pipeline - End-to-End LLD

#### Ingestion Layer (The Eyes)

```
Datadog Webhook / CloudWatch SNS / Custom JSON / User Query
                            |
                            v
                    Event Normalizer
              (common schema: event_id,
               tenant_id, severity, etc.)
                            |
                            v
                    Intent Analyzer
              (Expands shorthand, catches
               AMBIGUOUS/IRRELEVANT queries)
                            |
                            v
```

#### Agent Orchestration (The Brain - Supervisor Pattern, Cyclic)

```
                    +---------------------------+
                    |    SUPERVISOR ROUTER       | <-- reads STM + agent outputs
           +------>|  (LLM - iterative calls)   |
           |       |  * Formulates theory        |
           |       |  * Issues instructions      |
           |       |  * Controls delegation      |
           |       +-----------|----------------+
           |                   |
           |      +------------+------------+---------------+
           |      |  delegate ONE step at   |               |
           |      |  a time (theory-driven) |               |
           |  +---v-------+         +-------v------+ +------v-------+
           |  |os_engineer|         |cloud_engineer| |finops_agent  |
           |  +---+-------+         +-------+------+ +------+-------+
           |      |                         |               |
           |      v                         v               v
           |  +---------------------+ +---------------------+ +---------------------+
           |  | OS ENGINEER AGENT   | | CLOUD ENGINEER AGENT| | FINOPS AGENT        |
           |  | + RAG + ReAct loop  | | + RAG + ReAct loop  | | + RAG + ReAct loop  |
           |  |                     | |                     | |                     |
           |  | * Local OS commands | | * gcloud/aws/az/    | | * Billing APIs      |
           |  | * gcloud compute   | |   kubectl CLI       | | * Usage tracking    |
           |  |   ssh (global SSH) | | * Cloud API only    | | * Delegates shutdown|
           |  | * Mode 1/2/3 Exec  | | * Mode 1/2/3 Exec   | |   to Cloud Engineer |
           |  +----------+--------+ +----------+----------+ +----------+----------+
           |             |                     |                       |
           |             +---------------------+-----------------------+
           |                                   |
           |             [ BLOCKLIST-FIRST SECURITY PIPELINE ]
           |             Stage 1: Global & Mode Blocklist (only gate that rejects)
           |             Stage 2: Risk Signal Heuristic (tags NONE/ELEVATED/CRITICAL)
           |             Stage 3: LLM Gate (ELEVATED/CRITICAL risk only)
           |             Stage 4: HITL (CRITICAL risk in Mode 3)
           |                                   |
           +-----------------------------------+
                  (always return to Supervisor Router)

      When Supervisor determines all evidence is gathered:
                            |
                            v
      +------------------------------------------------------+
      |         SECURITY REVIEW (mandatory) + RAG             |
      |                                                        |
      |  1. Receive agent analysis output                      |
      |  2. Embed recommendations -> sqlite-vec search         |
      |  3. Validate against tenant ADRs and standards         |
      |  4. Flag contradictions, enrich with references        |
      +-------------------------+------------------------------+
                                |
                                v
```

#### Output

```
                    +-----------------------------+
                    |  Analysis and Remediation   | --> writes resolution to LTM
                    |  Playbook                   |
                    +-------------+---------------+
                                  |
                                  v
                    +-----------------------------+
                    |     Tenant Web UI (GUI)     |
                    |  - Chat & Resolutions       |
                    |  - Token Usage Dashboard    |
                    +-----------------------------+
```

#### Knowledge Ingestion Pipeline (async, runs independently)

```
   ADRs and        Runbooks        Infra
   Post-Mortems                   Inventory
       |               |              |
       +---------------+--------------+
                        |
                        v
               +-------------------+
               |   Chunker         |
               |   (text splitter) |
               +--------+----------+
                        |
                        v
               +--------------------+
               | text-embedding-005 |
               | (embed chunks)    |
               +--------+----------+
                        |
                        v
               +--------------------+
               |    sqlite-vec     | --> writes to LTM
               |  (vector store)   |
               +--------------------+
```

#### Per-Tenant SQLite Database

```
  +----------------------------------+ +----------------------------------+
  |   STM - Short-Term Memory        | |   LTM - Long-Term Memory         |
  |   (structured rows)              | |   (sqlite-vec vectors)           |
  | -------------------------------- | | -------------------------------- |
  | * Session context                | | * Past incident embeddings       |
  | * Active conversation state      | | * ADR embeddings                 |
  | * Current incident metadata      | | * Runbook embeddings             |
  | * Router theory + instructions   | | * Infra inventory embeddings     |
  | * Command execution audit log    | |                                  |
  |                                  | |  <-- read: OS Agent RAG          |
  |  <-- read/write: Supervisor      | |  <-- read: Cloud Agent RAG      |
  |                                  | |  <-- read: Security Review       |
  |                                  | |  <-- write: Knowledge Pipeline   |
  |                                  | |  <-- write: Incident Output      |
  +----------------------------------+ +----------------------------------+
```

- The **Intent Analyzer** acts as the frontline gatekeeper for user queries. It performs entity resolution (expanding shorthand like 'cart' to full VM names), detects if a query is a continuation of an existing session, and catches **AMBIGUOUS** queries (e.g., "my database" without specifying a project). If a query is ambiguous, it immediately halts execution and asks the user for clarification, preventing the downstream RAG pipeline from hallucinating mismatched ADRs.
- The **Supervisor Router** acts as the central orchestrator using a **Hierarchical Swarm (Supervisor) Pattern**. Rather than a simple classifier that fires once, the Router operates in a **cyclic, closed-loop** - it formulates a working theory, delegates one step at a time to a specialist agent, **cross-validates the findings against the original user query**, identifies gaps, and re-delegates until the evidence fully addresses what the user asked. This closed-loop ensures the system never finalizes prematurely based on incomplete data.
- **Specialist agents report to the Supervisor, not to the user.** The OS Engineer, Cloud Engineer, and FinOps Agent produce raw diagnostic evidence and findings. They do NOT format user-facing answers. The Supervisor cross-validates agent output, decides when the investigation is complete, and only then forwards to Security Review for final user-facing output.
- **Multi-layer tasks** (spanning both OS and cloud layers) are handled by the **Supervisor's iterative delegation**.
- The **Environment Discovery** module (`discovery/probe.py`) runs at request time (with 1-hour cache TTL) and probes the live GCP infrastructure. The discovered profile is formatted as an `ENVIRONMENT CONTEXT` block and injected into every agent's system prompt.
- The **FinOps Agent** acts as the "ruthless paranoid CFO" of the swarm. It understands the tenant's business vertical and P&L targets (querying the Supervisor/User if missing) to determine ideal budget allocations... In **Mode 3**, it can detect severe consumption violations (e.g., 2x ADR allowance) and instruct the Supervisor to dispatch the Cloud Engineer to forcibly shut down resources if required. Its niche role is to relentlessly optimize cloud spend.
  - **Hourly:** Monitors for abrupt spikes and abusive usage levels.
  - **Daily/Monthly:** Analyzes bill differences at the component level, maps them against workload effectiveness, performs deep analysis on the top 5 billing consumers, and identifies idle/underutilized resources for cleanup or resizing.
  HITL is considered here.
  - **Optimization Loop:** Every month, it pushes the Cloud and OS Engineers (via the Supervisor) to investigate if architectural changes can yield cost savings, and recalibrates actual usage against ideal budgets until satisfied.
  HITL is considered here.

- The **OS Engineer Agent** specializes in Linux internals with **global SSH access** to all VMs via `gcloud compute ssh`.
- The **Cloud Engineer Agent** specializes in cloud-provider APIs. It operates **exclusively at the cloud API layer** and **cannot SSH** into VMs.
- The **Security Review** gate is **mandatory** - every agent-produced analysis passes through it before surfacing to the user. Every final response **begins with a TLDR**.

---

## 5. Execution Modes and Capabilities

The platform operates under a flexible, env-var controlled `VCE_EXECUTION_MODE`. Security is enforced through a **Blocklist-First Pipeline** — the blocklist is the only mechanism that rejects commands. A **Risk Signal Heuristic** tags commands as NONE/ELEVATED/CRITICAL to route them through downstream security gates (LLM Gate, HITL), but never rejects.

### 5.1 Mode 1 - Read-Only Advisor (Default)
| Capability | Details |
|---|---|
| **Operations** | Read, analyze, and suggest **only**. |
| **What's allowed** | Any command that doesn't match the Global Blocklist or Mode 1's blocked-verb list. This includes all read-only operations AND any novel/unknown command that doesn't use a mutating or destructive verb. |
| **What's blocked** | Global Blocklist patterns + all mutating verbs (`start`, `stop`, `restart`, `scale`, etc.) + all destructive verbs (`delete`, `kill`, `rm`, etc.). |
| **Security gates** | Commands that pass the blocklist execute immediately (~0ms overhead). No LLM Gate in Mode 1 — if it's not blocked, it runs. |

### 5.2 Mode 2 - Read + Edit (Controlled Execution)
| Capability | Details |
|---|---|
| **Operations** | Read operations + non-destructive writes. |
| **What's allowed** | Everything in Mode 1, plus commands with mutating verbs (`start`, `stop`, `update`, `modify`, `scale`, `restart`, `apply`, `patch`). |
| **What's blocked** | Global Blocklist patterns + destructive verbs (`delete`, `terminate`, `rm`, `kill`, `reboot`, `create`, `destroy`). |
| **Security gates** | Commands with mutating verbs (Risk ELEVATED) are routed to the **LLM Pre-Execution Security Gate** for blast radius and ADR compliance checks. |

### 5.3 Mode 3 - Full Access (Autonomous with Guardrails)
| Capability | Details |
|---|---|
| **Operations** | Destructive actions permitted with strict supervision. |
| **What's allowed** | Everything except Global Blocklist patterns (`mkfs`, `gcloud projects delete`, `terraform destroy`, etc.). |
| **What's blocked** | Only the Global Blocklist — no mode-specific verb blocking. |
| **Security gates** | Commands with mutating verbs → LLM Gate. Commands with destructive verbs → LLM Gate + **HITL approval** via the chat interface. |

### 5.4 Future Roadmap: Scale and Maturity

| Capability | Details |
|---|---|
| **Multi-Cloud** | Full support for AWS, GCP, and Azure in a single tenant. |
| **Auto-Scaling Actions** | Execute scaling recommendations (e.g., resize VMs, adjust autoscaler thresholds). |
| **Runbook Automation** | Auto-execute tenant-approved runbooks for known incident patterns. |

### 5.5 Future Roadmap: Cost Optimization at Scale

| Capability | Details |
|---|---|
| **SLM Router** | Replace the LLM-based Supervisor Router with a fine-tuned small language model (SLM) to reduce routing cost per request at high tenant/alert volume. |
| **Tiered Model Strategy** | Use SLMs for classification/triage and reserve full LLMs for complex reasoning and analysis, optimizing cost-to-quality ratio. |

---

## 6. Credential Vault and Security

### 6.1 Credential Lifecycle
1. Tenant inputs cloud credentials (API keys, service account JSON, etc.) via the secure web UI.
2. **v1-v2:** Credentials are hashed and stored within the tenant's container volume. No plaintext credentials are persisted at rest.
3. **v3+:** Migration to a dedicated secrets manager (e.g., HashiCorp Vault) for centralized, auditable credential lifecycle management.
4. Credentials are never logged, never transmitted outside the container.
5. Credential rotation and revocation are managed by the tenant through the UI.
6. Both the Cloud Engineer and OS Engineer agents receive credential injection - Cloud Engineer for cloud CLI commands, OS Engineer for `gcloud compute ssh` remote access.

### 6.2 Zero-Trust Principles
- No implicit trust between containers.
- All inter-service communication (if any) is authenticated and encrypted.
- The platform itself has **no standing access** to tenant infrastructure - all access is mediated through tenant-supplied credentials at runtime.

---

## 7. Authentication & User Management

### 7.1 Initial Installation & Access
- The system features a dedicated standalone Authentication Module.
- Upon initial installation/deployment, the system provisions a default `admin` user with a static, pre-configured password like VCE-HQ#2026 

### 7.2 User Management
- The `admin` user has access to a dedicated **User Management Section** in the UI.
- Within this section, the admin can change their password, and create/manage additional user accounts for the tenant.

### 7.3 Data Store
- All user identities, hashed passwords, and session data utilize the existing **per-tenant SQLite database**. There is no need for an external database like Postgres or Redis.

---

## 8. Webhook Ingestion and Event Schema

### 8.1 Supported Sources (v1)
- Datadog (alert webhooks)
- AWS CloudWatch (SNS -> webhook bridge)
- Generic JSON (user-defined schema)

### 8.2 Normalized Event Schema
```json
{
  "event_id": "uuid",
  "tenant_id": "string",
  "source": "datadog | cloudwatch | custom",
  "severity": "critical | warning | info",
  "timestamp": "ISO-8601",
  "title": "string",
  "body": "string | object",
  "tags": ["string"],
  "details": {}
}
```

All incoming webhooks are normalized into this schema before being handed to the Supervisor Router.

---

## 9. Non-Functional Requirements

| Requirement | Target |
|---|---|
| **Tenant Isolation** | Complete - no shared state, no shared compute, no shared storage between tenants. |
| **Latency (Alert -> Analysis)** | < 30 seconds for initial triage classification. |
| **Availability** | 99.5% uptime for the ingestion and routing layer. |
| **Scalability** | Horizontal - spin up/down tenant containers on demand. |
| **Data Retention** | Configurable per tenant. Default: 90 days for incident history. |
| **Compliance** | SOC 2 Type II alignment as a design goal (not a v1 certification target). |

---

## 10. Deployment and Infrastructure (not now, now it's just a plain VM)

- **Container Runtime:** Docker (production target: Kubernetes on GKE).
- **Future Consideration:** Firecracker micro-VMs for stronger isolation if required by enterprise tenants.
- **Orchestration:** Kubernetes for container lifecycle management, autoscaling, and health monitoring.
- **CI/CD:** GitHub Actions -> Container Registry -> GKE rolling deployment.

## 11. Decisions Log

> **All initial open questions have been resolved:**
> - **Execution Security:** Migrated from Version A's static allowlist-first model to a **Blocklist-First** architecture. Commands are allowed by default and blocked only by explicit dangerous-pattern rules. There is no approved-command list. The blocklist is the sole mechanism that rejects commands.
> - **Risk Signal Heuristic:** A lightweight, deterministic scanner tags commands as NONE (execute immediately), ELEVATED (route to LLM Gate), or CRITICAL (route to LLM Gate + HITL). It never rejects — it only decides downstream scrutiny. Unknown binaries default to ELEVATED risk for safety.
> - **Pre-Execution Security Gate:** A new LLM node (`security_gate.py`) intercepts ELEVATED and CRITICAL risk commands *before* execution. It reviews the command against tenant ADRs and assesses the blast radius. Risk NONE commands bypass the LLM gate entirely for speed.
> - **HITL (Human-in-the-loop):** For Mode 3 CRITICAL-risk commands (e.g., deleting a VM), the LLM Security Gate flags the action as `requires_hitl`. Execution is paused, and the user must approve or reject the action via the UI.
> - **Router model:** Single LLM provider through v3. SLM optimization deferred to v4+ when scale justifies fine-tuning investment.
> - **Router pattern:** Evolved from static classifier to **Closed-Loop Supervisor (Hierarchical Swarm) Pattern** with cyclic delegation. The Router formulates theories, issues explicit instructions, cross-validates findings against the original query, identifies gaps, and re-delegates until evidence fully addresses the user's question. Agents report raw evidence to the Supervisor — they do not produce user-facing answers.
> - **Router constraint awareness:** The Router has visibility into **blocklist rules only** (not an allowlist). All commands are available unless blocked. When an agent reports a command was blocked, the Router understands *why* (global blocklist match or mode-specific verb block) and suggests alternative approaches that avoid the blocked pattern.
> - **Environment Discovery:** Added runtime infrastructure probing (`discovery/probe.py`) that detects IAP configuration, firewall rules, VM inventory, enabled APIs, and network topology. Results are injected as `ENVIRONMENT CONTEXT` into every agent prompt, enabling dynamic SSH method selection and self-configuring behavior without manual prompt engineering.
> - **OS Engineer scope:** Expanded from local-only to **global SSH access** via `gcloud compute ssh`. SSH method (IAP tunnel vs. direct) is **auto-selected** by the Environment Discovery probe. All remote commands validated through a 4-stage security pipeline including SSH inner-command extraction.
> - **Cloud Engineer scope:** Explicitly restricted to **cloud API layer only**. Cannot SSH. Reports VM inventories and defers OS-level inspection to the Supervisor -> OS Engineer path.
> - **FinOps Execution:** FinOps primarily uses read-only commands (which pass the blocklist in all modes), but in extreme cases, it instructs the Router to have the Cloud Engineer shut down resources. It does not execute state changes directly.
> - **Credentials:** Hashed storage through v2. HashiCorp Vault (or equivalent) considered from v3+. OS Engineer now also receives credential injection for `gcloud compute ssh` commands.
> - **Multi-signal routing:** Iterative, theory-driven delegation with closed-loop validation. Supervisor delegates one step at a time, cross-validates completeness after each return, and re-delegates if findings are incomplete. The principle "Never Guess — Always Gather Evidence" prevents premature finalization based on metadata alone.
> - **Response format:** All final responses begin with a mandatory **TLDR** (1-3 sentence executive summary). Security Review adapts its output format (informational vs. diagnostic) to the query type.
> - **Token Usage Tracking UI:** Token tracking metrics (input, output, reasoning, cache) are logged to STM per agent. A requirement has been added to display this aggregated usage data in the Tenant Web UI to provide clear billing and FinOps visibility.
> - **Token Caching:** Implemented `CacheManager` using Gemini Context Caching (`langchain-google-genai`) to cache bulky, static system prompts and environment contexts across all agents, significantly reducing token usage and latency during iterative ReAct loops.
> - **Entity Resolution (Shorthand Mapping):** Added fuzzy matching and entity resolution to the Intent Analyzer. It maps partial infrastructure names (e.g., "cart") against the Environment Profile and forwards a `resolved_query` to ensure downstream agents use exact resource identifiers.
> - **Billing:** Per-tenant pricing - token burn (LLM usage) + premium tier for dedicated container consumption.
> - **CLI:** No CLI planned. GUI (web UI) only.
> - **Embedding model:** Google `text-embedding-005` for v1-v2. `gemini-embedding-2` (multimodal, 3072-dim) considered from v3+ if PDF/diagram ingestion is needed.
> - **Allowlist → Blocklist Migration:** Documented tradeoff — Version A's allowlist model provides tighter control but creates operational friction at scale. Version B's blocklist model prioritizes velocity and extensibility, compensating for the wider surface area with deeper LLM Gate analysis, mandatory HITL for destructive operations, and a comprehensive global blocklist for universally dangerous patterns.

> - **Authentication Module:** Decided against complex initial auth (like Google OAuth) for now to ensure easier on-prem/self-hosted deployment. Adopted a standalone Auth module utilizing the local SQLite DB. Features an initial default admin + static password setup, with password rotation and user provisioning handled within a built-in User Management UI.

---

## 12. Success Metrics

| Metric | Target |
|---|---|
| **MTTT (Mean Time to Triage)** | < 2 minutes. |
| **Accuracy** | >= 80% of root-cause analyses match the actual root cause (validated post-incident). |
| **Tenant Onboarding Time** | < 10 minutes from signup to first alert ingested. |
| **User Satisfaction (NPS)** | >= 40 within first 3 months of pilot. |
| **New Workload Unblocked Rate** | 100% — new CLI tools and cloud services should work without validator changes. |

---

## 13. Milestones

| Phase | Deliverable | Target |
|---|---|---|
| **M0 - Foundation** | Project scaffolding, LangGraph agent skeleton, SQLite integration, container-per-tenant PoC. | Week 1-2 |
| **M1 - Brain** | Supervisor Router + OS Agent + Cloud Agent with ReAct loops. Blocklist-first validation pipeline. End-to-end query -> analysis flow. | Week 3-5 |
| **M2 - Eyes** | Webhook ingestion endpoints (Datadog, CloudWatch). Event normalization. | Week 5-6 |
| **M3 - Vault** | Credential input UI, encryption-at-rest, per-tenant scoping. | Week 6-7 |
| **M4 - Integration** | Full pipeline: Webhook -> Supervisor -> Agent(s) -> Analysis. Tenant isolation validated. | Week 7-8 |
| **M5 - Pilot** | Deploy to 2-3 beta tenants. Collect feedback, measure MTTT and accuracy. | Week 9-10 |
