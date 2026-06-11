# VCE-HQ - Product Requirements Document

> **Version:** 1.3
> **Last Updated:** 2026-05-11
> **Status:** Active

---

## 1. Executive Summary

VCE-HQ is a multi-tenant, AI-powered infrastructure operations platform that acts as a **read-only advisor** for cloud and OS-level incidents. It ingests observability signals (webhooks, alerts), routes them through a swarm of specialized LLM agents orchestrated by a **Supervisor Router**, and delivers root-cause analyses and remediation playbooks - all without touching the target infrastructure.

The system features **runtime Environment Discovery** — at startup, it probes the live GCP infrastructure (IAP configurations, firewall rules, VM inventory, enabled APIs) and injects this context into every agent's prompt, enabling autonomous adaptation to the deployment environment without manual configuration.

Each tenant runs in a fully isolated container with its own local database, credentials vault, and agent context, ensuring zero cross-tenant data leakage.

---

## 2. Problem Statement

Modern infrastructure teams are overwhelmed by a growing volume of alerts from monitoring systems like Datadog, CloudWatch, and Prometheus. Triage is manual, context-switching is constant, and junior engineers lack the institutional knowledge to diagnose complex, cross-layer issues quickly.

**VCE-HQ addresses this by providing:**
- Automated alert triage and root-cause analysis via specialized AI agents.
- A structured decision pipeline orchestrated by a **Supervisor Router** that mirrors how senior SREs think - iteratively formulating theories, gathering evidence from specialist agents, cross-validating findings against the original query, and refining conclusions.
- **Environment-aware intelligence** — the system auto-discovers the deployment infrastructure and adapts its behavior (SSH methods, API availability, network topology) without manual configuration.
- Tenant-isolated execution, so each customer's data and credentials remain strictly sandboxed.

---

## 3. Vision and Core Pillars

The architecture is organized around four conceptual pillars:

| Pillar | Role | Description |
|---|---|---|
| **The Eyes** | Observability Ingestion | Receives webhooks and alert payloads from monitoring platforms (Datadog, CloudWatch, Prometheus, PagerDuty). Normalizes events into a common schema for downstream processing. |
| **The Brain** | LLM Agent Swarm (Supervisor Pattern) | A cyclic graph-based orchestration layer (Supervisor Router <-> OS Agent / Cloud Agent -> Security Review) that reasons about incidents, correlates signals, and produces actionable analysis. The Supervisor iteratively delegates tasks, cross-validates findings, and refines theories based on agent outputs. |
| **The Senses** | Environment Discovery | Runtime infrastructure probing layer that inspects the deployment environment (GCP APIs, IAP configuration, firewall rules, VM inventory, network topology) at startup and injects situational awareness into every agent's prompt. Enables self-configuration without manual prompt engineering. |
| **The Vault** | Credential Management | Zero-trust, per-tenant credential storage. Tenants input cloud credentials via a secure web UI; credentials are encrypted at rest and scoped to the tenant's container. |
| **The Hands** | Sandboxed Execution | Isolated Docker (or Firecracker) environments per tenant. In v1, used only for read-only API calls, SSH diagnostics, and analysis. In future versions, will support controlled write operations. |

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
           |  | * gcloud compute   | |   kubectl CLI       |
           |  |   ssh (global SSH) | | * Cloud API only    |
           |  | * Read-only only   | | * NO SSH access     |
           |  +----------+--------+ +----------+----------+
           |             |                      |
           +-------------+----------------------+
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

- The **Supervisor Router** acts as the central orchestrator using a **Hierarchical Swarm (Supervisor) Pattern**. Rather than a simple classifier that fires once, the Router operates in a **cyclic, closed-loop** - it formulates a working theory, delegates one step at a time to a specialist agent, **cross-validates the findings against the original user query**, identifies gaps, and re-delegates until the evidence fully addresses what the user asked. This closed-loop ensures the system never finalizes prematurely based on incomplete data. Through **v1-v3**, the router uses a single LLM. From **v4+**, the router may be replaced with a fine-tuned SLM to reduce per-request cost at scale.
- **Specialist agents report to the Supervisor, not to the user.** The OS Engineer and Cloud Engineer produce raw diagnostic evidence and findings. They do NOT format user-facing answers. The Supervisor cross-validates agent output, decides when the investigation is complete, and only then forwards to Security Review for final user-facing output.
- **Multi-layer tasks** (spanning both OS and cloud layers) are handled by the **Supervisor's iterative delegation**. For example, "map all VMs to their functionality" results in: Step 1 -> Cloud Engineer lists VM inventory with metadata/tags -> Step 2 -> OS Engineer SSHs into EACH running VM to run `docker ps`, `ps aux`, `ss -tulnp`, `systemctl list-units` -> Step 3 -> Supervisor validates completeness (all running VMs inspected?) -> Security Review. The Supervisor never guesses from metadata alone — it always gathers real OS-level evidence.
- The **Environment Discovery** module (`discovery/probe.py`) runs at request time (with 1-hour cache TTL) and probes the live GCP infrastructure. It detects: current project and service account, enabled APIs, IAP firewall rules, VM inventory with zones and IPs, and network topology. The discovered profile is formatted as an `ENVIRONMENT CONTEXT` block and injected into every agent's system prompt, enabling dynamic SSH method selection (IAP tunneling vs. direct SSH vs. restricted) and infrastructure-aware orchestration.
- When IAP is **not configured**, the system proactively surfaces actionable security recommendations (exact `gcloud` commands to enable IAP TCP Forwarding) rather than silently failing or guessing.
- The **FinOps Agent** acts as the "ruthless paranoid CFO" of the swarm. It understands the tenant's business vertical and P&L targets (querying the Supervisor/User if missing) to determine ideal budget allocations. Its niche role is to relentlessly optimize cloud spend:
  - **Hourly:** Monitors for abrupt spikes and abusive usage levels.
  - **Daily/Monthly:** Analyzes bill differences at the component level, maps them against workload effectiveness, performs deep analysis on the top 5 billing consumers, and identifies idle/underutilized resources for cleanup or resizing.
  - **Optimization Loop:** Every month, it pushes the Cloud and OS Engineers (via the Supervisor) to investigate if architectural changes can yield cost savings, and recalibrates actual usage against ideal budgets until satisfied.
- The **OS Engineer Agent** specializes in Linux internals: kernel logs, systemd services, disk/memory/CPU diagnostics, networking, and package management. It has **global SSH access** to all VMs via `gcloud compute ssh`, with the SSH method (IAP tunnel vs. direct) **auto-selected by the Environment Discovery probe**. SSH commands are validated through a 4-stage security pipeline (blocklist -> allowlist -> SSH inner-command validation -> injection sanitization).
- The **Cloud Engineer Agent** specializes in cloud-provider APIs: IAM, networking (VPCs, firewalls, load balancers), compute (VMs, containers, serverless), and managed services. It operates **exclusively at the cloud API layer** and **cannot SSH** into VMs. When OS-level data from a remote VM is needed, it reports the VM inventory and defers to the Supervisor Router, which delegates to the OS Engineer.
- The **Security Review** gate is **mandatory** - every agent-produced analysis passes through it before surfacing to the user. The review is grounded in the tenant's **long-term vector memory** (ADRs, past incident resolutions, runbooks, and infrastructure inventory). Every final response **begins with a TLDR** (1-3 sentence executive summary) before detailed analysis, ensuring busy engineers and CTOs can immediately grasp the result.

---

## 5. Capabilities and Scope

### 5.1 Version 1 - Read-Only Advisor

| Capability | Details |
|---|---|
| **Mode** | Read, analyze, and suggest **only**. No write/execute operations against target infrastructure. |
| **Alert Ingestion** | Accept incoming webhooks from Datadog, CloudWatch, and generic JSON payloads. |
| **Root-Cause Analysis** | Correlate alert data with known patterns and tenant-specific ADRs/runbooks via semantic search; produce a ranked list of probable causes. |
| **Remediation Playbooks** | Generate step-by-step remediation instructions grounded in the tenant's own runbooks and past resolutions (human-executable, not auto-executed). |
| **Credential Vault UI** | A simple, secure web interface for tenants to input and manage their cloud credentials (read-only API keys). |
| **Conversation Memory** | Short-term structured context within a session. Long-term vector-indexed memory of past incidents, ADRs, and infrastructure inventory for semantic retrieval. |
| **Knowledge Ingestion** | Ingest tenant-provided ADRs, runbooks, post-mortems, and infrastructure inventory docs. Embed and index them in sqlite-vec for agent grounding. |
| **Global SSH Diagnostics** | OS Engineer can SSH into any VM across all projects via `gcloud compute ssh` to run read-only diagnostic commands, with 4-stage security validation. |
| **Environment Discovery** | Runtime probe inspects GCP infrastructure (IAP, firewalls, VMs, APIs) and injects environment context into agent prompts for self-configuring behavior. |
| **Dynamic SSH Method Selection** | SSH method (IAP tunnel vs. direct) auto-selected based on discovered firewall rules. Proactive security advisories when IAP is not configured. |
| **TLDR-First Responses** | Every final response begins with a 1-3 sentence executive summary for rapid consumption by CTOs and engineers. |
| **Closed-Loop Supervision** | Supervisor Router cross-validates agent findings against the original query and re-delegates if evidence is incomplete. |

### 5.2 Version 2 - Controlled Execution *(Future)*

| Capability | Details |
|---|---|
| **Write Operations** | Controlled, approval-gated execution of remediation steps against target infrastructure. |

### 5.3 Version 3 - Scale and Maturity *(Future)*

| Capability | Details |
|---|---|
| **Multi-Cloud** | Full support for AWS, GCP, and Azure in a single tenant. |
| **Auto-Scaling Actions** | Execute scaling recommendations (e.g., resize VMs, adjust autoscaler thresholds). |
| **Runbook Automation** | Auto-execute tenant-approved runbooks for known incident patterns. |

### 5.4 Version 4 - Cost Optimization at Scale *(Future)*

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
4. Credentials are never logged, never transmitted outside the container, and are scoped to read-only API permissions.
5. Credential rotation and revocation are managed by the tenant through the UI.
6. **Both** the Cloud Engineer and OS Engineer agents receive credential injection - Cloud Engineer for cloud CLI commands, OS Engineer for `gcloud compute ssh` remote access.

### 6.2 Zero-Trust Principles
- No implicit trust between containers.
- All inter-service communication (if any) is authenticated and encrypted.
- The platform itself has **no standing access** to tenant infrastructure - all access is mediated through tenant-supplied credentials at runtime.

---

## 7. Webhook Ingestion and Event Schema

### 7.1 Supported Sources (v1)
- Datadog (alert webhooks)
- AWS CloudWatch (SNS -> webhook bridge)
- Generic JSON (user-defined schema)

### 7.2 Normalized Event Schema
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
  "raw_payload": {}
}
```

All incoming webhooks are normalized into this schema before being handed to the Supervisor Router.

---

## 8. Non-Functional Requirements

| Requirement | Target |
|---|---|
| **Tenant Isolation** | Complete - no shared state, no shared compute, no shared storage between tenants. |
| **Latency (Alert -> Analysis)** | < 30 seconds for initial triage classification. |
| **Availability** | 99.5% uptime for the ingestion and routing layer. |
| **Scalability** | Horizontal - spin up/down tenant containers on demand. |
| **Data Retention** | Configurable per tenant. Default: 90 days for incident history. |
| **Compliance** | SOC 2 Type II alignment as a design goal (not a v1 certification target). |

---

## 9. Deployment and Infrastructure (not now, now it's just a plain VM)

- **Container Runtime:** Docker (production target: Kubernetes on GKE).
- **Future Consideration:** Firecracker micro-VMs for stronger isolation if required by enterprise tenants.
- **Orchestration:** Kubernetes for container lifecycle management, autoscaling, and health monitoring.
- **CI/CD:** GitHub Actions -> Container Registry -> GKE rolling deployment.

---

## 10. Decisions Log

> **All initial open questions have been resolved:**
> - **Router model:** Single LLM provider through v3. SLM optimization deferred to v4+ when scale justifies fine-tuning investment.
> - **Router pattern:** Evolved from static classifier to **Closed-Loop Supervisor (Hierarchical Swarm) Pattern** with cyclic delegation. The Router formulates theories, issues explicit instructions, cross-validates findings against the original query, identifies gaps, and re-delegates until evidence fully addresses the user's question. Agents report raw evidence to the Supervisor — they do not produce user-facing answers.
> - **Environment Discovery:** Added runtime infrastructure probing (`discovery/probe.py`) that detects IAP configuration, firewall rules, VM inventory, enabled APIs, and network topology. Results are injected as `ENVIRONMENT CONTEXT` into every agent prompt, enabling dynamic SSH method selection and self-configuring behavior without manual prompt engineering.
> - **OS Engineer scope:** Expanded from local-only to **global SSH access** via `gcloud compute ssh`. SSH method (IAP tunnel vs. direct) is **auto-selected** by the Environment Discovery probe. All remote commands validated through a 4-stage security pipeline including SSH inner-command extraction.
> - **Cloud Engineer scope:** Explicitly restricted to **cloud API layer only**. Cannot SSH. Reports VM inventories and defers OS-level inspection to the Supervisor -> OS Engineer path.
> - **Credentials:** Hashed storage through v2. HashiCorp Vault (or equivalent) considered from v3+. OS Engineer now also receives credential injection for `gcloud compute ssh` commands.
> - **Multi-signal routing:** Iterative, theory-driven delegation with closed-loop validation. Supervisor delegates one step at a time, cross-validates completeness after each return, and re-delegates if findings are incomplete. The principle "Never Guess — Always Gather Evidence" prevents premature finalization based on metadata alone.
> - **Response format:** All final responses begin with a mandatory **TLDR** (1-3 sentence executive summary). Security Review adapts its output format (informational vs. diagnostic) to the query type.
> - **Billing:** Per-tenant pricing - token burn (LLM usage) + premium tier for dedicated container consumption.
> - **CLI:** No CLI planned. GUI (web UI) only.
> - **Embedding model:** Google `text-embedding-005` for v1-v2. `gemini-embedding-2` (multimodal, 3072-dim) considered from v3+ if PDF/diagram ingestion is needed.

---

## 11. Success Metrics (v1)

| Metric | Target |
|---|---|
| **Mean Time to Triage (MTTT)** | Reduce from ~15 min (manual) to < 1 min (automated). |
| **Accuracy** | >= 80% of root-cause analyses match the actual root cause (validated post-incident). |
| **Tenant Onboarding Time** | < 10 minutes from signup to first alert ingested. |
| **User Satisfaction (NPS)** | >= 40 within first 3 months of pilot. |

---

## 12. Milestones

| Phase | Deliverable | Target |
|---|---|---|
| **M0 - Foundation** | Project scaffolding, LangGraph agent skeleton, SQLite integration, container-per-tenant PoC. | Week 1-2 |
| **M1 - Brain** | Supervisor Router + OS Agent + Cloud Agent with ReAct loops. End-to-end query -> analysis flow. | Week 3-5 |
| **M2 - Eyes** | Webhook ingestion endpoints (Datadog, CloudWatch). Event normalization. | Week 5-6 |
| **M3 - Vault** | Credential input UI, encryption-at-rest, per-tenant scoping. | Week 6-7 |
| **M4 - Integration** | Full pipeline: Webhook -> Supervisor -> Agent(s) -> Analysis. Tenant isolation validated. | Week 7-8 |
| **M5 - Pilot** | Deploy to 2-3 beta tenants. Collect feedback, measure MTTT and accuracy. | Week 9-10 |
