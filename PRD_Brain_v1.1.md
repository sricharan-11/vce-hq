# PRD: The Brain - Agent Swarm with Supervisor Orchestration and Live Diagnostics

> **Module:** The Brain (Agent Orchestration)
> **Version:** 1.2
> **Last Updated:** 2026-05-09
> **Status:** Active
> **Parent PRD:** [PRD_main_v1.1.md](./PRD_main_v1.1.md) - Section 4.4

---

## 1. Purpose

This PRD defines the detailed design of **The Brain** - the LangGraph-based agent swarm that performs incident analysis. It extends the architecture defined in `PRD_main_v1.1.md` Section 4.4 by describing:

1. The **Supervisor (Hierarchical Swarm) Pattern** - the Router operates as a cyclic, closed-loop orchestrator with cross-validation
2. The **ReAct (Reason + Act) loop** inside each specialist agent for live diagnostics
3. The **4-stage command validation pipeline** including SSH inner-command extraction
4. The **OS Engineer's global SSH access** via `gcloud compute ssh`
5. The **Environment Discovery** module for runtime infrastructure probing and self-configuration

### Current Graph Topology (implemented)

```
Supervisor Router <-> [OS Agent | Cloud Agent] (cyclic) -> Security Review -> END
```

The Supervisor Router formulates a theory, delegates one step at a time, reads agent outputs, cross-validates the findings against the original query, identifies gaps, and re-delegates until the evidence fully addresses the user's question. Agents report raw evidence to the Supervisor — they do not produce user-facing answers. When the Supervisor determines all evidence is gathered, it delegates to Security Review for final user-facing output.

---

## 2. Problem This Solves

The original architecture (PRD_main v0.0 Section 4.4) used a static, linear topology:
```
Router (classify once) -> [OS | Cloud] (sequential) -> Security Review -> END
```

This was insufficient for:
- **Cross-layer investigations:** "list open ports on all VMs" requires Cloud Engineer to list VMs first, then OS Engineer to SSH into each one. A static classifier cannot orchestrate multi-step, cross-agent tasks.
- **Novel or ambiguous incidents:** The alert may lack detail, requiring iterative evidence gathering across both agents.
- **Context retention:** A one-shot classifier loses context between agent executions. The Supervisor retains full context across cycles.
- **Remote diagnostics:** The original OS Engineer could only inspect the local host. Real SRE work requires SSH access to any VM.

**The Supervisor Pattern closes all these gaps.**

---

## 3. Alignment with Main PRD Section 4.4

| Section 4.4 Concept | This PRD's Treatment |
|---|---|
| Router -> OS/Cloud -> Security Review | **Evolved.** Router is now a Supervisor that delegates cyclically. Agents always return to the Supervisor. Security Review is the terminal node. |
| RAG retrieval (steps 1-5 per agent) | **Preserved.** RAG still executes first. Command execution is an additional step *after* RAG. |
| Mandatory Security Review with RAG grounding | **Unchanged.** Security Review now also validates the commands that were executed (audit trail). |
| STM/LTM memory model | **Extended.** Supervisor theory + instructions stored in STM. Command outputs stored in STM for session context. |
| Multi-signal routing | **Replaced.** No longer a static "classify and sequence." The Supervisor dynamically determines which agent to invoke next based on accumulated evidence. |
| Read-only mode (v1) | **Enforced.** Only read-only commands allowed. 4-stage validation enforced via allowlists + SSH inner-command extraction. |

---

## 4. Supervisor Router Architecture

### 4.1 The Supervisor Loop

The Supervisor Router operates as the "brain" of the swarm. Unlike a simple classifier, it:
1. **Formulates a theory** about what the query requires
2. **Delegates one step** to the appropriate specialist agent with a specific instruction
3. **Reads the agent's output** when it returns
4. **Cross-validates findings** against the original user query — checks for completeness and gaps
5. **Re-delegates** if evidence is incomplete (e.g., VMs not yet inspected, missing data)
6. **Delegates to Security Review** only when fully satisfied that findings address the query

```
+---------------------------+
|    SUPERVISOR ROUTER       | <-- reads STM conversation history
|  (LLM - iterative calls)  | <-- reads os_analysis, cloud_analysis
|                            |
|  Input: user_query/event   |
|  Output JSON:              |
|  {                         |
|    "theory": "...",        |
|    "delegate_to": "...",   |
|    "instruction": "...",   |
|    "gaps": "..."           |
|  }                         |
+-----------|---------------+
            |
            v
   Conditional Edge:
   * "os_engineer"     -> OS Engineer node
   * "cloud_engineer"  -> Cloud Engineer node
   * "finops_agent"    -> FinOps Agent node
   * "security_review" -> Security Review (terminal)

   After OS/Cloud/FinOps execution:
   * Unconditional edge BACK to Supervisor Router
```

### 4.2 Supervisor State Schema

```python
class AgentState(TypedDict, total=False):
    # Identity
    tenant_id: str
    session_id: str

    # Input (one of these will be populated)
    event: dict[str, Any]
    user_query: str

    # Supervisor output
    router_theory: str
    router_instruction: str
    delegate_to: Literal["os_engineer", "cloud_engineer", "finops_agent", "security_review"]

    # Context
    conversation_history: str
    retrieved_context: str

    # Agent outputs
    os_analysis: str
    cloud_analysis: str
    finops_analysis: str

    # Command execution (The Hands)
    command_log: list[dict[str, Any]]
    command_count: int

    # Security Review
    security_review: str
    security_flags: list[str]

    # Final
    final_output: str

    # Control
    error: str
    current_agent: str
```

### 4.3 Key Design Principles

1. **Theory-driven.** The Supervisor always has a working theory that guides delegation decisions.
2. **One step at a time.** The Supervisor delegates to exactly one agent per cycle, never both simultaneously.
3. **Closed-loop validation.** After each agent returns, the Supervisor cross-validates findings against the original query and identifies gaps before proceeding.
4. **Agents report to Supervisor, not user.** Specialist agents produce raw diagnostic evidence and findings. They do NOT format user-facing answers. The Supervisor decides when the investigation is complete.
5. **Never guess.** Cloud metadata (tags, names, labels) is not sufficient. The Supervisor must dispatch agents to gather real OS-level evidence from running VMs before finalizing.
6. **Context retention.** Agent outputs (os_analysis, cloud_analysis) and conversation history persist across cycles.
7. **Bounded cycles.** The graph terminates when the Supervisor delegates to "security_review" (enforced by graph topology - Security Review has edge to END).
8. **Fail-safe.** If the Supervisor fails to parse its own LLM output, it defaults to delegating to Security Review (ending the loop).

---

## 5. Specialist Agent Tool Architecture

### 5.1 The ReAct (Reason + Act) Loop

Each specialist agent (OS Engineer, Cloud Engineer, FinOps Agent) operates in a bounded ReAct loop. **Agents report their findings to the Supervisor Router, not to the user.** They produce raw diagnostic evidence; the Supervisor cross-validates and decides next steps.

```
+---------------------------------------------------------------+
|             SPECIALIST AGENT (OS / Cloud / FinOps)            |
|                                                                |
|  1. Receive Supervisor instruction + alert/query               |
|          |                                                      |
|          v                                                      |
|  2. RAG Retrieval (unchanged from Section 4.4)                 |
|     * Embed query -> sqlite-vec search -> retrieve context     |
|          |                                                      |
|          v                                                      |
|  3. LLM Reasoning (iteration 1)                               |
|     * Analyze alert + RAG context + Supervisor instruction     |
|     * Decision: Do I have enough data to diagnose?             |
|          |                                                      |
|          +---- YES -> Produce final analysis -> exit loop       |
|          |                                                      |
|          +---- NO -> Formulate diagnostic command(s)           |
|                    |                                            |
|                    v                                            |
|  4. Command Execution (via The Hands)                          |
|     * Validate command (4-stage pipeline)                      |
|     * Execute in sandboxed environment                         |
|     * Capture stdout/stderr                                    |
|     * Store output in STM                                      |
|          |                                                      |
|          v                                                      |
|  5. LLM Reasoning (iteration 2...N)                            |
|     * Analyze alert + RAG context + command outputs            |
|     * Decision: Do I have enough data now?                     |
|          |                                                      |
|          +---- YES -> Produce final analysis -> exit loop       |
|          +---- NO -> Formulate more commands (up to max_iter)  |
|                                                                |
|  Max iterations: 5 (configurable)                              |
|  If max reached: produce best-effort analysis with available   |
|  data + flag that further investigation is needed              |
|                                                                |
+---------------------------------------------------------------+
```

### 5.2 Key Design Principles

1. **RAG-first.** Agents always consult long-term memory before executing any commands.
2. **Instruction-driven.** Agents follow the Supervisor's specific instruction, not their own intuition.
3. **Report, don't answer.** Agents produce raw evidence and findings for the Supervisor. They do NOT format user-facing answers or make final conclusions.
4. **Minimum-commands.** The LLM decides whether a command is needed - it is not automatic.
5. **Read-only enforced.** Commands are validated against strict allowlists before execution.
6. **Bounded iteration.** The ReAct loop is capped at a configurable maximum (default: 5 iterations).
7. **Full audit trail.** Every command, its output, and the agent's reasoning are logged in STM.

---

## 6. OS Engineer Agent - Command Toolkit

### 6.1 Allowed Commands (Read-Only)

The OS Engineer Agent can execute these commands **locally** or **remotely via gcloud compute ssh**:

| Category | Commands | Purpose |
|---|---|---|
| **System** | `uname -a`, `uptime`, `hostnamectl`, `timedatectl` | System identity and uptime |
| **CPU** | `top -bn1 -o %CPU`, `mpstat`, `pidstat`, `cat /proc/loadavg` | CPU diagnostics, per-process breakdown |
| **Memory** | `free -mh`, `vmstat`, `cat /proc/meminfo`, `slabtop -o` | Memory usage, swap, slab cache |
| **Disk** | `df -hT`, `du -sh /var/log/*`, `lsblk`, `blkid`, `cat /proc/mounts`, `iostat` | Disk usage, mount points, I/O stats |
| **Processes** | `ps aux --sort=-%mem`, `ps aux --sort=-%cpu`, `pstree -p` | Process listing, resource consumers |
| **Network** | `ss -tulnp`, `ip addr`, `ip route`, `cat /etc/resolv.conf`, `iptables -L -n -v`, `netstat` | Listening ports, routes, DNS, firewall |
| **Logs** | `journalctl -u <service> --no-pager -n 100`, `dmesg --level=err,warn -T`, `tail -n 100 /var/log/syslog` | System and service logs |
| **Systemd** | `systemctl status <service>`, `systemctl list-units --failed`, `systemctl show <service>` | Service health |
| **Kernel** | `dmesg -T --level=emerg,alert,crit,err`, `sysctl`, `lsmod`, `modinfo` | Kernel errors, modules |
| **Packages** | `dpkg -l`, `dpkg -s`, `apt list`, `apt-cache`, `rpm -q`, `yum list` | Installed packages |
| **Remote** | `gcloud compute ssh <instance> --zone=<zone> --project=<project> --command="<cmd>"` | **Global SSH access to any VM** |

### 6.2 Remote VM Access (Global SSH)

The OS Engineer has **global SSH access** to all VMs via `gcloud compute ssh`. The SSH method (IAP tunneling vs. direct SSH) is **auto-selected by the Environment Discovery probe** based on the runtime environment:

- **IAP detected** → `--tunnel-through-iap` flag is used automatically
- **Direct SSH only** → standard `gcloud compute ssh` without IAP + security advisory recommending IAP enablement
- **Neither available** → agent surfaces actionable remediation steps (exact `gcloud` commands to enable IAP)

```
gcloud compute ssh <INSTANCE_NAME> --zone=<ZONE> --project=<PROJECT> <SSH_FLAGS> --command="<OS_COMMAND>"
```

**Security constraints on SSH:**
- The `--command` flag is **mandatory** - interactive SSH sessions are blocked.
- The inner command (inside `--command="..."`) is validated against the OS blocklist.
- The `--zone` and `--project` flags are required.
- Credentials are injected automatically via the Vault credential resolver.

### 6.3 Explicitly Blocked Patterns

Any command matching these patterns is **rejected before execution**:

- `rm`, `rmdir`, `unlink`, `shred` (destructive file operations)
- `mkfs`, `fdisk`, `parted`, `dd` (disk formatting/partitioning)
- `kill`, `killall`, `pkill` (process killing)
- `reboot`, `shutdown`, `poweroff`, `init` (system power)
- `systemctl start/stop/restart/enable/disable/mask/unmask/daemon-reload` (systemd write ops)
- `apt install/remove/purge/upgrade`, `yum install/remove`, `pip install` (package management write)
- `chmod`, `chown`, `chattr`, `chgrp` (permission changes)
- `useradd`, `userdel`, `usermod`, `passwd`, `groupadd`, `groupdel` (user management)
- `iptables -A/-D/-F/-X/-Z/-P/-I/-R`, `nft add/delete/flush/insert` (firewall write ops)
- `tee`, `sed -i`, `awk -i inplace` (file writes)
- `curl`, `wget`, `nc`, `ncat`, `netcat` (outbound network)
- `vi`, `vim`, `nano`, `emacs`, `ed` (editors)
- `crontab -e/-r`, `at` (scheduling)
- Backtick or `$(...)` subshell execution
- `>`, `>>` redirects (except to `/dev/null`)
- `;`, `&&`, `||` command chaining
- `export`, `source`, `eval`, `exec` (environment manipulation)

### 6.4 Command Validation Flow (4-Stage Pipeline)

```
Agent formulates command
        |
        v
+-------------------+
|  Stage 1:         |
|  Regex Blocklist  |---- MATCH ---- REJECT + log reason
|  Check            |
+-------+-----------+
        | PASS
        v
+-------------------+
|  Stage 2:         |
|  Allowlist Prefix |---- NO MATCH -- REJECT + log reason
|  Check            |
+-------+-----------+
        | MATCH
        v
+-------------------+
|  Stage 3:         |
|  SSH Inner-Command|---- BLOCKED --- REJECT + log reason
|  Validation       |  (only for gcloud compute ssh commands)
|  * Extract --command="..." payload
|  * Validate inner command against OS blocklist
|  * Block interactive SSH (no --command flag)
+-------+-----------+
        | PASS
        v
+-------------------+
|  Stage 4:         |
|  Argument         |---- SUSPICIOUS - REJECT + log reason
|  Sanitization     |  (injection detection)
+-------+-----------+
        | CLEAN
        v
    EXECUTE
```

---

## 7. Cloud Engineer Agent - Command Toolkit

### 7.1 Allowed Commands (Read-Only)

The Cloud Engineer Agent can execute CLI commands using the tenant's credentials.

**Explicitly: The Cloud Engineer CANNOT SSH into VMs.** It operates at the cloud API layer only. When OS-level data from a remote VM is needed, it reports the VM inventory and the Supervisor Router delegates SSH work to the OS Engineer.

#### AWS CLI (`aws`)

| Category | Commands | Purpose |
|---|---|---|
| **EC2** | `aws ec2 describe-instances`, `describe-vpcs`, `describe-subnets`, `describe-security-groups` | Compute and networking state |
| **IAM** | `aws iam get-user`, `list-roles`, `list-policies`, `simulate-principal-policy` | Identity and access diagnostics |
| **ELB** | `aws elbv2 describe-load-balancers`, `describe-target-groups`, `describe-target-health` | Load balancer health |
| **CloudWatch** | `aws cloudwatch get-metric-statistics`, `describe-alarms` | Metric data, alarm state |
| **Logs** | `aws logs filter-log-events`, `describe-log-groups` | CloudWatch log retrieval |
| **ECS/EKS** | `aws ecs describe-services`, `describe-tasks`, `aws eks describe-cluster` | Container orchestration state |
| **RDS** | `aws rds describe-db-instances`, `describe-events` | Database status |
| **S3** | `aws s3 ls`, `aws s3api get-bucket-policy` | Storage listing, policies |

#### GCP CLI (`gcloud`)

| Category | Commands | Purpose |
|---|---|---|
| **Compute** | `gcloud compute instances describe`, `instances list`, `disks list` | VM state |
| **Network** | `gcloud compute firewall-rules list`, `networks list`, `forwarding-rules list` | Network config |
| **IAM** | `gcloud projects get-iam-policy`, `iam roles list`, `iam service-accounts list` | Access policies |
| **GKE** | `gcloud container clusters describe`, `kubectl get pods`, `kubectl describe pod` | Kubernetes state |
| **Logging** | `gcloud logging read` | Log retrieval |

#### Azure CLI (`az`)

| Category | Commands | Purpose |
|---|---|---|
| **Compute** | `az vm show`, `az vm list`, `az vmss show` | VM state |
| **Network** | `az network nsg show`, `az network vnet show`, `az network lb show` | Network config |
| **IAM** | `az role assignment list`, `az ad sp show` | Access policies |
| **AKS** | `az aks show`, `kubectl get pods`, `kubectl describe pod` | Kubernetes state |

### 7.2 Explicitly Blocked Patterns

- Any `create`, `delete`, `update`, `modify`, `remove`, `add`, `set`, `assign`, `detach`, `attach`, `start`, `stop`, `restart`, `terminate`, `deallocate` subcommand
- `aws s3 cp`, `aws s3 mv`, `aws s3 rm`, `aws s3 sync`
- `kubectl apply`, `kubectl delete`, `kubectl edit`, `kubectl patch`, `kubectl scale`, `kubectl drain`, `kubectl cordon`
- `gcloud compute instances delete`, `create`, `start`, `stop`, `reset`
- `az vm create`, `delete`, `start`, `stop`, `restart`, `deallocate`

### 7.3 Credential Injection

Cloud CLI commands require credentials. The flow:

```
Agent formulates cloud CLI command
        |
        v
Vault Manager retrieves tenant credentials (by provider)
        |
        v
Credentials injected as environment variables
into the sandboxed execution context:
  * AWS: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION
  * GCP: GOOGLE_APPLICATION_CREDENTIALS (service account JSON path)
  * Azure: AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID
        |
        v
Command executed in sandboxed container
        |
        v
Credentials purged from environment after execution
```

Credentials are **never** embedded in the command string itself. Both the Cloud Engineer and OS Engineer (for SSH commands) use this same credential injection mechanism.

---

## 8. Command Execution Layer (The Hands)

### 8.1 Execution Model

Commands run inside the tenant's sandboxed container (Docker). Since each tenant already has a dedicated container (per main PRD Section 4.2), command execution happens within that same isolation boundary.

```
+----------------------------------------------------+
|              TENANT CONTAINER                       |
|                                                     |
|  +---------------+    +------------------------+   |
|  |  VCE-HQ       |    |  Execution Sandbox     |   |
|  |  Agent         |--->|                        |   |
|  |  Process       |    |  * Subprocess call     |   |
|  |                |<---|  * Timeout enforced    |   |
|  |                |    |  * stdout/stderr cap.  |   |
|  +---------------+    |  * Exit code tracked   |   |
|                        +------------------------+   |
|                                                     |
|  +------------------------------------------------+ |
|  |  Execution modes:                               | |
|  |  * OS local:  subprocess with /bin/sh           | |
|  |  * OS remote: gcloud compute ssh --command=     | |
|  |  * Cloud CLI: local exec with injected creds    | |
|  +------------------------------------------------+ |
+----------------------------------------------------+
```

### 8.2 Execution Constraints

| Constraint | Value | Rationale |
|---|---|---|
| **Command timeout** | 30 seconds | Prevent hung commands from blocking the pipeline |
| **Max output size** | 64 KB (stdout), 16 KB (stderr) | Prevent memory exhaustion from verbose commands |
| **Max iterations per agent** | 5 | Bound the ReAct loop |
| **Max total commands per session** | 15 | Prevent runaway sessions across agents |
| **Concurrent commands** | 1 (sequential only) | Predictable resource usage |
| **Output truncation** | Tail-truncate if exceeding max | Always capture the most recent output |

### 8.3 Execution Result Schema

```json
{
  "command_id": "uuid",
  "command": "df -hT",
  "agent": "os_engineer",
  "timestamp": "ISO-8601",
  "exit_code": 0,
  "stdout": "Filesystem     Type  Size  Used Avail Use% Mounted on\n...",
  "stderr": "",
  "duration_ms": 245,
  "validated_by": "allowlist_v1",
  "truncated": false
}
```

---

## 9. Security Review - Extended for Command Audit

### 9.1 Additional Review Responsibilities

| Responsibility | Details |
|---|---|
| **Command audit** | Review every command executed by specialist agents. Flag any that seem unnecessarily broad or could leak sensitive data. |
| **Output sensitivity scan** | Check command outputs for sensitive data (API keys, passwords, tokens) that should be redacted before presenting to the user. |
| **Execution justification** | Validate that each command was reasonably necessary for the diagnosis. |
| **ADR compliance** | Cross-reference commands against tenant ADRs (e.g., "we never query production databases directly"). |

### 9.2 Mandatory TLDR

Every final response produced by the Security Review **MUST begin with a TLDR** — a concise 1-3 sentence executive summary of the key findings. This allows busy engineers and CTOs to immediately understand the result without reading the full analysis.

Format:
```
**TLDR:** [1-3 sentence executive summary]
```

### 9.3 Adaptive Response Format

The Security Review adapts its output format to match the query type:
- **Informational responses** (VM lists, disk usage): Pass through cleanly with minimal annotation.
- **Diagnostic responses** (root cause analysis): Full structured review with Security Review Status, Validated Analysis, Security Flags, ADR References, and Final Remediation Playbook.

---

## 10. Environment Discovery - The Senses

### 10.1 Purpose

The Environment Discovery module (`discovery/probe.py`) runs at request time (with a 1-hour cache TTL) and probes the live GCP infrastructure to build an `EnvironmentProfile`. This profile is formatted as an `ENVIRONMENT CONTEXT` block and injected into **every agent's system prompt** — Router, OS Engineer, and Cloud Engineer all receive the same infrastructure awareness.

This eliminates the need for hardcoded SSH assumptions, manual prompt engineering per environment, and reduces "accepting defeat" behavior when agents encounter unknown infrastructure configurations.

### 10.2 What It Discovers

| Probe | Command | What It Reveals |
|---|---|---|
| **Project Identity** | `gcloud config get-value project` | Current project ID and service account |
| **Enabled APIs** | `gcloud services list --enabled` | Which GCP APIs are active (IAP, Resource Manager, Compute, etc.) |
| **Firewall Rules** | `gcloud compute firewall-rules list` | IAP availability, internal SSH rules, network topology |
| **VM Inventory** | `gcloud compute instances list` | Running VMs with zones, IPs, and status |

### 10.3 EnvironmentProfile Data Model

```python
@dataclass
class EnvironmentProfile:
    project_id: str
    service_account: str | None
    network_name: str | None
    iap_available: bool              # Is IAP TCP Forwarding configured?
    iap_firewall_rule: str | None    # Name of the IAP firewall rule
    direct_ssh_available: bool       # Is internal SSH (port 22) open?
    ssh_method: str                  # "iap" | "direct" | "restricted"
    running_vms: list[dict]          # [{name, zone, internal_ip, external_ip}]
    enabled_apis: list[str]          # List of enabled API service names
    cross_project_access: bool       # Can we list projects?
    raw_probe_data: dict             # Full raw probe output for debugging
```

### 10.4 SSH Method Selection Logic

```
IAP firewall rule detected?
    ├── YES → ssh_method = "iap"
    │         (always use --tunnel-through-iap)
    │
    └── NO → Internal SSH rule (port 22) detected?
              ├── YES → ssh_method = "direct"
              │         (use standard SSH + surface IAP security advisory)
              │
              └── NO → ssh_method = "restricted"
                        (surface actionable remediation with exact gcloud commands)
```

### 10.5 Advisory Intelligence

When the probe detects a suboptimal configuration, it doesn't just report the limitation — it proactively recommends remediation:

- **Direct SSH without IAP:** Surfaces a security advisory recommending IAP enablement with exact `gcloud` commands (enable API, create firewall rule, grant IAM role).
- **No SSH access at all:** Surfaces a critical recommendation with step-by-step `gcloud` commands to enable IAP TCP Forwarding, targeted at CTOs and infrastructure admins.

### 10.6 Prompt Injection

The `EnvironmentProfile.to_prompt_context()` method formats the discovered data into a structured text block:

```
=== ENVIRONMENT CONTEXT (auto-discovered at runtime) ===
Project: <project_id>
Service Account: <service_account>
SSH Method: <method + flags>
Running VMs:
  - <name> (zone: <zone>, ip: <ip>)
  ...
Enabled APIs: compute, iap, logging, ...
Cross-Project Access: YES/RESTRICTED
===
```

This block is injected as a system message into every agent's prompt, immediately after the agent's identity prompt.

### 10.7 Caching

The environment probe result is cached with a **1-hour TTL** via `get_environment_profile()`. This ensures:
- The first request per hour pays the probe cost (~4 subprocess calls)
- Subsequent requests reuse the cached profile
- Infrastructure changes are picked up within 1 hour

---

## 11. STM/LTM Extensions

### 11.1 STM - Command Execution Log Table

```sql
CREATE TABLE IF NOT EXISTS command_executions (
    command_id       TEXT PRIMARY KEY,
    session_id       TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
    agent            TEXT NOT NULL,       -- 'os_engineer' | 'cloud_engineer'
    command          TEXT NOT NULL,       -- The executed command string
    reasoning        TEXT NOT NULL,       -- Why the agent chose to run this
    exit_code        INTEGER,
    stdout           TEXT,
    stderr           TEXT,
    duration_ms      INTEGER,
    validated_by     TEXT NOT NULL,       -- 'allowlist_v1'
    truncated        INTEGER DEFAULT 0,  -- boolean
    created_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_cmd_exec_session ON command_executions(session_id);
```

### 11.2 STM - Token Usage Log Table

```sql
CREATE TABLE IF NOT EXISTS token_usage (
    usage_id         TEXT PRIMARY KEY,
    session_id       TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
    tenant_id        TEXT NOT NULL,
    agent            TEXT NOT NULL,
    prompt_tokens    INTEGER NOT NULL,
    completion_tokens INTEGER NOT NULL,
    total_tokens     INTEGER NOT NULL,
    model_name       TEXT NOT NULL,
    created_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_token_usage_session ON token_usage(session_id);
```

### 11.3 STM - Supervisor Decision Log

Router decisions (theory + delegation) are persisted as conversation turns in the existing `conversation_turns` table, formatted as:

```
[ROUTER THEORY]: <theory text>
[DELEGATED TO OS_ENGINEER]: <instruction text>
```

This ensures full traceability of the Supervisor's reasoning across cycles.

### 11.3 LTM - Diagnostic Patterns

When an incident is resolved, the successful diagnostic *pattern* (which commands were useful, what they revealed) is embedded into LTM alongside the resolution. This allows future RAG queries to retrieve not just "what happened" but "how we diagnosed it."

---

## 12. Configuration

| Setting | Default | Description |
|---|---|---|
| `VCE_CMD_MAX_ITERATIONS` | `5` | Maximum ReAct loop iterations per agent |
| `VCE_CMD_MAX_PER_SESSION` | `15` | Maximum total commands across all agents per session |
| `VCE_CMD_TIMEOUT_SECONDS` | `30` | Per-command execution timeout |
| `VCE_CMD_MAX_STDOUT_BYTES` | `65536` | Maximum stdout capture (64 KB) |
| `VCE_CMD_MAX_STDERR_BYTES` | `16384` | Maximum stderr capture (16 KB) |
| `VCE_CMD_ENABLED` | `true` | Global kill switch for command execution |

---

## 13. Resolved Questions

| # | Question | Resolution |
|---|---|---|
| 1 | Should command outputs be auto-redacted for secrets before storing in STM? | Rely on Security Review for now. Auto-redaction considered for v2. |
| 2 | Should the OS agent SSH to the host or use a local agent? | **SSH via `gcloud compute ssh`**. Simpler deployment, no agent installation required on target VMs. |
| 3 | Should there be a tenant-configurable allowlist extension? | Deferred to v2. Security risk too high for v1 without proper UI and guardrails. |
| 4 | How to handle distro differences (`apt` vs `yum`)? | Agent detects distro via `cat /etc/os-release` first, then uses appropriate commands. |

---

## 14. Success Metrics (Brain Module)

| Metric | Target |
|---|---|
| **Diagnosis accuracy with commands** | >= 90% (up from 80% without commands) |
| **Avg commands per session** | <= 3 (efficiency - agents should need few commands) |
| **Command rejection rate** | < 1% (agents learn to stay within allowlist) |
| **Time per command execution** | < 5 seconds average |
| **Security Review flag rate on commands** | < 5% (agents should not run unnecessary commands) |
| **Supervisor delegation accuracy** | >= 95% (correct agent chosen on first delegation per step) |
