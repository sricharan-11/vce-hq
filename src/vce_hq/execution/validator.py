"""Command validator — blocklist-first enforcement.

Implements the blocklist-first validation flow from PRD_Brain_vB1.2:
    Stage 1: Global Blocklist → REJECT if match
    Stage 1b: Mode Blocklist → REJECT if action verb is blocked in current mode
    Stage 2: Risk Signal Heuristic → tag NONE/ELEVATED/CRITICAL (never rejects)
    Stage 2.5: Horizontal API Translation → for curl/python, map HTTP methods to risk
    Stage 3: Injection Sanitization → reject shell injection vectors
    Stage 4: SSH inner-command validation → validate gcloud compute ssh payloads

The blocklist is the ONLY gate that rejects commands.
The Risk Signal Heuristic only decides downstream scrutiny (LLM Gate, HITL).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from enum import StrEnum

from vce_hq.config import settings

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════
# RISK SIGNAL — Tags for downstream security gate routing
# ══════════════════════════════════════════════════════════════

class RiskSignal(StrEnum):
    """Risk level tagged by the heuristic. Never causes rejection."""
    NONE = "none"           # Execute immediately, no LLM Gate
    ELEVATED = "elevated"   # Route to LLM Gate for review
    CRITICAL = "critical"   # Route to LLM Gate + flag for HITL


# ══════════════════════════════════════════════════════════════
# ENUMS & DATA CLASSES
# ══════════════════════════════════════════════════════════════

class CommandDomain(StrEnum):
    """Identifies which agent domain a command belongs to."""
    OS = "os"
    CLOUD = "cloud"

class ValidationStatus(StrEnum):
    """Result of command validation."""
    APPROVED = "approved"
    BLOCKED = "blocked_by_blocklist"
    MODE_BLOCKED = "blocked_by_mode"
    SANITIZATION_FAILED = "sanitization_failed"

@dataclass(frozen=True)
class ValidationResult:
    """Outcome of a single command validation.

    Attributes:
        status: Whether the command was approved or rejected.
        command: The original command string.
        domain: The domain the command was validated against.
        reason: Human-readable explanation (especially for rejections).
        risk_signal: The risk level tag (NONE/ELEVATED/CRITICAL).
            Only meaningful when status is APPROVED.
    """
    status: ValidationStatus
    command: str
    domain: CommandDomain
    reason: str
    risk_signal: RiskSignal = RiskSignal.NONE

    @property
    def approved(self) -> bool:
        """Whether the command passed validation."""
        return self.status == ValidationStatus.APPROVED


# ══════════════════════════════════════════════════════════════
# GLOBAL BLOCKLIST — Always blocked, regardless of mode
# ══════════════════════════════════════════════════════════════

_GLOBAL_BLOCKLIST_OS: list[re.Pattern[str]] = [
    # Filesystem destruction
    re.compile(r"\bmkfs\b", re.IGNORECASE),
    re.compile(r"\bfdisk\b", re.IGNORECASE),
    re.compile(r"\bparted\b", re.IGNORECASE),
    re.compile(r"\bdd\s", re.IGNORECASE),
    re.compile(r"\bshred\b", re.IGNORECASE),
    re.compile(r"\bwipefs\b", re.IGNORECASE),
    # Block device writes
    re.compile(r">\s*/dev/(sd|nvme|xvd|vd)", re.IGNORECASE),
    # Interactive editors (agents can't interact with TUI)
    re.compile(r"\b(vi|vim|nano|emacs|ed)\s"),
    # Fork bombs
    re.compile(r":\(\)\s*\{"),
    # Cron manipulation
    re.compile(r"\bcrontab\s+-(e|r)\b"),
    # User/account manipulation
    re.compile(r"\b(useradd|userdel|usermod)\b", re.IGNORECASE),
    re.compile(r"\bpasswd\b", re.IGNORECASE),
    # Privilege escalation configuration
    re.compile(r"\bvisudo\b", re.IGNORECASE),
    re.compile(r"\bsudoers\b", re.IGNORECASE),
    # Firewall flush (wipes all rules, exposes network)
    re.compile(r"\biptables\s+-(F|X)\b"),
    re.compile(r"\bnft\s+flush\b", re.IGNORECASE),
    # Swap manipulation
    re.compile(r"\b(swapoff|swapon)\b", re.IGNORECASE),
]

_GLOBAL_BLOCKLIST_CLOUD: list[re.Pattern[str]] = [
    # Entire project / account / resource group deletion
    re.compile(r"\bgcloud\s+projects\s+delete\b", re.IGNORECASE),
    re.compile(r"\baws\s+organizations\s+close-account\b", re.IGNORECASE),
    re.compile(r"\baz\s+group\s+delete\b", re.IGNORECASE),
    # Namespace deletion (cascading)
    re.compile(r"\bkubectl\s+delete\s+namespace\b", re.IGNORECASE),
    re.compile(r"\bkubectl\s+delete\s+ns\b", re.IGNORECASE),
    # Infrastructure-as-code teardown
    re.compile(r"\bterraform\s+destroy\b", re.IGNORECASE),
    re.compile(r"\bpulumi\s+destroy\b", re.IGNORECASE),
    # Dangerous flags combined with destructive verbs
    # (matched separately via _has_dangerous_flag_combo)
]

def _has_dangerous_flag_combo(command: str) -> str | None:
    """Check for dangerous flag combinations with destructive verbs.

    Flags like --force, --quiet, --no-wait combined with destructive
    verbs bypass safety prompts.

    Returns:
        A reason string if dangerous combo detected, None otherwise.
    """
    destructive_verb_pattern = re.compile(
        r"\b(delete|terminate|destroy|remove|rm|purge|deallocate|unlink)\b",
        re.IGNORECASE,
    )
    if not destructive_verb_pattern.search(command):
        return None

    dangerous_flags = [
        (re.compile(r"--force\b"), "--force with destructive verb"),
        (re.compile(r"--quiet\b"), "--quiet with destructive verb"),
        (re.compile(r"--no-wait\b"), "--no-wait with destructive verb"),
        (re.compile(r"-f\b(?!\s*[/\w])"), "-f (force) with destructive verb"),
    ]
    for pattern, reason in dangerous_flags:
        if pattern.search(command):
            return reason
    return None


# ══════════════════════════════════════════════════════════════
# MODE BLOCKLIST — Verb sets blocked per execution mode
# ══════════════════════════════════════════════════════════════

_DESTRUCTIVE_VERBS: set[str] = {
    "create", "delete", "terminate", "destroy", "rm", "rmdir",
    "kill", "killall", "pkill", "reboot", "shutdown", "poweroff",
    "unlink", "install", "remove", "purge", "deallocate",
}

_MUTATING_VERBS: set[str] = {
    "start", "stop", "restart", "update", "modify", "scale",
    "set", "apply", "patch", "edit", "enable", "disable",
    "daemon-reload", "link", "rollout", "chmod", "chown", "chgrp",
}

# Mode 1 blocks mutating + destructive verbs
# Mode 2 blocks destructive verbs only
# Mode 3 blocks nothing (only global blocklist applies)
_MODE_BLOCKED_VERBS: dict[int, set[str]] = {
    1: _MUTATING_VERBS | _DESTRUCTIVE_VERBS,
    2: _DESTRUCTIVE_VERBS,
    3: set(),  # No mode-specific blocks
}


# ══════════════════════════════════════════════════════════════
# CLI NAMESPACE PREFIXES — For verb extraction
# ══════════════════════════════════════════════════════════════

# Ordered longest-first so greedy matching works correctly.
_CLI_NAMESPACE_PREFIXES: list[str] = [
    # GCP — multi-level namespaces
    "gcloud compute instances ",
    "gcloud compute disks ",
    "gcloud compute firewall-rules ",
    "gcloud compute networks ",
    "gcloud compute subnets ",
    "gcloud compute forwarding-rules ",
    "gcloud compute backend-services ",
    "gcloud compute url-maps ",
    "gcloud compute addresses ",
    "gcloud compute routers ",
    "gcloud compute routes ",
    "gcloud compute ssl-certificates ",
    "gcloud compute target-https-proxies ",
    "gcloud compute machine-types ",
    "gcloud compute regions ",
    "gcloud compute zones ",
    "gcloud compute operations ",
    "gcloud compute ssh",  # special case — treated as read in verb extraction
    "gcloud compute ",
    "gcloud container clusters ",
    "gcloud container node-pools ",
    "gcloud container ",
    "gcloud run services ",
    "gcloud run revisions ",
    "gcloud run ",
    "gcloud app versions ",
    "gcloud app services ",
    "gcloud app ",
    "gcloud functions ",
    "gcloud sql instances ",
    "gcloud sql databases ",
    "gcloud sql ",
    "gcloud storage buckets ",
    "gcloud storage ",
    "gcloud billing projects ",
    "gcloud billing accounts ",
    "gcloud billing budgets ",
    "gcloud billing ",
    "gcloud services ",
    "gcloud logging ",
    "gcloud monitoring dashboards ",
    "gcloud monitoring ",
    "gcloud dns managed-zones ",
    "gcloud dns record-sets ",
    "gcloud dns ",
    "gcloud network-connectivity hubs ",
    "gcloud projects ",
    "gcloud iam roles ",
    "gcloud iam service-accounts ",
    "gcloud iam ",
    "gcloud resource-manager folders ",
    "gcloud organizations ",
    "gcloud asset ",
    "gcloud config configurations ",
    "gcloud config ",
    "gcloud auth ",
    "gcloud ",
    # AWS — two-level namespaces
    "aws ec2 ",
    "aws iam ",
    "aws elbv2 ",
    "aws elb ",
    "aws cloudwatch ",
    "aws logs ",
    "aws ecs ",
    "aws eks ",
    "aws rds ",
    "aws s3api ",
    "aws s3 ",
    "aws sts ",
    "aws lambda ",
    "aws route53 ",
    "aws sns ",
    "aws sqs ",
    "aws autoscaling ",
    "aws cloudformation ",
    "aws pricing ",
    "aws ce ",
    "aws organizations ",
    "aws account ",
    "aws support ",
    "aws ",
    # Azure — two-level namespaces
    "az vm ",
    "az vmss ",
    "az network nsg ",
    "az network vnet ",
    "az network lb ",
    "az network public-ip ",
    "az network nic ",
    "az network route-table ",
    "az network application-gateway ",
    "az network dns zone ",
    "az network dns record-set ",
    "az network ",
    "az role assignment ",
    "az role definition ",
    "az ad sp ",
    "az ad ",
    "az aks ",
    "az container ",
    "az monitor metrics ",
    "az monitor log-analytics ",
    "az monitor activity-log ",
    "az monitor ",
    "az storage account ",
    "az storage blob ",
    "az storage container ",
    "az storage ",
    "az resource ",
    "az account ",
    "az group ",
    "az billing ",
    "az consumption ",
    "az ",
    # Kubernetes
    "kubectl ",
    # Systemd
    "systemctl ",
]

# OS utilities that are inherently read-only (the binary name IS the verb)
_READ_ONLY_OS_UTILITIES: set[str] = {
    "ps", "pstree", "top", "htop",
    "df", "du", "lsblk", "blkid", "findmnt", "stat", "iostat",
    "free", "vmstat", "slabtop",
    "ss", "ip", "netstat", "nft",
    "journalctl", "dmesg",
    "cat", "head", "tail", "less", "more", "zcat", "grep",
    "uname", "uptime", "hostnamectl", "timedatectl", "hostname",
    "mpstat", "pidstat", "nproc", "lscpu", "lsmem", "lsns", "lsof",
    "whoami", "id", "w", "who", "last", "lastlog",
    "date", "cal", "env", "printenv",
    "sysctl", "lsmod", "modinfo",
    "dpkg", "apt-cache", "rpm", "yum", "mount", "ulimit", "getconf",
    "ls",
}


# ══════════════════════════════════════════════════════════════
# VERB EXTRACTION
# ══════════════════════════════════════════════════════════════

def _extract_action_verb(command: str) -> str | None:
    """Extract the action verb from a command by stripping CLI namespace prefixes.

    Examples:
        "gcloud compute instances list --project=x" → "list"
        "kubectl delete pod my-pod" → "delete"
        "systemctl restart nginx" → "restart"
        "ps aux" → "ps" (bare OS utility)
        "aws ec2 describe-instances" → "describe-instances" → verb root "describe"

    Returns:
        The extracted verb string, or None if extraction fails.
    """
    cmd_lower = command.lower().strip()

    # Try stripping CLI namespace prefixes (longest-first)
    for prefix in _CLI_NAMESPACE_PREFIXES:
        if cmd_lower.startswith(prefix.lower()):
            remainder = command[len(prefix):].strip()
            if remainder:
                # The first token after the namespace is the action verb
                verb = remainder.split()[0].lower()
                # Handle compound verbs like "describe-instances" → "describe"
                if "-" in verb:
                    verb_root = verb.split("-")[0]
                    return verb_root
                return verb
            # gcloud compute ssh — the prefix itself is the command
            if "ssh" in prefix:
                return "ssh"
            return None

    # Bare OS utility — the command name itself is the verb
    first_token = command.split()[0].lower() if command.split() else None
    if first_token:
        # Strip path if present (e.g., /usr/bin/ps → ps)
        bare = first_token.rsplit("/", 1)[-1]
        return bare

    return None


# ══════════════════════════════════════════════════════════════
# RISK SIGNAL HEURISTIC — Tags, never rejects
# ══════════════════════════════════════════════════════════════

def _assess_risk_signal(command: str, verb: str | None) -> RiskSignal:
    """Tag a command with a risk level for downstream security gate routing.

    This function NEVER rejects — it only decides how much scrutiny
    the LLM Gate and HITL should apply.

    Args:
        command: The full command string.
        verb: The extracted action verb (may be None).

    Returns:
        A RiskSignal tag.
    """
    if verb is None:
        # Can't determine verb — treat as elevated for safety
        return RiskSignal(settings.unknown_binary_risk.lower())

    # Check if it's a known read-only OS utility
    if verb in _READ_ONLY_OS_UTILITIES:
        return RiskSignal.NONE

    # Check destructive verbs → CRITICAL
    if verb in _DESTRUCTIVE_VERBS:
        return RiskSignal.CRITICAL

    # Check mutating verbs → ELEVATED
    if verb in _MUTATING_VERBS:
        return RiskSignal.ELEVATED

    # Known read verbs from cloud CLIs
    _read_verbs = {
        "list", "describe", "get", "show", "status", "info", "view",
        "explain", "logs", "log", "top", "read", "query", "search",
        "filter", "can-i", "cluster-info", "api-resources", "api-versions",
        "version", "auth", "ls", "head", "history", "ssh",
    }
    if verb in _read_verbs:
        return RiskSignal.NONE

    # Unknown verb — route to LLM Gate for review
    return RiskSignal(settings.unknown_binary_risk.lower())


# ══════════════════════════════════════════════════════════════
# HORIZONTAL API TRANSLATION — Risk signals for raw scripts
# ══════════════════════════════════════════════════════════════

# Known read-only POST endpoints (APIs that use POST for queries)
_READ_ONLY_POST_ENDPOINTS: list[re.Pattern[str]] = [
    re.compile(r"monitoring\.googleapis\.com/.*/timeSeries:query", re.IGNORECASE),
    re.compile(r"logging\.googleapis\.com/.*/entries:list", re.IGNORECASE),
    re.compile(r"/graphql\b", re.IGNORECASE),
]

def _assess_script_risk(command: str) -> RiskSignal:
    """Assess risk for raw scripts (curl, python) via HTTP method analysis.

    Maps HTTP methods to risk signals:
        GET/HEAD/OPTIONS → NONE
        POST (to known read endpoints) → NONE
        POST/PUT/PATCH → ELEVATED
        DELETE → CRITICAL

    Args:
        command: The full script command string.

    Returns:
        A RiskSignal for the script.
    """
    # Detect HTTP methods
    has_delete = bool(re.search(
        r"(-X\s*DELETE|requests\.delete|method=['\"]DELETE['\"])",
        command, re.IGNORECASE,
    ))
    has_mutating = bool(re.search(
        r"(-X\s*(POST|PUT|PATCH)|requests\.(post|put|patch)|method=['\"](?:POST|PUT|PATCH)['\"])",
        command, re.IGNORECASE,
    ))

    if has_delete:
        return RiskSignal.CRITICAL
    if has_mutating:
        # Check if POST is to a known read-only endpoint
        endpoints = re.findall(r'https?://[^\s\'"]+', command)
        for endpoint in endpoints:
            if any(p.search(endpoint) for p in _READ_ONLY_POST_ENDPOINTS):
                return RiskSignal.NONE
        return RiskSignal.ELEVATED

    return RiskSignal.NONE


# ══════════════════════════════════════════════════════════════
# SHARED — Shell Injection Sanitization (unchanged from v1.2)
# ══════════════════════════════════════════════════════════════

_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    # Subshell execution
    re.compile(r"\$\("),               # $(...)
    re.compile(r"`"),                   # backtick subshell
    # Output redirection to files (> or >> to anything except /dev/null)
    re.compile(r">\s*(?!/dev/null)"),   # > not followed by /dev/null
    re.compile(r">>\s*(?!/dev/null)"),  # >> not followed by /dev/null
    # Pipe to write commands
    re.compile(r"\|\s*(tee|dd|bash|sh|zsh|python|perl|ruby|node)\b"),
    # Semicolons and logical operators for command chaining
    re.compile(r";\s*\S"),             # command chaining via semicolon
    re.compile(r"&&\s*\S"),            # AND chaining
    re.compile(r"\|\|\s*\S"),          # OR chaining
    # Environment manipulation
    re.compile(r"\bexport\s"),
    re.compile(r"\bsource\s"),
    re.compile(r"\beval\s"),
    re.compile(r"\bexec\s"),
]

# Safe pipes: allow piping to read-only filter commands
_SAFE_PIPE_TARGETS: list[str] = [
    "grep", "awk", "sed", "sort", "uniq", "wc", "head", "tail",
    "cut", "tr", "column", "less", "more", "cat", "jq", "xargs echo",
]


# ══════════════════════════════════════════════════════════════
# BLOCKLIST REFERENCE (for Router prompt injection)
# ══════════════════════════════════════════════════════════════

def get_blocklist_reference() -> str:
    """Build a formatted reference of blocklist constraints and mode restrictions.

    Used by the Supervisor Router to understand what's blocked and why,
    so it can suggest alternative approaches when a command is rejected.

    Returns:
        A multi-line string describing blocklist patterns and mode restrictions.
    """
    mode_num = int(str(settings.execution_mode)[-1])

    sections = [
        "## Blocklist Constraints (Current Mode: {})".format(settings.execution_mode.value),
        "",
        "### Global Blocklist (always blocked, all modes)",
        "OS: mkfs, fdisk, parted, dd, shred, wipefs, vi/vim/nano/emacs, fork bombs, "
        "crontab -e/-r, useradd/userdel/usermod, passwd, visudo, iptables -F/-X, "
        "nft flush, swapoff/swapon, block device writes",
        "Cloud: gcloud projects delete, aws organizations close-account, "
        "az group delete, kubectl delete namespace, terraform destroy, "
        "pulumi destroy, --force/--quiet/--no-wait with destructive verbs",
        "",
        "### Mode Restrictions",
    ]

    blocked = _MODE_BLOCKED_VERBS.get(mode_num, set())
    if blocked:
        mut = sorted(_MUTATING_VERBS & blocked)
        dest = sorted(_DESTRUCTIVE_VERBS & blocked)
        if mut:
            sections.append(f"  Mutating verbs BLOCKED: {', '.join(mut)}")
        if dest:
            sections.append(f"  Destructive verbs BLOCKED: {', '.join(dest)}")
    else:
        sections.append("  No mode-specific verb restrictions (Mode 3 — all verbs allowed).")

    sections.extend([
        "",
        "### What IS allowed",
        "Any command that does NOT match the above blocklist patterns. "
        "There is no approved-command list — agents are free to use any CLI tool, "
        "subcommand, or utility as long as it doesn't hit a blocklist rule.",
    ])

    return "\n".join(sections)


# ══════════════════════════════════════════════════════════════
# PUBLIC API
# ══════════════════════════════════════════════════════════════

def validate_command(command: str, domain: CommandDomain) -> ValidationResult:
    """Validate a command using the blocklist-first pipeline.

    The blocklist is the ONLY gate that rejects commands.
    The Risk Signal Heuristic tags commands for downstream scrutiny
    (LLM Gate, HITL) but never rejects.

    Pipeline:
        Stage 1:  Global Blocklist check → REJECT if match
        Stage 1b: Mode Blocklist check → REJECT if action verb blocked in mode
        Stage 2:  Risk Signal Heuristic → tag NONE/ELEVATED/CRITICAL
        Stage 2.5: Horizontal API Translation (curl/python only)
        Stage 3:  SSH inner-command validation
        Stage 4:  Injection sanitization

    Args:
        command: The raw command string to validate.
        domain: Whether this is an OS or Cloud command.

    Returns:
        A ``ValidationResult`` with risk_signal set if approved.
    """
    command = command.strip()

    if not command:
        return ValidationResult(
            status=ValidationStatus.SANITIZATION_FAILED,
            command=command,
            domain=domain,
            reason="Empty command",
        )

    # Select domain-specific global blocklist
    if domain == CommandDomain.OS:
        global_blocklist = _GLOBAL_BLOCKLIST_OS
    else:
        global_blocklist = _GLOBAL_BLOCKLIST_CLOUD

    # ── Stage 1: Global Blocklist ──────────────────────────────
    for pattern in global_blocklist:
        if pattern.search(command):
            reason = f"Globally blocked pattern: {pattern.pattern}"
            logger.warning(
                "Command REJECTED (global blocklist) | domain=%s cmd='%s' reason='%s'",
                domain.value, command, reason,
            )
            return ValidationResult(
                status=ValidationStatus.BLOCKED,
                command=command,
                domain=domain,
                reason=reason,
            )

    # Cloud domain: check dangerous flag combos
    if domain == CommandDomain.CLOUD:
        flag_issue = _has_dangerous_flag_combo(command)
        if flag_issue:
            logger.warning(
                "Command REJECTED (dangerous flag combo) | domain=%s cmd='%s' reason='%s'",
                domain.value, command, flag_issue,
            )
            return ValidationResult(
                status=ValidationStatus.BLOCKED,
                command=command,
                domain=domain,
                reason=f"Globally blocked: {flag_issue}",
            )

    # ── Stage 1b: Mode Blocklist ───────────────────────────────
    mode_num = int(str(settings.execution_mode)[-1])
    blocked_verbs = _MODE_BLOCKED_VERBS.get(mode_num, set())

    verb = _extract_action_verb(command)

    if verb and verb in blocked_verbs:
        reason = f"Verb '{verb}' is blocked in {settings.execution_mode.value}"
        logger.warning(
            "Command REJECTED (mode blocklist) | domain=%s mode=%s verb='%s' cmd='%s'",
            domain.value, settings.execution_mode.value, verb, command,
        )
        return ValidationResult(
            status=ValidationStatus.MODE_BLOCKED,
            command=command,
            domain=domain,
            reason=reason,
        )

    # ── Stage 2: Risk Signal Heuristic ─────────────────────────
    # For raw scripts (curl, python), use HTTP method analysis
    if command.startswith("python") or command.startswith("curl"):
        risk_signal = _assess_script_risk(command)
        # Also check script endpoints against global blocklist
        endpoints = re.findall(r'https?://[^\s\'"]+', command)
        for endpoint in endpoints:
            for pattern in _GLOBAL_BLOCKLIST_CLOUD:
                if pattern.search(endpoint):
                    return ValidationResult(
                        status=ValidationStatus.BLOCKED,
                        command=command,
                        domain=domain,
                        reason=f"Script targets globally blocked endpoint: {endpoint}",
                    )
    else:
        risk_signal = _assess_risk_signal(command, verb)

    # ── Stage 3: SSH inner-command validation ──────────────────
    if domain == CommandDomain.OS and command.startswith("gcloud compute ssh"):
        ssh_issue = _validate_ssh_inner_command(command)
        if ssh_issue:
            logger.warning(
                "Command REJECTED (SSH inner-command) | cmd='%s' reason='%s'",
                command, ssh_issue,
            )
            return ValidationResult(
                status=ValidationStatus.BLOCKED,
                command=command,
                domain=domain,
                reason=ssh_issue,
                risk_signal=risk_signal,
            )

    # ── Stage 4: Injection Sanitization ────────────────────────
    sanitization_issue = _check_injection(command)
    if sanitization_issue:
        logger.warning(
            "Command REJECTED (sanitization) | domain=%s cmd='%s' reason='%s'",
            domain.value, command, sanitization_issue,
        )
        return ValidationResult(
            status=ValidationStatus.SANITIZATION_FAILED,
            command=command,
            domain=domain,
            reason=sanitization_issue,
            risk_signal=risk_signal,
        )

    # ── All stages passed ─────────────────────────────────────
    logger.info(
        "Command APPROVED | domain=%s risk=%s cmd='%s'",
        domain.value, risk_signal.value, command,
    )
    return ValidationResult(
        status=ValidationStatus.APPROVED,
        command=command,
        domain=domain,
        reason=f"Passed blocklist validation (risk: {risk_signal.value})",
        risk_signal=risk_signal,
    )


def _check_injection(command: str) -> str | None:
    """Check for shell injection patterns.

    Pipes to safe filter commands (grep, awk, etc.) are allowed.
    All other injection vectors are blocked.

    Args:
        command: The command to check.

    Returns:
        A reason string if injection is detected, ``None`` if clean.
    """
    # First, handle pipes: split on pipe and check each segment
    if "|" in command:
        segments = command.split("|")
        for segment in segments[1:]:  # Skip the first segment (the main command)
            segment = segment.strip()
            if not segment:
                continue
            # Check if the pipe target is a safe filter command
            if not any(segment.startswith(safe) for safe in _SAFE_PIPE_TARGETS):
                return f"Pipe to non-allowlisted command: '{segment.split()[0]}'"

    # Check other injection patterns
    for pattern in _INJECTION_PATTERNS:
        match = pattern.search(command)
        if match:
            # Allow pipes to safe targets (already checked above)
            if match.group(0).startswith("|"):
                continue
            return f"Shell injection pattern detected: '{match.group(0)}'"

    return None


def _validate_ssh_inner_command(command: str) -> str | None:
    """Validate the inner command payload of a gcloud compute ssh command.

    Extracts the ``--command="..."`` argument and validates it against
    the OS global blocklist and mode blocklist.

    Args:
        command: The full ``gcloud compute ssh ... --command="..."`` string.

    Returns:
        A reason string if validation fails, ``None`` if the inner command is safe.
    """
    # Extract inner command from --command="..." or --command='...'
    inner_match = re.search(r'--command=["\'](.*?)["\']', command)
    if not inner_match:
        # No --command flag means interactive SSH — block it
        if "--command" not in command:
            return "Interactive SSH sessions are not allowed. Use --command=\"<cmd>\" to run a specific command."
        return None

    inner_cmd = inner_match.group(1).strip()
    if not inner_cmd:
        return "Empty inner command in gcloud compute ssh"

    # Validate inner command against OS global blocklist
    for pattern in _GLOBAL_BLOCKLIST_OS:
        if pattern.search(inner_cmd):
            return f"SSH inner command blocked by global blocklist: {pattern.pattern}"

    # Validate inner command against mode blocklist
    mode_num = int(str(settings.execution_mode)[-1])
    blocked_verbs = _MODE_BLOCKED_VERBS.get(mode_num, set())
    inner_verb = _extract_action_verb(inner_cmd)
    if inner_verb and inner_verb in blocked_verbs:
        return f"SSH inner command verb '{inner_verb}' is blocked in {settings.execution_mode.value}"

    return None
