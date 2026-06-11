"""Command validator — allowlist/blocklist enforcement.

Implements the three-stage validation flow from PRD_Brain_v1.0 §5.3:
    1. Regex blocklist check (reject known-dangerous patterns)
    2. Allowlist prefix check (only allow known-safe command prefixes)
    3. Argument sanitization (reject shell injection vectors)

Every command an agent formulates MUST pass all three stages before
execution. Validation failures are logged with the rejection reason
for audit and agent feedback.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from enum import StrEnum

logger = logging.getLogger(__name__)


class CommandDomain(StrEnum):
    """Identifies which agent domain a command belongs to."""
    OS = "os"
    CLOUD = "cloud"


class ValidationStatus(StrEnum):
    """Result of command validation."""
    APPROVED = "approved"
    BLOCKED = "blocked_by_blocklist"
    NOT_ALLOWLISTED = "not_in_allowlist"
    SANITIZATION_FAILED = "sanitization_failed"


@dataclass(frozen=True)
class ValidationResult:
    """Outcome of a single command validation.

    Attributes:
        status: Whether the command was approved or rejected.
        command: The original command string.
        domain: The domain the command was validated against.
        reason: Human-readable explanation (especially for rejections).
    """
    status: ValidationStatus
    command: str
    domain: CommandDomain
    reason: str

    @property
    def approved(self) -> bool:
        """Whether the command passed validation."""
        return self.status == ValidationStatus.APPROVED


# ══════════════════════════════════════════════════════════════
# OS DOMAIN — Allowlists and Blocklists
# ══════════════════════════════════════════════════════════════

# Allowlisted command prefixes for OS diagnostics (read-only).
# The command must start with one of these prefixes.
_OS_ALLOWLIST_PREFIXES: list[str] = [
    # System
    "uname", "uptime", "hostnamectl", "timedatectl", "hostname",
    # CPU
    "top -b", "mpstat", "pidstat", "cat /proc/loadavg", "nproc",
    # Memory
    "free", "vmstat", "cat /proc/meminfo", "slabtop -o",
    # Disk
    "df", "du -s", "du -sh", "lsblk", "blkid", "cat /proc/mounts",
    "iostat", "findmnt", "stat ",
    # Processes
    "ps ", "pstree", "cat /proc/", "ls /proc/",
    # Network
    "ss ", "ip addr", "ip route", "ip link", "ip neigh",
    "cat /etc/resolv.conf", "cat /etc/hosts",
    "iptables -L", "iptables -S", "iptables -nvL",
    "nft list", "netstat ",
    # Logs
    "journalctl ", "dmesg", "tail ", "head ", "cat /var/log/",
    "zcat /var/log/", "less /var/log/", "grep ",
    # Systemd
    "systemctl status", "systemctl list-units", "systemctl show",
    "systemctl is-active", "systemctl is-enabled", "systemctl is-failed",
    # Kernel
    "sysctl ", "lsmod", "modinfo",
    # Packages
    "dpkg -l", "dpkg -s", "dpkg --list",
    "apt list", "apt-cache", "apt show",
    "rpm -q", "yum list", "yum info",
    # Misc read-only
    "whoami", "id", "w", "who", "last", "lastlog",
    "date", "cal", "env", "printenv",
    "lscpu", "lsmem", "lsns", "lsof",
    "mount", "cat /etc/fstab",
    "ulimit", "getconf",
    # Remote VM access via gcloud SSH (inner command validated separately)
    "gcloud compute ssh",
]

# Regex patterns that ALWAYS block a command, regardless of allowlist.
_OS_BLOCKLIST_PATTERNS: list[re.Pattern[str]] = [
    # Destructive file operations
    re.compile(r"\brm\s", re.IGNORECASE),
    re.compile(r"\brmdir\s", re.IGNORECASE),
    re.compile(r"\bunlink\s", re.IGNORECASE),
    re.compile(r"\bshred\s", re.IGNORECASE),
    # Disk formatting / partitioning
    re.compile(r"\bmkfs\b", re.IGNORECASE),
    re.compile(r"\bfdisk\b", re.IGNORECASE),
    re.compile(r"\bparted\b", re.IGNORECASE),
    re.compile(r"\bdd\s", re.IGNORECASE),
    # Process killing
    re.compile(r"\bkill\s", re.IGNORECASE),
    re.compile(r"\bkillall\s", re.IGNORECASE),
    re.compile(r"\bpkill\s", re.IGNORECASE),
    # System power
    re.compile(r"\breboot\b", re.IGNORECASE),
    re.compile(r"\bshutdown\b", re.IGNORECASE),
    re.compile(r"\bpoweroff\b", re.IGNORECASE),
    re.compile(r"\binit\s+[0-6]\b", re.IGNORECASE),
    # Systemd write operations
    re.compile(r"\bsystemctl\s+(start|stop|restart|enable|disable|mask|unmask|daemon-reload)\b"),
    # Package management (write)
    re.compile(r"\bapt\s+(install|remove|purge|upgrade|dist-upgrade|autoremove)\b"),
    re.compile(r"\bapt-get\s+(install|remove|purge|upgrade)\b"),
    re.compile(r"\byum\s+(install|remove|erase|update|upgrade)\b"),
    re.compile(r"\bdnf\s+(install|remove|erase|update|upgrade)\b"),
    re.compile(r"\bpip\s+install\b"),
    re.compile(r"\bpip3\s+install\b"),
    # Permission changes
    re.compile(r"\bchmod\s"),
    re.compile(r"\bchown\s"),
    re.compile(r"\bchattr\s"),
    re.compile(r"\bchgrp\s"),
    # User management
    re.compile(r"\buseradd\b"),
    re.compile(r"\buserdel\b"),
    re.compile(r"\busermod\b"),
    re.compile(r"\bpasswd\b"),
    re.compile(r"\bgroupadd\b"),
    re.compile(r"\bgroupdel\b"),
    # Firewall write operations
    re.compile(r"\biptables\s+-(A|D|F|X|Z|P|I|R)\b"),
    re.compile(r"\bnft\s+(add|delete|flush|insert)\b"),
    # File writes
    re.compile(r"\btee\s"),
    re.compile(r"\bsed\s+-i\b"),
    re.compile(r"\bawk\s+-i\s+inplace\b"),
    # Outbound network
    re.compile(r"\bcurl\s"),
    re.compile(r"\bwget\s"),
    re.compile(r"\b(nc|ncat|netcat)\s"),
    # Editors (interactive / write)
    re.compile(r"\b(vi|vim|nano|emacs|ed)\s"),
    # Cron / scheduling
    re.compile(r"\bcrontab\s+-[er]\b"),
    re.compile(r"\bat\s"),
]


# ══════════════════════════════════════════════════════════════
# CLOUD DOMAIN — Allowlists and Blocklists
# ══════════════════════════════════════════════════════════════

_CLOUD_ALLOWLIST_PREFIXES: list[str] = [
    # ── AWS — read-only ───────────────────────────────────────
    "aws ec2 describe-", "aws ec2 get-",
    "aws iam get-", "aws iam list-", "aws iam simulate-",
    "aws iam get-account-summary",
    "aws elbv2 describe-",
    "aws elb describe-",
    "aws cloudwatch get-", "aws cloudwatch describe-", "aws cloudwatch list-",
    "aws logs filter-log-events", "aws logs describe-log-groups",
    "aws logs describe-log-streams", "aws logs get-log-events", "aws logs get-",
    "aws ecs describe-", "aws ecs list-",
    "aws eks describe-", "aws eks list-",
    "aws rds describe-",
    "aws s3 ls", "aws s3api get-", "aws s3api list-", "aws s3api head-",
    "aws sts get-caller-identity",
    "aws lambda get-", "aws lambda list-",
    "aws route53 list-", "aws route53 get-",
    "aws sns list-", "aws sns get-",
    "aws sqs list-", "aws sqs get-",
    "aws sqs receive-message",
    "aws autoscaling describe-",
    "aws cloudformation describe-", "aws cloudformation list-",
    "aws pricing get-", "aws ce get-",
    "aws organizations describe-", "aws organizations list-",
    "aws account get-",
    "aws support describe-",
    # ── GCP — read-only ───────────────────────────────────────
    # Compute
    "gcloud compute instances list", "gcloud compute instances describe",
    "gcloud compute disks list", "gcloud compute disks describe",
    "gcloud compute firewall-rules list", "gcloud compute firewall-rules describe",
    "gcloud compute networks list", "gcloud compute networks describe",
    "gcloud compute subnets list", "gcloud compute subnets describe",
    "gcloud compute forwarding-rules list", "gcloud compute forwarding-rules describe",
    "gcloud compute backend-services list", "gcloud compute backend-services describe",
    "gcloud compute url-maps list", "gcloud compute url-maps describe",
    "gcloud compute addresses list", "gcloud compute addresses describe",
    "gcloud compute routers list", "gcloud compute routers describe",
    "gcloud compute routes list",
    "gcloud compute ssl-certificates list",
    "gcloud compute target-https-proxies list",
    "gcloud compute machine-types list",
    "gcloud compute regions list", "gcloud compute zones list",
    "gcloud compute operations list", "gcloud compute operations describe",
    # IAM
    "gcloud projects get-iam-policy", "gcloud projects describe",
    "gcloud projects list",
    "gcloud iam roles list", "gcloud iam roles describe",
    "gcloud iam service-accounts list", "gcloud iam service-accounts describe",
    "gcloud iam service-accounts get-iam-policy",
    "gcloud resource-manager folders list",
    "gcloud organizations list",
    # GKE / Kubernetes
    "gcloud container clusters describe", "gcloud container clusters list",
    "gcloud container node-pools list", "gcloud container node-pools describe",
    # Cloud Run / App Engine
    "gcloud run services list", "gcloud run services describe",
    "gcloud run revisions list",
    "gcloud app versions list", "gcloud app services list",
    # Cloud Functions
    "gcloud functions list", "gcloud functions describe",
    # Storage / SQL / Services
    "gcloud sql instances describe", "gcloud sql instances list",
    "gcloud sql databases list",
    "gcloud storage ls", "gcloud storage buckets list",
    "gcloud services list", "gcloud services enable --dry-run",
    # Monitoring / Logging
    "gcloud logging read", "gcloud logging logs list",
    "gcloud logging sinks list",
    "gcloud monitoring dashboards list",
    # DNS / Networking
    "gcloud dns managed-zones list", "gcloud dns record-sets list",
    "gcloud network-connectivity hubs list",
    # Config / Meta
    "gcloud config list", "gcloud config configurations list",
    "gcloud info",
    "gcloud auth list",
    # ── Azure — read-only ─────────────────────────────────────
    "az vm show", "az vm list",
    "az vmss show", "az vmss list",
    "az network nsg show", "az network nsg list",
    "az network vnet show", "az network vnet list",
    "az network lb show", "az network lb list",
    "az network public-ip show", "az network public-ip list",
    "az network nic show", "az network nic list",
    "az network route-table show", "az network route-table list",
    "az network application-gateway show", "az network application-gateway list",
    "az network dns zone list", "az network dns record-set list",
    "az role assignment list", "az role definition list",
    "az ad sp show", "az ad sp list",
    "az aks show", "az aks list",
    "az container show", "az container list",
    "az monitor metrics list", "az monitor log-analytics query",
    "az monitor activity-log list",
    "az storage account show", "az storage account list",
    "az storage blob list", "az storage container list",
    "az resource show", "az resource list",
    "az account show", "az account list",
    "az account subscription list",
    "az group show", "az group list",
    # ── Kubernetes — read-only ────────────────────────────────
    "kubectl get ", "kubectl describe ",
    "kubectl logs ", "kubectl log ",
    "kubectl top ", "kubectl cluster-info",
    "kubectl api-resources", "kubectl api-versions",
    "kubectl config view", "kubectl config current-context",
    "kubectl config get-contexts",
    "kubectl version",
    "kubectl explain ",
    "kubectl rollout status",
    "kubectl rollout history",
    "kubectl auth can-i",
]

_CLOUD_BLOCKLIST_PATTERNS: list[re.Pattern[str]] = [
    # AWS write operations
    re.compile(r"\baws\s+\S+\s+(create|delete|update|modify|remove|put-|run-|"
               r"start|stop|reboot|terminate|deregister|revoke|attach|detach|"
               r"enable|disable|associate|disassociate)\b", re.IGNORECASE),
    re.compile(r"\baws\s+s3\s+(cp|mv|rm|sync|mb|rb)\b", re.IGNORECASE),
    re.compile(r"\baws\s+s3api\s+(put-|delete-|create-)\b", re.IGNORECASE),
    # GCP write operations
    re.compile(r"\bgcloud\s+\S+\s+\S+\s+(create|delete|update|reset|start|stop|"
               r"set-|add-|remove-)\b", re.IGNORECASE),
    # Azure write operations
    re.compile(r"\baz\s+\S+\s+(create|delete|update|start|stop|restart|deallocate|"
               r"set|assign|remove)\b", re.IGNORECASE),
    # kubectl write operations
    re.compile(r"\bkubectl\s+(apply|delete|edit|patch|scale|drain|cordon|uncordon|"
               r"taint|label|annotate|rollout|set|replace|create|run|expose)\b",
               re.IGNORECASE),
]


# ══════════════════════════════════════════════════════════════
# SHARED — Shell Injection Sanitization
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
# PUBLIC API
# ══════════════════════════════════════════════════════════════

def validate_command(command: str, domain: CommandDomain) -> ValidationResult:
    """Validate a command against the allowlist/blocklist for a domain.

    Implements the three-stage flow:
        1. Blocklist check (regex) → reject if any pattern matches
        2. Allowlist check (prefix) → reject if no prefix matches
        3. Sanitization (injection detection) → reject if suspicious

    Args:
        command: The raw command string to validate.
        domain: Whether this is an OS or Cloud command.

    Returns:
        A ``ValidationResult`` indicating approval or rejection with reason.
    """
    command = command.strip()

    if not command:
        return ValidationResult(
            status=ValidationStatus.SANITIZATION_FAILED,
            command=command,
            domain=domain,
            reason="Empty command",
        )

    # Select domain-specific lists
    if domain == CommandDomain.OS:
        blocklist = _OS_BLOCKLIST_PATTERNS
        allowlist = _OS_ALLOWLIST_PREFIXES
    else:
        blocklist = _CLOUD_BLOCKLIST_PATTERNS
        allowlist = _CLOUD_ALLOWLIST_PREFIXES

    # ── Stage 1: Blocklist check ──────────────────────────────
    for pattern in blocklist:
        if pattern.search(command):
            reason = f"Blocked by pattern: {pattern.pattern}"
            logger.warning(
                "Command REJECTED (blocklist) | domain=%s cmd='%s' reason='%s'",
                domain.value, command, reason,
            )
            return ValidationResult(
                status=ValidationStatus.BLOCKED,
                command=command,
                domain=domain,
                reason=reason,
            )

    # ── Stage 2: Allowlist prefix check ───────────────────────
    if not any(command.startswith(prefix) for prefix in allowlist):
        logger.warning(
            "Command REJECTED (allowlist) | domain=%s cmd='%s'",
            domain.value, command,
        )
        return ValidationResult(
            status=ValidationStatus.NOT_ALLOWLISTED,
            command=command,
            domain=domain,
            reason=f"Command does not match any allowlisted prefix for {domain.value} domain",
        )

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
            )

    # ── Stage 4: Sanitization ─────────────────────────────────
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
        )

    # ── All stages passed ─────────────────────────────────────
    logger.info(
        "Command APPROVED | domain=%s cmd='%s'",
        domain.value, command,
    )
    return ValidationResult(
        status=ValidationStatus.APPROVED,
        command=command,
        domain=domain,
        reason="Passed all validation stages",
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
    the OS blocklist to prevent destructive remote execution.

    Args:
        command: The full ``gcloud compute ssh ... --command="..."`` string.

    Returns:
        A reason string if validation fails, ``None`` if the inner command is safe.
    """
    # Extract inner command from --command="..." or --command='...'
    inner_match = re.search(r'--command=["\'](.+?)["\']', command)
    if not inner_match:
        # No --command flag means interactive SSH — block it
        if "--command" not in command:
            return "Interactive SSH sessions are not allowed. Use --command=\"<cmd>\" to run a specific command."
        return None

    inner_cmd = inner_match.group(1).strip()
    if not inner_cmd:
        return "Empty inner command in gcloud compute ssh"

    # Validate the inner command against the OS blocklist
    for pattern in _OS_BLOCKLIST_PATTERNS:
        if pattern.search(inner_cmd):
            return f"SSH inner command blocked by OS blocklist: {pattern.pattern}"

    return None
