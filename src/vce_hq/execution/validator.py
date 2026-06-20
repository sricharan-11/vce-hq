"""Command validator — allowlist/blocklist enforcement.

Implements the three-stage validation flow from PRD_Brain_v1.2:
    1. Tiered Allowlist Classification (No LLM) -> Sets matched_tier
    2. Regex blocklist check (reject known-dangerous patterns not allowed in ANY mode)
    3. Argument sanitization (reject shell injection vectors)

Every command an agent formulates MUST pass validation before execution.
Validation failures are logged with the rejection reason.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from enum import StrEnum

logger = logging.getLogger(__name__)

# Horizontal API Translation Mapping
# We map REST endpoints/actions to Tiers to evaluate raw scripts (python/curl) without LLM overhead.
# Since AWS actions are in headers/payloads (not URLs), we map standard Action names too.

_API_ALLOWLIST = {
    1: [
        # GCP (Read Only endpoints or base domains assuming GET method)
        re.compile(r"https://(compute|logging|monitoring|cloudbilling|cloudresourcemanager|iam|container|run|appengine|cloudfunctions|sqladmin|storage|serviceusage|dns|networkconnectivity)\.googleapis\.com/.*", re.IGNORECASE),
        
        # AWS (Action headers for describing/listing)
        re.compile(r"(Describe|List|Get|Simulate|FilterLogEvents)[A-Za-z]+", re.IGNORECASE),
        
        # Azure (Read Only ARM endpoints)
        re.compile(r"https://management\.azure\.com/subscriptions/.*", re.IGNORECASE),
    ],
    2: [
        # GCP (Start/Stop/Update)
        re.compile(r"https://compute\.googleapis\.com/compute/v1/projects/[^/]+/zones/[^/]+/instances/[^/]+/(start|stop|setLabels)", re.IGNORECASE),
        re.compile(r"https://cloudbilling\.googleapis\.com/v1/projects/[^/]+/billingInfo", re.IGNORECASE),
        
        # AWS (State transitions)
        re.compile(r"(Start|Stop|Modify)[A-Za-z]+", re.IGNORECASE),
        
        # Azure (Start/Stop)
        re.compile(r"https://management\.azure\.com/subscriptions/.*/(start|stop|restart|deallocate)", re.IGNORECASE),
    ],
    3: [
        # GCP (Destructive)
        re.compile(r"https://compute\.googleapis\.com/compute/v1/projects/[^/]+/zones/[^/]+/instances/[^/]+$", re.IGNORECASE), # DELETE
        
        # AWS (Destructive)
        re.compile(r"(Terminate|Delete|Create)[A-Za-z]+", re.IGNORECASE),
        
        # Azure (Destructive)
        re.compile(r"https://management\.azure\.com/subscriptions/.*/delete", re.IGNORECASE),
    ]
}

def _detect_destructive_methods(command: str) -> bool:
    """Detect if a raw script contains destructive HTTP methods or actions."""
    destructive_keywords = [
        r'requests\.delete', r'requests\.post', r'requests\.put', r'requests\.patch',
        r'method=[\'"]DELETE[\'"]', r'method=[\'"]POST[\'"]', r'method=[\'"]PUT[\'"]',
        r'-X\s*DELETE', r'-X\s*POST', r'-X\s*PUT', r'-X\s*PATCH'
    ]
    return any(re.search(pattern, command, re.IGNORECASE) for pattern in destructive_keywords)


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
        matched_tier: The tier (1, 2, or 3) that matched the command.
    """
    status: ValidationStatus
    command: str
    domain: CommandDomain
    reason: str
    matched_tier: int | None = None  # 1, 2, or 3

    @property
    def approved(self) -> bool:
        """Whether the command passed validation."""
        return self.status == ValidationStatus.APPROVED

# ══════════════════════════════════════════════════════════════
# OS DOMAIN
# ══════════════════════════════════════════════════════════════

_OS_TIER_1: list[str] = [
    # System
    "uname", "uptime", "hostnamectl", "timedatectl", "hostname",
    # CPU
    "top -b", "mpstat", "pidstat", "cat /proc/loadavg", "nproc",
    # Memory
    "free", "vmstat", "cat /proc/meminfo", "slabtop -o",
    # Disk
    "df", "du -s", "du -sh", "lsblk", "blkid", "cat /proc/mounts", "iostat", "findmnt", "stat ",
    # Processes
    "ps ", "pstree", "cat /proc/", "ls /proc/",
    # Network
    "ss ", "ip addr", "ip route", "ip link", "ip neigh", "cat /etc/resolv.conf", "cat /etc/hosts",
    "iptables -L", "iptables -S", "iptables -nvL", "nft list", "netstat ",
    # Logs
    "journalctl ", "dmesg", "tail ", "head ", "cat /var/log/", "zcat /var/log/", "less /var/log/", "grep ",
    # Systemd
    "systemctl status", "systemctl list-units", "systemctl show", "systemctl is-active", "systemctl is-enabled", "systemctl is-failed",
    # Kernel
    "sysctl ", "lsmod", "modinfo",
    # Packages
    "dpkg -l", "dpkg -s", "dpkg --list", "apt list", "apt-cache", "apt show", "rpm -q", "yum list", "yum info",
    # Misc read-only
    "whoami", "id", "w", "who", "last", "lastlog", "date", "cal", "env", "printenv", "lscpu", "lsmem", "lsns", "lsof", "mount", "cat /etc/fstab", "ulimit", "getconf",
    # Remote VM access via gcloud SSH
    "gcloud compute ssh",
]

_OS_TIER_2: list[str] = [
    "systemctl start", "systemctl stop", "systemctl restart", "systemctl enable", "systemctl disable", "systemctl daemon-reload",
    "chmod ", "chown ", "chgrp ",
]

_OS_TIER_3: list[str] = [
    "rm ", "rmdir ", "kill ", "killall ", "pkill ", "reboot", "shutdown", "poweroff",
    "apt install", "apt remove", "apt-get install", "apt-get remove", "apt purge", "apt-get purge",
    "yum install", "yum remove", "dnf install", "dnf remove",
]

# Patterns blocked in ALL modes (e.g. disk formatting, shell injection, interactive editors)
_OS_BLOCKLIST_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bmkfs\b", re.IGNORECASE),
    re.compile(r"\bfdisk\b", re.IGNORECASE),
    re.compile(r"\bparted\b", re.IGNORECASE),
    re.compile(r"\bdd\s", re.IGNORECASE),
    re.compile(r"\b(vi|vim|nano|emacs|ed)\s"),
]

# ══════════════════════════════════════════════════════════════
# CLOUD DOMAIN
# ══════════════════════════════════════════════════════════════

_CLOUD_TIER_1: list[str] = [
    "aws ec2 describe-", "aws ec2 get-",
    "aws iam get-", "aws iam list-", "aws iam simulate-", "aws iam get-account-summary",
    "aws elbv2 describe-", "aws elb describe-",
    "aws cloudwatch get-", "aws cloudwatch describe-", "aws cloudwatch list-",
    "aws logs filter-log-events", "aws logs describe-log-groups", "aws logs describe-log-streams", "aws logs get-log-events", "aws logs get-",
    "aws ecs describe-", "aws ecs list-", "aws eks describe-", "aws eks list-", "aws rds describe-",
    "aws s3 ls", "aws s3api get-", "aws s3api list-", "aws s3api head-",
    "aws sts get-caller-identity", "aws lambda get-", "aws lambda list-", "aws route53 list-", "aws route53 get-",
    "aws sns list-", "aws sns get-", "aws sqs list-", "aws sqs get-", "aws sqs receive-message",
    "aws autoscaling describe-", "aws cloudformation describe-", "aws cloudformation list-",
    "aws pricing ", "aws ce ", "aws organizations describe-", "aws organizations list-", "aws account get-", "aws support describe-",
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
    "gcloud compute routes list", "gcloud compute ssl-certificates list", "gcloud compute target-https-proxies list",
    "gcloud compute machine-types list", "gcloud compute regions list", "gcloud compute zones list",
    "gcloud compute operations list", "gcloud compute operations describe",
    "gcloud projects get-iam-policy", "gcloud projects describe", "gcloud projects list",
    "gcloud iam roles list", "gcloud iam roles describe", "gcloud iam service-accounts list", "gcloud iam service-accounts describe", "gcloud iam service-accounts get-iam-policy",
    "gcloud resource-manager folders list", "gcloud organizations list",
    "gcloud asset search-all-resources",
    "gcloud container clusters describe", "gcloud container clusters list", "gcloud container node-pools list", "gcloud container node-pools describe",
    "gcloud run services list", "gcloud run services describe", "gcloud run revisions list",
    "gcloud app versions list", "gcloud app services list",
    "gcloud functions list", "gcloud functions describe",
    "gcloud sql instances describe", "gcloud sql instances list", "gcloud sql databases list",
    "gcloud storage ls", "gcloud storage buckets list",
    "gcloud billing accounts list", "gcloud billing accounts describe", "gcloud billing budgets list", "gcloud billing budgets describe",
    "gcloud billing projects describe", "gcloud billing projects list",
    "gcloud services list", "gcloud services enable --dry-run", "gcloud services pricing",
    "gcloud logging read", "gcloud logging logs list", "gcloud logging sinks list",
    "gcloud monitoring dashboards list",
    "gcloud dns managed-zones list", "gcloud dns record-sets list",
    "gcloud network-connectivity hubs list",
    "gcloud config list", "gcloud config configurations list", "gcloud info", "gcloud auth list",
    "az vm show", "az vm list", "az vmss show", "az vmss list",
    "az network nsg show", "az network nsg list", "az network vnet show", "az network vnet list",
    "az network lb show", "az network lb list", "az network public-ip show", "az network public-ip list",
    "az network nic show", "az network nic list", "az network route-table show", "az network route-table list",
    "az network application-gateway show", "az network application-gateway list",
    "az network dns zone list", "az network dns record-set list",
    "az role assignment list", "az role definition list", "az ad sp show", "az ad sp list",
    "az aks show", "az aks list", "az container show", "az container list",
    "az monitor metrics list", "az monitor log-analytics query", "az monitor activity-log list",
    "az storage account show", "az storage account list", "az storage blob list", "az storage container list",
    "az resource show", "az resource list", "az account show", "az account list", "az account subscription list", "az group show", "az group list",
    "az billing ", "az consumption ",
    "kubectl get ", "kubectl describe ", "kubectl logs ", "kubectl log ", "kubectl top ", "kubectl cluster-info",
    "kubectl api-resources", "kubectl api-versions", "kubectl config view", "kubectl config current-context", "kubectl config get-contexts",
    "kubectl version", "kubectl explain ", "kubectl rollout status", "kubectl rollout history", "kubectl auth can-i",
]

_CLOUD_TIER_2: list[str] = [
    "aws ec2 start-", "aws ec2 stop-", "aws ec2 modify-",
    "gcloud compute instances start", "gcloud compute instances stop", "gcloud compute instances update",
    "gcloud billing projects link",
    "az vm start", "az vm stop", "az vm update",
    "kubectl scale ", "kubectl rollout ", "kubectl set ", "kubectl apply ", "kubectl patch ", "kubectl edit ",
]

_CLOUD_TIER_3: list[str] = [
    "aws ec2 terminate-", "aws ec2 create-", "aws ec2 delete-",
    "gcloud compute instances create", "gcloud compute instances delete",
    "gcloud billing projects unlink",
    "az vm create", "az vm delete", "az vm deallocate",
    "kubectl delete ", "kubectl create ",
]

_CLOUD_BLOCKLIST_PATTERNS: list[re.Pattern[str]] = [
    # Patterns blocked in ALL modes
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
# ALLOWLIST REFERENCE (for Router prompt injection)
# ══════════════════════════════════════════════════════════════

def get_allowlist_reference() -> str:
    """Build a formatted reference of all allowlisted command prefixes.

    Used by the Supervisor Router to know exactly which commands are
    available so it can suggest concrete alternatives when an agent
    reports that something is "not possible".

    Returns:
        A multi-line string listing all tiers for OS and Cloud domains.
    """
    def _fmt(tier_name: str, prefixes: list[str]) -> str:
        items = ", ".join(f"`{p.strip()}`" for p in prefixes)
        return f"  {tier_name}: {items}"

    # FinOps-specific command prefixes (subset of Cloud tiers used by finops_agent)
    _FINOPS_TIER_1 = [p for p in _CLOUD_TIER_1 if any(
        kw in p for kw in ("pricing", "ce ", "billing", "consumption")
    )]
    _FINOPS_TIER_2 = [p for p in _CLOUD_TIER_2 if "billing" in p]
    _FINOPS_TIER_3 = [p for p in _CLOUD_TIER_3 if "billing" in p]

    sections = [
        "## OS Domain",
        _fmt("Tier 1 (Read-Only)", _OS_TIER_1),
        _fmt("Tier 2 (Service Control)", _OS_TIER_2),
        _fmt("Tier 3 (Destructive)", _OS_TIER_3),
        "",
        "## Cloud Domain",
        _fmt("Tier 1 (Read/List/Describe)", _CLOUD_TIER_1),
        _fmt("Tier 2 (Start/Stop/Update)", _CLOUD_TIER_2),
        _fmt("Tier 3 (Create/Delete)", _CLOUD_TIER_3),
        "",
        "## FinOps Domain (billing, pricing, consumption)",
        _fmt("Tier 1 (Read-Only)", _FINOPS_TIER_1),
        _fmt("Tier 2 (Billing Links)", _FINOPS_TIER_2),
        _fmt("Tier 3 (Billing Unlinks)", _FINOPS_TIER_3),
    ]
    return "\n".join(sections)


# ══════════════════════════════════════════════════════════════
# PUBLIC API
# ══════════════════════════════════════════════════════════════

def validate_command(command: str, domain: CommandDomain) -> ValidationResult:
    """Validate a command against the tiered allowlists/blocklist for a domain.

    Implements the three-stage flow:
        1. Tiered Allowlist Classification
        2. Blocklist check (regex) → reject if any pattern matches
        3. Sanitization (injection detection) → reject if suspicious

    Args:
        command: The raw command string to validate.
        domain: Whether this is an OS or Cloud command.

    Returns:
        A ``ValidationResult`` indicating approval or rejection with reason.
        If approved, ``matched_tier`` is set to 1, 2, or 3.
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
        tiers = {1: _OS_TIER_1, 2: _OS_TIER_2, 3: _OS_TIER_3}
        blocklist = _OS_BLOCKLIST_PATTERNS
    else:
        tiers = {1: _CLOUD_TIER_1, 2: _CLOUD_TIER_2, 3: _CLOUD_TIER_3}
        blocklist = _CLOUD_BLOCKLIST_PATTERNS

    # ── Stage 1: Tiered Allowlist Classification ───────────────────────
    matched_tier = None
    for tier_level, prefixes in tiers.items():
        if any(command.startswith(prefix) for prefix in prefixes):
            matched_tier = tier_level
            break

    # ── Stage 2.5: Horizontal API Translation ────────────────────────
    # If the command did not match a CLI prefix but appears to be a raw script
    if matched_tier is None and (command.startswith("python") or command.startswith("curl")):
        endpoints = re.findall(r'https?://[^\s\'"]+', command)
        
        # AWS actions are usually strings in payloads or headers, not URLs.
        aws_actions = re.findall(r'(Describe|List|Get|Simulate|FilterLogEvents|Start|Stop|Modify|Terminate|Delete|Create)[A-Za-z]+', command, re.IGNORECASE)
        
        combined_targets = endpoints + aws_actions
        
        if combined_targets:
            highest_tier_required = 1
            all_targets_allowed = True
            has_destructive_methods = _detect_destructive_methods(command)
            
            for target in combined_targets:
                target_allowed = False
                for tier_level, patterns in _API_ALLOWLIST.items():
                    if any(pattern.match(target) for pattern in patterns):
                        target_allowed = True
                        
                        # If it's a destructive HTTP method, we automatically escalate Tier 1 (Read-Only) URLs to Tier 3 (Destructive)
                        if has_destructive_methods and tier_level == 1:
                            highest_tier_required = max(highest_tier_required, 3)
                        else:
                            highest_tier_required = max(highest_tier_required, tier_level)
                        break
                
                if not target_allowed:
                    logger.warning("Horizontal API Translation failed: target not allowed: '%s'", target)
                    all_targets_allowed = False
                    break
            
            if all_targets_allowed:
                matched_tier = highest_tier_required
                logger.info("Horizontal API Translation successful. Translated script to Tier %d based on targets: %s", matched_tier, combined_targets)

    if matched_tier is None:
        logger.warning(
            "Command REJECTED (allowlist) | domain=%s cmd='%s'",
            domain.value, command,
        )
        return ValidationResult(
            status=ValidationStatus.NOT_ALLOWLISTED,
            command=command,
            domain=domain,
            reason=f"Command does not match any allowlisted prefix for {domain.value} domain (Tiers 1-3)",
        )

    # ── Stage 2: Blocklist check ──────────────────────────────
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
                matched_tier=matched_tier,
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
                matched_tier=matched_tier,
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
            matched_tier=matched_tier,
        )

    # ── All stages passed ─────────────────────────────────────
    logger.info(
        "Command APPROVED | domain=%s tier=%d cmd='%s'",
        domain.value, matched_tier, command,
    )
    return ValidationResult(
        status=ValidationStatus.APPROVED,
        command=command,
        domain=domain,
        reason=f"Passed validation for Tier {matched_tier}",
        matched_tier=matched_tier,
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
    the OS blocklist.

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
