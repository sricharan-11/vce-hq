"""Environment Discovery Probe — runtime infrastructure introspection.

Runs a suite of read-only CLI commands at application startup to build
an ``EnvironmentProfile`` — a structured snapshot of the live environment.
This profile is injected into agent system prompts so they can make
intelligent, context-aware decisions without hardcoded assumptions.

Example discoveries:
    - IAP tunneling is configured → agents use ``--tunnel-through-iap``
    - Cloud Resource Manager API is disabled → agents skip cross-project queries
    - Direct SSH is open between subnets → agents use direct ``gcloud compute ssh``
    - VMs in multiple zones/projects → agents know the full inventory

The probe is designed to be:
    - **Safe**: Only read-only commands, never mutates infrastructure
    - **Cached**: Results are cached with a configurable TTL
    - **Resilient**: Individual probe failures don't crash the system
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


@dataclass
class EnvironmentProfile:
    """Discovered facts about the runtime infrastructure.

    Attributes:
        cloud_provider: Detected cloud provider (gcp, aws, azure, unknown).
        project_id: Current GCP project ID.
        service_account: Active service account email.
        enabled_apis: List of enabled GCP API service names.
        iap_available: Whether IAP TCP forwarding is configured.
        iap_firewall_rule: Name of the IAP firewall rule (if found).
        internal_ssh_allowed: Whether direct SSH between VMs is allowed.
        running_vms: List of running VM dicts with name, zone, project, IP.
        ssh_method: Recommended SSH method based on discovery.
        network_name: Primary VPC network name.
        discovered_at: When the probe was last run.
        probe_errors: Any non-fatal errors encountered during probing.
    """

    cloud_provider: str = "unknown"
    project_id: str = ""
    service_account: str = ""
    enabled_apis: list[str] = field(default_factory=list)
    iap_available: bool = False
    iap_firewall_rule: str = ""
    internal_ssh_allowed: bool = False
    running_vms: list[dict] = field(default_factory=list)
    ssh_method: str = "direct"  # "iap" | "direct" | "ssm"
    network_name: str = ""
    discovered_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    probe_errors: list[str] = field(default_factory=list)

    def to_prompt_context(self) -> str:
        """Format discovered environment facts for injection into agent prompts.

        Returns a human-readable block that gives agents situational awareness
        about the live infrastructure they're operating in.
        """
        lines = [
            "## ENVIRONMENT CONTEXT (auto-discovered at startup)",
            "CRITICAL WARNING: This context represents the VCE-HQ platform host environment. For tenant-specific queries, you MUST use the SSH and VM details provided in the TENANT CONTEXT (Retrieved Context) instead of the details listed here. Do NOT SSH into the VMs listed below unless explicitly investigating the VCE-HQ platform itself.",
            f"Cloud Provider: {self.cloud_provider.upper()}",
            f"Project: {self.project_id}",
            f"Service Account: {self.service_account}",
            f"Network: {self.network_name or 'unknown'}",
        ]

        # SSH method — the critical intelligence
        if self.ssh_method == "iap":
            lines.append(
                f"SSH Method: IAP Tunneling (firewall rule: {self.iap_firewall_rule}). "
                "ALWAYS use --tunnel-through-iap for gcloud compute ssh."
            )
        elif self.ssh_method == "direct":
            lines.append(
                "SSH Method: Direct SSH (internal port 22 is open between subnets). "
                "Use standard gcloud compute ssh without IAP flag."
            )
            lines.append(
                "⚠️ SECURITY ADVISORY: IAP TCP Forwarding is NOT configured in this "
                "environment. Direct internal SSH relies on firewall rules that may be "
                "overly permissive. Recommend enabling IAP for secure, auditable SSH:\n"
                "  1. gcloud services enable iap.googleapis.com\n"
                "  2. Create firewall rule allowing 35.235.240.0/20 on TCP:22\n"
                "  3. Grant roles/iap.tunnelResourceAccessor to the service account\n"
                "Surface this recommendation to the user if they are a CTO or admin."
            )
        else:
            lines.append(
                "SSH Method: RESTRICTED — Neither IAP tunneling nor direct internal SSH "
                "is available. Remote VM access will fail."
            )
            lines.append(
                "🔒 RECOMMENDED ACTION: Enable IAP TCP Forwarding for secure remote access. "
                "This is the GCP best practice for locked-down environments:\n"
                "  1. gcloud services enable iap.googleapis.com --project="
                f"{self.project_id}\n"
                "  2. gcloud compute firewall-rules create allow-iap-ssh "
                "--network=default --allow=tcp:22 "
                "--source-ranges=35.235.240.0/20 --description='IAP TCP forwarding'\n"
                "  3. gcloud projects add-iam-policy-binding " + self.project_id +
                " --member=serviceAccount:" + (self.service_account or "<SA>") +
                " --role=roles/iap.tunnelResourceAccessor\n"
                "Surface this as a critical recommendation to the user."
            )

        # Running VMs
        if self.running_vms:
            lines.append(f"\nRunning VMs ({len(self.running_vms)}):")
            for vm in self.running_vms:
                lines.append(
                    f"  - {vm['name']} | zone={vm['zone']} | "
                    f"project={vm.get('project', self.project_id)} | "
                    f"ip={vm.get('ip', 'N/A')}"
                )
        else:
            lines.append("\nRunning VMs: None discovered (check permissions)")

        # API availability
        if "cloudresourcemanager.googleapis.com" in self.enabled_apis:
            lines.append(
                "\nCross-Project Access: ENABLED (Resource Manager API is active)"
            )
        else:
            lines.append(
                "\nCross-Project Access: RESTRICTED (Resource Manager API "
                "not enabled — can only see current project)"
            )

        # Probe errors (so agents know what they can't rely on)
        if self.probe_errors:
            lines.append("\n⚠️ Discovery Warnings:")
            for err in self.probe_errors:
                lines.append(f"  - {err}")

        return "\n".join(lines)


# IAP's well-known IP range for TCP forwarding
_IAP_CIDR = "35.235.240.0/20"


async def _run_probe_command(
    cmd: str, timeout: int = 15
) -> tuple[str, str, int]:
    """Run a single probe command and return (stdout, stderr, exit_code).

    Failures are captured, not raised — individual probe errors
    should never crash the application.
    """
    try:
        process = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            executable="/bin/sh",
        )
        stdout, stderr = await asyncio.wait_for(
            process.communicate(), timeout=timeout
        )
        return (
            stdout.decode("utf-8", errors="replace").strip(),
            stderr.decode("utf-8", errors="replace").strip(),
            process.returncode or 0,
        )
    except asyncio.TimeoutError:
        return "", f"Probe timed out after {timeout}s: {cmd}", -1
    except Exception as e:
        return "", f"Probe failed: {e}", -1


async def probe_environment() -> EnvironmentProfile:
    """Run all discovery probes and build an EnvironmentProfile.

    This function is safe to call at any time — it only runs read-only
    commands and gracefully handles individual probe failures.

    Returns:
        A populated EnvironmentProfile with all discovered facts.
    """
    profile = EnvironmentProfile()
    profile.cloud_provider = "gcp"  # We detect GCP for now

    logger.info("Environment Discovery: starting probe...")
    start = time.monotonic()

    # ── Probe 1: Current project & service account ────────────
    stdout, stderr, rc = await _run_probe_command(
        "gcloud config get-value project 2>/dev/null"
    )
    if rc == 0 and stdout:
        profile.project_id = stdout.strip()
    else:
        profile.probe_errors.append(f"Could not detect project: {stderr}")

    stdout, stderr, rc = await _run_probe_command(
        "gcloud auth list --filter=status:ACTIVE --format='value(account)' 2>/dev/null"
    )
    if rc == 0 and stdout:
        profile.service_account = stdout.strip().split("\n")[0]
    else:
        profile.probe_errors.append(
            f"Could not detect service account: {stderr}"
        )

    # ── Probe 2: Enabled APIs ─────────────────────────────────
    stdout, stderr, rc = await _run_probe_command(
        "gcloud services list --enabled --format='value(name)' 2>/dev/null"
    )
    if rc == 0 and stdout:
        profile.enabled_apis = [
            api.strip() for api in stdout.split("\n") if api.strip()
        ]
    else:
        profile.probe_errors.append(f"Could not list enabled APIs: {stderr}")

    # ── Probe 3: Firewall rules (detect IAP & internal SSH) ───
    stdout, stderr, rc = await _run_probe_command(
        "gcloud compute firewall-rules list --format=json 2>/dev/null"
    )
    if rc == 0 and stdout:
        try:
            fw_rules = json.loads(stdout)
            for rule in fw_rules:
                source_ranges = rule.get("sourceRanges", [])
                allowed = rule.get("allowed", [])
                direction = rule.get("direction", "INGRESS")

                if direction != "INGRESS":
                    continue

                # Check for IAP: source range contains 35.235.240.0/20
                if _IAP_CIDR in source_ranges:
                    # Verify it allows TCP:22
                    for allow_entry in allowed:
                        protocol = allow_entry.get("IPProtocol", "")
                        ports = allow_entry.get("ports", [])
                        if protocol == "tcp" and ("22" in ports or not ports):
                            profile.iap_available = True
                            profile.iap_firewall_rule = rule.get("name", "")
                            break

                # Check for internal SSH (RFC1918 ranges allowing port 22)
                rfc1918 = {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
                if rfc1918.intersection(set(source_ranges)):
                    for allow_entry in allowed:
                        protocol = allow_entry.get("IPProtocol", "")
                        ports = allow_entry.get("ports", [])
                        if protocol == "tcp" and ("22" in ports or not ports):
                            profile.internal_ssh_allowed = True
                            break

                # Detect network name from first rule
                if not profile.network_name:
                    network = rule.get("network", "")
                    if network:
                        # network is a full URL; extract the name
                        profile.network_name = network.rstrip("/").split("/")[-1]

        except json.JSONDecodeError as e:
            profile.probe_errors.append(f"Failed to parse firewall rules: {e}")
    else:
        profile.probe_errors.append(
            f"Could not list firewall rules: {stderr}"
        )

    # ── Probe 4: Running VMs ──────────────────────────────────
    stdout, stderr, rc = await _run_probe_command(
        "gcloud compute instances list "
        "--filter='status=RUNNING' "
        "--format='json(name,zone.basename(),networkInterfaces[0].networkIP)' "
        "2>/dev/null"
    )
    if rc == 0 and stdout:
        try:
            vms = json.loads(stdout)
            for vm in vms:
                zone = vm.get("zone", "")
                interfaces = vm.get("networkInterfaces", [{}])
                ip = (
                    interfaces[0].get("networkIP", "N/A")
                    if interfaces
                    else "N/A"
                )
                profile.running_vms.append(
                    {
                        "name": vm.get("name", ""),
                        "zone": zone,
                        "project": profile.project_id,
                        "ip": ip,
                    }
                )
        except json.JSONDecodeError as e:
            profile.probe_errors.append(f"Failed to parse VM list: {e}")
    else:
        profile.probe_errors.append(f"Could not list running VMs: {stderr}")

    # ── Determine SSH method ──────────────────────────────────
    if profile.iap_available:
        profile.ssh_method = "iap"
    elif profile.internal_ssh_allowed:
        profile.ssh_method = "direct"
    else:
        profile.ssh_method = "iap"  # Safe default: try IAP

    elapsed = int((time.monotonic() - start) * 1000)
    logger.info(
        "Environment Discovery: completed in %dms | provider=%s project=%s "
        "ssh_method=%s iap=%s vms=%d apis=%d errors=%d",
        elapsed,
        profile.cloud_provider,
        profile.project_id,
        profile.ssh_method,
        profile.iap_available,
        len(profile.running_vms),
        len(profile.enabled_apis),
        len(profile.probe_errors),
    )

    return profile


# ── Singleton Cache ───────────────────────────────────────────

_cached_profile: EnvironmentProfile | None = None
_cache_timestamp: float = 0.0
_CACHE_TTL_SECONDS: float = 3600.0  # 1 hour


async def get_environment_profile(
    *, force_refresh: bool = False
) -> EnvironmentProfile:
    """Get the cached environment profile, refreshing if stale.

    Args:
        force_refresh: If True, force a re-probe regardless of TTL.

    Returns:
        The current (possibly cached) EnvironmentProfile.
    """
    global _cached_profile, _cache_timestamp

    now = time.monotonic()
    if (
        not force_refresh
        and _cached_profile is not None
        and (now - _cache_timestamp) < _CACHE_TTL_SECONDS
    ):
        return _cached_profile

    _cached_profile = await probe_environment()
    _cache_timestamp = now
    return _cached_profile
