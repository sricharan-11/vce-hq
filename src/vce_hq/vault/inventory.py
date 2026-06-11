"""Proactive inventory capture — triggered on credential store.

When a new cloud credential is added to The Vault, this module
authenticates to the provider and executes a curated sweep of
read-only inventory commands.  All results are stored as
``KnowledgeChunk`` records (category: ``infra_inventory``) in the
tenant's Long-Term Memory so the Cloud Engineer agent can reference
real infrastructure state via RAG without running commands on every query.

Supported providers and their sweep commands
────────────────────────────────────────────
GCP    : projects, compute instances, networks, firewall-rules, GKE clusters,
         Cloud Run services, Cloud SQL, IAM service-accounts, logging sinks
AWS    : caller-identity, EC2 instances/VPCs/security-groups, IAM summary,
         RDS, EKS/ECS clusters, S3 buckets, Lambda functions
Azure  : account, VM list, VNets, NSGs, AKS, storage accounts, resource groups
"""

from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone

from vce_hq.db.connection import create_connection
from vce_hq.db.long_term import LongTermMemory
from vce_hq.db.models import KnowledgeCategory, KnowledgeChunk
from vce_hq.embeddings.service import EmbeddingService
from vce_hq.vault.credential_resolver import resolve_credentials

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Sweep definitions — one per provider
# ─────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class SweepCommand:
    """A single inventory collection command.

    Attributes:
        label: Human-readable name for the data being collected.
        command: The shell command to execute.
        format_json: Whether the output is JSON (parsed for cleaner storage).
    """
    label: str
    command: str
    format_json: bool = False


# GCP inventory sweep (all output-format=json for clean parsing)
_GCP_SWEEP: list[SweepCommand] = [
    SweepCommand("GCP Projects",         "gcloud projects list --format=json",                 format_json=True),
    SweepCommand("GCP Auth Account",     "gcloud auth list --format=json",                     format_json=True),
    SweepCommand("GCP Config",           "gcloud config list --format=json",                   format_json=True),
    SweepCommand("GCP Compute Instances","gcloud compute instances list --format=json",         format_json=True),
    SweepCommand("GCP Networks",         "gcloud compute networks list --format=json",          format_json=True),
    SweepCommand("GCP Firewall Rules",   "gcloud compute firewall-rules list --format=json",    format_json=True),
    SweepCommand("GCP GKE Clusters",     "gcloud container clusters list --format=json",        format_json=True),
    SweepCommand("GCP Cloud Run",        "gcloud run services list --format=json",              format_json=True),
    SweepCommand("GCP Cloud SQL",        "gcloud sql instances list --format=json",             format_json=True),
    SweepCommand("GCP Service Accounts", "gcloud iam service-accounts list --format=json",     format_json=True),
    SweepCommand("GCP Enabled Services", "gcloud services list --enabled --format=json",        format_json=True),
    SweepCommand("GCP Storage Buckets",  "gcloud storage ls",                                   format_json=False),
]

# AWS inventory sweep
_AWS_SWEEP: list[SweepCommand] = [
    SweepCommand("AWS Identity",         "aws sts get-caller-identity",                         format_json=True),
    SweepCommand("AWS EC2 Instances",    "aws ec2 describe-instances",                          format_json=True),
    SweepCommand("AWS VPCs",             "aws ec2 describe-vpcs",                               format_json=True),
    SweepCommand("AWS Security Groups",  "aws ec2 describe-security-groups",                    format_json=True),
    SweepCommand("AWS Subnets",          "aws ec2 describe-subnets",                            format_json=True),
    SweepCommand("AWS IAM Summary",      "aws iam get-account-summary",                         format_json=True),
    SweepCommand("AWS IAM Roles",        "aws iam list-roles",                                  format_json=True),
    SweepCommand("AWS RDS Instances",    "aws rds describe-db-instances",                       format_json=True),
    SweepCommand("AWS EKS Clusters",     "aws eks list-clusters",                               format_json=True),
    SweepCommand("AWS ECS Clusters",     "aws ecs list-clusters",                               format_json=True),
    SweepCommand("AWS Lambda Functions", "aws lambda list-functions",                           format_json=True),
    SweepCommand("AWS S3 Buckets",       "aws s3 ls",                                           format_json=False),
    SweepCommand("AWS CloudFormation",   "aws cloudformation list-stacks",                      format_json=True),
]

# Azure inventory sweep
_AZURE_SWEEP: list[SweepCommand] = [
    SweepCommand("Azure Account",        "az account show",                                     format_json=True),
    SweepCommand("Azure Subscriptions",  "az account list",                                     format_json=True),
    SweepCommand("Azure Resource Groups","az group list",                                       format_json=True),
    SweepCommand("Azure VMs",            "az vm list",                                          format_json=True),
    SweepCommand("Azure VNets",          "az network vnet list",                                format_json=True),
    SweepCommand("Azure NSGs",           "az network nsg list",                                 format_json=True),
    SweepCommand("Azure AKS Clusters",   "az aks list",                                        format_json=True),
    SweepCommand("Azure Storage Accts",  "az storage account list",                             format_json=True),
    SweepCommand("Azure Role Assignments","az role assignment list",                            format_json=True),
]

_PROVIDER_SWEEPS: dict[str, list[SweepCommand]] = {
    "gcp":   _GCP_SWEEP,
    "aws":   _AWS_SWEEP,
    "azure": _AZURE_SWEEP,
}


# ─────────────────────────────────────────────────────────────────────────────
# Result dataclass
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class InventoryResult:
    """Result of a complete inventory sweep.

    Attributes:
        provider: Cloud provider identifier.
        credential_name: Name of the vault credential used.
        tenant_id: Owning tenant.
        captured_at: When the sweep ran.
        chunks_stored: How many KnowledgeChunks were persisted.
        errors: Any command-level errors (non-fatal).
    """
    provider: str
    credential_name: str
    tenant_id: str
    captured_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    chunks_stored: int = 0
    errors: list[str] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# Core execution
# ─────────────────────────────────────────────────────────────────────────────

async def _run_command(
    command: str,
    env_overrides: dict[str, str],
    timeout: int = 60,
) -> tuple[str, str, int | None]:
    """Run a shell command and capture output.

    Args:
        command: Shell command string.
        env_overrides: Environment variables to inject.
        timeout: Per-command timeout in seconds.

    Returns:
        Tuple of (stdout, stderr, exit_code).
    """
    import os
    env = os.environ.copy()
    env.update(env_overrides)

    try:
        process = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
            executable="/bin/sh",
        )
        raw_stdout, raw_stderr = await asyncio.wait_for(
            process.communicate(), timeout=timeout
        )
        return (
            raw_stdout.decode("utf-8", errors="replace"),
            raw_stderr.decode("utf-8", errors="replace"),
            process.returncode,
        )
    except asyncio.TimeoutError:
        return "", f"TIMEOUT: exceeded {timeout}s", None
    except Exception as exc:
        return "", str(exc), -1


def _format_chunk_content(label: str, command: str, stdout: str, format_json: bool) -> str:
    """Format command output into a readable KnowledgeChunk content string.

    Tries to pretty-print JSON output if ``format_json`` is True.

    Args:
        label: Human-readable label.
        command: The command that was run.
        stdout: Raw stdout from the command.
        format_json: Whether to attempt JSON pretty-printing.

    Returns:
        Formatted string ready for embedding and storage.
    """
    content_parts = [
        f"# {label}",
        f"Command: `{command}`",
        f"Captured: {datetime.now(timezone.utc).isoformat()}",
        "",
    ]

    if format_json and stdout.strip():
        try:
            parsed = json.loads(stdout)
            content_parts.append(json.dumps(parsed, indent=2))
        except json.JSONDecodeError:
            content_parts.append(stdout)
    elif stdout.strip():
        content_parts.append(stdout)
    else:
        content_parts.append("(no output)")

    return "\n".join(content_parts)


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

async def capture_inventory(
    *,
    tenant_id: str,
    credential_name: str,
    provider: str,
    credential_value: str,
    db_path: str,
    embedding_service: EmbeddingService,
) -> InventoryResult:
    """Authenticate to a cloud provider and capture a full inventory snapshot.

    This function:
    1. Opens a fresh DB connection (runs in a background task, not a request).
    2. Resolves the correct auth env vars for the provider.
    3. Executes all curated sweep commands for the provider.
    4. Stores each result as a ``KnowledgeChunk`` (category: infra_inventory).
    5. Deletes stale inventory chunks for this credential before writing new ones.

    Args:
        tenant_id: Owning tenant.
        credential_name: Name of the vault credential (used as source document).
        provider: Cloud provider identifier (``"gcp"``, ``"aws"``, ``"azure"``).
        credential_value: Plaintext credential (decrypted from vault).
        db_path: Path to the tenant's SQLite DB file.
        embedding_service: For generating embedding vectors.

    Returns:
        An ``InventoryResult`` summarising the sweep.
    """
    result = InventoryResult(
        provider=provider,
        credential_name=credential_name,
        tenant_id=tenant_id,
    )

    sweeps = _PROVIDER_SWEEPS.get(provider.lower())
    if not sweeps:
        logger.warning(
            "inventory: no sweep defined for provider '%s' (credential '%s')",
            provider, credential_name,
        )
        result.errors.append(f"No sweep commands defined for provider '{provider}'")
        return result

    logger.info(
        "inventory: starting sweep for tenant='%s' provider='%s' credential='%s' (%d commands)",
        tenant_id, provider, credential_name, len(sweeps),
    )

    # Open a dedicated DB connection for this background task
    conn = create_connection(db_path)
    ltm = LongTermMemory(conn)

    # Source document key — used to purge stale chunks before re-capture
    source_doc = f"inventory::{provider}::{credential_name}"

    # Purge stale inventory for this credential
    purged = ltm.delete_knowledge_by_document(source_doc)
    if purged:
        logger.info("inventory: purged %d stale chunks for '%s'", purged, source_doc)

    # Build credential dict for resolver
    cred_dict = [{"name": credential_name, "provider": provider, "credential_value": credential_value}]

    # Determine a representative command prefix for the resolver
    probe_command = {
        "gcp": "gcloud info",
        "aws": "aws sts get-caller-identity",
        "azure": "az account show",
    }.get(provider.lower(), sweeps[0].command)

    with resolve_credentials(probe_command, cred_dict) as env_overrides:
        for sweep in sweeps:
            logger.debug("inventory: running '%s' → %s", credential_name, sweep.command)

            stdout, stderr, exit_code = await _run_command(
                sweep.command, env_overrides, timeout=60
            )

            if exit_code != 0 or not stdout.strip():
                err_msg = f"{sweep.label}: exit={exit_code} stderr={stderr[:200]}"
                logger.warning("inventory: command failed — %s", err_msg)
                result.errors.append(err_msg)
                # Still store partial/error info so agent knows what was attempted
                stdout = f"(command failed)\nExit: {exit_code}\nStderr: {stderr[:500]}"

            content = _format_chunk_content(
                sweep.label, sweep.command, stdout, sweep.format_json
            )

            chunk = KnowledgeChunk(
                tenant_id=tenant_id,
                category=KnowledgeCategory.INFRA_INVENTORY,
                source_document=source_doc,
                content=content,
                metadata={
                    "provider": provider,
                    "credential_name": credential_name,
                    "command": sweep.command,
                    "exit_code": exit_code,
                    "captured_at": result.captured_at.isoformat(),
                },
            )

            try:
                embedding = await embedding_service.embed_async(content)
                ltm.store_knowledge_chunk(chunk, embedding)
                result.chunks_stored += 1
                logger.debug("inventory: stored chunk for '%s'", sweep.label)
            except Exception as exc:
                logger.error("inventory: failed to embed/store '%s': %s", sweep.label, exc)
                result.errors.append(f"{sweep.label}: embedding failed — {exc}")

    conn.close()

    logger.info(
        "inventory: sweep complete for tenant='%s' provider='%s' — "
        "%d chunks stored, %d errors",
        tenant_id, provider, result.chunks_stored, len(result.errors),
    )
    return result


def schedule_inventory_capture(
    *,
    tenant_id: str,
    credential_name: str,
    provider: str,
    credential_value: str,
    db_path: str,
) -> None:
    """Schedule an inventory capture as a background asyncio task.

    Called from the FastAPI credential store endpoint so the HTTP response
    is not blocked. The capture runs concurrently in the same event loop.

    Args:
        tenant_id: Owning tenant.
        credential_name: Vault credential name.
        provider: Cloud provider identifier.
        credential_value: Decrypted plaintext credential.
        db_path: Absolute path to the tenant's SQLite DB.
    """
    from vce_hq.embeddings.service import EmbeddingService  # avoid circular at module level

    async def _task() -> None:
        try:
            embedding_service = EmbeddingService()
            await capture_inventory(
                tenant_id=tenant_id,
                credential_name=credential_name,
                provider=provider,
                credential_value=credential_value,
                db_path=db_path,
                embedding_service=embedding_service,
            )
        except Exception as exc:
            logger.error(
                "inventory: background task failed for tenant='%s' credential='%s': %s",
                tenant_id, credential_name, exc,
            )

    asyncio.create_task(_task())
    logger.info(
        "inventory: background capture scheduled for tenant='%s' provider='%s' credential='%s'",
        tenant_id, provider, credential_name,
    )
