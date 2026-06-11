"""Credential resolver — maps cloud CLI commands to vault credentials.

Given a shell command and a set of stored credentials, this module
resolves which credential to use and constructs the correct environment
variables to inject into the subprocess environment so the CLI can
authenticate.

Supported CLIs and their authentication mechanisms:

    gcloud (GCP):
        - Service account JSON key → GOOGLE_APPLICATION_CREDENTIALS
          (written to a temp file and cleaned up after execution)
        - API key → CLOUDSDK_AUTH_ACCESS_TOKEN (limited use)

    aws (AWS):
        - Access key / secret JSON → AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
        - Session token → AWS_SESSION_TOKEN

    az (Azure):
        - Service principal JSON → AZURE_CLIENT_ID, AZURE_CLIENT_SECRET,
          AZURE_TENANT_ID, AZURE_SUBSCRIPTION_ID

    kubectl (Kubernetes):
        - kubeconfig → KUBECONFIG (written to temp file and cleaned up)

Security notes:
    - Credentials are decrypted in memory only for the duration of the
      subprocess call and are never written to disk (except for
      GOOGLE_APPLICATION_CREDENTIALS / KUBECONFIG temp files, which are
      immediately cleaned up in a try/finally block).
    - This module NEVER logs credential values.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from contextlib import contextmanager
from typing import Generator

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# CLI detection
# ─────────────────────────────────────────────────────────────────────────────

def detect_cli(command: str) -> str | None:
    """Detect which cloud CLI a command targets.

    Args:
        command: The shell command string.

    Returns:
        One of ``"gcloud"``, ``"aws"``, ``"az"``, ``"kubectl"``,
        or ``None`` if no known CLI is detected.
    """
    stripped = command.strip()
    if stripped.startswith("gcloud"):
        return "gcloud"
    if stripped.startswith("aws"):
        return "aws"
    if stripped.startswith("az"):
        return "az"
    if stripped.startswith("kubectl"):
        return "kubectl"
    return None


def pick_credential(
    credentials: list[dict],
    cli: str,
) -> dict | None:
    """Pick the most appropriate credential for a CLI from a list.

    Preferences:
        gcloud → provider == "gcp"
        aws    → provider == "aws"
        az     → provider == "azure"
        kubectl→ provider == "kubernetes" or "gcp" (GKE kubeconfig)

    Args:
        credentials: List of dicts with ``name``, ``provider``,
            ``credential_value`` (plaintext, already decrypted).
        cli: The detected CLI string.

    Returns:
        The first matching credential dict, or ``None``.
    """
    provider_map: dict[str, list[str]] = {
        "gcloud": ["gcp"],
        "aws": ["aws"],
        "az": ["azure"],
        "kubectl": ["kubernetes", "gcp"],
    }
    preferred = provider_map.get(cli, [])
    for cred in credentials:
        if cred.get("provider", "").lower() in preferred:
            return cred
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Environment builders (per CLI)
# ─────────────────────────────────────────────────────────────────────────────

@contextmanager
def build_env_for_gcloud(
    credential_value: str,
) -> Generator[dict[str, str], None, None]:
    """Build env vars for gcloud authentication.

    Accepts either:
    - A GCP service account JSON string → writes to a temp file,
      sets GOOGLE_APPLICATION_CREDENTIALS, then cleans up.
    - A raw API key / access token → sets CLOUDSDK_AUTH_ACCESS_TOKEN.

    Args:
        credential_value: The raw credential string from the vault.

    Yields:
        Dict of environment variables to inject into the subprocess.
    """
    env: dict[str, str] = {}
    tmp_path: str | None = None

    try:
        # Try to parse as JSON service account key
        parsed = json.loads(credential_value)
        if parsed.get("type") == "service_account":
            # Write to a secure temp file in the local .tmp dir (Snap-friendly)
            tmp_dir = os.path.join(os.getcwd(), ".tmp")
            os.makedirs(tmp_dir, exist_ok=True)
            
            fd, tmp_path = tempfile.mkstemp(suffix=".json", prefix="vce_sa_", dir=tmp_dir)
            with os.fdopen(fd, "w") as f:
                json.dump(parsed, f)
            
            env["GOOGLE_APPLICATION_CREDENTIALS"] = tmp_path
            env["CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE"] = tmp_path
            env["CLOUDSDK_CORE_DISABLE_PROMPTS"] = "1"
            
            # Build a command prefix that activates the service account
            # BEFORE the actual gcloud command runs. This is required
            # because snap-installed gcloud ignores env-var overrides
            # and falls back to the VM's metadata server identity.
            # The prefix runs: activate-service-account → set project → <user command>
            auth_prefix = (
                f"gcloud auth activate-service-account"
                f" --key-file={tmp_path} --quiet 2>/dev/null"
            )
            
            # Extract and set project ID if present
            project_id = parsed.get("project_id")
            if project_id:
                env["CLOUDSDK_CORE_PROJECT"] = project_id
                auth_prefix += (
                    f" && gcloud config set project {project_id}"
                    f" --quiet 2>/dev/null"
                )
                logger.info(
                    "gcloud: using service account key for project '%s'"
                    " (with activate-service-account prefix)",
                    project_id,
                )
            else:
                logger.info(
                    "gcloud: using service account key (no project_id found in JSON)"
                )
            
            # Store the prefix in a special key. The executor will
            # extract this and prepend it to the command AFTER validation.
            env["_VCE_CMD_PREFIX_"] = auth_prefix + " && "
        else:
            logger.warning("gcloud: unrecognised JSON structure — skipping auth injection")
    except (json.JSONDecodeError, ValueError):
        # Treat as an OAuth access token
        env["CLOUDSDK_AUTH_ACCESS_TOKEN"] = credential_value
        env["CLOUDSDK_CORE_DISABLE_PROMPTS"] = "1"
        logger.info("gcloud: using access token (CLOUDSDK_AUTH_ACCESS_TOKEN)")

    try:
        yield env
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)
            logger.debug("gcloud: cleaned up temp credentials file")


@contextmanager
def build_env_for_aws(
    credential_value: str,
) -> Generator[dict[str, str], None, None]:
    """Build env vars for AWS CLI authentication.

    Accepts either:
    - A JSON dict with ``access_key_id``, ``secret_access_key``, and
      optionally ``session_token`` and ``region``.
    - A colon-separated string ``ACCESS_KEY_ID:SECRET_ACCESS_KEY``.

    Args:
        credential_value: The raw credential string from the vault.

    Yields:
        Dict of environment variables to inject into the subprocess.
    """
    env: dict[str, str] = {}
    try:
        parsed = json.loads(credential_value)
        env["AWS_ACCESS_KEY_ID"] = parsed["access_key_id"]
        env["AWS_SECRET_ACCESS_KEY"] = parsed["secret_access_key"]
        if "session_token" in parsed:
            env["AWS_SESSION_TOKEN"] = parsed["session_token"]
        if "region" in parsed:
            env["AWS_DEFAULT_REGION"] = parsed["region"]
        logger.info("aws: using JSON credential dict")
    except (json.JSONDecodeError, KeyError):
        # Try colon-separated format KEY_ID:SECRET
        parts = credential_value.strip().split(":", 1)
        if len(parts) == 2:
            env["AWS_ACCESS_KEY_ID"] = parts[0]
            env["AWS_SECRET_ACCESS_KEY"] = parts[1]
            logger.info("aws: using colon-separated credential")
        else:
            logger.warning("aws: unrecognised credential format — skipping auth injection")

    yield env


@contextmanager
def build_env_for_az(
    credential_value: str,
) -> Generator[dict[str, str], None, None]:
    """Build env vars for Azure CLI authentication.

    Accepts a JSON dict with ``client_id``, ``client_secret``,
    ``tenant_id``, and optionally ``subscription_id``.

    Args:
        credential_value: The raw credential string from the vault.

    Yields:
        Dict of environment variables to inject into the subprocess.
    """
    env: dict[str, str] = {}
    try:
        parsed = json.loads(credential_value)
        env["AZURE_CLIENT_ID"] = parsed["client_id"]
        env["AZURE_CLIENT_SECRET"] = parsed["client_secret"]
        env["AZURE_TENANT_ID"] = parsed["tenant_id"]
        if "subscription_id" in parsed:
            env["AZURE_SUBSCRIPTION_ID"] = parsed["subscription_id"]
        logger.info("az: using service principal credentials")
    except (json.JSONDecodeError, KeyError):
        logger.warning("az: unrecognised credential format — skipping auth injection")

    yield env


@contextmanager
def build_env_for_kubectl(
    credential_value: str,
) -> Generator[dict[str, str], None, None]:
    """Build env vars for kubectl authentication.

    Accepts a raw kubeconfig YAML/JSON string. Writes to a temp file,
    sets KUBECONFIG, then cleans up after execution.

    Args:
        credential_value: The raw kubeconfig string from the vault.

    Yields:
        Dict of environment variables to inject into the subprocess.
    """
    env: dict[str, str] = {}
    tmp_path: str | None = None

    try:
        # Write to a secure temp file in the local .tmp dir (Snap-friendly)
        tmp_dir = os.path.join(os.getcwd(), ".tmp")
        os.makedirs(tmp_dir, exist_ok=True)

        fd, tmp_path = tempfile.mkstemp(suffix=".yaml", prefix="vce_kube_", dir=tmp_dir)
        with os.fdopen(fd, "w") as f:
            f.write(credential_value)
        env["KUBECONFIG"] = tmp_path
        logger.info("kubectl: using kubeconfig (KUBECONFIG)")

        yield env
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)
            logger.debug("kubectl: cleaned up temp kubeconfig file")


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

@contextmanager
def resolve_credentials(
    command: str,
    available_credentials: list[dict],
) -> Generator[dict[str, str], None, None]:
    """Detect CLI, pick credential, and yield injected environment vars.

    This is the primary entry point used by the Cloud Engineer agent.
    It is a context manager so that any temp files created (e.g., for
    GOOGLE_APPLICATION_CREDENTIALS) are guaranteed to be cleaned up even
    if an exception is raised during execution.

    Args:
        command: The command about to be executed.
        available_credentials: List of dicts with ``provider`` and
            ``credential_value`` (plaintext, already decrypted from vault).

    Yields:
        A dict of env var overrides to pass to ``CommandExecutor.execute()``.
        Yields an empty dict if no matching credential is found.

    Example::

        async with resolve_credentials(cmd, creds) as env_overrides:
            result = await executor.execute(cmd, env_overrides=env_overrides)
    """
    cli = detect_cli(command)

    if cli is None:
        logger.debug("resolve_credentials: no known CLI detected in command")
        yield {}
        return

    cred = pick_credential(available_credentials, cli)
    if cred is None:
        logger.warning(
            "resolve_credentials: no credential available for CLI '%s' — "
            "command will run unauthenticated",
            cli,
        )
        yield {}
        return

    logger.info(
        "resolve_credentials: matched credential '%s' (provider=%s) for CLI '%s'",
        cred.get("name", "<unnamed>"), cred.get("provider"), cli,
    )

    credential_value = cred["credential_value"]

    # Dispatch to the right builder
    if cli == "gcloud":
        with build_env_for_gcloud(credential_value) as env:
            yield env
    elif cli == "aws":
        with build_env_for_aws(credential_value) as env:
            yield env
    elif cli == "az":
        with build_env_for_az(credential_value) as env:
            yield env
    elif cli == "kubectl":
        with build_env_for_kubectl(credential_value) as env:
            yield env
    else:
        yield {}
