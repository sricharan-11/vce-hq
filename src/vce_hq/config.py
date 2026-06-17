"""Centralized configuration loaded from environment variables.

All settings are validated at startup via Pydantic. Missing required
values (e.g., GOOGLE_API_KEY) will raise a clear error before any
request is served.
"""

from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class ExecutionMode(StrEnum):
    MODE_1 = "mode_1"  # Read-only (default)
    MODE_2 = "mode_2"  # Read + Edit/Update
    MODE_3 = "mode_3"  # Full Access (Create/Delete)


class Settings(BaseSettings):
    """Application-wide settings sourced from environment variables.

    Attributes:
        google_api_key: Google AI API key for Gemini LLM and embedding calls.
        llm_model: Gemini model identifier used by all agents.
        embedding_model: Google embedding model for vector generation.
        embedding_dimensions: Dimensionality of the embedding vectors.
        data_dir: Root directory for per-tenant SQLite databases.
        host: Server bind address.
        port: Server bind port.
        log_level: Structured logging level.
        log_format: Logging output format.
        credential_secret: Secret key used to derive per-tenant credential hashes.
        cmd_max_iterations: Max ReAct loop iterations per agent.
        cmd_max_per_session: Max total commands across all agents per session.
        cmd_timeout_seconds: Per-command execution timeout.
        cmd_max_stdout_bytes: Maximum stdout capture size.
        cmd_max_stderr_bytes: Maximum stderr capture size.
        cmd_enabled: Global kill switch for command execution.
        execution_mode: The phased execution mode (1=read-only, 2=read+edit, 3=full).
    """

    model_config = SettingsConfigDict(
        env_prefix="VCE_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Google AI — no prefix override, read directly as GOOGLE_API_KEY
    google_api_key: str

    # LLM
    llm_model: str = "gemini-3.1-pro"

    # Embeddings
    embedding_model: str = "text-embedding-005"
    embedding_dimensions: int = 768

    # Storage
    data_dir: Path = Path("./data")

    # Server
    host: str = "0.0.0.0"
    port: int = 8000

    # Logging
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    log_format: Literal["json", "console"] = "json"

    # Security
    credential_secret: str = "change-this-to-a-strong-random-secret"

    # Command execution (The Hands)
    cmd_max_iterations: int = 5
    cmd_max_per_session: int = 15
    cmd_timeout_seconds: int = 30
    cmd_max_stdout_bytes: int = 65536   # 64 KB
    cmd_max_stderr_bytes: int = 16384   # 16 KB
    cmd_enabled: bool = True
    
    # Orchestration
    router_max_iterations: int = 3
    execution_mode: ExecutionMode = ExecutionMode.MODE_1

    def tenant_db_path(self, tenant_id: str) -> Path:
        """Return the SQLite database path for a given tenant.

        Each tenant gets an isolated directory under ``data_dir``.
        The directory is created if it does not exist.
        """
        tenant_dir = self.data_dir / tenant_id
        tenant_dir.mkdir(parents=True, exist_ok=True)
        return tenant_dir / "vce.db"


# Module-level singleton — import ``settings`` anywhere.
# Override GOOGLE_API_KEY via a non-prefixed env var since it's a
# Google-ecosystem convention.
class _SettingsWithGoogleKey(Settings):
    """Extends Settings to accept GOOGLE_API_KEY without the VCE_ prefix."""

    model_config = SettingsConfigDict(
        env_prefix="VCE_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Override: read GOOGLE_API_KEY directly (no VCE_ prefix).
    google_api_key: str

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: any,
        env_settings: any,
        dotenv_settings: any,
        file_secret_settings: any,
    ) -> tuple:
        """Add a non-prefixed env source for GOOGLE_API_KEY."""
        from pydantic_settings import EnvSettingsSource

        # Standard prefixed source (VCE_*)
        prefixed = env_settings
        # Non-prefixed source for GOOGLE_API_KEY
        non_prefixed = EnvSettingsSource(
            settings_cls,
            env_prefix="",
            env_nested_delimiter=None,
        )
        return (init_settings, prefixed, non_prefixed, dotenv_settings, file_secret_settings)


def get_settings() -> Settings:
    """Factory for creating settings. Used by FastAPI dependency injection."""
    return _SettingsWithGoogleKey()  # type: ignore[return-value]


settings: Settings = get_settings()
