"""Centralized configuration loaded from environment variables.

All settings are validated at startup via Pydantic.
"""

from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import Field, AliasChoices
from pydantic_settings import BaseSettings, SettingsConfigDict


class ExecutionMode(StrEnum):
    MODE_1 = "mode_1"  # Read-only (default)
    MODE_2 = "mode_2"  # Read + Edit/Update
    MODE_3 = "mode_3"  # Full Access (Create/Delete)


class Settings(BaseSettings):
    """Application-wide settings sourced from environment variables.

    Attributes:
        google_api_key: Google AI API key.
        openai_api_key: OpenAI API key (also used for Qwen/DeepSeek if via OpenAI compatible endpoint).
        anthropic_api_key: Anthropic API key.
        llm_provider: The provider to use for the LLM (e.g., google_genai, openai, anthropic).
        llm_model: The specific model identifier used by all agents.
        embedding_provider: The provider to use for embeddings.
        embedding_model: The specific embedding model.
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

    # API Keys (can be provided without VCE_ prefix)
    google_api_key: str | None = Field(default=None, validation_alias=AliasChoices('vce_google_api_key', 'google_api_key'))
    openai_api_key: str | None = Field(default=None, validation_alias=AliasChoices('vce_openai_api_key', 'openai_api_key'))
    anthropic_api_key: str | None = Field(default=None, validation_alias=AliasChoices('vce_anthropic_api_key', 'anthropic_api_key'))
    deepseek_api_key: str | None = Field(default=None, validation_alias=AliasChoices('vce_deepseek_api_key', 'deepseek_api_key'))
    qwen_api_key: str | None = Field(default=None, validation_alias=AliasChoices('vce_qwen_api_key', 'qwen_api_key'))
    
    # Custom API Base (useful for OpenAI-compatible providers like DeepSeek, Qwen)
    openai_api_base: str | None = Field(default=None, validation_alias=AliasChoices('vce_openai_api_base', 'openai_api_base'))

    # LLM Configuration
    llm_provider: str = "google_genai"
    llm_model: str = "gemini-3.1-pro"

    # Embeddings Configuration
    embedding_provider: str = "google_genai"
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

    # Security & Auth
    credential_secret: str = "change-this-to-a-strong-random-secret"
    jwt_secret_key: str = "change-this-to-a-strong-random-jwt-secret"
    jwt_expiration_minutes: int = 1440  # 24 hours
    admin_password: str = "VCE-HQ#2026"  # PRD §7.1 default — override via VCE_ADMIN_PASSWORD

    # Command execution (The Hands)
    cmd_max_iterations: int = 5
    cmd_max_per_session: int = 15
    cmd_timeout_seconds: int = 30
    cmd_max_stdout_bytes: int = 65536   # 64 KB
    cmd_max_stderr_bytes: int = 16384   # 16 KB
    cmd_enabled: bool = True
    unknown_binary_risk: str = "ELEVATED"
    
    # Orchestration
    router_max_iterations: int = 3
    execution_mode: ExecutionMode = ExecutionMode.MODE_1

    def tenant_db_path(self, tenant_id: str) -> Path:
        """Return the SQLite database path for a given tenant."""
        tenant_dir = self.data_dir / tenant_id
        tenant_dir.mkdir(parents=True, exist_ok=True)
        return tenant_dir / "vce.db"


def get_settings() -> Settings:
    """Factory for creating settings. Used by FastAPI dependency injection."""
    return Settings()


settings: Settings = get_settings()

