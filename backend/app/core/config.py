"""Application settings, loaded from environment with an ``SOAR_`` prefix."""

from __future__ import annotations

import json
import secrets
from functools import lru_cache
from typing import Annotated, Any, Literal

from pydantic import Field, PostgresDsn, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

Environment = Literal["development", "staging", "production", "test"]

# List settings arrive from the environment as either JSON or comma-separated
# text. NoDecode stops pydantic-settings from JSON-decoding them up front (which
# rejects CSV) so ``_split_csv`` can handle both forms.
CsvList = Annotated[list[str], NoDecode]


class Settings(BaseSettings):
    """Runtime configuration.

    Every value can be overridden by an environment variable prefixed with
    ``SOAR_`` (for example ``SOAR_DATABASE_URL``). In production the app
    refuses to boot with placeholder credentials — see :meth:`_validate_production`.
    """

    model_config = SettingsConfigDict(
        env_prefix="SOAR_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ── Core ──────────────────────────────────────────────────────────
    environment: Environment = "development"
    debug: bool = False
    log_level: str = "INFO"
    log_format: Literal["json", "console"] = "json"
    app_name: str = "QuantNexa SOAR·AI"
    api_v1_prefix: str = "/api/v1"

    # ── Security ──────────────────────────────────────────────────────
    secret_key: str = Field(default_factory=lambda: secrets.token_hex(32))
    jwt_algorithm: str = "HS256"
    access_token_ttl_minutes: int = 60
    refresh_token_ttl_days: int = 14
    webhook_hmac_secret: str = Field(default_factory=lambda: secrets.token_hex(32))
    cors_origins: CsvList = Field(default_factory=lambda: ["http://localhost:5173"])
    trusted_hosts: CsvList = Field(default_factory=lambda: ["*"])
    rate_limit_per_minute: int = 600
    bootstrap_admin_email: str = "admin@quantnexa.com"
    bootstrap_admin_password: str | None = None

    # ── Datastores ────────────────────────────────────────────────────
    database_url: str = "postgresql+asyncpg://soar:soar@localhost:5432/soar"
    database_pool_size: int = 10
    database_max_overflow: int = 20
    database_echo: bool = False
    redis_url: str = "redis://localhost:6379/0"

    # ── Anthropic ─────────────────────────────────────────────────────
    anthropic_api_key: str | None = None
    anthropic_model: str = "claude-sonnet-4-6"
    anthropic_max_tokens: int = 2000
    anthropic_temperature: float = 0.1
    anthropic_timeout_seconds: float = 120.0
    agent_max_iterations: int = 6

    # ── RAG ───────────────────────────────────────────────────────────
    embedding_provider: Literal["hashing", "voyage", "openai"] = "hashing"
    embedding_dimensions: int = 768
    embedding_model: str = "voyage-3"
    voyage_api_key: str | None = None
    openai_api_key: str | None = None
    rag_top_k: int = 4
    rag_chunk_size: int = 256
    rag_chunk_overlap: int = 50
    rag_min_score: float = 0.01

    # ── Integrations ──────────────────────────────────────────────────
    splunk_url: str | None = None
    splunk_token: str | None = None
    elastic_url: str | None = None
    elastic_api_key: str | None = None
    crowdstrike_client_id: str | None = None
    crowdstrike_client_secret: str | None = None
    crowdstrike_base_url: str = "https://api.crowdstrike.com"
    virustotal_api_key: str | None = None
    abuseipdb_api_key: str | None = None
    otx_api_key: str | None = None
    misp_url: str | None = None
    misp_api_key: str | None = None
    paloalto_url: str | None = None
    paloalto_api_key: str | None = None
    tenable_access_key: str | None = None
    tenable_secret_key: str | None = None
    jira_url: str | None = None
    jira_user: str | None = None
    jira_token: str | None = None
    n8n_url: str = "http://localhost:5678"
    n8n_api_key: str | None = None
    integration_timeout_seconds: float = 20.0

    # ── AWS ───────────────────────────────────────────────────────────
    aws_region: str = "ap-south-1"
    aws_account_id: str | None = None
    aws_role_arn: str | None = None

    # ── Notifications ─────────────────────────────────────────────────
    slack_webhook_url: str | None = None
    pagerduty_routing_key: str | None = None
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_user: str | None = None
    smtp_password: str | None = None
    smtp_from: str = "soar@quantnexa.com"
    critical_recipients: CsvList = Field(default_factory=list)

    # ── Safety rails ──────────────────────────────────────────────────
    allow_destructive_actions: bool = False
    require_approval_for_containment: bool = True
    approval_timeout_seconds: int = 300

    # ── Observability ─────────────────────────────────────────────────
    metrics_enabled: bool = True
    tracing_enabled: bool = False
    otlp_endpoint: str | None = None

    @field_validator("cors_origins", "trusted_hosts", "critical_recipients", mode="before")
    @classmethod
    def _split_csv(cls, value: Any) -> Any:
        """Accept both a JSON list and a comma-separated string from the environment."""
        if isinstance(value, str):
            value = value.strip()
            if not value:
                return []
            if value.startswith("["):
                return json.loads(value)
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @field_validator("database_url")
    @classmethod
    def _require_async_driver(cls, value: str) -> str:
        if value.startswith("postgresql://"):
            # A sync DSN silently breaks the async engine; normalise it instead.
            return value.replace("postgresql://", "postgresql+asyncpg://", 1)
        return value

    @model_validator(mode="after")
    def _validate_production(self) -> Settings:
        if self.environment != "production":
            return self
        placeholders = {"change-me", "changeme", "secret", ""}
        if self.secret_key.lower() in placeholders or self.secret_key.startswith("change-me"):
            raise ValueError("SOAR_SECRET_KEY must be set to a real secret in production")
        if self.webhook_hmac_secret.startswith("change-me"):
            raise ValueError("SOAR_WEBHOOK_HMAC_SECRET must be set to a real secret in production")
        if self.debug:
            raise ValueError("SOAR_DEBUG must be false in production")
        if "*" in self.cors_origins:
            raise ValueError("SOAR_CORS_ORIGINS must not be a wildcard in production")
        return self

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def sync_database_url(self) -> str:
        """Alembic runs migrations synchronously."""
        return self.database_url.replace("+asyncpg", "+psycopg").replace(
            "postgresql+psycopg://", "postgresql://", 1
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Cached settings singleton — safe to call from anywhere including DI."""
    return Settings()


settings = get_settings()

__all__ = ["PostgresDsn", "Settings", "get_settings", "settings"]
