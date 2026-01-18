"""Application configuration using Pydantic Settings."""

from functools import lru_cache
from pathlib import Path
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Application
    app_env: str = Field(
        default="development",
        pattern="^(development|staging|production)$",
    )
    debug: bool = False
    secret_key: str = "dev-secret-change-in-production"

    # Anthropic (Claude API)
    anthropic_api_key: str = Field(
        ...,
        description="Anthropic API key for Claude",
    )

    # GitHub
    github_token: str = Field(
        ...,
        description="GitHub personal access token with repo scope",
    )

    # Slack
    slack_webhook_url: str = Field(
        ...,
        description="Slack incoming webhook URL",
    )
    slack_signing_secret: Optional[str] = Field(
        default=None,
        description="Slack signing secret for verifying requests",
    )
    slack_default_channel: str = "#errors"

    # Sentry
    sentry_webhook_secret: Optional[str] = Field(
        default=None,
        description="Secret for verifying Sentry webhooks",
    )

    # Rate Limiting & Thresholds
    max_fix_attempts_per_hour: int = 10
    min_confidence_threshold: float = 0.8

    # Paths
    projects_config_path: Path = Path("config/projects.yaml")


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


settings = get_settings()
