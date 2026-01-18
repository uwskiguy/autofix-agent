"""Configuration for AutoFix Agent."""

from typing import Optional

from pydantic import BaseModel, Field


class AutoFixConfig(BaseModel):
    """Configuration for the AutoFix Agent."""

    # Required
    anthropic_api_key: str = Field(..., description="Anthropic API key for Claude")
    github_token: str = Field(..., description="GitHub token with repo scope")
    github_repo: str = Field(..., description="GitHub repo in owner/repo format")
    slack_webhook_url: str = Field(..., description="Slack incoming webhook URL")

    # Optional
    github_path: str = Field(
        default="",
        description="Subfolder in repo where code lives (e.g., 'backend/')",
    )
    slack_channel: Optional[str] = Field(
        default=None,
        description="Slack channel for notifications",
    )
    slack_signing_secret: Optional[str] = Field(
        default=None,
        description="Slack signing secret for verifying requests",
    )
    sentry_webhook_secret: Optional[str] = Field(
        default=None,
        description="Secret for verifying Sentry webhooks",
    )

    # Thresholds
    min_confidence: float = Field(
        default=0.8,
        ge=0.0,
        le=1.0,
        description="Minimum confidence to propose a fix",
    )
    max_attempts_per_hour: int = Field(
        default=10,
        ge=1,
        description="Rate limit for fix attempts",
    )

    class Config:
        extra = "ignore"
