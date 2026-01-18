"""
AutoFix Agent - Claude-powered error monitoring and auto-fixing for FastAPI apps.

Usage:
    from fastapi import FastAPI
    from autofix_agent import AutoFixAgent

    app = FastAPI()

    autofix = AutoFixAgent(
        anthropic_api_key="sk-ant-...",
        github_token="ghp_...",
        github_repo="owner/repo",
        slack_webhook_url="https://hooks.slack.com/...",
    )

    # Add routes to your app
    autofix.mount(app, prefix="/autofix")
"""

__version__ = "1.0.0"

from .agent import AutoFixAgent
from .config import AutoFixConfig
from .schemas import FixAttempt, FixStatus, ProjectConfig

__all__ = [
    "AutoFixAgent",
    "AutoFixConfig",
    "FixAttempt",
    "FixStatus",
    "ProjectConfig",
]
