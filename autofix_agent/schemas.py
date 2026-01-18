"""Pydantic schemas for AutoFix Agent."""

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class FixStatus(str, Enum):
    """Status of a fix attempt."""

    PENDING = "pending"
    ANALYZING = "analyzing"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    PR_CREATED = "pr_created"
    REJECTED = "rejected"
    FAILED = "failed"
    SKIPPED = "skipped"


class ProjectConfig(BaseModel):
    """Configuration for a monitored project."""

    name: str
    github_repo: str
    github_path: str = ""
    sentry_project: Optional[str] = None
    slack_channel: Optional[str] = None


class SentryEventData(BaseModel):
    """Parsed Sentry event data."""

    event_id: str
    project: str
    message: Optional[str] = None
    culprit: Optional[str] = None
    level: str = "error"
    platform: Optional[str] = None
    exception_type: Optional[str] = None
    exception_value: Optional[str] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    function_name: Optional[str] = None
    stack_frames: list[dict[str, Any]] = Field(default_factory=list)
    context_lines: Optional[str] = None
    pre_context: list[str] = Field(default_factory=list)
    post_context: list[str] = Field(default_factory=list)


class ErrorAnalysis(BaseModel):
    """Analysis result from Claude."""

    error_type: str
    error_message: str
    root_cause: str
    file_path: str
    line_number: Optional[int] = None
    function_name: Optional[str] = None
    confidence: float = Field(ge=0.0, le=1.0)
    can_auto_fix: bool
    explanation: str


class ProposedFix(BaseModel):
    """A proposed code fix."""

    file_path: str
    original_code: str
    fixed_code: str
    explanation: str
    confidence: float = Field(ge=0.0, le=1.0)


class FixAttempt(BaseModel):
    """A complete fix attempt record."""

    id: str
    status: FixStatus = FixStatus.PENDING
    project_name: Optional[str] = None
    github_repo: Optional[str] = None
    sentry_event_id: str
    error_analysis: Optional[ErrorAnalysis] = None
    proposed_fixes: list[ProposedFix] = Field(default_factory=list)
    slack_message_ts: Optional[str] = None
    slack_channel: Optional[str] = None
    pr_url: Optional[str] = None
    pr_number: Optional[int] = None
    failure_reason: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    approved_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


class WebhookResponse(BaseModel):
    """Response to webhooks."""

    received: bool = True
    fix_attempt_id: Optional[str] = None
    message: str
