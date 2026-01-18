"""Fix orchestrator - coordinates the entire auto-fix workflow."""

import logging
import uuid
from datetime import datetime, timedelta
from typing import Any, Optional

from app.config import settings
from app.schemas import (
    FixAttempt,
    FixStatus,
    ProjectConfig,
    SentryEventData,
)
from app.services.analyzer import analyzer_service
from app.services.github_service import github_service
from app.services.slack_service import slack_service

logger = logging.getLogger(__name__)

# In-memory storage (use Redis in production)
_fix_attempts: dict[str, FixAttempt] = {}
_rate_limit_tracker: dict[str, datetime] = {}


class FixOrchestrator:
    """Orchestrates the entire auto-fix workflow."""

    def __init__(self):
        self.max_attempts_per_hour = settings.max_fix_attempts_per_hour
        self.min_confidence = settings.min_confidence_threshold

    def _check_rate_limit(self) -> bool:
        """Check if we're within rate limits."""
        now = datetime.utcnow()
        cutoff = now - timedelta(hours=1)

        # Clean old entries
        global _rate_limit_tracker
        _rate_limit_tracker = {
            k: v for k, v in _rate_limit_tracker.items() if v > cutoff
        }

        return len(_rate_limit_tracker) < self.max_attempts_per_hour

    def _record_attempt(self, attempt_id: str) -> None:
        """Record an attempt for rate limiting."""
        _rate_limit_tracker[attempt_id] = datetime.utcnow()

    def get_fix_attempt(self, attempt_id: str) -> Optional[FixAttempt]:
        """Get a fix attempt by ID."""
        return _fix_attempts.get(attempt_id)

    def get_recent_attempts(self, limit: int = 20) -> list[FixAttempt]:
        """Get recent fix attempts."""
        attempts = sorted(
            _fix_attempts.values(),
            key=lambda x: x.created_at,
            reverse=True,
        )
        return attempts[:limit]

    async def process_sentry_error(
        self,
        event_data: SentryEventData,
        project_config: Optional[ProjectConfig] = None,
    ) -> FixAttempt:
        """
        Process a Sentry error through the full auto-fix workflow.

        1. Analyze error with Claude
        2. Generate proposed fix
        3. Send to Slack for approval
        4. Wait for user action (approve/reject)

        Args:
            event_data: Parsed Sentry event data
            project_config: Optional project configuration

        Returns:
            FixAttempt with current status
        """
        attempt_id = str(uuid.uuid4())
        fix_attempt = FixAttempt(
            id=attempt_id,
            status=FixStatus.PENDING,
            sentry_event_id=event_data.event_id,
            project_name=project_config.name if project_config else None,
            github_repo=project_config.github_repo if project_config else None,
        )

        # Store attempt
        _fix_attempts[attempt_id] = fix_attempt

        try:
            # Check rate limits
            if not self._check_rate_limit():
                fix_attempt.status = FixStatus.SKIPPED
                fix_attempt.failure_reason = f"Rate limit exceeded ({self.max_attempts_per_hour}/hour)"
                return fix_attempt

            self._record_attempt(attempt_id)
            fix_attempt.status = FixStatus.ANALYZING

            # Get source code if we have repo info
            source_code = ""
            if project_config and event_data.file_path:
                file_path = event_data.file_path
                if project_config.github_path:
                    file_path = f"{project_config.github_path.rstrip('/')}/{file_path.lstrip('/')}"

                source_code = await github_service.get_file_content(
                    repo=project_config.github_repo,
                    file_path=file_path,
                ) or ""

            # Analyze error with Claude
            logger.info(f"Analyzing error {event_data.event_id}")
            analysis = await analyzer_service.analyze_error(event_data, source_code)
            fix_attempt.error_analysis = analysis

            # Check if we can auto-fix
            if not analysis.can_auto_fix:
                fix_attempt.status = FixStatus.SKIPPED
                fix_attempt.failure_reason = f"Cannot auto-fix: {analysis.explanation}"
                # Still notify on Slack for visibility
                await slack_service.send_fix_proposal(fix_attempt)
                return fix_attempt

            if analysis.confidence < self.min_confidence:
                fix_attempt.status = FixStatus.SKIPPED
                fix_attempt.failure_reason = f"Confidence too low ({analysis.confidence:.0%} < {self.min_confidence:.0%})"
                return fix_attempt

            # Generate fix
            logger.info(f"Generating fix for {event_data.event_id}")
            fixes = await analyzer_service.generate_fix(analysis, source_code)
            fix_attempt.proposed_fixes = fixes

            if not fixes:
                fix_attempt.status = FixStatus.FAILED
                fix_attempt.failure_reason = "Could not generate a fix"
                return fix_attempt

            # Send to Slack for approval
            fix_attempt.status = FixStatus.AWAITING_APPROVAL
            channel = project_config.slack_channel if project_config else None
            success, message_ts = await slack_service.send_fix_proposal(
                fix_attempt, channel=channel
            )

            if success:
                fix_attempt.slack_message_ts = message_ts
                fix_attempt.slack_channel = channel
                logger.info(f"Fix proposal sent to Slack for {attempt_id}")
            else:
                logger.error(f"Failed to send Slack notification for {attempt_id}")

            return fix_attempt

        except Exception as e:
            logger.exception(f"Error processing fix attempt {attempt_id}: {e}")
            fix_attempt.status = FixStatus.FAILED
            fix_attempt.failure_reason = str(e)
            fix_attempt.completed_at = datetime.utcnow()
            return fix_attempt

    async def approve_fix(
        self,
        attempt_id: str,
        user_name: str,
        response_url: Optional[str] = None,
    ) -> FixAttempt:
        """
        Approve a fix and create the GitHub PR.

        Args:
            attempt_id: ID of the fix attempt to approve
            user_name: Name of the user who approved
            response_url: Slack response URL for updating the message

        Returns:
            Updated FixAttempt
        """
        fix_attempt = _fix_attempts.get(attempt_id)
        if not fix_attempt:
            raise ValueError(f"Fix attempt {attempt_id} not found")

        if fix_attempt.status != FixStatus.AWAITING_APPROVAL:
            raise ValueError(f"Fix attempt {attempt_id} is not awaiting approval")

        fix_attempt.status = FixStatus.APPROVED
        fix_attempt.approved_at = datetime.utcnow()

        logger.info(f"Fix {attempt_id} approved by {user_name}")

        # Create PR
        if fix_attempt.github_repo and fix_attempt.proposed_fixes:
            pr_url, pr_number = await github_service.create_fix_pr(fix_attempt)

            if pr_url:
                fix_attempt.status = FixStatus.PR_CREATED
                fix_attempt.pr_url = pr_url
                fix_attempt.pr_number = pr_number
                fix_attempt.completed_at = datetime.utcnow()
                logger.info(f"PR created for fix {attempt_id}: {pr_url}")
            else:
                fix_attempt.status = FixStatus.FAILED
                fix_attempt.failure_reason = "Failed to create GitHub PR"
        else:
            fix_attempt.status = FixStatus.FAILED
            fix_attempt.failure_reason = "Missing GitHub repo or fixes"

        # Notify Slack of result
        await slack_service.send_fix_result(fix_attempt, response_url)

        return fix_attempt

    async def reject_fix(
        self,
        attempt_id: str,
        user_name: str,
        response_url: Optional[str] = None,
    ) -> FixAttempt:
        """
        Reject a fix proposal.

        Args:
            attempt_id: ID of the fix attempt to reject
            user_name: Name of the user who rejected
            response_url: Slack response URL for updating the message

        Returns:
            Updated FixAttempt
        """
        fix_attempt = _fix_attempts.get(attempt_id)
        if not fix_attempt:
            raise ValueError(f"Fix attempt {attempt_id} not found")

        fix_attempt.status = FixStatus.REJECTED
        fix_attempt.completed_at = datetime.utcnow()
        fix_attempt.failure_reason = f"Rejected by {user_name}"

        logger.info(f"Fix {attempt_id} rejected by {user_name}")

        # Notify Slack
        await slack_service.send_fix_result(fix_attempt, response_url)

        return fix_attempt


# Singleton
fix_orchestrator = FixOrchestrator()
