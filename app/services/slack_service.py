"""Slack notification service with interactive buttons."""

import hashlib
import hmac
import json
import logging
import time
from typing import Optional

import httpx

from app.config import settings
from app.schemas import ErrorAnalysis, FixAttempt, ProposedFix

logger = logging.getLogger(__name__)


class SlackService:
    """Service for sending Slack notifications and handling interactions."""

    def __init__(self):
        self.webhook_url = settings.slack_webhook_url
        self.signing_secret = settings.slack_signing_secret
        self.default_channel = settings.slack_default_channel

    async def send_fix_proposal(
        self,
        fix_attempt: FixAttempt,
        channel: Optional[str] = None,
    ) -> tuple[bool, Optional[str]]:
        """
        Send a fix proposal to Slack with Approve/Reject buttons.

        Args:
            fix_attempt: The fix attempt with analysis and proposed fixes
            channel: Slack channel (uses default if not specified)

        Returns:
            Tuple of (success, message_ts)
        """
        if not fix_attempt.error_analysis or not fix_attempt.proposed_fixes:
            logger.warning("Cannot send Slack message without analysis and fixes")
            return False, None

        analysis = fix_attempt.error_analysis
        fixes = fix_attempt.proposed_fixes

        # Build the Slack message
        blocks = self._build_fix_proposal_blocks(fix_attempt, analysis, fixes)

        payload = {
            "channel": channel or self.default_channel,
            "blocks": blocks,
            "text": f"🔧 AutoFix: {analysis.error_type} in {analysis.file_path}",
        }

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.webhook_url,
                    json=payload,
                    timeout=10.0,
                )

                if response.status_code == 200:
                    # Note: Incoming webhooks don't return message_ts
                    # For full interactivity, use Slack Web API with chat.postMessage
                    return True, None

                logger.error(f"Slack webhook error: {response.text}")
                return False, None

        except Exception as e:
            logger.exception(f"Failed to send Slack notification: {e}")
            return False, None

    def _build_fix_proposal_blocks(
        self,
        fix_attempt: FixAttempt,
        analysis: ErrorAnalysis,
        fixes: list[ProposedFix],
    ) -> list[dict]:
        """Build Slack Block Kit blocks for fix proposal."""
        blocks = [
            # Header
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🔧 AutoFix: Error Detected",
                    "emoji": True,
                },
            },
            # Error Info
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Error Type:*\n`{analysis.error_type}`",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Confidence:*\n{analysis.confidence:.0%}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*File:*\n`{analysis.file_path}`",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Line:*\n{analysis.line_number or 'N/A'}",
                    },
                ],
            },
            # Error Message
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Error Message:*\n```{analysis.error_message[:500]}```",
                },
            },
            {"type": "divider"},
            # Root Cause
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*🔍 Root Cause Analysis:*\n{analysis.root_cause}",
                },
            },
            {"type": "divider"},
        ]

        # Add proposed fixes
        for i, fix in enumerate(fixes, 1):
            # Truncate code for Slack display
            orig_code = fix.original_code[:500] + ("..." if len(fix.original_code) > 500 else "")
            fixed_code = fix.fixed_code[:500] + ("..." if len(fix.fixed_code) > 500 else "")

            blocks.extend([
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*📝 Proposed Fix {i}:*\n{fix.explanation}",
                    },
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Before:*\n```{orig_code}```",
                    },
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*After:*\n```{fixed_code}```",
                    },
                },
            ])

        # Action buttons
        blocks.extend([
            {"type": "divider"},
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Project:* `{fix_attempt.project_name or 'Unknown'}` | *Repo:* `{fix_attempt.github_repo or 'Unknown'}`",
                },
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "✅ Authorize Fix",
                            "emoji": True,
                        },
                        "style": "primary",
                        "action_id": "autofix_approve",
                        "value": fix_attempt.id,
                    },
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "❌ Dismiss",
                            "emoji": True,
                        },
                        "style": "danger",
                        "action_id": "autofix_reject",
                        "value": fix_attempt.id,
                    },
                ],
            },
            # Context footer
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"Fix ID: `{fix_attempt.id}` | Sentry Event: `{fix_attempt.sentry_event_id[:12]}...`",
                    },
                ],
            },
        ])

        return blocks

    async def send_fix_result(
        self,
        fix_attempt: FixAttempt,
        response_url: Optional[str] = None,
    ) -> bool:
        """
        Send the result of a fix attempt (PR created or rejected).

        Args:
            fix_attempt: The completed fix attempt
            response_url: Slack response URL for updating the original message

        Returns:
            True if successful
        """
        if fix_attempt.pr_url:
            text = f"✅ *PR Created:* <{fix_attempt.pr_url}|View Pull Request #{fix_attempt.pr_number}>"
        elif fix_attempt.status.value == "rejected":
            text = "❌ *Fix Rejected* - No changes made."
        else:
            text = f"⚠️ *Fix Failed:* {fix_attempt.failure_reason or 'Unknown error'}"

        payload = {
            "text": text,
            "replace_original": False,
        }

        url = response_url or self.webhook_url

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(url, json=payload, timeout=10.0)
                return response.status_code == 200
        except Exception as e:
            logger.exception(f"Failed to send fix result: {e}")
            return False

    def verify_signature(
        self,
        body: bytes,
        timestamp: str,
        signature: str,
    ) -> bool:
        """Verify Slack request signature."""
        if not self.signing_secret:
            return True  # Skip verification if not configured

        # Check timestamp (prevent replay attacks)
        if abs(time.time() - int(timestamp)) > 300:
            return False

        # Compute expected signature
        sig_basestring = f"v0:{timestamp}:{body.decode()}"
        expected = "v0=" + hmac.new(
            self.signing_secret.encode(),
            sig_basestring.encode(),
            hashlib.sha256,
        ).hexdigest()

        return hmac.compare_digest(expected, signature)


# Singleton
slack_service = SlackService()
