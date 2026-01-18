"""
AutoFix Agent - Main class for integrating into FastAPI apps.

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

    autofix.mount(app)  # Adds /autofix/* routes
"""

import base64
import hashlib
import hmac
import json
import logging
import re
import time
import urllib.parse
import uuid
from datetime import datetime, timedelta
from typing import Any, Optional, Union

import httpx
from fastapi import APIRouter, BackgroundTasks, FastAPI, Header, HTTPException, Request, status

from .config import AutoFixConfig
from .schemas import (
    ErrorAnalysis,
    FixAttempt,
    FixStatus,
    ProposedFix,
    SentryEventData,
    WebhookResponse,
)

logger = logging.getLogger(__name__)


class AutoFixAgent:
    """
    Claude-powered error monitoring and auto-fixing agent.

    Integrates into your existing FastAPI app to:
    1. Receive Sentry error webhooks
    2. Analyze errors with Claude
    3. Send fix proposals to Slack
    4. Create GitHub PRs on approval
    """

    def __init__(
        self,
        anthropic_api_key: str,
        github_token: str,
        github_repo: str,
        slack_webhook_url: str,
        github_path: str = "",
        slack_channel: Optional[str] = None,
        slack_signing_secret: Optional[str] = None,
        sentry_webhook_secret: Optional[str] = None,
        min_confidence: float = 0.8,
        max_attempts_per_hour: int = 10,
        **kwargs,
    ):
        """
        Initialize the AutoFix Agent.

        Args:
            anthropic_api_key: Anthropic API key for Claude
            github_token: GitHub token with repo scope
            github_repo: GitHub repo in owner/repo format
            slack_webhook_url: Slack incoming webhook URL
            github_path: Subfolder in repo where code lives (e.g., 'backend/')
            slack_channel: Slack channel for notifications
            slack_signing_secret: For verifying Slack requests
            sentry_webhook_secret: For verifying Sentry webhooks
            min_confidence: Minimum confidence to propose a fix (0-1)
            max_attempts_per_hour: Rate limit for fix attempts
        """
        self.config = AutoFixConfig(
            anthropic_api_key=anthropic_api_key,
            github_token=github_token,
            github_repo=github_repo,
            slack_webhook_url=slack_webhook_url,
            github_path=github_path,
            slack_channel=slack_channel,
            slack_signing_secret=slack_signing_secret,
            sentry_webhook_secret=sentry_webhook_secret,
            min_confidence=min_confidence,
            max_attempts_per_hour=max_attempts_per_hour,
        )

        # Storage (in-memory, use Redis in production for persistence)
        self._fix_attempts: dict[str, FixAttempt] = {}
        self._rate_limit_tracker: dict[str, datetime] = {}

        self.router = self._create_router()

    def mount(
        self,
        app: FastAPI,
        prefix: str = "/autofix",
        tags: list[str] = None,
    ) -> None:
        """
        Mount the AutoFix routes onto a FastAPI app.

        Args:
            app: FastAPI application instance
            prefix: URL prefix for routes (default: /autofix)
            tags: OpenAPI tags for the routes
        """
        app.include_router(
            self.router,
            prefix=prefix,
            tags=tags or ["AutoFix"],
        )
        logger.info(f"AutoFix Agent mounted at {prefix}")

    def _create_router(self) -> APIRouter:
        """Create the FastAPI router with all endpoints."""
        router = APIRouter()

        @router.get("/status")
        async def get_status():
            """Get AutoFix status."""
            return {
                "status": "active",
                "github_repo": self.config.github_repo,
                "recent_attempts": len(self._fix_attempts),
            }

        @router.post("/webhooks/sentry", response_model=WebhookResponse)
        async def receive_sentry_webhook(
            request: Request,
            background_tasks: BackgroundTasks,
            sentry_hook_signature: Optional[str] = Header(None, alias="Sentry-Hook-Signature"),
        ):
            """Receive Sentry webhook and trigger analysis."""
            body = await request.body()

            # Verify signature if configured
            if self.config.sentry_webhook_secret and sentry_hook_signature:
                expected = hmac.new(
                    self.config.sentry_webhook_secret.encode(),
                    body,
                    hashlib.sha256,
                ).hexdigest()
                if not hmac.compare_digest(sentry_hook_signature, expected):
                    raise HTTPException(status_code=401, detail="Invalid signature")

            payload = await request.json()
            action = payload.get("action", "")

            if action not in ["created", "triggered"]:
                return WebhookResponse(message=f"Ignored action: {action}")

            event_data = self._parse_sentry_payload(payload)
            if not event_data:
                return WebhookResponse(message="Could not parse event data")

            logger.info(f"Sentry webhook received: {event_data.event_id}")

            background_tasks.add_task(self._process_error, event_data)

            return WebhookResponse(
                fix_attempt_id=event_data.event_id,
                message="Processing started",
            )

        @router.post("/slack/interact")
        async def handle_slack_interaction(
            request: Request,
            x_slack_signature: Optional[str] = Header(None, alias="X-Slack-Signature"),
            x_slack_request_timestamp: Optional[str] = Header(None, alias="X-Slack-Request-Timestamp"),
        ):
            """Handle Slack button clicks."""
            body = await request.body()

            # Verify signature if configured
            if self.config.slack_signing_secret and x_slack_signature and x_slack_request_timestamp:
                if not self._verify_slack_signature(body, x_slack_request_timestamp, x_slack_signature):
                    raise HTTPException(status_code=401, detail="Invalid signature")

            body_str = body.decode()
            parsed = urllib.parse.parse_qs(body_str)
            payload_str = parsed.get("payload", [""])[0]

            if not payload_str:
                raise HTTPException(status_code=400, detail="Missing payload")

            payload = json.loads(payload_str)

            if payload.get("type") != "block_actions":
                return {"ok": True}

            actions = payload.get("actions", [])
            if not actions:
                return {"ok": True}

            action = actions[0]
            action_id = action.get("action_id")
            attempt_id = action.get("value")
            user = payload.get("user", {})
            user_name = user.get("username", user.get("name", "Unknown"))
            response_url = payload.get("response_url")

            logger.info(f"Slack action: {action_id} for {attempt_id} by {user_name}")

            if action_id == "autofix_approve":
                await self._approve_fix(attempt_id, user_name, response_url)
            elif action_id == "autofix_reject":
                await self._reject_fix(attempt_id, user_name, response_url)

            return {"ok": True}

        @router.get("/attempts")
        async def list_attempts(limit: int = 20):
            """List recent fix attempts."""
            attempts = sorted(
                self._fix_attempts.values(),
                key=lambda x: x.created_at,
                reverse=True,
            )
            return attempts[:limit]

        @router.get("/attempts/{attempt_id}")
        async def get_attempt(attempt_id: str):
            """Get a specific fix attempt."""
            attempt = self._fix_attempts.get(attempt_id)
            if not attempt:
                raise HTTPException(status_code=404, detail="Not found")
            return attempt

        return router

    # -------------------------------------------------------------------------
    # Core Processing
    # -------------------------------------------------------------------------

    async def _process_error(self, event_data: SentryEventData) -> None:
        """Process an error through the full workflow."""
        attempt_id = str(uuid.uuid4())
        fix_attempt = FixAttempt(
            id=attempt_id,
            status=FixStatus.PENDING,
            sentry_event_id=event_data.event_id,
            github_repo=self.config.github_repo,
        )
        self._fix_attempts[attempt_id] = fix_attempt

        try:
            # Rate limit check
            if not self._check_rate_limit():
                fix_attempt.status = FixStatus.SKIPPED
                fix_attempt.failure_reason = "Rate limit exceeded"
                return

            self._record_attempt(attempt_id)
            fix_attempt.status = FixStatus.ANALYZING

            # Get source code
            source_code = ""
            if event_data.file_path:
                file_path = event_data.file_path
                if self.config.github_path:
                    file_path = f"{self.config.github_path.rstrip('/')}/{file_path.lstrip('/')}"
                source_code = await self._get_github_file(file_path) or ""

            # Analyze with Claude
            analysis = await self._analyze_error(event_data, source_code)
            fix_attempt.error_analysis = analysis

            if not analysis.can_auto_fix:
                fix_attempt.status = FixStatus.SKIPPED
                fix_attempt.failure_reason = analysis.explanation
                await self._send_slack_notification(fix_attempt)
                return

            if analysis.confidence < self.config.min_confidence:
                fix_attempt.status = FixStatus.SKIPPED
                fix_attempt.failure_reason = f"Confidence too low ({analysis.confidence:.0%})"
                return

            # Generate fix
            fixes = await self._generate_fix(analysis, source_code)
            fix_attempt.proposed_fixes = fixes

            if not fixes:
                fix_attempt.status = FixStatus.FAILED
                fix_attempt.failure_reason = "Could not generate fix"
                return

            # Automatically create PR
            pr_url, pr_number = await self._create_pr(fix_attempt)
            if pr_url:
                fix_attempt.pr_url = pr_url
                fix_attempt.pr_number = pr_number
                fix_attempt.status = FixStatus.AWAITING_APPROVAL
                logger.info(f"PR created: {pr_url}")
            else:
                fix_attempt.status = FixStatus.FAILED
                fix_attempt.failure_reason = "Failed to create PR"

            # Send to Slack - ask to deploy if PR created, or notify of failure
            await self._send_slack_notification(fix_attempt)

        except Exception as e:
            logger.exception(f"Error processing {attempt_id}: {e}")
            fix_attempt.status = FixStatus.FAILED
            fix_attempt.failure_reason = str(e)

    async def _approve_fix(
        self,
        attempt_id: str,
        user_name: str,
        response_url: Optional[str],
    ) -> None:
        """Approve deployment - merge the PR to deploy live."""
        fix_attempt = self._fix_attempts.get(attempt_id)
        if not fix_attempt or fix_attempt.status != FixStatus.AWAITING_APPROVAL:
            return

        fix_attempt.status = FixStatus.APPROVED
        fix_attempt.approved_at = datetime.utcnow()

        # Merge the PR to deploy
        if fix_attempt.pr_number:
            merged = await self._merge_pr(fix_attempt.pr_number, user_name)
            if merged:
                fix_attempt.status = FixStatus.DEPLOYED
                logger.info(f"PR #{fix_attempt.pr_number} merged by {user_name}")
            else:
                fix_attempt.status = FixStatus.FAILED
                fix_attempt.failure_reason = "Failed to merge PR"
        else:
            fix_attempt.status = FixStatus.FAILED
            fix_attempt.failure_reason = "No PR to merge"

        fix_attempt.completed_at = datetime.utcnow()
        await self._send_slack_result(fix_attempt, response_url)

    async def _reject_fix(
        self,
        attempt_id: str,
        user_name: str,
        response_url: Optional[str],
    ) -> None:
        """Reject a fix proposal."""
        fix_attempt = self._fix_attempts.get(attempt_id)
        if not fix_attempt:
            return

        fix_attempt.status = FixStatus.REJECTED
        fix_attempt.failure_reason = f"Rejected by {user_name}"
        fix_attempt.completed_at = datetime.utcnow()
        await self._send_slack_result(fix_attempt, response_url)

    # -------------------------------------------------------------------------
    # Claude Integration
    # -------------------------------------------------------------------------

    async def _analyze_error(
        self,
        event_data: SentryEventData,
        source_code: str,
    ) -> ErrorAnalysis:
        """Analyze error with Claude in CTO/Orchestrator mode."""
        prompt = f"""You are the CTO reviewing a production error. Analyze this thoroughly before recommending any fix.

## ERROR DETAILS
- Type: {event_data.exception_type or 'Unknown'}
- Message: {event_data.exception_value or event_data.message or ''}
- File: {event_data.file_path or 'Unknown'}
- Line: {event_data.line_number or 'Unknown'}
- Function: {event_data.function_name or 'Unknown'}

## CODE CONTEXT
{chr(10).join(event_data.pre_context)}
>>> {event_data.context_lines or ''}
{chr(10).join(event_data.post_context)}

## SOURCE FILE
```python
{source_code[:6000] if source_code else 'Not available'}
```

## CTO ANALYSIS REQUIRED

Perform a thorough Orchestrator-style analysis:

1. **COMPLEXITY**: Is this minimal/simple/standard/complex?
2. **ROOT CAUSE**: What exactly caused this error?
3. **BLAST RADIUS**: What else could be affected by this bug or its fix?
4. **SECURITY**: Could this error or fix have security implications?
5. **RISK ASSESSMENT**: What's the risk of auto-fixing vs. manual review?

## DECISION CRITERIA

can_auto_fix = TRUE only if ALL conditions met:
- Complexity is minimal or simple (single line change, obvious fix)
- No security implications (not auth, payments, PII, crypto)
- No database/schema changes required
- No external API contract changes
- Fix is isolated (won't affect other code paths)
- High confidence (>90%) the fix is correct

can_auto_fix = FALSE if ANY of these apply:
- Architecture or design issues
- Security-sensitive code (auth, tokens, encryption, validation)
- Database queries or schema
- External API integrations
- Business logic that requires product understanding
- Multiple files would need changes
- The fix could mask a deeper problem

RESPOND WITH JSON ONLY:
{{
    "error_type": "...",
    "error_message": "...",
    "root_cause": "detailed CTO-level explanation of what went wrong",
    "complexity": "minimal|simple|standard|complex",
    "security_implications": "none|low|medium|high",
    "blast_radius": "isolated|moderate|wide",
    "file_path": "{event_data.file_path or ''}",
    "line_number": {event_data.line_number or 'null'},
    "function_name": "{event_data.function_name or ''}",
    "confidence": 0.0 to 1.0,
    "can_auto_fix": true/false,
    "explanation": "CTO reasoning for why this can/cannot be safely auto-fixed",
    "recommendation": "Brief recommendation for the human reviewer"
}}
"""

        response = await self._call_claude(prompt)
        return self._parse_analysis(response, event_data)

    async def _generate_fix(
        self,
        analysis: ErrorAnalysis,
        source_code: str,
    ) -> list[ProposedFix]:
        """Generate fix with Claude in CTO mode."""
        prompt = f"""You are the CTO generating a production fix. Be conservative and precise.

## CTO ANALYSIS (Already Reviewed)
- Error: {analysis.error_type}
- Message: {analysis.error_message}
- Root Cause: {analysis.root_cause}
- File: {analysis.file_path}
- Line: {analysis.line_number}

## SOURCE CODE
```python
{source_code}
```

## CTO FIX GUIDELINES

1. **MINIMAL CHANGE**: Make the smallest possible fix. One line if possible.
2. **NO SIDE EFFECTS**: Don't refactor, don't "improve" surrounding code.
3. **DEFENSIVE**: Add null checks, bounds checks, or validation as needed.
4. **NO NEW DEPENDENCIES**: Don't add imports unless absolutely required.
5. **PRESERVE BEHAVIOR**: Fix the bug without changing intended functionality.

## QUALITY CHECKLIST (verify before responding)
- [ ] Fix addresses the root cause, not just the symptom
- [ ] No security vulnerabilities introduced
- [ ] No breaking changes to function signatures/returns
- [ ] Code follows existing patterns in the file

RESPOND WITH JSON ONLY:
{{
    "fixes": [
        {{
            "file_path": "{analysis.file_path}",
            "original_code": "exact code to replace (include enough surrounding context to be unique in the file)",
            "fixed_code": "corrected code with same formatting/indentation",
            "explanation": "CTO explanation of why this fix is safe and correct",
            "confidence": 0.0 to 1.0,
            "risk_notes": "any risks or edge cases to be aware of"
        }}
    ]
}}
"""

        response = await self._call_claude(prompt)
        return self._parse_fixes(response)

    async def _call_claude(self, prompt: str) -> str:
        """Call Claude API."""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": self.config.anthropic_api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": "claude-sonnet-4-20250514",
                    "max_tokens": 4096,
                    "messages": [{"role": "user", "content": prompt}],
                },
                timeout=60.0,
            )
            if response.status_code != 200:
                raise Exception(f"Claude API error: {response.status_code}")
            return response.json()["content"][0]["text"]

    # -------------------------------------------------------------------------
    # GitHub Integration
    # -------------------------------------------------------------------------

    async def _get_github_file(self, file_path: str) -> Optional[str]:
        """Get file content from GitHub."""
        clean_path = file_path.lstrip("/")
        url = f"https://api.github.com/repos/{self.config.github_repo}/contents/{clean_path}"

        async with httpx.AsyncClient() as client:
            response = await client.get(
                url,
                headers={
                    "Authorization": f"Bearer {self.config.github_token}",
                    "Accept": "application/vnd.github.v3.raw",
                },
                timeout=30.0,
            )
            if response.status_code == 200:
                return response.text
        return None

    async def _create_pr(self, fix_attempt: FixAttempt) -> tuple[Optional[str], Optional[int]]:
        """Create GitHub PR with the fix."""
        if not fix_attempt.proposed_fixes or not fix_attempt.error_analysis:
            return None, None

        analysis = fix_attempt.error_analysis
        branch_name = f"autofix/{fix_attempt.sentry_event_id[:12]}"

        async with httpx.AsyncClient() as client:
            headers = {
                "Authorization": f"Bearer {self.config.github_token}",
                "Accept": "application/vnd.github.v3+json",
            }

            # Get default branch SHA
            repo_resp = await client.get(
                f"https://api.github.com/repos/{self.config.github_repo}",
                headers=headers,
                timeout=30.0,
            )
            if repo_resp.status_code != 200:
                logger.error(f"Failed to get repo info: {repo_resp.status_code} - {repo_resp.text}")
                return None, None

            default_branch = repo_resp.json().get("default_branch", "main")

            ref_resp = await client.get(
                f"https://api.github.com/repos/{self.config.github_repo}/git/refs/heads/{default_branch}",
                headers=headers,
                timeout=30.0,
            )
            if ref_resp.status_code != 200:
                logger.error(f"Failed to get branch ref: {ref_resp.status_code} - {ref_resp.text}")
                return None, None

            base_sha = ref_resp.json()["object"]["sha"]

            # Create branch
            await client.post(
                f"https://api.github.com/repos/{self.config.github_repo}/git/refs",
                headers=headers,
                json={"ref": f"refs/heads/{branch_name}", "sha": base_sha},
                timeout=30.0,
            )

            # Apply fixes
            for fix in fix_attempt.proposed_fixes:
                file_path = fix.file_path.lstrip("/")
                if self.config.github_path and not file_path.startswith(self.config.github_path):
                    file_path = f"{self.config.github_path.rstrip('/')}/{file_path}"

                # Get file SHA
                file_resp = await client.get(
                    f"https://api.github.com/repos/{self.config.github_repo}/contents/{file_path}",
                    headers=headers,
                    params={"ref": branch_name},
                    timeout=30.0,
                )
                if file_resp.status_code != 200:
                    continue

                file_data = file_resp.json()
                current_content = base64.b64decode(file_data["content"]).decode()

                if fix.original_code not in current_content:
                    logger.warning(f"Original code not found in {file_path}")
                    continue

                new_content = current_content.replace(fix.original_code, fix.fixed_code, 1)

                await client.put(
                    f"https://api.github.com/repos/{self.config.github_repo}/contents/{file_path}",
                    headers=headers,
                    json={
                        "message": f"fix: {fix.explanation[:50]}",
                        "content": base64.b64encode(new_content.encode()).decode(),
                        "sha": file_data["sha"],
                        "branch": branch_name,
                    },
                    timeout=30.0,
                )

            # Create PR
            pr_resp = await client.post(
                f"https://api.github.com/repos/{self.config.github_repo}/pulls",
                headers=headers,
                json={
                    "title": f"[AutoFix] Fix {analysis.error_type}",
                    "body": self._build_pr_body(fix_attempt),
                    "head": branch_name,
                    "base": default_branch,
                },
                timeout=30.0,
            )

            if pr_resp.status_code == 201:
                pr_data = pr_resp.json()
                return pr_data["html_url"], pr_data["number"]

        return None, None

    def _build_pr_body(self, fix_attempt: FixAttempt) -> str:
        """Build PR description."""
        a = fix_attempt.error_analysis
        return f"""## 🔧 AutoFix: Automated Error Fix

| Field | Value |
|-------|-------|
| **Error** | `{a.error_type}` |
| **Message** | {a.error_message[:100]} |
| **File** | `{a.file_path}` |
| **Confidence** | {a.confidence:.0%} |

### Root Cause
{a.root_cause}

### Changes
{chr(10).join(f"- `{f.file_path}`: {f.explanation}" for f in fix_attempt.proposed_fixes)}

---
🤖 *Generated by AutoFix Agent*
"""

    async def _merge_pr(self, pr_number: int, user_name: str) -> bool:
        """Merge a PR to deploy the fix."""
        async with httpx.AsyncClient() as client:
            headers = {
                "Authorization": f"Bearer {self.config.github_token}",
                "Accept": "application/vnd.github.v3+json",
            }

            merge_resp = await client.put(
                f"https://api.github.com/repos/{self.config.github_repo}/pulls/{pr_number}/merge",
                headers=headers,
                json={
                    "commit_title": f"[AutoFix] Deploy fix (approved by {user_name})",
                    "merge_method": "squash",
                },
                timeout=30.0,
            )

            if merge_resp.status_code == 200:
                return True
            else:
                logger.error(f"Failed to merge PR #{pr_number}: {merge_resp.status_code} - {merge_resp.text}")
                return False

    # -------------------------------------------------------------------------
    # Slack Integration
    # -------------------------------------------------------------------------

    async def _send_slack_notification(self, fix_attempt: FixAttempt) -> None:
        """Send CTO-analyzed fix proposal to Slack."""
        if not fix_attempt.error_analysis:
            return

        analysis = fix_attempt.error_analysis

        # Header changes based on whether PR was created
        if fix_attempt.pr_url:
            header_text = "🔧 AutoFix: CTO Review Complete - Ready to Deploy"
        elif fix_attempt.status == FixStatus.FAILED:
            header_text = "⚠️ AutoFix: Analysis Failed"
        elif not analysis.can_auto_fix:
            header_text = "🔍 AutoFix: Manual Review Required"
        else:
            header_text = "🔧 AutoFix: Error Detected"

        # Security/risk emoji indicators
        security_emoji = {"none": "✅", "low": "🟡", "medium": "🟠", "high": "🔴"}.get(analysis.security_implications, "❓")
        complexity_emoji = {"minimal": "🟢", "simple": "🟢", "standard": "🟡", "complex": "🔴"}.get(analysis.complexity, "❓")

        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": header_text, "emoji": True}},
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Error:*\n`{analysis.error_type}`"},
                    {"type": "mrkdwn", "text": f"*File:*\n`{analysis.file_path}:{analysis.line_number or '?'}`"},
                ],
            },
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*Message:*\n```{analysis.error_message[:300]}```"}},
            {"type": "divider"},
            # CTO Analysis section
            {"type": "section", "text": {"type": "mrkdwn", "text": "*📊 CTO Analysis*"}},
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Complexity:*\n{complexity_emoji} {analysis.complexity.title()}"},
                    {"type": "mrkdwn", "text": f"*Security:*\n{security_emoji} {analysis.security_implications.title()}"},
                    {"type": "mrkdwn", "text": f"*Blast Radius:*\n{analysis.blast_radius.title()}"},
                    {"type": "mrkdwn", "text": f"*Confidence:*\n{analysis.confidence:.0%}"},
                ],
            },
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*🔍 Root Cause:*\n{analysis.root_cause}"}},
        ]

        # Add CTO recommendation if present
        if analysis.recommendation:
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*💡 CTO Recommendation:*\n{analysis.recommendation}"},
            })

        # Add PR link if created
        if fix_attempt.pr_url:
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*📋 Pull Request:* <{fix_attempt.pr_url}|PR #{fix_attempt.pr_number}>"},
            })

        # Add fixes
        for fix in fix_attempt.proposed_fixes:
            blocks.extend([
                {"type": "divider"},
                {"type": "section", "text": {"type": "mrkdwn", "text": f"*📝 Fix:* {fix.explanation}"}},
                {"type": "section", "text": {"type": "mrkdwn", "text": f"```diff\n- {fix.original_code[:300]}\n+ {fix.fixed_code[:300]}```"}},
            ])

        # Add deploy buttons if PR is ready
        if fix_attempt.status == FixStatus.AWAITING_APPROVAL and fix_attempt.pr_url:
            blocks.append({
                "type": "actions",
                "elements": [
                    {"type": "button", "text": {"type": "plain_text", "text": "🚀 Deploy Live", "emoji": True}, "style": "primary", "action_id": "autofix_approve", "value": fix_attempt.id},
                    {"type": "button", "text": {"type": "plain_text", "text": "❌ Dismiss", "emoji": True}, "style": "danger", "action_id": "autofix_reject", "value": fix_attempt.id},
                ],
            })
        elif fix_attempt.status == FixStatus.FAILED:
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*❌ Error:* {fix_attempt.failure_reason}"},
            })

        async with httpx.AsyncClient() as client:
            await client.post(
                self.config.slack_webhook_url,
                json={"blocks": blocks, "text": f"AutoFix: {analysis.error_type}"},
                timeout=10.0,
            )

    async def _send_slack_result(self, fix_attempt: FixAttempt, response_url: Optional[str]) -> None:
        """Send result notification to Slack."""
        if fix_attempt.status == FixStatus.DEPLOYED:
            text = f"🚀 *Deployed!* PR #{fix_attempt.pr_number} merged and deploying now. <{fix_attempt.pr_url}|View PR>"
        elif fix_attempt.status == FixStatus.REJECTED:
            text = f"❌ *Dismissed* - PR remains open: <{fix_attempt.pr_url}|PR #{fix_attempt.pr_number}>"
        elif fix_attempt.status == FixStatus.FAILED:
            text = f"⚠️ *Failed:* {fix_attempt.failure_reason}"
        else:
            text = f"✅ *PR Ready:* <{fix_attempt.pr_url}|View PR #{fix_attempt.pr_number}>"

        url = response_url or self.config.slack_webhook_url
        async with httpx.AsyncClient() as client:
            await client.post(url, json={"text": text, "replace_original": "true"}, timeout=10.0)

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------

    def _check_rate_limit(self) -> bool:
        """Check rate limits."""
        cutoff = datetime.utcnow() - timedelta(hours=1)
        self._rate_limit_tracker = {k: v for k, v in self._rate_limit_tracker.items() if v > cutoff}
        return len(self._rate_limit_tracker) < self.config.max_attempts_per_hour

    def _record_attempt(self, attempt_id: str) -> None:
        """Record attempt for rate limiting."""
        self._rate_limit_tracker[attempt_id] = datetime.utcnow()

    def _verify_slack_signature(self, body: bytes, timestamp: str, signature: str) -> bool:
        """Verify Slack request signature."""
        if abs(time.time() - int(timestamp)) > 300:
            return False
        sig_base = f"v0:{timestamp}:{body.decode()}"
        expected = "v0=" + hmac.new(self.config.slack_signing_secret.encode(), sig_base.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature)

    def _parse_sentry_payload(self, payload: dict[str, Any]) -> Optional[SentryEventData]:
        """Parse Sentry webhook payload."""
        try:
            data = payload.get("data", {})
            event = data.get("event", {}) or {}

            if not event:
                issue = data.get("issue", {})
                if issue:
                    event = {
                        "event_id": str(issue.get("id", "unknown")),
                        "project": issue.get("project", {}).get("slug", ""),
                        "message": issue.get("title", ""),
                        "culprit": issue.get("culprit", ""),
                        "level": issue.get("level", "error"),
                    }

            if not event.get("event_id"):
                return None

            # Extract exception info
            exc_type = exc_value = file_path = func_name = context = None
            line_num = None
            pre_ctx: list[str] = []
            post_ctx: list[str] = []
            frames: list[dict] = []

            exc_data = event.get("exception", {})
            if exc_data and "values" in exc_data:
                exc = exc_data["values"][0] if exc_data["values"] else {}
                exc_type = exc.get("type")
                exc_value = exc.get("value")

                st = exc.get("stacktrace", {})
                all_frames = st.get("frames", [])
                relevant = [f for f in all_frames if f.get("in_app") or "app/" in f.get("filename", "")]

                if relevant:
                    top = relevant[-1]
                    file_path = top.get("filename")
                    line_num = top.get("lineno")
                    func_name = top.get("function")
                    context = top.get("context_line")
                    pre_ctx = top.get("pre_context", [])
                    post_ctx = top.get("post_context", [])

                frames = [{"filename": f.get("filename"), "lineno": f.get("lineno"), "function": f.get("function")} for f in all_frames[-10:]]

            return SentryEventData(
                event_id=str(event.get("event_id")),
                project=event.get("project", ""),
                message=event.get("message"),
                culprit=event.get("culprit"),
                level=event.get("level", "error"),
                exception_type=exc_type,
                exception_value=exc_value,
                file_path=file_path,
                line_number=line_num,
                function_name=func_name,
                stack_frames=frames,
                context_lines=context,
                pre_context=pre_ctx,
                post_context=post_ctx,
            )
        except Exception as e:
            logger.warning(f"Failed to parse Sentry payload: {e}")
            return None

    def _parse_analysis(self, response: str, event_data: SentryEventData) -> ErrorAnalysis:
        """Parse Claude's CTO analysis response."""
        try:
            match = re.search(r"\{[\s\S]*\}", response)
            if match:
                data = json.loads(match.group(0))
                return ErrorAnalysis(
                    error_type=data.get("error_type", event_data.exception_type or "Unknown"),
                    error_message=data.get("error_message", event_data.exception_value or ""),
                    root_cause=data.get("root_cause", "Unknown"),
                    file_path=data.get("file_path", event_data.file_path or ""),
                    line_number=data.get("line_number"),
                    function_name=data.get("function_name"),
                    confidence=float(data.get("confidence", 0.5)),
                    can_auto_fix=data.get("can_auto_fix", False),
                    explanation=data.get("explanation", ""),
                    # CTO/Orchestrator fields
                    complexity=data.get("complexity", "simple"),
                    security_implications=data.get("security_implications", "none"),
                    blast_radius=data.get("blast_radius", "isolated"),
                    recommendation=data.get("recommendation"),
                )
        except Exception as e:
            logger.warning(f"Failed to parse analysis: {e}")

        return ErrorAnalysis(
            error_type=event_data.exception_type or "Unknown",
            error_message=event_data.exception_value or "",
            root_cause="Analysis failed",
            file_path=event_data.file_path or "",
            confidence=0.0,
            can_auto_fix=False,
            explanation="Failed to analyze",
            complexity="unknown",
            security_implications="unknown",
            blast_radius="unknown",
        )

    def _parse_fixes(self, response: str) -> list[ProposedFix]:
        """Parse Claude's fix response."""
        fixes = []
        try:
            match = re.search(r"\{[\s\S]*\}", response)
            if match:
                data = json.loads(match.group(0))
                for f in data.get("fixes", []):
                    fixes.append(ProposedFix(
                        file_path=f["file_path"],
                        original_code=f["original_code"],
                        fixed_code=f["fixed_code"],
                        explanation=f["explanation"],
                        confidence=float(f.get("confidence", 0.8)),
                    ))
        except Exception as e:
            logger.warning(f"Failed to parse fixes: {e}")
        return fixes
