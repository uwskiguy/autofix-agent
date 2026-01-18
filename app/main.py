"""AutoFix Agent - Main FastAPI Application."""

import hashlib
import hmac
import json
import logging
import urllib.parse
from typing import Any, Optional

from fastapi import (
    BackgroundTasks,
    FastAPI,
    Header,
    HTTPException,
    Request,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app import __version__
from app.config import settings
from app.schemas import FixAttempt, FixStatus, ProjectConfig, SentryEventData
from app.services.fix_orchestrator import fix_orchestrator
from app.services.slack_service import slack_service

# Configure logging
logging.basicConfig(
    level=logging.DEBUG if settings.debug else logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="AutoFix Agent",
    description="Claude-powered error monitoring and auto-fixing service",
    version=__version__,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory project configs (load from config file in production)
_project_configs: dict[str, ProjectConfig] = {}


def _load_project_configs():
    """Load project configurations from YAML file."""
    import yaml

    config_path = settings.projects_config_path
    if config_path.exists():
        with open(config_path) as f:
            data = yaml.safe_load(f)
            for project in data.get("projects", []):
                config = ProjectConfig(**project)
                _project_configs[config.sentry_project or config.name] = config
                logger.info(f"Loaded project config: {config.name}")


# Response models
class WebhookResponse(BaseModel):
    received: bool = True
    fix_attempt_id: Optional[str] = None
    message: str


class StatusResponse(BaseModel):
    status: str
    version: str
    projects_configured: int


# Startup event
@app.on_event("startup")
async def startup():
    """Initialize on startup."""
    logger.info(f"Starting AutoFix Agent v{__version__}")
    _load_project_configs()
    logger.info(f"Loaded {len(_project_configs)} project configurations")


# Health check
@app.get("/", tags=["Health"])
async def root():
    """Root endpoint - health check."""
    return {"status": "ok", "service": "autofix-agent", "version": __version__}


@app.get("/api/v1/status", response_model=StatusResponse, tags=["Health"])
async def get_status():
    """Get service status."""
    return StatusResponse(
        status="healthy",
        version=__version__,
        projects_configured=len(_project_configs),
    )


# Sentry webhook
@app.post(
    "/api/v1/webhooks/sentry",
    response_model=WebhookResponse,
    tags=["Webhooks"],
)
async def receive_sentry_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    sentry_hook_signature: Optional[str] = Header(None, alias="Sentry-Hook-Signature"),
):
    """
    Receive Sentry webhook and trigger auto-fix analysis.

    The analysis runs in the background - this endpoint returns immediately.
    """
    body = await request.body()

    # Verify signature if configured
    if settings.sentry_webhook_secret:
        if not sentry_hook_signature:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing webhook signature",
            )
        expected = hmac.new(
            settings.sentry_webhook_secret.encode(),
            body,
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(sentry_hook_signature, expected):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid webhook signature",
            )

    # Parse payload
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid JSON payload",
        )

    # Extract action
    action = payload.get("action", "")
    if action not in ["created", "triggered", "resolved"]:
        return WebhookResponse(message=f"Ignored action: {action}")

    # Parse event data
    event_data = _parse_sentry_payload(payload)
    if not event_data:
        return WebhookResponse(message="Could not parse event data")

    # Find project config
    project_name = event_data.project
    project_config = _project_configs.get(project_name)

    if not project_config:
        logger.warning(f"No project config found for: {project_name}")
        # Still process but without GitHub integration
        project_config = None

    logger.info(
        f"Received Sentry webhook for {event_data.event_id}",
        extra={
            "event_id": event_data.event_id,
            "project": event_data.project,
            "exception_type": event_data.exception_type,
        },
    )

    # Process in background
    background_tasks.add_task(
        _process_error_async,
        event_data,
        project_config,
    )

    return WebhookResponse(
        fix_attempt_id=event_data.event_id,
        message="Processing started",
    )


async def _process_error_async(
    event_data: SentryEventData,
    project_config: Optional[ProjectConfig],
):
    """Background task to process error."""
    try:
        await fix_orchestrator.process_sentry_error(event_data, project_config)
    except Exception as e:
        logger.exception(f"Error processing Sentry event: {e}")


def _parse_sentry_payload(payload: dict[str, Any]) -> Optional[SentryEventData]:
    """Parse Sentry webhook payload into SentryEventData."""
    try:
        data = payload.get("data", {})
        event = data.get("event", {})

        if not event:
            # Try issue format
            issue = data.get("issue", {})
            if issue:
                event = {
                    "event_id": str(issue.get("id", "unknown")),
                    "project": issue.get("project", {}).get("slug", ""),
                    "message": issue.get("title", ""),
                    "culprit": issue.get("culprit", ""),
                    "level": issue.get("level", "error"),
                    "platform": issue.get("platform"),
                }

        if not event.get("event_id"):
            return None

        # Extract exception info
        exception_type = None
        exception_value = None
        file_path = None
        line_number = None
        function_name = None
        stack_frames = []
        context_lines = None
        pre_context = []
        post_context = []

        exception_data = event.get("exception", {})
        if exception_data and "values" in exception_data:
            exc_values = exception_data["values"]
            if exc_values:
                exc = exc_values[0]
                exception_type = exc.get("type")
                exception_value = exc.get("value")

                stacktrace = exc.get("stacktrace", {})
                frames = stacktrace.get("frames", [])

                if frames:
                    # Get relevant frames (in-app or app/ path)
                    relevant_frames = [
                        f for f in frames
                        if f.get("in_app") or "app/" in f.get("filename", "")
                    ]

                    if relevant_frames:
                        top_frame = relevant_frames[-1]
                        file_path = top_frame.get("filename")
                        line_number = top_frame.get("lineno")
                        function_name = top_frame.get("function")
                        context_lines = top_frame.get("context_line")
                        pre_context = top_frame.get("pre_context", [])
                        post_context = top_frame.get("post_context", [])

                    stack_frames = [
                        {
                            "filename": f.get("filename"),
                            "lineno": f.get("lineno"),
                            "function": f.get("function"),
                            "context_line": f.get("context_line"),
                        }
                        for f in frames[-15:]
                    ]

        return SentryEventData(
            event_id=str(event.get("event_id", "unknown")),
            project=event.get("project", ""),
            message=event.get("message") or event.get("title"),
            culprit=event.get("culprit"),
            level=event.get("level", "error"),
            platform=event.get("platform"),
            exception_type=exception_type,
            exception_value=exception_value,
            file_path=file_path,
            line_number=line_number,
            function_name=function_name,
            stack_frames=stack_frames,
            context_lines=context_lines,
            pre_context=pre_context or [],
            post_context=post_context or [],
        )

    except Exception as e:
        logger.warning(f"Failed to parse Sentry payload: {e}")
        return None


# Slack interaction handler
@app.post("/api/v1/slack/interact", tags=["Slack"])
async def handle_slack_interaction(
    request: Request,
    x_slack_signature: Optional[str] = Header(None, alias="X-Slack-Signature"),
    x_slack_request_timestamp: Optional[str] = Header(
        None, alias="X-Slack-Request-Timestamp"
    ),
):
    """
    Handle Slack interactive component callbacks (button clicks).
    """
    body = await request.body()

    # Verify Slack signature
    if settings.slack_signing_secret and x_slack_signature and x_slack_request_timestamp:
        if not slack_service.verify_signature(
            body, x_slack_request_timestamp, x_slack_signature
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Slack signature",
            )

    # Parse payload (URL-encoded form data)
    body_str = body.decode()
    parsed = urllib.parse.parse_qs(body_str)
    payload_str = parsed.get("payload", [""])[0]

    if not payload_str:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing payload",
        )

    try:
        payload = json.loads(payload_str)
    except json.JSONDecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid JSON in payload",
        )

    # Extract interaction data
    interaction_type = payload.get("type")
    if interaction_type != "block_actions":
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

    logger.info(
        f"Slack interaction: {action_id} for {attempt_id} by {user_name}"
    )

    try:
        if action_id == "autofix_approve":
            await fix_orchestrator.approve_fix(attempt_id, user_name, response_url)
        elif action_id == "autofix_reject":
            await fix_orchestrator.reject_fix(attempt_id, user_name, response_url)
    except ValueError as e:
        logger.error(f"Error handling Slack interaction: {e}")

    return {"ok": True}


# Fix attempts API
@app.get(
    "/api/v1/attempts",
    response_model=list[FixAttempt],
    tags=["Attempts"],
)
async def list_fix_attempts(limit: int = 20):
    """List recent fix attempts."""
    return fix_orchestrator.get_recent_attempts(limit)


@app.get(
    "/api/v1/attempts/{attempt_id}",
    response_model=FixAttempt,
    tags=["Attempts"],
)
async def get_fix_attempt(attempt_id: str):
    """Get a specific fix attempt."""
    attempt = fix_orchestrator.get_fix_attempt(attempt_id)
    if not attempt:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Fix attempt {attempt_id} not found",
        )
    return attempt


# Projects API
@app.get("/api/v1/projects", tags=["Projects"])
async def list_projects():
    """List configured projects."""
    return list(_project_configs.values())


@app.post("/api/v1/projects", tags=["Projects"])
async def add_project(project: ProjectConfig):
    """Add a project configuration."""
    _project_configs[project.sentry_project or project.name] = project
    return {"status": "added", "project": project.name}
