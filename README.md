# AutoFix Agent

A pip-installable package that adds Claude-powered error monitoring and auto-fixing to your FastAPI app. Errors get analyzed, fixes proposed via Slack, and PRs created on approval - all within your existing deployment.

## Installation

```bash
pip install git+https://github.com/uwskiguy/autofix-agent.git
```

## Quick Start

Add 3 lines to your FastAPI app:

```python
from fastapi import FastAPI
from autofix_agent import AutoFixAgent

app = FastAPI()

# Initialize AutoFix with your credentials
autofix = AutoFixAgent(
    anthropic_api_key="sk-ant-...",
    github_token="ghp_...",
    github_repo="owner/repo",
    slack_webhook_url="https://hooks.slack.com/services/...",
    github_path="backend/",  # Optional: subfolder where your code lives
)

# Mount the routes
autofix.mount(app)  # Adds /autofix/* endpoints
```

That's it! Your app now has error monitoring at:
- `POST /autofix/webhooks/sentry` - Receives Sentry webhooks
- `POST /autofix/slack/interact` - Handles Slack button clicks
- `GET /autofix/status` - Check status
- `GET /autofix/attempts` - List recent fix attempts

## How It Works

```
[Sentry Error] → [Your App] → [Claude Analysis] → [Slack Notification]
                                                          ↓
                                                  [You Click "Approve"]
                                                          ↓
                                                  [GitHub PR Created]
```

1. **Error occurs** → Sentry sends webhook to your app
2. **Claude analyzes** → Identifies root cause, generates fix
3. **Slack notification** → You see the error + proposed fix
4. **You approve** → Click "Authorize Fix" button
5. **PR created** → Fix applied to a branch, PR opened for review

## Configuration

### Using Environment Variables

```python
import os
from autofix_agent import AutoFixAgent

autofix = AutoFixAgent(
    anthropic_api_key=os.environ["ANTHROPIC_API_KEY"],
    github_token=os.environ["GITHUB_TOKEN"],
    github_repo=os.environ.get("GITHUB_REPO", "owner/repo"),
    slack_webhook_url=os.environ["SLACK_WEBHOOK_URL"],

    # Optional settings
    github_path="backend/",           # Subfolder in repo
    slack_channel="#errors",          # Slack channel
    min_confidence=0.8,               # Min confidence to propose fix (0-1)
    max_attempts_per_hour=10,         # Rate limit
)
```

### Required Environment Variables

| Variable | Description |
|----------|-------------|
| `ANTHROPIC_API_KEY` | Anthropic API key for Claude |
| `GITHUB_TOKEN` | GitHub PAT with `repo` scope |
| `SLACK_WEBHOOK_URL` | Slack incoming webhook URL |

### Optional Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GITHUB_REPO` | - | Repository in `owner/repo` format |
| `GITHUB_PATH` | `""` | Subfolder where code lives |
| `MIN_CONFIDENCE` | `0.8` | Minimum confidence threshold |

## Setup Instructions

### 1. Create Slack App

1. Go to https://api.slack.com/apps
2. Create New App → From scratch
3. **Incoming Webhooks**: Enable and create a webhook for your channel
4. **Interactivity**: Enable and set Request URL to:
   ```
   https://your-app.railway.app/autofix/slack/interact
   ```
5. Copy the webhook URL and signing secret

### 2. Create GitHub Token

1. Go to https://github.com/settings/tokens
2. Generate new token (classic)
3. Select scope: `repo` (full control)
4. Copy the token

### 3. Configure Sentry Webhook

1. In Sentry, go to **Settings → Integrations → Webhooks**
2. Add webhook URL:
   ```
   https://your-app.railway.app/autofix/webhooks/sentry
   ```
3. Enable for: **Issue Created**, **Error**

### 4. Get Anthropic API Key

1. Go to https://console.anthropic.com/settings/keys
2. Create a new API key

## Example: JunkGems Integration

```python
# backend/app/main.py
from fastapi import FastAPI
from autofix_agent import AutoFixAgent

from app.config import settings

app = FastAPI(title="JunkGems")

# Initialize AutoFix
autofix = AutoFixAgent(
    anthropic_api_key=settings.anthropic_api_key,
    github_token=settings.github_token,
    github_repo="bensharpe/JunkGems",
    github_path="backend/",
    slack_webhook_url=settings.slack_webhook_url,
)

autofix.mount(app, prefix="/autofix")

# ... rest of your app
```

## What Gets Fixed?

**Auto-fixable errors:**
- Typos in variable/function names
- Missing null/None checks
- Wrong variable references
- Missing imports
- Simple logic errors
- Off-by-one errors

**Not auto-fixed (sent to Slack for visibility only):**
- Architectural issues
- Security-sensitive code
- Database schema problems
- External API changes
- Missing features

## API Reference

### `AutoFixAgent`

```python
AutoFixAgent(
    anthropic_api_key: str,      # Required
    github_token: str,           # Required
    github_repo: str,            # Required (owner/repo format)
    slack_webhook_url: str,      # Required
    github_path: str = "",       # Optional subfolder
    slack_channel: str = None,   # Optional channel override
    min_confidence: float = 0.8, # Minimum confidence (0-1)
    max_attempts_per_hour: int = 10,
)
```

### `autofix.mount(app, prefix="/autofix")`

Mounts the following routes:
- `POST {prefix}/webhooks/sentry` - Sentry webhook receiver
- `POST {prefix}/slack/interact` - Slack interaction handler
- `GET {prefix}/status` - Service status
- `GET {prefix}/attempts` - List fix attempts
- `GET {prefix}/attempts/{id}` - Get specific attempt

## License

MIT
