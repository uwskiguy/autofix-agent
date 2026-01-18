# AutoFix Agent

A standalone, reusable service that monitors Sentry errors and uses Claude AI to analyze, propose fixes, and create GitHub PRs - with human approval via Slack.

## Features

- **Sentry Integration**: Receives error webhooks from any Sentry project
- **Claude-Powered Analysis**: Uses Claude to understand errors and propose fixes
- **Slack Notifications**: Sends error analysis with proposed fix to Slack
- **Human-in-the-Loop**: Requires approval before creating PRs
- **Multi-Project Support**: Can monitor multiple repos/projects simultaneously

## Architecture

```
[Sentry] → [AutoFix Agent] → [Claude API] → [Slack Notification]
                                                    ↓
                                            [User Approves]
                                                    ↓
                                            [GitHub PR Created]
```

## Quick Start

### 1. Clone and Setup

```bash
git clone https://github.com/bensharpe/autofix-agent.git
cd autofix-agent
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env with your credentials
```

Required environment variables:
- `ANTHROPIC_API_KEY` - Claude API key
- `SLACK_WEBHOOK_URL` - Slack incoming webhook
- `SLACK_SIGNING_SECRET` - For verifying Slack interactions
- `GITHUB_TOKEN` - Personal access token with repo permissions
- `SENTRY_WEBHOOK_SECRET` - (Optional) To verify Sentry webhooks

### 3. Run the Service

```bash
# Development
uvicorn app.main:app --reload --port 8080

# Production (Railway, Render, etc.)
gunicorn app.main:app -w 4 -k uvicorn.workers.UvicornWorker
```

### 4. Configure Sentry Webhook

In your Sentry project:
1. Go to **Settings → Integrations → Webhooks**
2. Add webhook URL: `https://your-autofix-agent.com/api/v1/webhooks/sentry`
3. Enable for: **Issue Created**, **Error**

### 5. Configure Slack App

1. Create a Slack app at https://api.slack.com/apps
2. Enable **Incoming Webhooks** and create one
3. Enable **Interactivity** and set Request URL to: `https://your-autofix-agent.com/api/v1/slack/interact`
4. Add the signing secret to your `.env`

## Multi-Project Setup

AutoFix Agent can monitor multiple projects. Configure each project in `config/projects.yaml`:

```yaml
projects:
  - name: junkgems-backend
    github_repo: bensharpe/JunkGems
    github_path: backend/
    sentry_project: junkgems-backend
    slack_channel: "#junkgems-alerts"

  - name: another-project
    github_repo: bensharpe/another-project
    sentry_project: another-project
    slack_channel: "#another-alerts"
```

## How It Works

### 1. Error Detection
When Sentry catches an error, it sends a webhook to AutoFix Agent.

### 2. Analysis
Claude analyzes the error:
- Identifies root cause
- Reads relevant source code from GitHub
- Determines if it can be auto-fixed
- Generates a proposed fix

### 3. Slack Notification
You receive a Slack message with:
- Error type and message
- Root cause analysis
- Proposed code fix (diff format)
- Confidence score
- **"Authorize Fix"** button

### 4. Human Approval
Click **"Authorize Fix"** to create a PR, or **"Dismiss"** to ignore.

### 5. PR Creation
AutoFix Agent creates a branch, applies the fix, and opens a PR with:
- Error details
- Analysis
- Code changes
- Review checklist

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/webhooks/sentry` | POST | Receive Sentry webhooks |
| `/api/v1/slack/interact` | POST | Handle Slack button clicks |
| `/api/v1/status` | GET | Service health check |
| `/api/v1/projects` | GET | List configured projects |

## Deployment

### Railway (Recommended)
```bash
railway init
railway up
```

### Docker
```bash
docker build -t autofix-agent .
docker run -p 8080:8080 --env-file .env autofix-agent
```

## License

MIT
