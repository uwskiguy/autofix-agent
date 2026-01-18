# AutoFix Agent

Claude-powered error monitoring and auto-fixing for FastAPI apps. Works standalone or as a **runtime companion to Orchestrator**.

## How It Works

```
Production Error → Sentry → AutoFix → Claude (CTO) Analysis → PR Created → Slack
                                                                              ↓
                                                              [🚀 Deploy Live] → Merge → Deploy
```

1. **Error occurs** in production
2. **Sentry captures** and sends webhook to AutoFix
3. **Claude analyzes** as CTO (complexity, security, blast radius)
4. **PR created** automatically with the fix
5. **Slack notification** with "Deploy Live" button
6. **You approve** → PR merges → Auto-deploy via Railway/Vercel/etc.

## Installation

```bash
pip install git+https://github.com/uwskiguy/autofix-agent.git
```

## Quick Start

```python
from fastapi import FastAPI
from autofix_agent import AutoFixAgent

app = FastAPI()

autofix = AutoFixAgent(
    anthropic_api_key="sk-ant-...",
    github_token="github_pat_...",
    github_repo="owner/repo",
    github_path="backend/",  # Optional: subfolder containing code
    slack_webhook_url="https://hooks.slack.com/...",
)

autofix.mount(app, prefix="/api/v1/autofix")
```

## CTO Analysis Mode

AutoFix uses Claude as a CTO to analyze every error with Orchestrator-style analysis:

| Analysis | Description |
|----------|-------------|
| **Complexity** | minimal, simple, standard, complex |
| **Security** | none, low, medium, high |
| **Blast Radius** | isolated, moderate, wide |
| **Confidence** | 0-100% |

### Auto-Fix Criteria

Auto-fix is **enabled** when ALL conditions are met:
- Complexity is minimal or simple
- Security implications are none or low
- Confidence is ≥80%
- Single file change
- Fix is isolated (won't affect other code paths)

Auto-fix is **blocked** for:
- Security-sensitive code (auth, tokens, encryption, validation)
- Database queries or migrations
- External API integrations
- Business logic requiring product knowledge
- Multi-file changes
- Complex issues that could mask deeper problems

Blocked issues appear in Slack as "🔍 Manual Review Required" with full CTO analysis.

## Slack Notifications

### Fix Ready to Deploy
```
🔧 AutoFix: CTO Review Complete - Ready to Deploy

Error: TypeError
File: app/api/v1/router.py:55

📊 CTO Analysis
Complexity: 🟢 Minimal    Security: ✅ None
Blast Radius: Isolated    Confidence: 95%

🔍 Root Cause: [detailed explanation]

💡 CTO Recommendation: [advice for reviewer]

📋 Pull Request: PR #1

[🚀 Deploy Live]  [❌ Dismiss]
```

### Manual Review Required
```
🔍 AutoFix: Manual Review Required

📊 CTO Analysis
Complexity: 🔴 Complex    Security: 🟠 Medium
...

💡 CTO Recommendation: This requires human review because...
```

## Configuration

### Environment Variables

```bash
ANTHROPIC_API_KEY=sk-ant-...          # Claude API key
AUTOFIX_GITHUB_TOKEN=github_pat_...   # GitHub PAT with repo scope
AUTOFIX_SLACK_WEBHOOK_URL=https://... # Slack incoming webhook
SENTRY_WEBHOOK_SECRET=...             # Optional: verify Sentry webhooks
```

### Sentry Webhook

Configure Sentry to send webhooks to:
```
https://your-app.com/api/v1/autofix/webhooks/sentry
```

Events to enable: `issue.created`

### Slack Interactivity

For the "Deploy Live" button to work, configure Slack interactivity:
```
https://your-app.com/api/v1/autofix/slack/interact
```

## Integration with Orchestrator

AutoFix is designed to work with the [Orchestrator framework](https://github.com/uwskiguy/orchestrator). When both are used:

- **Development time**: Orchestrator coordinates agents for implementation
- **Runtime**: AutoFix monitors and fixes production errors
- **Shared philosophy**: Both use the same CTO analysis criteria

Configuration in `.orchestrator/autofix.yaml`:

```yaml
autofix:
  enabled: true
  github:
    repo: "owner/repo"
    path: "backend/"
  cto_analysis:
    min_confidence: 0.8
    blocked_categories:
      - security
      - database
      - payments
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/autofix/status` | GET | Health check and status |
| `/autofix/webhooks/sentry` | POST | Receive Sentry webhooks |
| `/autofix/slack/interact` | POST | Handle Slack button clicks |
| `/autofix/attempts` | GET | List recent fix attempts |
| `/autofix/attempts/{id}` | GET | Get specific attempt details |

## Setup Instructions

### 1. Create Slack App

1. Go to https://api.slack.com/apps
2. Create New App → From scratch
3. **Incoming Webhooks**: Enable and create a webhook for your channel
4. **Interactivity**: Enable and set Request URL to:
   ```
   https://your-app.com/api/v1/autofix/slack/interact
   ```
5. Copy the webhook URL

### 2. Create GitHub Token

1. Go to https://github.com/settings/tokens
2. **Fine-grained token** (recommended):
   - Repository access: Select your repo
   - Permissions: Contents (Read/Write), Pull requests (Read/Write)
3. Or **Classic token** with `repo` scope
4. Copy the token

### 3. Configure Sentry Webhook

1. In Sentry, go to **Settings → Integrations → Webhooks**
2. Add webhook URL:
   ```
   https://your-app.com/api/v1/autofix/webhooks/sentry
   ```
3. Enable events: `issue.created`
4. Copy the webhook secret (optional but recommended)

### 4. Get Anthropic API Key

1. Go to https://console.anthropic.com/settings/keys
2. Create a new API key

### 5. Set Environment Variables

For Railway:
```bash
railway variables --set "ANTHROPIC_API_KEY=sk-ant-..."
railway variables --set "AUTOFIX_GITHUB_TOKEN=github_pat_..."
railway variables --set "AUTOFIX_SLACK_WEBHOOK_URL=https://hooks.slack.com/..."
railway variables --set "SENTRY_WEBHOOK_SECRET=..."
```

## API Reference

### `AutoFixAgent`

```python
AutoFixAgent(
    anthropic_api_key: str,           # Required: Anthropic API key
    github_token: str,                # Required: GitHub PAT
    github_repo: str,                 # Required: owner/repo format
    slack_webhook_url: str,           # Required: Slack webhook URL
    github_path: str = "",            # Optional: subfolder in repo
    slack_channel: str = None,        # Optional: channel override
    slack_signing_secret: str = None, # Optional: verify Slack requests
    sentry_webhook_secret: str = None,# Optional: verify Sentry webhooks
    min_confidence: float = 0.8,      # Minimum confidence (0-1)
    max_attempts_per_hour: int = 10,  # Rate limit
)
```

### `autofix.mount(app, prefix="/autofix")`

Mounts routes onto your FastAPI app:
- `POST {prefix}/webhooks/sentry` - Sentry webhook receiver
- `POST {prefix}/slack/interact` - Slack interaction handler
- `GET {prefix}/status` - Service status
- `GET {prefix}/attempts` - List fix attempts
- `GET {prefix}/attempts/{id}` - Get specific attempt

## License

MIT
