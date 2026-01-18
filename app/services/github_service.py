"""GitHub integration service for reading code and creating PRs."""

import base64
import logging
from typing import Optional

import httpx

from app.config import settings
from app.schemas import ErrorAnalysis, FixAttempt, ProposedFix

logger = logging.getLogger(__name__)


class GitHubService:
    """Service for GitHub API operations."""

    def __init__(self):
        self.token = settings.github_token
        self.base_url = "https://api.github.com"

    def _headers(self) -> dict:
        """Get headers for GitHub API requests."""
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github.v3+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    async def get_file_content(
        self,
        repo: str,
        file_path: str,
        ref: str = "main",
    ) -> Optional[str]:
        """
        Get the content of a file from GitHub.

        Args:
            repo: Repository in owner/repo format
            file_path: Path to file in the repository
            ref: Branch or commit SHA

        Returns:
            File content as string, or None if not found
        """
        # Clean up file path
        clean_path = file_path.lstrip("/")

        url = f"{self.base_url}/repos/{repo}/contents/{clean_path}"

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    url,
                    headers={
                        **self._headers(),
                        "Accept": "application/vnd.github.v3.raw",
                    },
                    params={"ref": ref},
                    timeout=30.0,
                )

                if response.status_code == 200:
                    return response.text
                elif response.status_code == 404:
                    logger.warning(f"File not found: {repo}/{clean_path}")
                else:
                    logger.error(f"GitHub API error: {response.status_code} - {response.text}")

        except Exception as e:
            logger.exception(f"Failed to get file from GitHub: {e}")

        return None

    async def create_fix_pr(
        self,
        fix_attempt: FixAttempt,
    ) -> tuple[Optional[str], Optional[int]]:
        """
        Create a GitHub PR with the proposed fixes.

        Args:
            fix_attempt: Fix attempt with analysis and proposed fixes

        Returns:
            Tuple of (pr_url, pr_number) or (None, None) on failure
        """
        if not fix_attempt.github_repo or not fix_attempt.proposed_fixes:
            return None, None

        repo = fix_attempt.github_repo
        analysis = fix_attempt.error_analysis
        fixes = fix_attempt.proposed_fixes

        # Create unique branch name
        branch_name = f"autofix/{fix_attempt.sentry_event_id[:12]}"

        try:
            async with httpx.AsyncClient() as client:
                # Get default branch
                repo_info = await client.get(
                    f"{self.base_url}/repos/{repo}",
                    headers=self._headers(),
                    timeout=30.0,
                )
                default_branch = repo_info.json().get("default_branch", "main")

                # Get base SHA
                ref_response = await client.get(
                    f"{self.base_url}/repos/{repo}/git/refs/heads/{default_branch}",
                    headers=self._headers(),
                    timeout=30.0,
                )
                base_sha = ref_response.json()["object"]["sha"]

                # Create branch
                create_branch_response = await client.post(
                    f"{self.base_url}/repos/{repo}/git/refs",
                    headers=self._headers(),
                    json={
                        "ref": f"refs/heads/{branch_name}",
                        "sha": base_sha,
                    },
                    timeout=30.0,
                )

                if create_branch_response.status_code not in [200, 201]:
                    logger.error(f"Failed to create branch: {create_branch_response.text}")
                    return None, None

                # Apply each fix
                for fix in fixes:
                    success = await self._apply_fix(client, repo, branch_name, fix)
                    if not success:
                        logger.error(f"Failed to apply fix to {fix.file_path}")
                        # Continue with other fixes

                # Create PR
                pr_title = f"[AutoFix] Fix {analysis.error_type}"
                if analysis.function_name:
                    pr_title += f" in {analysis.function_name}"

                pr_body = self._build_pr_body(fix_attempt)

                pr_response = await client.post(
                    f"{self.base_url}/repos/{repo}/pulls",
                    headers=self._headers(),
                    json={
                        "title": pr_title,
                        "body": pr_body,
                        "head": branch_name,
                        "base": default_branch,
                    },
                    timeout=30.0,
                )

                if pr_response.status_code == 201:
                    pr_data = pr_response.json()
                    return pr_data["html_url"], pr_data["number"]
                else:
                    logger.error(f"Failed to create PR: {pr_response.text}")

        except Exception as e:
            logger.exception(f"Failed to create fix PR: {e}")

        return None, None

    async def _apply_fix(
        self,
        client: httpx.AsyncClient,
        repo: str,
        branch: str,
        fix: ProposedFix,
    ) -> bool:
        """Apply a single fix to a file."""
        file_path = fix.file_path.lstrip("/")

        try:
            # Get current file content and SHA
            file_response = await client.get(
                f"{self.base_url}/repos/{repo}/contents/{file_path}",
                headers=self._headers(),
                params={"ref": branch},
                timeout=30.0,
            )

            if file_response.status_code != 200:
                logger.error(f"File not found: {file_path}")
                return False

            file_data = file_response.json()
            file_sha = file_data["sha"]

            # Decode current content
            current_content = base64.b64decode(file_data["content"]).decode("utf-8")

            # Apply the fix
            if fix.original_code not in current_content:
                logger.warning(f"Original code not found in {file_path}")
                return False

            new_content = current_content.replace(
                fix.original_code, fix.fixed_code, 1
            )

            if new_content == current_content:
                logger.warning(f"No changes made to {file_path}")
                return False

            # Update file
            update_response = await client.put(
                f"{self.base_url}/repos/{repo}/contents/{file_path}",
                headers=self._headers(),
                json={
                    "message": f"fix: {fix.explanation[:50]}",
                    "content": base64.b64encode(new_content.encode()).decode(),
                    "sha": file_sha,
                    "branch": branch,
                },
                timeout=30.0,
            )

            return update_response.status_code == 200

        except Exception as e:
            logger.exception(f"Failed to apply fix to {file_path}: {e}")
            return False

    def _build_pr_body(self, fix_attempt: FixAttempt) -> str:
        """Build the PR description."""
        analysis = fix_attempt.error_analysis
        fixes = fix_attempt.proposed_fixes

        body = f"""## 🔧 AutoFix: Automated Error Fix

This PR was automatically generated by the AutoFix Agent after detecting an error in Sentry.

### Error Details

| Field | Value |
|-------|-------|
| **Type** | `{analysis.error_type}` |
| **Message** | {analysis.error_message[:200]} |
| **File** | `{analysis.file_path}` |
| **Line** | {analysis.line_number or 'N/A'} |
| **Function** | `{analysis.function_name or 'N/A'}` |
| **Confidence** | {analysis.confidence:.0%} |

### Root Cause Analysis

{analysis.root_cause}

### Changes Made

"""

        for i, fix in enumerate(fixes, 1):
            body += f"""
#### Fix {i}: `{fix.file_path}`

**Explanation:** {fix.explanation}

```diff
- {fix.original_code}
+ {fix.fixed_code}
```

"""

        body += f"""
### Review Checklist

- [ ] The fix addresses the root cause
- [ ] No unintended side effects
- [ ] Tests pass (if applicable)
- [ ] Code follows project conventions

---

**Sentry Event ID:** `{fix_attempt.sentry_event_id}`

🤖 *Generated by [AutoFix Agent](https://github.com/bensharpe/autofix-agent)*
"""

        return body


# Singleton
github_service = GitHubService()
