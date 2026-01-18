"""Claude-powered error analysis service."""

import json
import logging
import re
from typing import Optional

import httpx

from app.config import settings
from app.schemas import ErrorAnalysis, ProposedFix, SentryEventData

logger = logging.getLogger(__name__)


class AnalyzerService:
    """Service for analyzing errors using Claude."""

    def __init__(self):
        self.api_key = settings.anthropic_api_key
        self.min_confidence = settings.min_confidence_threshold

    async def analyze_error(
        self,
        event_data: SentryEventData,
        source_code: str = "",
    ) -> ErrorAnalysis:
        """
        Analyze an error using Claude.

        Args:
            event_data: Parsed Sentry event data
            source_code: Source code of the file where error occurred

        Returns:
            ErrorAnalysis with root cause and fix recommendation
        """
        prompt = self._build_analysis_prompt(event_data, source_code)
        response = await self._call_claude(prompt)
        return self._parse_analysis_response(response, event_data)

    async def generate_fix(
        self,
        analysis: ErrorAnalysis,
        source_code: str,
    ) -> list[ProposedFix]:
        """
        Generate a code fix using Claude.

        Args:
            analysis: Error analysis result
            source_code: Full source code of the file

        Returns:
            List of proposed fixes
        """
        prompt = self._build_fix_prompt(analysis, source_code)
        response = await self._call_claude(prompt)
        return self._parse_fix_response(response)

    def _build_analysis_prompt(
        self,
        event_data: SentryEventData,
        source_code: str,
    ) -> str:
        """Build the analysis prompt for Claude."""
        return f"""Analyze this Python error and determine if it can be automatically fixed.

ERROR DETAILS:
- Type: {event_data.exception_type or 'Unknown'}
- Message: {event_data.exception_value or event_data.message or ''}
- File: {event_data.file_path or 'Unknown'}
- Line: {event_data.line_number or 'Unknown'}
- Function: {event_data.function_name or 'Unknown'}

CONTEXT (code around the error):
Pre-context:
{chr(10).join(event_data.pre_context)}

Error line:
{event_data.context_lines or ''}

Post-context:
{chr(10).join(event_data.post_context)}

STACK TRACE:
{json.dumps(event_data.stack_frames[:10], indent=2)}

FULL SOURCE FILE:
```python
{source_code[:8000] if source_code else 'Not available'}
```

RESPOND WITH JSON ONLY:
{{
    "error_type": "type of error",
    "error_message": "the error message",
    "root_cause": "detailed explanation of what caused this error",
    "file_path": "{event_data.file_path or ''}",
    "line_number": {event_data.line_number or 'null'},
    "function_name": "{event_data.function_name or ''}",
    "confidence": 0.0 to 1.0,
    "can_auto_fix": true/false,
    "explanation": "why this can/cannot be auto-fixed"
}}

RULES FOR can_auto_fix:
- TRUE for: typos, missing null checks, incorrect variable names, missing imports, simple logic errors, off-by-one errors
- FALSE for: architectural issues, requires new features, security-sensitive code, database schema changes, external API changes, missing test coverage
"""

    def _build_fix_prompt(
        self,
        analysis: ErrorAnalysis,
        source_code: str,
    ) -> str:
        """Build the fix generation prompt for Claude."""
        return f"""Generate a fix for this error.

ERROR ANALYSIS:
- Type: {analysis.error_type}
- Message: {analysis.error_message}
- Root Cause: {analysis.root_cause}
- File: {analysis.file_path}
- Line: {analysis.line_number}
- Function: {analysis.function_name}

FULL SOURCE FILE:
```python
{source_code}
```

Generate a minimal, targeted fix. RESPOND WITH JSON ONLY:
{{
    "fixes": [
        {{
            "file_path": "{analysis.file_path}",
            "original_code": "exact code to replace (copy from source, include enough context to be unique)",
            "fixed_code": "the corrected code",
            "explanation": "why this fixes the issue",
            "confidence": 0.0 to 1.0
        }}
    ]
}}

RULES:
1. Make the SMALLEST change that fixes the issue
2. Do NOT refactor or improve other code
3. The original_code must match EXACTLY (including whitespace and indentation)
4. Include enough context in original_code to make it unique in the file
5. Only output valid JSON, no markdown or explanation outside JSON
"""

    async def _call_claude(self, prompt: str) -> str:
        """Call Claude API."""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": self.api_key,
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
                logger.error(f"Claude API error: {response.text}")
                raise Exception(f"Claude API error: {response.status_code}")

            data = response.json()
            return data["content"][0]["text"]

    def _parse_analysis_response(
        self,
        response: str,
        event_data: SentryEventData,
    ) -> ErrorAnalysis:
        """Parse Claude's analysis response."""
        try:
            json_match = re.search(r"\{[\s\S]*\}", response)
            if json_match:
                data = json.loads(json_match.group(0))
                return ErrorAnalysis(
                    error_type=data.get("error_type", event_data.exception_type or "Unknown"),
                    error_message=data.get("error_message", event_data.exception_value or ""),
                    root_cause=data.get("root_cause", "Could not determine"),
                    file_path=data.get("file_path", event_data.file_path or ""),
                    line_number=data.get("line_number"),
                    function_name=data.get("function_name"),
                    confidence=float(data.get("confidence", 0.5)),
                    can_auto_fix=data.get("can_auto_fix", False),
                    explanation=data.get("explanation", ""),
                )
        except Exception as e:
            logger.warning(f"Failed to parse analysis response: {e}")

        return ErrorAnalysis(
            error_type=event_data.exception_type or "Unknown",
            error_message=event_data.exception_value or "",
            root_cause="Could not determine - analysis failed",
            file_path=event_data.file_path or "",
            line_number=event_data.line_number,
            function_name=event_data.function_name,
            confidence=0.0,
            can_auto_fix=False,
            explanation="Failed to analyze error",
        )

    def _parse_fix_response(self, response: str) -> list[ProposedFix]:
        """Parse Claude's fix response."""
        fixes = []
        try:
            json_match = re.search(r"\{[\s\S]*\}", response)
            if json_match:
                data = json.loads(json_match.group(0))
                for fix_data in data.get("fixes", []):
                    fixes.append(
                        ProposedFix(
                            file_path=fix_data["file_path"],
                            original_code=fix_data["original_code"],
                            fixed_code=fix_data["fixed_code"],
                            explanation=fix_data["explanation"],
                            confidence=float(fix_data.get("confidence", 0.8)),
                        )
                    )
        except Exception as e:
            logger.warning(f"Failed to parse fix response: {e}")

        return fixes


# Singleton
analyzer_service = AnalyzerService()
