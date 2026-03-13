"""
LLM service abstraction layer.

Provides a unified interface for AI-powered vulnerability analysis
using OpenRouter (which supports OpenAI, Anthropic, Google models).
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import aiohttp

from engine import config
from engine.utils.logger import get_logger

logger = get_logger("llm_service")


class LLMService:
    """Abstraction over LLM providers via OpenRouter."""

    def __init__(
        self,
        api_key: str = "",
        api_base: str = "",
        model: str = "",
    ):
        self.api_key = api_key or config.LLM_API_KEY
        self.api_base = api_base or config.LLM_API_BASE
        self.model = model or config.LLM_MODEL
        self._available = bool(self.api_key)

    @property
    def is_available(self) -> bool:
        return self._available

    async def analyze(self, prompt: str, system_prompt: str = "") -> Optional[str]:
        """
        Send a prompt to the LLM and return the response text.
        Returns None if the service is unavailable or fails.
        """
        if not self._available:
            logger.warning("LLM service unavailable — no API key configured")
            return None

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://securesuitex.local",
            "X-Title": "SecureSuiteX Security Scanner",
        }

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model,
            "messages": messages,
            "max_tokens": 2000,
            "temperature": 0.3,
        }

        try:
            timeout = aiohttp.ClientTimeout(total=60)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(
                    f"{self.api_base}/chat/completions",
                    headers=headers,
                    json=payload,
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        choices = data.get("choices", [])
                        if choices:
                            return choices[0].get("message", {}).get("content", "")
                    else:
                        error_text = await resp.text()
                        logger.error(f"LLM API error {resp.status}: {error_text[:200]}")
                        return None
        except Exception as exc:
            logger.error(f"LLM request failed: {exc}")
            return None

    async def analyze_findings(
        self, findings: List[Dict[str, Any]], target: str
    ) -> Optional[str]:
        """
        Generate an AI-powered executive summary of scan findings.
        """
        system_prompt = (
            "You are a senior cybersecurity analyst reviewing VAPT scan results. "
            "Provide a concise, actionable executive summary. "
            "Prioritize critical and high severity findings. "
            "Suggest remediation steps in order of priority. "
            "Be direct and technical. No marketing fluff."
        )

        # Prepare a condensed version of findings for the prompt
        condensed = []
        for f in findings[:30]:  # Limit to top 30 findings
            condensed.append({
                "severity": f.get("severity", "info"),
                "type": f.get("type", ""),
                "title": f.get("title", ""),
                "description": f.get("description", "")[:200],
                "remediation": f.get("remediation", ""),
            })

        prompt = (
            f"## Target: {target}\n\n"
            f"## Scan Findings ({len(findings)} total):\n\n"
            f"```json\n{json.dumps(condensed, indent=2)}\n```\n\n"
            f"Provide:\n"
            f"1. Executive Summary (2-3 sentences)\n"
            f"2. Risk Score (1-10) with justification\n"
            f"3. Top 5 Priority Remediation Steps\n"
            f"4. Overall Security Posture Assessment"
        )

        return await self.analyze(prompt, system_prompt)

    async def analyze_single_finding(self, finding: Dict[str, Any]) -> Optional[str]:
        """Generate AI analysis for a single finding."""
        system_prompt = (
            "You are a cybersecurity expert. Analyze this vulnerability finding. "
            "Explain the real-world impact and provide step-by-step remediation. "
            "Be concise and technical."
        )

        prompt = (
            f"Analyze this vulnerability:\n\n"
            f"**Type:** {finding.get('type')}\n"
            f"**Severity:** {finding.get('severity')}\n"
            f"**Title:** {finding.get('title')}\n"
            f"**Description:** {finding.get('description')}\n"
            f"**Evidence:** {finding.get('evidence', 'N/A')}\n\n"
            f"Provide:\n"
            f"1. Real-world impact\n"
            f"2. Attack scenario\n"
            f"3. Step-by-step remediation"
        )

        return await self.analyze(prompt, system_prompt)


# Module-level singleton
llm_service = LLMService()
