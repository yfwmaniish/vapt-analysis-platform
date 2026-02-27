"""
HTTP cookie security analyzer.

Checks cookies for missing Secure, HttpOnly, SameSite flags
and other security issues.
"""

from __future__ import annotations

from typing import Any, List
from http.cookies import SimpleCookie

import aiohttp

from engine.models.finding import Finding, Severity
from engine.scanners.base import BaseScanner
from engine.scanners.registry import ScannerRegistry
from engine.utils.network import normalize_target


@ScannerRegistry.register
class CookieScanner(BaseScanner):

    @property
    def name(self) -> str:
        return "cookies"

    @property
    def display_name(self) -> str:
        return "Cookie Security Analyzer"

    @property
    def description(self) -> str:
        return "Analyze HTTP cookies for missing security flags (Secure, HttpOnly, SameSite)"

    async def scan(self, target: str, **kwargs: Any) -> List[Finding]:
        url = normalize_target(target)
        findings: List[Finding] = []

        self.report_progress(10.0, f"Fetching cookies from {url}")

        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, ssl=False, allow_redirects=True) as resp:
                    cookies = resp.cookies
                    set_cookie_headers = resp.headers.getall("Set-Cookie", [])
        except Exception as exc:
            return [Finding(
                scanner=self.name, type="Connection Failed", severity=Severity.INFO,
                title=f"Cannot fetch cookies from {url}",
                description=str(exc), location=url,
            )]

        if not cookies and not set_cookie_headers:
            findings.append(Finding(
                scanner=self.name, type="Cookie Analysis", severity=Severity.INFO,
                title="No cookies set by the server",
                description=f"{url} does not set any cookies on initial request.",
                location=url,
            ))
            return findings

        self.report_progress(40.0, f"Analyzing {len(set_cookie_headers)} cookies")

        for raw_cookie in set_cookie_headers:
            # Parse cookie name from raw header
            cookie_name = raw_cookie.split("=")[0].strip() if "=" in raw_cookie else "Unknown"
            raw_lower = raw_cookie.lower()

            # Check Secure flag
            if "secure" not in raw_lower:
                findings.append(Finding(
                    scanner=self.name, type="Missing Secure Flag", severity=Severity.MEDIUM,
                    title=f"Cookie '{cookie_name}' missing Secure flag",
                    description="Without the Secure flag, this cookie can be sent over unencrypted HTTP.",
                    evidence=raw_cookie, location=url,
                    remediation=f"Add the Secure flag to cookie '{cookie_name}'.",
                    cwe_id="CWE-614",
                ))

            # Check HttpOnly flag
            if "httponly" not in raw_lower:
                findings.append(Finding(
                    scanner=self.name, type="Missing HttpOnly Flag", severity=Severity.MEDIUM,
                    title=f"Cookie '{cookie_name}' missing HttpOnly flag",
                    description="Without HttpOnly, JavaScript can access this cookie (enabling XSS theft).",
                    evidence=raw_cookie, location=url,
                    remediation=f"Add the HttpOnly flag to cookie '{cookie_name}'.",
                    cwe_id="CWE-1004",
                ))

            # Check SameSite flag
            if "samesite" not in raw_lower:
                findings.append(Finding(
                    scanner=self.name, type="Missing SameSite Flag", severity=Severity.LOW,
                    title=f"Cookie '{cookie_name}' missing SameSite attribute",
                    description="Without SameSite, the cookie may be sent in CSRF attacks.",
                    evidence=raw_cookie, location=url,
                    remediation=f"Add SameSite=Strict or SameSite=Lax to cookie '{cookie_name}'.",
                    cwe_id="CWE-352",
                ))

            # Check for overly broad Path
            if "path=/" in raw_lower and "path=/;" not in raw_lower.replace(" ", ""):
                # path=/ is fine, but warn if there are sensitive sub-paths
                pass  # Most cookies use path=/, this is generally acceptable

        self.report_progress(100.0, f"Analyzed {len(set_cookie_headers)} cookies")
        return findings
