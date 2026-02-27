"""
Session & Cookie Security Deep-Dive Scanner.

Goes beyond basic cookie flag checks to analyze:
- Session ID entropy and predictability
- Session fixation vulnerabilities (pre/post login heuristic)
- Overly permissive cookie scope (domain/path)
- CORS misconfiguration for credential leakage
"""

from __future__ import annotations

import math
import string
from collections import Counter
from typing import Any, List
from urllib.parse import urlparse

import aiohttp

from engine.models.finding import Finding, Severity
from engine.scanners.base import BaseScanner
from engine.scanners.registry import ScannerRegistry
from engine.utils.network import normalize_target


@ScannerRegistry.register
class SessionScanner(BaseScanner):

    @property
    def name(self) -> str:
        return "session"

    @property
    def display_name(self) -> str:
        return "Session Security Auditor"

    @property
    def description(self) -> str:
        return "Deep-dive into session ID entropy, fixation, and CORS credential leakage"

    # ── Helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _calculate_entropy(value: str) -> float:
        """Calculate Shannon entropy of a string (bits per character)."""
        if not value:
            return 0.0
        counter = Counter(value)
        length = len(value)
        entropy = -sum(
            (count / length) * math.log2(count / length)
            for count in counter.values()
        )
        return entropy

    @staticmethod
    def _extract_session_cookies(raw_headers: list[str]) -> list[dict]:
        """
        Parse Set-Cookie headers and identify those that look like session IDs
        based on common naming patterns.
        """
        session_patterns = [
            "session", "sess", "sid", "ssid", "token", "auth",
            "jsessionid", "phpsessid", "asp.net_sessionid", "csrf",
        ]
        results = []
        for raw in raw_headers:
            if "=" not in raw:
                continue
            name = raw.split("=")[0].strip()
            value_part = raw.split("=", 1)[1].split(";")[0].strip()
            is_session = any(p in name.lower() for p in session_patterns)
            results.append({
                "name": name,
                "value": value_part,
                "raw": raw,
                "is_session_like": is_session,
            })
        return results

    # ── Main Scan Logic ─────────────────────────────────────────────

    async def scan(self, target: str, **kwargs: Any) -> List[Finding]:
        url = normalize_target(target)
        findings: List[Finding] = []
        auth_header = kwargs.get("auth_header", "")

        self.report_progress(5.0, f"Fetching session cookies from {url}")

        headers = {}
        if auth_header:
            headers["Authorization"] = auth_header

        # ── Phase 1: Fetch cookies from two separate requests ──────
        cookies_r1: list[str] = []
        cookies_r2: list[str] = []

        try:
            timeout_val = aiohttp.ClientTimeout(total=self.timeout)
            async with aiohttp.ClientSession(timeout=timeout_val) as session:
                # Request 1
                async with session.get(url, ssl=False, allow_redirects=True, headers=headers) as resp1:
                    cookies_r1 = resp1.headers.getall("Set-Cookie", [])

                # Request 2 (separate session to get fresh cookies)
            async with aiohttp.ClientSession(timeout=timeout_val) as session2:
                async with session2.get(url, ssl=False, allow_redirects=True, headers=headers) as resp2:
                    cookies_r2 = resp2.headers.getall("Set-Cookie", [])
                    # Also check CORS
                    cors_header = resp2.headers.get("Access-Control-Allow-Origin", "")
                    cors_creds = resp2.headers.get("Access-Control-Allow-Credentials", "")

        except Exception as exc:
            return [Finding(
                scanner=self.name, type="Connection Failed", severity=Severity.INFO,
                title=f"Cannot connect to {url} for session analysis",
                description=str(exc), location=url,
            )]

        if not cookies_r1:
            findings.append(Finding(
                scanner=self.name, type="Session Analysis", severity=Severity.INFO,
                title="No session cookies detected",
                description=f"{url} does not issue session cookies on initial request.",
                location=url,
            ))
            self.report_progress(100.0, "No cookies to analyze")
            return findings

        self.report_progress(30.0, f"Analyzing {len(cookies_r1)} cookies")

        parsed_r1 = self._extract_session_cookies(cookies_r1)
        parsed_r2 = self._extract_session_cookies(cookies_r2)

        # ── Phase 2: Entropy Analysis ──────────────────────────────

        for cookie in parsed_r1:
            if not cookie["is_session_like"]:
                continue

            entropy = self._calculate_entropy(cookie["value"])
            value_len = len(cookie["value"])

            if value_len < 16:
                findings.append(Finding(
                    scanner=self.name, type="Short Session ID", severity=Severity.HIGH,
                    title=f"Session cookie '{cookie['name']}' is too short ({value_len} chars)",
                    description=(
                        "Short session IDs are easier to brute-force. "
                        "OWASP recommends at least 128 bits (≈22 base64 chars) of randomness."
                    ),
                    evidence=f"Value length: {value_len}, Value: {cookie['value'][:20]}...",
                    location=url,
                    remediation="Use a cryptographically secure random generator with at least 128 bits.",
                    cwe_id="CWE-330",
                ))
            elif entropy < 3.0:
                findings.append(Finding(
                    scanner=self.name, type="Low Entropy Session ID", severity=Severity.MEDIUM,
                    title=f"Session cookie '{cookie['name']}' has low entropy ({entropy:.2f} bits/char)",
                    description=(
                        "Low entropy in session IDs suggests predictable values, "
                        "making brute-force or guessing attacks feasible."
                    ),
                    evidence=f"Entropy: {entropy:.2f} bits/char, Length: {value_len}",
                    location=url,
                    remediation="Use a CSPRNG to generate session tokens.",
                    cwe_id="CWE-330",
                ))

        self.report_progress(55.0, "Checking for session fixation")

        # ── Phase 3: Session Fixation Heuristic ────────────────────
        # Compare session IDs between two independent requests.
        # If the server issues the SAME session ID to two unauthenticated
        # clients, it MAY indicate session fixation risk.

        for c1 in parsed_r1:
            if not c1["is_session_like"]:
                continue
            for c2 in parsed_r2:
                if c1["name"] == c2["name"] and c1["value"] == c2["value"]:
                    findings.append(Finding(
                        scanner=self.name, type="Potential Session Fixation", severity=Severity.MEDIUM,
                        title=f"Session ID '{c1['name']}' is identical across separate requests",
                        description=(
                            "Two independent requests received the same session identifier. "
                            "This could indicate the server is not regenerating session IDs, "
                            "leaving it vulnerable to session fixation attacks."
                        ),
                        evidence=f"Cookie '{c1['name']}' value is identical in both responses.",
                        location=url,
                        remediation="Regenerate session IDs after authentication and on each new session.",
                        cwe_id="CWE-384",
                    ))

        self.report_progress(75.0, "Auditing CORS configuration")

        # ── Phase 4: CORS Credential Leakage ──────────────────────

        if cors_header == "*" and cors_creds.lower() == "true":
            findings.append(Finding(
                scanner=self.name, type="CORS Misconfiguration", severity=Severity.HIGH,
                title="Wildcard CORS with credentials enabled",
                description=(
                    "The server allows any origin (*) AND credentials. "
                    "This enables any website to make authenticated requests on behalf of users."
                ),
                evidence=f"Access-Control-Allow-Origin: {cors_header}, Allow-Credentials: {cors_creds}",
                location=url,
                remediation="Never use wildcard origins with credentials. Specify explicit allowed origins.",
                cwe_id="CWE-942",
            ))
        elif cors_header and cors_header != "*":
            # Check if Origin reflects back (another common misconfiguration)
            # We'd need to send a custom Origin header to test this properly
            pass

        # ── Phase 5: Cookie Scope Audit ────────────────────────────

        self.report_progress(90.0, "Checking cookie scope")
        target_domain = urlparse(url).netloc

        for cookie in parsed_r1:
            raw_lower = cookie["raw"].lower()
            # Check for overly broad domain
            if "domain=" in raw_lower:
                domain_val = ""
                for part in raw_lower.split(";"):
                    if "domain=" in part:
                        domain_val = part.split("=", 1)[1].strip()
                        break
                if domain_val.startswith("."):
                    # Leading dot means all subdomains get the cookie
                    findings.append(Finding(
                        scanner=self.name, type="Broad Cookie Domain", severity=Severity.LOW,
                        title=f"Cookie '{cookie['name']}' scoped to all subdomains ({domain_val})",
                        description=(
                            "A leading dot in the Domain attribute means all subdomains "
                            "can access this cookie, increasing the attack surface."
                        ),
                        evidence=f"Domain: {domain_val}",
                        location=url,
                        remediation="Restrict cookie domain to the specific host unless cross-subdomain access is required.",
                    ))

        self.report_progress(100.0, "Session security audit complete")
        return findings
