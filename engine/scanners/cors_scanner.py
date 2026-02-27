"""
CORS Origin Reflection Scanner.

Actively probes for CORS misconfigurations by sending crafted
Origin headers and checking if the server reflects them.

Tests:
1. Arbitrary origin reflection (Origin: https://evil.com)
2. Null origin acceptance (Origin: null)
3. Subdomain wildcard bypass (Origin: attacker.target.com)
4. Credentials with reflected origin
"""

from __future__ import annotations

from typing import Any, List
from urllib.parse import urlparse

import aiohttp

from engine.models.finding import Finding, Severity
from engine.scanners.base import BaseScanner
from engine.scanners.registry import ScannerRegistry
from engine.utils.network import normalize_target


@ScannerRegistry.register
class CORSScanner(BaseScanner):

    @property
    def name(self) -> str:
        return "cors"

    @property
    def display_name(self) -> str:
        return "CORS Misconfiguration Scanner"

    @property
    def description(self) -> str:
        return "Test for CORS origin reflection, null origin, and credential leakage"

    async def _probe_origin(
        self,
        session: aiohttp.ClientSession,
        url: str,
        origin: str,
    ) -> dict:
        """Send a request with a crafted Origin header and return CORS headers."""
        try:
            headers = {"Origin": origin}
            async with session.get(url, headers=headers, ssl=False, allow_redirects=True) as resp:
                return {
                    "acao": resp.headers.get("Access-Control-Allow-Origin", ""),
                    "acac": resp.headers.get("Access-Control-Allow-Credentials", ""),
                    "acam": resp.headers.get("Access-Control-Allow-Methods", ""),
                    "acah": resp.headers.get("Access-Control-Allow-Headers", ""),
                    "status": resp.status,
                }
        except Exception:
            return {"acao": "", "acac": "", "acam": "", "acah": "", "status": 0}

    async def scan(self, target: str, **kwargs: Any) -> List[Finding]:
        url = normalize_target(target)
        findings: List[Finding] = []
        parsed = urlparse(url)
        target_domain = parsed.netloc

        self.report_progress(5.0, f"Probing CORS on {url}")

        timeout_val = aiohttp.ClientTimeout(total=self.timeout)

        async with aiohttp.ClientSession(timeout=timeout_val) as session:

            # ── Test 1: Arbitrary Origin Reflection ────────────
            self.report_progress(15.0, "Testing arbitrary origin reflection")
            evil_origin = "https://evil-attacker.com"
            result = await self._probe_origin(session, url, evil_origin)

            if result["acao"] == evil_origin:
                severity = Severity.HIGH
                if result["acac"].lower() == "true":
                    severity = Severity.CRITICAL

                findings.append(Finding(
                    scanner=self.name,
                    type="CORS Origin Reflection",
                    severity=severity,
                    title="Server reflects arbitrary Origin header in ACAO",
                    description=(
                        f"The server reflected the attacker-controlled Origin '{evil_origin}' "
                        "in the Access-Control-Allow-Origin response header. "
                        + ("Combined with Access-Control-Allow-Credentials: true, "
                           "this allows any website to make fully authenticated cross-origin requests, "
                           "stealing user data." if result["acac"].lower() == "true" else
                           "While credentials are not explicitly allowed, this still exposes "
                           "unauthenticated API data to any origin.")
                    ),
                    evidence=(
                        f"Request Origin: {evil_origin}\n"
                        f"Response ACAO: {result['acao']}\n"
                        f"Response ACAC: {result['acac']}"
                    ),
                    location=url,
                    remediation="Whitelist specific trusted origins instead of reflecting the Origin header.",
                    cwe_id="CWE-942",
                ))

            # ── Test 2: Null Origin Acceptance ─────────────────
            self.report_progress(35.0, "Testing null origin acceptance")
            null_result = await self._probe_origin(session, url, "null")

            if null_result["acao"] == "null":
                findings.append(Finding(
                    scanner=self.name,
                    type="CORS Null Origin Accepted",
                    severity=Severity.HIGH,
                    title="Server accepts 'null' Origin (iframe/redirect bypass)",
                    description=(
                        "The server returns Access-Control-Allow-Origin: null when the "
                        "Origin header is 'null'. This can be exploited via sandboxed iframes "
                        "(sandbox attribute) or data: URI redirects to bypass CORS protections."
                    ),
                    evidence=(
                        f"Request Origin: null\n"
                        f"Response ACAO: {null_result['acao']}\n"
                        f"Response ACAC: {null_result['acac']}"
                    ),
                    location=url,
                    remediation="Never allow 'null' as a valid origin. Remove it from whitelists.",
                    cwe_id="CWE-942",
                ))

            # ── Test 3: Subdomain Wildcard Bypass ──────────────
            self.report_progress(55.0, "Testing subdomain prefix bypass")
            # Try: evil-target.com (prefix attack)
            prefix_origin = f"https://evil-{target_domain}"
            prefix_result = await self._probe_origin(session, url, prefix_origin)

            if prefix_result["acao"] == prefix_origin:
                findings.append(Finding(
                    scanner=self.name,
                    type="CORS Prefix Bypass",
                    severity=Severity.MEDIUM,
                    title=f"Server accepts prefixed domain '{prefix_origin}'",
                    description=(
                        "The server uses a prefix-based origin check instead of exact matching. "
                        f"It accepted '{prefix_origin}' which an attacker could register."
                    ),
                    evidence=(
                        f"Request Origin: {prefix_origin}\n"
                        f"Response ACAO: {prefix_result['acao']}"
                    ),
                    location=url,
                    remediation="Use exact string matching for allowed origins, not prefix/suffix matching.",
                    cwe_id="CWE-942",
                ))

            # Try: attacker.target.com (subdomain takeover potential)
            subdomain_origin = f"https://attacker.{target_domain}"
            sub_result = await self._probe_origin(session, url, subdomain_origin)

            if sub_result["acao"] == subdomain_origin:
                findings.append(Finding(
                    scanner=self.name,
                    type="CORS Subdomain Trust",
                    severity=Severity.MEDIUM,
                    title=f"Server trusts all subdomains (*.{target_domain})",
                    description=(
                        "The server accepts any subdomain as a valid CORS origin. "
                        "If any subdomain is vulnerable to XSS or takeover, the attacker "
                        "can use it to make cross-origin requests to the main domain."
                    ),
                    evidence=(
                        f"Request Origin: {subdomain_origin}\n"
                        f"Response ACAO: {sub_result['acao']}"
                    ),
                    location=url,
                    remediation="Only whitelist specific, trusted subdomains. Audit all subdomains for vulnerabilities.",
                    cwe_id="CWE-942",
                ))

            # ── Test 4: Wildcard with Credentials ──────────────
            self.report_progress(75.0, "Testing wildcard + credentials")
            wildcard_result = await self._probe_origin(session, url, "https://example.com")

            if wildcard_result["acao"] == "*" and wildcard_result["acac"].lower() == "true":
                findings.append(Finding(
                    scanner=self.name,
                    type="CORS Wildcard Credentials",
                    severity=Severity.CRITICAL,
                    title="ACAO: * combined with Allow-Credentials: true",
                    description=(
                        "The server returns both Access-Control-Allow-Origin: * AND "
                        "Access-Control-Allow-Credentials: true. While browsers technically "
                        "block this combination, misconfigured reverse proxies or older clients "
                        "may not enforce this restriction."
                    ),
                    evidence=(
                        f"Response ACAO: {wildcard_result['acao']}\n"
                        f"Response ACAC: {wildcard_result['acac']}"
                    ),
                    location=url,
                    remediation="Never combine wildcard origins with credentials. Use explicit origin whitelisting.",
                    cwe_id="CWE-942",
                ))

        if not findings:
            findings.append(Finding(
                scanner=self.name, type="CORS Analysis", severity=Severity.INFO,
                title="CORS policy appears properly configured",
                description="No origin reflection, null acceptance, or credential misconfigurations detected.",
                location=url,
            ))

        self.report_progress(100.0, "CORS analysis complete")
        return findings
