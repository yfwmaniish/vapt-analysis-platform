"""
Open Redirect Scanner.

Injects redirect payloads into URL parameters commonly used for
redirections (url=, next=, return=, redirect=, etc.) and checks
if the server issues a 3xx redirect to an external domain.
"""

from __future__ import annotations

from typing import Any, Dict, List
from urllib.parse import urlencode, urlparse, parse_qsl, urlunparse

import aiohttp

from engine.models.finding import Finding, Severity
from engine.scanners.base import BaseScanner
from engine.scanners.registry import ScannerRegistry
from engine.utils.network import normalize_target


# Parameters commonly used for URL redirections
REDIRECT_PARAMS = {
    "url", "redirect", "redirect_url", "redirect_uri", "return",
    "return_url", "returnurl", "next", "next_url", "dest",
    "destination", "go", "goto", "target", "link", "rurl",
    "continue", "callback", "out", "forward", "ref", "site",
}

# External domains to inject as redirect targets
REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "https://evil.com/%2f..",
    "/\\evil.com",
    "https:evil.com",
]


@ScannerRegistry.register
class RedirectScanner(BaseScanner):

    @property
    def name(self) -> str:
        return "redirect"

    @property
    def display_name(self) -> str:
        return "Open Redirect Scanner"

    @property
    def description(self) -> str:
        return "Detect open redirect vulnerabilities in URL parameters"

    async def scan(self, target: str, **kwargs: Any) -> List[Finding]:
        attack_surface = kwargs.get("attack_surface", {})
        findings: List[Finding] = []

        if not attack_surface:
            self.report_progress(100.0, "No attack surface data. Run crawler first.")
            return findings

        urls = attack_surface.get("internal_urls", [])
        param_urls = [u for u in urls if "?" in u]

        if not param_urls:
            self.report_progress(100.0, "No parameterized URLs found.")
            return findings

        self.report_progress(5.0, f"Scanning {len(param_urls)} URLs for open redirects")

        timeout_val = aiohttp.ClientTimeout(total=self.timeout)
        tested = 0
        total = 0

        # Count only redirect-like parameters
        for url in param_urls:
            parsed = urlparse(url)
            params = parse_qsl(parsed.query)
            for key, _ in params:
                if key.lower() in REDIRECT_PARAMS:
                    total += len(REDIRECT_PAYLOADS)

        if total == 0:
            self.report_progress(100.0, "No redirect-like parameters detected.")
            return findings

        seen_vulns: set = set()

        async with aiohttp.ClientSession(
            timeout=timeout_val,
            headers={"User-Agent": "Veltro-RedirectScanner/1.0"},
        ) as session:
            for url in param_urls:
                parsed = urlparse(url)
                params = parse_qsl(parsed.query)

                for i, (key, value) in enumerate(params):
                    if key.lower() not in REDIRECT_PARAMS:
                        continue

                    for payload in REDIRECT_PAYLOADS:
                        fuzzed_params = list(params)
                        fuzzed_params[i] = (key, payload)
                        fuzzed_query = urlencode(fuzzed_params)
                        fuzzed_url = urlunparse((
                            parsed.scheme, parsed.netloc, parsed.path,
                            parsed.params, fuzzed_query, parsed.fragment,
                        ))

                        try:
                            async with session.get(
                                fuzzed_url, ssl=False, allow_redirects=False,
                            ) as resp:
                                location = resp.headers.get("Location", "")

                                if resp.status in (301, 302, 303, 307, 308) and location:
                                    loc_parsed = urlparse(location)
                                    # Check if redirected to an external domain
                                    if (
                                        loc_parsed.netloc
                                        and loc_parsed.netloc != parsed.netloc
                                        and "evil" in loc_parsed.netloc.lower()
                                    ):
                                        vuln_key = f"{key}@{parsed.path}"
                                        if vuln_key not in seen_vulns:
                                            seen_vulns.add(vuln_key)
                                            findings.append(Finding(
                                                scanner=self.name,
                                                type="Open Redirect",
                                                severity=Severity.MEDIUM,
                                                title=f"Open redirect via parameter '{key}'",
                                                description=(
                                                    f"The '{key}' parameter redirects to an attacker-controlled "
                                                    "domain without validation. This can be used for phishing attacks "
                                                    "by luring victims through a trusted URL that redirects to a "
                                                    "malicious site."
                                                ),
                                                evidence=(
                                                    f"Injected: {payload}\n"
                                                    f"Redirect to: {location}\n"
                                                    f"HTTP Status: {resp.status}"
                                                ),
                                                location=fuzzed_url,
                                                remediation=(
                                                    "Validate redirect URLs against a whitelist of allowed domains. "
                                                    "Use relative paths instead of absolute URLs for redirections."
                                                ),
                                                cwe_id="CWE-601",
                                            ))
                        except Exception:
                            pass

                        tested += 1
                        if total > 0:
                            self.report_progress(
                                5.0 + (tested / total * 90.0),
                                f"Testing redirect params ({tested}/{total})",
                            )

        if not findings:
            findings.append(Finding(
                scanner=self.name, type="Redirect Analysis", severity=Severity.INFO,
                title="No open redirect vulnerabilities detected",
                description=f"Tested {tested} redirect parameter combinations without finding exploitable redirects.",
                location=target,
            ))

        self.report_progress(100.0, "Open redirect scan complete")
        return findings
