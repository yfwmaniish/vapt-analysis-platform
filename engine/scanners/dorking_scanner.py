"""
Google dorking scanner for OSINT reconnaissance.

Uses search engine queries (Google dorks) to find exposed
sensitive information about the target domain.
"""

from __future__ import annotations

import asyncio
from typing import Any, List

import aiohttp

from engine.models.finding import Finding, Severity
from engine.scanners.base import BaseScanner
from engine.scanners.registry import ScannerRegistry
from engine.utils.network import extract_domain


# Dork templates: (query_format, description, severity)
DORK_TEMPLATES = [
    ('site:{domain} filetype:pdf', "PDF documents on target", Severity.INFO),
    ('site:{domain} filetype:sql', "SQL dumps — potential data leak", Severity.CRITICAL),
    ('site:{domain} filetype:log', "Log files — may contain sensitive info", Severity.HIGH),
    ('site:{domain} filetype:env', "Environment files — may expose credentials", Severity.CRITICAL),
    ('site:{domain} filetype:xml', "XML configuration files", Severity.LOW),
    ('site:{domain} filetype:conf', "Server config files", Severity.MEDIUM),
    ('site:{domain} filetype:bak', "Backup files — source/config exposure", Severity.HIGH),
    ('site:{domain} inurl:admin', "Admin pages indexed by search engines", Severity.MEDIUM),
    ('site:{domain} inurl:login', "Login pages indexed", Severity.LOW),
    ('site:{domain} inurl:dashboard', "Dashboard pages indexed", Severity.MEDIUM),
    ('site:{domain} intitle:"index of"', "Directory listings — file exposure", Severity.HIGH),
    ('site:{domain} "password" filetype:txt', "Password files", Severity.CRITICAL),
    ('site:{domain} "api_key" OR "api key"', "Exposed API keys", Severity.CRITICAL),
    ('site:{domain} inurl:wp-content', "WordPress content directory", Severity.LOW),
    ('site:{domain} inurl:wp-config', "WordPress config exposure", Severity.CRITICAL),
    ('site:{domain} ext:php intitle:phpinfo', "PHP info pages", Severity.HIGH),
]


@ScannerRegistry.register
class DorkingScanner(BaseScanner):

    @property
    def name(self) -> str:
        return "dorking"

    @property
    def display_name(self) -> str:
        return "Google Dorking Scanner"

    @property
    def description(self) -> str:
        return "OSINT reconnaissance using search engine dork queries"

    async def _search_dork(self, query: str) -> List[str]:
        """
        Execute a search query.
        Uses a lightweight approach to avoid heavy dependencies.
        Returns list of result URLs.
        """
        # Use Google's custom search JSON API approach via HTML scraping
        # Note: This is a lightweight approach; for production, use Google Custom Search API
        encoded_query = query.replace(" ", "+")
        url = f"https://www.google.com/search?q={encoded_query}&num=5"

        try:
            timeout = aiohttp.ClientTimeout(total=10)
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, headers=headers, ssl=False) as resp:
                    if resp.status == 200:
                        body = await resp.text()
                        # Extract URLs from search results (simplified)
                        results = []
                        import re
                        # Look for result links
                        url_pattern = r'href="(/url\?q=|)(https?://[^"&]+)'
                        matches = re.findall(url_pattern, body)
                        for _, found_url in matches:
                            if "google.com" not in found_url:
                                results.append(found_url)
                        return results[:5]  # Max 5 results per dork
                    elif resp.status == 429:
                        return []  # Rate limited
        except Exception:
            pass
        return []

    async def scan(self, target: str, **kwargs: Any) -> List[Finding]:
        domain = extract_domain(target)
        findings: List[Finding] = []

        self.report_progress(5.0, f"Running {len(DORK_TEMPLATES)} dork queries for {domain}")

        for i, (query_template, description, severity) in enumerate(DORK_TEMPLATES):
            query = query_template.format(domain=domain)

            self.report_progress(
                ((i + 1) / len(DORK_TEMPLATES)) * 90 + 5,
                f"Dorking: {query[:50]}..."
            )

            results = await self._search_dork(query)

            if results:
                result_urls = "\n".join(f"  • {u}" for u in results)
                findings.append(Finding(
                    scanner=self.name,
                    type="OSINT Discovery",
                    severity=severity,
                    title=f"Dork hit: {description}",
                    description=(
                        f"Google dork query found {len(results)} results for: {query}\n"
                        f"This indicates {description.lower()} that may be unintentionally exposed."
                    ),
                    evidence=f"Query: {query}\nResults:\n{result_urls}",
                    location=domain,
                    remediation="Review exposed resources and restrict access if sensitive.",
                ))

            # Add a small delay to avoid rate limiting
            await asyncio.sleep(1)

        if not findings:
            findings.append(Finding(
                scanner=self.name, type="Dorking Scan", severity=Severity.INFO,
                title=f"No sensitive exposures found via dorking for {domain}",
                description="Google dork queries did not find indexed sensitive resources.",
                location=domain,
            ))

        self.report_progress(100.0, "Dorking scan complete")
        return findings
