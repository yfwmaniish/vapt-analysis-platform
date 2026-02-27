"""
Dev/debug endpoint detection scanner.

Discovers exposed development, admin, and debug endpoints
that should not be present in production.
"""

from __future__ import annotations

import asyncio
from typing import Any, List

import aiohttp

from engine.models.finding import Finding, Severity
from engine.scanners.base import BaseScanner
from engine.scanners.registry import ScannerRegistry
from engine.utils.network import normalize_target


# Dev/debug endpoints with their risk level and unique signatures to avoid Soft 404 false positives
ENDPOINTS = {
    "/.env": {"severity": Severity.CRITICAL, "signatures": ["DB_", "APP_ENV", "SECRET_KEY", "AWS_ACCESS_KEY_ID"]},
    "/.git/HEAD": {"severity": Severity.CRITICAL, "signatures": ["ref: refs/heads/", "ref: refs/remotes/"]},
    "/.svn/entries": {"severity": Severity.CRITICAL, "signatures": ["svn://", "dir\n8\n"]},
    "/phpinfo.php": {"severity": Severity.HIGH, "signatures": ["<title>phpinfo()</title>", 'id="phpinfo"']},
    "/info.php": {"severity": Severity.HIGH, "signatures": ["<title>phpinfo()</title>", 'id="phpinfo"']},
    "/server-status": {"severity": Severity.HIGH, "signatures": ["Apache Server Status"]},
    "/server-info": {"severity": Severity.HIGH, "signatures": ["Apache Server Information"]},
    "/swagger-ui.html": {"severity": Severity.MEDIUM, "signatures": ["<title>Swagger UI</title>", "swagger-ui-bundle"]},
    "/swagger/index.html": {"severity": Severity.MEDIUM, "signatures": ["<title>Swagger UI</title>", "swagger-ui-bundle"]},
    "/api-docs": {"severity": Severity.MEDIUM, "signatures": ['"openapi":', '"swagger":', 'paths:']},
    "/graphiql": {"severity": Severity.MEDIUM, "signatures": ["<title>GraphiQL</title>", "graphiql.min.js"]},
    "/actuator": {"severity": Severity.HIGH, "signatures": ['"_links"', '"health"']},
    "/actuator/health": {"severity": Severity.MEDIUM, "signatures": ['"status":"UP"', '"status":"UNKNOWN"']},
    "/actuator/env": {"severity": Severity.CRITICAL, "signatures": ['"propertySources"', '"activeProfiles"']},
    "/actuator/mappings": {"severity": Severity.HIGH, "signatures": ['"dispatcherServlet"', '"handlerMethods"']},
    "/debug/pprof": {"severity": Severity.HIGH, "signatures": ["Types of profiles", "goroutine"]},
    "/debug/vars": {"severity": Severity.HIGH, "signatures": ['"cmdline"', '"memstats"']},
    "/elmah.axd": {"severity": Severity.HIGH, "signatures": ["Error Log for", "Powered by ELMAH"]},
    "/trace.axd": {"severity": Severity.HIGH, "signatures": ["Application Trace", "Request Details"]},
    "/metrics": {"severity": Severity.MEDIUM, "signatures": ["jvm_memory_", "process_cpu_", "python_gc_"]},
}


@ScannerRegistry.register
class EndpointScanner(BaseScanner):

    @property
    def name(self) -> str:
        return "endpoints"

    @property
    def display_name(self) -> str:
        return "Endpoint Scanner"

    @property
    def description(self) -> str:
        return "Detect exposed dev, debug, admin, and monitoring endpoints"

    async def _check_endpoint(
        self, session: aiohttp.ClientSession, base_url: str,
        path: str, config: dict, semaphore: asyncio.Semaphore
    ) -> Finding | None:
        """Check if a dev/debug endpoint is accessible and matches expected signatures."""
        async with semaphore:
            url = f"{base_url.rstrip('/')}{path}"
            try:
                # Disallow redirects so we don't follow soft 404 redirects
                async with session.get(url, ssl=False, allow_redirects=False) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        
                        # Signature verification for Soft 404 evasion
                        matched_signature = next((sig for sig in config["signatures"] if sig in text), None)
                        
                        if matched_signature:
                            body_preview = text[:200]
                            return Finding(
                                scanner=self.name,
                                type="Exposed Endpoint",
                                severity=config["severity"],
                                title=f"Dev/debug endpoint accessible: {path}",
                                description=(
                                    f"The endpoint {path} is publicly accessible and matched the signature '{matched_signature}'. "
                                    f"This exposes sensitive info, configuration, or admin controls."
                                ),
                                evidence=f"Signature Match: '{matched_signature}'\nResponse preview: {body_preview}",
                                location=url,
                                remediation=f"Remove or restrict access to {path} in production.",
                                cwe_id="CWE-489",
                            )
            except Exception:
                pass
            return None

    async def scan(self, target: str, **kwargs: Any) -> List[Finding]:
        base_url = normalize_target(target)
        findings: List[Finding] = []

        self.report_progress(5.0, f"Checking {len(ENDPOINTS)} endpoints")

        semaphore = asyncio.Semaphore(self.threads)
        timeout = aiohttp.ClientTimeout(total=self.timeout)

        async with aiohttp.ClientSession(timeout=timeout) as session:
            tasks = [
                self._check_endpoint(session, base_url, path, config, semaphore)
                for path, config in ENDPOINTS.items()
            ]

            for i, coro in enumerate(asyncio.as_completed(tasks)):
                result = await coro
                if result:
                    findings.append(result)
                if (i + 1) % 10 == 0:
                    progress = ((i + 1) / len(tasks)) * 90 + 5
                    self.report_progress(progress, f"Checked {i + 1}/{len(tasks)} endpoints")

        if not findings:
            findings.append(Finding(
                scanner=self.name, type="Endpoint Scan", severity=Severity.INFO,
                title="No exposed dev/debug endpoints found",
                description="No common development or debug endpoints are publicly accessible.",
                location=base_url,
            ))

        self.report_progress(100.0, f"Found {len(findings)} exposed endpoints")
        return findings
