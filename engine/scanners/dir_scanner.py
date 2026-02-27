"""
Directory and file brute-force scanner.

Probes for common hidden directories and files on web servers
using a wordlist.
"""

from __future__ import annotations

import asyncio
from typing import Any, List

import aiohttp

from engine.models.finding import Finding, Severity
from engine.scanners.base import BaseScanner
from engine.scanners.registry import ScannerRegistry
from engine.utils.network import normalize_target
from engine import config


# Default wordlist of common directories
DEFAULT_WORDLIST = [
    ".git", ".git/config", ".svn", ".env", ".htaccess", ".htpasswd",
    "backup", "backups", "backup.zip", "backup.tar.gz", "backup.sql",
    "db", "database", "dump.sql", "phpmyadmin", "adminer",
    "wp-admin", "wp-login.php", "wp-config.php.bak",
    "admin", "administrator", "panel", "cpanel", "dashboard",
    "config.php", "config.yml", "config.json", "config.bak",
    "robots.txt", "sitemap.xml", "crossdomain.xml",
    "server-status", "server-info", ".well-known",
    "api", "api/v1", "api/v2", "swagger", "api-docs", "docs",
    "graphql", "graphiql",
    "debug", "test", "testing", "staging", "dev",
    "uploads", "upload", "files", "media", "assets",
    "logs", "log", "error_log", "access_log",
    "tmp", "temp", "cache", "private", "secret",
    "console", "shell", "terminal", "cmd",
    "info.php", "phpinfo.php", "test.php",
    ".DS_Store", "Thumbs.db", "web.config",
    "package.json", "composer.json", "Gemfile",
    ".dockerenv", "docker-compose.yml", "Dockerfile",
    "Makefile", ".travis.yml", "Jenkinsfile",
]

# Paths that are especially sensitive
CRITICAL_PATHS = {
    ".git/config": "Git repository configuration exposed — source code may be downloadable",
    ".env": "Environment file exposed — may contain API keys, database credentials",
    "backup.sql": "SQL backup exposed — contains database dumps",
    "dump.sql": "SQL dump exposed — contains database data",
    ".htpasswd": "Password file exposed — contains hashed credentials",
    "wp-config.php.bak": "WordPress config backup — contains database credentials",
    "config.php": "Configuration file exposed — may contain credentials",
    "docker-compose.yml": "Docker config exposed — reveals infrastructure",
}

# Paths to ignore as they are standard public files and cause noise
IGNORE_PATHS = {
    "robots.txt",
    "sitemap.xml",
    "favicon.ico",
    "crossdomain.xml",
}


@ScannerRegistry.register
class DirScanner(BaseScanner):

    @property
    def name(self) -> str:
        return "dir_bruteforce"

    @property
    def display_name(self) -> str:
        return "Directory Scanner"

    @property
    def description(self) -> str:
        return "Brute-force scan for hidden directories, config files, and backups"

    async def _get_fingerprint(self, session: aiohttp.ClientSession, base_url: str) -> dict | None:
        """Probe a non-existent path to detect Universal 200/Soft 404 behavior."""
        import uuid
        random_path = f"vapt-probe-{uuid.uuid4().hex}"
        url = f"{base_url.rstrip('/')}/{random_path}"
        try:
            async with session.get(url, ssl=False, allow_redirects=False) as resp:
                # If the server returns success for a non-existent path, it's doing Soft 404
                if resp.status in (200, 301, 302, 403):
                    text = await resp.text()
                    return {
                        "status": resp.status,
                        "content_length": resp.headers.get("Content-Length"),
                        "snippet": text[:100] if text else ""
                    }
        except Exception:
            pass
        return None

    async def _check_path(
        self, session: aiohttp.ClientSession, base_url: str, path: str,
        semaphore: asyncio.Semaphore, fingerprint: dict | None = None
    ) -> dict | None:
        """Check if a path exists on the target server, dodging false positives."""
        async with semaphore:
            url = f"{base_url.rstrip('/')}/{path}"
            try:
                async with session.get(url, ssl=False, allow_redirects=False) as resp:
                    if resp.status in (200, 301, 302, 403):
                        content_length = resp.headers.get("Content-Length")
                        
                        # Compare against fingerprint to detect false positives
                        if fingerprint:
                            if resp.status == fingerprint["status"]:
                                text = await resp.text()
                                # If status and one other metric match, it's likely a false positive
                                if content_length == fingerprint["content_length"] or text[:100] == fingerprint["snippet"]:
                                    return None

                        return {
                            "path": path,
                            "url": url,
                            "status": resp.status,
                            "content_length": content_length or "Unknown",
                        }
            except Exception:
                pass
            return None

    async def scan(self, target: str, **kwargs: Any) -> Any: # Changed return type for deeper details
        base_url = normalize_target(target)
        findings: List[Finding] = []
        wordlist = kwargs.get("wordlist", DEFAULT_WORDLIST)
        discovered_paths = []

        self.report_progress(2.0, f"Initializing discovery for {base_url}")

        semaphore = asyncio.Semaphore(self.threads)
        timeout = aiohttp.ClientTimeout(total=self.timeout)

        async with aiohttp.ClientSession(timeout=timeout) as session:
            # Step 1: Detect Soft 404 / Universal 200
            self.report_progress(5.0, "Detecting server response behavior...")
            fingerprint = await self._get_fingerprint(session, base_url)
            if fingerprint:
                self.report_progress(8.0, f"⚠️ Universal {fingerprint['status']} detected. Enabling fingerprint filtering.")

            # Step 2: Run brute-force
            tasks = [
                self._check_path(session, base_url, path, semaphore, fingerprint)
                for path in wordlist
            ]

            results = []
            for i, coro in enumerate(asyncio.as_completed(tasks)):
                result = await coro
                if result:
                    results.append(result)
                    if result["status"] == 200:
                        discovered_paths.append({
                            "type": "directory",
                            "url": result["url"],
                            "status": 200,
                            "info": f"Size: {result['content_length']}"
                        })
                
                if (i + 1) % 10 == 0:
                    progress = ((i + 1) / len(tasks)) * 80 + 10
                    self.report_progress(progress, f"Scanned {i + 1}/{len(tasks)} paths")

        # Generate findings
        for result in sorted(results, key=lambda r: r["path"]):
            path = result["path"]
            status = result["status"]

            if path in IGNORE_PATHS:
                continue

            if path in CRITICAL_PATHS:
                if status == 200:
                    findings.append(Finding(
                        scanner=self.name,
                        type="Sensitive File Exposed",
                        severity=Severity.CRITICAL,
                        title=f"Sensitive file EXPOSED: /{path} (HTTP 200)",
                        description=CRITICAL_PATHS[path],
                        evidence=f"URL: {result['url']} | Status: 200 | Size: {result['content_length']}",
                        location=result["url"],
                        remediation=f"Immediately block access to /{path} via server config or .htaccess rules.",
                        cwe_id="CWE-538",
                        cvss_score=8.5,
                    ))
                elif status in (301, 302):
                    findings.append(Finding(
                        scanner=self.name,
                        type="Sensitive Path Redirect",
                        severity=Severity.MEDIUM,
                        title=f"Sensitive path redirects: /{path} (HTTP {status})",
                        description=f"/{path} redirects (HTTP {status}). Verify the redirect target does not expose the file.",
                        evidence=f"URL: {result['url']} | Status: {status}",
                        location=result["url"],
                        remediation=f"Ensure /{path} returns 404, not a redirect.",
                        cwe_id="CWE-538",
                    ))
                else:
                    findings.append(Finding(
                        scanner=self.name,
                        type="Sensitive Path Exists",
                        severity=Severity.INFO,
                        title=f"Sensitive path exists but blocked: /{path} (HTTP {status})",
                        description=f"The server returns {status} for /{path}, meaning access is denied. File is properly protected.",
                        evidence=f"URL: {result['url']} | Status: {status}",
                        location=result["url"],
                        remediation=f"Return 404 instead of {status} to avoid confirmation of path existence.",
                    ))
            elif status == 200:
                findings.append(Finding(
                    scanner=self.name,
                    type="Directory Found",
                    severity=Severity.LOW,
                    title=f"Accessible path: /{path}",
                    description=f"The path /{path} is accessible on the server.",
                    evidence=f"Status: {status} | Size: {result['content_length']}",
                    location=result["url"],
                ))

        if not findings:
            findings.append(Finding(
                scanner=self.name, type="Directory Scan", severity=Severity.INFO,
                title="No hidden directories or files found",
                description="Directory brute-force scan found no accessible paths.",
                location=base_url,
            ))

        self.report_progress(100.0, f"Found {len(results)} accessible paths")
        
        # Return both findings and discovery data
        return findings, {"paths": discovered_paths}
