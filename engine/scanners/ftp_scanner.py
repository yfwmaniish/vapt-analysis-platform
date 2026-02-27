"""
FTP anonymous access scanner.

Checks if the target allows anonymous FTP login,
which can expose sensitive files.
"""

from __future__ import annotations

import asyncio
import ftplib
from typing import Any, List

from engine.models.finding import Finding, Severity
from engine.scanners.base import BaseScanner
from engine.scanners.registry import ScannerRegistry
from engine.utils.network import extract_domain, resolve_host


ANONYMOUS_USERS = ["anonymous", "ftp", "guest"]
FTP_DEFAULT_PORT = 21


@ScannerRegistry.register
class FTPScanner(BaseScanner):

    @property
    def name(self) -> str:
        return "ftp"

    @property
    def display_name(self) -> str:
        return "FTP Scanner"

    @property
    def description(self) -> str:
        return "Detect anonymous FTP login and exposed file listings"

    async def _try_anonymous_login(self, host: str, port: int, username: str) -> dict | None:
        """Attempt anonymous FTP login with a specific username."""
        loop = asyncio.get_event_loop()

        def _attempt():
            try:
                ftp = ftplib.FTP()
                ftp.connect(host, port, timeout=self.timeout)
                banner = ftp.getwelcome()
                ftp.login(username, "anonymous@example.com")

                # Try to list files
                files = []
                try:
                    files = ftp.nlst()[:20]  # Limit to first 20 entries
                except ftplib.error_perm:
                    pass

                ftp.quit()
                return {
                    "username": username,
                    "banner": banner,
                    "files": files,
                    "success": True,
                }
            except (ftplib.all_errors, OSError):
                return None

        return await loop.run_in_executor(None, _attempt)

    async def scan(self, target: str, **kwargs: Any) -> List[Finding]:
        domain = extract_domain(target)
        ip = await resolve_host(domain)
        host = ip or domain
        port = kwargs.get("port", FTP_DEFAULT_PORT)
        findings: List[Finding] = []

        self.report_progress(10.0, f"Attempting FTP connections to {host}:{port}")

        for i, username in enumerate(ANONYMOUS_USERS):
            result = await self._try_anonymous_login(host, port, username)
            progress = ((i + 1) / len(ANONYMOUS_USERS)) * 80 + 10
            self.report_progress(progress, f"Tried {username}@{host}")

            if result and result.get("success"):
                files_str = "\n".join(f"  • {f}" for f in result["files"]) if result["files"] else "No files listed"
                findings.append(Finding(
                    scanner=self.name,
                    type="Anonymous FTP Access",
                    severity=Severity.HIGH,
                    title=f"Anonymous FTP login allowed as '{username}'",
                    description=(
                        f"The FTP server at {domain}:{port} allows anonymous login "
                        f"with username '{username}'. This can expose sensitive files."
                    ),
                    evidence=f"Banner: {result['banner']}\nFiles:\n{files_str}",
                    location=f"{domain}:{port}",
                    remediation="Disable anonymous FTP access or restrict to read-only with only public files.",
                    cwe_id="CWE-284",
                ))
                break  # One successful login is enough

        if not findings:
            findings.append(Finding(
                scanner=self.name, type="FTP Scan", severity=Severity.INFO,
                title=f"No anonymous FTP access on {domain}:{port}",
                description="Anonymous FTP login is not available.",
                location=f"{domain}:{port}",
            ))

        self.report_progress(100.0, "FTP scan complete")
        return findings
