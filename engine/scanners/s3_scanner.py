"""
S3 bucket misconfiguration scanner.

Checks for publicly accessible S3 buckets using common naming
patterns derived from the target domain.
"""

from __future__ import annotations

from typing import Any, List

import aiohttp

from engine.models.finding import Finding, Severity
from engine.scanners.base import BaseScanner
from engine.scanners.registry import ScannerRegistry
from engine.utils.network import extract_domain
from engine import config


@ScannerRegistry.register
class S3Scanner(BaseScanner):

    @property
    def name(self) -> str:
        return "s3_bucket"

    @property
    def display_name(self) -> str:
        return "S3 Bucket Scanner"

    @property
    def description(self) -> str:
        return "Detect publicly accessible AWS S3 buckets via naming pattern enumeration"

    async def _check_bucket(self, bucket_name: str, session: aiohttp.ClientSession) -> dict | None:
        """Check if a specific S3 bucket exists and is publicly accessible."""
        url = f"https://{bucket_name}.s3.amazonaws.com"
        try:
            async with session.get(url, ssl=False) as resp:
                if resp.status == 200:
                    body = await resp.text()
                    return {"bucket": bucket_name, "status": "PUBLIC_READ", "url": url, "body_preview": body[:500]}
                elif resp.status == 403:
                    return {"bucket": bucket_name, "status": "EXISTS_BUT_FORBIDDEN", "url": url}
                # 404 = doesn't exist, skip
        except Exception:
            pass
        return None

    async def scan(self, target: str, **kwargs: Any) -> List[Finding]:
        domain = extract_domain(target)
        # Generate bucket name candidates from domain
        base_name = domain.replace(".", "-").replace("www-", "")
        candidates = [p.format(target=base_name) for p in config.S3_BUCKET_PATTERNS]

        findings: List[Finding] = []
        self.report_progress(5.0, f"Checking {len(candidates)} bucket patterns")

        timeout = aiohttp.ClientTimeout(total=self.timeout)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            for i, bucket_name in enumerate(candidates):
                result = await self._check_bucket(bucket_name, session)
                progress = ((i + 1) / len(candidates)) * 90 + 5
                self.report_progress(progress, f"Checked {bucket_name}")

                if result:
                    if result["status"] == "PUBLIC_READ":
                        findings.append(Finding(
                            scanner=self.name,
                            type="Public S3 Bucket",
                            severity=Severity.CRITICAL,
                            title=f"Publicly readable S3 bucket: {result['bucket']}",
                            description=(
                                f"The S3 bucket '{result['bucket']}' is publicly accessible. "
                                f"Anyone can list and download its contents."
                            ),
                            evidence=result.get("body_preview", ""),
                            location=result["url"],
                            remediation="Set bucket ACL to private. Enable S3 Block Public Access.",
                            cwe_id="CWE-284",
                        ))
                    elif result["status"] == "EXISTS_BUT_FORBIDDEN":
                        findings.append(Finding(
                            scanner=self.name,
                            type="S3 Bucket Exists",
                            severity=Severity.LOW,
                            title=f"S3 bucket exists but is not public: {result['bucket']}",
                            description=(
                                f"The S3 bucket '{result['bucket']}' exists but returns 403. "
                                f"This confirms bucket existence which aids targeted attacks."
                            ),
                            location=result["url"],
                            remediation="Consider using randomized bucket names to avoid enumeration.",
                        ))

        if not findings:
            findings.append(Finding(
                scanner=self.name, type="S3 Bucket Scan", severity=Severity.INFO,
                title="No publicly accessible S3 buckets found",
                description=f"No S3 buckets matching common patterns for {domain} were found.",
                location=domain,
            ))

        self.report_progress(100.0, "S3 bucket scan complete")
        return findings
