"""
Subdomain enumeration using multiple techniques.

Uses DNS brute-force with a built-in wordlist and Certificate
Transparency log queries (crt.sh).
"""

from __future__ import annotations

import asyncio
from typing import Any, List, Set

import aiohttp

from engine.models.finding import Finding, Severity
from engine.scanners.base import BaseScanner
from engine.scanners.registry import ScannerRegistry
from engine.utils.network import extract_domain, resolve_host


# Common subdomains to brute-force
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "webmail", "smtp", "pop", "ns1", "ns2",
    "blog", "shop", "dev", "staging", "test", "api", "cdn", "media",
    "static", "app", "portal", "vpn", "remote", "secure", "login",
    "dashboard", "monitor", "status", "docs", "wiki", "git", "gitlab",
    "jenkins", "ci", "cd", "internal", "intranet", "beta", "alpha",
    "sandbox", "demo", "preview", "old", "new", "backup", "db",
    "database", "redis", "elastic", "kibana", "grafana", "prometheus",
    "sentry", "auth", "sso", "oauth", "id", "accounts", "billing",
    "payments", "support", "help", "forum", "community", "m", "mobile",
]


@ScannerRegistry.register
class SubdomainScanner(BaseScanner):

    @property
    def name(self) -> str:
        return "subdomain"

    @property
    def display_name(self) -> str:
        return "Subdomain Enumerator"

    @property
    def description(self) -> str:
        return "Enumerate subdomains using DNS brute-force and Certificate Transparency logs"

    async def _query_crtsh(self, domain: str) -> Set[str]:
        """Query crt.sh Certificate Transparency logs for subdomains."""
        subdomains: Set[str] = set()
        url = f"https://crt.sh/?q=%.{domain}&output=json"

        try:
            timeout = aiohttp.ClientTimeout(total=15)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, ssl=False) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        for entry in data:
                            name = entry.get("name_value", "")
                            for line in name.split("\n"):
                                line = line.strip().lower()
                                if line.endswith(f".{domain}") or line == domain:
                                    # Remove wildcards
                                    clean = line.lstrip("*.")
                                    if clean:
                                        subdomains.add(clean)
        except Exception:
            pass  # crt.sh can be slow or down; don't fail the whole scan

        return subdomains

    async def _dns_bruteforce(self, domain: str) -> Set[str]:
        """Brute-force subdomains by attempting DNS resolution."""
        found: Set[str] = set()
        semaphore = asyncio.Semaphore(self.threads)

        async def _check(sub: str):
            async with semaphore:
                fqdn = f"{sub}.{domain}"
                ip = await resolve_host(fqdn)
                if ip:
                    found.add(fqdn)

        tasks = [_check(sub) for sub in COMMON_SUBDOMAINS]
        await asyncio.gather(*tasks)
        return found

    async def scan(self, target: str, **kwargs: Any) -> List[Finding]:
        domain = extract_domain(target)
        findings: List[Finding] = []

        self.report_progress(5.0, f"Starting subdomain enumeration for {domain}")

        # Run both methods concurrently
        crtsh_task = self._query_crtsh(domain)
        dns_task = self._dns_bruteforce(domain)

        self.report_progress(10.0, "Running DNS brute-force + crt.sh query")
        crtsh_results, dns_results = await asyncio.gather(crtsh_task, dns_task)

        all_subdomains = crtsh_results | dns_results
        all_subdomains.discard(domain)  # Remove the base domain

        self.report_progress(80.0, f"Found {len(all_subdomains)} subdomains")

        if not all_subdomains:
            findings.append(Finding(
                scanner=self.name, type="Subdomain Enumeration", severity=Severity.INFO,
                title=f"No subdomains found for {domain}",
                description="No additional subdomains were discovered.",
                location=domain,
            ))
        else:
            # Resolve IPs for found subdomains
            resolved = {}
            for sub in sorted(all_subdomains):
                ip = await resolve_host(sub)
                resolved[sub] = ip or "Unresolved"

            subdomain_list = "\n".join(
                f"  • {sub} → {ip}" for sub, ip in resolved.items()
            )

            findings.append(Finding(
                scanner=self.name, type="Subdomain Enumeration", severity=Severity.INFO,
                title=f"Found {len(all_subdomains)} subdomains for {domain}",
                description=f"Subdomain enumeration discovered {len(all_subdomains)} subdomains.",
                evidence=subdomain_list,
                location=domain,
            ))

            # Flag sensitive subdomains
            sensitive_prefixes = [
                "admin", "staging", "dev", "test", "internal", "intranet",
                "backup", "db", "database", "jenkins", "gitlab", "redis",
                "elastic", "kibana", "grafana", "sentry",
            ]
            for sub in all_subdomains:
                prefix = sub.split(".")[0]
                if prefix in sensitive_prefixes:
                    findings.append(Finding(
                        scanner=self.name, type="Sensitive Subdomain", severity=Severity.MEDIUM,
                        title=f"Sensitive subdomain exposed: {sub}",
                        description=(
                            f"The subdomain '{sub}' suggests an internal or sensitive service "
                            f"that should not be publicly accessible."
                        ),
                        location=sub,
                        remediation=f"Restrict access to {sub} via firewall or VPN.",
                    ))

        self.report_progress(100.0, "Subdomain enumeration complete")
        return findings
