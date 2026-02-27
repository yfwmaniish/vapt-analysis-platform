"""
Async port scanner with service/banner detection.

Scans common ports, identifies running services, and detects
potentially dangerous open ports.
"""

from __future__ import annotations

import asyncio
import socket
from typing import Any, Dict, List

from engine.models.finding import Finding, Severity
from engine.scanners.base import BaseScanner
from engine.scanners.registry import ScannerRegistry
from engine.utils.network import extract_domain, resolve_host


# Well-known port → service mapping
SERVICE_MAP: Dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
    8888: "HTTP-Alt", 9200: "Elasticsearch", 27017: "MongoDB",
}

# Ports that are inherently risky when exposed
RISKY_PORTS = {
    21: ("FTP exposes unencrypted file transfer", Severity.MEDIUM),
    23: ("Telnet transmits credentials in cleartext", Severity.HIGH),
    135: ("MSRPC can be exploited for remote code execution", Severity.HIGH),
    139: ("NetBIOS can leak system information", Severity.MEDIUM),
    445: ("SMB is a common ransomware attack vector", Severity.HIGH),
    1433: ("MSSQL exposed to internet is a critical risk", Severity.CRITICAL),
    3306: ("MySQL exposed to internet allows brute-force attacks", Severity.CRITICAL),
    3389: ("RDP exposed is a top attack vector for ransomware", Severity.HIGH),
    5432: ("PostgreSQL exposed to internet is critical", Severity.CRITICAL),
    5900: ("VNC often has weak authentication", Severity.HIGH),
    6379: ("Redis without auth allows data exfiltration", Severity.CRITICAL),
    9200: ("Elasticsearch exposed leaks sensitive data", Severity.CRITICAL),
    27017: ("MongoDB without auth is a critical vulnerability", Severity.CRITICAL),
}

DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379,
    8080, 8443, 8888, 9200, 27017,
]


@ScannerRegistry.register
class PortScanner(BaseScanner):

    @property
    def name(self) -> str:
        return "port_scan"

    @property
    def display_name(self) -> str:
        return "Port Scanner"

    @property
    def description(self) -> str:
        return "Async port scanning with service detection and risk assessment"

    async def _check_port(
        self, ip: str, port: int, semaphore: asyncio.Semaphore
    ) -> dict | None:
        """Check if a single port is open and grab banner if possible."""
        async with semaphore:
            try:
                future = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(future, timeout=self.timeout)

                # Try to grab a service banner
                banner = ""
                try:
                    writer.write(b"\r\n")
                    await writer.drain()
                    data = await asyncio.wait_for(reader.read(1024), timeout=2)
                    banner = data.decode("utf-8", errors="replace").strip()
                except (asyncio.TimeoutError, Exception):
                    pass
                finally:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass

                service = SERVICE_MAP.get(port, "Unknown")
                return {"port": port, "service": service, "banner": banner, "state": "open"}

            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return None

    async def scan(self, target: str, **kwargs: Any) -> List[Finding]:
        domain = extract_domain(target)
        ip = await resolve_host(domain)
        if not ip:
            return [Finding(
                scanner=self.name, type="DNS Resolution Failed", severity=Severity.INFO,
                title=f"Cannot resolve {domain}",
                description=f"DNS lookup for {domain} failed. Port scan skipped.",
            )]

        self.report_progress(5.0, f"Resolved {domain} → {ip}")
        ports = kwargs.get("ports", DEFAULT_PORTS)
        semaphore = asyncio.Semaphore(self.threads)

        # Scan all ports concurrently
        tasks = [self._check_port(ip, port, semaphore) for port in ports]
        total = len(tasks)
        results = []

        for i, coro in enumerate(asyncio.as_completed(tasks)):
            result = await coro
            if result:
                results.append(result)
            progress = ((i + 1) / total) * 90 + 5
            self.report_progress(progress, f"Scanned {i + 1}/{total} ports")

        # Generate findings
        findings: List[Finding] = []

        if not results:
            findings.append(Finding(
                scanner=self.name, type="Port Scan", severity=Severity.INFO,
                title="No open ports detected",
                description=f"No open ports found on {domain} ({ip}) from the scanned range.",
                location=f"{domain} ({ip})",
            ))
            return findings

        # Report each open port
        for result in sorted(results, key=lambda r: r["port"]):
            port = result["port"]
            service = result["service"]
            banner = result["banner"]

            # Check if this port is inherently risky
            if port in RISKY_PORTS:
                risk_desc, severity = RISKY_PORTS[port]
                findings.append(Finding(
                    scanner=self.name,
                    type="Risky Open Port",
                    severity=severity,
                    title=f"Port {port} ({service}) is open — {risk_desc}",
                    description=(
                        f"Port {port} ({service}) is open on {domain} ({ip}). "
                        f"{risk_desc}. This port should not be exposed to the internet."
                    ),
                    evidence=f"Banner: {banner}" if banner else None,
                    location=f"{domain}:{port}",
                    remediation=f"Close port {port} or restrict access via firewall rules.",
                ))
            else:
                findings.append(Finding(
                    scanner=self.name,
                    type="Open Port",
                    severity=Severity.INFO,
                    title=f"Port {port} ({service}) is open",
                    description=f"Port {port} running {service} on {domain} ({ip}).",
                    evidence=f"Banner: {banner}" if banner else None,
                    location=f"{domain}:{port}",
                ))

        self.report_progress(100.0, f"Found {len(results)} open ports")
        return findings
