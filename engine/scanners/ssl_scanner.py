"""
SSL/TLS certificate and configuration analyzer.

Checks certificate validity, protocol support, cipher strength,
and common SSL misconfigurations.
"""

from __future__ import annotations

import asyncio
import ssl
import socket
from datetime import datetime, timezone
from typing import Any, Dict, List

from engine.models.finding import Finding, Severity
from engine.scanners.base import BaseScanner
from engine.scanners.registry import ScannerRegistry
from engine.utils.network import extract_domain


# Weak protocols and ciphers
WEAK_PROTOCOLS = ["TLSv1", "TLSv1.1", "SSLv2", "SSLv3"]
WEAK_CIPHERS = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT"]


@ScannerRegistry.register
class SSLScanner(BaseScanner):

    @property
    def name(self) -> str:
        return "ssl_scan"

    @property
    def display_name(self) -> str:
        return "SSL/TLS Analyzer"

    @property
    def description(self) -> str:
        return "Analyze SSL/TLS certificates, protocols, and cipher configuration"

    async def _get_cert_info(self, domain: str, port: int = 443) -> Dict[str, Any]:
        """Fetch SSL certificate information from the target."""
        loop = asyncio.get_event_loop()

        def _fetch():
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((domain, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    cipher = ssock.cipher()
                    protocol = ssock.version()
                    der_cert = ssock.getpeercert(binary_form=True)

                    return {
                        "cert": cert,
                        "cipher": cipher,
                        "protocol": protocol,
                        "der_cert": der_cert,
                    }

        return await loop.run_in_executor(None, _fetch)

    async def _check_protocol(self, domain: str, port: int, protocol_const: int, protocol_name: str) -> bool:
        """Check if a specific SSL/TLS protocol version is supported."""
        loop = asyncio.get_event_loop()

        def _check():
            try:
                ctx = ssl.SSLContext(protocol_const)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((domain, port), timeout=self.timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=domain):
                        return True
            except (ssl.SSLError, OSError, ConnectionRefusedError):
                return False

        try:
            return await loop.run_in_executor(None, _check)
        except Exception:
            return False

    async def scan(self, target: str, **kwargs: Any) -> List[Finding]:
        domain = extract_domain(target)
        port = kwargs.get("port", 443)
        findings: List[Finding] = []

        self.report_progress(10.0, f"Connecting to {domain}:{port}")

        # Fetch certificate
        try:
            info = await self._get_cert_info(domain, port)
        except Exception as exc:
            findings.append(Finding(
                scanner=self.name, type="SSL Connection Failed", severity=Severity.HIGH,
                title=f"Cannot establish SSL connection to {domain}:{port}",
                description=f"SSL handshake failed: {exc}. The server may not support HTTPS.",
                location=f"{domain}:{port}",
            ))
            return findings

        cert = info.get("cert", {})
        cipher = info.get("cipher", ())
        protocol = info.get("protocol", "Unknown")

        self.report_progress(40.0, "Analyzing certificate")

        # ── Certificate Expiry ──────────────────────────────
        if cert:
            not_after = cert.get("notAfter", "")
            if not_after:
                try:
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    expiry = expiry.replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    days_left = (expiry - now).days

                    if days_left < 0:
                        findings.append(Finding(
                            scanner=self.name, type="Expired Certificate", severity=Severity.CRITICAL,
                            title=f"SSL certificate expired {abs(days_left)} days ago",
                            description=f"The SSL certificate for {domain} expired on {not_after}.",
                            evidence=f"Expiry: {not_after}", location=f"{domain}:{port}",
                            remediation="Renew the SSL certificate immediately.",
                            cwe_id="CWE-295",
                        ))
                    elif days_left < 30:
                        findings.append(Finding(
                            scanner=self.name, type="Certificate Expiring Soon", severity=Severity.MEDIUM,
                            title=f"SSL certificate expires in {days_left} days",
                            description=f"Certificate for {domain} expires on {not_after}.",
                            evidence=f"Days remaining: {days_left}", location=f"{domain}:{port}",
                            remediation="Renew the SSL certificate before it expires.",
                        ))
                except ValueError:
                    pass

            # ── Self-Signed Check ──────────────────────────
            issuer = dict(x[0] for x in cert.get("issuer", []))
            subject = dict(x[0] for x in cert.get("subject", []))
            if issuer == subject:
                findings.append(Finding(
                    scanner=self.name, type="Self-Signed Certificate", severity=Severity.HIGH,
                    title="Self-signed SSL certificate detected",
                    description=f"The certificate for {domain} is self-signed and will not be trusted by browsers.",
                    evidence=f"Issuer: {issuer.get('commonName', 'Unknown')}",
                    location=f"{domain}:{port}",
                    remediation="Use a certificate from a trusted CA (e.g., Let's Encrypt).",
                    cwe_id="CWE-295",
                ))

        # ── Protocol Version ──────────────────────────────
        self.report_progress(60.0, "Checking protocol versions")
        if protocol in WEAK_PROTOCOLS:
            findings.append(Finding(
                scanner=self.name, type="Weak TLS Protocol", severity=Severity.HIGH,
                title=f"Weak protocol {protocol} in use",
                description=f"{domain} is using {protocol} which has known vulnerabilities.",
                evidence=f"Active protocol: {protocol}", location=f"{domain}:{port}",
                remediation="Disable TLS 1.0 and 1.1. Use TLS 1.2+ only.",
                cwe_id="CWE-326",
            ))

        # ── Cipher Strength ──────────────────────────────
        self.report_progress(80.0, "Analyzing cipher suite")
        if cipher:
            cipher_name = cipher[0] if isinstance(cipher, tuple) else str(cipher)
            for weak in WEAK_CIPHERS:
                if weak.lower() in cipher_name.lower():
                    findings.append(Finding(
                        scanner=self.name, type="Weak Cipher Suite", severity=Severity.HIGH,
                        title=f"Weak cipher detected: {cipher_name}",
                        description=f"The cipher {cipher_name} uses {weak} which is considered insecure.",
                        evidence=f"Cipher: {cipher_name}", location=f"{domain}:{port}",
                        remediation=f"Disable {weak}-based ciphers. Use AES-256-GCM or ChaCha20.",
                        cwe_id="CWE-327",
                    ))

        # If no issues found, add an info finding
        if not findings:
            findings.append(Finding(
                scanner=self.name, type="SSL Configuration", severity=Severity.INFO,
                title=f"SSL certificate valid for {domain}",
                description=f"SSL/TLS configuration looks secure. Protocol: {protocol}.",
                location=f"{domain}:{port}",
            ))

        self.report_progress(100.0, "SSL analysis complete")
        return findings
