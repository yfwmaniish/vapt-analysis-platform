"""
JWT token vulnerability analyzer.

Performs both passive analysis and active security tests:
- Algorithm confusion (alg:none bypass forge)
- Weak HMAC secret brute-force
- Missing/insecure claims
- Sensitive data leakage in payload
"""

from __future__ import annotations

import base64
import json
import hashlib
import hmac
from typing import Any, List

from engine.models.finding import Finding, Severity
from engine.scanners.base import BaseScanner
from engine.scanners.registry import ScannerRegistry
from engine import config


@ScannerRegistry.register
class JWTScanner(BaseScanner):

    @property
    def name(self) -> str:
        return "jwt"

    @property
    def display_name(self) -> str:
        return "JWT Analyzer"

    @property
    def description(self) -> str:
        return "Analyze JWT tokens for algorithm confusion, weak secrets, and insecure claims"

    # ── Helpers ──────────────────────────────────────────────────────

    def _decode_jwt_part(self, part: str) -> dict:
        """Decode a base64url-encoded JWT part."""
        padding = 4 - len(part) % 4
        if padding != 4:
            part += "=" * padding
        try:
            decoded = base64.urlsafe_b64decode(part)
            return json.loads(decoded)
        except Exception:
            return {}

    def _b64url_encode(self, data: bytes) -> str:
        """Base64url encode without padding."""
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")

    def _check_weak_secret(self, token: str) -> str | None:
        """Try to crack the JWT signature with common weak secrets."""
        parts = token.split(".")
        if len(parts) != 3:
            return None

        signing_input = f"{parts[0]}.{parts[1]}".encode("utf-8")
        signature = parts[2]

        padding = 4 - len(signature) % 4
        if padding != 4:
            signature += "=" * padding

        try:
            expected_sig = base64.urlsafe_b64decode(signature)
        except Exception:
            return None

        for secret in config.JWT_COMMON_SECRETS:
            computed = hmac.new(
                secret.encode("utf-8"), signing_input, hashlib.sha256
            ).digest()
            if hmac.compare_digest(computed, expected_sig):
                return secret

        return None

    def _forge_alg_none_token(self, token: str) -> str:
        """
        Actively forge a JWT with alg:none to test if the server
        would accept an unsigned token.
        Returns the forged token string.
        """
        parts = token.split(".")
        if len(parts) != 3:
            return ""

        # Modify header to set alg: none
        header = self._decode_jwt_part(parts[0])
        header["alg"] = "none"

        new_header_b64 = self._b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        # Keep original payload, strip the signature
        forged_token = f"{new_header_b64}.{parts[1]}."
        return forged_token

    # ── Main Scan Logic ─────────────────────────────────────────────

    async def scan(self, target: str, **kwargs: Any) -> List[Finding]:
        jwt_token = kwargs.get("jwt_token", "")
        if not jwt_token:
            return [Finding(
                scanner=self.name, type="JWT Analysis", severity=Severity.INFO,
                title="No JWT token provided for analysis",
                description="Provide a JWT token using the jwt_token parameter.",
            )]

        findings: List[Finding] = []
        parts = jwt_token.split(".")

        self.report_progress(5.0, "Parsing JWT token")

        if len(parts) != 3:
            findings.append(Finding(
                scanner=self.name, type="Malformed JWT", severity=Severity.MEDIUM,
                title="JWT token has invalid format",
                description=f"Expected 3 parts (header.payload.signature), got {len(parts)}.",
                evidence=jwt_token[:50] + "...",
            ))
            return findings

        header = self._decode_jwt_part(parts[0])
        payload = self._decode_jwt_part(parts[1])

        # ── 1. Algorithm Analysis ──────────────────────────────────

        self.report_progress(15.0, "Analyzing JWT algorithm")
        alg = header.get("alg", "").upper()

        if alg == "NONE":
            findings.append(Finding(
                scanner=self.name, type="JWT Algorithm None", severity=Severity.CRITICAL,
                title="JWT uses 'none' algorithm — signature validation bypassed",
                description="The JWT algorithm is set to 'none', meaning the token is unsigned.",
                evidence=f"Header: {json.dumps(header)}",
                remediation="Always enforce a specific algorithm (RS256 or ES256).",
                cwe_id="CWE-345",
            ))

        if alg in ("HS256", "HS384", "HS512"):
            findings.append(Finding(
                scanner=self.name, type="Symmetric JWT Algorithm", severity=Severity.MEDIUM,
                title=f"JWT uses symmetric algorithm ({alg})",
                description=(
                    f"The token uses {alg} (HMAC). If the secret is weak, "
                    f"anyone can forge tokens. Prefer asymmetric algorithms."
                ),
                evidence=f"Algorithm: {alg}",
                remediation="Use RS256 or ES256 (asymmetric) instead of HMAC-based algorithms.",
                cwe_id="CWE-327",
            ))

        # ── 2. Active: alg:none Forge Test ─────────────────────────

        self.report_progress(30.0, "Forging alg:none bypass token")
        if alg != "NONE":
            forged = self._forge_alg_none_token(jwt_token)
            if forged:
                findings.append(Finding(
                    scanner=self.name, type="Active Bypass Test", severity=Severity.INFO,
                    title="Generated alg:none forged token for manual verification",
                    description=(
                        "An unsigned (alg:none) version of the provided token was generated. "
                        "If the target server accepts this token, it is critically vulnerable to "
                        "authentication bypass (CWE-345). Test by replaying this token against protected endpoints."
                    ),
                    evidence=f"Forged Token: {forged[:80]}...",
                    remediation="Ensure the server explicitly rejects tokens with alg:none.",
                    cwe_id="CWE-345",
                ))

        # ── 3. Weak Secret Brute-Force ─────────────────────────────

        self.report_progress(50.0, "Brute-forcing weak HMAC secrets")
        if alg.startswith("HS"):
            weak_secret = self._check_weak_secret(jwt_token)
            if weak_secret:
                findings.append(Finding(
                    scanner=self.name, type="Weak JWT Secret", severity=Severity.CRITICAL,
                    title=f"JWT signed with weak secret: '{weak_secret}'",
                    description="The JWT secret was cracked from a list of common weak secrets.",
                    evidence=f"Secret found: {weak_secret}",
                    remediation="Use a strong, randomly generated secret (256+ bits).",
                    cwe_id="CWE-798",
                ))

        # ── 4. Missing Claims ──────────────────────────────────────

        self.report_progress(70.0, "Analyzing JWT payload claims")

        if "exp" not in payload:
            findings.append(Finding(
                scanner=self.name, type="Missing Expiration", severity=Severity.MEDIUM,
                title="JWT has no expiration (exp) claim",
                description="Tokens without expiration never become invalid, increasing risk if stolen.",
                evidence=f"Payload: {json.dumps(payload)}",
                remediation="Always include an 'exp' claim with a reasonable TTL.",
            ))

        if "iss" not in payload:
            findings.append(Finding(
                scanner=self.name, type="Missing Issuer", severity=Severity.LOW,
                title="JWT has no issuer (iss) claim",
                description="Missing 'iss' claim makes it harder to validate token origin.",
                evidence=f"Payload: {json.dumps(payload)}",
                remediation="Include an 'iss' claim to identify the token issuer.",
            ))

        if "sub" not in payload:
            findings.append(Finding(
                scanner=self.name, type="Missing Subject", severity=Severity.LOW,
                title="JWT has no subject (sub) claim",
                description="Missing 'sub' makes it unclear who the token represents.",
            ))

        # ── 5. Sensitive Data Leakage ──────────────────────────────

        self.report_progress(85.0, "Checking for sensitive data leakage")

        sensitive_keys = [
            "password", "secret", "api_key", "credit_card", "ssn",
            "token", "private_key", "access_key", "bank", "cvv",
            "pin", "social_security", "pwd", "passwd", "credential",
        ]
        for key in payload:
            if any(s in key.lower() for s in sensitive_keys):
                findings.append(Finding(
                    scanner=self.name, type="Sensitive Data in JWT", severity=Severity.HIGH,
                    title=f"JWT contains potentially sensitive claim: '{key}'",
                    description="JWTs are base64-encoded, not encrypted. Sensitive data is exposed.",
                    evidence=f"Claim: {key}",
                    remediation="Never store sensitive data in JWT payloads. Use encrypted tokens (JWE).",
                    cwe_id="CWE-312",
                ))

        if not findings:
            findings.append(Finding(
                scanner=self.name, type="JWT Analysis", severity=Severity.INFO,
                title="JWT token appears well-configured",
                description=f"Algorithm: {alg}, Claims: {list(payload.keys())}",
            ))

        self.report_progress(100.0, "JWT analysis complete")
        return findings
