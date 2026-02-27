"""
OWASP Top 10 2025 Mapper.

Maps CWE IDs to OWASP Top 10 categories for compliance reporting.
Based on the official CWE → OWASP mapping from OWASP Foundation.
"""

from __future__ import annotations

from typing import Optional

# OWASP Top 10 2025 category definitions
OWASP_CATEGORIES = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable & Outdated Components",
    "A07": "Identification & Authentication Failures",
    "A08": "Software & Data Integrity Failures",
    "A09": "Security Logging & Monitoring Failures",
    "A10": "Server-Side Request Forgery",
}

# CWE → OWASP Top 10 mapping (commonly tested CWEs)
CWE_TO_OWASP: dict[str, str] = {
    # A01: Broken Access Control
    "CWE-22": "A01",    # Path Traversal
    "CWE-284": "A01",   # Improper Access Control
    "CWE-285": "A01",   # Improper Authorization
    "CWE-352": "A01",   # CSRF
    "CWE-384": "A01",   # Session Fixation
    "CWE-601": "A01",   # Open Redirect
    "CWE-639": "A01",   # IDOR
    "CWE-942": "A01",   # CORS Misconfiguration

    # A02: Cryptographic Failures
    "CWE-261": "A02",   # Weak Encoding for Password
    "CWE-296": "A02",   # Improper Certificate Validation
    "CWE-310": "A02",   # Cryptographic Issues
    "CWE-319": "A02",   # Cleartext Transmission
    "CWE-326": "A02",   # Inadequate Encryption Strength
    "CWE-327": "A02",   # Use of Broken Crypto Algorithm
    "CWE-330": "A02",   # Insufficient Randomness
    "CWE-614": "A02",   # Sensitive Cookie Without Secure
    "CWE-798": "A02",   # Use of Hard-coded Credentials

    # A03: Injection
    "CWE-77": "A03",    # Command Injection
    "CWE-78": "A03",    # OS Command Injection
    "CWE-79": "A03",    # XSS
    "CWE-89": "A03",    # SQL Injection
    "CWE-91": "A03",    # XML Injection
    "CWE-94": "A03",    # Code Injection
    "CWE-611": "A03",   # XXE
    "CWE-917": "A03",   # SSTI
    "CWE-1336": "A03",  # Template Injection

    # A04: Insecure Design
    "CWE-209": "A04",   # Error Message Information Leak
    "CWE-256": "A04",   # Plaintext Storage of Password
    "CWE-312": "A04",   # Cleartext Storage of Sensitive Info
    "CWE-501": "A04",   # Trust Boundary Violation

    # A05: Security Misconfiguration
    "CWE-16": "A05",    # Configuration
    "CWE-200": "A05",   # Information Exposure
    "CWE-1004": "A05",  # Sensitive Cookie Without HttpOnly
    "CWE-1021": "A05",  # Improper Restriction of Rendered UI Layers

    # A06: Vulnerable & Outdated Components
    "CWE-1035": "A06",  # Use of Known Vulnerable Components
    "CWE-1104": "A06",  # Use of Unmaintained Third Party Components

    # A07: Identification & Authentication Failures
    "CWE-287": "A07",   # Improper Authentication
    "CWE-345": "A07",   # Insufficient Verification of Authenticity
    "CWE-384": "A07",   # Session Fixation (also A01)
    "CWE-613": "A07",   # Insufficient Session Expiration

    # A08: Software & Data Integrity Failures
    "CWE-345": "A08",   # Insufficient Verification (also A07)
    "CWE-502": "A08",   # Deserialization of Untrusted Data

    # A09: Security Logging & Monitoring Failures
    "CWE-223": "A09",   # Omission of Security-relevant Information
    "CWE-778": "A09",   # Insufficient Logging

    # A10: Server-Side Request Forgery
    "CWE-918": "A10",   # SSRF
}


def map_cwe_to_owasp(cwe_id: Optional[str]) -> Optional[str]:
    """
    Map a CWE ID to an OWASP Top 10 2025 category.

    Args:
        cwe_id: CWE identifier string (e.g., 'CWE-79')

    Returns:
        OWASP category code (e.g., 'A03') or None if unmapped.
    """
    if not cwe_id:
        return None
    return CWE_TO_OWASP.get(cwe_id)


def get_owasp_label(code: str) -> str:
    """Get the full OWASP category label from its code."""
    return OWASP_CATEGORIES.get(code, "Unknown")


def get_full_owasp_label(cwe_id: Optional[str]) -> Optional[str]:
    """
    Map a CWE ID directly to a full OWASP label.
    E.g., 'CWE-79' → 'A03: Injection'
    """
    code = map_cwe_to_owasp(cwe_id)
    if not code:
        return None
    return f"{code}: {get_owasp_label(code)}"
