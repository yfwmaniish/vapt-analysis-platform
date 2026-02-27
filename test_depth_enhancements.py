"""
Phase 6 Depth Enhancement Verification.
Tests all new scanners and OWASP mapping functionality.
"""

import asyncio
import sys
import os
import io

# Force UTF-8 output for Windows PowerShell
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

async def main():
    print("=" * 60)
    print("  PHASE 6: DEPTH ENHANCEMENT VERIFICATION")
    print("=" * 60)

    # 1. Import and verify all scanner registrations
    print("\n[1] Verifying scanner registry...")
    # Import ALL scanner modules (same as engine/main.py)
    import engine.scanners.port_scanner          # noqa: F401
    import engine.scanners.ssl_scanner           # noqa: F401
    import engine.scanners.subdomain_scanner     # noqa: F401
    import engine.scanners.s3_scanner            # noqa: F401
    import engine.scanners.ftp_scanner           # noqa: F401
    import engine.scanners.jwt_scanner           # noqa: F401
    import engine.scanners.header_scanner        # noqa: F401
    import engine.scanners.cookie_scanner        # noqa: F401
    import engine.scanners.dir_scanner           # noqa: F401
    import engine.scanners.endpoint_scanner      # noqa: F401
    import engine.scanners.dorking_scanner       # noqa: F401
    import engine.scanners.crawler_scanner       # noqa: F401
    import engine.scanners.fuzzer_scanner        # noqa: F401
    try:
        import engine.scanners.browser_scanner   # noqa: F401
    except Exception:
        pass  # Playwright may not be installed
    import engine.scanners.ssrf_scanner          # noqa: F401
    import engine.scanners.xxe_scanner           # noqa: F401
    import engine.scanners.session_scanner       # noqa: F401
    import engine.scanners.fingerprint_scanner   # noqa: F401
    import engine.scanners.cors_scanner          # noqa: F401
    import engine.scanners.redirect_scanner      # noqa: F401
    from engine.scanners.registry import ScannerRegistry

    scanners = ScannerRegistry.get_all()
    print(f"   ✅ {len(scanners)} scanners registered: {', '.join(scanners.keys())}")

    # Check new scanners exist
    for name in ["fingerprint", "cors", "redirect"]:
        assert name in scanners, f"Missing scanner: {name}"
    print("   ✅ All 3 new scanners verified (fingerprint, cors, redirect)")

    # 2. Test Fingerprint Scanner
    print("\n[2] Testing Fingerprint Scanner...")
    fp_scanner = scanners["fingerprint"]()
    findings = await fp_scanner.safe_scan("https://example.com")
    print(f"   ✅ Fingerprint findings: {len(findings)}")
    for f in findings:
        print(f"      [{f.severity.value.upper()}] {f.title}")

    # 3. Test CORS Scanner
    print("\n[3] Testing CORS Scanner...")
    cors_scanner = scanners["cors"]()
    findings = await cors_scanner.safe_scan("https://example.com")
    print(f"   ✅ CORS findings: {len(findings)}")
    for f in findings:
        print(f"      [{f.severity.value.upper()}] {f.title}")

    # 4. Test OWASP Mapper
    print("\n[4] Testing OWASP Mapper...")
    from engine.utils.owasp_mapper import map_cwe_to_owasp, get_full_owasp_label

    test_cases = {
        "CWE-89": "A03",    # SQLi → Injection
        "CWE-79": "A03",    # XSS → Injection
        "CWE-918": "A10",   # SSRF
        "CWE-319": "A02",   # Cleartext → Crypto
        "CWE-942": "A01",   # CORS → Access Control
        "CWE-601": "A01",   # Open Redirect → Access Control
        "CWE-1336": "A03",  # SSTI → Injection
        "CWE-78": "A03",    # Command Injection
    }

    all_passed = True
    for cwe, expected in test_cases.items():
        result = map_cwe_to_owasp(cwe)
        status = "✅" if result == expected else "❌"
        if result != expected:
            all_passed = False
        label = get_full_owasp_label(cwe) or "None"
        print(f"   {status} {cwe} → {result} ({label})")

    assert all_passed, "Some OWASP mappings failed!"
    print(f"   ✅ All {len(test_cases)} OWASP mappings verified")

    # 5. Test expanded fuzzer payloads
    print("\n[5] Verifying expanded fuzzer payloads...")
    from engine.scanners.fuzzer_scanner import (
        SQLI_PAYLOADS, SQLI_BLIND_PAYLOADS, XSS_PAYLOADS,
        XSS_POLYGLOT_PAYLOADS, SSTI_PAYLOADS, CMDI_PAYLOADS,
    )
    total = (
        len(SQLI_PAYLOADS) + len(SQLI_BLIND_PAYLOADS)
        + len(XSS_PAYLOADS) + len(XSS_POLYGLOT_PAYLOADS)
        + len(SSTI_PAYLOADS) + len(CMDI_PAYLOADS)
    )
    print(f"   SQLi Error-Based: {len(SQLI_PAYLOADS)} payloads")
    print(f"   SQLi Blind/Time:  {len(SQLI_BLIND_PAYLOADS)} payloads")
    print(f"   XSS Reflected:    {len(XSS_PAYLOADS)} payloads")
    print(f"   XSS Polyglot:     {len(XSS_POLYGLOT_PAYLOADS)} payloads")
    print(f"   SSTI:             {len(SSTI_PAYLOADS)} payloads")
    print(f"   CMDi:             {len(CMDI_PAYLOADS)} payloads")
    print(f"   ✅ Total payloads: {total} (was 8)")

    # 6. Test Finding model has owasp_category
    print("\n[6] Verifying Finding model...")
    from engine.models.finding import Finding
    f = Finding(
        scanner="test",
        type="Test",
        severity="info",
        title="Test",
        description="Test",
        cwe_id="CWE-79",
        owasp_category="A03: Injection",
    )
    assert f.owasp_category == "A03: Injection"
    print("   ✅ Finding.owasp_category field works")

    # 7. Test ScanModule enum
    print("\n[7] Verifying ScanModule enum...")
    from engine.models.scan import ScanModule
    for mod in ["FINGERPRINT", "CORS", "REDIRECT"]:
        assert hasattr(ScanModule, mod), f"Missing ScanModule.{mod}"
    print("   ✅ All new ScanModule values present")

    print("\n" + "=" * 60)
    print("  ALL VERIFICATIONS PASSED ✅")
    print(f"  Scanners: {len(scanners)} | Payloads: {total} | OWASP: {len(test_cases)} mapped")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
