import asyncio
from engine.scanners.jwt_scanner import JWTScanner
from engine.scanners.session_scanner import SessionScanner

async def test_auth_audit():
    target_url = "http://testphp.vulnweb.com"
    
    # ── 1. Test Enhanced JWT Scanner ──────────────────────────
    print("=" * 60)
    print("[*] Testing Enhanced JWT Scanner")
    print("=" * 60)
    
    jwt = JWTScanner()
    jwt.set_progress_callback(lambda p, m: None)
    
    # Test with a sample HS256 token signed with "secret"
    # header: {"alg":"HS256","typ":"JWT"}, payload: {"sub":"1234","name":"test","password":"hunter2"}
    sample_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0IiwibmFtZSI6InRlc3QiLCJwYXNzd29yZCI6Imh1bnRlcjIifQ.YWRtaW4"
    
    findings_jwt = await jwt.scan(target_url, jwt_token=sample_token)
    
    print(f"\n[!] JWT Findings ({len(findings_jwt)}):")
    for f in findings_jwt:
        print(f"  - [{f.severity.value.upper()}] {f.title}")
        if f.evidence:
            print(f"    Evidence: {f.evidence[:80]}")
    
    # ── 2. Test Session Security Scanner ──────────────────────
    print("\n" + "=" * 60)
    print("[*] Testing Session Security Scanner")
    print("=" * 60)
    
    session = SessionScanner()
    session.set_progress_callback(lambda p, m: None)
    
    findings_session = await session.scan(target_url)
    
    print(f"\n[!] Session Findings ({len(findings_session)}):")
    for f in findings_session:
        print(f"  - [{f.severity.value.upper()}] {f.title}")
        if f.evidence:
            print(f"    Evidence: {f.evidence[:80]}")
    
    print("\n[✓] Auth Audit Test Complete")

if __name__ == "__main__":
    asyncio.run(test_auth_audit())
