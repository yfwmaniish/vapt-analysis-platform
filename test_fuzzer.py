import asyncio
import json
from engine.agents.orchestrator import ScanOrchestrator
from engine.models.scan import ScanModule

# Ensure scanners are loaded
import engine.main 

async def main():
    orchestrator = ScanOrchestrator()
    print("Starting scan (Crawler + Fuzzer) on http://testphp.vulnweb.com")
    
    def progress(mod, pct, msg):
        print(f"[{mod}] {pct}% - {msg}")
        
    orchestrator.set_progress_handler(progress)
    
    # Run the scan. We give it a long timeout because fuzzing takes time.
    result = await orchestrator.run_scan(
        scan_id="test-fuzzer-123",
        target="http://testphp.vulnweb.com",
        modules=[ScanModule.CRAWLER, ScanModule.FUZZER],
        ai_analysis=False,
        timeout=30
    )
    
    print("\n=== SCAN COMPLETE ===")
    print(f"Status: {result.status}")
    print(f"Duration: {result.duration_seconds}s")
    print(f"Modules run: {result.modules_run}")
    
    if result.attack_surface:
        surface = result.attack_surface
        print(f"\nAttack Surface: {len(surface.get('internal_urls', []))} URLs, "
              f"{len(surface.get('forms', []))} Forms, "
              f"{len(surface.get('parameters', []))} Parameters")
              
    print(f"\nTotal Findings: {len(result.findings)}")
    for f in result.findings:
        print(f"- [{f['severity']}] {f['title']}")
        if "SQLi" in f['title'] or "XSS" in f['title']:
            print(f"  Location: {f.get('location', '')}")
            print(f"  Evidence: {f.get('evidence', '')}")
            
if __name__ == "__main__":
    asyncio.run(main())
