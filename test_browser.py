import asyncio
from engine.agents.orchestrator import ScanOrchestrator
from engine.models.scan import ScanModule

# Ensure scanners are loaded
import engine.main 

async def main():
    orchestrator = ScanOrchestrator()
    print("Starting scan (Crawler + Browser) on http://testphp.vulnweb.com")
    
    def progress(mod, pct, msg):
        print(f"[{mod}] {pct:.1f}% - {msg}")
        
    orchestrator.set_progress_handler(progress)
    
    # Run the scan.
    result = await orchestrator.run_scan(
        scan_id="test-browser-123",
        target="http://testphp.vulnweb.com",
        modules=[ScanModule.CRAWLER, ScanModule.BROWSER],
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
        print(f"  Location: {f.get('location', '')}")
        print(f"  Description: {f.get('description', '')}")
        print(f"  Evidence: {f.get('evidence', '')}")
            
if __name__ == "__main__":
    asyncio.run(main())
