import asyncio
from engine.scanners.crawler_scanner import CrawlerScanner
from engine.scanners.ssrf_scanner import SSRFScanner
from engine.scanners.xxe_scanner import XXEScanner
from engine.models.scan import ScanRequest

async def test_server_side():
    target_url = "http://testphp.vulnweb.com"
    print(f"[*] Testing targeted crawling and server-side attacks against {target_url}\n")
    
    # 1. Discovery Phase
    crawler = CrawlerScanner()
    
    def on_progress(percentage: float, message: str):
        pass # print(f"    [Crawler] {percentage:.1f}%: {message}")
        
    crawler.set_progress_callback(on_progress)
    
    print("[*] Running Crawler to build Attack Surface...")
    findings_crawler, attack_surface = await crawler.scan(target_url, max_depth=1)
    
    print(f"[+] Crawler finished. Found {len(attack_surface.get('internal_urls', []))} internal URLs and {len(attack_surface.get('forms', []))} forms.\n")
    
    # 2. SSRF Attack Phase
    ssrf = SSRFScanner()
    
    def on_ssrf_progress(percentage: float, message: str):
        pass # print(f"    [SSRF] {percentage:.1f}%: {message}")
        
    ssrf.set_progress_callback(on_ssrf_progress)
    
    print("[*] Running SSRF Scanner using Attack Surface...")
    findings_ssrf = await ssrf.scan(target_url, attack_surface=attack_surface)
    
    print(f"\n[!] SSRF Scanner Findings ({len(findings_ssrf)}):")
    for f in findings_ssrf:
        print(f"  - [{f.severity}] {f.title} (Location: {f.location})")
        print(f"    Evidence: {f.evidence[:100]}...")
        
    # 3. XXE Attack Phase
    xxe = XXEScanner()
    
    def on_xxe_progress(percentage: float, message: str):
        pass # print(f"    [XXE] {percentage:.1f}%: {message}")
        
    xxe.set_progress_callback(on_xxe_progress)
    
    print("\n[*] Running XXE Scanner using Attack Surface...")
    findings_xxe = await xxe.scan(target_url, attack_surface=attack_surface)
    
    print(f"\n[!] XXE Scanner Findings ({len(findings_xxe)}):")
    for f in findings_xxe:
        print(f"  - [{f.severity}] {f.title} (Location: {f.location})")
        print(f"    Evidence: {f.evidence[:100]}...")

if __name__ == "__main__":
    asyncio.run(test_server_side())
