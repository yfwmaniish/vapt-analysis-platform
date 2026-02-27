"""
Professional HTML report generator for scan results with visualizations.
"""

from __future__ import annotations

import html
import json
import re
from typing import Any, Dict, List

from engine import config


class ReportGenerator:
    """Generate professional HTML reports from real scan results with visualizations."""

    def generate_html(self, scan_result: Dict[str, Any], theme: str = "white") -> str:
        """Generate a full HTML report using genuine scan data. Themes: 'dark', 'white'."""
        target = scan_result.get("target", "Unknown")
        findings = scan_result.get("findings", [])
        ai_summary = scan_result.get("ai_summary", "")
        duration = scan_result.get("duration_seconds", 0)
        created_at = scan_result.get("created_at", "")
        scan_id = scan_result.get("scan_id", "")
        modules_run = scan_result.get("modules_run", [])

        # Process real data for visualizations
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        type_counts = {}
        
        for f in findings:
            sev = str(f.get("severity", "info")).lower()
            if sev in counts:
                counts[sev] += 1
            else:
                counts["info"] += 1
                
            f_type = f.get("scanner", "Unknown")
            type_counts[f_type] = type_counts.get(f_type, 0) + 1

        severity_data = [counts["critical"], counts["high"], counts["medium"], counts["low"], counts["info"]]
        module_labels = list(type_counts.keys())
        module_data = list(type_counts.values())

        # Render sections
        findings_html = self._render_findings(findings, theme)
        ai_html = self._render_ai_summary(ai_summary, theme) if ai_summary else ""
        
        # Inject JSON safely into JS
        sev_data_json = json.dumps(severity_data)
        mod_labels_json = json.dumps(module_labels)
        mod_data_json = json.dumps(module_data)

        # Theme Configuration
        is_dark = theme == "dark"
        bg_color = "#030712" if is_dark else "#ffffff"
        card_bg = "rgba(31, 41, 55, 0.4)" if is_dark else "#f8fafc"
        card_border = "rgba(255,255,255,0.05)" if is_dark else "#e2e8f0"
        title_color = "text-white" if is_dark else "text-slate-900"
        muted_color = "text-gray-400" if is_dark else "text-slate-500"
        
        modules_list_html = "".join([f'<span class="px-2 py-0.5 {"bg-gray-900 border-gray-700 text-gray-300" if is_dark else "bg-white border-slate-200 text-slate-600"} border rounded text-[10px] font-mono">{html.escape(m)}</span>' for m in modules_run])

        # Render AI summary if present
        ai_summary_html = ""
        if scan_result.get("ai_summary"):
            ai_summary_html = self._render_ai_summary(scan_result["ai_summary"], theme)

        # Render Attack Surface Inventory
        attack_surface_html = ""
        if scan_result.get("attack_surface"):
            attack_surface_html = self._render_attack_surface(scan_result["attack_surface"], theme)

        # Placeholder for other new variables introduced in the template
        findings_count = len(findings)
        metrics_html = self._render_metrics(counts, duration, len(modules_run), findings_count, theme) # Assuming a new method for metrics
        owasp_heatmap_html = self._render_owasp_heatmap(findings, theme)
        desc_color = "text-gray-300" if is_dark else "text-slate-600" # Defined here as it's used in the new template

        # Full HTML structure
        html_template = f"""<!DOCTYPE html>
<html lang="en" class="{theme}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VAPTx Security Report — {html.escape(target)}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <script>
        tailwind.config = {{
            darkMode: 'class',
            theme: {{
                extend: {{
                    fontFamily: {{ sans: ['"Plus Jakarta Sans"', 'Inter', 'sans-serif'] }},
                    colors: {{
                        gray: {{ 850: '#1f2937', 900: '#111827', 950: '#030712' }},
                        critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e', info: '#3b82f6',
                        brand: {{
                            50: '#f0f9ff',
                            100: '#e0f2fe',
                            500: '#0ea5e9',
                            600: '#0284c7',
                            700: '#0369a1',
                        }}
                    }}
                }}
            }}
        }}
    </script>
    <style>
        {self._get_css(theme)}
    </style>
</head>
<body class="bg-page min-h-screen pb-20">
    <div class="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 pt-8">
        <!-- Header -->
        <header class="flex flex-col md:flex-row md:items-center justify-between gap-6 mb-12">
            <div>
                <div class="flex items-center gap-2 mb-2">
                    <span class="px-2 py-0.5 rounded text-[10px] font-bold tracking-widest uppercase bg-brand-500 text-white">VAPTx Engine</span>
                    <span class="text-xs {muted_color}">v3.2.0 Professional</span>
                </div>
                <h1 class="text-3xl font-extrabold tracking-tight {title_color}">
                    Security Audit <span class="text-brand-500">Report</span>
                </h1>
                <p class="mt-1 text-sm {desc_color}">Generated for target: <code class="px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-brand-600 font-medium">{target}</code></p>
            </div>
            
            <div class="flex items-center gap-3">
                <div class="text-right hidden sm:block">
                    <p class="text-[10px] uppercase tracking-wider font-bold {muted_color}">Audit Date</p>
                    <p class="text-sm font-semibold {title_color}">{created_at}</p>
                </div>
                <div class="h-10 w-[1px] bg-slate-200 dark:bg-slate-700 mx-2 hidden sm:block"></div>
                <div class="flex flex-col items-center justify-center h-12 w-12 rounded-xl bg-brand-500 text-white shadow-lg shadow-brand-500/20">
                    <span class="text-xs font-bold leading-none">{findings_count}</span>
                    <span class="text-[8px] uppercase tracking-tighter">Issues</span>
                </div>
            </div>
        </header>

        {metrics_html}

        <!-- Visuals -->
        <section class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-8">
            <div class="glass card">
                <h2 class="text-[10px] font-black uppercase tracking-widest mb-4 {title_color} opacity-60">Severity Distribution</h2>
                <div class="relative h-44 w-full flex justify-center"><canvas id="severityChart"></canvas></div>
            </div>
            <div class="glass card">
                <h2 class="text-[10px] font-black uppercase tracking-widest mb-4 {title_color} opacity-60">Engine Performance</h2>
                <div class="relative h-44 w-full flex justify-center"><canvas id="moduleChart"></canvas></div>
            </div>
        </section>

        {ai_summary_html}
        {owasp_heatmap_html}
        {attack_surface_html}

        <!-- Findings -->
        <section class="mt-8 print-break">
            <h2 class="text-xs font-black uppercase tracking-widest mb-6 {title_color} border-b border-gray-500/10 pb-3 flex items-center justify-between">
                <span>Detailed Findings Registry</span>
                <span class="text-[9px] bg-indigo-600 text-white px-3 py-1 rounded-full">{len(findings)} TOTAL</span>
            </h2>
            <div class="space-y-4">{findings_html}</div>
        </section>

        <footer class="mt-16 text-center text-[9px] font-bold {muted_color} pb-12 uppercase tracking-widest border-t border-gray-500/10 pt-8">
            <p>VAPTx AI Security Engine • Confidential Threat Intelligence</p>
            <p class="mt-2 opacity-50 font-mono tracking-tighter">Report ID: {scan_id}</p>
        </footer>
    </div>

    <script>
        const isDark = {str(is_dark).lower()};
        const fontColor = isDark ? '#9ca3af' : '#64748b';
        const gridColor = isDark ? 'rgba(255,255,255,0.05)' : 'rgba(0,0,0,0.05)';
        
        Chart.defaults.color = fontColor;
        Chart.defaults.font.family = '"Plus Jakarta Sans", sans-serif';

        new Chart(document.getElementById('severityChart'), {{
            type: 'doughnut',
            data: {{
                labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                datasets: [{{
                    data: {sev_data_json},
                    backgroundColor: ['#ef4444', '#f97316', '#eab308', '#22c55e', '#3b82f6'],
                    borderWidth: 0,
                    hoverOffset: 12
                }}]
            }},
            options: {{ responsive: true, maintainAspectRatio: false, plugins: {{ legend: {{ position: 'right' }} }}, cutout: '80%' }}
        }});

        new Chart(document.getElementById('moduleChart'), {{
            type: 'bar',
            data: {{
                labels: {mod_labels_json},
                datasets: [{{ label: 'Findings', data: {mod_data_json}, backgroundColor: '#4f46e5', borderRadius: 2 }}]
            }},
            options: {{ responsive: true, maintainAspectRatio: false, scales: {{ y: {{ grid: {{ color: gridColor }} }}, x: {{ grid: {{ display: false }} }} }}, plugins: {{ legend: {{ display: false }} }} }}
        }});
    </script>
</body>
</html>"""
        return html_template

    def _render_findings(self, findings: List[Dict], theme: str) -> str:
        is_dark = theme == "dark"
        muted_color = "text-gray-400" if is_dark else "text-slate-500"
        title_color = "text-white" if is_dark else "text-slate-900"
        desc_color = "text-gray-300" if is_dark else "text-slate-600"
        code_bg = "bg-gray-900 border-gray-800" if is_dark else "bg-slate-50 border-slate-200"
        code_text = "text-gray-300" if is_dark else "text-slate-700"

        if not findings:
            return f'<div class="glass card text-center py-10 {muted_color} text-xs font-bold uppercase tracking-widest">No vulnerabilities discovered during this scan.</div>'

        # Sort findings: critical first, high, medium, low, info
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(findings, key=lambda x: severity_order.get(str(x.get("severity", "info")).lower(), 5))

        html_parts = []
        for f in sorted_findings:
            sev = str(f.get("severity", "info")).lower()
            color_class = f"text-{sev}"
            border_class = f"border-l-2 border-{sev}"
            
            cwe_id = f.get("cwe_id")
            cwe_html = f'<span class="text-[9px] font-bold font-mono {code_bg} {code_text} px-1.5 py-0.5 rounded border">{html.escape(cwe_id)}</span>' if cwe_id else ''
            
            owasp = f.get("owasp_category")
            owasp_html = f'<span class="text-[9px] font-bold font-mono bg-indigo-600/10 text-indigo-600 px-1.5 py-0.5 rounded border border-indigo-600/20 ml-1.5">{html.escape(owasp)}</span>' if owasp else ''
            
            cvss_score = f.get("cvss_score")
            cvss_html = f'<span class="text-[9px] font-black bg-slate-900 text-white px-1.5 py-0.5 rounded ml-1.5">CVSS {float(cvss_score):.1f}</span>' if cvss_score else ''
            
            evidence = f.get("evidence", "")
            evidence_html = f"""
                <div class="mt-4">
                    <h5 class="text-[9px] uppercase tracking-widest {muted_color} font-black mb-2">Technical Evidence</h5>
                    <pre class="{code_bg} {code_text} p-3 rounded border overflow-x-auto text-[11px] font-mono leading-relaxed">{html.escape(str(evidence))}</pre>
                </div>
            """ if evidence else ""

            remediation = f.get("remediation", "")
            rem_bg = "bg-emerald-500/5 border-emerald-500/10" if is_dark else "bg-emerald-50 border-emerald-100"
            rem_text = "text-emerald-400" if is_dark else "text-emerald-700"
            remediation_html = f"""
                <div class="mt-4 {rem_bg} p-3 rounded border">
                    <h5 class="text-[9px] uppercase tracking-widest {rem_text} font-black mb-1.5 flex items-center gap-1.5">
                        <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>
                        Remediation Plan
                    </h5>
                    <p class="{desc_color} text-xs font-medium leading-relaxed">{html.escape(str(remediation))}</p>
                </div>
            """ if remediation else ""
            
            location = f.get("location", "")
            location_html = f'<div class="text-[10px] font-bold font-mono text-indigo-600 mt-2 break-all bg-indigo-50 inline-block px-2 py-0.5 rounded border border-indigo-100">{html.escape(str(location))}</div>' if location else ''

            html_parts.append(f"""
            <article class="glass card {border_class} relative group transition-all">
                <div class="flex flex-col md:flex-row md:items-start justify-between gap-3">
                    <div class="flex-1">
                        <div class="flex items-center gap-2 mb-1.5">
                            <span class="text-[9px] font-black uppercase tracking-tighter px-1.5 py-0.5 rounded {color_class} bg-white border border-current">{sev}</span>
                            <span class="{muted_color} text-[10px] font-bold uppercase tracking-tight">{html.escape(f.get('type', 'Finding'))} • {html.escape(f.get('scanner', 'engine'))}</span>
                        </div>
                        <h3 class="text-sm font-black {title_color} leading-snug">{html.escape(f.get('title', 'Untitled Finding'))}</h3>
                        {location_html}
                    </div>
                    <div class="flex items-center flex-wrap self-start shrink-0">
                        {cwe_html}
                        {owasp_html}
                        {cvss_html}
                    </div>
                </div>
                
                <div class="mt-3 {desc_color} text-xs font-medium leading-relaxed max-w-4xl border-t border-gray-500/5 pt-3">
                    {html.escape(f.get('description', ''))}
                </div>
                
                {evidence_html}
                {remediation_html}
            </article>
            """)
        return "\n".join(html_parts)

    def _render_ai_summary(self, summary: str, theme: str) -> str:
        is_dark = theme == "dark"
        title_color = "text-white" if is_dark else "text-slate-900"
        muted_color = "text-gray-400" if is_dark else "text-slate-500"
        desc_color = "text-gray-300" if is_dark else "text-slate-600"
        
        # Format the markdown-like AI summary to simple HTML
        formatted_summary = html.escape(summary).replace('\n', '<br>')
        formatted_summary = re.sub(r'\*\*(.*?)\*\*', f'<strong class="{title_color}">\\1</strong>', formatted_summary)
        formatted_summary = re.sub(r'\*(.*?)\*', f'<em class="{muted_color}">\\1</em>', formatted_summary)
        
        # Format list items
        formatted_summary = re.sub(r'(\d+\.\s.*?)(<br>|$)', r'<li class="ml-4 mb-1">\1</li>', formatted_summary)
        formatted_summary = re.sub(r'(-\s.*?)(<br>|$)', r'<li class="ml-4 mb-1">\1</li>', formatted_summary)
        
        return f"""
        <section class="glass card print-break relative overflow-hidden">
            <div class="absolute top-0 left-0 w-1 h-full bg-indigo-600"></div>
            <div class="flex items-center gap-2 mb-4">
                <div class="p-1.5 bg-indigo-600/10 rounded">
                    <svg class="w-4 h-4 text-indigo-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z" />
                    </svg>
                </div>
                <h2 class="text-xs font-black uppercase tracking-widest {title_color}">AI Strategic Audit</h2>
            </div>
            <div class="{desc_color} text-xs leading-relaxed font-medium">
                {formatted_summary}
            </div>
        </section>
        """

    def _render_owasp_heatmap(self, findings: List[Dict], theme: str) -> str:
        """Render an OWASP Top 10 2025 compliance heatmap section."""
        is_dark = theme == "dark"
        title_color = "text-white" if is_dark else "text-slate-900"
        muted_color = "text-gray-400" if is_dark else "text-slate-500"
        border_color = "border-gray-800" if is_dark else "border-slate-200"

        owasp_map = {
            "A01": {"name": "Broken Access Control", "findings": []},
            "A02": {"name": "Cryptographic Failures", "findings": []},
            "A03": {"name": "Injection", "findings": []},
            "A04": {"name": "Insecure Design", "findings": []},
            "A05": {"name": "Security Misconfiguration", "findings": []},
            "A06": {"name": "Vulnerable & Outdated Components", "findings": []},
            "A07": {"name": "Auth Failures", "findings": []},
            "A08": {"name": "Data Integrity Failures", "findings": []},
            "A09": {"name": "Logging & Monitoring", "findings": []},
            "A10": {"name": "SSRF", "findings": []},
        }

        for f in findings:
            owasp_cat = f.get("owasp_category", "")
            if owasp_cat:
                code = owasp_cat.split(":")[0].strip()
                if code in owasp_map:
                    owasp_map[code]["findings"].append(f)

        # Calculate risk score (weighted severity)
        weights = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}
        total_risk = sum(weights.get(str(f.get("severity", "info")).lower(), 0) for f in findings)
        risk_pct = min(100, int((total_risk / max(len(findings) * 10, 1)) * 100))

        risk_color = "#22c55e"
        risk_label = "Healthy"
        if risk_pct >= 70: risk_color, risk_label = "#ef4444", "Critical"
        elif risk_pct >= 45: risk_color, risk_label = "#f97316", "High"
        elif risk_pct >= 25: risk_color, risk_label = "#eab308", "Medium"

        rows = []
        for code, data in owasp_map.items():
            count = len(data["findings"])
            if count > 0:
                max_sev = "info"
                for f in data["findings"]:
                    s = str(f.get("severity", "info")).lower()
                    if weights.get(s, 0) > weights.get(max_sev, 0): max_sev = s
                status = f'<span class="text-{max_sev} font-black uppercase text-[10px]">Vulnerable ({count})</span>'
                bg = "bg-red-500/5" if is_dark else "bg-red-50"
            else:
                status = f'<span class="{muted_color} text-[10px] font-bold uppercase">— No Findings</span>'
                bg = ""

            rows.append(f'''
                <tr class="{bg} transition-colors">
                    <td class="py-2.5 px-4 font-mono text-[10px] font-bold {title_color} opacity-60">{code}</td>
                    <td class="py-2.5 px-4 text-[11px] font-bold {title_color}">{data["name"]}</td>
                    <td class="py-2.5 px-4 text-center">{status}</td>
                </tr>
            ''')

        return f"""
        <section class="glass card mt-4 print-break">
            <div class="flex items-center justify-between mb-6">
                <div class="flex items-center gap-2">
                    <div class="p-1.5 bg-indigo-600/10 rounded">
                        <svg class="w-4 h-4 text-indigo-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path>
                        </svg>
                    </div>
                    <h2 class="text-xs font-black uppercase tracking-widest {title_color}">Industry Compliance Matrix</h2>
                </div>
                <div class="text-right">
                    <div class="text-[9px] {muted_color} uppercase font-black tracking-widest leading-none">Risk Index</div>
                    <div class="text-xl font-black mt-1" style="color: {risk_color}">{risk_pct}%</div>
                </div>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-left">
                    <thead>
                        <tr class="border-b {border_color}">
                            <th class="py-2 px-4 text-[9px] {muted_color} uppercase font-black tracking-widest w-16">Code</th>
                            <th class="py-2 px-4 text-[9px] {muted_color} uppercase font-black tracking-widest">OWASP Category</th>
                            <th class="py-2 px-4 text-[9px] {muted_color} uppercase font-black tracking-widest text-center w-36">Status</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y {border_color} opacity-90">
                        {"".join(rows)}
                    </tbody>
                </table>
            </div>
        </section>
        """

    def _render_metrics(self, counts: Dict[str, int], duration: float, modules_count: int, findings_count: int, theme: str) -> str:
        is_dark = theme == "dark"
        muted_color = "text-gray-400" if is_dark else "text-slate-500"
        title_color = "text-white" if is_dark else "text-slate-900"
        
        return f"""
        <section class="grid grid-cols-2 md:grid-cols-5 gap-4 mb-8">
            <div class="glass card text-center border-b-2 border-b-critical py-4">
                <div class="text-[9px] {muted_color} uppercase tracking-widest font-bold mb-0.5">Critical</div>
                <div class="text-2xl font-black text-critical">{counts.get('critical', 0)}</div>
            </div>
            <div class="glass card text-center border-b-2 border-b-high py-4">
                <div class="text-[9px] {muted_color} uppercase tracking-widest font-bold mb-0.5">High</div>
                <div class="text-2xl font-black text-high">{counts.get('high', 0)}</div>
            </div>
            <div class="glass card text-center border-b-2 border-b-medium py-4">
                <div class="text-[9px] {muted_color} uppercase tracking-widest font-bold mb-0.5">Medium</div>
                <div class="text-2xl font-black text-medium">{counts.get('medium', 0)}</div>
            </div>
            <div class="glass card text-center border-b-2 border-b-low py-4">
                <div class="text-[9px] {muted_color} uppercase tracking-widest font-bold mb-0.5">Low</div>
                <div class="text-2xl font-black text-low">{counts.get('low', 0)}</div>
            </div>
            <div class="glass card text-center border-b-2 border-b-info py-4">
                <div class="text-[9px] {muted_color} uppercase tracking-widest font-bold mb-0.5">Info</div>
                <div class="text-2xl font-black text-info">{counts.get('info', 0)}</div>
            </div>
        </section>

        <!-- Scan Stats -->
        <section class="glass card mb-8">
            <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div>
                    <span class="block text-[9px] uppercase tracking-wider {muted_color} mb-1">Time Elapsed</span>
                    <span class="font-bold text-sm {title_color}">{duration:.1f} seconds</span>
                </div>
                <div>
                    <span class="block text-[9px] uppercase tracking-wider {muted_color} mb-1">Engines Run</span>
                    <span class="font-bold text-sm {title_color}">{modules_count} modules active</span>
                </div>
                <div>
                    <span class="block text-[9px] uppercase tracking-wider {muted_color} mb-1">Findings Density</span>
                    <span class="font-bold text-sm {title_color}">{findings_count} security items</span>
                </div>
            </div>
        </section>
        """

    def _render_attack_surface(self, attack_surface: Dict[str, Any], theme: str) -> str:
        is_dark = theme == "dark"
        title_color = "text-white" if is_dark else "text-slate-900"
        muted_color = "text-gray-400" if is_dark else "text-slate-500"
        desc_color = "text-gray-300" if is_dark else "text-slate-600"
        border_color = "border-gray-800" if is_dark else "border-slate-200"

        # Paths (from DirScanner)
        paths = attack_surface.get("paths", [])
        path_rows = []
        for p in paths[:20]: # Limit to 20 for report brevity
            status = p.get("status", 200)
            status_color = "text-emerald-500" if status == 200 else "text-amber-500" if status in (403, 401) else "text-blue-500"
            path_rows.append(f"""
                <tr class="border-b {border_color} hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors">
                    <td class="py-2 px-3 font-mono text-[10px] {title_color}">{html.escape(p.get('path', ''))}</td>
                    <td class="py-2 px-3 text-[10px] font-bold {status_color}">{status}</td>
                    <td class="py-2 px-3 text-[10px] {muted_color}">{html.escape(p.get('type', 'file'))}</td>
                </tr>
            """)
        
        path_table = f"""
            <div class="overflow-x-auto rounded border {border_color} mt-4">
                <table class="w-full text-left">
                    <thead class="bg-slate-50 dark:bg-slate-900/50">
                        <tr class="border-b {border_color}">
                            <th class="py-2 px-3 text-[9px] {muted_color} uppercase font-black tracking-widest">Discovered Path</th>
                            <th class="py-2 px-3 text-[9px] {muted_color} uppercase font-black tracking-widest w-16">Status</th>
                            <th class="py-2 px-3 text-[9px] {muted_color} uppercase font-black tracking-widest w-20">Type</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y {border_color}">
                        {"".join(path_rows) if path_rows else f'<tr><td colspan="3" class="py-4 text-center text-[10px] {muted_color}">No paths discovered</td></tr>'}
                    </tbody>
                </table>
            </div>
            {f'<p class="mt-2 text-[9px] {muted_color} italic text-right">Showing first 20 of {len(paths)} discovered paths</p>' if len(paths) > 20 else ''}
        """

        # Form Inventory
        forms = attack_surface.get("forms", [])
        form_cards = []
        for f in forms:
            action = f.get("action", "")
            method = f.get("method", "GET").upper()
            inputs = ", ".join(f.get("inputs", []))
            form_cards.append(f"""
                <div class="p-3 rounded border {border_color} bg-slate-50/50 dark:bg-slate-900/20">
                    <div class="flex items-center justify-between mb-2">
                        <span class="text-[9px] font-black tracking-widest uppercase {muted_color}">Form Entry</span>
                        <span class="px-1.5 py-0.5 rounded bg-brand-500 text-white text-[8px] font-bold">{method}</span>
                    </div>
                    <p class="text-[10px] font-mono {title_color} truncate mb-1">{html.escape(action)}</p>
                    <p class="text-[9px] {muted_color} truncate">Inputs: <span class="text-brand-600 dark:text-brand-400 font-bold">{html.escape(inputs)}</span></p>
                </div>
            """)

        form_section = f"""
            <div class="mt-6">
                <h3 class="text-[10px] font-black uppercase tracking-widest {muted_color} mb-3">Interactive Form Inventory</h3>
                <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    {"".join(form_cards) if form_cards else f'<div class="col-span-2 text-center py-4 border dashed {border_color} rounded text-[10px] {muted_color}">No interactive forms mapped</div>'}
                </div>
            </div>
        """

        return f"""
        <section class="glass card mt-8 print-break">
            <div class="flex items-center gap-2 mb-6">
                <div class="p-1.5 bg-brand-500/10 rounded">
                    <svg class="w-4 h-4 text-brand-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M9 20l-5.447-2.724A1 1 0 013 16.382V5.618a1 1 0 011.447-.894L9 7m0 13l6-3m-6 3V7m6 10l4.553 2.276A1 1 0 0021 18.382V7.618a1 1 0 00-.553-.894L15 4m0 13V4m0 0L9 7" />
                    </svg>
                </div>
                <h2 class="text-xs font-black uppercase tracking-widest {title_color}">Attack Surface Inventory</h2>
            </div>
            
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
                <div>
                    <h3 class="text-[10px] font-black uppercase tracking-widest {muted_color} mb-1">Directory Infrastructure</h3>
                    <p class="text-[10px] {desc_color} mb-4">Baseline mapping of server structure and file availability.</p>
                    {path_table}
                </div>
                <div>
                    <h3 class="text-[10px] font-black uppercase tracking-widest {muted_color} mb-1">Application Components</h3>
                    <p class="text-[10px] {desc_color} mb-4">Mapped entry points, external resources, and input vectors.</p>
                    
                    <div class="grid grid-cols-2 gap-4 mt-4">
                        <div class="p-3 rounded border {border_color}">
                            <span class="block text-[9px] uppercase tracking-wider {muted_color} mb-1">Internal Assets</span>
                            <span class="font-bold text-sm {title_color}">{len(attack_surface.get('internal_urls', []))} URLs</span>
                        </div>
                        <div class="p-3 rounded border {border_color}">
                            <span class="block text-[9px] uppercase tracking-wider {muted_color} mb-1">External Links</span>
                            <span class="font-bold text-sm {title_color}">{len(attack_surface.get('external_urls', []))} Assets</span>
                        </div>
                    </div>
                    
                    {form_section}
                </div>
            </div>
        </section>
        """

    def _get_css(self, theme: str) -> str:
        is_dark = theme == "dark"
        return f"""
            :root {{
                --critical: #ef4444;
                --high: #f97316;
                --medium: #eab308;
                --low: #22c55e;
                --info: #3b82f6;
                --brand: #0ea5e9;
            }}
            body {{ font-family: 'Plus Jakarta Sans', sans-serif; background-color: {"#030712" if is_dark else "#fdfdfd"}; }}
            .bg-page {{ background-color: {"#030712" if is_dark else "#fdfdfd"}; }}
            .glass {{
                backdrop-filter: blur(12px);
                background: {"rgba(17, 24, 39, 0.7)" if is_dark else "rgba(255, 255, 255, 0.8)"};
            }}
            .card {{
                border: 1px solid {"rgba(255, 255, 255, 0.05)" if is_dark else "#e2e8f0"};
                border-radius: 12px;
                padding: 1.5rem;
                box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 24px 48px -12px rgba(0, 0, 0, 0.05);
            }}
            .text-critical {{ color: var(--critical); }}
            .text-high {{ color: var(--high); }}
            .text-medium {{ color: var(--medium); }}
            .text-low {{ color: var(--low); }}
            .text-info {{ color: var(--info); }}
            .border-critical {{ border-color: var(--critical); }}
            .border-high {{ border-color: var(--high); }}
            .border-medium {{ border-color: var(--medium); }}
            .border-low {{ border-color: var(--low); }}
            .border-info {{ border-color: var(--info); }}
            .bg-critical {{ background-color: var(--critical); }}
            .bg-high {{ background-color: var(--high); }}
            .bg-medium {{ background-color: var(--medium); }}
            .bg-low {{ background-color: var(--low); }}
            .bg-info {{ background-color: var(--info); }}
            @media print {{
                .print-break {{ page-break-inside: avoid; }}
                body {{ background: white !important; }}
                .glass {{ backdrop-filter: none !important; background: white !important; border: 1px solid #eee !important; }}
                .card {{ box-shadow: none !important; }}
            }}
            ::-webkit-scrollbar {{ width: 8px; }}
            ::-webkit-scrollbar-track {{ background: transparent; }}
            ::-webkit-scrollbar-thumb {{ background: {"#374151" if is_dark else "#e2e8f0"}; border-radius: 4px; }}
        """


