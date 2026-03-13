"""
VIPER-style cyberpunk HTML report generator for scan results.
Matches the dashboard's dark neon aesthetic — CRT scanlines, cyber grid,
glassmorphism cards, neon severity badges, monospace fonts.
"""

from __future__ import annotations

import html
import json
import re
from typing import Any, Dict, List

from engine import config


# ── Neon Color Palette (matches globals.css) ──────────────────────────────
COLORS = {
    "bg_app": "#020205",
    "bg_panel": "rgba(10, 10, 18, 0.6)",
    "bg_element": "rgba(19, 19, 31, 0.8)",
    "bg_card": "rgba(5, 5, 10, 0.4)",
    "border_cyber": "rgba(0, 243, 255, 0.12)",
    "border_cyber_hover": "rgba(0, 243, 255, 0.25)",
    "text_primary": "#e2e8f0",
    "text_secondary": "#94a3b8",
    "neon_cyan": "#00f3ff",
    "neon_blue": "#3b82f6",
    "neon_green": "#00ff9f",
    "neon_red": "#ff003c",
    "neon_yellow": "#fcee0a",
    "neon_purple": "#bc13fe",
    "severity_critical": "#ff003c",
    "severity_high": "#f97316",
    "severity_medium": "#fcee0a",
    "severity_low": "#00ff9f",
    "severity_info": "#00f3ff",
}

SEV_COLORS = {
    "critical": COLORS["severity_critical"],
    "high": COLORS["severity_high"],
    "medium": COLORS["severity_medium"],
    "low": COLORS["severity_low"],
    "info": COLORS["severity_info"],
}


class ReportGenerator:
    """Generate VIPER-themed cyberpunk HTML reports from real scan results."""

    def generate_html(self, scan_result: Dict[str, Any], theme: str = "dark") -> str:
        """Generate a full HTML report using genuine scan data."""
        target = scan_result.get("target", "Unknown")
        findings = scan_result.get("findings", [])
        ai_summary = scan_result.get("ai_summary", "")
        duration = scan_result.get("duration_seconds", 0)
        created_at = scan_result.get("created_at", "")
        scan_id = scan_result.get("scan_id", "")
        modules_run = scan_result.get("modules_run", [])

        # ── Aggregate data ────────────────────────────────────────
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        type_counts: Dict[str, int] = {}

        for f in findings:
            sev = self._normalize_severity(f.get("severity", "info"))
            counts[sev] = counts.get(sev, 0) + 1
            scanner = f.get("scanner", "Unknown")
            type_counts[scanner] = type_counts.get(scanner, 0) + 1

        total_findings = len(findings)
        severity_data = json.dumps([counts[k] for k in ("critical", "high", "medium", "low", "info")])
        module_labels = json.dumps(list(type_counts.keys()))
        module_data = json.dumps(list(type_counts.values()))

        # ── Render sub-sections ───────────────────────────────────
        metrics_html = self._render_metrics(counts, duration, len(modules_run), total_findings)
        ai_html = self._render_ai_summary(ai_summary) if ai_summary else ""
        owasp_html = self._render_owasp_heatmap(findings)
        attack_surface_html = self._render_attack_surface(scan_result.get("attack_surface", {})) if scan_result.get("attack_surface") else ""
        findings_html = self._render_findings(findings)

        modules_badges = "".join(
            f'<span class="mod-badge">{html.escape(m)}</span>' for m in modules_run
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecureSuiteX Security Report — {html.escape(target)}</title>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700;800&family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>{self._get_css()}</style>
</head>
<body>
    <!-- CRT Scanline Overlay -->
    <div class="crt-overlay"></div>
    <div class="cyber-grid"></div>

    <div class="report-container">
        <!-- ═══ HEADER ═══ -->
        <header class="report-header">
            <div class="header-left">
                <div class="brand-row">
                    <span class="brand-badge">SecureSuiteX ENGINE</span>
                    <span class="brand-version">v3.2.0 • CLASSIFIED</span>
                </div>
                <h1 class="report-title">
                    SECURITY AUDIT <span class="title-accent">REPORT</span>
                </h1>
                <div class="target-row">
                    <span class="target-label">TARGET:</span>
                    <code class="target-url">{html.escape(target)}</code>
                </div>
                <div class="modules-row">
                    <span class="target-label">ENGINES:</span>
                    {modules_badges}
                </div>
            </div>
            <div class="header-right">
                <div class="header-stat">
                    <span class="stat-label">AUDIT DATE</span>
                    <span class="stat-value">{created_at}</span>
                </div>
                <div class="header-stat">
                    <span class="stat-label">DURATION</span>
                    <span class="stat-value">{duration:.1f}s</span>
                </div>
                <div class="findings-count-box">
                    <span class="findings-count-num">{total_findings}</span>
                    <span class="findings-count-label">ISSUES</span>
                </div>
            </div>
        </header>

        <!-- ═══ SEVERITY METRICS ═══ -->
        {metrics_html}

        <!-- ═══ CHARTS ═══ -->
        <section class="charts-grid">
            <div class="cyber-card">
                <h2 class="section-label">SEVERITY_DISTRIBUTION</h2>
                <div class="chart-container"><canvas id="severityChart"></canvas></div>
            </div>
            <div class="cyber-card">
                <h2 class="section-label">ENGINE_PERFORMANCE</h2>
                <div class="chart-container"><canvas id="moduleChart"></canvas></div>
            </div>
        </section>

        {ai_html}
        {owasp_html}
        {attack_surface_html}

        <!-- ═══ FINDINGS ═══ -->
        <section class="findings-section">
            <div class="section-header">
                <h2 class="section-label">DETAILED_FINDINGS_REGISTRY</h2>
                <span class="findings-total-badge">{total_findings} TOTAL</span>
            </div>
            <div class="findings-list">{findings_html}</div>
        </section>

        <!-- ═══ FOOTER ═══ -->
        <footer class="report-footer">
            <div class="footer-line"></div>
            <p class="footer-brand">SecureSuiteX AI SECURITY ENGINE • CONFIDENTIAL THREAT INTELLIGENCE</p>
            <p class="footer-copyright">&copy; 2026 Veltro. All rights reserved.</p>
            <p class="footer-id">REPORT_ID: {scan_id}</p>
        </footer>
    </div>

    <script>
        Chart.defaults.color = '{COLORS["text_secondary"]}';
        Chart.defaults.font.family = '"JetBrains Mono", monospace';
        Chart.defaults.font.size = 10;

        new Chart(document.getElementById('severityChart'), {{
            type: 'doughnut',
            data: {{
                labels: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
                datasets: [{{
                    data: {severity_data},
                    backgroundColor: ['{COLORS["severity_critical"]}', '{COLORS["severity_high"]}', '{COLORS["severity_medium"]}', '{COLORS["severity_low"]}', '{COLORS["severity_info"]}'],
                    borderWidth: 0,
                    hoverOffset: 8,
                    borderRadius: 2
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                cutout: '78%',
                plugins: {{
                    legend: {{
                        position: 'right',
                        labels: {{
                            usePointStyle: true,
                            pointStyle: 'rectRounded',
                            padding: 12,
                            font: {{ family: '"JetBrains Mono"', size: 9, weight: '600' }}
                        }}
                    }}
                }}
            }}
        }});

        new Chart(document.getElementById('moduleChart'), {{
            type: 'bar',
            data: {{
                labels: {module_labels},
                datasets: [{{
                    label: 'Findings',
                    data: {module_data},
                    backgroundColor: '{COLORS["neon_cyan"]}22',
                    borderColor: '{COLORS["neon_cyan"]}',
                    borderWidth: 1,
                    borderRadius: 3,
                    hoverBackgroundColor: '{COLORS["neon_cyan"]}44'
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                scales: {{
                    y: {{
                        grid: {{ color: 'rgba(0, 243, 255, 0.05)' }},
                        ticks: {{ font: {{ size: 9 }} }}
                    }},
                    x: {{
                        grid: {{ display: false }},
                        ticks: {{ font: {{ size: 8 }}, maxRotation: 45 }}
                    }}
                }},
                plugins: {{ legend: {{ display: false }} }}
            }}
        }});
    </script>
</body>
</html>"""

    # ══════════════════════════════════════════════════════════════
    #  PRIVATE RENDER METHODS
    # ══════════════════════════════════════════════════════════════

    def _normalize_severity(self, sev: Any) -> str:
        """Normalize severity to lowercase string."""
        if hasattr(sev, "value"):
            sev = sev.value
        sev = str(sev).lower()
        return sev if sev in ("critical", "high", "medium", "low", "info") else "info"

    def _render_metrics(self, counts: Dict[str, int], duration: float, modules: int, total: int) -> str:
        """Render the severity metric cards row."""
        cards = []
        for sev in ("critical", "high", "medium", "low", "info"):
            color = SEV_COLORS[sev]
            count = counts.get(sev, 0)
            cards.append(f"""
                <div class="metric-card" style="border-bottom: 2px solid {color}">
                    <span class="metric-label">{sev.upper()}</span>
                    <span class="metric-value" style="color: {color}">{count}</span>
                </div>
            """)

        return f"""
        <section class="metrics-grid">{"".join(cards)}</section>
        <section class="cyber-card stats-bar">
            <div class="stat-block">
                <span class="stat-block-label">TIME_ELAPSED</span>
                <span class="stat-block-value">{duration:.1f} seconds</span>
            </div>
            <div class="stat-block">
                <span class="stat-block-label">ENGINES_ACTIVE</span>
                <span class="stat-block-value">{modules} modules</span>
            </div>
            <div class="stat-block">
                <span class="stat-block-label">FINDINGS_DENSITY</span>
                <span class="stat-block-value">{total} security items</span>
            </div>
        </section>
        """

    def _render_findings(self, findings: List[Dict]) -> str:
        """Render the findings list with cyber-themed cards."""
        if not findings:
            return '<div class="cyber-card" style="text-align:center;padding:3rem"><span class="section-label">NO VULNERABILITIES DISCOVERED</span></div>'

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(findings, key=lambda x: severity_order.get(self._normalize_severity(x.get("severity", "info")), 5))

        parts = []
        for f in sorted_findings:
            sev = self._normalize_severity(f.get("severity", "info"))
            color = SEV_COLORS[sev]

            # Tags row
            tags = []
            cwe = f.get("cwe_id")
            if cwe:
                tags.append(f'<span class="tag tag-cwe">{html.escape(cwe)}</span>')
            owasp = f.get("owasp_category")
            if owasp:
                tags.append(f'<span class="tag tag-owasp">{html.escape(owasp)}</span>')
            cvss = f.get("cvss_score")
            if cvss:
                tags.append(f'<span class="tag tag-cvss">CVSS {float(cvss):.1f}</span>')
            tags_html = "".join(tags)

            # Location
            location = f.get("location", "")
            location_html = f'<div class="finding-location">{html.escape(str(location))}</div>' if location else ""

            # Evidence
            evidence = f.get("evidence", "")
            evidence_html = f"""
                <div class="finding-evidence">
                    <h5 class="evidence-label">TECHNICAL_EVIDENCE</h5>
                    <pre class="evidence-code">{html.escape(str(evidence))}</pre>
                </div>
            """ if evidence else ""

            # Remediation
            remediation = f.get("remediation", "")
            remediation_html = f"""
                <div class="finding-remediation">
                    <h5 class="remediation-label">⚡ REMEDIATION_PLAN</h5>
                    <p class="remediation-text">{html.escape(str(remediation))}</p>
                </div>
            """ if remediation else ""

            parts.append(f"""
            <article class="finding-card" style="border-left: 2px solid {color}">
                <div class="finding-header">
                    <div class="finding-header-left">
                        <div class="finding-meta">
                            <span class="sev-badge" style="color:{color};border-color:{color}">{sev.upper()}</span>
                            <span class="scanner-label">{html.escape(f.get('type', 'Finding'))} • {html.escape(f.get('scanner', 'engine'))}</span>
                        </div>
                        <h3 class="finding-title">{html.escape(f.get('title', 'Untitled Finding'))}</h3>
                        {location_html}
                    </div>
                    <div class="finding-tags">{tags_html}</div>
                </div>
                <div class="finding-desc">{html.escape(f.get('description', ''))}</div>
                {evidence_html}
                {remediation_html}
            </article>
            """)
        return "\n".join(parts)

    def _render_ai_summary(self, summary: str) -> str:
        """Render the AI strategic audit section."""
        formatted = html.escape(summary).replace('\n', '<br>')
        formatted = re.sub(r'\*\*(.*?)\*\*', r'<strong class="text-highlight">\1</strong>', formatted)
        formatted = re.sub(r'\*(.*?)\*', r'<em class="text-muted">\1</em>', formatted)
        formatted = re.sub(r'(\d+\.\s.*?)(<br>|$)', r'<li class="ai-list-item">\1</li>', formatted)
        formatted = re.sub(r'(-\s.*?)(<br>|$)', r'<li class="ai-list-item">\1</li>', formatted)

        return f"""
        <section class="cyber-card ai-section">
            <div class="ai-accent-bar"></div>
            <div class="section-header-inline">
                <span class="section-icon">🧪</span>
                <h2 class="section-label">AI_STRATEGIC_AUDIT</h2>
            </div>
            <div class="ai-content">{formatted}</div>
        </section>
        """

    def _render_owasp_heatmap(self, findings: List[Dict]) -> str:
        """Render OWASP Top 10 compliance matrix."""
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

        weights = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}

        for f in findings:
            owasp_cat = f.get("owasp_category", "")
            if owasp_cat:
                code = owasp_cat.split(":")[0].strip()
                if code in owasp_map:
                    owasp_map[code]["findings"].append(f)

        total_risk = sum(weights.get(self._normalize_severity(f.get("severity", "info")), 0) for f in findings)
        risk_pct = min(100, int((total_risk / max(len(findings) * 10, 1)) * 100))

        risk_color = COLORS["severity_low"]
        risk_label = "SECURE"
        if risk_pct >= 70:
            risk_color, risk_label = COLORS["severity_critical"], "CRITICAL"
        elif risk_pct >= 45:
            risk_color, risk_label = COLORS["severity_high"], "HIGH_RISK"
        elif risk_pct >= 25:
            risk_color, risk_label = COLORS["severity_medium"], "ELEVATED"

        rows = []
        for code, data in owasp_map.items():
            count = len(data["findings"])
            if count > 0:
                max_sev = "info"
                for f in data["findings"]:
                    s = self._normalize_severity(f.get("severity", "info"))
                    if weights.get(s, 0) > weights.get(max_sev, 0):
                        max_sev = s
                sev_color = SEV_COLORS[max_sev]
                status = f'<span style="color:{sev_color};font-weight:800;text-transform:uppercase;font-size:10px">VULNERABLE ({count})</span>'
                row_bg = "background:rgba(255,0,60,0.04);"
            else:
                status = f'<span style="color:{COLORS["text_secondary"]};font-size:10px;font-weight:700">— NO FINDINGS</span>'
                row_bg = ""

            rows.append(f"""
                <tr style="{row_bg}">
                    <td class="owasp-code">{code}</td>
                    <td class="owasp-name">{data["name"]}</td>
                    <td class="owasp-status">{status}</td>
                </tr>
            """)

        return f"""
        <section class="cyber-card owasp-section">
            <div class="section-header">
                <div class="section-header-inline">
                    <span class="section-icon">🛡️</span>
                    <h2 class="section-label">INDUSTRY_COMPLIANCE_MATRIX</h2>
                </div>
                <div class="risk-index">
                    <span class="risk-label">RISK_INDEX</span>
                    <span class="risk-value" style="color:{risk_color}">{risk_pct}%</span>
                    <span class="risk-tag" style="color:{risk_color}">{risk_label}</span>
                </div>
            </div>
            <table class="owasp-table">
                <thead>
                    <tr>
                        <th class="owasp-th">CODE</th>
                        <th class="owasp-th">OWASP CATEGORY</th>
                        <th class="owasp-th" style="text-align:center">STATUS</th>
                    </tr>
                </thead>
                <tbody>{"".join(rows)}</tbody>
            </table>
        </section>
        """

    def _render_attack_surface(self, attack_surface: Dict[str, Any]) -> str:
        """Render the attack surface inventory section."""
        # Paths
        paths = attack_surface.get("paths", [])
        path_rows = []
        for p in paths[:20]:
            status = p.get("status", 200)
            if status == 200:
                sc = COLORS["neon_green"]
            elif status in (403, 401):
                sc = COLORS["severity_high"]
            else:
                sc = COLORS["neon_blue"]

            path_rows.append(f"""
                <tr class="surface-row">
                    <td class="surface-path">{html.escape(p.get('path', ''))}</td>
                    <td class="surface-status" style="color:{sc}">{status}</td>
                    <td class="surface-type">{html.escape(p.get('type', 'file'))}</td>
                </tr>
            """)

        overflow_note = f'<p class="surface-overflow">Showing first 20 of {len(paths)} discovered paths</p>' if len(paths) > 20 else ""

        # Forms
        forms = attack_surface.get("forms", [])
        form_cards = []
        for f in forms:
            method = f.get("method", "GET").upper()
            action = f.get("action", "")
            inputs = ", ".join(f.get("inputs", []))
            form_cards.append(f"""
                <div class="form-card">
                    <div class="form-header">
                        <span class="form-label">FORM_ENTRY</span>
                        <span class="form-method">{method}</span>
                    </div>
                    <p class="form-action">{html.escape(action)}</p>
                    <p class="form-inputs">Inputs: <span class="form-inputs-list">{html.escape(inputs)}</span></p>
                </div>
            """)

        no_forms = f'<div class="no-data">NO INTERACTIVE FORMS MAPPED</div>' if not form_cards else ""

        return f"""
        <section class="cyber-card surface-section">
            <div class="section-header-inline">
                <span class="section-icon">🗺️</span>
                <h2 class="section-label">ATTACK_SURFACE_INVENTORY</h2>
            </div>
            <div class="surface-grid">
                <div>
                    <h3 class="subsection-label">DIRECTORY_INFRASTRUCTURE</h3>
                    <p class="subsection-desc">Baseline mapping of server structure.</p>
                    <table class="surface-table">
                        <thead>
                            <tr>
                                <th class="surface-th">DISCOVERED_PATH</th>
                                <th class="surface-th">STATUS</th>
                                <th class="surface-th">TYPE</th>
                            </tr>
                        </thead>
                        <tbody>
                            {"".join(path_rows) if path_rows else '<tr><td colspan="3" class="no-data">NO PATHS DISCOVERED</td></tr>'}
                        </tbody>
                    </table>
                    {overflow_note}
                </div>
                <div>
                    <h3 class="subsection-label">APPLICATION_COMPONENTS</h3>
                    <p class="subsection-desc">Mapped entry points, resources & input vectors.</p>
                    <div class="surface-stats">
                        <div class="surface-stat-card">
                            <span class="surface-stat-label">INTERNAL_ASSETS</span>
                            <span class="surface-stat-value">{len(attack_surface.get('internal_urls', []))} URLs</span>
                        </div>
                        <div class="surface-stat-card">
                            <span class="surface-stat-label">EXTERNAL_LINKS</span>
                            <span class="surface-stat-value">{len(attack_surface.get('external_urls', []))} Assets</span>
                        </div>
                    </div>
                    <h3 class="subsection-label" style="margin-top:1.5rem">FORM_INVENTORY</h3>
                    <div class="forms-grid">
                        {"".join(form_cards)}{no_forms}
                    </div>
                </div>
            </div>
        </section>
        """

    def _get_css(self) -> str:
        """Return the full VIPER cyberpunk stylesheet."""
        c = COLORS
        return f"""
            /* ═══ RESET & BASE ═══ */
            *, *::before, *::after {{ margin: 0; padding: 0; box-sizing: border-box; }}

            body {{
                font-family: 'Inter', system-ui, sans-serif;
                background: {c['bg_app']};
                color: {c['text_primary']};
                -webkit-font-smoothing: antialiased;
                line-height: 1.6;
                overflow-x: hidden;
            }}

            /* ═══ CRT SCANLINE & GRID ═══ */
            .crt-overlay {{
                position: fixed; inset: 0; z-index: 9998; pointer-events: none; opacity: 0.08;
                background: linear-gradient(to bottom, rgba(18,16,16,0) 50%, rgba(0,0,0,0.1) 50%);
                background-size: 100% 4px;
            }}
            .cyber-grid {{
                position: fixed; inset: 0; z-index: 9997; pointer-events: none; opacity: 0.5;
                background-image:
                    linear-gradient(rgba(0,243,255,0.015) 1px, transparent 1px),
                    linear-gradient(90deg, rgba(0,243,255,0.015) 1px, transparent 1px);
                background-size: 40px 40px;
            }}

            /* ═══ CONTAINER ═══ */
            .report-container {{
                max-width: 1100px; margin: 0 auto; padding: 2.5rem 1.5rem; position: relative; z-index: 1;
            }}

            /* ═══ CYBER CARD (glassmorphism) ═══ */
            .cyber-card {{
                background: {c['bg_element']};
                border: 1px solid {c['border_cyber']};
                border-radius: 12px;
                padding: 1.5rem;
                backdrop-filter: blur(12px);
                box-shadow: 0 0 20px rgba(0,243,255,0.03), 0 4px 24px rgba(0,0,0,0.3);
                margin-bottom: 1rem;
            }}
            .cyber-card:hover {{
                border-color: {c['border_cyber_hover']};
                box-shadow: 0 0 30px rgba(0,243,255,0.06), 0 4px 24px rgba(0,0,0,0.4);
            }}

            /* ═══ HEADER ═══ */
            .report-header {{
                display: flex; flex-wrap: wrap; justify-content: space-between; align-items: flex-start; gap: 1.5rem;
                margin-bottom: 2rem; padding-bottom: 2rem;
                border-bottom: 1px solid {c['border_cyber']};
            }}
            .header-left {{ flex: 1; min-width: 300px; }}
            .header-right {{ display: flex; align-items: center; gap: 1.5rem; flex-shrink: 0; }}

            .brand-row {{ display: flex; align-items: center; gap: 0.6rem; margin-bottom: 0.5rem; }}
            .brand-badge {{
                display: inline-block; padding: 3px 10px; border-radius: 4px; font-size: 9px;
                font-family: 'JetBrains Mono', monospace; font-weight: 800;
                letter-spacing: 2px; text-transform: uppercase;
                background: linear-gradient(135deg, {c['neon_cyan']}, {c['neon_blue']});
                color: {c['bg_app']}; box-shadow: 0 0 12px rgba(0,243,255,0.3);
            }}
            .brand-version {{ font-size: 10px; color: {c['text_secondary']}; font-family: 'JetBrains Mono', monospace; letter-spacing: 1px; }}

            .report-title {{
                font-family: 'JetBrains Mono', monospace; font-size: 1.8rem; font-weight: 800;
                letter-spacing: 3px; color: {c['text_primary']}; line-height: 1.2;
            }}
            .title-accent {{ color: {c['neon_cyan']}; text-shadow: 0 0 20px rgba(0,243,255,0.3); }}

            .target-row, .modules-row {{ display: flex; align-items: center; gap: 0.5rem; margin-top: 0.5rem; flex-wrap: wrap; }}
            .target-label {{
                font-size: 9px; font-family: 'JetBrains Mono', monospace; font-weight: 700;
                color: {c['text_secondary']}; letter-spacing: 2px;
            }}
            .target-url {{
                font-family: 'JetBrains Mono', monospace; font-size: 12px; font-weight: 500;
                color: {c['neon_cyan']}; background: rgba(0,243,255,0.06); padding: 2px 8px;
                border-radius: 4px; border: 1px solid rgba(0,243,255,0.15);
            }}

            .mod-badge {{
                display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 9px;
                font-family: 'JetBrains Mono', monospace; font-weight: 600; letter-spacing: 0.5px;
                background: {c['bg_card']}; border: 1px solid {c['border_cyber']}; color: {c['text_secondary']};
            }}

            .header-stat {{ text-align: right; }}
            .stat-label {{
                display: block; font-size: 8px; font-family: 'JetBrains Mono', monospace; font-weight: 800;
                letter-spacing: 2px; color: {c['text_secondary']}; text-transform: uppercase; margin-bottom: 2px;
            }}
            .stat-value {{
                font-size: 13px; font-weight: 700; color: {c['text_primary']};
                font-family: 'JetBrains Mono', monospace;
            }}

            .findings-count-box {{
                display: flex; flex-direction: column; align-items: center; justify-content: center;
                width: 56px; height: 56px; border-radius: 10px;
                background: linear-gradient(135deg, {c['neon_cyan']}, {c['neon_blue']});
                color: {c['bg_app']}; box-shadow: 0 0 20px rgba(0,243,255,0.25);
            }}
            .findings-count-num {{ font-size: 18px; font-weight: 800; font-family: 'JetBrains Mono', monospace; line-height: 1; }}
            .findings-count-label {{ font-size: 7px; font-weight: 800; letter-spacing: 1.5px; }}

            /* ═══ METRICS ═══ */
            .metrics-grid {{
                display: grid; grid-template-columns: repeat(5, 1fr); gap: 0.75rem; margin-bottom: 1rem;
            }}
            .metric-card {{
                background: {c['bg_element']}; border: 1px solid {c['border_cyber']}; border-radius: 10px;
                padding: 1rem; text-align: center; backdrop-filter: blur(8px);
            }}
            .metric-label {{
                display: block; font-size: 9px; font-family: 'JetBrains Mono', monospace; font-weight: 700;
                letter-spacing: 2px; color: {c['text_secondary']}; margin-bottom: 4px;
            }}
            .metric-value {{ font-size: 1.8rem; font-weight: 800; font-family: 'JetBrains Mono', monospace; }}

            .stats-bar {{
                display: grid; grid-template-columns: repeat(3, 1fr); gap: 1.5rem;
            }}
            .stat-block-label {{
                display: block; font-size: 8px; font-family: 'JetBrains Mono', monospace; font-weight: 800;
                letter-spacing: 2px; color: {c['text_secondary']}; margin-bottom: 4px;
            }}
            .stat-block-value {{ font-size: 13px; font-weight: 700; color: {c['text_primary']}; }}

            /* ═══ CHARTS ═══ */
            .charts-grid {{
                display: grid; grid-template-columns: repeat(2, 1fr); gap: 1rem; margin-bottom: 1rem;
            }}
            .chart-container {{ position: relative; height: 180px; width: 100%; display: flex; justify-content: center; }}

            /* ═══ SECTION LABELS ═══ */
            .section-label {{
                font-size: 10px; font-family: 'JetBrains Mono', monospace; font-weight: 800;
                letter-spacing: 3px; color: {c['text_primary']}; opacity: 0.7; text-transform: uppercase;
            }}
            .section-header {{
                display: flex; align-items: center; justify-content: space-between; margin-bottom: 1.5rem;
                padding-bottom: 0.75rem; border-bottom: 1px solid {c['border_cyber']};
            }}
            .section-header-inline {{ display: flex; align-items: center; gap: 0.5rem; margin-bottom: 1rem; }}
            .section-icon {{ font-size: 16px; }}
            .subsection-label {{
                font-size: 9px; font-family: 'JetBrains Mono', monospace; font-weight: 800;
                letter-spacing: 2px; color: {c['text_secondary']}; margin-bottom: 4px;
            }}
            .subsection-desc {{ font-size: 10px; color: {c['text_secondary']}; margin-bottom: 1rem; }}

            /* ═══ AI SECTION ═══ */
            .ai-section {{ position: relative; overflow: hidden; }}
            .ai-accent-bar {{
                position: absolute; top: 0; left: 0; width: 3px; height: 100%;
                background: linear-gradient(180deg, {c['neon_cyan']}, {c['neon_blue']});
                border-radius: 2px;
            }}
            .ai-content {{
                font-size: 12px; color: {c['text_secondary']}; line-height: 1.8; padding-left: 0.5rem;
            }}
            .ai-list-item {{ margin-left: 1rem; margin-bottom: 0.25rem; list-style: none; }}
            .text-highlight {{ color: {c['text_primary']}; }}
            .text-muted {{ color: {c['text_secondary']}; }}

            /* ═══ FINDINGS ═══ */
            .findings-section {{ margin-top: 1.5rem; }}
            .findings-list {{ display: flex; flex-direction: column; gap: 0.75rem; }}
            .findings-total-badge {{
                font-size: 9px; font-family: 'JetBrains Mono', monospace; font-weight: 800;
                letter-spacing: 1px; padding: 4px 12px; border-radius: 20px;
                background: rgba(0,243,255,0.1); color: {c['neon_cyan']}; border: 1px solid rgba(0,243,255,0.2);
            }}

            .finding-card {{
                background: {c['bg_element']}; border: 1px solid {c['border_cyber']};
                border-radius: 10px; padding: 1.25rem; backdrop-filter: blur(8px);
                transition: border-color 0.2s, box-shadow 0.2s;
            }}
            .finding-card:hover {{
                border-color: {c['border_cyber_hover']};
                box-shadow: 0 0 15px rgba(0,243,255,0.05);
            }}
            .finding-header {{ display: flex; flex-wrap: wrap; justify-content: space-between; gap: 0.75rem; }}
            .finding-header-left {{ flex: 1; min-width: 200px; }}
            .finding-meta {{ display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.4rem; }}
            .sev-badge {{
                font-size: 9px; font-family: 'JetBrains Mono', monospace; font-weight: 800;
                letter-spacing: 1px; padding: 2px 8px; border-radius: 3px;
                border: 1px solid; background: transparent; text-transform: uppercase;
            }}
            .scanner-label {{
                font-size: 10px; font-family: 'JetBrains Mono', monospace; font-weight: 700;
                color: {c['text_secondary']}; letter-spacing: 1px; text-transform: uppercase;
            }}
            .finding-title {{ font-size: 13px; font-weight: 800; color: {c['text_primary']}; line-height: 1.4; }}
            .finding-location {{
                font-size: 10px; font-family: 'JetBrains Mono', monospace; font-weight: 600;
                color: {c['neon_cyan']}; margin-top: 0.4rem; word-break: break-all;
                background: rgba(0,243,255,0.05); display: inline-block;
                padding: 2px 8px; border-radius: 4px; border: 1px solid rgba(0,243,255,0.12);
            }}
            .finding-tags {{ display: flex; align-items: center; flex-wrap: wrap; gap: 0.4rem; flex-shrink: 0; }}
            .tag {{
                font-size: 9px; font-family: 'JetBrains Mono', monospace; font-weight: 700;
                padding: 2px 8px; border-radius: 3px; border: 1px solid {c['border_cyber']};
            }}
            .tag-cwe {{ background: {c['bg_card']}; color: {c['text_secondary']}; }}
            .tag-owasp {{ background: rgba(0,243,255,0.05); color: {c['neon_cyan']}; border-color: rgba(0,243,255,0.15); }}
            .tag-cvss {{
                background: rgba(255,255,255,0.05); color: {c['text_primary']}; font-weight: 800;
                border-color: rgba(255,255,255,0.1);
            }}
            .finding-desc {{
                font-size: 12px; color: {c['text_secondary']}; line-height: 1.7; margin-top: 0.75rem;
                padding-top: 0.75rem; border-top: 1px solid rgba(255,255,255,0.03);
                max-width: 800px;
            }}
            .finding-evidence {{ margin-top: 1rem; }}
            .evidence-label {{
                font-size: 8px; font-family: 'JetBrains Mono', monospace; font-weight: 800;
                letter-spacing: 2px; color: {c['text_secondary']}; margin-bottom: 0.5rem;
            }}
            .evidence-code {{
                background: rgba(0,0,0,0.4); color: {c['neon_green']}; padding: 0.75rem;
                border-radius: 8px; border: 1px solid rgba(0,255,159,0.1);
                font-family: 'JetBrains Mono', monospace; font-size: 11px;
                line-height: 1.6; overflow-x: auto; white-space: pre-wrap; word-break: break-all;
            }}
            .finding-remediation {{
                margin-top: 1rem; background: rgba(0,255,159,0.03); padding: 0.75rem;
                border-radius: 8px; border: 1px solid rgba(0,255,159,0.08);
            }}
            .remediation-label {{
                font-size: 8px; font-family: 'JetBrains Mono', monospace; font-weight: 800;
                letter-spacing: 2px; color: {c['neon_green']}; margin-bottom: 0.3rem;
            }}
            .remediation-text {{ font-size: 12px; color: {c['text_secondary']}; line-height: 1.7; }}

            /* ═══ OWASP TABLE ═══ */
            .owasp-section {{ margin-top: 0.5rem; }}
            .risk-index {{ text-align: right; }}
            .risk-label {{
                display: block; font-size: 8px; font-family: 'JetBrains Mono', monospace; font-weight: 800;
                letter-spacing: 2px; color: {c['text_secondary']};
            }}
            .risk-value {{ font-size: 1.5rem; font-weight: 800; font-family: 'JetBrains Mono', monospace; }}
            .risk-tag {{ display: block; font-size: 8px; font-weight: 800; letter-spacing: 1px; }}
            .owasp-table {{ width: 100%; border-collapse: collapse; margin-top: 0.5rem; }}
            .owasp-th {{
                font-size: 8px; font-family: 'JetBrains Mono', monospace; font-weight: 800;
                letter-spacing: 2px; color: {c['text_secondary']}; padding: 0.6rem 0.75rem;
                text-align: left; border-bottom: 1px solid {c['border_cyber']};
            }}
            .owasp-code {{
                padding: 0.5rem 0.75rem; font-family: 'JetBrains Mono', monospace; font-size: 10px;
                font-weight: 700; color: {c['text_primary']}; opacity: 0.6; border-bottom: 1px solid rgba(255,255,255,0.02);
            }}
            .owasp-name {{
                padding: 0.5rem 0.75rem; font-size: 11px; font-weight: 700; color: {c['text_primary']};
                border-bottom: 1px solid rgba(255,255,255,0.02);
            }}
            .owasp-status {{ padding: 0.5rem 0.75rem; text-align: center; border-bottom: 1px solid rgba(255,255,255,0.02); }}

            /* ═══ ATTACK SURFACE ═══ */
            .surface-section {{ margin-top: 0.5rem; }}
            .surface-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 2rem; margin-top: 1rem; }}
            .surface-table {{ width: 100%; border-collapse: collapse; border: 1px solid {c['border_cyber']}; border-radius: 8px; overflow: hidden; }}
            .surface-th {{
                font-size: 8px; font-family: 'JetBrains Mono', monospace; font-weight: 800;
                letter-spacing: 2px; color: {c['text_secondary']}; padding: 0.5rem 0.75rem;
                text-align: left; background: rgba(0,0,0,0.3); border-bottom: 1px solid {c['border_cyber']};
            }}
            .surface-row {{ border-bottom: 1px solid rgba(255,255,255,0.02); }}
            .surface-row:hover {{ background: rgba(0,243,255,0.02); }}
            .surface-path {{
                padding: 0.4rem 0.75rem; font-family: 'JetBrains Mono', monospace; font-size: 10px; color: {c['text_primary']};
            }}
            .surface-status {{
                padding: 0.4rem 0.75rem; font-size: 10px; font-weight: 700; font-family: 'JetBrains Mono', monospace;
            }}
            .surface-type {{ padding: 0.4rem 0.75rem; font-size: 10px; color: {c['text_secondary']}; }}
            .surface-overflow {{
                margin-top: 0.5rem; font-size: 9px; color: {c['text_secondary']};
                text-align: right; font-style: italic;
            }}
            .surface-stats {{ display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; margin-top: 1rem; }}
            .surface-stat-card {{
                padding: 0.75rem; border-radius: 8px; border: 1px solid {c['border_cyber']};
                background: {c['bg_card']};
            }}
            .surface-stat-label {{
                display: block; font-size: 8px; font-family: 'JetBrains Mono', monospace;
                font-weight: 800; letter-spacing: 2px; color: {c['text_secondary']}; margin-bottom: 4px;
            }}
            .surface-stat-value {{ font-size: 13px; font-weight: 700; color: {c['text_primary']}; }}
            .forms-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; }}
            .form-card {{
                padding: 0.75rem; border-radius: 8px; border: 1px solid {c['border_cyber']};
                background: {c['bg_card']};
            }}
            .form-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.4rem; }}
            .form-label {{
                font-size: 8px; font-family: 'JetBrains Mono', monospace; font-weight: 800;
                letter-spacing: 2px; color: {c['text_secondary']};
            }}
            .form-method {{
                font-size: 8px; font-weight: 800; padding: 2px 6px; border-radius: 3px;
                background: linear-gradient(135deg, {c['neon_cyan']}, {c['neon_blue']});
                color: {c['bg_app']};
            }}
            .form-action {{
                font-size: 10px; font-family: 'JetBrains Mono', monospace; color: {c['text_primary']};
                overflow: hidden; text-overflow: ellipsis; white-space: nowrap; margin-bottom: 0.25rem;
            }}
            .form-inputs {{ font-size: 9px; color: {c['text_secondary']}; }}
            .form-inputs-list {{ color: {c['neon_cyan']}; font-weight: 700; }}

            .no-data {{
                text-align: center; padding: 1.5rem; font-size: 10px; font-family: 'JetBrains Mono', monospace;
                font-weight: 700; letter-spacing: 2px; color: {c['text_secondary']}; opacity: 0.5;
                border: 1px dashed {c['border_cyber']}; border-radius: 8px;
            }}

            /* ═══ FOOTER ═══ */
            .report-footer {{
                margin-top: 3rem; text-align: center; padding-top: 1.5rem;
            }}
            .footer-line {{
                height: 1px; margin-bottom: 1.5rem;
                background: linear-gradient(90deg, transparent, {c['border_cyber']}, transparent);
            }}
            .footer-brand {{
                font-size: 9px; font-family: 'JetBrains Mono', monospace; font-weight: 800;
                letter-spacing: 3px; color: {c['text_secondary']}; opacity: 0.6;
            }}
            .footer-id {{
                margin-top: 0.5rem; font-size: 9px; font-family: 'JetBrains Mono', monospace;
                color: {c['text_secondary']}; opacity: 0.3; letter-spacing: 0.5px;
            }}

            /* ═══ PRINT ═══ */
            @media print {{
                .crt-overlay, .cyber-grid {{ display: none !important; }}
                body {{ background: #0a0a12 !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
                .cyber-card, .finding-card, .metric-card {{ break-inside: avoid; box-shadow: none !important; }}
            }}

            /* ═══ RESPONSIVE ═══ */
            @media (max-width: 768px) {{
                .report-header {{ flex-direction: column; }}
                .metrics-grid {{ grid-template-columns: repeat(3, 1fr); }}
                .charts-grid {{ grid-template-columns: 1fr; }}
                .surface-grid {{ grid-template-columns: 1fr; }}
                .stats-bar {{ grid-template-columns: 1fr; }}
                .forms-grid {{ grid-template-columns: 1fr; }}
            }}
            @media (max-width: 480px) {{
                .metrics-grid {{ grid-template-columns: repeat(2, 1fr); }}
                .report-title {{ font-size: 1.2rem; letter-spacing: 1.5px; }}
            }}

            /* ═══ SCROLLBAR ═══ */
            ::-webkit-scrollbar {{ width: 6px; }}
            ::-webkit-scrollbar-track {{ background: transparent; }}
            ::-webkit-scrollbar-thumb {{ background: rgba(0,243,255,0.15); border-radius: 3px; }}
            ::-webkit-scrollbar-thumb:hover {{ background: rgba(0,243,255,0.3); }}
        """
