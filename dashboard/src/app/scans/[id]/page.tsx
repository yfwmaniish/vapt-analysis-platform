"use client";

import { useEffect, useState, useRef } from "react";
import { useParams } from "next/navigation";
import { motion, AnimatePresence } from "framer-motion";
import {
    Shield,
    AlertTriangle,
    AlertOctagon,
    Info,
    CheckCircle,
    Loader2,
    Clock,
    Target as TargetIcon,
    Brain,
    ChevronDown,
    ChevronUp,
    Download,
} from "lucide-react";
import {
    getScan,
    connectScanWS,
    type ScanResult,
    type Finding,
    type ProgressEvent,
} from "@/lib/api";
import AttackSurfaceView from "@/components/AttackSurfaceView";

/* ── Severity Helpers ──────────────────────────────────────── */
const SEV_ICON: Record<string, any> = {
    critical: AlertOctagon,
    high: AlertTriangle,
    medium: AlertTriangle,
    low: Info,
    info: Info,
};

function SeverityBadge({ severity }: { severity: string }) {
    return <span className={`badge badge-${severity}`}>{severity}</span>;
}

/* ── Finding Card ──────────────────────────────────────────── */
function FindingCard({ finding, index }: { finding: Finding; index: number }) {
    const [open, setOpen] = useState(false);
    const Icon = SEV_ICON[finding.severity] || Info;
    const borderColor = `var(--severity-${finding.severity})`;

    return (
        <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: index * 0.03 }}
            className="glass-card overflow-hidden"
            style={{ borderLeft: `3px solid ${borderColor}` }}
        >
            <button
                onClick={() => setOpen(!open)}
                className="w-full p-4 flex items-center justify-between text-left hover:bg-[var(--bg-card-hover)] transition-colors"
            >
                <div className="flex items-center gap-3 min-w-0">
                    <Icon className="w-4 h-4 flex-shrink-0" style={{ color: borderColor }} />
                    <div className="min-w-0">
                        <div className="flex items-center gap-2 mb-0.5 flex-wrap">
                            <SeverityBadge severity={finding.severity} />
                            <span className="text-xs text-[var(--text-secondary)]">{finding.scanner}</span>
                        </div>
                        <p className="text-sm font-medium truncate">{finding.title}</p>
                    </div>
                </div>
                {open ? (
                    <ChevronUp className="w-4 h-4 text-[var(--text-secondary)] flex-shrink-0" />
                ) : (
                    <ChevronDown className="w-4 h-4 text-[var(--text-secondary)] flex-shrink-0" />
                )}
            </button>

            <AnimatePresence>
                {open && (
                    <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: "auto", opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        className="border-t border-[var(--border-glass)] overflow-hidden"
                    >
                        <div className="p-4 space-y-3 text-sm">
                            <div>
                                <p className="text-[var(--text-secondary)] text-xs font-semibold uppercase mb-1">
                                    Description
                                </p>
                                <p className="text-[var(--text-primary)] leading-relaxed">{finding.description}</p>
                            </div>

                            {finding.evidence && (
                                <div>
                                    <p className="text-[var(--text-secondary)] text-xs font-semibold uppercase mb-1">
                                        Evidence
                                    </p>
                                    <pre className="text-xs text-[var(--text-secondary)] bg-black/30 rounded-md p-3 overflow-x-auto whitespace-pre-wrap font-mono">
                                        {finding.evidence}
                                    </pre>
                                </div>
                            )}

                            {finding.location && (
                                <div>
                                    <span className="text-xs text-[var(--text-secondary)]">📍 </span>
                                    <span className="text-xs font-mono">{finding.location}</span>
                                </div>
                            )}

                            {finding.remediation && (
                                <div className="bg-[rgba(6,214,160,0.05)] border border-[rgba(6,214,160,0.15)] rounded-md p-3">
                                    <p className="text-xs font-semibold text-[var(--accent-cyan)] uppercase mb-1">
                                        🔧 Remediation
                                    </p>
                                    <p className="text-sm text-[var(--text-primary)]">{finding.remediation}</p>
                                </div>
                            )}

                            {finding.cwe_id && (
                                <span className="text-xs text-[var(--text-secondary)]">
                                    CWE: {finding.cwe_id}
                                </span>
                            )}
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>
        </motion.div>
    );
}

/* ── Progress View ─────────────────────────────────────────── */
function ProgressView({ events }: { events: ProgressEvent[] }) {
    // Group by module
    const modules: Record<string, { pct: number; msg: string }> = {};
    for (const ev of events) {
        if (ev.module) {
            modules[ev.module] = { pct: ev.percentage || 0, msg: ev.message || "" };
        }
    }

    return (
        <div className="glass-card p-6 space-y-4">
            <div className="flex items-center gap-3 mb-2">
                <Loader2 className="w-5 h-5 text-[var(--accent-cyan)] animate-spin" />
                <h2 className="text-sm font-semibold uppercase tracking-widest text-[var(--text-secondary)]">
                    Scan In Progress
                </h2>
            </div>

            {Object.entries(modules).map(([mod, { pct, msg }]) => (
                <div key={mod} className="space-y-1">
                    <div className="flex justify-between text-xs">
                        <span className="font-medium">{mod}</span>
                        <span className="text-[var(--text-secondary)]">{pct.toFixed(0)}%</span>
                    </div>
                    <div className="progress-bar">
                        <div className="progress-fill" style={{ width: `${pct}%` }} />
                    </div>
                    <p className="text-[0.65rem] text-[var(--text-secondary)]">{msg}</p>
                </div>
            ))}
        </div>
    );
}

/* ── Scan Result Page ──────────────────────────────────────── */
export default function ScanResultPage() {
    const params = useParams();
    const scanId = params.id as string;
    const API_BASE = process.env.NEXT_PUBLIC_API_BASE || "http://localhost:8000";

    const [scan, setScan] = useState<ScanResult | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");
    const [progressEvents, setProgressEvents] = useState<ProgressEvent[]>([]);
    const [filter, setFilter] = useState<string>("all");
    const [activeTab, setActiveTab] = useState<"findings" | "surface">("findings");
    const wsRef = useRef<WebSocket | null>(null);

    useEffect(() => {
        if (!scanId) return;

        getScan(scanId)
            .then((data) => {
                setScan(data);

                // If still running, connect WS
                if (data.status === "running") {
                    const ws = connectScanWS(
                        scanId,
                        (event) => {
                            if (event.type === "progress") {
                                setProgressEvents((prev) => [...prev, event]);
                            } else if (event.type === "complete") {
                                // Reload full results
                                getScan(scanId).then(setScan);
                            }
                        },
                        () => {
                            // On close, reload
                            setTimeout(() => getScan(scanId).then(setScan), 1000);
                        }
                    );
                    wsRef.current = ws;
                }
            })
            .catch((err) => setError(err.message))
            .finally(() => setLoading(false));

        return () => wsRef.current?.close();
    }, [scanId]);

    // Auto-poll for running scans
    useEffect(() => {
        if (!scan || scan.status !== "running") return;
        const interval = setInterval(() => {
            getScan(scanId).then((data) => {
                setScan(data);
                if (data.status !== "running") clearInterval(interval);
            });
        }, 3000);
        return () => clearInterval(interval);
    }, [scan?.status, scanId]);

    if (loading) {
        return (
            <div className="max-w-5xl mx-auto flex items-center justify-center py-20">
                <Loader2 className="w-8 h-8 animate-spin text-[var(--accent-cyan)]" />
            </div>
        );
    }

    if (error || !scan) {
        return (
            <div className="max-w-5xl mx-auto glass-card p-10 text-center text-[var(--severity-critical)]">
                {error || "Scan not found"}
            </div>
        );
    }

    // Count severities
    const findings = scan.findings || [];
    const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach((f: any) => { counts[f.severity] = (counts[f.severity] || 0) + 1; });

    const filtered =
        filter === "all" ? findings : findings.filter((f: any) => f.severity === filter);

    return (
        <div className="max-w-5xl mx-auto space-y-6">
            {/* Header */}
            <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }} className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
                <div>
                    <div className="flex items-center gap-3 mb-1">
                        <h1 className="text-2xl font-bold">{scan.target}</h1>
                        <span
                            className={`badge badge-${scan.status === "completed" ? "info" : scan.status === "running" ? "medium" : "critical"
                                }`}
                        >
                            {scan.status}
                        </span>
                    </div>
                    <div className="flex items-center gap-4 text-xs text-[var(--text-secondary)]">
                        <span className="flex items-center gap-1">
                            <Clock className="w-3 h-3" />
                            {new Date(scan.created_at).toLocaleString()}
                        </span>
                        {scan.duration_seconds && <span>Duration: {scan.duration_seconds.toFixed(1)}s</span>}
                        <span>ID: {scan.scan_id.slice(0, 8)}</span>
                    </div>
                </div>
                {scan.status === "completed" && (
                    <div className="mt-4 sm:mt-0">
                        <a
                            href={`${API_BASE}/api/scans/${scan.scan_id}/report`}
                            download={`Veltro_VAPT_Report_${scan.scan_id.slice(0, 8)}.html`}
                            className="flex items-center gap-2 px-4 py-2 bg-[var(--accent-cyan)]/10 text-[var(--accent-cyan)] border border-[var(--accent-cyan)]/30 rounded font-medium text-sm hover:bg-[var(--accent-cyan)]/20 transition-colors"
                        >
                            <Download className="w-4 h-4" />
                            Download HTML Report
                        </a>
                    </div>
                )}
            </motion.div>

            {/* Progress (if running) */}
            {scan.status === "running" && <ProgressView events={progressEvents} />}

            {/* Severity Stats */}
            {
                scan.status !== "running" && (
                    <motion.div
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: 0.1 }}
                        className="grid grid-cols-5 gap-3"
                    >
                        {(["critical", "high", "medium", "low", "info"] as const).map((sev) => (
                            <button
                                key={sev}
                                onClick={() => {
                                    setFilter(filter === sev ? "all" : sev);
                                    setActiveTab("findings");
                                }}
                                className={`glass-card p-4 text-center cursor-pointer transition-all ${filter === sev ? "border-[var(--accent-cyan)]" : ""
                                    }`}
                            >
                                <p className="text-xl font-bold" style={{ color: `var(--severity-${sev})` }}>
                                    {counts[sev]}
                                </p>
                                <p className="text-[0.65rem] text-[var(--text-secondary)] uppercase font-semibold">
                                    {sev}
                                </p>
                            </button>
                        ))}
                    </motion.div>
                )
            }

            {/* AI Summary */}
            {
                scan.ai_summary && (
                    <motion.div
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: 0.2 }}
                        className="glass-card p-6 border-[rgba(6,214,160,0.2)]"
                    >
                        <h2 className="text-sm font-semibold uppercase tracking-widest text-[var(--accent-cyan)] mb-3 flex items-center gap-2">
                            <Brain className="w-4 h-4" />
                            AI Security Analysis
                        </h2>
                        <pre className="text-sm text-[var(--text-primary)] whitespace-pre-wrap leading-relaxed font-sans">
                            {scan.ai_summary}
                        </pre>
                    </motion.div>
                )
            }

            {/* Tab Navigation */}
            {
                scan.status !== "running" && scan.attack_surface && (
                    <div className="flex gap-6 border-b border-[var(--border-glass)] pt-4">
                        <button
                            onClick={() => setActiveTab("findings")}
                            className={`pb-3 text-sm font-semibold uppercase tracking-widest transition-colors ${activeTab === "findings" ? "text-[var(--accent-cyan)] border-b-2 border-[var(--accent-cyan)]" : "text-[var(--text-secondary)] hover:text-white"
                                }`}
                        >
                            Security Findings ({filtered.length})
                        </button>
                        <button
                            onClick={() => setActiveTab("surface")}
                            className={`pb-3 text-sm font-semibold uppercase tracking-widest transition-colors ${activeTab === "surface" ? "text-purple-400 border-b-2 border-purple-400" : "text-[var(--text-secondary)] hover:text-white"
                                }`}
                        >
                            <span className="flex items-center gap-2">
                                <TargetIcon className="w-4 h-4" />
                                Attack Surface Map
                            </span>
                        </button>
                    </div>
                )
            }

            {/* Tabs Content */}
            {
                scan.status !== "running" && (
                    <div className="mt-6">
                        {/* Findings Tab */}
                        {activeTab === "findings" && (
                            <div className="space-y-4">
                                {filtered.length === 0 ? (
                                    <div className="glass-card p-10 text-center">
                                        <CheckCircle className="w-12 h-12 mx-auto mb-3 text-[var(--accent-cyan)] opacity-30" />
                                        <p className="text-[var(--text-secondary)]">No findings match this filter.</p>
                                    </div>
                                ) : (
                                    <div className="space-y-2">
                                        {filtered.map((finding: any, i: number) => (
                                            <FindingCard key={i} finding={finding} index={i} />
                                        ))}
                                    </div>
                                )}
                            </div>
                        )}

                        {/* Attack Surface Tab */}
                        {activeTab === "surface" && scan.attack_surface && (
                            <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}>
                                <AttackSurfaceView data={scan.attack_surface} />
                            </motion.div>
                        )}
                    </div>
                )
            }
        </div >
    );
}
