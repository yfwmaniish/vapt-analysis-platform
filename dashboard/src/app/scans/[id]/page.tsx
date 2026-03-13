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
    Terminal,
    Network,
} from "lucide-react";
import {
    API_BASE,
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
            className={`cyber-card overflow-hidden ${open ? 'border-opacity-100 shadow-[0_0_15px_rgba(0,0,0,0.5)]' : 'border-opacity-50'}`}
            style={{ borderLeft: `3px solid ${borderColor}` }}
        >
            <button
                onClick={() => setOpen(!open)}
                className="w-full p-4 flex items-center justify-between text-left hover:bg-[rgba(255,255,255,0.02)] transition-colors"
            >
                <div className="flex items-center gap-4 min-w-0">
                    <div className="p-2 rounded bg-black/40 border border-[var(--border-cyber)]">
                        <Icon className="w-4 h-4 flex-shrink-0" style={{ color: borderColor }} />
                    </div>
                    <div className="min-w-0">
                        <div className="flex items-center gap-2 mb-1 flex-wrap">
                            <SeverityBadge severity={finding.severity} />
                            <span className="font-mono text-[10px] uppercase text-[var(--text-secondary)] opacity-80 tracking-widest">{finding.scanner}</span>
                        </div>
                        <p className={`text-sm font-semibold truncate font-mono tracking-wide ${open ? 'text-[var(--text-primary)] text-glow-sm' : 'text-[var(--text-primary)]'} transition-all`} style={open ? { color: borderColor } : {}}>
                            {finding.title}
                        </p>
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
                        className="border-t border-[var(--border-cyber)] overflow-hidden bg-black/20"
                    >
                        <div className="p-5 space-y-4 text-sm">
                            <div>
                                <p className="cyber-label mb-2 text-[var(--neon-cyan)] max-w-max flex items-center gap-2">
                                    <Shield className="w-3 h-3" /> Description
                                </p>
                                <p className="text-[var(--text-primary)] leading-relaxed font-sans">{finding.description}</p>
                            </div>

                            {finding.evidence && (
                                <div>
                                    <p className="cyber-label mb-2 text-[var(--neon-yellow)] max-w-max flex items-center gap-2">
                                        <Terminal className="w-3 h-3" /> Evidence // Proof_of_Concept
                                    </p>
                                    <div className="relative group">
                                        <div className="absolute inset-0 bg-[var(--neon-yellow)]/5 rounded-md pointer-events-none" />
                                        <div className="absolute left-0 top-0 bottom-0 w-1 bg-[var(--neon-yellow)] rounded-l-md" />
                                        <pre className="text-xs text-[var(--text-secondary)] bg-[#050510] border border-[var(--border-cyber)] rounded-md p-4 overflow-x-auto whitespace-pre-wrap font-mono pl-5">
                                            {finding.evidence}
                                        </pre>
                                    </div>
                                </div>
                            )}

                            {finding.location && (
                                <div>
                                    <span className="cyber-label inline-block mr-2 text-[var(--neon-purple)]">TARGET_LOC:</span>
                                    <span className="text-xs font-mono tracking-wide bg-black/50 px-2 py-1 border border-[var(--border-cyber)] rounded text-[var(--text-primary)]">{finding.location}</span>
                                </div>
                            )}

                            {finding.remediation && (
                                <div className="bg-[rgba(0,255,159,0.05)] border border-[rgba(0,255,159,0.2)] rounded-md p-4">
                                    <p className="cyber-label text-[var(--neon-green)] mb-2 flex items-center gap-2">
                                        <CheckCircle className="w-3 h-3" /> Remediation_Protocol
                                    </p>
                                    <p className="text-sm text-[var(--text-primary)] font-sans leading-relaxed">{finding.remediation}</p>
                                </div>
                            )}

                            {finding.cwe_id && (
                                <div className="pt-2">
                                    <span className="font-mono text-[10px] text-[var(--text-secondary)] opacity-70 uppercase tracking-widest border border-[var(--border-cyber)] px-2 py-1 rounded bg-black/30">
                                        CWE_REF: {finding.cwe_id}
                                    </span>
                                </div>
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
        <div className="cyber-card p-6 border-[var(--neon-blue)]/50 shadow-[0_0_20px_rgba(59,130,246,0.1)] relative overflow-hidden">
            <div className="absolute right-0 top-0 w-32 h-32 bg-[var(--neon-blue)]/10 blur-3xl rounded-full" />

            <div className="flex items-center gap-3 mb-6 relative z-10">
                <Loader2 className="w-5 h-5 text-[var(--neon-cyan)] animate-spin" />
                <h2 className="cyber-label text-[var(--neon-cyan)] text-glow">
                    Active_Scan_Sequence
                </h2>
                <div className="ml-auto w-2 h-2 rounded-full bg-[var(--neon-cyan)] pulse-glow" />
            </div>

            <div className="space-y-5 relative z-10">
                {Object.entries(modules).map(([mod, { pct, msg }]) => (
                    <div key={mod} className="space-y-2">
                        <div className="flex justify-between font-mono text-xs uppercase tracking-widest">
                            <span className="text-[var(--text-primary)] font-bold">{mod}</span>
                            <span className="text-[var(--neon-cyan)]">{pct.toFixed(0)}%</span>
                        </div>
                        <div className="progress-bar bg-black/50 border border-[var(--border-cyber)]">
                            <div className="progress-fill shadow-[0_0_10px_rgba(0,243,255,0.5)]" style={{ width: `${pct}%` }} />
                        </div>
                        <p className="font-mono text-[10px] text-[var(--text-secondary)] opacity-80 uppercase truncate">
                            &gt; {msg || "Processing..."}
                        </p>
                    </div>
                ))}
            </div>
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
                                getScan(scanId).then(setScan);
                            }
                        },
                        () => {
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
            <div className="max-w-5xl mx-auto flex flex-col items-center justify-center py-32">
                <Loader2 className="w-12 h-12 animate-spin text-[var(--neon-cyan)] drop-shadow-[0_0_15px_rgba(0,243,255,0.5)] mb-4" />
                <span className="cyber-label">Decrypting_Data_Stream...</span>
            </div>
        );
    }

    if (error || !scan) {
        return (
            <div className="max-w-5xl mx-auto cyber-card p-10 text-center border-[var(--severity-critical)] bg-black/50">
                <AlertOctagon className="w-12 h-12 text-[var(--severity-critical)] mx-auto mb-4" />
                <span className="font-mono text-lg text-[var(--severity-critical)] text-glow-sm">{error || "Scan record not found"}</span>
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
                    <div className="flex items-center gap-3 mb-2">
                        <div className="p-2 bg-black/40 border border-[var(--border-cyber)] rounded text-[var(--neon-cyan)]">
                            <TargetIcon className="w-5 h-5" />
                        </div>
                        <h1 className="text-2xl font-bold font-mono text-[var(--text-primary)] tracking-wide">{scan.target}</h1>
                        <span
                            className={`badge badge-${scan.status === "completed" ? "info" : scan.status === "running" ? "medium" : "critical"
                                } ml-2`}
                        >
                            {scan.status}
                        </span>
                    </div>
                    <div className="flex items-center gap-4 text-xs font-mono text-[var(--text-secondary)] uppercase tracking-widest pl-12">
                        <span className="flex items-center gap-1">
                            <Clock className="w-3 h-3" />
                            {new Date(scan.created_at).toLocaleString('en-US', { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' })}
                        </span>
                        {scan.duration_seconds && <span className="text-[var(--neon-blue)]">DUR: {scan.duration_seconds.toFixed(1)}s</span>}
                        <span className="opacity-50">UID: {scan.scan_id.slice(0, 8)}</span>
                    </div>
                </div>
                {scan.status === "completed" && (
                    <div className="mt-4 sm:mt-0">
                        <a
                            href={`${API_BASE}/api/scans/${scan.scan_id}/report`}
                            download={`Veltro_VAPT_${scan.scan_id.slice(0, 8)}.html`}
                            className="flex items-center gap-2 px-5 py-2.5 bg-transparent text-[var(--neon-cyan)] border border-[var(--neon-cyan)]/50 rounded font-mono text-xs uppercase tracking-widest hover:bg-[var(--neon-cyan)]/10 transition-colors shadow-[0_0_10px_rgba(0,243,255,0.1)]"
                        >
                            <Download className="w-4 h-4" />
                            DL_REPORT
                        </a>
                    </div>
                )}
            </motion.div>

            {/* Progress (if running) */}
            {scan.status === "running" && <ProgressView events={progressEvents} />}

            {/* Severity Stats - Cyber Style */}
            {
                scan.status !== "running" && (
                    <motion.div
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: 0.1 }}
                        className="grid grid-cols-2 sm:grid-cols-5 gap-3"
                    >
                        {(["critical", "high", "medium", "low", "info"] as const).map((sev) => {
                            const isActive = filter === sev;
                            const isAll = filter === "all";
                            const isDimmed = !isAll && !isActive;
                            
                            return (
                                <button
                                    key={sev}
                                    onClick={() => {
                                        setFilter(isActive ? "all" : sev);
                                        setActiveTab("findings");
                                    }}
                                    className={`cyber-card-sm p-4 text-center cursor-pointer transition-all ${
                                        isActive 
                                        ? `border-[var(--severity-${sev})] bg-[rgba(255,255,255,0.05)] shadow-[0_0_15px_rgba(0,0,0,0.5)]` 
                                        : "hover:border-[var(--border-cyber-hover)]"
                                    } ${isDimmed ? "opacity-40" : "opacity-100"}`}
                                >
                                    <p className={`text-3xl font-bold font-mono ${isActive ? "text-glow" : ""}`} style={{ color: `var(--severity-${sev})` }}>
                                        {counts[sev]}
                                    </p>
                                    <p className="font-mono text-[10px] text-[var(--text-secondary)] uppercase tracking-widest mt-1">
                                        {sev}
                                    </p>
                                </button>
                            );
                        })}
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
                        className="cyber-card p-6 border-[var(--neon-purple)]/40 relative overflow-hidden"
                    >
                        <div className="absolute right-0 top-0 w-32 h-32 bg-[var(--neon-purple)]/10 blur-3xl rounded-full" />
                        
                        <h2 className="cyber-label text-[var(--neon-purple)] text-glow-sm mb-4 flex items-center gap-2 relative z-10">
                            <Brain className="w-4 h-4" />
                            AI_Executive_Summary
                        </h2>
                        <div className="relative group z-10">
                            <div className="absolute left-0 top-0 bottom-0 w-1 bg-[var(--neon-purple)]/50 rounded-full" />
                            <pre className="text-sm text-[var(--text-primary)] whitespace-pre-wrap leading-relaxed font-sans pl-4">
                                {scan.ai_summary}
                            </pre>
                        </div>
                    </motion.div>
                )
            }

            {/* Tab Navigation */}
            {
                scan.status !== "running" && scan.attack_surface && (
                    <div className="flex gap-8 border-b border-[var(--border-cyber)] pt-4 px-2">
                        <button
                            onClick={() => setActiveTab("findings")}
                            className={`pb-3 cyber-label transition-colors relative ${activeTab === "findings" ? "text-[var(--neon-cyan)] text-glow-sm" : "text-[var(--text-secondary)] hover:text-white"
                                }`}
                        >
                            <span className="flex items-center gap-2">
                                <Shield className="w-4 h-4" />
                                Findings ({filtered.length})
                            </span>
                            {activeTab === "findings" && (
                                <motion.div layoutId="activeTab" className="absolute bottom-[-1px] left-0 right-0 h-0.5 bg-[var(--neon-cyan)] shadow-[0_0_10px_rgba(0,243,255,0.8)]" />
                            )}
                        </button>
                        <button
                            onClick={() => setActiveTab("surface")}
                            className={`pb-3 cyber-label transition-colors relative ${activeTab === "surface" ? "text-[var(--neon-purple)] text-glow-sm" : "text-[var(--text-secondary)] hover:text-white"
                                }`}
                        >
                            <span className="flex items-center gap-2">
                                <Network className="w-4 h-4" />
                                Attack_Map
                            </span>
                            {activeTab === "surface" && (
                                <motion.div layoutId="activeTab" className="absolute bottom-[-1px] left-0 right-0 h-0.5 bg-[var(--neon-purple)] shadow-[0_0_10px_rgba(188,19,254,0.8)]" />
                            )}
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
                                    <div className="cyber-card p-12 text-center flex flex-col items-center">
                                        <CheckCircle className="w-12 h-12 mb-4 text-[var(--neon-green)] opacity-40 shadow-glow" />
                                        <h3 className="font-mono text-lg text-[var(--neon-green)] mb-1">ALL_CLEAR</h3>
                                        <p className="font-mono text-[10px] text-[var(--text-secondary)] uppercase tracking-widest">No matching findings found.</p>
                                    </div>
                                ) : (
                                    <div className="space-y-3">
                                        {filtered.map((finding: any, i: number) => (
                                            <FindingCard key={i} finding={finding} index={i} />
                                        ))}
                                    </div>
                                )}
                            </div>
                        )}

                        {/* Attack Surface Tab */}
                        {activeTab === "surface" && scan.attack_surface && (
                            <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="cyber-card p-2 bg-black/20">
                                <AttackSurfaceView data={scan.attack_surface} />
                            </motion.div>
                        )}
                    </div>
                )
            }
        </div >
    );
}

// Map components fixing issues with missing icons from copy-paste
const Layers = Shield;
