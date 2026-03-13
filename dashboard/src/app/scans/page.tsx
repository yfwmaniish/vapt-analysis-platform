"use client";

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { ListChecks, Clock, Shield, ExternalLink, Crosshair } from "lucide-react";
import Link from "next/link";
import { listScans, type ScanListItem } from "@/lib/api";

export default function ScansListPage() {
    const [scans, setScans] = useState<ScanListItem[]>([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        listScans()
            .then(setScans)
            .catch(() => { })
            .finally(() => setLoading(false));
    }, []);

    const formatTime = (dateStr: string) => {
        const date = new Date(dateStr);
        return date.toLocaleString('en-US', {
            month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit'
        });
    };

    return (
        <div className="max-w-5xl mx-auto space-y-6">
            <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }}>
                <h1 className="text-2xl font-bold font-mono tracking-wide flex items-center gap-3">
                    <ListChecks className="w-6 h-6 text-[var(--neon-cyan)]" />
                    Operation_History
                </h1>
                <p className="cyber-label mt-2">
                    Review and analyze deployed scanning sequences
                </p>
            </motion.div>

            {loading ? (
                <div className="cyber-card p-10 text-center flex flex-col items-center">
                    <Crosshair className="w-8 h-8 text-[var(--neon-cyan)] animate-spin mb-3" />
                    <span className="cyber-label">Retrieving_Data...</span>
                </div>
            ) : scans.length === 0 ? (
                <div className="cyber-card p-10 text-center flex flex-col items-center">
                    <Shield className="w-12 h-12 mb-3 opacity-20" />
                    <span className="cyber-label opacity-50 mb-4">NO_OPERATIONS_FOUND</span>
                    <Link href="/scan">
                        <button className="btn-primary">Initialize Sequence</button>
                    </Link>
                </div>
            ) : (
                <div className="space-y-3">
                    {scans.map((scan, i) => {
                        const hasCritical = scan.critical_count > 0;
                        const hasHigh = scan.high_count > 0;
                        const borderColor = hasCritical ? 'var(--severity-critical)' : hasHigh ? 'var(--severity-high)' : 'var(--neon-cyan)';

                        return (
                            <motion.div
                                key={scan.scan_id}
                                initial={{ opacity: 0, y: 10 }}
                                animate={{ opacity: 1, y: 0 }}
                                transition={{ delay: i * 0.05 }}
                            >
                                <Link href={`/scans/${scan.scan_id}`}>
                                    <div
                                        className="cyber-card p-5 flex items-center justify-between hover:border-[var(--border-cyber-hover)] cursor-pointer group transition-all"
                                    >
                                        <div className="flex items-center gap-5">
                                            {/* Target Reticle Icon */}
                                            <div className="w-10 h-10 rounded border border-[var(--border-cyber)] bg-black/40 flex items-center justify-center group-hover:bg-[rgba(0,243,255,0.05)] group-hover:border-[var(--neon-cyan)] transition-colors">
                                                <Crosshair className="w-5 h-5 text-[var(--text-secondary)] group-hover:text-[var(--neon-cyan)] group-hover:scale-110 transition-all" />
                                            </div>

                                            <div>
                                                <div className="flex items-center gap-3 mb-1">
                                                    <p className="font-mono font-semibold text-lg text-[var(--text-primary)] group-hover:text-[var(--neon-cyan)] transition-colors">
                                                        {scan.target}
                                                    </p>
                                                    <span
                                                        className={`badge badge-${scan.status === "completed"
                                                            ? "info"
                                                            : scan.status === "running"
                                                                ? "medium"
                                                                : "critical"
                                                            }`}
                                                    >
                                                        {scan.status}
                                                    </span>
                                                </div>
                                                <div className="flex items-center gap-4 text-xs font-mono text-[var(--text-secondary)] uppercase">
                                                    <span className="flex items-center gap-1.5 opacity-80">
                                                        <Clock className="w-3 h-3" />
                                                        {formatTime(scan.created_at)}
                                                    </span>
                                                    {scan.duration_seconds && (
                                                        <span className="opacity-80">DUR: {scan.duration_seconds.toFixed(1)}s</span>
                                                    )}
                                                    <span className="opacity-80 text-[var(--neon-cyan)] tracking-wider">
                                                        [{scan.findings_count} DETECTED]
                                                    </span>
                                                </div>
                                            </div>
                                        </div>

                                        <div className="flex items-center gap-3">
                                            {scan.critical_count > 0 && (
                                                <span className="badge badge-critical flex items-center gap-1">
                                                    {scan.critical_count} CRITICAL
                                                </span>
                                            )}
                                            {scan.high_count > 0 && (
                                                <span className="badge badge-high flex items-center gap-1">
                                                    {scan.high_count} HIGH
                                                </span>
                                            )}
                                            <div className="w-8 flex justify-end">
                                                <ExternalLink className="w-4 h-4 text-[var(--neon-cyan)] opacity-0 group-hover:opacity-100 transition-opacity transform group-hover:-translate-y-0.5 group-hover:translate-x-0.5" />
                                            </div>
                                        </div>
                                    </div>
                                </Link>
                            </motion.div>
                        );
                    })}
                </div>
            )}
        </div>
    );
}
