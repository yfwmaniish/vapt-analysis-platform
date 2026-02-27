"use client";

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { ListChecks, Clock, Shield, ExternalLink } from "lucide-react";
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

    return (
        <div className="max-w-5xl mx-auto space-y-6">
            <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }}>
                <h1 className="text-2xl font-bold flex items-center gap-3">
                    <ListChecks className="w-6 h-6 text-[var(--accent-cyan)]" />
                    Scan History
                </h1>
                <p className="text-sm text-[var(--text-secondary)] mt-1">
                    View all previous security assessments
                </p>
            </motion.div>

            {loading ? (
                <div className="glass-card p-10 text-center text-[var(--text-secondary)]">
                    Loading scans...
                </div>
            ) : scans.length === 0 ? (
                <div className="glass-card p-10 text-center">
                    <Shield className="w-12 h-12 mx-auto mb-3 opacity-20" />
                    <p className="text-[var(--text-secondary)]">No scans found</p>
                    <Link href="/scan">
                        <button className="btn-primary mt-4">Start a Scan</button>
                    </Link>
                </div>
            ) : (
                <div className="space-y-3">
                    {scans.map((scan, i) => (
                        <motion.div
                            key={scan.scan_id}
                            initial={{ opacity: 0, y: 10 }}
                            animate={{ opacity: 1, y: 0 }}
                            transition={{ delay: i * 0.05 }}
                        >
                            <Link href={`/scans/${scan.scan_id}`}>
                                <div className="glass-card p-5 flex items-center justify-between hover:border-[var(--border-glass-hover)] cursor-pointer group">
                                    <div>
                                        <div className="flex items-center gap-3 mb-1">
                                            <p className="font-semibold">{scan.target}</p>
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
                                        <div className="flex items-center gap-4 text-xs text-[var(--text-secondary)]">
                                            <span className="flex items-center gap-1">
                                                <Clock className="w-3 h-3" />
                                                {new Date(scan.created_at).toLocaleString()}
                                            </span>
                                            {scan.duration_seconds && (
                                                <span>{scan.duration_seconds.toFixed(1)}s</span>
                                            )}
                                            <span>{scan.findings_count} findings</span>
                                        </div>
                                    </div>

                                    <div className="flex items-center gap-3">
                                        {scan.critical_count > 0 && (
                                            <span className="badge badge-critical">{scan.critical_count} Critical</span>
                                        )}
                                        {scan.high_count > 0 && (
                                            <span className="badge badge-high">{scan.high_count} High</span>
                                        )}
                                        <ExternalLink className="w-4 h-4 text-[var(--text-secondary)] opacity-0 group-hover:opacity-100 transition-opacity" />
                                    </div>
                                </div>
                            </Link>
                        </motion.div>
                    ))}
                </div>
            )}
        </div>
    );
}
