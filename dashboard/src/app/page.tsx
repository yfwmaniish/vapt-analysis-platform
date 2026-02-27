"use client";

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import {
  Shield,
  AlertTriangle,
  AlertOctagon,
  Activity,
  Clock,
  Target,
} from "lucide-react";
import Link from "next/link";
import { listScans, healthCheck, type ScanListItem } from "@/lib/api";

/* ── Severity Color Helpers ────────────────────────────────── */
function severityColor(sev: string) {
  const map: Record<string, string> = {
    critical: "var(--severity-critical)",
    high: "var(--severity-high)",
    medium: "var(--severity-medium)",
    low: "var(--severity-low)",
    info: "var(--severity-info)",
  };
  return map[sev] || "var(--severity-info)";
}

/* ── Stat Card Component ───────────────────────────────────── */
function StatCard({
  label,
  value,
  icon: Icon,
  color,
  delay,
}: {
  label: string;
  value: string | number;
  icon: any;
  color: string;
  delay: number;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay, duration: 0.4 }}
      className="glass-card p-5"
    >
      <div className="flex items-center justify-between mb-3">
        <span className="text-xs text-[var(--text-secondary)] uppercase tracking-widest font-semibold">
          {label}
        </span>
        <div
          className="w-8 h-8 rounded-lg flex items-center justify-center"
          style={{ background: `${color}15` }}
        >
          <Icon className="w-4 h-4" style={{ color }} />
        </div>
      </div>
      <p className="text-2xl font-bold" style={{ color }}>
        {value}
      </p>
    </motion.div>
  );
}

/* ── Dashboard Page ────────────────────────────────────────── */
export default function DashboardPage() {
  const [scans, setScans] = useState<ScanListItem[]>([]);
  const [health, setHealth] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      try {
        const [scanList, healthData] = await Promise.all([
          listScans().catch(() => []),
          healthCheck().catch(() => null),
        ]);
        setScans(scanList);
        setHealth(healthData);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  const totalFindings = scans.reduce((s, scan) => s + scan.findings_count, 0);
  const totalCritical = scans.reduce((s, scan) => s + scan.critical_count, 0);
  const totalHigh = scans.reduce((s, scan) => s + scan.high_count, 0);

  return (
    <div className="max-w-6xl mx-auto space-y-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex items-center justify-between"
      >
        <div>
          <h1 className="text-2xl font-bold">Dashboard</h1>
          <p className="text-sm text-[var(--text-secondary)] mt-1">
            Security overview and recent scan activity
          </p>
        </div>
        <Link href="/scan">
          <button className="btn-primary flex items-center gap-2">
            <Target className="w-4 h-4" />
            New Scan
          </button>
        </Link>
      </motion.div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          label="Total Scans"
          value={scans.length}
          icon={Activity}
          color="var(--accent-cyan)"
          delay={0}
        />
        <StatCard
          label="Total Findings"
          value={totalFindings}
          icon={Shield}
          color="var(--accent-blue)"
          delay={0.1}
        />
        <StatCard
          label="Critical Issues"
          value={totalCritical}
          icon={AlertOctagon}
          color="var(--severity-critical)"
          delay={0.2}
        />
        <StatCard
          label="High Issues"
          value={totalHigh}
          icon={AlertTriangle}
          color="var(--severity-high)"
          delay={0.3}
        />
      </div>

      {/* Engine Status */}
      {health && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.4 }}
          className="glass-card p-5"
        >
          <h2 className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-widest mb-3">
            Engine Status
          </h2>
          <div className="flex flex-wrap gap-6 text-sm">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-[var(--accent-cyan)]" />
              {health.engine} v{health.version}
            </div>
            <div className="text-[var(--text-secondary)]">
              {health.scanners_loaded} scanners loaded
            </div>
            <div className="text-[var(--text-secondary)]">
              AI: {health.ai_available ? "✅ Enabled" : "⚠️ Disabled"}
            </div>
          </div>
        </motion.div>
      )}

      {/* Recent Scans Table */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.5 }}
        className="glass-card overflow-hidden"
      >
        <div className="p-5 border-b border-[var(--border-glass)]">
          <h2 className="text-sm font-semibold uppercase tracking-widest text-[var(--text-secondary)]">
            Recent Scans
          </h2>
        </div>

        {loading ? (
          <div className="p-10 text-center text-[var(--text-secondary)]">
            Loading scan history...
          </div>
        ) : scans.length === 0 ? (
          <div className="p-10 text-center">
            <Shield className="w-12 h-12 mx-auto mb-3 opacity-20" />
            <p className="text-[var(--text-secondary)]">No scans yet</p>
            <Link href="/scan">
              <button className="btn-primary mt-4">Run Your First Scan</button>
            </Link>
          </div>
        ) : (
          <div className="divide-y divide-[var(--border-glass)]">
            {scans.slice(0, 10).map((scan, i) => (
              <Link key={scan.scan_id} href={`/scans/${scan.scan_id}`}>
                <motion.div
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: 0.5 + i * 0.05 }}
                  className="p-4 flex items-center justify-between hover:bg-[var(--bg-card-hover)] transition-colors cursor-pointer"
                >
                  <div className="flex items-center gap-4">
                    <div>
                      <p className="font-medium text-sm">{scan.target}</p>
                      <div className="flex items-center gap-3 mt-1 text-xs text-[var(--text-secondary)]">
                        <span className="flex items-center gap-1">
                          <Clock className="w-3 h-3" />
                          {new Date(scan.created_at).toLocaleDateString()}
                        </span>
                        <span
                          className={`badge badge-${scan.status === "completed" ? "info" : scan.status === "running" ? "medium" : "critical"}`}
                        >
                          {scan.status}
                        </span>
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-4 text-sm">
                    {scan.critical_count > 0 && (
                      <span className="badge badge-critical">
                        {scan.critical_count} Critical
                      </span>
                    )}
                    {scan.high_count > 0 && (
                      <span className="badge badge-high">
                        {scan.high_count} High
                      </span>
                    )}
                    <span className="text-[var(--text-secondary)]">
                      {scan.findings_count} findings
                    </span>
                  </div>
                </motion.div>
              </Link>
            ))}
          </div>
        )}
      </motion.div>
    </div>
  );
}
