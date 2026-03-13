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
  Crosshair,
  Layers,
  ShieldAlert,
  CheckCircle,
  Network,
} from "lucide-react";
import Link from "next/link";
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
  Radar,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
} from "recharts";
import { listScans, healthCheck, type ScanListItem } from "@/lib/api";

/* ── Severity Pie Colors ──────────────────────────────────── */
const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ff003c",
  high: "#f97316",
  medium: "#fcee0a",
  low: "#00ff9f",
  info: "#00f3ff",
};

/* ── Custom Chart Tooltip ─────────────────────────────────── */
function CyberTooltip({ active, payload }: any) {
  if (active && payload?.length) {
    const data = payload[0];
    return (
      <div className="bg-black/95 border border-[var(--border-cyber)] p-3 rounded-lg backdrop-blur-md shadow-lg">
        <div className="flex items-center gap-2 mb-1">
          <div
            className="w-2 h-2 rounded-full"
            style={{ backgroundColor: data.payload?.color || data.color }}
          />
          <span className="font-mono text-[10px] uppercase tracking-wider text-[var(--text-secondary)]">
            {data.name}
          </span>
        </div>
        <div className="text-lg font-bold text-[var(--text-primary)] font-mono pl-4">
          {data.value}
        </div>
      </div>
    );
  }
  return null;
}

/* ── Stat Card ────────────────────────────────────────────── */
function StatCard({
  label,
  value,
  icon: Icon,
  color,
  status,
  delay,
}: {
  label: string;
  value: string | number;
  icon: any;
  color: string;
  status: string;
  delay: number;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay, duration: 0.4 }}
      className="cyber-card p-6 rounded-xl relative overflow-hidden group"
      style={{ borderColor: `${color}20` }}
    >
      {/* Ghost icon */}
      <div className="absolute top-0 right-0 p-4 opacity-[0.07] group-hover:opacity-[0.15] transition-opacity">
        <Icon className="w-16 h-16" style={{ color }} />
      </div>
      <div className="font-mono text-[10px] uppercase tracking-[0.15em] text-[var(--text-secondary)]">
        {label}
      </div>
      <div
        className="text-3xl font-bold mt-2 font-mono text-glow"
        style={{ color }}
      >
        {value}
      </div>
      <div
        className="font-mono text-[10px] mt-2 opacity-70"
        style={{ color }}
      >
        {status}
      </div>
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

  /* ── Chart Data ──────────────────────────────────────────── */
  const hasData = scans.length > 0;

  // Aggregate severity counts across all scans
  const sevCounts = scans.reduce(
    (acc, scan) => {
      // We only have critical+high from the list API, estimate others
      acc.critical += scan.critical_count;
      acc.high += scan.high_count;
      acc.other += Math.max(0, scan.findings_count - scan.critical_count - scan.high_count);
      return acc;
    },
    { critical: 0, high: 0, other: 0 }
  );

  const pieData = [
    { name: "Critical", value: sevCounts.critical, color: SEVERITY_COLORS.critical },
    { name: "High", value: sevCounts.high, color: SEVERITY_COLORS.high },
    { name: "Medium/Low", value: sevCounts.other, color: SEVERITY_COLORS.medium },
  ].filter((d) => d.value > 0);

  // Radar data (mock categories from scan types)
  const radarData = [
    { subject: "Injection", A: Math.min(totalCritical * 25, 100) },
    { subject: "XSS", A: Math.min(totalHigh * 15, 100) },
    { subject: "Misconfig", A: Math.min(sevCounts.other * 10, 100) },
    { subject: "Auth", A: Math.min(totalHigh * 10, 100) },
    { subject: "Crypto", A: Math.min(sevCounts.other * 5, 100) },
    { subject: "SSRF", A: Math.min(totalCritical * 20, 100) },
  ].map((d) => ({ ...d, fullMark: 100 }));

  /* ── Time Formatter ──────────────────────────────────────── */
  function formatTime(dateStr: string) {
    const date = new Date(dateStr);
    const now = new Date();
    const diffSec = Math.floor((now.getTime() - date.getTime()) / 1000);
    if (diffSec < 60) return "Just now";
    if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
    if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
    return date.toLocaleDateString();
  }

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex items-center justify-between"
      >
        <div>
          <h1 className="text-2xl font-bold font-mono tracking-wide">
            Dashboard
          </h1>
          <p className="text-sm text-[var(--text-secondary)] mt-1 font-mono text-[11px] uppercase tracking-wider">
            Security overview &amp; recent operations
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
          color="var(--neon-cyan)"
          status={scans.length > 0 ? "SYSTEM ACTIVE" : "AWAITING INPUT"}
          delay={0}
        />
        <StatCard
          label="Critical Vulns"
          value={totalCritical}
          icon={AlertOctagon}
          color="var(--severity-critical)"
          status={totalCritical > 0 ? "ACTION REQUIRED" : "SYSTEM SECURE"}
          delay={0.1}
        />
        <StatCard
          label="High Vulns"
          value={totalHigh}
          icon={ShieldAlert}
          color="var(--severity-high)"
          status={totalHigh > 0 ? "INVESTIGATION REQ" : "NOMINAL"}
          delay={0.2}
        />
        <StatCard
          label="Total Findings"
          value={totalFindings}
          icon={Layers}
          color="var(--neon-blue)"
          status={totalFindings > 0 ? "CUMULATIVE ISSUES" : "NO DATA AVAILABLE"}
          delay={0.3}
        />
      </div>

      {/* Engine Status */}
      {health && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.4 }}
          className="cyber-card p-5"
        >
          <h2 className="cyber-label mb-3">Engine Status</h2>
          <div className="flex flex-wrap gap-6 text-sm font-mono">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-[var(--neon-cyan)] pulse-glow" />
              <span className="text-[var(--text-primary)]">
                {health.engine} v{health.version}
              </span>
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

      {/* Charts Row */}
      {hasData && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5 }}
          className="grid grid-cols-1 lg:grid-cols-2 gap-6"
        >
          {/* Severity Pie */}
          <div className="cyber-card rounded-xl p-6 flex flex-col">
            <h3 className="cyber-label flex items-center gap-2 mb-6">
              <Shield className="w-4 h-4 text-[var(--neon-cyan)]" />
              Threat_Severity_Distribution
            </h3>
            <div className="h-64 w-full flex-1 relative">
              {pieData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={pieData}
                      cx="50%"
                      cy="50%"
                      innerRadius={60}
                      outerRadius={80}
                      paddingAngle={5}
                      dataKey="value"
                      stroke="none"
                    >
                      {pieData.map((entry, index) => (
                        <Cell
                          key={`cell-${index}`}
                          fill={entry.color}
                          stroke="rgba(0,0,0,0.5)"
                          strokeWidth={2}
                        />
                      ))}
                    </Pie>
                    <Tooltip content={<CyberTooltip />} />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div className="flex flex-col items-center justify-center h-full text-[var(--text-secondary)] opacity-30 border border-dashed border-[var(--border-cyber)] rounded-lg">
                  <Activity className="w-12 h-12 mb-2" />
                  <span className="font-mono text-xs uppercase tracking-widest">
                    No_Data_Available
                  </span>
                </div>
              )}
              {/* Center count */}
              {pieData.length > 0 && (
                <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                  <span className="text-2xl font-bold text-[var(--text-primary)] font-mono text-glow">
                    {totalFindings}
                  </span>
                  <span className="text-[10px] text-[var(--text-secondary)] font-mono uppercase">
                    Issues
                  </span>
                </div>
              )}
            </div>
          </div>

          {/* Threat Radar */}
          <div className="cyber-card rounded-xl p-6">
            <h3 className="cyber-label flex items-center gap-2 mb-6">
              <Network className="w-4 h-4 text-[var(--neon-cyan)]" />
              Threat_Vector_Radar
            </h3>
            <div className="h-64 w-full flex items-center justify-center">
              <ResponsiveContainer width="100%" height="100%">
                <RadarChart cx="50%" cy="50%" outerRadius="70%" data={radarData}>
                  <PolarGrid
                    stroke="var(--text-secondary)"
                    strokeDasharray="3 3"
                    opacity={0.2}
                  />
                  <PolarAngleAxis
                    dataKey="subject"
                    tick={{
                      fill: "var(--text-secondary)",
                      fontSize: 10,
                      fontFamily: "monospace",
                    }}
                  />
                  <PolarRadiusAxis
                    angle={30}
                    domain={[0, 100]}
                    tick={false}
                    axisLine={false}
                  />
                  <Radar
                    name="Risk Score"
                    dataKey="A"
                    stroke="#00f3ff"
                    strokeWidth={2}
                    fill="#00f3ff"
                    fillOpacity={0.1}
                  />
                  <Tooltip content={<CyberTooltip />} />
                </RadarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </motion.div>
      )}

      {/* Recent Operations */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.6 }}
        className="cyber-card rounded-xl overflow-hidden"
      >
        <div className="p-4 border-b border-[var(--border-cyber)] flex justify-between items-center bg-black/30">
          <h3 className="cyber-label flex items-center gap-2">
            <Crosshair className="w-4 h-4 text-[var(--neon-cyan)]" />
            Recent_Operations
          </h3>
          {hasData && (
            <Link
              href="/scans"
              className="font-mono text-[10px] uppercase tracking-wider text-[var(--text-secondary)] hover:text-[var(--neon-cyan)] transition-colors"
            >
              VIEW_ALL
            </Link>
          )}
        </div>

        <div className="divide-y divide-[var(--border-cyber)]">
          {loading ? (
            <div className="p-10 text-center text-[var(--text-secondary)] font-mono text-sm">
              Loading scan history...
            </div>
          ) : scans.length === 0 ? (
            <div className="p-8 text-center flex flex-col items-center">
              <Shield className="w-12 h-12 mb-3 opacity-15" />
              <span className="font-mono text-xs text-[var(--text-secondary)] opacity-50 uppercase tracking-widest">
                NO_RECENT_OPERATIONS_FOUND
              </span>
              <Link href="/scan">
                <button className="btn-primary mt-4 text-sm">
                  Initialize First Scan
                </button>
              </Link>
            </div>
          ) : (
            scans.slice(0, 8).map((scan, i) => {
              const hasCritical = scan.critical_count > 0;
              const hasHigh = scan.high_count > 0;
              const statusColor = hasCritical
                ? "text-[var(--severity-critical)]"
                : hasHigh
                  ? "text-[var(--severity-high)]"
                  : "text-[var(--neon-green)]";

              return (
                <Link key={scan.scan_id} href={`/scans/${scan.scan_id}`}>
                  <div className="p-4 flex items-center justify-between hover:bg-[rgba(0,243,255,0.02)] transition-colors cursor-pointer group">
                    <div className="flex items-center gap-4">
                      <div className="w-10 h-10 rounded border border-[var(--border-cyber)] bg-black/30 flex items-center justify-center group-hover:border-[var(--neon-cyan)]/30 transition-colors">
                        <Crosshair className="w-5 h-5 text-[var(--text-secondary)] group-hover:text-[var(--neon-cyan)]" />
                      </div>
                      <div>
                        <div className="font-mono text-sm font-semibold text-[var(--text-primary)] group-hover:text-[var(--neon-cyan)] transition-colors">
                          {scan.target}
                        </div>
                        <div className="font-mono text-[10px] text-[var(--text-secondary)] uppercase flex items-center gap-1">
                          <Clock className="w-3 h-3" />
                          {formatTime(scan.created_at)}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-4 text-sm">
                      <div className={`font-mono text-xs font-bold flex items-center gap-1.5 ${statusColor}`}>
                        {hasCritical || hasHigh ? (
                          <AlertTriangle className="w-3 h-3" />
                        ) : (
                          <CheckCircle className="w-3 h-3" />
                        )}
                        {scan.findings_count} DETECTED
                      </div>
                      <span className={`badge ${hasCritical ? "badge-critical" : hasHigh ? "badge-high" : "badge-info"}`}>
                        {scan.status === "completed" ? "COMPLETED" : scan.status.toUpperCase()}
                      </span>
                    </div>
                  </div>
                </Link>
              );
            })
          )}
        </div>
      </motion.div>
    </div>
  );
}
