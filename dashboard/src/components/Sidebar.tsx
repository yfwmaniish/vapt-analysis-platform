"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
    LayoutDashboard,
    Crosshair,
    ListChecks,
    Settings,
    Activity,
} from "lucide-react";

const NAV_ITEMS = [
    { href: "/", label: "Dashboard", icon: LayoutDashboard },
    { href: "/scan", label: "New_Scan", icon: Crosshair },
    { href: "/scans", label: "History", icon: ListChecks },
    { href: "/settings", label: "Config", icon: Settings },
];

export default function Sidebar() {
    const pathname = usePathname();

    return (
        <aside className="fixed left-0 top-0 bottom-0 w-[260px] border-r border-[var(--border-cyber)] flex flex-col z-50 bg-black/40 backdrop-blur-md">
            {/* Brand */}
            <div className="h-16 flex items-center justify-center border-b border-[var(--border-cyber)] bg-black/20">
                <div className="flex items-center gap-3">
                    <img src="/logo.png" alt="SecureSuiteX Logo" className="w-8 h-8 rounded object-cover" />
                    <span className="font-mono text-xl font-bold tracking-wider text-glow text-[var(--neon-cyan)]">
                        SecureSuiteX
                    </span>
                </div>
            </div>

            {/* Status indicator */}
            <div className="px-4 py-4">
                <div className="flex items-center gap-2 px-3 py-2 rounded bg-black/30 border border-[var(--border-cyber)]">
                    <Activity className="w-3.5 h-3.5 text-[var(--neon-cyan)]" />
                    <span className="font-mono text-[10px] uppercase tracking-widest text-[var(--text-secondary)]">
                        Engine
                    </span>
                    <div className="ml-auto flex items-center gap-1.5">
                        <div className="w-1.5 h-1.5 rounded-full bg-[var(--neon-cyan)] pulse-glow" />
                        <span className="font-mono text-[10px] text-[var(--neon-cyan)]">
                            ONLINE
                        </span>
                    </div>
                </div>
            </div>

            {/* Nav links */}
            <nav className="flex-1 px-3 space-y-1">
                {NAV_ITEMS.map((item) => {
                    const isActive = pathname === item.href;
                    const Icon = item.icon;
                    return (
                        <Link key={item.href} href={item.href}>
                            <div className={`sidebar-item ${isActive ? "active" : ""}`}>
                                <Icon className="w-[18px] h-[18px]" />
                                {item.label}
                            </div>
                        </Link>
                    );
                })}
            </nav>

            {/* Footer */}
            <div className="p-4 border-t border-[var(--border-cyber)] bg-black/20">
                <p className="text-center font-mono text-[10px] text-[var(--text-secondary)] opacity-50 uppercase tracking-wider">
                    v1.0 — SecureSuiteX by Veltro
                </p>
            </div>
        </aside>
    );
}
