"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  ShieldAlert,
  LayoutDashboard,
  FileSearch,
  Crosshair,
  Globe2,
  Database,
  FileText,
  Settings,
  Activity,
} from "lucide-react";
import { cn } from "@/lib/utils";

const NAV_ITEMS = [
  { href: "/", label: "Dashboard", icon: LayoutDashboard },
  { href: "/analyze", label: "Analyze Email", icon: Crosshair },
  { href: "/investigations", label: "Investigations", icon: FileSearch },
  { href: "/geo-intelligence", label: "Geo Intelligence", icon: Globe2 },
  { href: "/threat-intelligence", label: "Threat Intel", icon: Database },
  { href: "/reports", label: "Reports", icon: FileText },
  { href: "/settings", label: "System Health", icon: Settings },
];

export default function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="w-64 flex-shrink-0 bg-surface border-r border-surface-border flex flex-col h-screen fixed left-0 top-0 z-30">
      {/* Brand Header */}
      <div className="p-5 border-b border-surface-border flex items-center gap-3">
        <div className="w-10 h-10 rounded-lg bg-gradient-to-tr from-indigo-600 to-indigo-400 flex items-center justify-center shadow-glow">
          <ShieldAlert className="w-6 h-6 text-white" />
        </div>
        <div>
          <div className="font-bold text-slate-100 tracking-wide flex items-center gap-1.5 text-sm">
            <span>SIH26106</span>
            <span className="text-xs bg-indigo-500/20 text-indigo-400 px-1.5 py-0.5 rounded border border-indigo-500/30">
              SOC
            </span>
          </div>
          <div className="text-[11px] text-slate-400 font-medium">Email Threat Platform</div>
        </div>
      </div>

      {/* Navigation Links */}
      <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
        <div className="px-3 pb-2 text-[10px] font-semibold tracking-wider text-slate-400 uppercase">
          Forensic Operations
        </div>
        {NAV_ITEMS.map((item) => {
          const Icon = item.icon;
          const isActive =
            item.href === "/" ? pathname === "/" : pathname.startsWith(item.href);

          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "flex items-center gap-3 px-3 py-2.5 rounded-lg text-xs font-medium transition-all",
                isActive
                  ? "bg-indigo-600/20 text-indigo-300 border border-indigo-500/40 shadow-sm"
                  : "text-slate-300 hover:text-white hover:bg-slate-800/60"
              )}
            >
              <Icon className={cn("w-4 h-4", isActive ? "text-indigo-400" : "text-slate-400")} />
              <span>{item.label}</span>
              {isActive && (
                <div className="ml-auto w-1.5 h-1.5 rounded-full bg-indigo-400 animate-pulse" />
              )}
            </Link>
          );
        })}
      </nav>

      {/* Sensor & Pipeline Telemetry Status */}
      <div className="p-4 border-t border-surface-border bg-slate-950/40 m-3 rounded-lg">
        <div className="flex items-center justify-between text-[11px] mb-2">
          <span className="text-slate-400 flex items-center gap-1.5">
            <Activity className="w-3.5 h-3.5 text-emerald-400 animate-pulse" />
            Sensor Status
          </span>
          <span className="text-emerald-400 font-medium text-[10px] bg-emerald-500/10 px-1.5 py-0.5 rounded border border-emerald-500/20">
            ONLINE
          </span>
        </div>
        <div className="text-[10px] text-slate-400 leading-tight">
          AICTE & SIH Defense Node • Pipeline v1.0.0
        </div>
      </div>
    </aside>
  );
}
