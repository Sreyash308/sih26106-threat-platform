"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  ShieldAlert,
  ShieldCheck,
  Crosshair,
  AlertTriangle,
  Globe2,
  FileSearch,
  Activity,
  ArrowUpRight,
  TrendingUp,
  Flame,
  FileWarning,
  Link2,
} from "lucide-react";
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  PieChart,
  Pie,
  Cell,
} from "recharts";

import { fetchDashboardStats, analyzeEmailPayload } from "@/lib/api";
import { DashboardStats } from "@/lib/types";
import { DEMO_EMAILS } from "@/data/demo_emails";
import { formatDate, getSeverityStyle, getStatusStyle } from "@/lib/utils";

export default function DashboardPage() {
  const router = useRouter();
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [demoLoading, setDemoLoading] = useState(false);

  useEffect(() => {
    loadStats();
  }, []);

  const loadStats = async () => {
    try {
      setLoading(true);
      const data = await fetchDashboardStats();
      setStats(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const handleLaunchDemo = async () => {
    setDemoLoading(true);
    try {
      const demo = DEMO_EMAILS[0]; // Phishing email
      const fd = new FormData();
      fd.append("raw_text", demo.raw);
      const result = await analyzeEmailPayload(fd);
      router.push(`/investigations/${result.summary.investigation_id}`);
    } catch (err) {
      console.error(err);
      router.push("/analyze");
    } finally {
      setDemoLoading(false);
    }
  };

  return (
    <div className="space-y-8">
      {/* Hero Banner */}
      <div className="bg-gradient-to-r from-surface via-surface-light to-surface border border-surface-border rounded-2xl p-6 md:p-8 relative overflow-hidden glow-border">
        <div className="absolute right-0 top-0 w-96 h-96 bg-indigo-500/5 rounded-full blur-3xl pointer-events-none" />

        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 relative z-10">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <span className="px-2.5 py-0.5 rounded-full bg-indigo-500/20 text-indigo-400 font-mono text-[11px] font-bold border border-indigo-500/30">
                SIH PROBLEM ID: SIH26106
              </span>
              <span className="text-xs text-slate-400">• AICTE Cybersecurity Platform</span>
            </div>
            <h1 className="text-2xl md:text-3xl font-extrabold text-white tracking-tight">
              AI-Powered Email Threat Detection
            </h1>
            <p className="text-slate-400 text-xs md:text-sm max-w-2xl mt-1.5 leading-relaxed">
              Email forensics, threat intelligence and geographic routing analysis. Ingest .eml or raw emails to unpack SPF/DKIM/DMARC headers, trace network hops, and evaluate explainable AI threat scores.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={handleLaunchDemo}
              disabled={demoLoading}
              className="px-4 py-2.5 rounded-xl bg-gradient-to-r from-red-600 to-orange-600 hover:from-red-500 hover:to-orange-500 text-white font-bold text-xs shadow-glow-red flex items-center gap-2 transition-all cursor-pointer"
            >
              <Flame className="w-4 h-4 animate-pulse" />
              <span>{demoLoading ? "Analyzing Demo..." : "Try Demo (Phishing)"}</span>
            </button>

            <Link
              href="/analyze"
              className="px-4 py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-bold text-xs shadow-glow flex items-center gap-2 transition-all"
            >
              <Crosshair className="w-4 h-4" />
              <span>New Investigation</span>
            </Link>
          </div>
        </div>
      </div>

      {/* SOC Telemetry Cards (8 Core Indicators) */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {[
          {
            label: "Total Investigations",
            value: stats?.total_investigations ?? 0,
            icon: FileSearch,
            color: "text-indigo-400",
            bg: "bg-indigo-500/10 border-indigo-500/20",
          },
          {
            label: "Threats Detected",
            value: stats?.threats_detected ?? 0,
            icon: AlertTriangle,
            color: "text-amber-400",
            bg: "bg-amber-500/10 border-amber-500/20",
          },
          {
            label: "Critical Threats",
            value: stats?.critical_threats ?? 0,
            icon: ShieldAlert,
            color: "text-red-400",
            bg: "bg-red-500/10 border-red-500/20",
          },
          {
            label: "Average Threat Score",
            value: `${stats?.average_threat_score ?? 0}`,
            icon: TrendingUp,
            color: "text-purple-400",
            bg: "bg-purple-500/10 border-purple-500/20",
          },
          {
            label: "Emails Analyzed",
            value: stats?.emails_analyzed ?? 0,
            icon: Activity,
            color: "text-emerald-400",
            bg: "bg-emerald-500/10 border-emerald-500/20",
          },
          {
            label: "High-Risk Emails",
            value: stats?.high_risk_emails ?? 0,
            icon: Flame,
            color: "text-orange-400",
            bg: "bg-orange-500/10 border-orange-500/20",
          },
          {
            label: "Suspicious URLs",
            value: stats?.suspicious_urls ?? 0,
            icon: Link2,
            color: "text-cyan-400",
            bg: "bg-cyan-500/10 border-cyan-500/20",
          },
          {
            label: "Suspicious Attachments",
            value: stats?.suspicious_attachments ?? 0,
            icon: FileWarning,
            color: "text-rose-400",
            bg: "bg-rose-500/10 border-rose-500/20",
          },
        ].map((c, i) => {
          const Icon = c.icon;
          return (
            <div
              key={i}
              className={`p-4 rounded-xl border bg-surface flex flex-col justify-between ${c.bg}`}
            >
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-semibold text-slate-400">{c.label}</span>
                <Icon className={`w-4 h-4 ${c.color}`} />
              </div>
              <div className="text-2xl font-extrabold text-white mt-2 font-mono">
                {c.value}
              </div>
            </div>
          );
        })}
      </div>

      {/* Analytics Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Severity Distribution Chart */}
        <div className="bg-surface border border-surface-border rounded-xl p-5 flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-bold text-slate-100 flex items-center justify-between">
              <span>Severity Distribution</span>
              <span className="text-xs text-slate-400 font-normal">Active Triage</span>
            </h3>
            <p className="text-[11px] text-slate-400 mt-0.5">
              Breakdown of email classifications across all cases.
            </p>
          </div>

          <div className="h-52 w-full mt-4">
            {stats?.severity_distribution ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={stats.severity_distribution}>
                  <XAxis dataKey="name" stroke="#64748b" fontSize={10} tickLine={false} />
                  <YAxis stroke="#64748b" fontSize={10} tickLine={false} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#0f172a",
                      borderColor: "#334155",
                      borderRadius: "8px",
                      fontSize: "12px",
                    }}
                  />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                    {stats.severity_distribution.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex items-center justify-center h-full text-xs text-slate-400">
                Loading telemetry...
              </div>
            )}
          </div>
        </div>

        {/* Authentication Compliance Card */}
        <div className="bg-surface border border-surface-border rounded-xl p-5">
          <h3 className="text-sm font-bold text-slate-100 flex items-center justify-between">
            <span>Authentication Health</span>
            <span className="text-xs text-slate-400 font-normal">SPF / DKIM / DMARC</span>
          </h3>
          <p className="text-[11px] text-slate-400 mt-0.5">
            Validation pass vs failure distribution.
          </p>

          <div className="space-y-4 mt-5 text-xs">
            {[
              {
                name: "SPF (Sender Policy Framework)",
                pass: stats?.authentication_distribution?.spf?.pass ?? 0,
                fail: stats?.authentication_distribution?.spf?.fail ?? 0,
              },
              {
                name: "DKIM (Cryptographic Signatures)",
                pass: stats?.authentication_distribution?.dkim?.pass ?? 0,
                fail: stats?.authentication_distribution?.dkim?.fail ?? 0,
              },
              {
                name: "DMARC (Domain Alignment)",
                pass: stats?.authentication_distribution?.dmarc?.pass ?? 0,
                fail: stats?.authentication_distribution?.dmarc?.fail ?? 0,
              },
            ].map((p, i) => {
              const total = p.pass + p.fail || 1;
              const passPct = Math.round((p.pass / total) * 100);
              return (
                <div key={i} className="p-3 rounded-lg bg-slate-900/60 border border-surface-border">
                  <div className="flex justify-between font-semibold text-slate-300 mb-1.5">
                    <span>{p.name}</span>
                    <span className="text-indigo-300">{passPct}% Passed</span>
                  </div>
                  <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden flex">
                    <div className="bg-emerald-500 h-full" style={{ width: `${passPct}%` }} />
                    <div className="bg-red-500 h-full" style={{ width: `${100 - passPct}%` }} />
                  </div>
                  <div className="flex justify-between text-[10px] text-slate-400 mt-1 font-mono">
                    <span className="text-emerald-400">{p.pass} Pass</span>
                    <span className="text-red-400">{p.fail} Fail</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Top Source Countries */}
        <div className="bg-surface border border-surface-border rounded-xl p-5">
          <h3 className="text-sm font-bold text-slate-100 flex items-center justify-between">
            <span>Top Relay Countries</span>
            <span className="text-xs text-slate-400 font-normal">Geographic Origin</span>
          </h3>
          <p className="text-[11px] text-slate-400 mt-0.5">
            Most frequent geographic locations for observed sender relays.
          </p>

          <div className="space-y-2.5 mt-5">
            {stats?.top_countries?.map((c, i) => (
              <div
                key={i}
                className="flex items-center justify-between p-2.5 rounded-lg bg-slate-900/60 border border-surface-border text-xs"
              >
                <div className="flex items-center gap-2">
                  <span className="text-indigo-400 font-bold font-mono">#{i + 1}</span>
                  <span className="text-slate-200 font-medium">{c.country}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-slate-400">{c.count} Hops</span>
                  <div className="w-16 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                    <div
                      className="bg-indigo-500 h-full rounded-full"
                      style={{ width: `${Math.min(100, c.count * 15)}%` }}
                    />
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Recent Investigations Table */}
      <div className="bg-surface border border-surface-border rounded-xl p-5">
        <div className="flex items-center justify-between border-b border-surface-border pb-3 mb-4">
          <div>
            <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <FileSearch className="w-4 h-4 text-indigo-400" />
              Recent Forensic Investigations
            </h3>
            <p className="text-[11px] text-slate-400">
              Click any row to open the complete digital forensics case workspace.
            </p>
          </div>

          <Link
            href="/investigations"
            className="text-xs text-indigo-400 hover:text-indigo-300 font-semibold flex items-center gap-1 transition-colors"
          >
            <span>View All Cases</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </Link>
        </div>

        {stats?.recent_investigations && stats.recent_investigations.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900/80 text-slate-400 uppercase text-[10px] font-semibold border-b border-surface-border">
                <tr>
                  <th className="py-2.5 px-3">Investigation ID</th>
                  <th className="py-2.5 px-3">Subject</th>
                  <th className="py-2.5 px-3">Sender</th>
                  <th className="py-2.5 px-3">Threat Score</th>
                  <th className="py-2.5 px-3">Severity</th>
                  <th className="py-2.5 px-3">SPF / DKIM / DMARC</th>
                  <th className="py-2.5 px-3">Source Relay</th>
                  <th className="py-2.5 px-3">Date</th>
                  <th className="py-2.5 px-3">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-surface-border">
                {stats.recent_investigations.map((inv) => {
                  const style = getSeverityStyle(inv.severity);
                  return (
                    <tr
                      key={inv.id}
                      onClick={() => router.push(`/investigations/${inv.id}`)}
                      className="hover:bg-slate-800/60 cursor-pointer transition-colors group"
                    >
                      <td className="py-3 px-3 font-mono font-bold text-indigo-400 group-hover:underline">
                        {inv.id}
                      </td>
                      <td className="py-3 px-3 max-w-xs truncate text-slate-200 font-medium">
                        {inv.subject}
                      </td>
                      <td className="py-3 px-3 max-w-[180px] truncate text-slate-400 font-mono text-[11px]">
                        {inv.sender}
                      </td>
                      <td className="py-3 px-3 font-mono font-bold text-slate-200">
                        {inv.threat_score} / 100
                      </td>
                      <td className="py-3 px-3">
                        <span className={`inline-block px-2 py-0.5 rounded-full text-[10px] font-bold ${style.badge}`}>
                          {inv.severity}
                        </span>
                      </td>
                      <td className="py-3 px-3 font-mono text-[11px]">
                        <span className={inv.spf_status === "Pass" ? "text-emerald-400" : "text-red-400"}>
                          {inv.spf_status?.[0] || "-"}
                        </span>
                        {" / "}
                        <span className={inv.dkim_status === "Pass" ? "text-emerald-400" : "text-red-400"}>
                          {inv.dkim_status?.[0] || "-"}
                        </span>
                        {" / "}
                        <span className={inv.dmarc_status === "Pass" ? "text-emerald-400" : "text-red-400"}>
                          {inv.dmarc_status?.[0] || "-"}
                        </span>
                      </td>
                      <td className="py-3 px-3 text-slate-300">
                        <div>{inv.source_country || "Unknown"}</div>
                        <div className="font-mono text-[10px] text-slate-400">{inv.source_ip}</div>
                      </td>
                      <td className="py-3 px-3 text-slate-400 text-[11px]">
                        {formatDate(inv.created_at)}
                      </td>
                      <td className="py-3 px-3">
                        <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${getStatusStyle(inv.status)}`}>
                          {inv.status}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="text-center py-10 text-xs text-slate-400">
            No investigations on record yet. Click &quot;New Investigation&quot; or &quot;Try Demo&quot; above.
          </div>
        )}
      </div>
    </div>
  );
}
