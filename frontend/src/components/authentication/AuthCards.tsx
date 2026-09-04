"use client";

import { AuthenticationSummary } from "@/lib/types";
import { ShieldCheck, ShieldAlert, Shield, HelpCircle, CheckCircle2, XCircle } from "lucide-react";

interface AuthCardsProps {
  auth: AuthenticationSummary;
}

export default function AuthCards({ auth }: AuthCardsProps) {
  const getStatusBadge = (status: string) => {
    const s = (status || "").toLowerCase();
    if (s === "pass") {
      return {
        badge: "bg-emerald-500/20 text-emerald-400 border-emerald-500/40",
        icon: CheckCircle2,
        color: "text-emerald-400",
      };
    } else if (s === "fail") {
      return {
        badge: "bg-red-500/20 text-red-400 border-red-500/40",
        icon: XCircle,
        color: "text-red-400",
      };
    } else if (s === "none") {
      return {
        badge: "bg-slate-700/50 text-slate-400 border-slate-600/40",
        icon: Shield,
        color: "text-slate-400",
      };
    } else {
      return {
        badge: "bg-amber-500/20 text-amber-400 border-amber-500/40",
        icon: HelpCircle,
        color: "text-amber-400",
      };
    }
  };

  const protocols = [
    {
      name: "SPF (Sender Policy Framework)",
      abbr: "SPF",
      item: auth.spf,
      desc: "Validates if the sending relay IP is authorized to transmit for the envelope domain.",
    },
    {
      name: "DKIM (DomainKeys Identified Mail)",
      abbr: "DKIM",
      item: auth.dkim,
      desc: "Verifies asymmetric cryptographic signature over email headers and body payload.",
    },
    {
      name: "DMARC (Domain-based Auth)",
      abbr: "DMARC",
      item: auth.dmarc,
      desc: "Asserts domain alignment policies (none/quarantine/reject) linking SPF and DKIM to Header.From.",
    },
  ];

  const trustScore = auth.header_trust_score;
  const trustColor =
    trustScore >= 80 ? "text-emerald-400" : trustScore >= 50 ? "text-amber-400" : "text-red-400";

  return (
    <div className="space-y-4">
      {/* Header Trust Score Banner */}
      <div className="bg-surface border border-surface-border rounded-xl p-4 flex flex-col sm:flex-row items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-indigo-500/10 text-indigo-400">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div>
            <div className="text-sm font-bold text-slate-100">Header Trust Score</div>
            <div className="text-xs text-slate-400">
              Measures cryptographic authenticity and domain alignment (independent of overall threat score).
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span className={`text-3xl font-extrabold font-mono ${trustColor}`}>
            {trustScore}
          </span>
          <span className="text-xs text-slate-400 font-semibold">/ 100</span>
        </div>
      </div>

      {/* Protocol Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {protocols.map((proto, idx) => {
          const cfg = getStatusBadge(proto.item.status);
          const Icon = cfg.icon;

          return (
            <div
              key={idx}
              className="bg-surface border border-surface-border rounded-xl p-4 flex flex-col justify-between"
            >
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="font-bold text-slate-200 text-sm">{proto.abbr}</span>
                  <span
                    className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold border uppercase ${cfg.badge}`}
                  >
                    <Icon className="w-3 h-3" />
                    {proto.item.status}
                  </span>
                </div>
                <div className="text-[11px] text-slate-400 mb-3">{proto.desc}</div>
              </div>

              <div className="pt-3 border-t border-surface-border">
                <div className="text-[10px] uppercase font-semibold text-slate-400 mb-1">
                  Observed Evidence
                </div>
                <div className="text-xs text-slate-300 font-mono bg-slate-950/60 p-2 rounded border border-slate-800 break-words leading-tight">
                  {proto.item.evidence || "No evidence recorded."}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
