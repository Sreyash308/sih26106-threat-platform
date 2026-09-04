"use client";

import { SenderAnalysis } from "@/lib/types";
import { UserCheck, AlertOctagon, CheckCircle2, UserX, Globe } from "lucide-react";

interface SenderCardProps {
  sender: SenderAnalysis;
}

export default function SenderCard({ sender }: SenderCardProps) {
  const hasMismatch =
    sender.from_reply_to_mismatch ||
    sender.from_return_path_mismatch ||
    sender.display_name_deception;

  return (
    <div className="bg-surface border border-surface-border rounded-xl p-5 space-y-4">
      <div className="flex items-center justify-between border-b border-surface-border pb-3">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-lg bg-indigo-500/10 text-indigo-400">
            <UserCheck className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-slate-100">Sender Forensics & Domain Identity</h3>
            <p className="text-[11px] text-slate-400">
              Cross-examination of display name, envelope path, and reverse reply channels.
            </p>
          </div>
        </div>

        <div>
          {hasMismatch ? (
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-bold bg-amber-500/15 text-amber-300 border border-amber-500/30">
              <AlertOctagon className="w-3.5 h-3.5" />
              Sender Anomaly Detected
            </span>
          ) : (
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-bold bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
              <CheckCircle2 className="w-3.5 h-3.5" />
              Consistent Identity
            </span>
          )}
        </div>
      </div>

      {/* Field Inspection Matrix */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
        <div className="p-2.5 rounded-lg bg-slate-900/60 border border-surface-border">
          <div className="text-slate-400 text-[10px] uppercase font-semibold">Display Name & From Address</div>
          <div className="text-slate-100 font-medium mt-0.5 break-all">
            {sender.display_name ? `"${sender.display_name}" <${sender.from_address}>` : sender.from_header || "None"}
          </div>
        </div>

        <div className="p-2.5 rounded-lg bg-slate-900/60 border border-surface-border">
          <div className="text-slate-400 text-[10px] uppercase font-semibold">Reply-To Routing Address</div>
          <div className="text-slate-100 font-mono mt-0.5 break-all">
            {sender.reply_to || "Identical to From address"}
          </div>
          {sender.from_reply_to_mismatch && (
            <div className="text-amber-400 text-[10px] font-semibold mt-1 flex items-center gap-1">
              <UserX className="w-3 h-3" />
              Reply routes to external domain
            </div>
          )}
        </div>

        <div className="p-2.5 rounded-lg bg-slate-900/60 border border-surface-border">
          <div className="text-slate-400 text-[10px] uppercase font-semibold">Return-Path (Envelope Sender)</div>
          <div className="text-slate-100 font-mono mt-0.5 break-all">
            {sender.return_path || "None declared"}
          </div>
          {sender.from_return_path_mismatch && (
            <div className="text-amber-400 text-[10px] font-semibold mt-1">
              Envelope sender domain mismatch
            </div>
          )}
        </div>

        <div className="p-2.5 rounded-lg bg-slate-900/60 border border-surface-border">
          <div className="text-slate-400 text-[10px] uppercase font-semibold">Domain Characteristics</div>
          <div className="flex flex-wrap gap-1.5 mt-1">
            <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono text-[11px] border border-slate-700">
              {sender.from_domain || "unknown"}
            </span>
            {sender.is_punycode && (
              <span className="px-2 py-0.5 rounded bg-red-500/20 text-red-300 font-semibold text-[10px] border border-red-500/30">
                PUNYCODE (xn--)
              </span>
            )}
            {sender.is_free_provider && (
              <span className="px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 font-semibold text-[10px] border border-amber-500/30">
                Free Email Provider
              </span>
            )}
            {sender.display_name_deception && (
              <span className="px-2 py-0.5 rounded bg-red-500/20 text-red-300 font-semibold text-[10px] border border-red-500/30">
                Brand Impersonation
              </span>
            )}
          </div>
        </div>
      </div>

      {/* Itemized Evidence */}
      {sender.evidence && sender.evidence.length > 0 && (
        <div className="p-3 rounded-lg bg-slate-950/80 border border-surface-border text-xs">
          <div className="text-[10px] uppercase font-bold text-slate-400 mb-1.5">
            Analyst Findings & Evidence
          </div>
          <ul className="space-y-1">
            {sender.evidence.map((ev, i) => (
              <li key={i} className="text-amber-300/90 text-xs flex items-start gap-1.5">
                <span className="text-amber-500">•</span>
                <span>{ev}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
