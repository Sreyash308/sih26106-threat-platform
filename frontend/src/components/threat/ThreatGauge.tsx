"use client";

import { SubScores, ThreatFactor } from "@/lib/types";
import { getSeverityStyle } from "@/lib/utils";
import { ShieldAlert, AlertTriangle, CheckCircle, Info } from "lucide-react";

interface ThreatGaugeProps {
  score: number;
  severity: string;
  verdict: string;
  subScores?: SubScores;
  factors?: ThreatFactor[];
}

export default function ThreatGauge({
  score,
  severity,
  verdict,
  subScores,
  factors = [],
}: ThreatGaugeProps) {
  const style = getSeverityStyle(severity);
  const circumference = 2 * Math.PI * 45; // radius = 45
  const strokeDashoffset = circumference - (score / 100) * circumference;

  return (
    <div className="bg-surface border border-surface-border rounded-xl p-6 glow-border">
      <div className="flex flex-col lg:flex-row items-center gap-8">
        {/* Radial Threat Gauge */}
        <div className="flex flex-col items-center flex-shrink-0">
          <div className="relative w-40 h-40 flex items-center justify-center">
            <svg className="w-full h-full -rotate-90 transform" viewBox="0 0 100 100">
              {/* Track */}
              <circle
                cx="50"
                cy="50"
                r="45"
                fill="transparent"
                stroke="#1e293b"
                strokeWidth="8"
              />
              {/* Progress */}
              <circle
                cx="50"
                cy="50"
                r="45"
                fill="transparent"
                stroke={style.hex}
                strokeWidth="8"
                strokeDasharray={circumference}
                strokeDashoffset={strokeDashoffset}
                strokeLinecap="round"
                className="transition-all duration-1000 ease-out"
              />
            </svg>

            {/* Centered Score Display */}
            <div className="absolute flex flex-col items-center justify-center text-center">
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">
                Threat Score
              </span>
              <span className="text-4xl font-extrabold text-white tracking-tight">
                {score}
              </span>
              <span className="text-[10px] font-medium text-slate-400">/ 100</span>
            </div>
          </div>

          <div className="mt-3 text-center">
            <span
              className={`inline-block px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider ${style.badge}`}
            >
              {severity} SEVERITY
            </span>
          </div>
        </div>

        {/* Verdict & Sub-Scores Grid */}
        <div className="flex-1 w-full space-y-4">
          <div className="p-3.5 rounded-lg bg-slate-900/60 border border-surface-border">
            <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-1 flex items-center gap-1.5">
              <ShieldAlert className="w-3.5 h-3.5 text-indigo-400" />
              Automated Forensic Assessment
            </div>
            <div className="text-sm text-slate-200 font-medium leading-relaxed">
              {verdict || "Analysis completed according to security policies."}
            </div>
            <div className="text-[10px] text-slate-400 mt-1">
              Automated heuristic risk score — analyst validation required.
            </div>
          </div>

          {/* 6 Core Sub-Scores */}
          {subScores && (
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-2.5">
              {[
                { label: "Auth Risk", val: subScores.authentication_risk },
                { label: "Sender Risk", val: subScores.sender_risk },
                { label: "URL Risk", val: subScores.url_risk },
                { label: "Attachment Risk", val: subScores.attachment_risk },
                { label: "Content/NLP", val: subScores.content_nlp_risk },
                { label: "Infra Relay", val: subScores.infrastructure_risk },
              ].map((sub, i) => {
                const subColor =
                  sub.val >= 70
                    ? "text-red-400 bg-red-500/10 border-red-500/20"
                    : sub.val >= 40
                    ? "text-amber-400 bg-amber-500/10 border-amber-500/20"
                    : "text-blue-400 bg-blue-500/10 border-blue-500/20";
                return (
                  <div
                    key={i}
                    className={`p-2 rounded-lg border flex flex-col justify-between ${subColor}`}
                  >
                    <span className="text-[10px] font-medium text-slate-300">{sub.label}</span>
                    <div className="flex items-baseline justify-between mt-1">
                      <span className="text-base font-bold">{sub.val}%</span>
                      <div className="w-12 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                        <div
                          className="h-full bg-current rounded-full"
                          style={{ width: `${sub.val}%` }}
                        />
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* Explainable Threat Factors ("Why Was This Email Flagged?") */}
      {factors.length > 0 && (
        <div className="mt-6 pt-5 border-t border-surface-border">
          <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-3 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-400" />
            Explainable Threat Factors ({factors.length} Active Indicators)
          </h3>
          <div className="space-y-2">
            {factors.map((f, idx) => (
              <div
                key={idx}
                className="p-2.5 rounded-lg bg-slate-900/80 border border-surface-border flex items-start gap-3 text-xs"
              >
                <div className="px-2 py-0.5 rounded bg-red-500/20 text-red-400 font-mono font-bold border border-red-500/30 flex-shrink-0">
                  +{f.points}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 font-semibold text-slate-200">
                    <span>{f.factor}</span>
                    <span className="text-[10px] text-slate-400 px-1.5 py-0.2 rounded bg-slate-800">
                      {f.category}
                    </span>
                  </div>
                  <div className="text-slate-400 text-[11px] mt-0.5">{f.description}</div>
                  {f.evidence && (
                    <div className="mt-1 font-mono text-[10px] text-indigo-300 truncate bg-slate-950/60 px-2 py-0.5 rounded border border-slate-800">
                      Evidence: {f.evidence}
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
