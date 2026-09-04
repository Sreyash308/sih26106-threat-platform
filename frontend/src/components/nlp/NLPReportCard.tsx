"use client";

import { NLPAnalysis } from "@/lib/types";
import { BrainCircuit, MessageSquareCode, Sparkles, AlertCircle, Quote } from "lucide-react";
import { getSeverityStyle } from "@/lib/utils";

interface NLPReportCardProps {
  nlp: NLPAnalysis;
}

export default function NLPReportCard({ nlp }: NLPReportCardProps) {
  const percent = Math.round((nlp.phishing_probability || 0) * 100);
  const style = getSeverityStyle(nlp.risk_level);

  return (
    <div className="bg-surface border border-surface-border rounded-xl p-5 space-y-5">
      <div className="flex items-center justify-between border-b border-surface-border pb-3">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-lg bg-indigo-500/10 text-indigo-400">
            <BrainCircuit className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-slate-100">
              AI/NLP Social Engineering & Threat Intent
            </h3>
            <p className="text-[11px] text-slate-400">
              Content semantics, psychological urgency triggers, and credential solicitation patterns.
            </p>
          </div>
        </div>

        <div className="text-[10px] text-slate-400 bg-slate-900 px-2 py-1 rounded border border-surface-border font-mono">
          Engine: {nlp.model_engine}
        </div>
      </div>

      {/* Main Score & Intent Badge */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="p-4 rounded-xl bg-slate-900/80 border border-surface-border flex items-center justify-between">
          <div>
            <div className="text-[10px] font-semibold text-slate-400 uppercase">
              Phishing Probability
            </div>
            <div className="text-2xl font-extrabold text-white mt-0.5">
              {percent}%
            </div>
            <div className="text-[10px] text-slate-400">
              Confidence: {Math.round(nlp.confidence * 100)}%
            </div>
          </div>
          <div className="w-12 h-12 rounded-full border-2 border-indigo-500/30 flex items-center justify-center font-bold text-indigo-400 text-sm">
            {percent}%
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/80 border border-surface-border">
          <div className="text-[10px] font-semibold text-slate-400 uppercase">
            Classified Intent Label
          </div>
          <div className="mt-1">
            <span
              className={`inline-block px-2.5 py-1 rounded-full text-xs font-bold ${style.badge}`}
            >
              {nlp.intent_label}
            </span>
          </div>
          <div className="text-[10px] text-slate-400 mt-1">
            Primary psychological assault vector
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/80 border border-surface-border">
          <div className="text-[10px] font-semibold text-slate-400 uppercase">
            Targeted Tactics & Tags
          </div>
          <div className="flex flex-wrap gap-1 mt-1">
            {nlp.categories.map((cat, idx) => (
              <span
                key={idx}
                className="px-2 py-0.5 rounded text-[10px] font-semibold bg-indigo-500/20 text-indigo-300 border border-indigo-500/30"
              >
                {cat}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* Suspicious Keywords Pill Cloud */}
      {nlp.suspicious_keywords.length > 0 && (
        <div>
          <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
            <Sparkles className="w-3 h-3 text-amber-400" />
            Extracted Threat Keywords & Phrases
          </div>
          <div className="flex flex-wrap gap-1.5">
            {nlp.suspicious_keywords.map((kw, i) => (
              <span
                key={i}
                className="px-2 py-1 rounded-md bg-slate-900 text-slate-200 border border-slate-700 text-xs font-mono"
              >
                &ldquo;{kw}&rdquo;
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Flagged Evidence Sentences */}
      {nlp.evidence_sentences.length > 0 && (
        <div className="space-y-2 pt-2 border-t border-surface-border">
          <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
            <Quote className="w-3 h-3 text-indigo-400" />
            Highlighted Evidence Excerpts
          </div>
          <div className="space-y-1.5">
            {nlp.evidence_sentences.map((sent, idx) => (
              <div
                key={idx}
                className="p-2.5 rounded-lg bg-slate-950 border border-red-500/20 text-xs text-slate-300 font-serif italic border-l-2 border-l-red-500"
              >
                &ldquo;{sent}&rdquo;
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
