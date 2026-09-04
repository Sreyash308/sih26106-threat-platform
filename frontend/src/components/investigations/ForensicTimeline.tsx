"use client";

import { TimelineEvent } from "@/lib/types";
import { formatDate } from "@/lib/utils";
import { Clock, Send, Server, FileBox, CheckCircle } from "lucide-react";

interface ForensicTimelineProps {
  events: TimelineEvent[];
}

export default function ForensicTimeline({ events = [] }: ForensicTimelineProps) {
  const getEventIcon = (type: string) => {
    switch (type) {
      case "EMAIL_DATE":
        return <Send className="w-3.5 h-3.5 text-blue-400" />;
      case "HOP_RECEIVED":
        return <Server className="w-3.5 h-3.5 text-indigo-400" />;
      case "ATTACHMENT_PARSED":
        return <FileBox className="w-3.5 h-3.5 text-amber-400" />;
      case "ANALYSIS_COMPLETED":
      default:
        return <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />;
    }
  };

  return (
    <div className="bg-surface border border-surface-border rounded-xl p-5">
      <div className="flex items-center gap-2.5 border-b border-surface-border pb-3 mb-5">
        <div className="p-2 rounded-lg bg-indigo-500/10 text-indigo-400">
          <Clock className="w-4 h-4" />
        </div>
        <div>
          <h3 className="text-sm font-bold text-slate-100">Forensic Transmission Timeline</h3>
          <p className="text-[11px] text-slate-400">
            Reconstructed chronological sequence of origin dispatch, relay hops, and parsing.
          </p>
        </div>
      </div>

      <div className="relative pl-6 space-y-6 before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-800">
        {events.map((ev, i) => (
          <div key={i} className="relative group">
            {/* Timeline Dot with Icon */}
            <div className="absolute -left-6 top-0.5 w-5 h-5 rounded-full bg-slate-900 border border-slate-700 flex items-center justify-center group-hover:border-indigo-500 transition-colors">
              {getEventIcon(ev.event_type)}
            </div>

            <div className="p-3 rounded-lg bg-slate-900/60 border border-surface-border group-hover:border-slate-700 transition-colors">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 mb-1">
                <span className="font-semibold text-xs text-slate-200">{ev.title}</span>
                <span className="font-mono text-[10px] text-slate-400">
                  {formatDate(ev.timestamp)}
                </span>
              </div>
              <div className="text-xs text-slate-300">{ev.description}</div>
              <div className="mt-1 text-[10px] text-slate-400 font-mono">
                Source: <span className="text-slate-300">{ev.source}</span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
