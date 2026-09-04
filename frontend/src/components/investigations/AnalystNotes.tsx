"use client";

import { useState } from "react";
import { AnalystNote } from "@/lib/types";
import { formatDate, getStatusStyle } from "@/lib/utils";
import { addInvestigationNote, updateInvestigationStatus } from "@/lib/api";
import { MessageSquarePlus, ShieldCheck, User, Clock, AlertCircle } from "lucide-react";

interface AnalystNotesProps {
  investigationId: string;
  initialStatus: string;
  initialNotes: AnalystNote[];
  onStatusChange?: (newStatus: string) => void;
}

export default function AnalystNotes({
  investigationId,
  initialStatus,
  initialNotes = [],
  onStatusChange,
}: AnalystNotesProps) {
  const [status, setStatus] = useState(initialStatus);
  const [notes, setNotes] = useState<AnalystNote[]>(initialNotes);
  const [author, setAuthor] = useState("SOC Lead Analyst");
  const [noteContent, setNoteContent] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isUpdatingStatus, setIsUpdatingStatus] = useState(false);
  const [errorMsg, setErrorMsg] = useState("");

  const handleStatusUpdate = async (newStatus: string) => {
    setIsUpdatingStatus(true);
    try {
      await updateInvestigationStatus(investigationId, newStatus);
      setStatus(newStatus);
      if (onStatusChange) onStatusChange(newStatus);
    } catch (err: any) {
      setErrorMsg(err.message || "Failed to update case status");
    } finally {
      setIsUpdatingStatus(false);
    }
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!noteContent.trim()) return;

    setIsSubmitting(true);
    setErrorMsg("");
    try {
      const res = await addInvestigationNote(investigationId, author, noteContent);
      setNotes(res.notes || []);
      setNoteContent("");
    } catch (err: any) {
      setErrorMsg(err.message || "Failed to add analyst note");
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="bg-surface border border-surface-border rounded-xl p-5 space-y-5">
      {/* Header & Status Control */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-surface-border pb-4">
        <div>
          <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
            <MessageSquarePlus className="w-4 h-4 text-indigo-400" />
            Case Triage & Analyst Activity Log
          </h3>
          <p className="text-[11px] text-slate-400">
            Persist investigation findings, escalate threats, and document SOC mitigation steps.
          </p>
        </div>

        {/* Status Dropdown */}
        <div className="flex items-center gap-2.5">
          <span className="text-xs text-slate-400 font-medium">Status:</span>
          <select
            value={status}
            disabled={isUpdatingStatus}
            onChange={(e) => handleStatusUpdate(e.target.value)}
            className={`text-xs font-bold px-3 py-1.5 rounded-lg border focus:outline-none transition-all cursor-pointer ${getStatusStyle(
              status
            )}`}
          >
            <option value="NEW" className="bg-slate-900 text-slate-100">NEW</option>
            <option value="IN_PROGRESS" className="bg-slate-900 text-slate-100">IN PROGRESS</option>
            <option value="REVIEWED" className="bg-slate-900 text-slate-100">REVIEWED</option>
            <option value="ESCALATED" className="bg-slate-900 text-slate-100">ESCALATED</option>
            <option value="CLOSED" className="bg-slate-900 text-slate-100">CLOSED</option>
          </select>
        </div>
      </div>

      {errorMsg && (
        <div className="p-2.5 rounded-lg bg-red-500/10 border border-red-500/30 text-xs text-red-400 flex items-center gap-2">
          <AlertCircle className="w-4 h-4" />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* Existing Notes Feed */}
      <div className="space-y-3">
        {notes.length === 0 ? (
          <div className="text-center py-6 text-xs text-slate-400 bg-slate-900/40 rounded-lg border border-surface-border">
            No analyst notes documented yet for this case. Add the first observation below.
          </div>
        ) : (
          notes.map((n, i) => (
            <div
              key={n.id || i}
              className="p-3.5 rounded-lg bg-slate-900/80 border border-surface-border space-y-1.5 text-xs"
            >
              <div className="flex items-center justify-between text-slate-400 text-[10px]">
                <span className="font-semibold text-indigo-300 flex items-center gap-1.5">
                  <User className="w-3 h-3" />
                  {n.author}
                </span>
                <span className="flex items-center gap-1 font-mono">
                  <Clock className="w-3 h-3" />
                  {formatDate(n.timestamp)}
                </span>
              </div>
              <div className="text-slate-200 leading-relaxed font-sans">{n.content}</div>
            </div>
          ))
        )}
      </div>

      {/* Add Note Form */}
      <form onSubmit={handleAddNote} className="space-y-3 pt-2 border-t border-surface-border">
        <div className="flex gap-2">
          <input
            type="text"
            placeholder="Analyst Name / Call-sign"
            value={author}
            onChange={(e) => setAuthor(e.target.value)}
            className="w-1/3 bg-slate-900 border border-surface-border rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
          />
        </div>
        <textarea
          rows={3}
          placeholder="Enter triage notes, host isolation steps, or campaign correlation details..."
          value={noteContent}
          onChange={(e) => setNoteContent(e.target.value)}
          className="w-full bg-slate-900 border border-surface-border rounded-lg p-3 text-xs text-slate-200 placeholder-slate-400 focus:outline-none focus:border-indigo-500 resize-none"
        />
        <div className="flex justify-end">
          <button
            type="submit"
            disabled={isSubmitting || !noteContent.trim()}
            className="px-4 py-1.5 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white font-semibold text-xs rounded-lg transition-colors shadow-sm"
          >
            {isSubmitting ? "Persisting..." : "Save Analyst Note"}
          </button>
        </div>
      </form>
    </div>
  );
}
