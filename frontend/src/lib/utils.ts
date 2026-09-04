import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatBytes(bytes: number, decimals = 1) {
  if (!bytes) return "0 B";
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
}

export function formatDate(dateStr?: string) {
  if (!dateStr) return "N/A";
  try {
    const d = new Date(dateStr);
    if (isNaN(d.getTime())) return dateStr;
    return d.toLocaleString("en-US", {
      month: "short",
      day: "2-digit",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    });
  } catch {
    return dateStr;
  }
}

export function getSeverityStyle(severity: string) {
  const s = (severity || "").toUpperCase();
  switch (s) {
    case "CRITICAL":
      return {
        bg: "bg-red-500/10",
        border: "border-red-500/30",
        text: "text-red-400",
        badge: "bg-red-500 text-white font-bold",
        dot: "bg-red-500",
        hex: "#ef4444",
      };
    case "HIGH":
      return {
        bg: "bg-orange-500/10",
        border: "border-orange-500/30",
        text: "text-orange-400",
        badge: "bg-orange-500 text-white font-bold",
        dot: "bg-orange-500",
        hex: "#f97316",
      };
    case "MEDIUM":
      return {
        bg: "bg-amber-500/10",
        border: "border-amber-500/30",
        text: "text-amber-400",
        badge: "bg-amber-500/20 text-amber-300 border border-amber-500/40",
        dot: "bg-amber-500",
        hex: "#f59e0b",
      };
    case "LOW":
      return {
        bg: "bg-blue-500/10",
        border: "border-blue-500/30",
        text: "text-blue-400",
        badge: "bg-blue-500/20 text-blue-300 border border-blue-500/40",
        dot: "bg-blue-500",
        hex: "#3b82f6",
      };
    case "SAFE":
    default:
      return {
        bg: "bg-emerald-500/10",
        border: "border-emerald-500/30",
        text: "text-emerald-400",
        badge: "bg-emerald-500/20 text-emerald-300 border border-emerald-500/40",
        dot: "bg-emerald-500",
        hex: "#10b981",
      };
  }
}

export function getStatusStyle(status: string) {
  const s = (status || "").toUpperCase();
  switch (s) {
    case "NEW":
      return "bg-purple-500/20 text-purple-300 border border-purple-500/40";
    case "IN_PROGRESS":
      return "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 animate-pulse";
    case "REVIEWED":
      return "bg-blue-500/20 text-blue-300 border border-blue-500/40";
    case "ESCALATED":
      return "bg-red-500/20 text-red-300 border border-red-500/40";
    case "CLOSED":
    default:
      return "bg-slate-700/50 text-slate-400 border border-slate-600/40";
  }
}
