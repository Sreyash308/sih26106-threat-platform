import {
  DashboardStats,
  FullAnalysisResult,
  InvestigationDetail,
  InvestigationListItem,
} from "./types";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000/api";

export async function fetchDashboardStats(): Promise<DashboardStats> {
  const res = await fetch(`${API_BASE}/v1/dashboard/stats`, { cache: "no-store" });
  if (!res.ok) throw new Error("Failed to load dashboard statistics");
  const json = await res.json();
  return json.data;
}

export async function analyzeEmailPayload(formData: FormData): Promise<FullAnalysisResult> {
  const res = await fetch(`${API_BASE}/v1/analyze`, {
    method: "POST",
    body: formData,
  });
  if (!res.ok) {
    const errorJson = await res.json().catch(() => ({}));
    throw new Error(errorJson?.error?.message || "Analysis failed");
  }
  return res.json();
}

export async function fetchInvestigations(params?: {
  skip?: number;
  limit?: number;
  severity?: string;
  status?: string;
  search?: string;
}): Promise<{ total: number; page: number; limit: number; items: InvestigationListItem[] }> {
  const query = new URLSearchParams();
  if (params?.skip !== undefined) query.set("skip", params.skip.toString());
  if (params?.limit !== undefined) query.set("limit", params.limit.toString());
  if (params?.severity) query.set("severity", params.severity);
  if (params?.status) query.set("status", params.status);
  if (params?.search) query.set("search", params.search);

  const res = await fetch(`${API_BASE}/v1/investigations?${query.toString()}`, { cache: "no-store" });
  if (!res.ok) throw new Error("Failed to load investigations");
  return res.json();
}

export async function fetchInvestigation(id: string): Promise<InvestigationDetail> {
  const res = await fetch(`${API_BASE}/v1/investigations/${id}`, { cache: "no-store" });
  if (!res.ok) throw new Error(`Failed to load investigation ${id}`);
  const json = await res.json();
  return json.data;
}

export async function updateInvestigationStatus(id: string, status: string): Promise<void> {
  const res = await fetch(`${API_BASE}/v1/investigations/${id}/status`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ status }),
  });
  if (!res.ok) throw new Error("Failed to update status");
}

export async function addInvestigationNote(id: string, author: string, note: string): Promise<any> {
  const res = await fetch(`${API_BASE}/v1/investigations/${id}/notes`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ author, note }),
  });
  if (!res.ok) throw new Error("Failed to save note");
  return res.json();
}

export async function deleteInvestigation(id: string): Promise<void> {
  const res = await fetch(`${API_BASE}/v1/investigations/${id}`, {
    method: "DELETE",
  });
  if (!res.ok) throw new Error("Failed to delete investigation");
}

export async function fetchGeoIntelligence(): Promise<any> {
  const res = await fetch(`${API_BASE}/v1/geo/intelligence`, { cache: "no-store" });
  if (!res.ok) throw new Error("Failed to load geo intelligence");
  return res.json();
}

export async function lookupThreat(type: "ip" | "domain" | "hash", value: string): Promise<any> {
  const res = await fetch(`${API_BASE}/v1/threat-intelligence/${type}/${encodeURIComponent(value)}`, {
    cache: "no-store",
  });
  if (!res.ok) throw new Error(`Threat lookup failed for ${value}`);
  return res.json();
}

export function getPDFReportUrl(id: string): string {
  return `${API_BASE}/v1/investigations/${id}/report/pdf`;
}

export function getJSONExportUrl(id: string): string {
  return `${API_BASE}/v1/investigations/${id}/export/json`;
}
