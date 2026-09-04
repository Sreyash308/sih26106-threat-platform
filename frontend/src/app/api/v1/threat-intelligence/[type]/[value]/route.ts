import { NextRequest, NextResponse } from "next/server";

export const dynamic = "force-dynamic";

export async function GET(
  _req: NextRequest,
  { params }: { params: { type: string; value: string } }
) {
  const type = params?.type || "domain";
  const value = params?.value || "";
  const decodedValue = decodeURIComponent(value);

  // Known demo IOCs
  if (decodedValue === "203.0.113.195") {
    return NextResponse.json({
      ioc_type: "ip",
      query: decodedValue,
      status: "malicious",
      reputation_score: 98,
      risk_level: "CRITICAL",
      confidence: "High",
      provider: "AbuseIPDB & VirusTotal",
      provider_status: "demo_intelligence",
      threat_categories: ["Bulletproof Hosting", "Phishing Relay", "Botnet Node"],
      details: {
        country: "Russian Federation",
        city: "Moscow",
        isp: "HostEvasion Transit Ltd",
        total_reports: 142,
        last_reported_at: new Date().toISOString(),
      },
    });
  }

  if (decodedValue.includes("phish") || decodedValue.includes("top") || decodedValue.includes("example")) {
    return NextResponse.json({
      ioc_type: type,
      query: decodedValue,
      status: "suspicious",
      reputation_score: 85,
      risk_level: "HIGH",
      confidence: "High",
      provider: "VirusTotal Community",
      provider_status: "demo_intelligence",
      threat_categories: ["Lookalike Domain", "Credential Harvesting Host"],
      details: {
        domain: decodedValue,
        registrar: "NameCheap / Anonymous Proxy",
        created_date: "2026-08-28",
        dns_records: ["203.0.113.195"],
      },
    });
  }

  return NextResponse.json({
    ioc_type: type,
    query: decodedValue,
    status: "clean",
    reputation_score: 0,
    risk_level: "SAFE",
    confidence: "Medium",
    provider: "Heuristic Provider",
    provider_status: "provider_not_configured",
    threat_categories: [],
    details: {
      message: "No malicious reputation recorded on local heuristic database.",
    },
  });
}
