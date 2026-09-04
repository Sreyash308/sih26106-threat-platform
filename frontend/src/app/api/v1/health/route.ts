import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";

export async function GET() {
  return NextResponse.json({
    status: "ACTIVE",
    version: "1.0.0",
    service: "SIH26106 Email Threat Intelligence Platform",
    components: {
      backend: "ACTIVE",
      database: "ACTIVE",
      nlp_engine: "ACTIVE (Rule-Based & TF-IDF Fallback)",
      geolocation: "AVAILABLE (ip-api.com & Synthetic Documentation Fallback)",
      threat_intelligence: "ACTIVE (Provider Abstraction: VirusTotal & AbuseIPDB)",
    },
  });
}
