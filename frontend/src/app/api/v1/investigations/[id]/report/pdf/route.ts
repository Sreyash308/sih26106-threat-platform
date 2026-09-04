import { NextRequest, NextResponse } from "next/server";
import { toInvestigationDetail } from "@/lib/forensic-engine";

export async function GET(_req: NextRequest, { params }: { params: { id: string } }) {
  try {
    const detail = toInvestigationDetail(params.id);
    if (!detail) {
      return NextResponse.json({ success: false, error: { message: "Investigation not found" } }, { status: 404 });
    }

    const html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>Forensic Report - ${detail.id}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 40px; color: #1e293b; line-height: 1.5; }
    .header { border-bottom: 2px solid #3b82f6; padding-bottom: 12px; margin-bottom: 24px; }
    h1 { margin: 0; font-size: 22px; color: #0f172a; }
    .badge { display: inline-block; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; }
    .critical { background: #fee2e2; color: #991b1b; }
    .high { background: #ffedd5; color: #9a3412; }
    .safe { background: #dcfce7; color: #166534; }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 24px; font-size: 13px; }
    .card { background: #f8fafc; border: 1px solid #e2e8f0; padding: 12px; border-radius: 6px; }
    table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 12px; }
    th, td { border: 1px solid #cbd5e1; padding: 8px; text-align: left; }
    th { background: #f1f5f9; }
    .factor-pts { font-weight: bold; color: #dc2626; }
  </style>
</head>
<body>
  <div class="header">
    <div style="float: right;">
      <span class="badge ${detail.severity.toLowerCase()}">${detail.severity} (Score: ${detail.threat_score}/100)</span>
    </div>
    <h1>SIH26106 SOC Digital Forensics & Threat Report</h1>
    <div style="font-size: 12px; color: #64748b; margin-top: 4px;">Case ID: ${detail.id} | Generated: ${new Date().toISOString()}</div>
  </div>

  <div class="grid">
    <div class="card">
      <strong>Subject:</strong> ${detail.subject}<br/>
      <strong>Sender (From):</strong> ${detail.sender}<br/>
      <strong>Recipient (To):</strong> ${detail.recipient}<br/>
      <strong>Transmission Date:</strong> ${detail.email_date}
    </div>
    <div class="card">
      <strong>Header Trust Score:</strong> ${detail.header_trust_score}/100<br/>
      <strong>SPF Alignment:</strong> ${detail.spf_status}<br/>
      <strong>DKIM Alignment:</strong> ${detail.dkim_status}<br/>
      <strong>DMARC Alignment:</strong> ${detail.dmarc_status}
    </div>
  </div>

  <h3>Forensic Threat Factor Schedule</h3>
  <table>
    <thead>
      <tr>
        <th>Category</th>
        <th>Factor</th>
        <th>Points</th>
        <th>Evidence</th>
      </tr>
    </thead>
    <tbody>
      ${(detail.analysis.threat_factors || [])
        .map(
          (f) => `<tr>
            <td>${f.category}</td>
            <td><strong>${f.factor}</strong><br/><small style="color:#64748b;">${f.description}</small></td>
            <td class="factor-pts">+${f.points}</td>
            <td><code>${f.evidence}</code></td>
          </tr>`
        )
        .join("")}
    </tbody>
  </table>

  <h3>Observed Relay Trajectory</h3>
  <table>
    <thead>
      <tr>
        <th>Hop</th>
        <th>Relayed From</th>
        <th>Relayed By</th>
        <th>Location</th>
        <th>IP Classification</th>
      </tr>
    </thead>
    <tbody>
      ${(detail.analysis.routing_hops || [])
        .map(
          (h) => `<tr>
            <td>#${h.hop_number}</td>
            <td>${h.from_hostname || h.from_ip}</td>
            <td>${h.by_hostname || h.by_ip}</td>
            <td>${h.city}, ${h.country}</td>
            <td>${h.ip_classification}</td>
          </tr>`
        )
        .join("")}
    </tbody>
  </table>
  <script>window.onload = function() { window.print(); };</script>
</body>
</html>`;

    return new Response(html, {
      status: 200,
      headers: {
        "Content-Type": "text/html; charset=utf-8",
      },
    });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
