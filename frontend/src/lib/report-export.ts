import { InvestigationDetail } from "./types";
import { formatDate } from "./utils";

export function exportInvestigationJSON(detail: InvestigationDetail) {
  const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(detail, null, 2));
  const downloadAnchor = document.createElement("a");
  downloadAnchor.setAttribute("href", dataStr);
  downloadAnchor.setAttribute("download", `forensic_report_${detail.id}.json`);
  document.body.appendChild(downloadAnchor);
  downloadAnchor.click();
  downloadAnchor.remove();
}

export function exportInvestigationPDF(detail: InvestigationDetail) {
  const printWindow = window.open("", "_blank");
  if (!printWindow) {
    alert("Please allow popups to export the PDF report.");
    return;
  }

  const sevColor =
    detail.severity === "CRITICAL"
      ? "#ef4444"
      : detail.severity === "HIGH"
      ? "#f97316"
      : detail.severity === "MEDIUM"
      ? "#eab308"
      : "#10b981";

  const html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>Forensic Report - ${detail.id}</title>
  <style>
    @media print {
      body { margin: 0; padding: 20px; font-size: 11px; }
      .no-print { display: none; }
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      margin: 40px auto;
      max-width: 900px;
      color: #0f172a;
      line-height: 1.5;
      padding: 0 20px;
    }
    .header {
      border-bottom: 3px solid #4f46e5;
      padding-bottom: 16px;
      margin-bottom: 24px;
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
    }
    .title {
      font-size: 20px;
      font-weight: 800;
      color: #1e1b4b;
      margin: 0;
    }
    .subtitle {
      font-size: 12px;
      color: #64748b;
      margin-top: 4px;
    }
    .badge {
      display: inline-block;
      padding: 4px 10px;
      border-radius: 6px;
      font-weight: 800;
      font-size: 12px;
      color: white;
      background-color: ${sevColor};
    }
    .grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 16px;
      margin-bottom: 20px;
      font-size: 12px;
    }
    .card {
      background: #f8fafc;
      border: 1px solid #e2e8f0;
      padding: 14px;
      border-radius: 8px;
    }
    .card-title {
      font-weight: bold;
      color: #334155;
      margin-bottom: 8px;
      border-bottom: 1px solid #e2e8f0;
      padding-bottom: 4px;
      text-transform: uppercase;
      font-size: 10px;
      letter-spacing: 0.5px;
    }
    .section-title {
      font-size: 14px;
      font-weight: 700;
      color: #1e293b;
      margin: 24px 0 10px 0;
      border-bottom: 1px solid #cbd5e1;
      padding-bottom: 4px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 8px;
      font-size: 11px;
    }
    th, td {
      border: 1px solid #cbd5e1;
      padding: 8px 10px;
      text-align: left;
    }
    th {
      background: #f1f5f9;
      color: #475569;
      font-weight: 700;
    }
    .factor-pts {
      font-weight: 800;
      color: #dc2626;
      text-align: center;
    }
    .status-pass { color: #166534; font-weight: bold; }
    .status-fail { color: #991b1b; font-weight: bold; }
    .code { font-family: monospace; font-size: 10px; background: #e2e8f0; padding: 2px 4px; border-radius: 3px; word-break: break-all; }
    .print-btn {
      background: #4f46e5;
      color: white;
      border: none;
      padding: 8px 16px;
      font-size: 12px;
      font-weight: bold;
      border-radius: 6px;
      cursor: pointer;
      margin-bottom: 20px;
    }
  </style>
</head>
<body>
  <div class="no-print" style="margin-bottom: 20px; text-align: right;">
    <button class="print-btn" onclick="window.print()">🖨️ Print / Save as PDF</button>
  </div>

  <div class="header">
    <div>
      <h1 class="title">SIH26106 SOC Digital Forensics & Threat Intelligence Report</h1>
      <div class="subtitle">Problem ID: SIH26106 | Case Dossier: <b>${detail.id}</b> | Generated: ${new Date().toUTCString()}</div>
    </div>
    <div>
      <span class="badge">${detail.severity} (Score: ${detail.threat_score}/100)</span>
    </div>
  </div>

  <div class="grid">
    <div class="card">
      <div class="card-title">Message Ingestion Metadata</div>
      <div><strong>Subject:</strong> ${detail.subject}</div>
      <div><strong>Sender (From):</strong> ${detail.sender}</div>
      <div><strong>Recipient (To):</strong> ${detail.recipient}</div>
      <div><strong>Transmission Date:</strong> ${formatDate(detail.email_date)}</div>
      <div><strong>Observed Inbound Relay:</strong> ${detail.source_ip} (${detail.source_country})</div>
    </div>
    <div class="card">
      <div class="card-title">Authentication Alignment Matrix</div>
      <div><strong>Header Trust Score:</strong> <b>${detail.header_trust_score}/100</b></div>
      <div><strong>SPF Record:</strong> <span class="${detail.spf_status === "Pass" ? "status-pass" : "status-fail"}">${detail.spf_status}</span></div>
      <div><strong>DKIM Cryptography:</strong> <span class="${detail.dkim_status === "Pass" ? "status-pass" : "status-fail"}">${detail.dkim_status}</span></div>
      <div><strong>DMARC Alignment:</strong> <span class="${detail.dmarc_status === "Pass" ? "status-pass" : "status-fail"}">${detail.dmarc_status}</span></div>
      <div><strong>SOC Triage Status:</strong> <b>${detail.status}</b></div>
    </div>
  </div>

  <div class="section-title">1. Itemized Threat Factor Attribution Schedule</div>
  <table>
    <thead>
      <tr>
        <th style="width: 15%;">Category</th>
        <th style="width: 25%;">Forensic Factor</th>
        <th style="width: 10%;">Impact</th>
        <th style="width: 50%;">Evidence & Technical Justification</th>
      </tr>
    </thead>
    <tbody>
      ${
        (detail.analysis?.threat_factors || []).length > 0
          ? detail.analysis.threat_factors
              .map(
                (f) => `<tr>
            <td><b>${f.category}</b></td>
            <td><b>${f.factor}</b><br/><small style="color:#64748b;">${f.description}</small></td>
            <td class="factor-pts">+${f.points}</td>
            <td><span class="code">${f.evidence}</span></td>
          </tr>`
              )
              .join("")
          : `<tr><td colspan="4" style="text-align: center; color: #166534;">No malicious threat factors identified. Verified safe.</td></tr>`
      }
    </tbody>
  </table>

  <div class="section-title">2. Chronological Relay Hop Trajectory</div>
  <table>
    <thead>
      <tr>
        <th style="width: 8%;">Hop</th>
        <th style="width: 25%;">Relayed From</th>
        <th style="width: 25%;">Relayed By</th>
        <th style="width: 22%;">Geographic Location</th>
        <th style="width: 20%;">IP Classification</th>
      </tr>
    </thead>
    <tbody>
      ${
        (detail.analysis?.routing_hops || []).length > 0
          ? detail.analysis.routing_hops
              .map(
                (h) => `<tr>
            <td>#${h.hop_number}</td>
            <td><b>${h.from_hostname || h.from_ip}</b></td>
            <td>${h.by_hostname || h.by_ip}</td>
            <td>${h.city}, ${h.country}</td>
            <td>${h.ip_classification}</td>
          </tr>`
              )
              .join("")
          : `<tr><td colspan="5" style="text-align: center; color: #64748b;">No intermediate relay hops detected.</td></tr>`
      }
    </tbody>
  </table>

  <div class="section-title">3. Suspicious Indicators & Payloads</div>
  <div class="grid">
    <div class="card">
      <div class="card-title">Extracted URLs (${detail.analysis?.urls?.length || 0})</div>
      ${
        (detail.analysis?.urls || []).length > 0
          ? detail.analysis.urls
              .slice(0, 5)
              .map(
                (u) => `<div style="margin-bottom: 6px;">
            <div><b>${u.display_text}</b> (${u.risk_level})</div>
            <div class="code">${u.full_url}</div>
          </div>`
              )
              .join("")
          : `<div>No hyperlinks detected.</div>`
      }
    </div>
    <div class="card">
      <div class="card-title">Attachment Fingerprints (${detail.analysis?.attachments?.length || 0})</div>
      ${
        (detail.analysis?.attachments || []).length > 0
          ? detail.analysis.attachments
              .map(
                (a) => `<div style="margin-bottom: 6px;">
            <div><b>${a.filename}</b> (${a.risk_level})</div>
            <div class="code">SHA256: ${a.sha256}</div>
          </div>`
              )
              .join("")
          : `<div>No email attachments present.</div>`
      }
    </div>
  </div>

  <div class="section-title">4. SOC Analyst Activity Log</div>
  <table>
    <thead>
      <tr>
        <th style="width: 20%;">Timestamp</th>
        <th style="width: 25%;">Author</th>
        <th style="width: 55%;">Note</th>
      </tr>
    </thead>
    <tbody>
      ${(detail.notes || [])
        .map(
          (n) => `<tr>
        <td>${formatDate(n.timestamp)}</td>
        <td><b>${n.author}</b></td>
        <td>${n.content}</td>
      </tr>`
        )
        .join("")}
    </tbody>
  </table>

  <div style="margin-top: 30px; border-top: 1px solid #e2e8f0; padding-top: 12px; font-size: 10px; color: #94a3b8; text-align: center;">
    SIH26106 Threat Platform • Automated Digital Forensics Report • Court & SOC Admissible Artifact
  </div>

  <script>
    window.onload = function() {
      setTimeout(() => {
        window.print();
      }, 500);
    };
  </script>
</body>
</html>`;

  printWindow.document.open();
  printWindow.document.write(html);
  printWindow.document.close();
}
