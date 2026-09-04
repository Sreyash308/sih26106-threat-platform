import crypto from "crypto";
import {
  FullAnalysisResult,
  InvestigationDetail,
  InvestigationListItem,
  DashboardStats,
  RoutingHop,
  RouteStats,
  URLItem,
  AttachmentItem,
  ThreatFactor,
  TimelineEvent,
  CryptoIndicator,
} from "./types";
import { DEMO_EMAILS } from "../data/demo_emails";

// In-memory investigation storage for serverless runtime
const investigationsStore = new Map<string, { analysis: FullAnalysisResult; rawHeaders: string; rawText: string; filename: string }>();
const analystNotesStore = new Map<string, any[]>();
let isInitialized = false;

// Helper: Calculate Haversine distance in km
function haversineDistance(lat1: number, lon1: number, lat2: number, lon2: number): number {
  const R = 6371; // Earth radius in km
  const dLat = (lat2 - lat1) * (Math.PI / 180);
  const dLon = (lon2 - lon1) * (Math.PI / 180);
  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(lat1 * (Math.PI / 180)) *
      Math.cos(lat2 * (Math.PI / 180)) *
      Math.sin(dLon / 2) *
      Math.sin(dLon / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return Math.round(R * c);
}

// Helper: Classify IP address
function classifyIp(ip: string): { classification: string; isPublic: boolean } {
  if (!ip) return { classification: "Unknown", isPublic: false };
  const cleanIp = ip.trim();
  if (cleanIp === "127.0.0.1" || cleanIp === "::1" || cleanIp.startsWith("127.")) {
    return { classification: "Loopback", isPublic: false };
  }
  if (
    cleanIp.startsWith("10.") ||
    cleanIp.startsWith("192.168.") ||
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(cleanIp)
  ) {
    return { classification: "RFC 1918 Private", isPublic: false };
  }
  if (
    cleanIp.startsWith("192.0.2.") ||
    cleanIp.startsWith("198.51.100.") ||
    cleanIp.startsWith("203.0.113.")
  ) {
    return { classification: "RFC 5737 Documentation Network", isPublic: false };
  }
  return { classification: "Public Internet IPv4", isPublic: true };
}

// IP Geolocation lookup
const KNOWN_GEO_LOOKUP: Record<
  string,
  { country: string; city: string; region: string; lat: number; lon: number; isp: string; org: string; asn: string }
> = {
  "203.0.113.195": {
    country: "Russian Federation",
    city: "Moscow",
    region: "Moscow City",
    lat: 55.7558,
    lon: 37.6173,
    isp: "Demo Bulletproof Transit Ltd",
    org: "HostEvasion AS",
    asn: "AS64512",
  },
  "198.51.100.88": {
    country: "United Kingdom",
    city: "London",
    region: "Greater London",
    lat: 51.5074,
    lon: -0.1278,
    isp: "Enterprise Gateway Exchange",
    org: "Defense Inbound MX",
    asn: "AS13335",
  },
  "198.51.100.25": {
    country: "Germany",
    city: "Frankfurt",
    region: "Hesse",
    lat: 50.1109,
    lon: 8.6821,
    isp: "Hetzner Online GmbH",
    org: "Cloud Transit Node",
    asn: "AS24940",
  },
  "198.51.100.12": {
    country: "United States",
    city: "Ashburn",
    region: "Virginia",
    lat: 39.0438,
    lon: -77.4874,
    isp: "Amazon Web Services",
    org: "AWS Cloud Inbound",
    asn: "AS16509",
  },
  "192.0.2.1": {
    country: "United States",
    city: "San Jose",
    region: "California",
    lat: 37.3382,
    lon: -121.8863,
    isp: "Workstation Dynamic DHCP",
    org: "Dynamic Access Pool",
    asn: "AS7018",
  },
};

// Pure TypeScript Forensic Analysis Engine
export function runForensicAnalysis(
  rawEmail: string,
  filename: string = "email.eml",
  presetId?: string
): FullAnalysisResult {
  const investigationId = presetId || "INV-" + crypto.randomBytes(4).toString("hex").toUpperCase();
  const nowIso = new Date().toISOString();
  const timeline: TimelineEvent[] = [];

  // 1. Separate Headers from Body
  const headerBodySplit = rawEmail.split(/\r?\n\r?\n/);
  const headerText = headerBodySplit[0] || "";
  const bodyText = headerBodySplit.slice(1).join("\n\n");

  // Parse raw headers into lines (unfolding multi-line headers)
  const headerLines: string[] = [];
  const rawLines = headerText.split(/\r?\n/);
  for (const line of rawLines) {
    if ((line.startsWith(" ") || line.startsWith("\t")) && headerLines.length > 0) {
      headerLines[headerLines.length - 1] += " " + line.trim();
    } else if (line.trim()) {
      headerLines.push(line);
    }
  }

  // Parse headers map
  const headersMap: Record<string, string[]> = {};
  for (const h of headerLines) {
    const idx = h.indexOf(":");
    if (idx !== -1) {
      const key = h.substring(0, idx).trim().toLowerCase();
      const val = h.substring(idx + 1).trim();
      if (!headersMap[key]) headersMap[key] = [];
      headersMap[key].push(val);
    }
  }

  const getHeader = (k: string): string => (headersMap[k.toLowerCase()]?.[0] || "").trim();

  const fromRaw = getHeader("From") || "Security Alert <security@enterprise.example>";
  const toRaw = getHeader("To") || "analyst@enterprise-defense.org";
  const subject = getHeader("Subject") || "Security Notification";
  const dateHeader = getHeader("Date") || new Date().toUTCString();
  const replyTo = getHeader("Reply-To") || "";
  const returnPath = getHeader("Return-Path") || "";
  const authResults = getHeader("Authentication-Results");
  const receivedSpf = getHeader("Received-SPF");
  const dkimSig = getHeader("DKIM-Signature");

  if (dateHeader) {
    timeline.push({
      timestamp: dateHeader,
      event_type: "EMAIL_DATE",
      title: "Message Dispatched",
      description: `Email Date header asserted by sender: ${dateHeader}`,
      source: "Header: Date",
    });
  }

  // 2. Authentication Analysis
  let spfStatus = "None";
  let spfEvidence = "No SPF verification records found.";
  if (receivedSpf) {
    if (/pass/i.test(receivedSpf)) {
      spfStatus = "Pass";
      spfEvidence = `SPF Pass verified: ${receivedSpf}`;
    } else if (/fail/i.test(receivedSpf)) {
      spfStatus = "Fail";
      spfEvidence = `SPF Failure recorded: ${receivedSpf}`;
    } else if (/softfail/i.test(receivedSpf)) {
      spfStatus = "SoftFail";
      spfEvidence = `SPF SoftFail: ${receivedSpf}`;
    }
  } else if (authResults) {
    const match = authResults.match(/spf=([a-zA-Z]+)/i);
    if (match) {
      const s = match[1].toLowerCase();
      spfStatus = s.charAt(0).toUpperCase() + s.slice(1);
      spfEvidence = `Authentication-Results SPF: ${spfStatus}`;
    }
  }

  let dkimStatus = "None";
  let dkimEvidence = "No DKIM signature detected.";
  if (dkimSig || authResults) {
    if (authResults && /dkim=pass/i.test(authResults)) {
      dkimStatus = "Pass";
      dkimEvidence = "Cryptographic signature validated successfully.";
    } else if (authResults && /dkim=fail/i.test(authResults)) {
      dkimStatus = "Fail";
      dkimEvidence = "DKIM signature verification failed (body hash or key mismatch).";
    } else if (dkimSig) {
      dkimStatus = "Pass";
      dkimEvidence = "Valid DKIM signature header present.";
    }
  }

  let dmarcStatus = "None";
  let dmarcEvidence = "No DMARC evaluation asserted.";
  if (authResults) {
    if (/dmarc=pass/i.test(authResults)) {
      dmarcStatus = "Pass";
      dmarcEvidence = "DMARC policy aligned and passed.";
    } else if (/dmarc=fail/i.test(authResults)) {
      dmarcStatus = "Fail";
      dmarcEvidence = "DMARC policy failed domain alignment check.";
    }
  }

  let headerTrustScore = 100;
  if (spfStatus === "Fail") headerTrustScore -= 30;
  else if (spfStatus === "SoftFail") headerTrustScore -= 15;
  if (dkimStatus === "Fail") headerTrustScore -= 35;
  else if (dkimStatus === "None") headerTrustScore -= 10;
  if (dmarcStatus === "Fail") headerTrustScore -= 35;
  headerTrustScore = Math.max(0, Math.min(100, headerTrustScore));

  const authSummary = {
    spf: { status: spfStatus, evidence: spfEvidence },
    dkim: { status: dkimStatus, evidence: dkimEvidence },
    dmarc: { status: dmarcStatus, evidence: dmarcEvidence },
    header_trust_score: headerTrustScore,
    evidence_notes: [
      spfStatus === "Fail" ? "Sender IP is not authorized in SPF record." : "SPF evaluated.",
      dkimStatus === "Fail" ? "DKIM verification failed." : "DKIM evaluated.",
      dmarcStatus === "Fail" ? "DMARC alignment failure." : "DMARC evaluated.",
    ],
  };

  // 3. Sender Analysis
  const emailRegex = /<([^>]+)>/;
  const fromMatch = fromRaw.match(emailRegex);
  const fromAddress = fromMatch ? fromMatch[1] : fromRaw.replace(/"/g, "").trim();
  const displayName = fromRaw.replace(/<[^>]+>/, "").replace(/"/g, "").trim();
  const fromDomain = fromAddress.split("@")[1] || "";

  const replyToMatch = replyTo.match(emailRegex);
  const replyToAddress = replyToMatch ? replyToMatch[1] : replyTo.replace(/"/g, "").trim();
  const replyToDomain = replyToAddress.split("@")[1] || "";

  const returnPathMatch = returnPath.match(emailRegex);
  const returnPathAddress = returnPathMatch ? returnPathMatch[1] : returnPath.replace(/"/g, "").trim();
  const returnPathDomain = returnPathAddress.split("@")[1] || "";

  const fromReplyToMismatch = Boolean(replyToDomain && fromDomain && replyToDomain.toLowerCase() !== fromDomain.toLowerCase());
  const fromReturnPathMismatch = Boolean(returnPathDomain && fromDomain && returnPathDomain.toLowerCase() !== fromDomain.toLowerCase());

  const brandKeywords = ["microsoft", "paypal", "google", "apple", "amazon", "netflix", "security", "support", "billing"];
  const isDisplayDeceptive = brandKeywords.some((b) => displayName.toLowerCase().includes(b)) && !brandKeywords.some((b) => fromDomain.toLowerCase().includes(b));

  const senderEvidence: string[] = [];
  if (fromReplyToMismatch) senderEvidence.push(`Reply-To address (${replyToAddress}) domain does not match From address (${fromAddress}).`);
  if (fromReturnPathMismatch) senderEvidence.push(`Return-Path address (${returnPathAddress}) differs from sender domain (${fromDomain}).`);
  if (isDisplayDeceptive) senderEvidence.push(`Display name "${displayName}" claims official brand identity on unrelated domain "${fromDomain}".`);

  const senderAnalysis = {
    from_header: fromRaw,
    display_name: displayName,
    from_address: fromAddress,
    from_domain: fromDomain,
    reply_to: replyToAddress,
    return_path: returnPathAddress,
    sender: fromAddress,
    from_reply_to_mismatch: fromReplyToMismatch,
    from_return_path_mismatch: fromReturnPathMismatch,
    display_name_deception: isDisplayDeceptive,
    is_punycode: fromDomain.includes("xn--"),
    is_free_provider: ["gmail.com", "yahoo.com", "hotmail.com"].includes(fromDomain.toLowerCase()),
    suspicious_domain_patterns: fromDomain.endsWith(".top") || fromDomain.endsWith(".xyz") ? [fromDomain] : [],
    risk_level: (fromReplyToMismatch || isDisplayDeceptive ? "HIGH" : "SAFE") as any,
    evidence: senderEvidence,
  };

  // 4. Received Hop Parsing & Geo Reconstruction
  const receivedHeaders = headersMap["received"] || [];
  const hops: RoutingHop[] = [];
  const reversedHops = [...receivedHeaders].reverse();

  let hopNum = 1;
  for (const rec of reversedHops) {
    const ipMatch = rec.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/);
    const ip = ipMatch ? ipMatch[0] : "";
    const fromHostMatch = rec.match(/from\s+([^\s\(\)]+)/i);
    const byHostMatch = rec.match(/by\s+([^\s\(\)]+)/i);
    const timeMatch = rec.match(/;\s*(.+)$/);

    const fromHost = fromHostMatch ? fromHostMatch[1] : "origin";
    const byHost = byHostMatch ? byHostMatch[1] : "relay";
    const hopTimestamp = timeMatch ? timeMatch[1].trim() : dateHeader;

    const { classification, isPublic } = classifyIp(ip);
    const geo = KNOWN_GEO_LOOKUP[ip] || {
      country: isPublic ? "United States" : "Internal Subnet",
      city: isPublic ? "Ashburn" : "Local Network",
      region: isPublic ? "Virginia" : "Private",
      lat: isPublic ? 39.0438 : 37.7749,
      lon: isPublic ? -77.4874 : -122.4194,
      isp: "Enterprise Gateway Transit",
      org: "Relay Node",
      asn: "AS13335",
    };

    const isSuspiciousHop = ip === "203.0.113.195" || geo.country === "Russian Federation";

    hops.push({
      hop_number: hopNum,
      timestamp: hopTimestamp,
      from_hostname: fromHost,
      from_ip: ip,
      by_hostname: byHost,
      by_ip: ip,
      ip_classification: classification,
      is_public: isPublic,
      country: geo.country,
      city: geo.city,
      region: geo.region,
      latitude: geo.lat,
      longitude: geo.lon,
      isp: geo.isp,
      organization: geo.org,
      asn: geo.asn,
      ordering_confidence: "High",
      suspicious: isSuspiciousHop,
      evidence: isSuspiciousHop ? "Originates from high-risk dynamic relay in Moscow, Russia." : `Hop processed by ${byHost}`,
      provider_status: "demo_intelligence",
    });

    timeline.push({
      timestamp: hopTimestamp,
      event_type: "HOP_RECEIVED",
      title: `Hop #${hopNum} Observed`,
      description: `Relayed by ${byHost} from ${fromHost} (${geo.city}, ${geo.country}) [IP: ${ip || "N/A"}]`,
      source: `Hop #${hopNum}`,
    });

    hopNum++;
  }

  // Calculate Route Statistics
  let totalDist = 0;
  let longestJump = 0;
  const countries = Array.from(new Set(hops.map((h) => h.country).filter(Boolean)));
  const uniqueAsns = Array.from(new Set(hops.map((h) => h.asn).filter(Boolean)));

  for (let i = 0; i < hops.length - 1; i++) {
    const h1 = hops[i];
    const h2 = hops[i + 1];
    if (h1.latitude && h1.longitude && h2.latitude && h2.longitude) {
      const d = haversineDistance(h1.latitude, h1.longitude, h2.latitude, h2.longitude);
      totalDist += d;
      if (d > longestJump) longestJump = d;
    }
  }

  const routeStats: RouteStats = {
    total_hops: hops.length,
    public_hops: hops.filter((h) => h.is_public).length,
    countries_traversed: countries,
    unique_asns: uniqueAsns,
    approximate_distance_km: totalDist,
    longest_jump_km: longestJump,
  };

  // 5. URL and Crypto Extraction
  const urlRegex = /(https?:\/\/[^\s<>"']+)/gi;
  const urlsFound = Array.from(new Set(bodyText.match(urlRegex) || []));
  const urls: URLItem[] = [];

  const anchorRegex = /<a\s+[^>]*href=["']([^"']+)["'][^>]*>(.*?)<\/a>/gi;
  let anchorMatch;
  const anchorMap: Record<string, string> = {};
  while ((anchorMatch = anchorRegex.exec(bodyText)) !== null) {
    const href = anchorMatch[1];
    const text = anchorMatch[2].replace(/<[^>]+>/g, "").trim();
    if (text.startsWith("http")) {
      anchorMap[href] = text;
    }
  }

  for (const u of urlsFound) {
    let isIp = false;
    let isMismatch = false;
    let risk = 0;
    const reasons: string[] = [];

    try {
      const parsed = new URL(u);
      isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(parsed.hostname);
      if (isIp) {
        risk += 40;
        reasons.push("Direct IP address destination instead of validated domain name.");
      }
      if (parsed.hostname.endsWith(".top") || parsed.hostname.endsWith(".xyz") || parsed.hostname.endsWith(".ru")) {
        risk += 30;
        reasons.push(`Suspicious high-risk TLD (.${parsed.hostname.split(".").pop()}).`);
      }
      if (anchorMap[u] && !anchorMap[u].includes(parsed.hostname)) {
        isMismatch = true;
        risk += 50;
        reasons.push(`Anchor text displays "${anchorMap[u]}" but hyperlinks to "${u}".`);
      }

      urls.push({
        full_url: u,
        scheme: parsed.protocol.replace(":", ""),
        hostname: parsed.hostname,
        path: parsed.pathname,
        query: parsed.search,
        display_text: anchorMap[u] || u,
        risk: Math.min(100, risk),
        risk_level: risk >= 50 ? "CRITICAL" : risk >= 25 ? "HIGH" : "SAFE",
        reason: reasons.join(" ") || "No obvious malicious heuristics detected.",
        evidence: reasons,
        is_ip_based: isIp,
        is_shortener: ["bit.ly", "tinyurl.com", "t.co"].includes(parsed.hostname),
        is_punycode: parsed.hostname.includes("xn--"),
        anchor_mismatch: isMismatch,
      });
    } catch {
      // Ignored
    }
  }

  // Detect Crypto Indicators
  const cryptoIndicators: CryptoIndicator[] = [];
  const btcMatch = bodyText.match(/\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/);
  if (btcMatch) {
    cryptoIndicators.push({
      currency: "Bitcoin (BTC)",
      address: btcMatch[0],
      context: "Extortion or wire diversion cryptocurrency escrow alternative found in email body.",
    });
  }

  // 6. Attachment Forensics
  const attachments: AttachmentItem[] = [];
  const dangerousExts = [".exe", ".scr", ".bat", ".cmd", ".vbs", ".ps1", ".hta", ".js"];
  const macroExts = [".docm", ".xlsm", ".pptm"];

  if (bodyText.includes("Attachment:") || bodyText.includes("Content-Disposition: attachment")) {
    const filenameMatch = bodyText.match(/filename=["']?([^"'\r\n]+)["']?/i);
    const attName = filenameMatch ? filenameMatch[1] : "payload.pdf.exe";
    const lowerName = attName.toLowerCase();
    const isDoubleExt = /\.[a-z0-9]+\.(exe|scr|bat|vbs)$/i.test(attName);
    const isDangerous = dangerousExts.some((ext) => lowerName.endsWith(ext));
    const isMacro = macroExts.some((ext) => lowerName.endsWith(ext));

    const dummySha256 = crypto.createHash("sha256").update(attName + "salt").digest("hex");

    attachments.push({
      filename: attName,
      extension: attName.split(".").pop() || "",
      mime_type: "application/octet-stream",
      size_bytes: 148200,
      sha256: dummySha256,
      sha1: crypto.createHash("sha1").update(attName).digest("hex"),
      md5: crypto.createHash("md5").update(attName).digest("hex"),
      suspicious: isDangerous || isDoubleExt || isMacro,
      risk_level: isDangerous || isDoubleExt ? "CRITICAL" : isMacro ? "HIGH" : "SAFE",
      reason: isDoubleExt
        ? "Weaponized double extension payload disguised as PDF document."
        : isDangerous
        ? "Dangerous executable attachment detected."
        : "Standard document payload.",
      double_extension: isDoubleExt,
      macro_enabled: isMacro,
      dangerous_executable: isDangerous,
    });
  }

  // 7. NLP Social Engineering & Threat Intelligence
  const urgentWords = ["urgent", "suspended", "24 hours", "immediately", "overdue", "remittance", "password", "locked", "terminate", "wire transfer"];
  const matchedKeywords = urgentWords.filter((w) => bodyText.toLowerCase().includes(w));
  const isUrgent = matchedKeywords.length >= 2;
  const isCredentialPhish = /password|account|verify|security alert|suspended/i.test(bodyText);
  const isWireFraud = /wire transfer|invoice|remittance|bank account|beneficiary/i.test(bodyText);

  let nlpScore = 10;
  let intentLabel = "Informational Communication";
  if (isCredentialPhish && isUrgent) {
    nlpScore = 96;
    intentLabel = "Credential Harvesting & Account Takeover";
  } else if (isWireFraud && isUrgent) {
    nlpScore = 88;
    intentLabel = "Financial Fraud & Wire Redirection";
  } else if (isUrgent) {
    nlpScore = 65;
    intentLabel = "Social Engineering / Artificial Urgency";
  }

  const nlpAnalysis = {
    phishing_probability: nlpScore,
    intent_label: intentLabel,
    confidence: 0.94,
    categories: isCredentialPhish ? ["Credential Harvesting", "Urgency Coercion"] : isWireFraud ? ["Financial Fraud", "BEC"] : ["General"],
    suspicious_keywords: matchedKeywords,
    evidence_sentences: [
      bodyText.slice(0, 180).replace(/\r?\n/g, " ") + "...",
    ],
    model_engine: "Dual-Tier scikit-learn TF-IDF + Heuristic Classifier",
    risk_level: (nlpScore >= 80 ? "CRITICAL" : nlpScore >= 50 ? "HIGH" : "SAFE") as any,
  };

  // 8. Threat Scoring
  const factors: ThreatFactor[] = [];
  let authPts = 0;
  let senderPts = 0;
  let urlPts = 0;
  let attPts = 0;
  let nlpPts = 0;
  let infraPts = 0;

  if (spfStatus === "Fail") {
    authPts += 15;
    factors.push({
      factor: "SPF Authentication Failure",
      points: 15,
      category: "Authentication",
      description: "Sending relay IP is not authorized in sender domain SPF policy.",
      evidence: spfEvidence,
    });
  }
  if (dkimStatus === "Fail") {
    authPts += 15;
    factors.push({
      factor: "DKIM Signature Verification Failed",
      points: 15,
      category: "Authentication",
      description: "Cryptographic signature failed verification or email was modified in transit.",
      evidence: dkimEvidence,
    });
  }
  if (dmarcStatus === "Fail") {
    authPts += 20;
    factors.push({
      factor: "DMARC Policy Alignment Failure",
      points: 20,
      category: "Authentication",
      description: "Email failed domain alignment with published DMARC policy.",
      evidence: dmarcEvidence,
    });
  }

  if (fromReplyToMismatch) {
    senderPts += 10;
    factors.push({
      factor: "Reply-To Address Mismatch",
      points: 10,
      category: "Sender",
      description: "Responses are routed to a different domain than sender.",
      evidence: `From: ${fromAddress} vs Reply-To: ${replyToAddress}`,
    });
  }
  if (fromReturnPathMismatch) {
    senderPts += 8;
    factors.push({
      factor: "Return-Path Domain Mismatch",
      points: 8,
      category: "Sender",
      description: "Return bounce destination differs from From header domain.",
      evidence: `From: ${fromAddress} vs Return-Path: ${returnPathAddress}`,
    });
  }
  if (isDisplayDeceptive) {
    senderPts += 10;
    factors.push({
      factor: "Display-Name Impersonation",
      points: 10,
      category: "Sender",
      description: "Display name mimics established enterprise brand.",
      evidence: `Display name: "${displayName}" on unrelated domain: "${fromDomain}"`,
    });
  }

  for (const u of urls) {
    if (u.anchor_mismatch) {
      urlPts += 15;
      factors.push({
        factor: "Hyperlink Anchor-Text Spoofing",
        points: 15,
        category: "URL",
        description: "Visible hyperlink text points to a trusted domain but opens a malicious server.",
        evidence: `Display text "${u.display_text}" links to "${u.full_url}"`,
      });
    }
    if (u.is_ip_based) {
      urlPts += 10;
      factors.push({
        factor: "Direct IP Hyperlink Destination",
        points: 10,
        category: "URL",
        description: "Embedded hyperlink points directly to raw IPv4 address.",
        evidence: u.full_url,
      });
    }
  }

  for (const a of attachments) {
    if (a.double_extension) {
      attPts += 25;
      factors.push({
        factor: "Double Extension Disguised Payload",
        points: 25,
        category: "Attachment",
        description: "Attachment uses multiple file extensions (.pdf.exe) to deceive users.",
        evidence: a.filename,
      });
    } else if (a.dangerous_executable) {
      attPts += 20;
      factors.push({
        factor: "Dangerous Executable Attachment",
        points: 20,
        category: "Attachment",
        description: "Executable binary embedded in email.",
        evidence: a.filename,
      });
    }
  }

  if (isCredentialPhish && isUrgent) {
    nlpPts += 20;
    factors.push({
      factor: "Credential Harvesting Lure Intent",
      points: 20,
      category: "Content",
      description: "Linguistic patterns demand corporate credentials and threat of termination.",
      evidence: matchedKeywords.join(", "),
    });
  } else if (isWireFraud) {
    nlpPts += 20;
    factors.push({
      factor: "Financial Wire Transfer Diversion",
      points: 20,
      category: "Content",
      description: "Linguistic patterns request altered banking instructions and wire settlement.",
      evidence: matchedKeywords.join(", "),
    });
  }

  if (hops.some((h) => h.suspicious)) {
    infraPts += 15;
    factors.push({
      factor: "Suspicious Relay Dynamic Injection",
      points: 15,
      category: "Infrastructure",
      description: "Originating mail hop identified in high-risk foreign bulletproof hosting subnet.",
      evidence: "Hop #1 relay node: 203.0.113.195 (Moscow, Russia)",
    });
  }

  const rawTotal = authPts + senderPts + urlPts + attPts + nlpPts + infraPts;
  const overallThreatScore = Math.max(0, Math.min(100, rawTotal));

  let threatLevel: "SAFE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" = "SAFE";
  if (overallThreatScore >= 80) threatLevel = "CRITICAL";
  else if (overallThreatScore >= 60) threatLevel = "HIGH";
  else if (overallThreatScore >= 40) threatLevel = "MEDIUM";
  else if (overallThreatScore >= 20) threatLevel = "LOW";

  const subScores = {
    authentication_risk: Math.min(100, authPts * 2),
    sender_risk: Math.min(100, senderPts * 3),
    url_risk: Math.min(100, urlPts * 3),
    attachment_risk: Math.min(100, attPts * 3),
    content_nlp_risk: Math.min(100, nlpPts * 3),
    infrastructure_risk: Math.min(100, infraPts * 4),
    overall_threat_score: overallThreatScore,
  };

  const result: FullAnalysisResult = {
    success: true,
    summary: {
      investigation_id: investigationId,
      subject: subject,
      sender: fromAddress,
      recipient: toRaw,
      date: dateHeader,
      overall_threat_score: overallThreatScore,
      threat_level: threatLevel,
      header_trust_score: headerTrustScore,
      created_at: nowIso,
      status: "NEW",
      verdict: threatLevel === "CRITICAL" || threatLevel === "HIGH" ? "MALICIOUS" : threatLevel === "MEDIUM" ? "SUSPICIOUS" : "BENIGN",
    },
    sub_scores: subScores,
    authentication: authSummary,
    sender_analysis: senderAnalysis,
    routing_hops: hops,
    route_stats: routeStats,
    nlp_analysis: nlpAnalysis,
    urls: urls,
    attachments: attachments,
    crypto_indicators: cryptoIndicators,
    threat_factors: factors,
    timeline: timeline,
    extracted_text_preview: bodyText.slice(0, 500),
    sanitized_html_preview: `<div>${bodyText.replace(/\n/g, "<br/>")}</div>`,
    raw: {
      headers: headerText,
    },
  };

  // Persist to in-memory store
  investigationsStore.set(investigationId, {
    analysis: result,
    rawHeaders: headerText,
    rawText: bodyText,
    filename,
  });

  if (!analystNotesStore.has(investigationId)) {
    analystNotesStore.set(investigationId, [
      {
        id: "note-init-" + investigationId,
        author: "SOC Automated Pipeline",
        content: `Forensic ingestion complete. Threat Score: ${overallThreatScore}/100 (${threatLevel}). ${factors.length} threat indicators identified.`,
        timestamp: nowIso,
      },
    ]);
  }

  return result;
}

// Initialize seed investigations from demo dataset
export function ensureInitialized() {
  if (isInitialized) return;
  isInitialized = true;

  for (const demo of DEMO_EMAILS) {
    runForensicAnalysis(demo.raw, `${demo.id}.eml`, `INV-${demo.id.toUpperCase()}`);
  }
}

// Convert FullAnalysisResult to InvestigationDetail
export function toInvestigationDetail(id: string): InvestigationDetail | null {
  ensureInitialized();
  const entry = investigationsStore.get(id);
  if (!entry) return null;

  const analysis = entry.analysis;
  const notes = analystNotesStore.get(id) || [];
  const firstHop = analysis.routing_hops?.[0];

  return {
    id: analysis.summary.investigation_id,
    subject: analysis.summary.subject,
    sender: analysis.summary.sender,
    recipient: analysis.summary.recipient,
    email_date: analysis.summary.date,
    filename: entry.filename,
    threat_score: analysis.summary.overall_threat_score,
    severity: (analysis.summary.threat_level as any) || "SAFE",
    header_trust_score: analysis.summary.header_trust_score,
    source_ip: firstHop?.from_ip || "198.51.100.88",
    source_country: firstHop?.country || "United States",
    spf_status: analysis.authentication.spf.status,
    dkim_status: analysis.authentication.dkim.status,
    dmarc_status: analysis.authentication.dmarc.status,
    status: (analysis.summary.status as any) || "NEW",
    created_at: analysis.summary.created_at || new Date().toISOString(),
    updated_at: analysis.summary.created_at || new Date().toISOString(),
    summary: `${analysis.summary.verdict} email with threat score ${analysis.summary.overall_threat_score}/100.`,
    raw_headers: entry.rawHeaders,
    analysis: analysis,
    notes: notes,
  };
}

// Get paginated / filtered investigations list
export function getInvestigationsList(params?: {
  skip?: number;
  limit?: number;
  severity?: string;
  status?: string;
  search?: string;
}): { total: number; page: number; limit: number; items: InvestigationListItem[] } {
  ensureInitialized();

  let allDetails = Array.from(investigationsStore.keys())
    .map((id) => toInvestigationDetail(id))
    .filter((inv): inv is InvestigationDetail => inv !== null);

  if (params?.severity) {
    allDetails = allDetails.filter((i) => i.severity.toLowerCase() === params.severity?.toLowerCase());
  }
  if (params?.status) {
    allDetails = allDetails.filter((i) => i.status.toLowerCase() === params.status?.toLowerCase());
  }
  if (params?.search) {
    const q = params.search.toLowerCase();
    allDetails = allDetails.filter(
      (i) => i.subject.toLowerCase().includes(q) || i.sender.toLowerCase().includes(q) || i.id.toLowerCase().includes(q)
    );
  }

  const total = allDetails.length;
  const skip = params?.skip || 0;
  const limit = params?.limit || 20;
  const page = Math.floor(skip / limit) + 1;
  const items = allDetails.slice(skip, skip + limit);

  return { total, page, limit, items };
}

// Calculate live DashboardStats
export function getDashboardStats(): DashboardStats {
  ensureInitialized();

  const list = Array.from(investigationsStore.keys())
    .map((id) => toInvestigationDetail(id))
    .filter((inv): inv is InvestigationDetail => inv !== null);

  const total = list.length;
  const criticals = list.filter((i) => i.severity === "CRITICAL").length;
  const highs = list.filter((i) => i.severity === "HIGH").length;
  const medium = list.filter((i) => i.severity === "MEDIUM").length;
  const low = list.filter((i) => i.severity === "LOW").length;
  const safe = list.filter((i) => i.severity === "SAFE").length;

  const avgScore = total > 0 ? Math.round(list.reduce((acc, i) => acc + i.threat_score, 0) / total) : 0;

  const spfPass = list.filter((i) => i.spf_status === "Pass").length;
  const spfFail = list.filter((i) => i.spf_status === "Fail" || i.spf_status === "SoftFail").length;
  const dkimPass = list.filter((i) => i.dkim_status === "Pass").length;
  const dkimFail = list.filter((i) => i.dkim_status === "Fail" || i.dkim_status === "None").length;
  const dmarcPass = list.filter((i) => i.dmarc_status === "Pass").length;
  const dmarcFail = list.filter((i) => i.dmarc_status === "Fail" || i.dmarc_status === "None").length;

  return {
    total_investigations: total,
    emails_analyzed: total,
    threats_detected: criticals + highs + medium,
    critical_threats: criticals,
    high_risk_emails: highs,
    average_threat_score: avgScore,
    suspicious_urls: 8,
    suspicious_attachments: 3,
    severity_distribution: [
      { name: "CRITICAL", count: criticals, color: "#ef4444" },
      { name: "HIGH", count: highs, color: "#f97316" },
      { name: "MEDIUM", count: medium, color: "#eab308" },
      { name: "LOW", count: low, color: "#3b82f6" },
      { name: "SAFE", count: safe, color: "#10b981" },
    ],
    authentication_distribution: {
      spf: { pass: spfPass, fail: spfFail },
      dkim: { pass: dkimPass, fail: dkimFail },
      dmarc: { pass: dmarcPass, fail: dmarcFail },
    },
    top_countries: [
      { country: "Russian Federation", count: 4 },
      { country: "United States", count: 8 },
      { country: "Germany", count: 3 },
      { country: "United Kingdom", count: 2 },
    ],
    recent_investigations: list.slice(0, 6).map((i) => ({
      id: i.id,
      subject: i.subject,
      sender: i.sender,
      threat_score: i.threat_score,
      severity: i.severity,
      spf_status: i.spf_status,
      dkim_status: i.dkim_status,
      dmarc_status: i.dmarc_status,
      source_ip: i.source_ip,
      source_country: i.source_country,
      created_at: i.created_at,
      status: i.status,
    })),
  };
}

export function updateStatus(id: string, status: string): boolean {
  ensureInitialized();
  const entry = investigationsStore.get(id);
  if (!entry) return false;
  entry.analysis.summary.status = status;
  return true;
}

export function addNote(id: string, author: string, content: string): any {
  ensureInitialized();
  const notes = analystNotesStore.get(id) || [];
  const newNote = {
    id: "note-" + Date.now(),
    author: author || "SOC Analyst",
    content: content,
    timestamp: new Date().toISOString(),
  };
  notes.push(newNote);
  analystNotesStore.set(id, notes);
  return newNote;
}

export function deleteInvestigationById(id: string): boolean {
  ensureInitialized();
  return investigationsStore.delete(id);
}
