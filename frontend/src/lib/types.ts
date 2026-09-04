export interface AuthResultItem {
  status: "Pass" | "Fail" | "None" | "Unknown" | string;
  evidence: string;
  details?: Record<string, any>;
}

export interface AuthenticationSummary {
  spf: AuthResultItem;
  dkim: AuthResultItem;
  dmarc: AuthResultItem;
  header_trust_score: number;
  evidence_notes?: string[];
}

export interface SenderAnalysis {
  from_header: string;
  display_name: string;
  from_address: string;
  from_domain: string;
  reply_to: string;
  return_path: string;
  sender: string;
  from_reply_to_mismatch: boolean;
  from_return_path_mismatch: boolean;
  display_name_deception: boolean;
  is_punycode: boolean;
  is_free_provider: boolean;
  suspicious_domain_patterns: string[];
  risk_level: "SAFE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  evidence: string[];
}

export interface RoutingHop {
  hop_number: number;
  timestamp?: string;
  from_hostname: string;
  from_ip: string;
  by_hostname: string;
  by_ip: string;
  ip_classification: string;
  is_public: boolean;
  country: string;
  city: string;
  region: string;
  latitude?: number | null;
  longitude?: number | null;
  isp: string;
  organization: string;
  asn: string;
  ordering_confidence: "High" | "Medium" | "Low";
  suspicious: boolean;
  evidence: string;
  provider_status: "active" | "local_heuristic" | "demo_intelligence" | "unavailable" | "local_classification";
}

export interface RouteStats {
  total_hops: number;
  public_hops: number;
  countries_traversed: string[];
  unique_asns: string[];
  approximate_distance_km: number;
  longest_jump_km: number;
}

export interface URLItem {
  full_url: string;
  scheme: string;
  hostname: string;
  port?: number | null;
  path: string;
  query: string;
  display_text: string;
  risk: number;
  risk_level: "SAFE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  reason: string;
  evidence: string[];
  is_ip_based: boolean;
  is_shortener: boolean;
  is_punycode: boolean;
  anchor_mismatch: boolean;
}

export interface AttachmentItem {
  filename: string;
  extension: string;
  mime_type: string;
  size_bytes: number;
  sha256: string;
  sha1?: string;
  md5?: string;
  suspicious: boolean;
  risk_level: "SAFE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  reason: string;
  double_extension: boolean;
  macro_enabled: boolean;
  dangerous_executable: boolean;
}

export interface NLPAnalysis {
  phishing_probability: number;
  intent_label: string;
  confidence: number;
  categories: string[];
  suspicious_keywords: string[];
  evidence_sentences: string[];
  model_engine: string;
  risk_level: "SAFE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
}

export interface ThreatFactor {
  factor: string;
  points: number;
  category: "Authentication" | "Sender" | "URL" | "Attachment" | "Content" | "Infrastructure" | string;
  description: string;
  evidence: string;
}

export interface TimelineEvent {
  timestamp: string;
  event_type: string;
  title: string;
  description: string;
  source: string;
}

export interface CryptoIndicator {
  currency: string;
  address: string;
  context: string;
}

export interface SubScores {
  authentication_risk: number;
  sender_risk: number;
  url_risk: number;
  attachment_risk: number;
  content_nlp_risk: number;
  infrastructure_risk: number;
  overall_threat_score: number;
}

export interface AnalysisSummary {
  investigation_id: string;
  subject: string;
  sender: string;
  recipient: string;
  date: string;
  overall_threat_score: number;
  threat_level: "SAFE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | string;
  header_trust_score: number;
  verdict: string;
}

export interface FullAnalysisResult {
  success: boolean;
  summary: AnalysisSummary;
  sub_scores: SubScores;
  authentication: AuthenticationSummary;
  sender_analysis: SenderAnalysis;
  routing_hops: RoutingHop[];
  route_stats: RouteStats;
  nlp_analysis: NLPAnalysis;
  urls: URLItem[];
  attachments: AttachmentItem[];
  crypto_indicators: CryptoIndicator[];
  threat_factors: ThreatFactor[];
  timeline: TimelineEvent[];
  extracted_text_preview: string;
  sanitized_html_preview: string;
  raw: {
    headers: string;
  };
}

export interface AnalystNote {
  id: string;
  timestamp: string;
  author: string;
  content: string;
}

export interface InvestigationListItem {
  id: string;
  subject: string;
  sender: string;
  recipient: string;
  email_date: string;
  filename: string;
  threat_score: number;
  severity: "SAFE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  header_trust_score: number;
  source_ip: string;
  source_country: string;
  spf_status: string;
  dkim_status: string;
  dmarc_status: string;
  status: "NEW" | "IN_PROGRESS" | "REVIEWED" | "ESCALATED" | "CLOSED";
  created_at: string;
  updated_at: string;
}

export interface InvestigationDetail extends InvestigationListItem {
  summary: string;
  raw_headers: string;
  analysis: FullAnalysisResult;
  notes: AnalystNote[];
}

export interface DashboardStats {
  total_investigations: number;
  emails_analyzed: number;
  threats_detected: number;
  critical_threats: number;
  high_risk_emails: number;
  average_threat_score: number;
  suspicious_urls: number;
  suspicious_attachments: number;
  severity_distribution: { name: string; count: number; color: string }[];
  authentication_distribution: {
    spf: { pass: number; fail: number };
    dkim: { pass: number; fail: number };
    dmarc: { pass: number; fail: number };
  };
  top_countries: { country: string; count: number }[];
  recent_investigations: {
    id: string;
    subject: string;
    sender: string;
    threat_score: number;
    severity: string;
    spf_status: string;
    dkim_status: string;
    dmarc_status: string;
    source_ip: string;
    source_country: string;
    created_at: string;
    status: string;
  }[];
}
