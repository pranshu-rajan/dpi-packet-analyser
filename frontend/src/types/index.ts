export interface FilterRule {
  id: string;
  type: 'ip' | 'app' | 'domain';
  value: string;
  enabled: boolean;
  description?: string;
}

export interface SummaryStats {
  total_packets: number;
  total_bytes: number;
  tcp_packets: number;
  udp_packets: number;
  forwarded: number;
  dropped: number;
}

export interface ThreadInfo {
  id: number;
  dispatched?: number;
  processed?: number;
}

export interface ThreadStats {
  lbs: ThreadInfo[];
  fps: ThreadInfo[];
}

export interface ApplicationBreakdown {
  name: string;
  count: number;
  percentage: number;
}

export interface DetectedSNI {
  sni: string;
  app: string;
}

export interface ThreatIndicator {
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  category: string;
  title: string;
  description: string;
  affected_count: number;
  suggested_action?: string;
}

export interface AnalysisResponse {
  analysis_id: string;
  filename: string;
  file_size_bytes: number;
  timestamp: string;
  summary: SummaryStats;
  thread_stats: ThreadStats;
  applications: ApplicationBreakdown[];
  detected_snis: DetectedSNI[];
  threat_score: number;
  threat_indicators: ThreatIndicator[];
  active_rules: FilterRule[];
  output_pcap_name?: string;
  output_pcap_download_url?: string;
}

export interface PacketSummary {
  id: number;
  timestamp: number;
  timestamp_str: string;
  length: number;
  src_mac: string;
  dst_mac: string;
  src_ip: string;
  dst_ip: string;
  src_port?: number;
  dst_port?: number;
  protocol: string;
  app: string;
  sni?: string;
  flags?: string;
  status: 'forwarded' | 'dropped';
  info: string;
}

export interface HexDumpLine {
  offset: string;
  hex: string;
  ascii: string;
}

export interface PacketDetail {
  summary: PacketSummary;
  layers: Record<string, any>;
  hex_dump: HexDumpLine[];
  raw_len: number;
}

export interface ChatMessage {
  role: 'user' | 'assistant' | 'system';
  content: string;
}
