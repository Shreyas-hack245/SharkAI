export interface CaptureSummary {
  id: string;
  filename: string;
  original_name: string;
  file_size: number;
  status: string;
  progress: number;
  packet_count: number;
  tcp_streams: number;
  http_sessions: number;
  dns_queries: number;
  files_count: number;
  findings_count: number;
  flags_count: number;
  iocs_count: number;
  summary?: Record<string, unknown>;
  created_at?: string;
  analyzed_at?: string;
}

export interface PacketRow {
  id: number;
  frame_number: number;
  timestamp: number;
  src: string;
  dst: string;
  protocol: string;
  length: number;
  info: string;
  stream?: number;
  severity: string;
}

export interface PacketDetail {
  frame_number: number;
  timestamp: number;
  layers: LayerNode[];
  hex_dump: string;
  ascii_dump: string;
}

export interface LayerNode {
  name: string;
  fields: Record<string, unknown>;
  children?: LayerNode[];
}

export interface StreamInfo {
  stream_id: number;
  protocol: string;
  src: string;
  dst: string;
  src_port: number;
  dst_port: number;
  packets: number;
  bytes: number;
  first_seen: number;
  last_seen: number;
}

export interface FlagFinding {
  flag: string;
  pattern: string;
  protocol: string;
  stream_id?: number;
  packet_numbers?: number[];
  confidence: number;
  decode_chain?: string[];
  context?: string;
}

export interface Finding {
  id: string;
  title: string;
  severity: string;
  confidence: number;
  category: string;
  description: string;
  evidence: Record<string, unknown>[];
  fact?: string;
  inference?: string;
}

export interface InvestigationResult {
  id?: string;
  query: string;
  response: string;
  evidence: Record<string, unknown>[];
  filter_applied?: string;
  intent?: Record<string, unknown>;
  status: string;
}

export interface ProgressUpdate {
  type: string;
  progress?: number;
  message?: string;
  step?: string;
  tool?: string;
  packet_count?: number;
  tcp_streams?: number;
  http_sessions?: number;
  dns_queries?: number;
  files_count?: number;
  findings_count?: number;
}

export type SidebarView =
  | 'overview'
  | 'packets'
  | 'conversations'
  | 'streams'
  | 'http'
  | 'dns'
  | 'files'
  | 'credentials'
  | 'flags'
  | 'iocs'
  | 'timeline'
  | 'graph';
