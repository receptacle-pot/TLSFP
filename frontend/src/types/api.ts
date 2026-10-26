export type Verdict = 'benign' | 'suspicious' | 'malicious' | 'unknown';
export type Severity = 'low' | 'medium' | 'high' | 'critical';

export type EventKind =
  | 'client_hello'
  | 'server_hello'
  | 'certificate'
  | 'http_request'
  | 'tcp_syn'
  | 'tcp_syn_ack';

export interface BaseEvent {
  ts_nanos: number;
  src: string;
  dst: string;
}

export interface ClientHelloEvent extends BaseEvent {
  kind: 'client_hello';
  ja3: string;
  ja3_raw: string;
  ja4: { hash: string; raw?: string };
  sni?: string;
  alpn?: string;
}

export interface ServerHelloEvent extends BaseEvent {
  kind: 'server_hello';
  ja3s: string;
  ja3s_raw: string;
  ja4s: { hash: string; raw?: string };
}

export interface CertificateEvent extends BaseEvent {
  kind: 'certificate';
  ja4x: string;
}

export interface HttpRequestEvent extends BaseEvent {
  kind: 'http_request';
  ja4h: { hash: string; raw?: string };
  method: string;
  host?: string;
  user_agent?: string;
}

export interface TcpSynEvent extends BaseEvent {
  kind: 'tcp_syn';
  ja4t: string;
}

export interface TcpSynAckEvent extends BaseEvent {
  kind: 'tcp_syn_ack';
  ja4ts: string;
}

export type TlsEvent =
  | ClientHelloEvent
  | ServerHelloEvent
  | CertificateEvent
  | HttpRequestEvent
  | TcpSynEvent
  | TcpSynAckEvent;

export interface IntelHit {
  kind: string;
  value: string;
  label: string;
  category: string;
  source: string;
  reference?: string;
  strength: number;
}

export interface IntelMatch {
  kind: string;
  observed: string;
  verdict: Verdict;
  threat_score: number;
  confidence: number;
  hits: IntelHit[];
}

export interface Alert {
  id?: string;
  ts_nanos: number;
  rule: string;
  severity: Severity;
  ip?: string;
  fp_kind?: string;
  fp_value?: string;
  title: string;
  detail: string;
  score?: number;
  evidence?: string;
  investigation_steps?: string[];
}

export interface FlowMessage {
  type: 'flow';
  event: TlsEvent;
  intel?: IntelMatch;
  alerts?: Alert[];
}

export interface AlertMessage {
  type: 'alert';
  alert: Alert;
}

export type StreamMessage = FlowMessage | AlertMessage;

export interface FeedItem {
  seq: number;
  message: StreamMessage;
}

export interface IntelSource {
  name: string;
  kind: string;
  license?: string;
  records: number;
}

export interface CategoryStat {
  category: string;
  records: number;
}

export interface RuleStat {
  rule: string;
  count: number;
}

export interface StatsResponse {
  intel: {
    sources: IntelSource[];
    by_category: CategoryStat[];
    total: number;
  };
  alerts_by_rule: RuleStat[];
  alert_total: number;
  flow_total?: number;
  unique_ja3?: number;
  unique_ja4?: number;
}

export interface CorpusSearchItem {
  kind: string;
  value: string;
  label: string;
  category: string;
  source: string;
  reference?: string;
}

export interface PcapJob {
  id: string;
  filename: string;
  file_size: number;
  status: 'pending' | 'processing' | 'completed' | 'failed';
  packet_count: number;
  handshake_count: number;
  created_at: string;
  completed_at?: string;
  error?: string;
}
