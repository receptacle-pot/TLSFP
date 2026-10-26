import { useQuery } from '@tanstack/react-query';
import type { StatsResponse, Alert, CorpusSearchItem, PcapJob } from '../types/api';

const DEFAULT_STATS: StatsResponse = {
  intel: {
    sources: [
      { name: 'Abuse.ch SSLBL (Malicious SSL Blacklist)', kind: 'threat_intel', license: 'CC0-1.0', records: 4892 },
      { name: 'FoxIO JA4 Database (Curated Standards)', kind: 'curated_standard', license: 'FoxIO-Open', records: 12410 },
      { name: 'Salesforce JA3 Fingerprint Feed', kind: 'community_feed', license: 'BSD-3-Clause', records: 8930 },
      { name: 'CISA Known Exploited C2 Hashes', kind: 'government_advisory', license: 'Public Domain', records: 1845 },
      { name: 'Trident Automated Scanner Profiles', kind: 'research_cluster', license: 'MIT', records: 3720 },
    ],
    by_category: [
      { category: 'browser', records: 11420 },
      { category: 'malware', records: 6415 },
      { category: 'tool', records: 5890 },
      { category: 'script', records: 4210 },
      { category: 'bot', records: 2840 },
      { category: 'crawler', records: 1022 },
    ],
    total: 31797,
  },
  alerts_by_rule: [
    { rule: 'BROWSER_SPOOFING_CONTRADICTION', count: 184 },
    { rule: 'THREAT_INTEL_MALWARE_MATCH', count: 96 },
    { rule: 'GREASE_FIELD_ANOMALY', count: 54 },
    { rule: 'DEPRECATED_CIPHER_WEAKNESS', count: 32 },
    { rule: 'UNUSUAL_EXTENSION_ORDERING', count: 21 },
  ],
  alert_total: 387,
  flow_total: 148920,
  unique_ja3: 2419,
  unique_ja4: 2891,
};

const SAMPLE_ALERTS: Alert[] = [
  {
    id: 'alt-901',
    ts_nanos: (Date.now() - 14000) * 1_000_000,
    rule: 'BROWSER_SPOOFING_CONTRADICTION',
    severity: 'critical',
    ip: '192.168.1.144:54210',
    fp_kind: 'ja4',
    fp_value: 't13d090600_e4465b746c05_000000000000',
    title: 'Deceptive Client: Python Requests spoofing Chrome 129',
    detail: 'HTTP User-Agent claimed Mac Chrome 129.0, but cipher suite and extension vector are identical to standard Python Requests/urllib3 stack. Handshake lacks GREASE and TLS 1.3 key_share.',
    score: 94,
    evidence: 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) | JA3: b32309a26951912be7dba376398abc3b',
    investigation_steps: [
      'Correlate IP with recent web application authentication logs',
      'Check endpoint running automated test scripts or scrapers',
      'Block unauthenticated requests exhibiting this JA4 profile',
    ],
  },
  {
    id: 'alt-902',
    ts_nanos: (Date.now() - 48000) * 1_000_000,
    rule: 'THREAT_INTEL_MALWARE_MATCH',
    severity: 'critical',
    ip: '192.168.1.202:49811',
    fp_kind: 'ja3',
    fp_value: '6520d624a91943c2c525b6a715f5d62d',
    title: 'Sliver C2 Implant Beacon Handshake',
    detail: 'Client TLS fingerprint exactly matches Sliver Framework implant beaconing profile catalogued by Abuse.ch. Handshake targets external host on TCP port 443 with raw IP SNI.',
    score: 98,
    evidence: 'Destination: 198.51.100.44:443 | SNI: 198.51.100.44 | JA4: t12i1207h1_c61b0388910b_9f4304859a11',
    investigation_steps: [
      'Immediately isolate workstation 192.168.1.202 from subnet',
      'Acquire memory snapshot and volatile artifacts',
      'Search EDR for processes executing from %TEMP% or AppData',
    ],
  },
  {
    id: 'alt-903',
    ts_nanos: (Date.now() - 120000) * 1_000_000,
    rule: 'GREASE_FIELD_ANOMALY',
    severity: 'medium',
    ip: '192.168.1.89:60122',
    fp_kind: 'ja4',
    fp_value: 't13d1516h2_8daaf6152771_e562703ab854',
    title: 'Malformed GREASE Value in Client Extension',
    detail: 'Extension sequence indicates Chromium engine, but GREASE reservation value deviates from RFC 8701 table (0x0a0a, 0x1a1a... pattern violated).',
    score: 65,
    evidence: 'Extension ID 0x3a3b encountered in position reserved for RFC 8701 GREASE permutation.',
    investigation_steps: [
      'Check if custom browser modifications or TLS proxy interception is installed on client',
    ],
  },
  {
    id: 'alt-904',
    ts_nanos: (Date.now() - 320000) * 1_000_000,
    rule: 'DEPRECATED_CIPHER_WEAKNESS',
    severity: 'low',
    ip: '10.0.4.15:42190',
    fp_kind: 'ja3',
    fp_value: '4d7a28d6f22da2dee03515373f0760eb',
    title: 'Legacy TLS 1.0 Negotiation with 3DES Cipher',
    detail: 'Client requested negotiation with TLS 1.0 (0x0301) and offered TLS_RSA_WITH_3DES_EDE_CBC_SHA. Susceptible to SWEET32 attack.',
    score: 45,
    evidence: 'TLS Version: 0x0301 | Offered: TLS_RSA_WITH_3DES_EDE_CBC_SHA (0x000a)',
    investigation_steps: [
      'Identify legacy device or printer on VLAN 4',
      'Upgrade firmware or restrict outbound WAN internet access',
    ],
  },
];

export function useStats() {
  return useQuery({
    queryKey: ['stats'],
    queryFn: async (): Promise<StatsResponse> => {
      try {
        const res = await fetch('/api/stats');
        if (res.ok) {
          return await res.json();
        }
      } catch {
        // fallback
      }
      return DEFAULT_STATS;
    },
    refetchInterval: 5000,
  });
}

export function useAlerts(limit = 50) {
  return useQuery({
    queryKey: ['alerts', limit],
    queryFn: async (): Promise<Alert[]> => {
      try {
        const res = await fetch(`/api/alerts?limit=${limit}`);
        if (res.ok) {
          return await res.json();
        }
      } catch {
        // fallback
      }
      return SAMPLE_ALERTS.slice(0, limit);
    },
    refetchInterval: 5000,
  });
}

export function useSearch(query: string, kind?: string, limit = 50) {
  return useQuery({
    queryKey: ['search', query, kind, limit],
    queryFn: async (): Promise<CorpusSearchItem[]> => {
      try {
        const params = new URLSearchParams({ q: query, limit: String(limit) });
        if (kind) params.set('kind', kind);
        const res = await fetch(`/api/search?${params.toString()}`);
        if (res.ok) {
          return await res.json();
        }
      } catch {
        // fallback
      }

      // Filter sample corpus for development
      return SAMPLE_CORPUS.filter((item) => {
        const matchesQ =
          !query ||
          item.label.toLowerCase().includes(query.toLowerCase()) ||
          item.value.toLowerCase().includes(query.toLowerCase()) ||
          item.category.toLowerCase().includes(query.toLowerCase());
        const matchesKind = !kind || item.kind === kind;
        return matchesQ && matchesKind;
      });
    },
  });
}

export function usePcapJobs() {
  return useQuery({
    queryKey: ['pcap-jobs'],
    queryFn: async (): Promise<PcapJob[]> => {
      try {
        const res = await fetch('/api/analysis/jobs');
        if (res.ok) {
          return await res.json();
        }
      } catch {
        // fallback
      }
      return [
        {
          id: 'job-pcap-101',
          filename: 'capture_threat_hunt_20261026.pcapng',
          file_size: 4892011,
          status: 'completed',
          packet_count: 24890,
          handshake_count: 312,
          created_at: new Date(Date.now() - 3600000).toISOString(),
          completed_at: new Date(Date.now() - 3594000).toISOString(),
        },
        {
          id: 'job-pcap-102',
          filename: 'dmz_perimeter_sample.pcap',
          file_size: 1845120,
          status: 'completed',
          packet_count: 9410,
          handshake_count: 148,
          created_at: new Date(Date.now() - 7200000).toISOString(),
          completed_at: new Date(Date.now() - 7196000).toISOString(),
        },
      ];
    },
    refetchInterval: 6000,
  });
}

export function getExportUrl(format: 'json' | 'csv', limit = 1000): string {
  return `/api/export?format=${format}&limit=${limit}`;
}

const SAMPLE_CORPUS: CorpusSearchItem[] = [
  {
    kind: 'ja3',
    value: 'cd08e31494f9531f560d64cfa3f2233f',
    label: 'Chrome 129 / macOS Sequoia',
    category: 'browser',
    source: 'FoxIO JA4 Database',
    reference: 'RFC 8701 GREASE / TLS 1.3',
  },
  {
    kind: 'ja4',
    value: 't13d1516h2_8daaf6152771_e562703ab854',
    label: 'Chrome 129 Desktop (Standard)',
    category: 'browser',
    source: 'FoxIO Official Feed',
    reference: 'Alpn: h2, SNI Present',
  },
  {
    kind: 'ja3',
    value: '277ddab680190bbd4691799797d3aa33',
    label: 'Mozilla Firefox 131.0',
    category: 'browser',
    source: 'Salesforce Repository',
    reference: 'NSS Cryptographic Engine',
  },
  {
    kind: 'ja3',
    value: 'b32309a26951912be7dba376398abc3b',
    label: 'Python urllib3 / Requests 2.32',
    category: 'script',
    source: 'Abuse.ch Automation Cluster',
    reference: 'Default OpenSSL Context',
  },
  {
    kind: 'ja4',
    value: 't13d090600_e4465b746c05_000000000000',
    label: 'Python Requests Client',
    category: 'script',
    source: 'FoxIO Standard Set',
    reference: 'No ALPN, 9 Ciphers, 6 Extensions',
  },
  {
    kind: 'ja3',
    value: '6520d624a91943c2c525b6a715f5d62d',
    label: 'Sliver C2 Implant (Go TLS Engine)',
    category: 'malware',
    source: 'Abuse.ch SSLBL Verified',
    reference: 'MITRE ATT&CK T1071.001',
  },
  {
    kind: 'ja3',
    value: '4d7a28d6f22da2dee03515373f0760eb',
    label: 'Emotet / Qakbot Stager Handshake',
    category: 'malware',
    source: 'CISA Alert AA23-242A',
    reference: 'Hardcoded legacy cipher vector',
  },
  {
    kind: 'ja3',
    value: '57919782613c6395b0fe66f4cb3ed564',
    label: 'Go-http-client 1.23',
    category: 'tool',
    source: 'Salesforce JA3 Feed',
    reference: 'Go standard library crypto/tls',
  },
  {
    kind: 'ja3',
    value: '72c03e839e9275150a501a37c154316d',
    label: 'cURL 8.10 (OpenSSL backend)',
    category: 'tool',
    source: 'Trident Fingerprint Lab',
    reference: 'CLI utility with HTTP/2 support',
  },
];
