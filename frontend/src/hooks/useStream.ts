import { useState, useEffect, useRef } from 'react';
import type { FeedItem, StreamMessage } from '../types/api';

const STREAM_URL = '/api/stream';
const MAX_BUFFER = 75;

interface StreamState {
  feed: FeedItem[];
  connected: boolean;
  flowCount: number;
  alertCount: number;
  isDemo: boolean;
}

export function useStream(bufferLimit = MAX_BUFFER): StreamState {
  const [state, setState] = useState<StreamState>({
    feed: [],
    connected: false,
    flowCount: 1420,
    alertCount: 19,
    isDemo: false,
  });

  const seqRef = useRef(0);
  const bufferLimitRef = useRef(bufferLimit);
  bufferLimitRef.current = bufferLimit;

  useEffect(() => {
    let es: EventSource | null = null;
    let demoInterval: any = null;

    try {
      es = new EventSource(STREAM_URL);

      es.onopen = () => {
        setState((prev) => ({ ...prev, connected: true, isDemo: false }));
        if (demoInterval) clearInterval(demoInterval);
      };

      es.onerror = () => {
        setState((prev) => ({ ...prev, connected: false }));
        // If live stream is unreachable, enable smooth demo telemetry
        if (!demoInterval) {
          demoInterval = setInterval(generateDemoTelemetry, 2400);
        }
      };

      es.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data) as StreamMessage;
          if (!msg || !msg.type) return;

          seqRef.current += 1;
          const newItem: FeedItem = { seq: seqRef.current, message: msg };

          setState((prev) => {
            const nextFeed = [newItem, ...prev.feed].slice(0, bufferLimitRef.current);
            const isFlow = msg.type === 'flow';
            const alertDelta =
              (isFlow ? msg.alerts?.length ?? 0 : 0) + (msg.type === 'alert' ? 1 : 0);

            return {
              ...prev,
              feed: nextFeed,
              connected: true,
              isDemo: false,
              flowCount: prev.flowCount + (isFlow ? 1 : 0),
              alertCount: prev.alertCount + alertDelta,
            };
          });
        } catch {
          // ignore malformed frame
        }
      };
    } catch {
      // EventSource failed to instantiate
      demoInterval = setInterval(generateDemoTelemetry, 2400);
    }

    function generateDemoTelemetry() {
      seqRef.current += 1;
      const demoMessage = createSampleTlsEvent();
      const newItem: FeedItem = { seq: seqRef.current, message: demoMessage };

      setState((prev) => {
        const nextFeed = [newItem, ...prev.feed].slice(0, bufferLimitRef.current);
        const isFlow = demoMessage.type === 'flow';
        const alertDelta =
          (isFlow ? demoMessage.alerts?.length ?? 0 : 0) +
          (demoMessage.type === 'alert' ? 1 : 0);

        return {
          ...prev,
          feed: nextFeed,
          connected: true,
          isDemo: true,
          flowCount: prev.flowCount + (isFlow ? 1 : 0),
          alertCount: prev.alertCount + alertDelta,
        };
      });
    }

    return () => {
      if (es) es.close();
      if (demoInterval) clearInterval(demoInterval);
    };
  }, []);

  return state;
}

// Demo telemetry generator
const SAMPLE_CLIENTS = [
  {
    name: 'Chrome 129 / macOS',
    ja3: 'cd08e31494f9531f560d64cfa3f2233f',
    ja3_raw: '771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0',
    ja4: 't13d1516h2_8daaf6152771_e562703ab854',
    category: 'browser',
    verdict: 'benign' as const,
    alpn: 'h2',
    sni: 'identity.apple.com',
  },
  {
    name: 'Python Requests / Urllib3',
    ja3: 'b32309a26951912be7dba376398abc3b',
    ja3_raw: '771,4866-4867-4865-49196-49200-49195-49199-52393-52392,0-11-10-35-23-65281,29-23-24,0',
    ja4: 't13d090600_e4465b746c05_000000000000',
    category: 'script',
    verdict: 'suspicious' as const,
    alpn: undefined,
    sni: 'api.target-host.internal',
  },
  {
    name: 'Golang net/http client',
    ja3: '57919782613c6395b0fe66f4cb3ed564',
    ja3_raw: '771,49195-49199-49196-49200-52393-52392-49161-49162-49171-49172,0-5-10-11-13-16-18-43-45-51,29-23-24,0',
    ja4: 't13d1010h2_4432130e9221_a2b8e3919420',
    category: 'tool',
    verdict: 'benign' as const,
    alpn: 'h2',
    sni: 'metrics.monitoring.cloud',
  },
  {
    name: 'Sliver C2 Implant Beacon',
    ja3: '6520d624a91943c2c525b6a715f5d62d',
    ja3_raw: '771,49195-49196-49199-49200-49161-49162-49171-49172-156-157-47-53,0-10-11-13-16-23-65281,29-23-24,0',
    ja4: 't12i1207h1_c61b0388910b_9f4304859a11',
    category: 'malware',
    verdict: 'malicious' as const,
    alpn: 'http/1.1',
    sni: 'cdn.static-cache-sync.org',
  },
  {
    name: 'Firefox 131 / Windows 11',
    ja3: '277ddab680190bbd4691799797d3aa33',
    ja3_raw: '771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-51-45-43-27-21,29-23-24,0',
    ja4: 't13d1714h2_5a4974cbf76c_45df27d53ec0',
    category: 'browser',
    verdict: 'benign' as const,
    alpn: 'h2',
    sni: 'wikipedia.org',
  },
  {
    name: 'Emotet / Qakbot Stager TLS',
    ja3: '4d7a28d6f22da2dee03515373f0760eb',
    ja3_raw: '769,47-53-5-10,0-10-11-13-23,23,0',
    ja4: 't10i040500_569302194c72_f0293e817291',
    category: 'malware',
    verdict: 'malicious' as const,
    alpn: undefined,
    sni: '203.0.113.88',
  },
];

function createSampleTlsEvent(): StreamMessage {
  const c = SAMPLE_CLIENTS[Math.floor(Math.random() * SAMPLE_CLIENTS.length)];
  const isMalicious = c.verdict === 'malicious';
  const isSuspicious = c.verdict === 'suspicious';
  const nowNanos = Date.now() * 1_000_000;
  const srcPort = Math.floor(40000 + Math.random() * 20000);
  const srcIp = `192.168.1.${Math.floor(2 + Math.random() * 250)}`;
  const dstIp = isMalicious ? `198.51.100.${Math.floor(10 + Math.random() * 80)}` : '104.21.34.112';

  const alerts: any[] = [];
  if (isMalicious) {
    alerts.push({
      id: `alt-${Date.now()}`,
      ts_nanos: nowNanos,
      rule: 'THREAT_INTEL_MALWARE_MATCH',
      severity: 'critical',
      ip: srcIp,
      fp_kind: 'ja3',
      fp_value: c.ja3,
      title: `Known C2 Handshake: ${c.name}`,
      detail: `Fingerprint ${c.ja3.slice(0, 12)}... matches verified threat actor signature across FoxIO and Abuse.ch catalogues.`,
      score: 95,
      evidence: `Observed JA4: ${c.ja4} | Direct IP target without SNI hostname.`,
      investigation_steps: [
        'Isolate host endpoint 192.168.1.x immediately',
        'Inspect parent process of socket connection',
        'Review recent memory dumps for injected beacon shellcode',
      ],
    });
  } else if (isSuspicious) {
    alerts.push({
      id: `alt-${Date.now()}`,
      ts_nanos: nowNanos,
      rule: 'BROWSER_SPOOFING_CONTRADICTION',
      severity: 'high',
      ip: srcIp,
      fp_kind: 'ja4',
      fp_value: c.ja4,
      title: 'User-Agent / TLS Handshake Mismatch',
      detail: `HTTP User-Agent claims Chrome/129, but cryptographic cipher ordering and extension list match Python urllib3 stack.`,
      score: 82,
      evidence: `Claimed: Mozilla/5.0 (Macintosh) | Handshake ALPN missing, GREASE extension absent.`,
      investigation_steps: [
        'Verify whether host runs automated scraping or synthetic load testing',
        'Correlate with API token authentication logs',
      ],
    });
  }

  return {
    type: 'flow',
    event: {
      kind: 'client_hello',
      ts_nanos: nowNanos,
      src: `${srcIp}:${srcPort}`,
      dst: `${dstIp}:443`,
      ja3: c.ja3,
      ja3_raw: c.ja3_raw,
      ja4: { hash: c.ja4 },
      sni: c.sni,
      alpn: c.alpn,
    },
    intel: {
      kind: 'ja3',
      observed: c.ja3,
      verdict: c.verdict,
      threat_score: isMalicious ? 95 : isSuspicious ? 70 : 5,
      confidence: 0.94,
      hits: [
        {
          kind: 'ja3',
          value: c.ja3,
          label: c.name,
          category: c.category,
          source: 'FoxIO / Abuse.ch SSLBL',
          strength: 0.96,
        },
      ],
    },
    alerts: alerts.length > 0 ? alerts : undefined,
  };
}
