import React, { useState } from 'react';
import { Frame } from './Frame';
import type { FeedItem, FlowMessage } from '../types/api';

interface LiveFeedPanelProps {
  feed: FeedItem[];
  connected: boolean;
  flowCount: number;
  className?: string;
}

export const LiveFeedPanel: React.FC<LiveFeedPanelProps> = ({
  feed,
  connected,
  flowCount,
  className = '',
}) => {
  const [selectedFlow, setSelectedFlow] = useState<FlowMessage | null>(null);

  const formatTimestamp = (tsNanos: number) => {
    const d = new Date(tsNanos / 1_000_000);
    const pad = (n: number, w = 2) => String(n).padStart(w, '0');
    return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(
      d.getMilliseconds(),
      3
    )}`;
  };

  return (
    <Frame
      label="live // passive wire-tap"
      aside={
        <span className="flex items-center gap-2">
          <span
            className={`inline-flex items-center gap-1 font-bold ${
              connected ? 'text-[#ff4d12]' : 'text-[#5a5f65]'
            }`}
          >
            <span
              className={`w-1.5 h-1.5 rounded-full ${
                connected ? 'bg-[#ff4d12] animate-pulse' : 'bg-[#5a5f65]'
              }`}
            />
            {connected ? 'REC' : 'DOWN'}
          </span>
          <span className="text-[#34383d]">|</span>
          <span className="text-[#8b8f95]">{flowCount.toLocaleString()} FLOWS</span>
        </span>
      }
      className={`min-h-[440px] ${className}`}
    >
      <div className="flex-1 relative overflow-hidden flex flex-col">
        {feed.length === 0 ? (
          <div className="flex-1 flex flex-col items-center justify-center p-8 text-center text-[#5a5f65] font-mono text-xs tracking-wider gap-2">
            <span className="text-[#8b8f95] uppercase font-bold tracking-[0.2em]">
              awaiting handshakes on the wire
            </span>
            <span className="text-[10px] text-[#34383d]">
              THE SCOPE IS BOUND TO PASSIVE BPF INTERFACE [PORT 443]
            </span>
          </div>
        ) : (
          <div className="flex-1 overflow-y-auto divide-y divide-[#ffffff0a] font-mono text-xs">
            {feed.map((item) => {
              if (item.message.type !== 'flow') return null;
              const flow = item.message;
              const ev = flow.event;
              const intel = flow.intel;
              const verdict = intel?.verdict ?? 'unknown';
              const isHot = verdict === 'malicious' || verdict === 'suspicious' || (flow.alerts && flow.alerts.length > 0);
              const label = intel?.hits?.[0]?.label ?? (ev.kind === 'client_hello' ? ev.sni : 'Unknown');

              let fpDisplay = '';
              if (ev.kind === 'client_hello') {
                fpDisplay = `JA4: ${ev.ja4?.hash ?? ''}`;
              } else if (ev.kind === 'server_hello') {
                fpDisplay = `JA4S: ${ev.ja4s?.hash ?? ''}`;
              } else if (ev.kind === 'http_request') {
                fpDisplay = `JA4H: ${ev.ja4h?.hash ?? ''}`;
              } else {
                fpDisplay = ev.kind;
              }

              return (
                <div
                  key={item.seq}
                  onClick={() => setSelectedFlow(flow)}
                  className={`p-3 cursor-pointer transition-all duration-100 flex flex-col gap-1.5 ${
                    isHot
                      ? 'bg-gradient-to-r from-[#ff4d121c] to-transparent border-l-2 border-[#ff4d12]'
                      : 'hover:bg-[#0f1113] border-l-2 border-transparent'
                  }`}
                  style={{ animation: 'row-enter 0.35s ease-out both' }}
                >
                  <div className="flex items-center justify-between gap-2 text-[10px]">
                    <span className="text-[#5a5f65] tracking-wider">
                      {formatTimestamp(ev.ts_nanos)}
                    </span>
                    <span className="text-[#6ea3ff] truncate max-w-[50%]">
                      {ev.src} <span className="text-[#34383d]">{'->'}</span> {ev.dst}
                    </span>
                  </div>

                  <div className="flex items-center justify-between gap-3">
                    <div className="flex items-center gap-2 truncate">
                      <span className="px-1.5 py-0.2 text-[9px] font-bold uppercase tracking-wider bg-[#ffffff0a] text-[#8b8f95] border border-[#ffffff14]">
                        {ev.kind.replace('_', ' ')}
                      </span>
                      <span className="text-[#f2f0e9] font-medium truncate text-xs">
                        {label || 'Unidentified Client'}
                      </span>
                    </div>

                    <span
                      className={`px-1.5 py-0.5 text-[9px] font-bold tracking-widest uppercase border ${
                        verdict === 'malicious'
                          ? 'text-[#ff2733] border-[#ff2733] bg-[#ff273318]'
                          : verdict === 'suspicious'
                          ? 'text-[#ff4d12] border-[#ff4d12] bg-[#ff4d1218]'
                          : verdict === 'benign'
                          ? 'text-[#14e7d2] border-[#14e7d2] bg-[#14e7d212]'
                          : 'text-[#8b8f95] border-[#ffffff1c] bg-[#ffffff08]'
                      }`}
                    >
                      {verdict}
                    </span>
                  </div>

                  <div className="flex items-center justify-between text-[10px] text-[#5a5f65] font-mono">
                    <span className="truncate">{fpDisplay}</span>
                    {ev.kind === 'client_hello' && ev.alpn && (
                      <span className="text-[#14e7d2] uppercase font-bold text-[9px]">
                        ALPN: {ev.alpn}
                      </span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Detail Modal / Handshake Inspector */}
      {selectedFlow && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div
            className="w-full max-w-2xl bg-[#0a0b0d] border border-[#ffffff26] p-6 flex flex-col gap-4 text-left font-mono relative max-h-[85vh] overflow-y-auto shadow-2xl"
            style={{
              boxShadow: '0 0 50px rgba(255, 77, 18, 0.15)',
            }}
          >
            <div className="flex items-center justify-between border-b border-[#ffffff14] pb-3">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 bg-[#ff4d12]" />
                <h3 className="font-display text-xl text-[#f2f0e9] tracking-wider uppercase">
                  TLS Handshake Dossier
                </h3>
              </div>
              <button
                onClick={() => setSelectedFlow(null)}
                className="text-[#8b8f95] hover:text-[#f2f0e9] text-xs font-bold px-2 py-1 border border-[#ffffff14]"
              >
                [CLOSE]
              </button>
            </div>

            <div className="grid grid-cols-2 gap-3 text-xs">
              <div className="flex flex-col gap-1 p-2 bg-[#050506] border border-[#ffffff0a]">
                <span className="text-[10px] text-[#5a5f65] uppercase">Source Endpoint</span>
                <span className="text-[#6ea3ff] font-bold">{selectedFlow.event.src}</span>
              </div>
              <div className="flex flex-col gap-1 p-2 bg-[#050506] border border-[#ffffff0a]">
                <span className="text-[10px] text-[#5a5f65] uppercase">Destination Endpoint</span>
                <span className="text-[#f2f0e9] font-bold">{selectedFlow.event.dst}</span>
              </div>
            </div>

            {selectedFlow.event.kind === 'client_hello' && (
              <div className="flex flex-col gap-3 text-xs">
                <div className="flex flex-col gap-1 p-3 bg-[#050506] border border-[#ffffff0a]">
                  <span className="text-[10px] text-[#ff4d12] uppercase font-bold tracking-widest">
                    Canonical JA3 Hash (MD5)
                  </span>
                  <span className="text-[#f2f0e9] break-all select-all font-bold">
                    {selectedFlow.event.ja3}
                  </span>
                  <span className="text-[10px] text-[#5a5f65] mt-1">Raw Format:</span>
                  <span className="text-[10px] text-[#8b8f95] break-all select-all font-mono">
                    {selectedFlow.event.ja3_raw}
                  </span>
                </div>

                <div className="flex flex-col gap-1 p-3 bg-[#050506] border border-[#ffffff0a]">
                  <span className="text-[10px] text-[#14e7d2] uppercase font-bold tracking-widest">
                    FoxIO JA4 Fingerprint (Standards Compliant)
                  </span>
                  <span className="text-[#f2f0e9] select-all font-bold text-sm">
                    {selectedFlow.event.ja4?.hash}
                  </span>
                  <span className="text-[10px] text-[#5a5f65] mt-1">
                    Protocol: TCP | TLS 1.3 | SNI: {selectedFlow.event.sni ?? 'None'} | ALPN: {selectedFlow.event.alpn ?? 'None'}
                  </span>
                </div>
              </div>
            )}

            {selectedFlow.intel && (
              <div className="p-3 bg-[#15181b] border border-[#ffffff14] flex flex-col gap-2">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] uppercase font-bold tracking-wider text-[#8b8f95]">
                    Threat Intelligence Attribution
                  </span>
                  <span className="text-xs uppercase font-bold text-[#ff4d12]">
                    Threat Score: {selectedFlow.intel.threat_score}/100
                  </span>
                </div>
                <div className="text-sm font-bold text-[#f2f0e9]">
                  {selectedFlow.intel.hits?.[0]?.label ?? 'Generic Cryptographic Signature'}
                </div>
                <div className="text-[11px] text-[#8b8f95]">
                  Source Feed: {selectedFlow.intel.hits?.[0]?.source} | Category: {selectedFlow.intel.hits?.[0]?.category}
                </div>
              </div>
            )}

            {selectedFlow.alerts && selectedFlow.alerts.length > 0 && (
              <div className="p-3 bg-[#ff4d1214] border border-[#ff4d1244] flex flex-col gap-2">
                <span className="text-[10px] uppercase font-bold tracking-wider text-[#ff4d12]">
                  Active Security Alerts Triggered
                </span>
                {selectedFlow.alerts.map((a, idx) => (
                  <div key={idx} className="flex flex-col gap-0.5 text-xs">
                    <span className="text-[#f2f0e9] font-bold">{a.title}</span>
                    <span className="text-[#8b8f95] text-[11px]">{a.detail}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </Frame>
  );
};
