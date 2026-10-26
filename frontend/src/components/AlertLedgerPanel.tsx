import React from 'react';
import { Frame } from './Frame';
import { useAlerts } from '../hooks/useApi';

interface AlertLedgerPanelProps {
  className?: string;
  limit?: number;
}

export const AlertLedgerPanel: React.FC<AlertLedgerPanelProps> = ({
  className = '',
  limit = 20,
}) => {
  const { data: alerts, isLoading } = useAlerts(limit);
  const list = alerts ?? [];

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
      label="alert ledger // provenance"
      aside={<span>{list.length.toLocaleString()} SIGNED</span>}
      className={`min-h-[300px] ${className}`}
    >
      <div className="flex-1 relative overflow-y-auto divide-y divide-[#ffffff0a] font-mono text-xs">
        {isLoading ? (
          <div className="p-8 text-center text-[#5a5f65] uppercase tracking-[0.2em]">
            reading the ledger...
          </div>
        ) : list.length === 0 ? (
          <div className="p-8 text-center text-[#5a5f65] uppercase tracking-[0.2em]">
            the ledger is clean
          </div>
        ) : (
          list.map((alert, idx) => {
            const isHigh = alert.severity === 'high' || alert.severity === 'critical';
            return (
              <div
                key={alert.id || idx}
                className={`p-3.5 flex flex-col gap-1 transition-colors hover:bg-[#0f1113] border-l-2 ${
                  isHigh
                    ? 'border-[#ff4d12] bg-gradient-to-r from-[#ff4d1214] to-transparent'
                    : 'border-[#ffffff0f]'
                }`}
              >
                <div className="flex items-center justify-between gap-2 text-[10px]">
                  <div className="flex items-center gap-2">
                    <span
                      className={`px-1.5 py-0.2 uppercase font-bold tracking-wider text-[9px] border ${
                        alert.severity === 'critical'
                          ? 'text-[#ff2733] border-[#ff2733] bg-[#ff273322]'
                          : alert.severity === 'high'
                          ? 'text-[#ff4d12] border-[#ff4d12] bg-[#ff4d1222]'
                          : 'text-[#14e7d2] border-[#14e7d2] bg-[#14e7d214]'
                      }`}
                    >
                      {alert.severity}
                    </span>
                    <span className="text-[#8b8f95] uppercase tracking-wider font-bold">
                      {alert.rule.replace(/_/g, ' ')}
                    </span>
                  </div>
                  <span className="text-[#5a5f65]">{formatTimestamp(alert.ts_nanos)}</span>
                </div>

                <div className="flex items-center justify-between gap-4 mt-0.5">
                  <h4 className="text-xs font-bold text-[#f2f0e9]">{alert.title}</h4>
                  {alert.ip && (
                    <span className="text-[10px] text-[#6ea3ff] shrink-0">{alert.ip}</span>
                  )}
                </div>

                <p className="text-[11px] text-[#8b8f95] leading-relaxed mt-0.5">
                  {alert.detail}
                </p>

                {alert.evidence && (
                  <div className="mt-1.5 p-2 bg-[#050506] border border-[#ffffff0f] text-[10px] text-[#5a5f65]">
                    <span className="text-[#ff4d12] font-bold">CRYPTOGRAPHIC EVIDENCE: </span>
                    <span className="text-[#8b8f95]">{alert.evidence}</span>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </Frame>
  );
};
