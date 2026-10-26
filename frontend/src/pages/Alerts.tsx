import React, { useState } from 'react';
import { useAlerts } from '../hooks/useApi';
import { Frame } from '../components/Frame';
import type { Severity } from '../types/api';

export const Alerts: React.FC = () => {
  const { data: alerts } = useAlerts(100);
  const [filterSeverity, setFilterSeverity] = useState<Severity | 'all'>('all');
  const [searchQuery, setSearchQuery] = useState('');

  const list = (alerts ?? []).filter((a) => {
    const matchesSev = filterSeverity === 'all' || a.severity === filterSeverity;
    const matchesQ =
      !searchQuery ||
      a.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      a.rule.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (a.ip && a.ip.includes(searchQuery));
    return matchesSev && matchesQ;
  });

  return (
    <div className="flex flex-col flex-1 gap-5 w-full max-w-[1640px] mx-auto p-[clamp(1rem,3vw,2rem)] font-mono">
      {/* Head */}
      <section className="relative overflow-hidden border-b border-[#ffffff1c] pb-4">
        <div className="max-w-[70ch]">
          <span className="block text-[10px] tracking-[0.28em] text-[#ff4d12] uppercase mb-2">
            cryptographic anomaly detections // triage
          </span>
          <h1 className="font-display text-[clamp(2.6rem,6vw,4.5rem)] text-[#f2f0e9] leading-[0.9] m-0 mb-3 tracking-wide">
            THREAT ALERTS
          </h1>
          <p className="text-[#8b8f95] text-sm leading-relaxed">
            Signed cryptographic contradictions on the wire. Evaluates client masquerading, C2 beacon
            patterns, ungreased ClientHello structures, and deprecated cipher negotiation.
          </p>
        </div>
      </section>

      {/* Filter bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-3 bg-[#0a0b0d] border border-[#ffffff1c]">
        <div className="flex items-center gap-1.5">
          {(['all', 'critical', 'high', 'medium', 'low'] as const).map((sev) => (
            <button
              key={sev}
              onClick={() => setFilterSeverity(sev)}
              className={`px-2.5 py-1 text-[10px] uppercase font-bold tracking-wider border ${
                filterSeverity === sev
                  ? sev === 'critical'
                    ? 'bg-[#ff2733] text-black border-[#ff2733]'
                    : sev === 'high'
                    ? 'bg-[#ff4d12] text-black border-[#ff4d12]'
                    : 'bg-[#14e7d2] text-black border-[#14e7d2]'
                  : 'bg-[#050506] text-[#8b8f95] border-[#ffffff14] hover:text-[#f2f0e9]'
              }`}
            >
              {sev}
            </button>
          ))}
        </div>

        <input
          type="text"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          placeholder="Filter by rule, IP, or title..."
          className="px-3 py-1 bg-[#050506] border border-[#ffffff1c] text-[#f2f0e9] text-xs outline-none w-64 focus:border-[#ff4d12]"
        />
      </div>

      {/* Alert Cards List */}
      <Frame label="alert dossier // triage ledger" aside={<span>{list.length} INCIDENTS</span>}>
        <div className="divide-y divide-[#ffffff0a] overflow-y-auto">
          {list.length === 0 ? (
            <div className="p-12 text-center text-[#5a5f65] uppercase tracking-wider">
              No alerts match the active filter criteria
            </div>
          ) : (
            list.map((alert, idx) => (
              <div
                key={alert.id || idx}
                className="p-5 flex flex-col gap-3 hover:bg-[#0f1113] transition-colors border-l-2 border-transparent hover:border-[#ff4d12]"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span
                      className={`px-2 py-0.5 text-[9px] uppercase font-bold tracking-wider border ${
                        alert.severity === 'critical'
                          ? 'text-[#ff2733] border-[#ff2733] bg-[#ff273322]'
                          : alert.severity === 'high'
                          ? 'text-[#ff4d12] border-[#ff4d12] bg-[#ff4d1222]'
                          : 'text-[#14e7d2] border-[#14e7d2] bg-[#14e7d214]'
                      }`}
                    >
                      {alert.severity}
                    </span>
                    <span className="text-[#8b8f95] uppercase tracking-wider text-[11px] font-bold">
                      {alert.rule.replace(/_/g, ' ')}
                    </span>
                  </div>

                  <div className="flex items-center gap-4 text-xs text-[#5a5f65]">
                    {alert.ip && <span className="text-[#6ea3ff] font-bold">{alert.ip}</span>}
                    <span>{new Date(alert.ts_nanos / 1_000_000).toLocaleTimeString()}</span>
                  </div>
                </div>

                <h3 className="text-sm font-bold text-[#f2f0e9]">{alert.title}</h3>
                <p className="text-xs text-[#8b8f95] leading-relaxed">{alert.detail}</p>

                {alert.evidence && (
                  <div className="p-3 bg-[#050506] border border-[#ffffff0a] text-xs">
                    <span className="text-[#ff4d12] font-bold">CRYPTOGRAPHIC EVIDENCE: </span>
                    <span className="text-[#8b8f95]">{alert.evidence}</span>
                  </div>
                )}

                {alert.investigation_steps && alert.investigation_steps.length > 0 && (
                  <div className="flex flex-col gap-1 p-3 bg-[#15181b] border border-[#ffffff14] text-xs">
                    <span className="text-[10px] uppercase font-bold tracking-wider text-[#8b8f95]">
                      Recommended Remediation & Triage
                    </span>
                    <ul className="list-disc list-inside text-[#d8d6cd] text-[11px] space-y-0.5">
                      {alert.investigation_steps.map((step, sIdx) => (
                        <li key={sIdx}>{step}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      </Frame>
    </div>
  );
};
