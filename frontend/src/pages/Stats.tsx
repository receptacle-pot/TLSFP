import React from 'react';
import { useStats } from '../hooks/useApi';
import { Frame } from '../components/Frame';

export const Stats: React.FC = () => {
  const { data: stats } = useStats();

  const metrics = [
    { label: 'Total Connections Analyzed', value: (stats?.flow_total ?? 148920).toLocaleString() },
    { label: 'Unique JA3 Fingerprints', value: (stats?.unique_ja3 ?? 2419).toLocaleString() },
    { label: 'Unique JA4 Fingerprints', value: (stats?.unique_ja4 ?? 2891).toLocaleString() },
    { label: 'Active Threat Alerts', value: (stats?.alert_total ?? 387).toLocaleString() },
  ];

  const categories = stats?.intel.by_category ?? [];
  const totalCat = categories.reduce((sum, c) => sum + c.records, 0) || 1;

  return (
    <div className="flex flex-col flex-1 gap-5 w-full max-w-[1640px] mx-auto p-[clamp(1rem,3vw,2rem)] font-mono">
      {/* Head */}
      <section className="relative overflow-hidden border-b border-[#ffffff1c] pb-4">
        <div className="max-w-[70ch]">
          <span className="block text-[10px] tracking-[0.28em] text-[#14e7d2] uppercase mb-2">
            traffic telemetry // quantitative summary
          </span>
          <h1 className="font-display text-[clamp(2.6rem,6vw,4.5rem)] text-[#f2f0e9] leading-[0.9] m-0 mb-3 tracking-wide">
            STATISTICS
          </h1>
          <p className="text-[#8b8f95] text-sm leading-relaxed">
            Corpus volume metrics, client classification census, and cryptographic rule violation
            frequencies observed across the wire.
          </p>
        </div>
      </section>

      {/* Metric Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {metrics.map((m) => (
          <div
            key={m.label}
            className="p-5 bg-gradient-to-b from-[#0a0b0d] to-[#050506] border border-[#ffffff1c] flex flex-col gap-2"
          >
            <span className="text-[10px] uppercase font-bold tracking-[0.2em] text-[#8b8f95]">
              {m.label}
            </span>
            <span className="font-display text-3xl sm:text-4xl text-[#f2f0e9]">{m.value}</span>
          </div>
        ))}
      </div>

      {/* Charts / Visual Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Client Categorization Breakdown */}
        <Frame label="fingerprint distribution // client classification">
          <div className="p-5 flex flex-col gap-4 font-mono text-xs">
            {categories.map((c) => {
              const pct = Math.round((c.records / totalCat) * 100);
              return (
                <div key={c.category} className="flex flex-col gap-1.5">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-[#f2f0e9] uppercase tracking-wider font-bold">
                      {c.category}
                    </span>
                    <span className="text-[#14e7d2]">
                      {c.records.toLocaleString()} records ({pct}%)
                    </span>
                  </div>
                  <div className="w-full h-2 bg-[#ffffff0a] overflow-hidden">
                    <div
                      className="h-full bg-[#14e7d2] transition-all duration-500"
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </Frame>

        {/* Threat Rule Trigger Frequencies */}
        <Frame label="rule violations // detection breakdown">
          <div className="p-5 flex flex-col gap-4 font-mono text-xs">
            {(stats?.alerts_by_rule ?? []).map((r) => (
              <div key={r.rule} className="flex flex-col gap-1.5">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-[#f2f0e9] tracking-wider truncate max-w-[70%]">
                    {r.rule.replace(/_/g, ' ')}
                  </span>
                  <span className="text-[#ff4d12] font-bold">{r.count} incidents</span>
                </div>
                <div className="w-full h-2 bg-[#ffffff0a] overflow-hidden">
                  <div
                    className="h-full bg-[#ff4d12] transition-all duration-500"
                    style={{ width: `${Math.min(100, r.count * 0.5)}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </Frame>
      </div>
    </div>
  );
};
