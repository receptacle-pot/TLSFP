import React from 'react';
import { useStats, getExportUrl } from '../hooks/useApi';
import { Frame } from '../components/Frame';
import { SearchBar } from '../components/SearchBar';

export const Intel: React.FC = () => {
  const { data: stats } = useStats();
  const sources = stats?.intel.sources ?? [];
  const totalFp = stats?.intel.total ?? 31797;

  return (
    <div className="flex flex-col flex-1 gap-5 w-full max-w-[1640px] mx-auto p-[clamp(1rem,3vw,2rem)]">
      {/* Head */}
      <section className="relative overflow-hidden border-b border-[#ffffff1c] pb-4">
        {/* Decorative X-Ray Lily */}
        <img
          src="/assets/objects/xray-lily.png"
          alt=""
          className="pointer-events-none absolute top-1/2 right-[1%] -translate-y-1/2 h-[150%] opacity-50 z-0 mix-blend-screen"
          style={{
            filter: 'drop-shadow(0 0 40px rgba(47, 123, 255, 0.3))',
          }}
        />

        <div className="relative z-[1] max-w-[68ch]">
          <span className="block font-mono text-[10px] tracking-[0.28em] text-[#14e7d2] uppercase mb-2">
            threat intelligence / catalogue
          </span>
          <h1 className="font-display text-[clamp(2.6rem,6vw,4.5rem)] text-[#f2f0e9] leading-[0.9] m-0 mb-3 tracking-wide">
            THE CORPUS
          </h1>
          <p className="text-[#8b8f95] text-sm leading-relaxed">
            {totalFp.toLocaleString()} fingerprints fused from {sources.length} feeds. Query it for
            a known hand, or carry the ledger out.
          </p>
        </div>
      </section>

      {/* Grid: Search on left, Feeds & Exports on right */}
      <section className="grid grid-cols-1 lg:grid-cols-[minmax(0,1.7fr)_minmax(0,1fr)] gap-4 items-start">
        {/* Left: Search component */}
        <SearchBar />

        {/* Right: Side controls */}
        <div className="flex flex-col gap-4">
          {/* Feeds // Provenance */}
          <Frame label="feeds // provenance" className="min-h-[260px]">
            <div className="p-2 font-mono text-xs divide-y divide-[#ffffff0a]">
              {sources.map((src) => (
                <div
                  key={src.name}
                  className="flex items-center justify-between gap-3 p-2.5 hover:bg-[#0f1113] transition-colors"
                >
                  <span className="text-[#d8d6cd] truncate text-[11px] font-medium">
                    {src.name}
                  </span>
                  <div className="flex items-center gap-3 shrink-0">
                    <span className="text-[10px] uppercase tracking-wider text-[#5a5f65]">
                      {src.license ?? 'unlicensed'}
                    </span>
                    <span className="text-[#14e7d2] font-bold text-[11px]">
                      {src.records.toLocaleString()}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </Frame>

          {/* Export // Ledger */}
          <Frame label="export // ledger" className="min-h-[160px]">
            <div className="p-4 flex flex-col gap-3 font-mono">
              <p className="text-[#8b8f95] text-xs leading-relaxed">
                Carry the alert ledger out, structured for a report or raw for an offline Jupyter
                notebook or SIEM ingestion pipeline.
              </p>
              <div className="grid grid-cols-2 gap-3 mt-1">
                <a
                  href={getExportUrl('json', 5000)}
                  download="tls_intel_ledger.json"
                  className="py-2.5 px-4 text-center font-bold text-xs uppercase tracking-[0.18em] text-[#f2f0e9] bg-[#15181b] border border-[#ffffff1c] hover:bg-[#1c2024] hover:border-[#ffffff33] hover:text-[#14e7d2] transition-colors"
                >
                  JSON LEDGER
                </a>
                <a
                  href={getExportUrl('csv', 5000)}
                  download="tls_intel_ledger.csv"
                  className="py-2.5 px-4 text-center font-bold text-xs uppercase tracking-[0.18em] text-[#f2f0e9] bg-[#15181b] border border-[#ffffff1c] hover:bg-[#1c2024] hover:border-[#ffffff33] hover:text-[#14e7d2] transition-colors"
                >
                  CSV EXPORT
                </a>
              </div>
            </div>
          </Frame>
        </div>
      </section>
    </div>
  );
};
