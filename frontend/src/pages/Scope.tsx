import React from 'react';
import { useStream } from '../hooks/useStream';
import { StatsCluster } from '../components/StatsCluster';
import { LiveFeedPanel } from '../components/LiveFeedPanel';
import { AnomalyPanel } from '../components/AnomalyPanel';
import { DistributionPanel } from '../components/DistributionPanel';
import { AlertLedgerPanel } from '../components/AlertLedgerPanel';

export const Scope: React.FC = () => {
  const stream = useStream();

  return (
    <div className="flex flex-col flex-1 gap-5 w-full max-w-[1640px] mx-auto p-[clamp(1rem,3vw,2rem)]">
      {/* Masthead */}
      <section className="relative overflow-hidden border-b border-[#ffffff1c] pb-5 grid grid-cols-1 lg:grid-cols-[1fr_auto] gap-5 items-end">
        {/* Decorative background butterfly */}
        <img
          src="/assets/objects/xray-butterfly.png"
          alt=""
          className="pointer-events-none absolute top-1/2 left-[36%] -translate-y-1/2 w-[360px] opacity-[0.16] z-0 mix-blend-screen"
        />

        <div className="relative z-[1] min-w-0">
          <span className="block font-mono text-[10px] tracking-[0.28em] text-[#ff4d12] uppercase mb-2">
            passive tls surveillance / live
          </span>
          <h1 className="font-display text-[clamp(2.6rem,6vw,4.5rem)] text-[#f2f0e9] leading-[0.9] m-0 mb-3 tracking-wide">
            THE SCOPE
          </h1>
          <p className="text-[#8b8f95] text-sm leading-relaxed max-w-[52ch]">
            Fingerprints crossing the wire, scored against the corpus and read for the lie they tell.
          </p>
        </div>

        {/* Top 4 Stats Cluster */}
        <StatsCluster flowCount={stream.flowCount} className="relative z-[1] w-full lg:w-auto" />
      </section>

      {/* Main Analysis Grid */}
      <section className="grid grid-cols-1 lg:grid-cols-[minmax(0,1.62fr)_minmax(0,1fr)] gap-4 items-start">
        {/* Left Column: Real-time Wiretap Stream */}
        <div className="flex flex-col gap-4">
          <LiveFeedPanel
            feed={stream.feed}
            connected={stream.connected}
            flowCount={stream.flowCount}
          />
        </div>

        {/* Right Column: Contradiction Anomaly & Distribution Census */}
        <div className="flex flex-col gap-4">
          <AnomalyPanel />
          <DistributionPanel />
        </div>

        {/* Bottom Full-Width: Alert Ledger */}
        <div className="lg:col-span-2">
          <AlertLedgerPanel limit={25} />
        </div>
      </section>
    </div>
  );
};
