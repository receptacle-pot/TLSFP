import React from 'react';
import { useStats } from '../hooks/useApi';

interface StatsClusterProps {
  flowCount: number;
  className?: string;
}

export const StatsCluster: React.FC<StatsClusterProps> = ({ flowCount, className = '' }) => {
  const { data: stats } = useStats();

  const items = [
    {
      value: stats?.intel.total ?? 31797,
      label: 'intel corpus',
      sub: 'fingerprints held',
    },
    {
      value: stats?.alert_total ?? 387,
      label: 'alerts',
      sub: 'rules tripped',
    },
    {
      value: stats?.intel.sources.length ?? 5,
      label: 'feeds',
      sub: 'sources fused',
    },
    {
      value: flowCount,
      label: 'live flows',
      sub: 'seen this session',
    },
  ];

  return (
    <div
      className={`grid grid-cols-2 md:grid-cols-4 border border-[#ffffff1c] ${className}`}
      style={{
        background: 'linear-gradient(180deg, #0a0b0d 0%, #050506 100%)',
      }}
    >
      {items.map((item, idx) => (
        <div
          key={item.label}
          className={`flex flex-col justify-between p-4 sm:p-5 relative ${
            idx < items.length - 1 ? 'border-r border-[#ffffff0f]' : ''
          }`}
        >
          <span
            className="font-display text-3xl sm:text-4xl lg:text-5xl text-[#f2f0e9] tracking-tight leading-none mb-2"
          >
            {item.value.toLocaleString()}
          </span>
          <div className="flex flex-col gap-0.5">
            <span className="font-mono text-[10px] uppercase font-bold tracking-[0.2em] text-[#8b8f95]">
              {item.label}
            </span>
            <span className="font-mono text-[10px] tracking-[0.14em] text-[#5a5f65]">
              {item.sub}
            </span>
          </div>
        </div>
      ))}
    </div>
  );
};
