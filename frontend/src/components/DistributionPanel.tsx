import React from 'react';
import { Frame } from './Frame';
import { useStats } from '../hooks/useApi';

interface DistributionPanelProps {
  className?: string;
}

export const DistributionPanel: React.FC<DistributionPanelProps> = ({ className = '' }) => {
  const { data: stats } = useStats();

  const categories = stats?.intel.by_category ?? [];
  const rules = stats?.alerts_by_rule ?? [];

  const maxCat = Math.max(1, ...categories.map((c) => c.records));
  const maxRule = Math.max(1, ...rules.map((r) => r.count));

  return (
    <Frame label="distribution // census" className={`min-h-[260px] ${className}`}>
      <div className="flex-1 flex flex-col p-4 gap-4 font-mono text-xs overflow-y-auto">
        {/* Categories */}
        <div className="flex flex-col gap-2">
          <div className="text-[10px] uppercase tracking-[0.2em] text-[#5a5f65] font-bold">
            intel corpus / category
          </div>
          <div className="flex flex-col gap-1.5">
            {categories.map((cat) => {
              const pct = Math.round((cat.records / maxCat) * 100);
              return (
                <div key={cat.category} className="flex flex-col gap-0.5">
                  <div className="flex items-center justify-between text-[11px]">
                    <span className="text-[#8b8f95] uppercase tracking-wider">{cat.category}</span>
                    <span className="text-[#14e7d2] font-bold">{cat.records.toLocaleString()}</span>
                  </div>
                  <div className="w-full h-1 bg-[#ffffff0a] overflow-hidden">
                    <div
                      className="h-full bg-[#14e7d2] transition-all duration-500"
                      style={{ width: `${pct}%`, opacity: 0.7 }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Rules */}
        <div className="flex flex-col gap-2 pt-2 border-t border-[#ffffff0f]">
          <div className="text-[10px] uppercase tracking-[0.2em] text-[#5a5f65] font-bold">
            alerts tripped / rule
          </div>
          <div className="flex flex-col gap-1.5">
            {rules.map((rule) => {
              const pct = Math.round((rule.count / maxRule) * 100);
              return (
                <div key={rule.rule} className="flex flex-col gap-0.5">
                  <div className="flex items-center justify-between text-[11px]">
                    <span className="text-[#8b8f95] truncate max-w-[70%]">
                      {rule.rule.replace(/_/g, ' ')}
                    </span>
                    <span className="text-[#ff4d12] font-bold">{rule.count}</span>
                  </div>
                  <div className="w-full h-1 bg-[#ffffff0a] overflow-hidden">
                    <div
                      className="h-full bg-[#ff4d12] transition-all duration-500"
                      style={{ width: `${pct}%`, opacity: 0.7 }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </Frame>
  );
};
