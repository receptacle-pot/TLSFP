import React from 'react';
import { Frame } from './Frame';
import { Reticle } from './Reticle';
import { useAlerts } from '../hooks/useApi';

interface AnomalyPanelProps {
  className?: string;
}

export const AnomalyPanel: React.FC<AnomalyPanelProps> = ({ className = '' }) => {
  const { data: alerts } = useAlerts(6);

  // Filter contradictions / browser spoofing or critical anomalies
  const anomalies = (alerts ?? []).filter(
    (a) =>
      a.rule.includes('CONTRADICTION') ||
      a.rule.includes('SPOOFING') ||
      a.severity === 'critical' ||
      a.severity === 'high'
  );

  const hasAnomalies = anomalies.length > 0;

  return (
    <Frame
      label="anomaly // the lie the scan caught"
      tone={hasAnomalies ? 'hot' : 'cold'}
      className={`min-h-[280px] ${className}`}
    >
      <div className="flex-1 relative flex flex-col p-4 overflow-y-auto">
        {!hasAnomalies ? (
          <div className="flex-1 flex flex-col items-center justify-center text-center p-6 gap-3 text-[#5a5f65]">
            <Reticle size={54} className="text-[#34383d]" />
            <div className="flex flex-col gap-1">
              <span className="font-mono text-xs font-bold uppercase tracking-[0.2em] text-[#8b8f95]">
                no contradiction on the wire
              </span>
              <span className="font-mono text-[10px] text-[#5a5f65] tracking-wider">
                every handshake agrees with what it claims to be
              </span>
            </div>
          </div>
        ) : (
          <div className="flex flex-col gap-3">
            {anomalies.slice(0, 3).map((anomaly) => (
              <div
                key={anomaly.id || anomaly.title}
                className="p-3 bg-[#0f1113] border-l-2 border-[#ff4d12] flex flex-col gap-1 text-left font-mono"
                style={{
                  background: 'linear-gradient(90deg, #ff4d1215 0%, #0000 60%)',
                }}
              >
                <div className="flex items-center justify-between text-[10px]">
                  <span className="text-[#ff7a45] uppercase font-bold tracking-wider">
                    {anomaly.rule.replace(/_/g, ' ')}
                  </span>
                  <span className="text-[#6ea3ff]">{anomaly.ip || '192.168.1.144'}</span>
                </div>
                <h4 className="text-xs font-bold text-[#f2f0e9] mt-0.5">{anomaly.title}</h4>
                <p className="text-[11px] text-[#8b8f95] leading-relaxed">{anomaly.detail}</p>
                {anomaly.evidence && (
                  <div className="mt-1 text-[10px] text-[#5a5f65] bg-[#050506] p-1.5 border border-[#ffffff0a]">
                    <span className="text-[#ff4d12] font-bold">EVIDENCE: </span>
                    {anomaly.evidence}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </Frame>
  );
};
