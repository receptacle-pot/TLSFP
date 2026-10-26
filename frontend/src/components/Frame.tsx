import React from 'react';

interface FrameProps {
  label?: string;
  aside?: React.ReactNode;
  tone?: 'cold' | 'hot' | 'cyan';
  className?: string;
  children: React.ReactNode;
}

export const Frame: React.FC<FrameProps> = ({
  label,
  aside,
  tone = 'cold',
  className = '',
  children,
}) => {
  const isHot = tone === 'hot';
  const isCyan = tone === 'cyan';

  return (
    <section
      className={`relative flex flex-col min-w-0 transition-colors ${className}`}
      style={{
        background: 'linear-gradient(180deg, #0a0b0d 0%, #050506 100%)',
        border: `1px solid ${isHot ? '#ff4d1266' : isCyan ? '#14e7d244' : '#ffffff1c'}`,
        boxShadow: isHot ? '0 0 24px #ff4d1215' : 'none',
      }}
    >
      {/* Corner Crop Accents */}
      <div
        className="absolute -top-[1px] -left-[1px] w-[5px] h-[5px] pointer-events-none"
        style={{ borderTop: '2px solid #ffffff44', borderLeft: '2px solid #ffffff44' }}
      />
      <div
        className="absolute -top-[1px] -right-[1px] w-[5px] h-[5px] pointer-events-none"
        style={{ borderTop: '2px solid #ffffff44', borderRight: '2px solid #ffffff44' }}
      />
      <div
        className="absolute -bottom-[1px] -left-[1px] w-[5px] h-[5px] pointer-events-none"
        style={{ borderBottom: '2px solid #ffffff44', borderLeft: '2px solid #ffffff44' }}
      />
      <div
        className="absolute -bottom-[1px] -right-[1px] w-[5px] h-[5px] pointer-events-none"
        style={{ borderBottom: '2px solid #ffffff44', borderRight: '2px solid #ffffff44' }}
      />

      {(label || aside) && (
        <header
          className="flex justify-between items-center gap-3 px-3 py-2 select-none"
          style={{ borderBottom: '1px solid #ffffff0f' }}
        >
          {label && (
            <span
              className="inline-flex items-center gap-2 font-mono text-[10px] font-bold tracking-[0.22em] uppercase"
              style={{ color: isHot ? '#ff7a45' : isCyan ? '#14e7d2' : '#8b8f95' }}
            >
              <span
                className="w-1.5 h-1.5 inline-block"
                style={{
                  background: isHot ? '#ff4d12' : isCyan ? '#14e7d2' : '#fff3',
                }}
              />
              {label}
            </span>
          )}
          {aside && (
            <span className="font-mono text-[10px] tracking-[0.16em] text-[#5a5f65] whitespace-nowrap">
              {aside}
            </span>
          )}
        </header>
      )}

      <div className="flex-1 min-h-0 relative flex flex-col">{children}</div>
    </section>
  );
};
