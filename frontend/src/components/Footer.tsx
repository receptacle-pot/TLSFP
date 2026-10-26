import React from 'react';

const FOOTER_TAGS = [
  'ja3 / ja4 / ja4+ / quic',
  'biometric overlays',
  'x-ray scans of bodies & objects',
  'timestamped data grids',
];

export const Footer: React.FC = () => {
  return (
    <footer
      className="w-full px-4 sm:px-6 py-4 flex flex-wrap items-center justify-between gap-3 border-t text-[#5a5f65] font-mono text-[10px] tracking-[0.16em] uppercase"
      style={{
        backgroundColor: '#050506',
        borderColor: '#ffffff0f',
      }}
    >
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
        {FOOTER_TAGS.map((tag) => (
          <span key={tag} className="flex items-center gap-1">
            <span className="text-[#34383d] font-bold">+</span>
            <span>{tag}</span>
          </span>
        ))}
      </div>
      <div className="flex items-center gap-4 text-[#34383d]">
        <span>TLSFP // TLS INTELLIGENCE ARCHIVE</span>
        <span>SPECIMEN 006</span>
      </div>
    </footer>
  );
};
