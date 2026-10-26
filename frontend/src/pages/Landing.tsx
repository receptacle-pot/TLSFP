import React from 'react';
import { Link } from 'react-router-dom';
import { RegistrationMark } from '../components/Reticle';

const NOTES = [
  'ja3 / ja4 / ja4+ / quic',
  'biometric overlays',
  'x-ray scans of bodies & objects',
  'timestamped data grids',
];

export const Landing: React.FC = () => {
  return (
    <div className="relative flex flex-col justify-between flex-1 min-h-[100dvh] p-[clamp(1.25rem,5vw,3rem)] overflow-hidden select-none bg-[#050506]">
      {/* Specimen X-Ray Butterfly */}
      <img
        src="/assets/objects/xray-butterfly.png"
        alt=""
        className="pointer-events-none absolute top-1/2 right-[-6%] -translate-y-1/2 w-[clamp(420px,56vw,880px)] opacity-90 z-0 mix-blend-screen"
        style={{
          filter: 'drop-shadow(0 0 60px rgba(47, 123, 255, 0.28))',
        }}
      />

      {/* Repeating Scanlines Overlay */}
      <div
        className="absolute inset-0 pointer-events-none z-[1]"
        style={{
          backgroundImage:
            'repeating-linear-gradient(0deg, rgba(255, 255, 255, 0.04) 0px, rgba(255, 255, 255, 0.04) 1px, transparent 1px, transparent 3px)',
        }}
      />

      {/* Corner Registration Marks */}
      <div className="absolute top-5 left-5 z-[2] text-[#5a5f65]">
        <RegistrationMark />
      </div>
      <div className="absolute top-5 right-5 z-[2] text-[#5a5f65]">
        <RegistrationMark />
      </div>
      <div className="absolute bottom-5 left-5 z-[2] text-[#5a5f65]">
        <RegistrationMark />
      </div>
      <div className="absolute bottom-5 right-5 z-[2] text-[#5a5f65]">
        <RegistrationMark />
      </div>

      {/* Top Header metadata */}
      <header className="relative z-[3] flex justify-between items-center text-[#5a5f65] font-mono text-[10px] tracking-[0.2em] uppercase">
        <span>tls dossier / passive</span>
        <span>specimen 006 / handshake</span>
      </header>

      {/* Center Hero */}
      <main className="relative z-[3] flex flex-col items-start max-w-[80ch] py-8 my-auto">
        <span
          className="font-mono text-xs tracking-[0.34em] text-[#ff4d12] uppercase mb-6"
          style={{ textShadow: '0 0 10px rgba(255, 77, 18, 0.35)' }}
        >
          sleep is counter surveillance
        </span>

        <h1
          className="font-display text-[clamp(5rem,18vw,13rem)] text-white tracking-[0.01em] leading-[0.82] mb-7 select-none"
          style={{ textShadow: '0 0 48px rgba(47, 123, 255, 0.16)' }}
        >
          TLSFP
        </h1>

        <p className="text-[#d8d6cd] text-base sm:text-lg leading-relaxed max-w-[clamp(54ch,30vw+17ch,76ch)] font-sans">
          An x-ray of the handshake. Every client carries a fingerprint it cannot hide,
          and the instant a user-agent claims to be a browser while its fingerprint is a script,
          the lie is on the table.
        </p>

        <Link
          to="/scope"
          className="inline-flex items-center gap-2.5 mt-10 px-5 py-3 bg-[#ff4d12] text-black font-mono text-sm font-bold uppercase tracking-[0.16em] transition-all hover:brightness-110 active:translate-y-0.5 shadow-lg"
          style={{
            boxShadow: '0 0 30px rgba(255, 77, 18, 0.3)',
          }}
        >
          <span className="font-bold">-&gt;</span>
          <span>enter the scope</span>
        </Link>
      </main>

      {/* Footer Notes */}
      <footer className="relative z-[3] flex flex-wrap gap-x-6 gap-y-2 text-[#5a5f65] font-mono text-[10px] tracking-[0.16em] uppercase">
        {NOTES.map((note) => (
          <span key={note} className="flex items-center gap-1.5">
            <span className="text-[#34383d] font-bold">+</span>
            <span>{note}</span>
          </span>
        ))}
      </footer>
    </div>
  );
};
