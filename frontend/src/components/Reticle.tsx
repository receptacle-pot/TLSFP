import React from 'react';

interface ReticleProps {
  className?: string;
  size?: number;
}

export const Reticle: React.FC<ReticleProps> = ({ className = '', size = 80 }) => {
  return (
    <svg
      className={className}
      width={size}
      height={size}
      viewBox="0 0 80 80"
      aria-hidden="true"
      style={{ stroke: 'currentColor', fill: 'none', strokeWidth: 1 }}
    >
      <circle cx="40" cy="40" r="30" strokeDasharray="3 3" opacity="0.4" />
      <circle cx="40" cy="40" r="16" opacity="0.7" />
      <circle cx="40" cy="40" r="3" fill="currentColor" />
      <path d="M40 2v18M40 60v18M2 40h18M60 40h18" />
    </svg>
  );
};

export const RegistrationMark: React.FC<{ className?: string }> = ({ className = '' }) => {
  return (
    <svg
      className={className}
      width="18"
      height="18"
      viewBox="0 0 100 100"
      aria-hidden="true"
      style={{ stroke: '#FFFFFF', fill: 'none', strokeWidth: 7 }}
    >
      <polygon points="50,8 7,92 93,92" />
      <circle cx="50" cy="64" r="26.5" />
      <line x1="50" y1="8" x2="50" y2="92" />
    </svg>
  );
};
