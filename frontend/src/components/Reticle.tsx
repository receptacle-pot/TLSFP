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
      viewBox="0 0 18 18"
      aria-hidden="true"
      style={{ stroke: 'currentColor', fill: 'none', strokeWidth: 1 }}
    >
      <path d="M9 0v6M9 12v6M0 9h6M12 9h6" />
      <circle cx="9" cy="9" r="2.4" />
    </svg>
  );
};
