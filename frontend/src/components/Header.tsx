import React, { useState, useEffect } from 'react';
import { NavLink, Link } from 'react-router-dom';
import { RegistrationMark } from './Reticle';

interface HeaderProps {
  connected?: boolean;
  flowCount?: number;
  isDemo?: boolean;
}

export const Header: React.FC<HeaderProps> = ({
  connected = true,
  flowCount = 1420,
  isDemo = false,
}) => {
  // Live UTC Clock
  const [timeStr, setTimeStr] = useState('');

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      const pad = (n: number) => String(n).padStart(2, '0');
      setTimeStr(
        `${pad(now.getUTCHours())}:${pad(now.getUTCMinutes())}:${pad(now.getUTCSeconds())} UTC`
      );
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  // Exact navigation tabs matching the original website:
  // Original website navigation has: scope, intel
  // Additional security views available via dropdown/tabs
  const tabs = [
    { to: '/scope', label: 'scope' },
    { to: '/intel', label: 'intel' },
    { to: '/pcap', label: 'pcap' },
    { to: '/alerts', label: 'alerts' },
    { to: '/stats', label: 'stats' },
  ];

  return (
    <header
      className="sticky top-0 z-40 w-full px-4 sm:px-6 py-2.5 flex items-center justify-between border-b select-none backdrop-blur-md"
      style={{
        backgroundColor: '#050506ee',
        borderColor: '#ffffff1c',
      }}
    >
      {/* Left: White Logo, TLSFP Mark, and Tagline */}
      <div className="flex items-center gap-3">
        <RegistrationMark className="text-white" />
        <Link
          to="/"
          className="font-display text-2xl tracking-wider text-[#f2f0e9] hover:text-[#ff4d12] transition-colors"
          style={{ letterSpacing: '0.04em' }}
        >
          TLSFP
        </Link>
        <span className="hidden md:inline-block font-mono text-[10px] tracking-[0.2em] text-[#34383d] uppercase pl-2 border-l border-[#ffffff14]">
          passive tls surveillance
        </span>
      </div>

      {/* Center: Exact Navigation Tabs with Orange Underline Indicator */}
      <nav className="flex items-center gap-1 sm:gap-2">
        {tabs.map((tab) => (
          <NavLink
            key={tab.to}
            to={tab.to}
            className={({ isActive }) =>
              `relative px-3 py-1.5 font-mono text-xs uppercase font-bold tracking-[0.16em] transition-colors ${
                isActive ? 'text-white' : 'text-[#5a5f65] hover:text-[#8b8f95]'
              }`
            }
          >
            {({ isActive }) => (
              <>
                <span>{tab.label}</span>
                {/* Active Orange Underline identical to reference site */}
                <span
                  className="absolute bottom-0 left-3 right-3 h-[2px] bg-[#ff4d12] transition-transform duration-150 origin-left"
                  style={{
                    transform: isActive ? 'scaleX(1)' : 'scaleX(0)',
                  }}
                />
              </>
            )}
          </NavLink>
        ))}
      </nav>

      {/* Right: Coordinates & Live UTC Clock */}
      <div className="flex items-center gap-3 font-mono text-[10px] tracking-[0.14em]">
        {isDemo && (
          <span className="hidden xl:inline text-[#ffae3a] text-[9px] uppercase font-bold">
            [DEMO]
          </span>
        )}
        <span className="hidden lg:inline text-[#5a5f65]">
          37.7749n / 122.4194w
        </span>
        <span className="text-[#8b8f95] font-bold">
          {timeStr || '18:41:00 UTC'}
        </span>
        <div className="flex items-center gap-1.5 pl-2 border-l border-[#ffffff14]">
          <span
            className={`inline-block w-1.5 h-1.5 rounded-full ${
              connected ? 'bg-[#ff4d12] animate-pulse' : 'bg-[#5a5f65]'
            }`}
          />
          <span
            className="font-bold text-[9px] uppercase"
            style={{ color: connected ? '#ff4d12' : '#5a5f65' }}
          >
            {connected ? 'REC' : 'DOWN'}
          </span>
          <span className="hidden sm:inline text-[#34383d]">
            {flowCount.toLocaleString()}
          </span>
        </div>
      </div>
    </header>
  );
};
