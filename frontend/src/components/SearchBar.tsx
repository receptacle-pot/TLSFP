import React, { useState } from 'react';
import { Frame } from './Frame';
import { useSearch } from '../hooks/useApi';

interface SearchBarProps {
  className?: string;
}

// Exact tabs from the original website's catalogue query:
// all, ja3, ja3s, ja4, ja4s, ja4h, ja4x, ja4t, ja4ts
const KIND_TABS = ['', 'ja3', 'ja3s', 'ja4', 'ja4s', 'ja4h', 'ja4x', 'ja4t', 'ja4ts'];

export const SearchBar: React.FC<SearchBarProps> = ({ className = '' }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [kindFilter, setKindFilter] = useState('');
  const { data: results, isFetching } = useSearch(searchTerm, kindFilter || undefined, 60);

  const list = results ?? [];

  return (
    <Frame
      label="catalogue // query the corpus"
      aside={
        <span className="text-[#8b8f95] font-mono text-[10px]">
          {list.length} {list.length >= 60 ? '+' : ''} HITS
        </span>
      }
      className={`min-h-[540px] ${className}`}
    >
      <div className="flex-1 flex flex-col font-mono text-xs overflow-hidden">
        {/* Search controls */}
        <div className="p-3 border-b border-[#ffffff0f] flex flex-col gap-2.5 bg-[#0a0b0d]">
          {/* Prompt input */}
          <div
            className={`flex items-center gap-2 px-3 py-1.5 bg-[#050506] border transition-colors ${
              isFetching ? 'border-[#ff4d12]' : 'border-[#ffffff1c]'
            }`}
          >
            <span className="text-[#ff4d12] font-bold select-none text-xs">/</span>
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="search the intelligence catalogue"
              className="flex-1 bg-transparent border-none outline-none text-[#f2f0e9] placeholder-[#5a5f65] text-xs font-mono"
            />
            {searchTerm && (
              <button
                onClick={() => setSearchTerm('')}
                className="text-[#5a5f65] hover:text-[#f2f0e9] text-[10px]"
              >
                [clear]
              </button>
            )}
          </div>

          {/* Exact 9 Fingerprint Filter Tabs */}
          <div className="flex flex-wrap items-center gap-1.5">
            {KIND_TABS.map((k) => (
              <button
                key={k || 'all'}
                type="button"
                onClick={() => setKindFilter(k)}
                className={`px-2 py-0.5 text-[10px] uppercase font-bold tracking-[0.1em] transition-all ${
                  kindFilter === k
                    ? 'text-white bg-[#1c2024] border border-[#8b8f95]'
                    : 'text-[#5a5f65] bg-[#0f1113] border border-[#ffffff0f] hover:text-[#d8d6cd] hover:border-[#ffffff33]'
                }`}
              >
                {k || 'all'}
              </button>
            ))}
          </div>
        </div>

        {/* Results List */}
        <div className="flex-1 overflow-y-auto divide-y divide-[#ffffff0a]">
          {list.length === 0 ? (
            <div className="p-12 text-center text-[#5a5f65] uppercase tracking-[0.2em]">
              {searchTerm || kindFilter
                ? 'no fingerprint in the corpus matches that query'
                : 'the corpus is open; supply a label or a hash to filter it'}
            </div>
          ) : (
            list.map((item, idx) => (
              <div
                key={`${item.kind}-${item.value}-${idx}`}
                className="p-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2 hover:bg-[#0f1113] transition-colors"
              >
                <div className="flex flex-col gap-1 min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] text-[#5a5f65] tracking-wider uppercase">
                      <span className="text-[#34383d]">[</span>
                      {item.kind}
                      <span className="text-[#34383d]">]</span>
                    </span>
                    <span className="font-bold text-[#f2f0e9] text-xs truncate">
                      {item.label}
                    </span>
                    <span className="text-[9px] uppercase tracking-wider text-[#8b8f95] px-1 bg-[#ffffff05] border border-[#ffffff0a]">
                      {item.category}
                    </span>
                  </div>
                  <span className="text-[11px] text-[#8b8f95] font-mono break-all select-all">
                    {item.value}
                  </span>
                </div>

                <div className="flex sm:flex-col sm:items-end justify-between text-[10px] text-[#5a5f65] shrink-0">
                  <span className="text-[#6ea3ff]">{item.source}</span>
                  {item.reference && (
                    <span className="truncate max-w-[200px] text-[9px] text-[#34383d]">
                      {item.reference}
                    </span>
                  )}
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </Frame>
  );
};
