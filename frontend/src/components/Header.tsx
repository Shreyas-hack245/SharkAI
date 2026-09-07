import { Flag, Search, Settings, Upload } from 'lucide-react';
import type { CaptureSummary } from '../types';

interface HeaderProps {
  capture?: CaptureSummary | null;
  mode: 'beginner' | 'expert';
  setMode: (m: 'beginner' | 'expert') => void;
  ctfMode: boolean;
  setCtfMode: (v: boolean) => void;
  onSearch?: (q: string) => void;
}

export default function Header({ capture, mode, setMode, ctfMode, setCtfMode, onSearch }: HeaderProps) {
  return (
    <header className="h-12 flex items-center justify-between px-4 bg-shark-900 border-b border-shark-700 shrink-0">
      <div className="flex items-center gap-3">
        <span className="text-xl">🦈</span>
        <div>
          <h1 className="text-sm font-bold tracking-wide text-shark-50">
            SHARK<span className="text-shark-accent">AI</span>
          </h1>
          {capture && (
            <p className="text-[10px] text-shark-400 font-mono">{capture.original_name}</p>
          )}
        </div>
        {ctfMode && (
          <span className="px-2 py-0.5 text-[10px] font-bold bg-shark-accent/20 text-shark-accent border border-shark-accent/30 rounded">
            CTF MODE
          </span>
        )}
      </div>

      <div className="flex items-center gap-3">
        {capture && onSearch && (
          <div className="relative">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-shark-400" />
            <input
              type="text"
              placeholder="Search everything... (Ctrl+K)"
              className="pl-8 pr-3 py-1.5 w-64 bg-shark-800 border border-shark-600 rounded text-xs font-mono
                         focus:outline-none focus:border-shark-accent/50"
              onChange={(e) => onSearch(e.target.value)}
            />
          </div>
        )}

        <button
          onClick={() => setCtfMode(!ctfMode)}
          className={`p-1.5 rounded transition-colors ${ctfMode ? 'bg-shark-accent/20 text-shark-accent' : 'text-shark-400 hover:text-shark-200'}`}
          title="CTF Mode"
        >
          <Flag className="w-4 h-4" />
        </button>

        <div className="flex items-center bg-shark-800 rounded-md border border-shark-600 text-[10px]">
          <button
            onClick={() => setMode('beginner')}
            className={`px-2 py-1 rounded-l-md transition-colors ${mode === 'beginner' ? 'bg-shark-accent/20 text-shark-accent' : 'text-shark-400'}`}
          >
            Beginner
          </button>
          <button
            onClick={() => setMode('expert')}
            className={`px-2 py-1 rounded-r-md transition-colors ${mode === 'expert' ? 'bg-shark-accent/20 text-shark-accent' : 'text-shark-400'}`}
          >
            Expert
          </button>
        </div>
      </div>
    </header>
  );
}
