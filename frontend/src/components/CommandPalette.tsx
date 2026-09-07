import { Search } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';

interface CommandPaletteProps {
  onClose: () => void;
  onCommand: (command: string) => void;
  captureId: string;
}

const COMMANDS = [
  { cmd: '/summary', desc: 'Show capture summary' },
  { cmd: '/streams', desc: 'List TCP streams' },
  { cmd: '/http', desc: 'HTTP analysis' },
  { cmd: '/dns', desc: 'DNS analysis' },
  { cmd: '/files', desc: 'Extracted files' },
  { cmd: '/flags', desc: 'Search for flags' },
  { cmd: '/iocs', desc: 'Extract IOCs' },
  { cmd: '/timeline', desc: 'Investigation timeline' },
  { cmd: '/graph', desc: 'Network graph' },
];

export default function CommandPalette({ onClose, onCommand }: CommandPaletteProps) {
  const [query, setQuery] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => { inputRef.current?.focus(); }, []);

  const filtered = COMMANDS.filter(c =>
    c.cmd.includes(query.toLowerCase()) || c.desc.toLowerCase().includes(query.toLowerCase())
  );

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-[20vh] bg-black/60" onClick={onClose}>
      <div className="w-full max-w-md panel shadow-2xl" onClick={e => e.stopPropagation()}>
        <div className="flex items-center gap-2 p-3 border-b border-shark-700">
          <Search className="w-4 h-4 text-shark-400" />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={e => setQuery(e.target.value)}
            onKeyDown={e => {
              if (e.key === 'Enter' && filtered.length > 0) {
                onCommand(filtered[0].cmd);
              }
            }}
            placeholder="Type a command..."
            className="flex-1 bg-transparent text-sm focus:outline-none"
          />
          <kbd className="text-[10px] text-shark-500 bg-shark-800 px-1.5 py-0.5 rounded">ESC</kbd>
        </div>
        <ul className="max-h-64 overflow-y-auto">
          {filtered.map(c => (
            <li key={c.cmd}>
              <button
                onClick={() => onCommand(c.cmd)}
                className="w-full flex items-center gap-3 px-3 py-2 text-sm hover:bg-shark-800 transition-colors"
              >
                <span className="font-mono text-shark-accent">{c.cmd}</span>
                <span className="text-shark-400 text-xs">{c.desc}</span>
              </button>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
