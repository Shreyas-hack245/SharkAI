import { Flag, Loader2, Search } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import { getFlags } from '../services/api';

interface FlagHunterProps {
  captureId: string;
}

const PATTERNS = [
  { label: 'Auto Detect', value: '' },
  { label: 'flag{...}', value: 'flag{...}' },
  { label: 'FLAG{...}', value: 'FLAG{...}' },
  { label: 'CTF{...}', value: 'CTF{...}' },
  { label: 'THM{...}', value: 'THM{...}' },
  { label: 'picoCTF{...}', value: 'picoCTF{...}' },
];

export default function FlagHunter({ captureId }: FlagHunterProps) {
  const [flags, setFlags] = useState<Record<string, unknown>[]>([]);
  const [loading, setLoading] = useState(true);
  const [pattern, setPattern] = useState('');
  const [customPattern, setCustomPattern] = useState('');

  const search = useCallback(async () => {
    setLoading(true);
    try {
      const data = await getFlags(captureId);
      let results = data.flags;
      if (pattern || customPattern) {
        const p = customPattern || pattern;
        results = results.filter(f =>
          (f.pattern as string)?.includes(p) || (f.flag as string)?.match(new RegExp(p.replace('...', '.+'), 'i'))
        );
      }
      setFlags(results);
    } catch { /* ignore */ }
    setLoading(false);
  }, [captureId, pattern, customPattern]);

  useEffect(() => { search(); }, [search]);

  return (
    <div className="h-full flex flex-col p-4">
      <div className="flex items-center gap-2 mb-4">
        <Flag className="w-5 h-5 text-shark-accent" />
        <h2 className="text-sm font-bold">CTF Flag Hunter</h2>
      </div>

      <div className="flex gap-2 mb-4">
        <select
          value={pattern}
          onChange={(e) => setPattern(e.target.value)}
          className="input-field w-40"
        >
          {PATTERNS.map(p => <option key={p.label} value={p.value}>{p.label}</option>)}
        </select>
        <input
          type="text"
          value={customPattern}
          onChange={(e) => setCustomPattern(e.target.value)}
          placeholder="Custom regex..."
          className="input-field flex-1"
        />
        <button onClick={search} className="btn-primary flex items-center gap-1">
          <Search className="w-3.5 h-3.5" /> Search
        </button>
      </div>

      {loading ? (
        <div className="flex justify-center py-8"><Loader2 className="w-6 h-6 animate-spin text-shark-accent" /></div>
      ) : flags.length === 0 ? (
        <p className="text-shark-400 text-sm text-center py-8">No flags found in this capture.</p>
      ) : (
        <div className="space-y-3 overflow-y-auto flex-1">
          {flags.map((f, i) => (
            <div key={i} className="panel p-4 border-shark-accent/20">
              <div className="flex items-center gap-2 mb-2">
                <span className="text-lg">🚩</span>
                <span className="text-shark-accent font-bold font-mono text-sm">{f.flag as string}</span>
              </div>
              <div className="grid grid-cols-2 gap-2 text-[11px] text-shark-400">
                <div>Protocol: <span className="text-shark-200">{f.protocol as string}</span></div>
                <div>Confidence: <span className="text-shark-accent">{((f.confidence as number) * 100).toFixed(0)}%</span></div>
                {f.stream_id !== undefined && (
                  <div>TCP Stream: <span className="text-shark-200">#{f.stream_id as number}</span></div>
                )}
                {f.packet_numbers && (
                  <div>Packets: <span className="text-shark-200">{(f.packet_numbers as number[]).join(', ')}</span></div>
                )}
              </div>
              {f.decode_chain && (f.decode_chain as string[]).length > 1 && (
                <div className="mt-2 text-[10px] text-shark-400">
                  Decode: {(f.decode_chain as string[]).join(' → ')}
                </div>
              )}
              {f.context && (
                <pre className="mt-2 p-2 bg-shark-800 rounded text-[10px] font-mono text-shark-300 overflow-x-auto">
                  {f.context as string}
                </pre>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
