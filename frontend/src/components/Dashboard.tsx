import { Download, Loader2, Shield } from 'lucide-react';
import { useEffect, useState } from 'react';
import { getIocs } from '../services/api';
import type { CaptureSummary } from '../types';

interface DashboardProps {
  capture: CaptureSummary;
  view?: string;
}

export default function Dashboard({ capture, view }: DashboardProps) {
  const [iocs, setIocs] = useState<Record<string, unknown>[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getIocs(capture.id).then(data => {
      setIocs(data.iocs);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, [capture.id]);

  const grouped: Record<string, Record<string, unknown>[]> = {};
  iocs.forEach(ioc => {
    const type = ioc.type as string;
    grouped[type] = grouped[type] || [];
    grouped[type].push(ioc);
  });

  const exportIocs = (format: string) => {
    window.open(`/api/captures/${capture.id}/iocs?format=${format}`, '_blank');
  };

  if (loading) return <div className="flex justify-center py-8"><Loader2 className="w-6 h-6 animate-spin text-shark-accent" /></div>;

  return (
    <div className="h-full overflow-y-auto p-4">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Shield className="w-4 h-4 text-shark-accent" />
          <h2 className="text-sm font-bold">Indicators of Compromise</h2>
          <span className="text-xs text-shark-400">{iocs.length} total</span>
        </div>
        <div className="flex gap-1">
          {['json', 'csv', 'txt'].map(fmt => (
            <button key={fmt} onClick={() => exportIocs(fmt)} className="btn-secondary text-[10px] flex items-center gap-1">
              <Download className="w-3 h-3" /> {fmt.toUpperCase()}
            </button>
          ))}
        </div>
      </div>

      {Object.entries(grouped).map(([type, items]) => (
        <div key={type} className="mb-4">
          <h3 className="text-xs uppercase tracking-wider text-shark-400 mb-2 font-semibold">
            {type} ({items.length})
          </h3>
          <div className="space-y-0.5">
            {[...new Set(items.map(i => i.value as string))].slice(0, 50).map((val, i) => (
              <div key={i} className="text-xs font-mono px-2 py-1 bg-shark-800/50 rounded text-shark-200">
                {val}
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}
