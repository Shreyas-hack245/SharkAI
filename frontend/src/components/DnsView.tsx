import { Loader2, Network } from 'lucide-react';
import { useEffect, useState } from 'react';
import { getSummary } from '../services/api';

interface DnsViewProps {
  captureId: string;
}

export default function DnsView({ captureId }: DnsViewProps) {
  const [queries, setQueries] = useState<Record<string, unknown>[]>([]);
  const [suspicious, setSuspicious] = useState<Record<string, unknown>[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getSummary(captureId).then(data => {
      setQueries((data.dns_queries as Record<string, unknown>[]) || []);
      setSuspicious((data.suspicious_dns as Record<string, unknown>[]) || []);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, [captureId]);

  if (loading) return <div className="flex justify-center py-8"><Loader2 className="w-6 h-6 animate-spin text-shark-accent" /></div>;

  return (
    <div className="h-full overflow-y-auto p-4 space-y-4">
      <div className="flex items-center gap-2">
        <Network className="w-4 h-4 text-shark-accent" />
        <h2 className="text-sm font-bold">DNS Analysis</h2>
        <span className="text-xs text-shark-400">{queries.length} queries</span>
      </div>

      {suspicious.length > 0 && (
        <div className="panel p-3 border-shark-warning/30">
          <h3 className="text-xs text-shark-warning font-semibold mb-2">Suspicious DNS ({suspicious.length})</h3>
          {suspicious.map((s, i) => (
            <div key={i} className="text-xs p-2 bg-shark-800/50 rounded mb-1">
              <span className="font-medium">{s.query_name as string || s.client as string}</span>
              <p className="text-shark-400 mt-0.5">{(s.reasons as string[])?.join('; ')}</p>
              <p className="text-[10px] text-shark-500">Confidence: {((s.confidence as number) * 100).toFixed(0)}%</p>
            </div>
          ))}
        </div>
      )}

      <table className="w-full text-xs font-mono">
        <thead>
          <tr className="text-shark-400 text-left border-b border-shark-700">
            <th className="px-2 py-1.5">Pkt</th>
            <th className="px-2 py-1.5">Client</th>
            <th className="px-2 py-1.5">Query</th>
            <th className="px-2 py-1.5">Type</th>
          </tr>
        </thead>
        <tbody>
          {queries.map((q, i) => (
            <tr key={i} className="border-b border-shark-800/50 hover:bg-shark-800/30">
              <td className="px-2 py-1 text-shark-accent">{q.packet_number as number}</td>
              <td className="px-2 py-1">{q.client as string}</td>
              <td className="px-2 py-1">{q.query_name as string}</td>
              <td className="px-2 py-1 text-shark-400">{q.query_type as string}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
