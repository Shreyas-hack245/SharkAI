import { Globe, Loader2 } from 'lucide-react';
import { useEffect, useState } from 'react';
import { getSummary } from '../services/api';

interface HttpViewProps {
  captureId: string;
}

export default function HttpView({ captureId }: HttpViewProps) {
  const [requests, setRequests] = useState<Record<string, unknown>[]>([]);
  const [credentials, setCredentials] = useState<Record<string, unknown>[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getSummary(captureId).then(data => {
      setRequests((data.http_requests as Record<string, unknown>[]) || []);
      setCredentials((data.credentials as Record<string, unknown>[]) || []);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, [captureId]);

  if (loading) return <div className="flex justify-center py-8"><Loader2 className="w-6 h-6 animate-spin text-shark-accent" /></div>;

  return (
    <div className="h-full overflow-y-auto p-4 space-y-4">
      <div className="flex items-center gap-2">
        <Globe className="w-4 h-4 text-shark-accent" />
        <h2 className="text-sm font-bold">HTTP Analysis</h2>
        <span className="text-xs text-shark-400">{requests.length} requests</span>
      </div>

      {credentials.length > 0 && (
        <div className="panel p-3 border-shark-danger/30">
          <h3 className="text-xs text-shark-danger font-semibold mb-2">⚠ Credentials Found ({credentials.length})</h3>
          {credentials.map((c, i) => (
            <div key={i} className="text-xs p-2 bg-shark-800/50 rounded mb-1">
              <span className="text-shark-danger font-medium">{c.type as string}</span>
              <span className="text-shark-400 ml-2">pkt #{c.packet_number as number}</span>
              <pre className="mt-1 font-mono text-[10px] text-shark-300 truncate">{(c.value as string)?.slice(0, 200)}</pre>
            </div>
          ))}
        </div>
      )}

      <table className="w-full text-xs font-mono">
        <thead>
          <tr className="text-shark-400 text-left border-b border-shark-700">
            <th className="px-2 py-1.5">Pkt</th>
            <th className="px-2 py-1.5">Method</th>
            <th className="px-2 py-1.5">Host</th>
            <th className="px-2 py-1.5">URI</th>
            <th className="px-2 py-1.5">Stream</th>
          </tr>
        </thead>
        <tbody>
          {requests.map((r, i) => (
            <tr key={i} className="border-b border-shark-800/50 hover:bg-shark-800/30">
              <td className="px-2 py-1 text-shark-accent">{r.packet_number as number}</td>
              <td className="px-2 py-1"><span className="px-1 bg-shark-700 rounded">{r.method as string}</span></td>
              <td className="px-2 py-1">{r.host as string}</td>
              <td className="px-2 py-1 truncate max-w-xs">{r.uri as string}</td>
              <td className="px-2 py-1 text-shark-400">{r.stream_id as number}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
