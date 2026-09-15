import { FileText, Key, Loader2 } from 'lucide-react';
import { useEffect, useState } from 'react';
import { getSummary } from '../services/api';

interface EvidenceListProps {
  captureId: string;
  kind: 'files' | 'credentials';
}

export default function EvidenceList({ captureId, kind }: EvidenceListProps) {
  const [items, setItems] = useState<Record<string, unknown>[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    getSummary(captureId).then(summary => {
      setItems((summary[kind] as Record<string, unknown>[]) || []);
    }).catch(() => setItems([])).finally(() => setLoading(false));
  }, [captureId, kind]);

  const isFiles = kind === 'files';
  const title = isFiles ? 'Transferred Files' : 'Plaintext Credentials & Tokens';
  const Icon = isFiles ? FileText : Key;

  if (loading) return <div className="flex justify-center py-8"><Loader2 className="w-6 h-6 animate-spin text-shark-accent" /></div>;

  return (
    <div className="h-full overflow-y-auto p-4">
      <div className="flex items-center gap-2 mb-4">
        <Icon className="w-4 h-4 text-shark-accent" />
        <h2 className="text-sm font-bold">{title}</h2>
        <span className="text-xs text-shark-400">{items.length} found</span>
      </div>
      {items.length === 0 ? (
        <p className="text-shark-400 text-sm text-center py-8">No {isFiles ? 'transferred files' : 'plaintext credential evidence'} was detected.</p>
      ) : isFiles ? (
        <div className="panel overflow-x-auto">
          <table className="w-full text-xs font-mono">
            <thead><tr className="text-left text-shark-400 border-b border-shark-700">
              <th className="p-2">Filename</th><th className="p-2">Protocol</th><th className="p-2">MIME</th><th className="p-2">Size</th><th className="p-2">Packet</th><th className="p-2">Stream</th>
            </tr></thead>
            <tbody>{items.map((item, index) => (
              <tr key={`${item.packet_number}-${index}`} className="border-b border-shark-800/60 text-shark-200">
                <td className="p-2">{String(item.filename || 'unknown')}</td><td className="p-2">{String(item.protocol || 'unknown')}</td><td className="p-2 text-shark-400">{String(item.mime || '—')}</td><td className="p-2">{Number(item.size || 0).toLocaleString()}</td><td className="p-2">#{String(item.packet_number || '—')}</td><td className="p-2">{item.stream_id === null || item.stream_id === undefined ? '—' : `#${String(item.stream_id)}`}</td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      ) : (
        <div className="space-y-2">{items.map((item, index) => (
          <article key={`${item.packet_number}-${index}`} className="panel p-3 border-shark-danger/20">
            <div className="flex items-center gap-2 text-xs"><span className="font-semibold text-shark-danger">{String(item.type || 'credential')}</span><span className="text-shark-400">Packet #{String(item.packet_number || '—')}</span>{item.stream_id !== undefined && <span className="text-shark-500">Stream #{String(item.stream_id)}</span>}</div>
            <pre className="mt-2 whitespace-pre-wrap break-all text-[11px] text-shark-200 font-mono">{String(item.value || '')}</pre>
            <p className="mt-2 text-[10px] text-shark-400">FACT: The value was observed in unencrypted application-layer traffic. Verify scope and rotation requirements before disclosure.</p>
          </article>
        ))}</div>
      )}
    </div>
  );
}
