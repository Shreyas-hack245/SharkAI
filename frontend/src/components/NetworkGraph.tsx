import { Hash, Loader2 } from 'lucide-react';
import { useEffect, useState } from 'react';
import { getGraph } from '../services/api';

interface NetworkGraphProps {
  captureId: string;
}

const NODE_COLORS: Record<string, string> = {
  ip: '#00d4aa',
  domain: '#3498db',
  stream: '#ffa502',
  url: '#9b59b6',
  file: '#ff4757',
};

export default function NetworkGraph({ captureId }: NetworkGraphProps) {
  const [graph, setGraph] = useState<{ nodes: Record<string, unknown>[]; edges: Record<string, unknown>[] } | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getGraph(captureId).then(data => {
      setGraph(data);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, [captureId]);

  if (loading) return <div className="flex justify-center py-8"><Loader2 className="w-6 h-6 animate-spin text-shark-accent" /></div>;

  if (!graph || graph.nodes.length === 0) {
    return <p className="text-shark-400 text-sm text-center py-8">No graph data available.</p>;
  }

  return (
    <div className="h-full overflow-y-auto p-4">
      <div className="flex items-center gap-2 mb-4">
        <Hash className="w-4 h-4 text-shark-accent" />
        <h2 className="text-sm font-bold">Network Graph</h2>
        <span className="text-xs text-shark-400">{graph.nodes.length} nodes · {graph.edges.length} edges</span>
      </div>

      <div className="panel p-4 font-mono text-xs space-y-1">
        {graph.nodes.map((node) => (
          <div key={node.id as string} className="flex items-center gap-2 py-0.5">
            <span
              className="w-2 h-2 rounded-full shrink-0"
              style={{ background: NODE_COLORS[node.type as string] || '#6b8299' }}
            />
            <span className="text-shark-400">[{node.type as string}]</span>
            <span className="text-shark-200">{node.label as string}</span>
          </div>
        ))}
      </div>

      <div className="mt-4 panel p-4">
        <h3 className="text-[10px] uppercase text-shark-400 mb-2">Connections</h3>
        {graph.edges.map((edge, i) => (
          <div key={i} className="text-[11px] text-shark-300 py-0.5">
            {(edge.source as string).replace(/^\w+:/, '')} → {(edge.target as string).replace(/^\w+:/, '')}
            <span className="text-shark-500 ml-1">({edge.label as string})</span>
          </div>
        ))}
      </div>
    </div>
  );
}
