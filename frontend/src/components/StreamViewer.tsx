import { Loader2, Radio } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import { followStream, getStreams } from '../services/api';

interface StreamViewerProps {
  captureId: string;
  selectedStream: number | null;
  onStreamSelect: (id: number) => void;
}

export default function StreamViewer({ captureId, selectedStream, onStreamSelect }: StreamViewerProps) {
  const [streams, setStreams] = useState<Record<string, unknown>[]>([]);
  const [content, setContent] = useState<Record<string, string> | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getStreams(captureId).then(data => {
      setStreams(data.streams);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, [captureId]);

  const loadStream = useCallback(async (id: number) => {
    onStreamSelect(id);
    const data = await followStream(captureId, id);
    setContent(data);
  }, [captureId, onStreamSelect]);

  useEffect(() => {
    if (selectedStream !== null) loadStream(selectedStream);
  }, [selectedStream, loadStream]);

  if (loading) {
    return <div className="flex justify-center py-8"><Loader2 className="w-6 h-6 animate-spin text-shark-accent" /></div>;
  }

  return (
    <div className="h-full flex">
      <div className="w-72 border-r border-shark-700 overflow-y-auto shrink-0">
        <div className="p-2 border-b border-shark-700">
          <span className="text-xs text-shark-400">{streams.length} TCP streams</span>
        </div>
        {streams.map((s) => (
          <button
            key={s.stream_id as number}
            onClick={() => loadStream(s.stream_id as number)}
            className={`w-full text-left px-3 py-2 text-xs border-b border-shark-800/50 hover:bg-shark-800/50 transition-colors
              ${selectedStream === s.stream_id ? 'bg-shark-accent/10' : ''}`}
          >
            <div className="flex items-center gap-1.5">
              <Radio className="w-3 h-3 text-shark-accent" />
              <span className="font-mono text-shark-accent">#{s.stream_id as number}</span>
            </div>
            <div className="text-shark-400 mt-0.5 truncate">
              {s.src as string}:{s.src_port as number} → {s.dst as string}:{s.dst_port as number}
            </div>
            <div className="text-[10px] text-shark-500">{s.packets as number} pkts · {((s.bytes as number) / 1024).toFixed(1)} KB</div>
          </button>
        ))}
      </div>

      <div className="flex-1 overflow-auto p-3">
        {content ? (
          <div>
            <h3 className="text-sm font-bold text-shark-accent mb-2">
              TCP Stream #{selectedStream}
            </h3>
            <pre className="text-[11px] font-mono text-shark-300 whitespace-pre-wrap leading-relaxed bg-shark-800/50 p-3 rounded">
              {content.combined || content.client_to_server + '\n' + content.server_to_client}
            </pre>
          </div>
        ) : (
          <p className="text-shark-400 text-sm text-center py-8">Select a stream to follow</p>
        )}
      </div>
    </div>
  );
}
