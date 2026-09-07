import { ChevronDown, ChevronRight } from 'lucide-react';
import { useState } from 'react';
import type { LayerNode, PacketDetail } from '../types';

interface PacketDetailsProps {
  detail: PacketDetail;
  mode: 'beginner' | 'expert';
}

function LayerTree({ layer, depth = 0 }: { layer: LayerNode; depth?: number }) {
  const [expanded, setExpanded] = useState(depth < 2);

  return (
    <div className="ml-3">
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex items-center gap-1 text-xs hover:text-shark-accent transition-colors py-0.5"
      >
        {expanded ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
        <span className="font-medium text-shark-accent">{layer.name}</span>
      </button>
      {expanded && (
        <div className="ml-4 border-l border-shark-700 pl-2">
          {Object.entries(layer.fields).map(([key, value]) => (
            <div key={key} className="text-[11px] py-0.5 font-mono">
              <span className="text-shark-400">{key}: </span>
              <span className="text-shark-200">{String(value)}</span>
            </div>
          ))}
          {layer.children?.map((child, i) => (
            <LayerTree key={i} layer={child} depth={depth + 1} />
          ))}
        </div>
      )}
    </div>
  );
}

export default function PacketDetails({ detail, mode }: PacketDetailsProps) {
  return (
    <div className="p-3 h-full overflow-auto">
      <div className="flex items-center gap-3 mb-3">
        <h3 className="text-sm font-bold text-shark-accent">
          Packet #{detail.frame_number}
        </h3>
        <span className="text-[10px] text-shark-400 font-mono">
          t={detail.timestamp.toFixed(6)}
        </span>
      </div>

      <div className="space-y-1">
        {detail.layers.map((layer, i) => (
          <LayerTree key={i} layer={layer} />
        ))}
      </div>

      {mode === 'beginner' && detail.layers.length > 0 && (
        <div className="mt-3 p-2 bg-shark-800/50 rounded text-xs text-shark-300">
          This packet contains {detail.layers.length} protocol layer(s).
          Expand each layer to see detailed field values.
        </div>
      )}
    </div>
  );
}
