import { Activity, Loader2 } from 'lucide-react';
import { useEffect, useState } from 'react';
import { getTimeline } from '../services/api';

interface TimelineProps {
  captureId: string;
}

export default function Timeline({ captureId }: TimelineProps) {
  const [events, setEvents] = useState<Record<string, unknown>[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getTimeline(captureId).then(data => {
      setEvents(data.events);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, [captureId]);

  if (loading) return <div className="flex justify-center py-8"><Loader2 className="w-6 h-6 animate-spin text-shark-accent" /></div>;

  return (
    <div className="h-full overflow-y-auto p-4">
      <div className="flex items-center gap-2 mb-4">
        <Activity className="w-4 h-4 text-shark-accent" />
        <h2 className="text-sm font-bold">Investigation Timeline</h2>
      </div>

      {events.length === 0 ? (
        <p className="text-shark-400 text-sm">No timeline events available.</p>
      ) : (
        <div className="relative ml-4 border-l border-shark-700 space-y-3">
          {events.map((e, i) => (
            <div key={i} className="relative pl-6">
              <div className={`absolute -left-1.5 top-1.5 w-3 h-3 rounded-full border-2 border-shark-900
                ${e.severity === 'high' ? 'bg-shark-danger' : e.severity === 'medium' ? 'bg-shark-warning' : 'bg-shark-accent'}`}
              />
              <div className="text-xs">
                <span className="text-[10px] font-mono text-shark-400 uppercase">{e.event_type as string}</span>
                <p className="text-shark-200 mt-0.5">{e.description as string}</p>
                {e.packet_number && (
                  <span className="text-[10px] text-shark-500">Packet #{e.packet_number as number}</span>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
