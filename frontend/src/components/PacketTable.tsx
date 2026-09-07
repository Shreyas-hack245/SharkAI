import { ChevronLeft, ChevronRight, Filter, Loader2 } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import { getPackets } from '../services/api';
import type { PacketRow } from '../types';

interface PacketTableProps {
  captureId: string;
  onPacketSelect: (packet: PacketRow) => void;
  selectedPacket: PacketRow | null;
  displayFilter: string;
  onFilterChange: (filter: string) => void;
  searchQuery: string;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'text-red-400',
  high: 'text-shark-danger',
  medium: 'text-shark-warning',
  low: 'text-yellow-300',
  info: 'text-shark-300',
};

export default function PacketTable({
  captureId, onPacketSelect, selectedPacket, displayFilter, onFilterChange, searchQuery,
}: PacketTableProps) {
  const [packets, setPackets] = useState<PacketRow[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [localFilter, setLocalFilter] = useState(displayFilter);
  const pageSize = 100;

  const loadPackets = useCallback(async () => {
    setLoading(true);
    try {
      const data = await getPackets(captureId, page, pageSize, displayFilter, searchQuery);
      setPackets(data.packets);
      setTotal(data.total);
    } catch { /* ignore */ }
    setLoading(false);
  }, [captureId, page, displayFilter, searchQuery]);

  useEffect(() => { loadPackets(); }, [loadPackets]);
  useEffect(() => { setPage(1); }, [displayFilter, searchQuery]);

  const totalPages = Math.ceil(total / pageSize);

  const applyFilter = () => {
    onFilterChange(localFilter);
  };

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center gap-2 p-2 border-b border-shark-700 shrink-0">
        <Filter className="w-3.5 h-3.5 text-shark-400" />
        <input
          type="text"
          value={localFilter}
          onChange={(e) => setLocalFilter(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && applyFilter()}
          placeholder="Display filter: tcp, http, ip.addr == 10.0.0.1..."
          className="input-field flex-1"
        />
        <button onClick={applyFilter} className="btn-secondary text-xs">Apply</button>
        {displayFilter && (
          <button onClick={() => { setLocalFilter(''); onFilterChange(''); }} className="text-xs text-shark-400 hover:text-shark-200">
            Clear
          </button>
        )}
        <span className="text-[10px] text-shark-400 font-mono whitespace-nowrap">
          {total.toLocaleString()} packets
        </span>
      </div>

      <div className="flex-1 overflow-auto">
        {loading ? (
          <div className="flex items-center justify-center h-32">
            <Loader2 className="w-6 h-6 animate-spin text-shark-accent" />
          </div>
        ) : (
          <table className="w-full text-xs font-mono">
            <thead className="sticky top-0 bg-shark-800 z-10">
              <tr className="text-shark-400 text-left">
                <th className="px-2 py-1.5 w-16">No.</th>
                <th className="px-2 py-1.5 w-24">Time</th>
                <th className="px-2 py-1.5">Source</th>
                <th className="px-2 py-1.5">Destination</th>
                <th className="px-2 py-1.5 w-20">Protocol</th>
                <th className="px-2 py-1.5 w-16">Length</th>
                <th className="px-2 py-1.5">Info</th>
                <th className="px-2 py-1.5 w-14">Stream</th>
              </tr>
            </thead>
            <tbody>
              {packets.map((pkt) => (
                <tr
                  key={pkt.id}
                  onClick={() => onPacketSelect(pkt)}
                  className={`cursor-pointer border-b border-shark-800/50 hover:bg-shark-800/50 transition-colors
                    ${selectedPacket?.id === pkt.id ? 'bg-shark-accent/10' : ''}`}
                >
                  <td className="px-2 py-1 text-shark-accent">{pkt.frame_number}</td>
                  <td className="px-2 py-1 text-shark-400">{pkt.timestamp.toFixed(6)}</td>
                  <td className="px-2 py-1">{pkt.src}</td>
                  <td className="px-2 py-1">{pkt.dst}</td>
                  <td className="px-2 py-1">
                    <span className="px-1 py-0.5 bg-shark-700 rounded text-[10px]">{pkt.protocol}</span>
                  </td>
                  <td className="px-2 py-1 text-shark-400">{pkt.length}</td>
                  <td className="px-2 py-1 truncate max-w-xs">{pkt.info}</td>
                  <td className="px-2 py-1 text-shark-400">{pkt.stream ?? ''}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="flex items-center justify-between p-2 border-t border-shark-700 shrink-0">
        <button
          disabled={page <= 1}
          onClick={() => setPage(p => p - 1)}
          className="btn-secondary text-xs disabled:opacity-30"
        >
          <ChevronLeft className="w-3 h-3" />
        </button>
        <span className="text-[10px] text-shark-400 font-mono">
          Page {page} of {totalPages || 1}
        </span>
        <button
          disabled={page >= totalPages}
          onClick={() => setPage(p => p + 1)}
          className="btn-secondary text-xs disabled:opacity-30"
        >
          <ChevronRight className="w-3 h-3" />
        </button>
      </div>
    </div>
  );
}
