import {
  Activity, BarChart3, FileText, Flag, Globe, Hash, Key, Layers,
  Network, Package, Radio, Shield,
} from 'lucide-react';
import type { CaptureSummary, SidebarView } from '../types';

const NAV_ITEMS: { id: SidebarView; label: string; icon: typeof Activity }[] = [
  { id: 'overview', label: 'Overview', icon: BarChart3 },
  { id: 'packets', label: 'Packets', icon: Layers },
  { id: 'streams', label: 'TCP Streams', icon: Radio },
  { id: 'http', label: 'HTTP', icon: Globe },
  { id: 'dns', label: 'DNS', icon: Network },
  { id: 'files', label: 'Files', icon: Package },
  { id: 'credentials', label: 'Credentials', icon: Key },
  { id: 'flags', label: 'Flags', icon: Flag },
  { id: 'iocs', label: 'IOCs', icon: Shield },
  { id: 'timeline', label: 'Timeline', icon: Activity },
  { id: 'graph', label: 'Graph', icon: Hash },
];

interface SidebarProps {
  activeView: SidebarView;
  onViewChange: (view: SidebarView) => void;
  capture: CaptureSummary;
}

export default function Sidebar({ activeView, onViewChange, capture }: SidebarProps) {
  const counts: Partial<Record<SidebarView, number>> = {
    packets: capture.packet_count,
    streams: capture.tcp_streams,
    http: capture.http_sessions,
    dns: capture.dns_queries,
    files: capture.files_count,
    flags: capture.flags_count,
    iocs: capture.iocs_count,
  };

  return (
    <nav className="h-full bg-shark-900 border-r border-shark-700 overflow-y-auto">
      <div className="p-3">
        <p className="text-[10px] uppercase tracking-wider text-shark-400 mb-2 font-semibold">Analysis</p>
        <ul className="space-y-0.5">
          {NAV_ITEMS.map(({ id, label, icon: Icon }) => (
            <li key={id}>
              <button
                onClick={() => onViewChange(id)}
                className={`w-full flex items-center gap-2.5 px-2.5 py-1.5 rounded text-xs transition-colors
                  ${activeView === id
                    ? 'bg-shark-accent/10 text-shark-accent border border-shark-accent/20'
                    : 'text-shark-300 hover:bg-shark-800 hover:text-shark-100'
                  }`}
              >
                <Icon className="w-3.5 h-3.5 shrink-0" />
                <span className="flex-1 text-left">{label}</span>
                {counts[id] !== undefined && counts[id]! > 0 && (
                  <span className="text-[10px] font-mono text-shark-400">
                    {counts[id]!.toLocaleString()}
                  </span>
                )}
              </button>
            </li>
          ))}
        </ul>
      </div>

      {capture.findings_count > 0 && (
        <div className="p-3 border-t border-shark-700">
          <p className="text-[10px] uppercase tracking-wider text-shark-warning mb-1 font-semibold">
            Findings
          </p>
          <p className="text-lg font-bold text-shark-warning">{capture.findings_count}</p>
        </div>
      )}
    </nav>
  );
}
