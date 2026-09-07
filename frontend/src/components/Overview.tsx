import { AlertTriangle, Loader2 } from 'lucide-react';
import { useEffect, useState } from 'react';
import { Bar, BarChart, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { getFindings, getSummary } from '../services/api';
import type { CaptureSummary, SidebarView } from '../types';

const COLORS = ['#00d4aa', '#3498db', '#ffa502', '#ff4757', '#9b59b6', '#6b8299'];

interface OverviewProps {
  capture: CaptureSummary;
  onViewChange: (view: SidebarView) => void;
}

export default function Overview({ capture, onViewChange }: OverviewProps) {
  const [summary, setSummary] = useState<Record<string, unknown> | null>(null);
  const [findings, setFindings] = useState<Record<string, unknown>[]>([]);
  const [loading, setLoading] = useState(capture.status !== 'complete');

  useEffect(() => {
    if (capture.status !== 'complete') return;
    Promise.all([
      getSummary(capture.id).catch(() => null),
      getFindings(capture.id).catch(() => ({ findings: [] })),
    ]).then(([s, f]) => {
      setSummary(s);
      setFindings(f?.findings || []);
      setLoading(false);
    });
  }, [capture.id, capture.status]);

  if (capture.status === 'analyzing' || capture.status === 'pending') {
    return (
      <div className="flex flex-col items-center justify-center h-full p-8">
        <Loader2 className="w-8 h-8 animate-spin text-shark-accent mb-4" />
        <p className="text-sm text-shark-200 mb-2">Analyzing capture...</p>
        <div className="w-64 h-2 bg-shark-800 rounded-full overflow-hidden">
          <div
            className="h-full bg-shark-accent transition-all duration-500 rounded-full"
            style={{ width: `${capture.progress}%` }}
          />
        </div>
        <p className="text-xs text-shark-400 mt-2 font-mono">{capture.progress.toFixed(0)}%</p>
        <div className="grid grid-cols-2 gap-4 mt-6 text-xs text-shark-400">
          <div>Packets indexed: <span className="text-shark-accent font-mono">{capture.packet_count.toLocaleString()}</span></div>
          <div>TCP streams: <span className="text-shark-accent font-mono">{capture.tcp_streams}</span></div>
          <div>HTTP sessions: <span className="text-shark-accent font-mono">{capture.http_sessions}</span></div>
          <div>DNS queries: <span className="text-shark-accent font-mono">{capture.dns_queries}</span></div>
        </div>
      </div>
    );
  }

  if (capture.status === 'error') {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="text-center">
          <AlertTriangle className="w-8 h-8 text-shark-danger mx-auto mb-2" />
          <p className="text-shark-danger">Analysis failed</p>
        </div>
      </div>
    );
  }

  const protocolStats = (summary?.protocol_stats || capture.summary?.protocol_stats || {}) as Record<string, number>;
  const topTalkers = (summary?.top_talkers || capture.summary?.top_talkers || {}) as {
    sources?: { ip: string; count: number }[];
    destinations?: { ip: string; count: number }[];
  };

  const pieData = Object.entries(protocolStats).map(([name, value]) => ({ name, value }));
  const topSrcData = (topTalkers.sources || []).slice(0, 8);

  const stats = [
    { label: 'Packets', value: capture.packet_count, view: 'packets' as SidebarView },
    { label: 'TCP Streams', value: capture.tcp_streams, view: 'streams' as SidebarView },
    { label: 'HTTP Requests', value: capture.http_sessions, view: 'http' as SidebarView },
    { label: 'DNS Queries', value: capture.dns_queries, view: 'dns' as SidebarView },
    { label: 'Files', value: capture.files_count, view: 'files' as SidebarView },
    { label: 'IOCs', value: capture.iocs_count, view: 'iocs' as SidebarView },
    { label: 'Findings', value: capture.findings_count, view: 'overview' as SidebarView },
    { label: 'Flags', value: capture.flags_count, view: 'flags' as SidebarView },
  ];

  return (
    <div className="h-full overflow-y-auto p-4 space-y-4">
      <div className="grid grid-cols-4 gap-3">
        {stats.map(({ label, value, view }) => (
          <button
            key={label}
            onClick={() => onViewChange(view)}
            className="panel p-3 text-left hover:border-shark-accent/30 transition-colors"
          >
            <p className="text-[10px] uppercase tracking-wider text-shark-400">{label}</p>
            <p className="text-xl font-bold font-mono text-shark-accent mt-1">
              {value.toLocaleString()}
            </p>
          </button>
        ))}
      </div>

      <div className="grid grid-cols-2 gap-4">
        {pieData.length > 0 && (
          <div className="panel p-4">
            <h3 className="text-xs uppercase tracking-wider text-shark-400 mb-3 font-semibold">Protocol Distribution</h3>
            <ResponsiveContainer width="100%" height={200}>
              <PieChart>
                <Pie data={pieData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={70} label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}>
                  {pieData.map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
                </Pie>
                <Tooltip contentStyle={{ background: '#151c2c', border: '1px solid #243044', fontSize: 11 }} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        )}

        {topSrcData.length > 0 && (
          <div className="panel p-4">
            <h3 className="text-xs uppercase tracking-wider text-shark-400 mb-3 font-semibold">Top Source IPs</h3>
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={topSrcData} layout="vertical">
                <XAxis type="number" tick={{ fontSize: 10, fill: '#6b8299' }} />
                <YAxis type="category" dataKey="ip" tick={{ fontSize: 9, fill: '#6b8299' }} width={100} />
                <Tooltip contentStyle={{ background: '#151c2c', border: '1px solid #243044', fontSize: 11 }} />
                <Bar dataKey="count" fill="#00d4aa" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>

      {findings.length > 0 && (
        <div className="panel p-4">
          <h3 className="text-xs uppercase tracking-wider text-shark-400 mb-3 font-semibold">Security Findings</h3>
          <div className="space-y-2">
            {findings.slice(0, 8).map((f, i) => (
              <div key={i} className="flex items-start gap-2 p-2 bg-shark-800/50 rounded text-xs">
                <span className={
                  f.severity === 'high' ? 'severity-high' :
                  f.severity === 'medium' ? 'severity-medium' : 'severity-low'
                }>
                  {f.severity === 'high' ? '🔴' : f.severity === 'medium' ? '🟠' : '🟡'}
                </span>
                <div>
                  <p className="font-medium text-shark-100">{f.title as string}</p>
                  <p className="text-shark-400 mt-0.5">{f.description as string}</p>
                  <p className="text-[10px] text-shark-500 mt-0.5">
                    Confidence: {((f.confidence as number) * 100).toFixed(0)}%
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
