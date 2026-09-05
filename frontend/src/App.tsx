import {
  Activity, BarChart3, ChevronRight, Copy, Download, FileText, Flag,
  Globe, Hash, Key, Layers, Network, Package, Radio, Search, Shield,
  Upload, Zap,
} from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import { Panel, PanelGroup, PanelResizeHandle } from 'react-resizable-panels';
import AIAnalyst from './components/AIAnalyst';
import CommandPalette from './components/CommandPalette';
import Dashboard from './components/Dashboard';
import DnsView from './components/DnsView';
import FlagHunter from './components/FlagHunter';
import Header from './components/Header';
import HexViewer from './components/HexViewer';
import HttpView from './components/HttpView';
import NetworkGraph from './components/NetworkGraph';
import Overview from './components/Overview';
import PacketDetails from './components/PacketDetails';
import PacketTable from './components/PacketTable';
import Sidebar from './components/Sidebar';
import StreamViewer from './components/StreamViewer';
import Timeline from './components/Timeline';
import UploadZone from './components/UploadZone';
import { getCapture, getPacketDetail } from './services/api';
import type { CaptureSummary, PacketDetail, PacketRow, SidebarView } from './types';

export default function App() {
  const [capture, setCapture] = useState<CaptureSummary | null>(null);
  const [activeView, setActiveView] = useState<SidebarView>('overview');
  const [selectedPacket, setSelectedPacket] = useState<PacketRow | null>(null);
  const [packetDetail, setPacketDetail] = useState<PacketDetail | null>(null);
  const [displayFilter, setDisplayFilter] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [mode, setMode] = useState<'beginner' | 'expert'>('expert');
  const [ctfMode, setCtfMode] = useState(false);
  const [showCommandPalette, setShowCommandPalette] = useState(false);
  const [selectedStream, setSelectedStream] = useState<number | null>(null);

  const handleCaptureLoaded = useCallback((cap: CaptureSummary) => {
    setCapture(cap);
    setActiveView('overview');
    setSelectedPacket(null);
    setPacketDetail(null);
  }, []);

  const handlePacketSelect = useCallback(async (packet: PacketRow) => {
    setSelectedPacket(packet);
    if (capture) {
      try {
        const detail = await getPacketDetail(capture.id, packet.frame_number);
        setPacketDetail(detail);
      } catch {
        setPacketDetail(null);
      }
    }
  }, [capture]);

  useEffect(() => {
    if (!capture || capture.status === 'complete' || capture.status === 'error') return;
    const interval = setInterval(async () => {
      try {
        const updated = await getCapture(capture.id);
        setCapture(updated);
      } catch { /* ignore */ }
    }, 2000);
    return () => clearInterval(interval);
  }, [capture?.id, capture?.status]);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setShowCommandPalette(true);
      }
      if (e.key === 'Escape') {
        setShowCommandPalette(false);
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

  const handleCommand = useCallback((command: string) => {
    setShowCommandPalette(false);
    if (!capture) return;

    const cmdMap: Record<string, SidebarView> = {
      '/summary': 'overview',
      '/streams': 'streams',
      '/http': 'http',
      '/dns': 'dns',
      '/files': 'files',
      '/flags': 'flags',
      '/iocs': 'iocs',
      '/timeline': 'timeline',
      '/graph': 'graph',
    };

    const view = cmdMap[command.split(' ')[0]];
    if (view) setActiveView(view);
  }, [capture]);

  if (!capture) {
    return (
      <div className="min-h-screen flex flex-col">
        <Header mode={mode} setMode={setMode} ctfMode={ctfMode} setCtfMode={setCtfMode} />
        <UploadZone onCaptureLoaded={handleCaptureLoaded} />
      </div>
    );
  }

  return (
    <div className="h-screen flex flex-col overflow-hidden">
      <Header
        capture={capture}
        mode={mode}
        setMode={setMode}
        ctfMode={ctfMode}
        setCtfMode={setCtfMode}
        onSearch={setSearchQuery}
      />

      <PanelGroup direction="horizontal" className="flex-1">
        <Panel defaultSize={15} minSize={10} maxSize={25}>
          <Sidebar
            activeView={activeView}
            onViewChange={setActiveView}
            capture={capture}
          />
        </Panel>

        <PanelResizeHandle className="w-1 bg-shark-800 hover:bg-shark-accent/30 transition-colors" />

        <Panel defaultSize={55} minSize={30}>
          <div className="h-full flex flex-col">
            {activeView === 'overview' && <Overview capture={capture} onViewChange={setActiveView} />}
            {activeView === 'packets' && (
              <PacketTable
                captureId={capture.id}
                onPacketSelect={handlePacketSelect}
                selectedPacket={selectedPacket}
                displayFilter={displayFilter}
                onFilterChange={setDisplayFilter}
                searchQuery={searchQuery}
              />
            )}
            {activeView === 'streams' && (
              <StreamViewer
                captureId={capture.id}
                selectedStream={selectedStream}
                onStreamSelect={setSelectedStream}
              />
            )}
            {activeView === 'http' && <HttpView captureId={capture.id} />}
            {activeView === 'dns' && <DnsView captureId={capture.id} />}
            {activeView === 'flags' && <FlagHunter captureId={capture.id} />}
            {activeView === 'timeline' && <Timeline captureId={capture.id} />}
            {activeView === 'graph' && <NetworkGraph captureId={capture.id} />}
            {activeView === 'iocs' && <Dashboard capture={capture} view="iocs" />}
            {!['overview', 'packets', 'streams', 'http', 'dns', 'flags', 'timeline', 'graph', 'iocs'].includes(activeView) && (
              <Overview capture={capture} onViewChange={setActiveView} />
            )}

            {selectedPacket && packetDetail && activeView === 'packets' && (
              <div className="border-t border-shark-700 max-h-[40%] overflow-auto">
                <PanelGroup direction="horizontal">
                  <Panel defaultSize={60}>
                    <PacketDetails detail={packetDetail} mode={mode} />
                  </Panel>
                  <PanelResizeHandle className="w-1 bg-shark-800" />
                  <Panel defaultSize={40}>
                    <HexViewer hexDump={packetDetail.hex_dump} />
                  </Panel>
                </PanelGroup>
              </div>
            )}
          </div>
        </Panel>

        <PanelResizeHandle className="w-1 bg-shark-800 hover:bg-shark-accent/30 transition-colors" />

        <Panel defaultSize={30} minSize={20} maxSize={45}>
          <AIAnalyst
            captureId={capture.id}
            mode={mode}
            ctfMode={ctfMode}
            onFilterApplied={setDisplayFilter}
            onViewChange={setActiveView}
            onStreamSelect={(id) => { setSelectedStream(id); setActiveView('streams'); }}
          />
        </Panel>
      </PanelGroup>

      {showCommandPalette && (
        <CommandPalette
          onClose={() => setShowCommandPalette(false)}
          onCommand={handleCommand}
          captureId={capture.id}
        />
      )}
    </div>
  );
}
