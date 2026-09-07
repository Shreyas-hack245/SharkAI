import { AlertTriangle, FileUp, Loader2, Upload } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import { checkHealth, getCapture, uploadCapture } from '../services/api';
import type { CaptureSummary } from '../types';

interface UploadZoneProps {
  onCaptureLoaded: (capture: CaptureSummary) => void;
}

export default function UploadZone({ onCaptureLoaded }: UploadZoneProps) {
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState('');
  const [tsharkOk, setTsharkOk] = useState<boolean | null>(null);
  const [dragOver, setDragOver] = useState(false);

  useEffect(() => {
    checkHealth().then(h => setTsharkOk(h.tshark_available)).catch(() => setTsharkOk(false));
  }, []);

  const handleFile = useCallback(async (file: File) => {
    setUploading(true);
    setError('');
    try {
      const result = await uploadCapture(file);
      const capture = await getCapture(result.id);
      onCaptureLoaded(capture);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Upload failed');
    } finally {
      setUploading(false);
    }
  }, [onCaptureLoaded]);

  const onDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files[0];
    if (file) handleFile(file);
  }, [handleFile]);

  return (
    <div className="flex-1 flex items-center justify-center p-8">
      <div className="max-w-lg w-full space-y-6">
        <div className="text-center space-y-2">
          <span className="text-6xl">🦈</span>
          <h2 className="text-2xl font-bold text-shark-50">
            Shark<span className="text-shark-accent">AI</span>
          </h2>
          <p className="text-shark-400 text-sm">AI-Powered Network Forensics & CTF Analyzer</p>
        </div>

        {tsharkOk === false && (
          <div className="flex items-start gap-2 p-3 bg-shark-warning/10 border border-shark-warning/30 rounded-lg text-sm">
            <AlertTriangle className="w-4 h-4 text-shark-warning shrink-0 mt-0.5" />
            <div>
              <p className="text-shark-warning font-medium">tshark not detected</p>
              <p className="text-shark-400 text-xs mt-1">
                Install Wireshark for full packet analysis capabilities.
              </p>
            </div>
          </div>
        )}

        <div
          onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
          onDragLeave={() => setDragOver(false)}
          onDrop={onDrop}
          className={`border-2 border-dashed rounded-xl p-12 text-center transition-colors cursor-pointer
            ${dragOver ? 'border-shark-accent bg-shark-accent/5' : 'border-shark-600 hover:border-shark-500'}`}
          onClick={() => document.getElementById('file-input')?.click()}
        >
          <input
            id="file-input"
            type="file"
            accept=".pcap,.pcapng,.cap"
            className="hidden"
            onChange={(e) => e.target.files?.[0] && handleFile(e.target.files[0])}
          />
          {uploading ? (
            <Loader2 className="w-10 h-10 mx-auto text-shark-accent animate-spin" />
          ) : (
            <Upload className="w-10 h-10 mx-auto text-shark-400 mb-3" />
          )}
          <p className="text-shark-200 font-medium">
            {uploading ? 'Uploading & analyzing...' : 'Drop PCAP file here'}
          </p>
          <p className="text-shark-400 text-xs mt-1">.pcap, .pcapng, .cap — up to 500 MB</p>
        </div>

        {error && (
          <p className="text-shark-danger text-sm text-center">{error}</p>
        )}

        <div className="grid grid-cols-3 gap-3 text-center text-xs text-shark-400">
          <div className="panel p-3">
            <p className="text-shark-accent font-bold text-lg">AI</p>
            <p>Natural language queries</p>
          </div>
          <div className="panel p-3">
            <p className="text-shark-accent font-bold text-lg">CTF</p>
            <p>Flag hunting engine</p>
          </div>
          <div className="panel p-3">
            <p className="text-shark-accent font-bold text-lg">DFIR</p>
            <p>Evidence-based analysis</p>
          </div>
        </div>
      </div>
    </div>
  );
}
