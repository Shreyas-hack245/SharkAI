import { Copy } from 'lucide-react';
import { useState } from 'react';

interface HexViewerProps {
  hexDump: string;
}

export default function HexViewer({ hexDump }: HexViewerProps) {
  const [copied, setCopied] = useState(false);

  const copyToClipboard = () => {
    navigator.clipboard.writeText(hexDump);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  if (!hexDump) {
    return (
      <div className="p-3 text-xs text-shark-400">No hex data available</div>
    );
  }

  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center justify-between p-2 border-b border-shark-700">
        <span className="text-[10px] uppercase tracking-wider text-shark-400 font-semibold">Hex + ASCII</span>
        <button onClick={copyToClipboard} className="text-shark-400 hover:text-shark-accent transition-colors">
          <Copy className="w-3.5 h-3.5" />
        </button>
      </div>
      <pre className="flex-1 overflow-auto p-2 text-[11px] font-mono text-shark-300 leading-relaxed">
        {hexDump}
      </pre>
      {copied && <span className="text-[10px] text-shark-accent px-2 pb-1">Copied!</span>}
    </div>
  );
}
