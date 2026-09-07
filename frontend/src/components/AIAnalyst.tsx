import { Loader2, Send, Sparkles } from 'lucide-react';
import { useCallback, useRef, useState } from 'react';
import ReactMarkdown from 'react-markdown';
import { connectInvestigationWs, investigate } from '../services/api';
import type { SidebarView } from '../types';

interface Message {
  role: 'user' | 'assistant' | 'system';
  content: string;
  intent?: Record<string, unknown>;
  steps?: Record<string, unknown>[];
}

interface AIAnalystProps {
  captureId: string;
  mode: 'beginner' | 'expert';
  ctfMode: boolean;
  onFilterApplied: (filter: string) => void;
  onViewChange: (view: SidebarView) => void;
  onStreamSelect: (streamId: number) => void;
}

const SUGGESTIONS = [
  'What happened in this PCAP?',
  'Find the flag.',
  'Find credentials transmitted in plaintext.',
  'Show me suspicious HTTP requests.',
  'Find all HTTP POST requests.',
  'Show evidence of data exfiltration.',
];

const CTF_SUGGESTIONS = [
  'Find the flag.',
  'Search for base64 encoded data.',
  'Follow the suspicious TCP stream.',
  'Find hidden data in DNS queries.',
];

export default function AIAnalyst({
  captureId, mode, ctfMode, onFilterApplied, onViewChange, onStreamSelect,
}: AIAnalystProps) {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState<string[]>([]);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  const handleSubmit = useCallback(async (query: string) => {
    if (!query.trim() || loading) return;

    setMessages(prev => [...prev, { role: 'user', content: query }]);
    setInput('');
    setLoading(true);
    setProgress(['Understanding request...']);

    try {
      const ws = connectInvestigationWs(captureId, query, mode, (data) => {
        if (data.type === 'progress') {
          const step = data.step as string;
          const tool = data.tool as string;
          if (step === 'understanding') {
            setProgress(prev => [...prev, 'Intent parsed']);
            if (data.intent) {
              const intent = data.intent as Record<string, unknown>;
              if (intent.filter) onFilterApplied(intent.filter as string);
            }
          } else if (step === 'tool_call' && tool) {
            setProgress(prev => [...prev, `Running: ${tool}()`]);
          }
        } else if (data.type === 'complete') {
          setMessages(prev => [...prev, {
            role: 'assistant',
            content: data.response as string,
            intent: data.intent as Record<string, unknown>,
            steps: data.steps as Record<string, unknown>[],
          }]);
          setLoading(false);
          setProgress([]);
          scrollToBottom();
        } else if (data.type === 'error') {
          setMessages(prev => [...prev, {
            role: 'assistant',
            content: `Error: ${data.message}`,
          }]);
          setLoading(false);
          setProgress([]);
        }
      });

      setTimeout(() => {
        if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) return;
        investigate(captureId, query, mode).then(result => {
          setMessages(prev => [...prev, {
            role: 'assistant',
            content: result.response,
            intent: result.intent,
          }]);
          if (result.filter_applied) onFilterApplied(result.filter_applied);
          setLoading(false);
          setProgress([]);
          scrollToBottom();
        }).catch(err => {
          setMessages(prev => [...prev, {
            role: 'assistant',
            content: `Investigation failed: ${err.message}`,
          }]);
          setLoading(false);
          setProgress([]);
        });
      }, 3000);
    } catch (err) {
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: `Error: ${err instanceof Error ? err.message : 'Unknown error'}`,
      }]);
      setLoading(false);
      setProgress([]);
    }
  }, [captureId, mode, loading, onFilterApplied]);

  const suggestions = ctfMode ? CTF_SUGGESTIONS : SUGGESTIONS;

  return (
    <div className="h-full flex flex-col bg-shark-900 border-l border-shark-700">
      <div className="p-3 border-b border-shark-700 shrink-0">
        <div className="flex items-center gap-2">
          <Sparkles className="w-4 h-4 text-shark-accent" />
          <h2 className="text-sm font-bold">AI Analyst</h2>
        </div>
        <p className="text-[10px] text-shark-400 mt-0.5">Ask SharkAI anything about this capture</p>
      </div>

      <div className="flex-1 overflow-y-auto p-3 space-y-3">
        {messages.length === 0 && (
          <div className="space-y-2">
            <p className="text-xs text-shark-400">Try asking:</p>
            {suggestions.map((s) => (
              <button
                key={s}
                onClick={() => handleSubmit(s)}
                className="block w-full text-left px-3 py-2 text-xs bg-shark-800 hover:bg-shark-700
                           rounded-md border border-shark-600 transition-colors text-shark-200"
              >
                {s}
              </button>
            ))}
          </div>
        )}

        {messages.map((msg, i) => (
          <div key={i} className={`${msg.role === 'user' ? 'ml-4' : 'mr-4'}`}>
            <div className={`p-3 rounded-lg text-xs ${
              msg.role === 'user'
                ? 'bg-shark-accent/10 border border-shark-accent/20 text-shark-100'
                : 'bg-shark-800 border border-shark-700'
            }`}>
              {msg.role === 'assistant' ? (
                <div className="prose prose-invert prose-xs max-w-none">
                  <ReactMarkdown>{msg.content}</ReactMarkdown>
                </div>
              ) : (
                msg.content
              )}
            </div>
            {msg.intent && (
              <div className="mt-1 px-2 text-[10px] text-shark-400 font-mono">
                Intent: {(msg.intent as Record<string, string>).action || 'investigate'}
                {(msg.intent as Record<string, string>).filter && (
                  <span> | Filter: {(msg.intent as Record<string, string>).filter}</span>
                )}
              </div>
            )}
          </div>
        ))}

        {loading && (
          <div className="space-y-1">
            {progress.map((step, i) => (
              <div key={i} className="flex items-center gap-2 text-[10px] text-shark-400">
                {i === progress.length - 1 ? (
                  <Loader2 className="w-3 h-3 animate-spin text-shark-accent" />
                ) : (
                  <span className="text-shark-accent">✓</span>
                )}
                {step}
              </div>
            ))}
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      <div className="p-3 border-t border-shark-700 shrink-0">
        <form onSubmit={(e) => { e.preventDefault(); handleSubmit(input); }} className="flex gap-2">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder={ctfMode ? 'Find the flag...' : 'Ask SharkAI...'}
            className="input-field flex-1"
            disabled={loading}
          />
          <button type="submit" disabled={loading || !input.trim()} className="btn-primary px-3">
            <Send className="w-4 h-4" />
          </button>
        </form>
      </div>
    </div>
  );
}
