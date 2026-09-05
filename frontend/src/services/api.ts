import type {
  CaptureSummary,
  InvestigationResult,
  PacketDetail,
  PacketRow,
  ProgressUpdate,
} from '../types';

const API = '/api';

async function request<T>(url: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API}${url}`, options);
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || `HTTP ${res.status}`);
  }
  return res.json();
}

export async function uploadCapture(file: File): Promise<{ id: string; filename: string; status: string }> {
  const form = new FormData();
  form.append('file', file);
  return request('/captures/upload', { method: 'POST', body: form });
}

export async function getCapture(id: string): Promise<CaptureSummary> {
  return request(`/captures/${id}`);
}

export async function getCaptureProgress(id: string): Promise<ProgressUpdate> {
  return request(`/captures/${id}/progress`);
}

export async function getPackets(
  captureId: string,
  page = 1,
  pageSize = 100,
  filter = '',
  search = '',
): Promise<{ packets: PacketRow[]; total: number; page: number; page_size: number }> {
  const params = new URLSearchParams({ page: String(page), page_size: String(pageSize) });
  if (filter) params.set('filter', filter);
  if (search) params.set('search', search);
  return request(`/captures/${captureId}/packets?${params}`);
}

export async function getPacketDetail(captureId: string, frameNumber: number): Promise<PacketDetail> {
  return request(`/captures/${captureId}/packets/${frameNumber}`);
}

export async function getStreams(captureId: string): Promise<{ streams: Record<string, unknown>[]; count: number }> {
  return request(`/captures/${captureId}/streams`);
}

export async function followStream(captureId: string, streamId: number): Promise<Record<string, string>> {
  return request(`/captures/${captureId}/streams/${streamId}`);
}

export async function getSummary(captureId: string): Promise<Record<string, unknown>> {
  return request(`/captures/${captureId}/summary`);
}

export async function getFlags(captureId: string): Promise<{ flags: Record<string, unknown>[] }> {
  return request(`/captures/${captureId}/flags`);
}

export async function getFindings(captureId: string): Promise<{ findings: Record<string, unknown>[] }> {
  return request(`/captures/${captureId}/findings`);
}

export async function getIocs(captureId: string): Promise<{ iocs: Record<string, unknown>[] }> {
  return request(`/captures/${captureId}/iocs`);
}

export async function getTimeline(captureId: string): Promise<{ events: Record<string, unknown>[] }> {
  return request(`/captures/${captureId}/timeline`);
}

export async function getGraph(captureId: string): Promise<{ nodes: Record<string, unknown>[]; edges: Record<string, unknown>[] }> {
  return request(`/captures/${captureId}/graph`);
}

export async function investigate(captureId: string, query: string, mode = 'expert'): Promise<InvestigationResult> {
  return request('/ai/investigate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ capture_id: captureId, query, mode }),
  });
}

export async function globalSearch(captureId: string, query: string): Promise<Record<string, { count: number; items: unknown[] }>> {
  return request('/ai/search', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ capture_id: captureId, query, limit: 100 }),
  });
}

export async function checkHealth(): Promise<{ status: string; tshark_available: boolean }> {
  return request('/health');
}

export function connectProgressWs(captureId: string, onMessage: (data: ProgressUpdate) => void): WebSocket {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const ws = new WebSocket(`${protocol}//${window.location.host}/api/captures/${captureId}/ws`);
  ws.onmessage = (event) => {
    try {
      onMessage(JSON.parse(event.data));
    } catch { /* ignore */ }
  };
  return ws;
}

export function connectInvestigationWs(
  captureId: string,
  query: string,
  mode: string,
  onMessage: (data: Record<string, unknown>) => void,
): WebSocket {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const ws = new WebSocket(`${protocol}//${window.location.host}/api/ai/investigate/ws`);
  ws.onopen = () => {
    ws.send(JSON.stringify({ capture_id: captureId, query, mode }));
  };
  ws.onmessage = (event) => {
    try {
      onMessage(JSON.parse(event.data));
    } catch { /* ignore */ }
  };
  return ws;
}
