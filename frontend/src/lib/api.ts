import { AnalysisResponse, FilterRule, PacketSummary, PacketDetail, ChatMessage, CaptureHistoryItem } from '@/types';

export const API_BASE = (process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000').replace(/\/+$/, '');
const API_KEY = process.env.NEXT_PUBLIC_DPI_API_KEY;

const apiHeaders = (headers: HeadersInit = {}): HeadersInit => ({
  ...(API_KEY ? { 'X-API-Key': API_KEY } : {}),
  ...headers,
});

export async function getStatus() {
  const res = await fetch(`${API_BASE}/api/analyze/status`, { headers: apiHeaders() });
  if (!res.ok) throw new Error('Failed to fetch engine status');
  return res.json();
}

export async function getDatabaseRules(): Promise<FilterRule[]> {
  const res = await fetch(`${API_BASE}/api/rules`, { headers: apiHeaders() });
  if (!res.ok) throw new Error('Failed to fetch rules from database');
  return res.json();
}

export async function createDatabaseRule(rule: {
  type: string;
  value: string;
  action?: string;
  enabled?: boolean;
  description?: string;
}): Promise<FilterRule> {
  const res = await fetch(`${API_BASE}/api/rules`, {
    method: 'POST',
    headers: apiHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(rule),
  });
  if (!res.ok) throw new Error('Failed to create rule in database');
  return res.json();
}

export async function toggleDatabaseRule(ruleId: string): Promise<FilterRule> {
  const res = await fetch(`${API_BASE}/api/rules/${ruleId}/toggle`, {
    method: 'PATCH',
    headers: apiHeaders(),
  });
  if (!res.ok) throw new Error(`Failed to toggle rule ${ruleId}`);
  return res.json();
}

export async function deleteDatabaseRule(ruleId: string): Promise<{ status: string }> {
  const res = await fetch(`${API_BASE}/api/rules/${ruleId}`, {
    method: 'DELETE',
    headers: apiHeaders(),
  });
  if (!res.ok) throw new Error(`Failed to delete rule ${ruleId}`);
  return res.json();
}

export async function bulkSyncDatabaseRules(rules: FilterRule[]): Promise<FilterRule[]> {
  const res = await fetch(`${API_BASE}/api/rules/bulk`, {
    method: 'POST',
    headers: apiHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(rules),
  });
  if (!res.ok) throw new Error('Failed to sync rules to database');
  return res.json();
}

export async function getCaptureHistory(): Promise<CaptureHistoryItem[]> {
  const res = await fetch(`${API_BASE}/api/analyze/history`, { headers: apiHeaders() });
  if (!res.ok) throw new Error('Failed to fetch capture history from database');
  return res.json();
}

export async function getCaptureSession(analysisId: string): Promise<AnalysisResponse> {
  const res = await fetch(`${API_BASE}/api/analyze/session/${analysisId}`, { headers: apiHeaders() });
  if (!res.ok) throw new Error(`Failed to fetch capture session ${analysisId}`);
  return res.json();
}

export async function deleteCaptureSession(analysisId: string): Promise<{ status: string }> {
  const res = await fetch(`${API_BASE}/api/analyze/session/${analysisId}`, {
    method: 'DELETE',
    headers: apiHeaders(),
  });
  if (!res.ok) throw new Error(`Failed to delete capture session ${analysisId}`);
  return res.json();
}

export async function getChatHistory(analysisId: string): Promise<ChatMessage[]> {
  const res = await fetch(`${API_BASE}/api/chat/history/${analysisId}`, { headers: apiHeaders() });
  if (!res.ok) throw new Error('Failed to fetch chat history');
  return res.json();
}

export async function analyzeSample(rules?: FilterRule[]): Promise<AnalysisResponse> {
  const formData = new FormData();
  if (rules && rules.length > 0) {
    formData.append('rules_json', JSON.stringify(rules));
  }
  const res = await fetch(`${API_BASE}/api/analyze/sample`, {
    method: 'POST',
    body: formData,
    headers: apiHeaders(),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Analysis failed' }));
    throw new Error(err.detail || 'Sample analysis failed');
  }
  return res.json();
}

export async function uploadAndAnalyze(file: File, rules?: FilterRule[]): Promise<AnalysisResponse> {
  const formData = new FormData();
  formData.append('file', file);
  if (rules && rules.length > 0) {
    formData.append('rules_json', JSON.stringify(rules));
  }
  const res = await fetch(`${API_BASE}/api/analyze/upload`, {
    method: 'POST',
    body: formData,
    headers: apiHeaders(),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Upload failed' }));
    throw new Error(err.detail || 'PCAP upload failed');
  }
  return res.json();
}

export async function refilterCapture(analysisId: string, rules: FilterRule[]): Promise<AnalysisResponse> {
  const formData = new FormData();
  formData.append('analysis_id', analysisId);
  formData.append('rules_json', JSON.stringify(rules));

  const res = await fetch(`${API_BASE}/api/analyze/refilter`, {
    method: 'POST',
    body: formData,
    headers: apiHeaders(),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Refilter failed' }));
    throw new Error(err.detail || 'Refiltering failed');
  }
  return res.json();
}

export async function getPackets(params: {
  analysisId?: string;
  limit?: number;
  offset?: number;
  protocol?: string;
  search?: string;
}): Promise<{ packets: PacketSummary[]; total: number; limit: number; offset: number }> {
  const url = new URL(`${API_BASE}/api/packets`);
  if (params.analysisId) url.searchParams.set('analysis_id', params.analysisId);
  if (params.limit) url.searchParams.set('limit', params.limit.toString());
  if (params.offset !== undefined) url.searchParams.set('offset', params.offset.toString());
  if (params.protocol && params.protocol !== 'ALL') url.searchParams.set('protocol', params.protocol);
  if (params.search) url.searchParams.set('search', params.search);

  const res = await fetch(url.toString(), { headers: apiHeaders() });
  if (!res.ok) throw new Error('Failed to fetch packet list');
  return res.json();
}

export async function getPacketDetail(packetId: number, analysisId?: string): Promise<PacketDetail> {
  const url = new URL(`${API_BASE}/api/packets/${packetId}`);
  if (analysisId) url.searchParams.set('analysis_id', analysisId);

  const res = await fetch(url.toString(), { headers: apiHeaders() });
  if (!res.ok) throw new Error(`Failed to fetch details for packet #${packetId}`);
  return res.json();
}

export async function getRulePresets(): Promise<FilterRule[]> {
  const res = await fetch(`${API_BASE}/api/rules/presets`, { headers: apiHeaders() });
  if (!res.ok) throw new Error('Failed to fetch rule presets');
  return res.json();
}

export async function streamChatResponse(
  messages: ChatMessage[],
  analysisId: string | undefined,
  onToken: (token: string) => void,
  onDone: () => void,
  onError: (err: string) => void
) {
  try {
    const res = await fetch(`${API_BASE}/api/chat/stream`, {
      method: 'POST',
      headers: apiHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ messages, analysis_id: analysisId }),
    });

    if (!res.ok) {
      throw new Error(`Chat API error: ${res.statusText}`);
    }

    if (!res.body) {
      throw new Error('Readable stream not supported by browser.');
    }

    const reader = res.body.getReader();
    const decoder = new TextDecoder('utf-8');
    let buffer = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n\n');
      buffer = lines.pop() || '';

      for (const block of lines) {
        const trimmed = block.trim();
        if (!trimmed.startsWith('data: ')) continue;
        const dataStr = trimmed.substring(6).trim();

        if (dataStr === '[DONE]') {
          onDone();
          return;
        }

        try {
          const parsed = JSON.parse(dataStr);
          if (parsed.error) {
            onError(parsed.error);
            return;
          }
          if (parsed.token) {
            onToken(parsed.token);
          }
        } catch {
          // ignore malformed line
        }
      }
    }
    onDone();
  } catch (err: unknown) {
    onError(err instanceof Error ? err.message : 'Stream connection error');
  }
}
