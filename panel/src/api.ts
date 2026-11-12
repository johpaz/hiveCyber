const KEY = 'hc_token';

export const getToken = () => sessionStorage.getItem(KEY);
export const setToken = (t: string) => sessionStorage.setItem(KEY, t.trim());
export const clearToken = () => sessionStorage.removeItem(KEY);

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch('/api' + path, {
    ...init,
    headers: {
      'content-type': 'application/json',
      authorization: `Bearer ${getToken() ?? ''}`,
      ...(init.headers ?? {}),
    },
  });
  if (res.status === 401) {
    clearToken();
    window.dispatchEvent(new Event('hc:unauth'));
    throw new ApiError(401, 'token inválido');
  }
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new ApiError(res.status, body?.error ?? res.statusText);
  return body as T;
}

/** Opens the chat WebSocket using a one-shot ticket (browsers can't set WS headers). */
export async function openChat(agent: string, thread?: string, rehydrate = false): Promise<WebSocket> {
  const { ticket } = await api<{ ticket: string }>('/ws-ticket', { method: 'POST' });
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const q = new URLSearchParams({ ticket, ...(thread ? { thread } : {}), ...(rehydrate ? { rehydrate: '1' } : {}) });
  return new WebSocket(`${proto}://${location.host}/api/chat/${encodeURIComponent(agent)}?${q}`);
}
