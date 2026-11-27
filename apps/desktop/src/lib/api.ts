import { invoke, isTauri } from '@tauri-apps/api/core';

export type RoutingProfile = {
  id: string;
  name: string;
  status: 'unconfigured';
  unique_ip_required: boolean;
  kill_switch_required: boolean;
  tunnel_id?: string;
  created_at: string;
};

export type ProxyEndpoint = {
  id: string;
  name: string;
  protocol: 'socks5' | 'http-connect';
  listen_host: string;
  port: number;
  profile_id: string;
  status: 'draft';
  created_at: string;
};

export type Overview = {
  profiles: number;
  proxy_endpoints: number;
  active_proxies: number;
  connected_vpns: number;
  verified_exit_ips: number;
  network_enforcement_ready: boolean;
};

export type Health = {
  status: string;
  version: string;
  platform: string;
  uptime_seconds: number;
  mode: string;
  capabilities: Record<string, boolean>;
};

const ROOT = (import.meta.env.VITE_EGRESSLAB_API_URL || 'http://127.0.0.1:8787').replace(/\/$/, '');

type DesktopResponse<T> = {
  version: number;
  status: number;
  body: T;
};

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  // The desktop app talks to its controller only through the private IPC; it never falls back to HTTP.
  if (isTauri()) {
    let response: DesktopResponse<T | { error?: { code?: string; message?: string } }>;
    try {
      response = await invoke('controller_request', {
        request: {
          method: init.method ?? 'GET',
          path,
          body: init.body ? JSON.parse(String(init.body)) : null
        }
      });
    } catch (error) {
      // The supervisor rejects with its own message as a string.
      throw new Error(typeof error === 'string' ? error : 'Desktop controller unavailable');
    }

    if (response.status < 200 || response.status >= 300) {
      const body = response.body as { error?: { message?: string } };
      throw new Error(body?.error?.message ?? `Request failed (${response.status})`);
    }

    return response.body as T;
  }

  if (!import.meta.env.DEV) {
    throw new Error('Desktop runtime is required');
  }

  let response: Response;
  try {
    response = await fetch(`${ROOT}/api/v1${path}`, {
      ...init,
      headers: {
        ...(init.body !== undefined ? { 'Content-Type': 'application/json' } : {}),
        ...init.headers
      }
    });
  } catch {
    throw new Error('Cannot connect to local controller. Start Go controller on 127.0.0.1:8787.');
  }

  if (response.status === 204) return undefined as T;
  const data = await response.json();
  if (!response.ok) {
    throw new Error(data?.error?.message || `Request failed (${response.status})`);
  }
  return data as T;
}

export type AgentDiscovery = {
  os?: string;
  capabilities: Record<string, { status: string }>;
  links: { name: string; kind: string; category: string; operational_state: string }[];
  lab_namespaces: string[];
  other_namespaces: number;
  errors: string[];
};

export type AgentStatus = {
  id: string;
  status: 'online' | 'unreachable' | 'unauthorized' | 'invalid_response' | 'error' | string;
  mode?: string;
  network_ready: boolean;
  discovery?: AgentDiscovery;
};

// A WireGuard interface the agent saw on its host. EgressLab does not manage it (managed=false).
export type DiscoveredTunnel = {
  id: string;
  name: string;
  kind: string;
  operational_state: string;
  managed: boolean;
  source: string;
};

// A list read page by page and this window's writes take turns, so no write shifts a page under a read.
let turn: Promise<unknown> = Promise.resolve();

function inTurn<T>(run: () => Promise<T>): Promise<T> {
  const result = turn.then(run);
  turn = result.catch(() => undefined);
  return result;
}

// Lists are read page by page, so that no single reply outgrows the desktop IPC frame.
function listAll<T>(path: string): Promise<{ items: T[] }> {
  return inTurn(async () => {
    const items: T[] = [];
    let offset = 0;

    for (;;) {
      const page = await api<{ items: T[]; next_offset?: number }>(
        `${path}?limit=200&offset=${offset}`
      );
      items.push(...page.items);

      if (page.next_offset === undefined || page.next_offset <= offset) {
        return { items };
      }

      offset = page.next_offset;
    }
  });
}

// Agents and tunnels asked for together share one snapshot, and one round of agent calls.
let discovery: Promise<{ agents: AgentStatus[]; tunnels: DiscoveredTunnel[] }> | undefined;

function getDiscovery() {
  discovery ??= api<{ agents: AgentStatus[]; tunnels: DiscoveredTunnel[] }>('/discovery').finally(
    () => {
      discovery = undefined;
    }
  );

  return discovery;
}

export const getAgents = () => getDiscovery().then((d) => ({ items: d.agents }));
export const getTunnels = () => getDiscovery().then((d) => ({ items: d.tunnels }));
export const getProfiles = () => listAll<RoutingProfile>('/profiles');
export const getEndpoints = () => listAll<ProxyEndpoint>('/endpoints');
export const getOverview = () => api<Overview>('/overview');
export const getHealth = () => api<Health>('/health');
export const createProfile = (name: string) =>
  inTurn(() =>
    api<RoutingProfile>('/profiles', {
      method: 'POST',
      body: JSON.stringify({ name })
    })
  );
export const createEndpoint = (input: {
  name: string;
  protocol: string;
  port: number;
  profile_id: string;
}) =>
  inTurn(() => api<ProxyEndpoint>('/endpoints', { method: 'POST', body: JSON.stringify(input) }));
export const deleteProfile = (id: string) =>
  inTurn(() => api<void>(`/profiles/${encodeURIComponent(id)}`, { method: 'DELETE' }));
export const deleteEndpoint = (id: string) =>
  inTurn(() => api<void>(`/endpoints/${encodeURIComponent(id)}`, { method: 'DELETE' }));
