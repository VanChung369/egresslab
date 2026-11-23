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

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
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

export const getAgents = () => api<{ items: AgentStatus[] }>('/agents');
export const getTunnels = () => api<{ items: DiscoveredTunnel[] }>('/tunnels');
export const getProfiles = () => api<{ items: RoutingProfile[] }>('/profiles');
export const getEndpoints = () => api<{ items: ProxyEndpoint[] }>('/endpoints');
export const getOverview = () => api<Overview>('/overview');
export const getHealth = () => api<Health>('/health');
export const createProfile = (name: string) =>
  api<RoutingProfile>('/profiles', {
    method: 'POST',
    body: JSON.stringify({ name })
  });
export const createEndpoint = (input: {
  name: string;
  protocol: string;
  port: number;
  profile_id: string;
}) => api<ProxyEndpoint>('/endpoints', { method: 'POST', body: JSON.stringify(input) });
export const deleteProfile = (id: string) =>
  api<void>(`/profiles/${encodeURIComponent(id)}`, { method: 'DELETE' });
export const deleteEndpoint = (id: string) =>
  api<void>(`/endpoints/${encodeURIComponent(id)}`, { method: 'DELETE' });
