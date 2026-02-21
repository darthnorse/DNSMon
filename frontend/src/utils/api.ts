import axios from 'axios';
import type {
  Query,
  AlertRule,
  AlertRuleCreate,
  Stats,
  QuerySearchParams,
  SettingsResponse,
  PiholeServer,
  PiholeServerCreate,
  DomainEntry,
  Statistics,
  StatisticsParams,
  StatisticsClientsParams,
  ClientInfo,
  BlockingStatusResponse,
  BlockingSetRequest,
  BlockingSetResponse,
  User,
  AuthCheckResponse,
  LoginRequest,
  SetupRequest,
  UserCreate,
  UserUpdate,
  OIDCProviderPublic,
  OIDCProvider,
  OIDCProviderCreate,
  OIDCProviderUpdate,
  NotificationChannel,
  NotificationChannelCreate,
  NotificationChannelUpdate,
  TemplateVariablesResponse,
  ChannelTypesResponse,
  ApiKey,
  ApiKeyCreate,
  ApiKeyCreateResponse,
  SyncPreview,
  SyncHistoryEntry,
} from '../types';

const API_BASE_URL = '/api';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  withCredentials: true,
});

// 401 response interceptor - redirect to login when session expires
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      // Check if we're not already on login or setup page
      const currentPath = window.location.pathname;
      if (currentPath !== '/login' && currentPath !== '/setup') {
        window.location.href = '/login';
      }
    }
    return Promise.reject(error);
  }
);

export const queryApi = {
  search: async (params: QuerySearchParams): Promise<Query[]> => {
    const response = await api.get<Query[]>('/queries', { params });
    return response.data;
  },

  count: async (params: QuerySearchParams): Promise<number> => {
    const response = await api.get<{ count: number }>('/queries/count', { params });
    return response.data.count;
  },
};

export const statsApi = {
  get: async (): Promise<Stats> => {
    const response = await api.get<Stats>('/stats');
    return response.data;
  },
};

export const statisticsApi = {
  get: async (params?: StatisticsParams): Promise<Statistics> => {
    const response = await api.get<Statistics>('/statistics', { params });
    return response.data;
  },
  getClients: async (params?: StatisticsClientsParams): Promise<ClientInfo[]> => {
    const response = await api.get<ClientInfo[]>('/statistics/clients', { params });
    return response.data;
  },
};

export const alertRuleApi = {
  getAll: async (): Promise<AlertRule[]> => {
    const response = await api.get<AlertRule[]>('/alert-rules');
    return response.data;
  },

  create: async (rule: AlertRuleCreate): Promise<AlertRule> => {
    const response = await api.post<AlertRule>('/alert-rules', rule);
    return response.data;
  },

  update: async (id: number, rule: AlertRuleCreate): Promise<AlertRule> => {
    const response = await api.put<AlertRule>(`/alert-rules/${id}`, rule);
    return response.data;
  },

  delete: async (id: number): Promise<void> => {
    await api.delete(`/alert-rules/${id}`);
  },
};

export const settingsApi = {
  get: async (): Promise<SettingsResponse> => {
    const response = await api.get<SettingsResponse>('/settings');
    return response.data;
  },

  updateSetting: async (key: string, value: string): Promise<{ message: string; setting: unknown; requires_restart: boolean }> => {
    const response = await api.put<{ message: string; setting: unknown; requires_restart: boolean }>(`/settings/${key}`, { value });
    return response.data;
  },

  restart: async (): Promise<void> => {
    await api.post('/settings/restart');
  },

  servers: {
    getAll: async (): Promise<PiholeServer[]> => {
      const response = await api.get<{ servers: PiholeServer[] }>('/settings/pihole-servers');
      return response.data.servers;
    },

    create: async (server: PiholeServerCreate): Promise<PiholeServer> => {
      const response = await api.post<{ server: PiholeServer }>('/settings/pihole-servers', server);
      return response.data.server;
    },

    update: async (id: number, server: Partial<PiholeServerCreate>): Promise<PiholeServer> => {
      const response = await api.put<{ server: PiholeServer }>(`/settings/pihole-servers/${id}`, server);
      return response.data.server;
    },

    delete: async (id: number): Promise<void> => {
      await api.delete(`/settings/pihole-servers/${id}`);
    },

    test: async (server: PiholeServerCreate): Promise<{ success: boolean; message: string }> => {
      const response = await api.post<{ success: boolean; message: string }>('/settings/pihole-servers/test', server);
      return response.data;
    },
  },
};

export const syncApi = {
  preview: async (): Promise<SyncPreview> => {
    const response = await api.get<SyncPreview>('/sync/preview');
    return response.data;
  },

  execute: async (): Promise<{ message: string; sync_history_ids: number[]; sync_history_id: number | null }> => {
    const response = await api.post<{ message: string; sync_history_ids: number[]; sync_history_id: number | null }>('/sync/execute');
    return response.data;
  },

  getHistory: async (limit: number = 20): Promise<SyncHistoryEntry[]> => {
    const response = await api.get<{ history: SyncHistoryEntry[] }>('/sync/history', { params: { limit } });
    return response.data.history;
  },
};

export const domainApi = {
  whitelist: async (domain: string): Promise<void> => {
    await api.post('/domains/whitelist', { domain });
  },

  blacklist: async (domain: string): Promise<void> => {
    await api.post('/domains/blacklist', { domain });
  },

  getWhitelist: async (): Promise<DomainEntry[]> => {
    const response = await api.get<{ domains: DomainEntry[] }>('/domains/whitelist');
    return response.data.domains;
  },

  getBlacklist: async (): Promise<DomainEntry[]> => {
    const response = await api.get<{ domains: DomainEntry[] }>('/domains/blacklist');
    return response.data.domains;
  },

  getRegexWhitelist: async (): Promise<DomainEntry[]> => {
    const response = await api.get<{ domains: DomainEntry[] }>('/domains/regex-whitelist');
    return response.data.domains;
  },

  getRegexBlacklist: async (): Promise<DomainEntry[]> => {
    const response = await api.get<{ domains: DomainEntry[] }>('/domains/regex-blacklist');
    return response.data.domains;
  },

  addToRegexWhitelist: async (pattern: string): Promise<void> => {
    await api.post('/domains/regex-whitelist', { domain: pattern });
  },

  addToRegexBlacklist: async (pattern: string): Promise<void> => {
    await api.post('/domains/regex-blacklist', { domain: pattern });
  },

  removeFromWhitelist: async (domain: string): Promise<void> => {
    await api.delete(`/domains/whitelist/${encodeURIComponent(domain)}`);
  },

  removeFromBlacklist: async (domain: string): Promise<void> => {
    await api.delete(`/domains/blacklist/${encodeURIComponent(domain)}`);
  },

  removeFromRegexWhitelist: async (pattern: string): Promise<void> => {
    await api.delete(`/domains/regex-whitelist/${encodeURIComponent(pattern)}`);
  },

  removeFromRegexBlacklist: async (pattern: string): Promise<void> => {
    await api.delete(`/domains/regex-blacklist/${encodeURIComponent(pattern)}`);
  },
};

export const blockingApi = {
  getStatus: async (): Promise<BlockingStatusResponse> => {
    const response = await api.get<BlockingStatusResponse>('/blocking/status');
    return response.data;
  },

  setBlocking: async (serverId: number, request: BlockingSetRequest): Promise<BlockingSetResponse> => {
    const response = await api.post<BlockingSetResponse>(`/blocking/${serverId}`, request);
    return response.data;
  },

  setAllBlocking: async (request: BlockingSetRequest): Promise<BlockingSetResponse> => {
    const response = await api.post<BlockingSetResponse>('/blocking/all', request);
    return response.data;
  },
};

// ============================================================================
// Authentication API
// ============================================================================

export const authApi = {
  check: async (): Promise<AuthCheckResponse> => {
    const response = await api.get<AuthCheckResponse>('/auth/check');
    return response.data;
  },

  setup: async (data: SetupRequest): Promise<User> => {
    const response = await api.post<{ message: string; user: User }>('/auth/setup', data);
    return response.data.user;
  },

  login: async (data: LoginRequest): Promise<User> => {
    const response = await api.post<{ message: string; user: User }>('/auth/login', data);
    return response.data.user;
  },

  logout: async (): Promise<void> => {
    await api.post('/auth/logout');
  },

  getMe: async (): Promise<User> => {
    const response = await api.get<User>('/auth/me');
    return response.data;
  },

  getOIDCProviders: async (): Promise<OIDCProviderPublic[]> => {
    const response = await api.get<OIDCProviderPublic[]>('/auth/oidc/providers');
    return response.data;
  },

  getOIDCAuthorizeUrl: (providerName: string): string => {
    return `${API_BASE_URL}/auth/oidc/${encodeURIComponent(providerName)}/authorize`;
  },
};

// ============================================================================
// User Management API (Admin only)
// ============================================================================

export const userApi = {
  getAll: async (): Promise<User[]> => {
    const response = await api.get<User[]>('/users');
    return response.data;
  },

  create: async (data: UserCreate): Promise<User> => {
    const response = await api.post<User>('/users', data);
    return response.data;
  },

  update: async (id: number, data: UserUpdate): Promise<User> => {
    const response = await api.put<User>(`/users/${id}`, data);
    return response.data;
  },

  delete: async (id: number): Promise<void> => {
    await api.delete(`/users/${id}`);
  },
};

// ============================================================================
// OIDC Provider Management API (Admin only)
// ============================================================================

export const oidcProviderApi = {
  getAll: async (): Promise<OIDCProvider[]> => {
    const response = await api.get<OIDCProvider[]>('/oidc-providers');
    return response.data;
  },

  get: async (id: number): Promise<OIDCProvider> => {
    const response = await api.get<OIDCProvider>(`/oidc-providers/${id}`);
    return response.data;
  },

  create: async (data: OIDCProviderCreate): Promise<OIDCProvider> => {
    const response = await api.post<OIDCProvider>('/oidc-providers', data);
    return response.data;
  },

  update: async (id: number, data: OIDCProviderUpdate): Promise<OIDCProvider> => {
    const response = await api.put<OIDCProvider>(`/oidc-providers/${id}`, data);
    return response.data;
  },

  delete: async (id: number): Promise<void> => {
    await api.delete(`/oidc-providers/${id}`);
  },

  test: async (data: OIDCProviderCreate): Promise<{ success: boolean; message: string }> => {
    const response = await api.post<{ success: boolean; message: string }>('/oidc-providers/test', data);
    return response.data;
  },

  testById: async (id: number): Promise<{ success: boolean; message: string }> => {
    const response = await api.post<{ success: boolean; message: string }>(`/oidc-providers/${id}/test`);
    return response.data;
  },
};

// ============================================================================
// Notification Channel API
// ============================================================================

export const notificationChannelApi = {
  getAll: async (): Promise<NotificationChannel[]> => {
    const response = await api.get<NotificationChannel[]>('/notification-channels');
    return response.data;
  },

  get: async (id: number): Promise<NotificationChannel> => {
    const response = await api.get<NotificationChannel>(`/notification-channels/${id}`);
    return response.data;
  },

  create: async (data: NotificationChannelCreate): Promise<NotificationChannel> => {
    const response = await api.post<NotificationChannel>('/notification-channels', data);
    return response.data;
  },

  update: async (id: number, data: NotificationChannelUpdate): Promise<NotificationChannel> => {
    const response = await api.put<NotificationChannel>(`/notification-channels/${id}`, data);
    return response.data;
  },

  delete: async (id: number): Promise<void> => {
    await api.delete(`/notification-channels/${id}`);
  },

  test: async (id: number): Promise<{ success: boolean; message: string }> => {
    const response = await api.post<{ success: boolean; message: string }>(`/notification-channels/${id}/test`);
    return response.data;
  },

  getTemplateVariables: async (): Promise<TemplateVariablesResponse> => {
    const response = await api.get<TemplateVariablesResponse>('/notification-channels/template-variables');
    return response.data;
  },

  getChannelTypes: async (): Promise<ChannelTypesResponse> => {
    const response = await api.get<ChannelTypesResponse>('/notification-channels/channel-types');
    return response.data;
  },
};

// ============================================================================
// API Key Management API (Admin only)
// ============================================================================

export const apiKeyApi = {
  getAll: async (): Promise<ApiKey[]> => {
    const response = await api.get<ApiKey[]>('/api-keys');
    return response.data;
  },

  create: async (data: ApiKeyCreate): Promise<ApiKeyCreateResponse> => {
    const payload = { ...data };
    if (payload.expires_at && !payload.expires_at.endsWith('Z') && !/[+-]\d{2}:?\d{2}$/.test(payload.expires_at)) {
      payload.expires_at = new Date(payload.expires_at).toISOString();
    }
    const response = await api.post<ApiKeyCreateResponse>('/api-keys', payload);
    return response.data;
  },

  revoke: async (id: number): Promise<void> => {
    await api.delete(`/api-keys/${id}`);
  },
};

export default api;
