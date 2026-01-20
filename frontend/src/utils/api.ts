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
} from '../types';

const API_BASE_URL = '/api';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  withCredentials: true, // Include session cookie
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
  get: async (params?: { period?: string; servers?: string }): Promise<Statistics> => {
    const response = await api.get<Statistics>('/statistics', { params });
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
  // Get all settings
  get: async (): Promise<SettingsResponse> => {
    const response = await api.get<SettingsResponse>('/settings');
    return response.data;
  },

  // Update a single app setting
  updateSetting: async (key: string, value: string): Promise<{ message: string; setting: any; requires_restart: boolean }> => {
    const response = await api.put<{ message: string; setting: any; requires_restart: boolean }>(`/settings/${key}`, { value });
    return response.data;
  },

  // Trigger application restart
  restart: async (): Promise<void> => {
    await api.post('/settings/restart');
  },

  // Pi-hole server operations
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
  // Preview what would be synced
  preview: async (): Promise<any> => {
    const response = await api.get('/sync/preview');
    return response.data;
  },

  // Execute sync from all sources to their respective targets
  execute: async (): Promise<{ message: string; sync_history_ids: number[]; sync_history_id: number | null }> => {
    const response = await api.post<{ message: string; sync_history_ids: number[]; sync_history_id: number | null }>('/sync/execute');
    return response.data;
  },

  // Get sync history
  getHistory: async (limit: number = 20): Promise<any[]> => {
    const response = await api.get<{ history: any[] }>('/sync/history', { params: { limit } });
    return response.data.history;
  },
};

export const domainApi = {
  // Quick actions - add to whitelist/blacklist
  whitelist: async (domain: string): Promise<void> => {
    await api.post('/domains/whitelist', { domain });
  },

  blacklist: async (domain: string): Promise<void> => {
    await api.post('/domains/blacklist', { domain });
  },

  // List management
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
  // Get blocking status for all servers
  getStatus: async (): Promise<BlockingStatusResponse> => {
    const response = await api.get<BlockingStatusResponse>('/blocking/status');
    return response.data;
  },

  // Set blocking for a specific server
  setBlocking: async (serverId: number, request: BlockingSetRequest): Promise<BlockingSetResponse> => {
    const response = await api.post<BlockingSetResponse>(`/blocking/${serverId}`, request);
    return response.data;
  },

  // Set blocking for all servers
  setAllBlocking: async (request: BlockingSetRequest): Promise<BlockingSetResponse> => {
    const response = await api.post<BlockingSetResponse>('/blocking/all', request);
    return response.data;
  },
};

// ============================================================================
// Authentication API
// ============================================================================

export const authApi = {
  // Check authentication status (for app initialization)
  check: async (): Promise<AuthCheckResponse> => {
    const response = await api.get<AuthCheckResponse>('/auth/check');
    return response.data;
  },

  // Initial setup - create first admin user
  setup: async (data: SetupRequest): Promise<User> => {
    const response = await api.post<{ message: string; user: User }>('/auth/setup', data);
    return response.data.user;
  },

  // Login with username/password
  login: async (data: LoginRequest): Promise<User> => {
    const response = await api.post<{ message: string; user: User }>('/auth/login', data);
    return response.data.user;
  },

  // Logout - clear session
  logout: async (): Promise<void> => {
    await api.post('/auth/logout');
  },

  // Get current user info
  getMe: async (): Promise<User> => {
    const response = await api.get<User>('/auth/me');
    return response.data;
  },

  // Get enabled OIDC providers (public, for login page)
  getOIDCProviders: async (): Promise<OIDCProviderPublic[]> => {
    const response = await api.get<OIDCProviderPublic[]>('/auth/oidc/providers');
    return response.data;
  },

  // Start OIDC login flow - returns the authorization URL
  getOIDCAuthorizeUrl: (providerName: string): string => {
    return `${API_BASE_URL}/auth/oidc/${encodeURIComponent(providerName)}/authorize`;
  },
};

// ============================================================================
// User Management API (Admin only)
// ============================================================================

export const userApi = {
  // Get all users
  getAll: async (): Promise<User[]> => {
    const response = await api.get<User[]>('/users');
    return response.data;
  },

  // Create a new user
  create: async (data: UserCreate): Promise<User> => {
    const response = await api.post<User>('/users', data);
    return response.data;
  },

  // Update a user
  update: async (id: number, data: UserUpdate): Promise<User> => {
    const response = await api.put<User>(`/users/${id}`, data);
    return response.data;
  },

  // Delete a user
  delete: async (id: number): Promise<void> => {
    await api.delete(`/users/${id}`);
  },
};

// ============================================================================
// OIDC Provider Management API (Admin only)
// ============================================================================

export const oidcProviderApi = {
  // Get all OIDC providers (admin view with secrets)
  getAll: async (): Promise<OIDCProvider[]> => {
    const response = await api.get<OIDCProvider[]>('/oidc-providers');
    return response.data;
  },

  // Get a single OIDC provider
  get: async (id: number): Promise<OIDCProvider> => {
    const response = await api.get<OIDCProvider>(`/oidc-providers/${id}`);
    return response.data;
  },

  // Create a new OIDC provider
  create: async (data: OIDCProviderCreate): Promise<OIDCProvider> => {
    const response = await api.post<OIDCProvider>('/oidc-providers', data);
    return response.data;
  },

  // Update an OIDC provider
  update: async (id: number, data: OIDCProviderUpdate): Promise<OIDCProvider> => {
    const response = await api.put<OIDCProvider>(`/oidc-providers/${id}`, data);
    return response.data;
  },

  // Delete an OIDC provider
  delete: async (id: number): Promise<void> => {
    await api.delete(`/oidc-providers/${id}`);
  },

  // Test OIDC provider configuration
  test: async (data: OIDCProviderCreate): Promise<{ success: boolean; message: string }> => {
    const response = await api.post<{ success: boolean; message: string }>('/oidc-providers/test', data);
    return response.data;
  },
};

// ============================================================================
// Notification Channel API
// ============================================================================

export const notificationChannelApi = {
  // Get all notification channels
  getAll: async (): Promise<NotificationChannel[]> => {
    const response = await api.get<NotificationChannel[]>('/notification-channels');
    return response.data;
  },

  // Get a single notification channel
  get: async (id: number): Promise<NotificationChannel> => {
    const response = await api.get<NotificationChannel>(`/notification-channels/${id}`);
    return response.data;
  },

  // Create a new notification channel
  create: async (data: NotificationChannelCreate): Promise<NotificationChannel> => {
    const response = await api.post<NotificationChannel>('/notification-channels', data);
    return response.data;
  },

  // Update a notification channel
  update: async (id: number, data: NotificationChannelUpdate): Promise<NotificationChannel> => {
    const response = await api.put<NotificationChannel>(`/notification-channels/${id}`, data);
    return response.data;
  },

  // Delete a notification channel
  delete: async (id: number): Promise<void> => {
    await api.delete(`/notification-channels/${id}`);
  },

  // Test a notification channel
  test: async (id: number): Promise<{ success: boolean; message: string }> => {
    const response = await api.post<{ success: boolean; message: string }>(`/notification-channels/${id}/test`);
    return response.data;
  },

  // Get available template variables
  getTemplateVariables: async (): Promise<TemplateVariablesResponse> => {
    const response = await api.get<TemplateVariablesResponse>('/notification-channels/template-variables');
    return response.data;
  },

  // Get available channel types
  getChannelTypes: async (): Promise<ChannelTypesResponse> => {
    const response = await api.get<ChannelTypesResponse>('/notification-channels/channel-types');
    return response.data;
  },
};

export default api;
