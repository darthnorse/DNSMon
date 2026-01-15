import axios from 'axios';
import type { Query, AlertRule, AlertRuleCreate, Stats, QuerySearchParams, SettingsResponse, PiholeServer, PiholeServerCreate, DomainEntry, Statistics, BlockingStatusResponse, BlockingSetRequest, BlockingSetResponse } from '../types';

const API_BASE_URL = '/api';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

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

  // Test Telegram connection
  testTelegram: async (bot_token: string, chat_id: string): Promise<{ success: boolean; message: string }> => {
    const response = await api.post<{ success: boolean; message: string }>('/settings/telegram/test', {
      bot_token,
      chat_id
    });
    return response.data;
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

  // Execute sync from source to targets
  execute: async (): Promise<{ message: string; sync_history_id: number }> => {
    const response = await api.post<{ message: string; sync_history_id: number }>('/sync/execute');
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

  removeFromWhitelist: async (domain: string): Promise<void> => {
    await api.delete(`/domains/whitelist/${encodeURIComponent(domain)}`);
  },

  removeFromBlacklist: async (domain: string): Promise<void> => {
    await api.delete(`/domains/blacklist/${encodeURIComponent(domain)}`);
  },

  removeFromRegexWhitelist: async (id: number): Promise<void> => {
    await api.delete(`/domains/regex-whitelist/${id}`);
  },

  removeFromRegexBlacklist: async (id: number): Promise<void> => {
    await api.delete(`/domains/regex-blacklist/${id}`);
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

export default api;
