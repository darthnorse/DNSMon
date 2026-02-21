import React, { useState, useEffect } from 'react';
import { settingsApi, syncApi, oidcProviderApi } from '../utils/api';
import { useAuth } from '../contexts/AuthContext';
import { getErrorMessage } from '../utils/errors';
import { copyToClipboard } from '../utils/clipboard';
import NotificationsSettings from '../components/NotificationsSettings';
import Users from './Users';
import ApiKeys from './ApiKeys';
import type { PiholeServer, PiholeServerCreate, ServerType, OIDCProvider, OIDCProviderCreate, SyncPreview, SyncPreviewSource, SyncHistoryEntry } from '../types';

type TabType = 'servers' | 'notifications' | 'polling' | 'sync' | 'oidc' | 'advanced' | 'users' | 'api-keys';

const SERVER_TYPE_LABELS: Record<ServerType, string> = {
  pihole: 'Pi-hole',
  adguard: 'AdGuard',
  technitium: 'Technitium',
};

const SERVER_TYPE_BADGE_COLORS: Record<ServerType, string> = {
  pihole: 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300',
  adguard: 'bg-teal-100 dark:bg-teal-900/30 text-teal-800 dark:text-teal-300',
  technitium: 'bg-orange-100 dark:bg-orange-900/30 text-orange-800 dark:text-orange-300',
};

export default function Settings() {
  const [activeTab, setActiveTab] = useState<TabType>('servers');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  const [servers, setServers] = useState<PiholeServer[]>([]);
  const [showServerForm, setShowServerForm] = useState(false);
  const [editingServer, setEditingServer] = useState<PiholeServer | null>(null);
  const [serverFormData, setServerFormData] = useState<PiholeServerCreate>({
    name: '',
    url: '',
    password: '',
    username: '',
    server_type: 'pihole',
    skip_ssl_verify: false,
    extra_config: {},
    enabled: true,
    is_source: false,
    sync_enabled: false
  });

  const [pollingData, setPollingData] = useState({
    poll_interval_seconds: 60,
    query_lookback_seconds: 65,
    retention_days: 60,
    max_catchup_seconds: 300
  });

  const [syncInterval, setSyncInterval] = useState(900); // 15 minutes default
  const [syncPreview, setSyncPreview] = useState<SyncPreview | null>(null);
  const [syncHistory, setSyncHistory] = useState<SyncHistoryEntry[]>([]);
  const [syncing, setSyncing] = useState(false);
  const [loadingSync, setLoadingSync] = useState(false);
  const [expandedSyncId, setExpandedSyncId] = useState<number | null>(null);

  const [corsOrigins, setCorsOrigins] = useState<string>('');

  const { user } = useAuth();
  const [oidcProviders, setOidcProviders] = useState<OIDCProvider[] | null>(null);
  const [loadingOidc, setLoadingOidc] = useState(false);
  const [disableLocalAuth, setDisableLocalAuth] = useState(false);
  const [showOidcForm, setShowOidcForm] = useState(false);
  const [editingOidc, setEditingOidc] = useState<OIDCProvider | null>(null);
  const [oidcFormData, setOidcFormData] = useState<OIDCProviderCreate>({
    name: '',
    display_name: '',
    issuer_url: '',
    client_id: '',
    client_secret: '',
    scopes: 'openid profile email',
    username_claim: 'preferred_username',
    email_claim: 'email',
    display_name_claim: 'name',
    groups_claim: '',
    admin_group: '',
    enabled: true,
  });
  const [testingOidc, setTestingOidc] = useState(false);
  const [oidcTestResult, setOidcTestResult] = useState<{ success: boolean; message: string } | null>(null);

  const [showRestartModal, setShowRestartModal] = useState(false);
  const [restarting, setRestarting] = useState(false);

  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null);

  useEffect(() => {
    loadSettings();
    loadServers();
  }, []);

  useEffect(() => {
    if (successMessage) {
      const timer = setTimeout(() => setSuccessMessage(null), 5000);
      return () => clearTimeout(timer);
    }
  }, [successMessage]);

  useEffect(() => {
    if (activeTab === 'sync') {
      handleLoadSyncHistory();
    }
  }, [activeTab]);

  useEffect(() => {
    if (activeTab === 'oidc' && user?.is_admin) {
      loadOidcProviders();
    }
  }, [activeTab, user?.is_admin]);

  const loadSettings = async () => {
    try {
      setLoading(true);
      const data = await settingsApi.get();

      setPollingData({
        poll_interval_seconds: Number(data.app_settings.poll_interval_seconds?.value || 60),
        query_lookback_seconds: Number(data.app_settings.query_lookback_seconds?.value || 65),
        retention_days: Number(data.app_settings.retention_days?.value || 60),
        max_catchup_seconds: Number(data.app_settings.max_catchup_seconds?.value || 300),
      });

      setSyncInterval(Number(data.app_settings.sync_interval_seconds?.value || 900));

      const origins = data.app_settings.cors_origins?.value as string[];
      setCorsOrigins(origins ? origins.join(', ') : '');

      setDisableLocalAuth(data.app_settings.disable_local_auth?.value === true);

      setError(null);
    } catch (err) {
      setError('Failed to load settings');
    } finally {
      setLoading(false);
    }
  };

  const loadServers = async () => {
    try {
      const data = await settingsApi.servers.getAll();
      setServers(data);
    } catch (err) {
      console.error('Failed to load servers:', err);
    }
  };

  const validateServer = (data: PiholeServerCreate, isEditing: boolean = false): string[] => {
    const errors: string[] = [];

    if (!data.name || data.name.trim().length === 0) {
      errors.push('Server name is required');
    } else if (data.name.length > 100) {
      errors.push('Server name must be 100 characters or less');
    }

    if (!data.url || data.url.trim().length === 0) {
      errors.push('Server URL is required');
    } else if (!data.url.startsWith('http://') && !data.url.startsWith('https://')) {
      errors.push('URL must start with http:// or https://');
    } else if (data.url.length > 255) {
      errors.push('URL must be 255 characters or less');
    }

    if (!isEditing && (!data.password || data.password.trim().length === 0)) {
      errors.push(data.server_type === 'technitium' ? 'API Token is required' : 'Password is required');
    }

    return errors;
  };

  const handleServerSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    const errors = validateServer(serverFormData, !!editingServer);
    if (errors.length > 0) {
      setError(errors.join('. '));
      return;
    }

    try {
      setSaving(true);
      setError(null);

      if (editingServer) {
        await settingsApi.servers.update(editingServer.id, serverFormData);
      } else {
        await settingsApi.servers.create(serverFormData);
      }

      await loadServers();
      handleCancelServerForm();
      setSuccessMessage('Server saved successfully');
    } catch (err: unknown) {
      setError(getErrorMessage(err, 'Failed to save server'));
    } finally {
      setSaving(false);
    }
  };

  const handleEditServer = (server: PiholeServer) => {
    setEditingServer(server);
    setServerFormData({
      name: server.name,
      url: server.url,
      password: '',
      username: server.username || '',
      server_type: server.server_type || 'pihole',
      skip_ssl_verify: server.skip_ssl_verify || false,
      extra_config: server.extra_config || {},
      enabled: server.enabled,
      is_source: server.is_source,
      sync_enabled: server.sync_enabled
    });
    setShowServerForm(true);
    setError(null);
  };

  const handleDeleteServer = async (id: number) => {
    if (!window.confirm('Are you sure you want to delete this server?')) {
      return;
    }

    try {
      setSaving(true);
      await settingsApi.servers.delete(id);
      await loadServers();
      setSuccessMessage('Server deleted successfully');
    } catch (err: unknown) {
      setError(getErrorMessage(err, 'Failed to delete server'));
    } finally {
      setSaving(false);
    }
  };

  const handleCancelServerForm = () => {
    setShowServerForm(false);
    setEditingServer(null);
    setServerFormData({
      name: '',
      url: '',
      password: '',
      username: '',
      server_type: 'pihole',
      skip_ssl_verify: false,
      extra_config: {},
      enabled: true,
      is_source: false,
      sync_enabled: false
    });
    setError(null);
    setTestResult(null);
  };

  const handleTestConnection = async () => {
    const errors = validateServer(serverFormData, !!editingServer);
    if (errors.length > 0) {
      setError(errors.join('. '));
      return;
    }

    if (editingServer && !serverFormData.password) {
      const credLabel = serverFormData.server_type === 'technitium' ? 'API Token' : 'Password';
      setError(`Please re-enter the ${credLabel} to test the connection.`);
      return;
    }

    try {
      setTesting(true);
      setError(null);
      setTestResult(null);

      const result = await settingsApi.servers.test(serverFormData);
      setTestResult(result);

      if (!result.success) {
        setError(result.message);
      }
    } catch (err: unknown) {
      const msg = getErrorMessage(err, 'Test connection failed');
      setTestResult({ success: false, message: msg });
      setError(msg);
    } finally {
      setTesting(false);
    }
  };

  const handleSavePolling = async () => {
    const errors: string[] = [];

    if (pollingData.poll_interval_seconds < 10 || pollingData.poll_interval_seconds > 3600) {
      errors.push('Poll interval must be between 10 and 3600 seconds');
    }
    if (pollingData.query_lookback_seconds < 10 || pollingData.query_lookback_seconds > 3600) {
      errors.push('Query lookback must be between 10 and 3600 seconds');
    }
    if (pollingData.retention_days < 1 || pollingData.retention_days > 365) {
      errors.push('Retention days must be between 1 and 365');
    }
    if (pollingData.max_catchup_seconds < 60 || pollingData.max_catchup_seconds > 3600) {
      errors.push('Max catchup must be between 60 and 3600 seconds');
    }

    if (errors.length > 0) {
      setError(errors.join('. '));
      return;
    }

    try {
      setSaving(true);
      setError(null);

      let needsRestart = false;

      const result1 = await settingsApi.updateSetting('poll_interval_seconds', String(pollingData.poll_interval_seconds));
      if (result1.requires_restart) needsRestart = true;

      const result2 = await settingsApi.updateSetting('query_lookback_seconds', String(pollingData.query_lookback_seconds));
      if (result2.requires_restart) needsRestart = true;

      const result3 = await settingsApi.updateSetting('retention_days', String(pollingData.retention_days));
      if (result3.requires_restart) needsRestart = true;

      const result4 = await settingsApi.updateSetting('max_catchup_seconds', String(pollingData.max_catchup_seconds));
      if (result4.requires_restart) needsRestart = true;

      if (needsRestart) {
        setShowRestartModal(true);
      } else {
        setSuccessMessage('Settings saved successfully');
        await loadSettings();
      }
    } catch (err: unknown) {
      setError(getErrorMessage(err, 'Failed to save settings'));
    } finally {
      setSaving(false);
    }
  };

  const handleSaveSyncInterval = async () => {
    if (syncInterval < 60 || syncInterval > 86400) {
      setError('Sync interval must be between 60 and 86400 seconds (1 minute to 24 hours)');
      return;
    }

    try {
      setSaving(true);
      setError(null);

      const result = await settingsApi.updateSetting('sync_interval_seconds', String(syncInterval));

      if (result.requires_restart) {
        setShowRestartModal(true);
      } else {
        setSuccessMessage('Sync interval saved successfully');
        await loadSettings();
      }
    } catch (err: unknown) {
      setError(getErrorMessage(err, 'Failed to save sync interval'));
    } finally {
      setSaving(false);
    }
  };

  const handleLoadSyncPreview = async () => {
    try {
      setLoadingSync(true);
      setError(null);
      const preview = await syncApi.preview();
      setSyncPreview(preview);
    } catch (err: unknown) {
      setError(getErrorMessage(err, 'Failed to load sync preview'));
      setSyncPreview(null);
    } finally {
      setLoadingSync(false);
    }
  };

  const handleExecuteSync = async () => {
    try {
      setSyncing(true);
      setError(null);
      await syncApi.execute();
      setSuccessMessage('Sync completed successfully');
      await handleLoadSyncPreview();
      await handleLoadSyncHistory();
    } catch (err: unknown) {
      setError(getErrorMessage(err, 'Failed to execute sync'));
    } finally {
      setSyncing(false);
    }
  };

  const handleLoadSyncHistory = async () => {
    try {
      const history = await syncApi.getHistory(10);
      setSyncHistory(history);
    } catch (err: unknown) {
      console.error('Failed to load sync history:', getErrorMessage(err, 'Unknown error'));
    }
  };

  const handleSaveCors = async () => {
    const originsArray = corsOrigins.split(',').map(o => o.trim()).filter(o => o);
    const errors: string[] = [];

    for (const origin of originsArray) {
      try {
        new URL(origin);
      } catch {
        errors.push(`Invalid origin: ${origin}`);
      }
    }

    if (errors.length > 0) {
      setError(errors.join('. '));
      return;
    }

    try {
      setSaving(true);
      setError(null);

      const result = await settingsApi.updateSetting('cors_origins', JSON.stringify(originsArray));

      if (result.requires_restart) {
        setShowRestartModal(true);
      } else {
        setSuccessMessage('CORS settings saved successfully');
        await loadSettings();
      }
    } catch (err: unknown) {
      setError(getErrorMessage(err, 'Failed to save settings'));
    } finally {
      setSaving(false);
    }
  };

  const handleToggleDisableLocalAuth = async (enabled: boolean) => {
    if (enabled && (!oidcProviders || oidcProviders.filter(p => p.enabled).length === 0)) {
      setError('Cannot disable local authentication: At least one OIDC provider must be enabled first.');
      return;
    }

    try {
      setSaving(true);
      setError(null);
      await settingsApi.updateSetting('disable_local_auth', String(enabled));
      setDisableLocalAuth(enabled);
      setSuccessMessage(enabled
        ? 'Local password authentication disabled. Users must now use OIDC.'
        : 'Local password authentication enabled.');
    } catch (err: unknown) {
      setError(getErrorMessage(err, 'Failed to update setting'));
    } finally {
      setSaving(false);
    }
  };

  const loadOidcProviders = async () => {
    try {
      setLoadingOidc(true);
      const providers = await oidcProviderApi.getAll();
      setOidcProviders(providers);
    } catch (err: unknown) {
      console.error('Failed to load OIDC providers:', getErrorMessage(err, 'Unknown error'));
    } finally {
      setLoadingOidc(false);
    }
  };

  const validateOidcProvider = (data: OIDCProviderCreate, isEdit: boolean = false): string[] => {
    const errors: string[] = [];

    if (!data.name || data.name.trim().length === 0) {
      errors.push('Provider name is required');
    } else if (!/^[a-z0-9_-]+$/.test(data.name)) {
      errors.push('Provider name must be lowercase alphanumeric with underscores and dashes only');
    }

    if (!data.display_name || data.display_name.trim().length === 0) {
      errors.push('Display name is required');
    }

    if (!data.issuer_url || data.issuer_url.trim().length === 0) {
      errors.push('Issuer URL is required');
    } else if (!data.issuer_url.startsWith('http://') && !data.issuer_url.startsWith('https://')) {
      errors.push('Issuer URL must start with http:// or https://');
    }

    if (!data.client_id || data.client_id.trim().length === 0) {
      errors.push('Client ID is required');
    }

    if (!isEdit && (!data.client_secret || data.client_secret.trim().length === 0)) {
      errors.push('Client secret is required');
    }

    return errors;
  };

  const handleOidcSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    const errors = validateOidcProvider(oidcFormData, !!editingOidc);
    if (errors.length > 0) {
      setError(errors.join('. '));
      return;
    }

    try {
      setSaving(true);
      setError(null);

      if (editingOidc) {
        await oidcProviderApi.update(editingOidc.id, oidcFormData);
      } else {
        await oidcProviderApi.create(oidcFormData);
      }

      await loadOidcProviders();
      handleCancelOidcForm();
      setSuccessMessage('OIDC provider saved successfully');
    } catch (err: unknown) {
      setError(getErrorMessage(err, 'Failed to save OIDC provider'));
    } finally {
      setSaving(false);
    }
  };

  const handleEditOidc = (provider: OIDCProvider) => {
    setEditingOidc(provider);
    setOidcFormData({
      name: provider.name,
      display_name: provider.display_name,
      issuer_url: provider.issuer_url,
      client_id: provider.client_id,
      client_secret: '',
      scopes: provider.scopes,
      username_claim: provider.username_claim,
      email_claim: provider.email_claim,
      display_name_claim: provider.display_name_claim,
      groups_claim: provider.groups_claim || '',
      admin_group: provider.admin_group || '',
      enabled: provider.enabled,
    });
    setShowOidcForm(true);
    setError(null);
    setOidcTestResult(null);
  };

  const handleDeleteOidc = async (id: number) => {
    if (!window.confirm('Are you sure you want to delete this OIDC provider?')) {
      return;
    }

    try {
      setSaving(true);
      await oidcProviderApi.delete(id);
      await loadOidcProviders();
      setSuccessMessage('OIDC provider deleted successfully');
    } catch (err: unknown) {
      setError(getErrorMessage(err, 'Failed to delete OIDC provider'));
    } finally {
      setSaving(false);
    }
  };

  const handleCancelOidcForm = () => {
    setShowOidcForm(false);
    setEditingOidc(null);
    setOidcFormData({
      name: '',
      display_name: '',
      issuer_url: '',
      client_id: '',
      client_secret: '',
      scopes: 'openid profile email',
      username_claim: 'preferred_username',
      email_claim: 'email',
      display_name_claim: 'name',
      groups_claim: '',
      admin_group: '',
      enabled: true,
    });
    setError(null);
    setOidcTestResult(null);
  };

  const handleTestOidcProvider = async () => {
    if (!editingOidc) {
      const errors = validateOidcProvider(oidcFormData, false);
      if (errors.length > 0) {
        setError(errors.join('. '));
        return;
      }
    }

    try {
      setTestingOidc(true);
      setError(null);
      setOidcTestResult(null);

      const result = editingOidc
        ? await oidcProviderApi.testById(editingOidc.id)
        : await oidcProviderApi.test(oidcFormData);
      setOidcTestResult(result);

      if (!result.success) {
        setError(result.message);
      }
    } catch (err: unknown) {
      const msg = getErrorMessage(err, 'Test connection failed');
      setOidcTestResult({ success: false, message: msg });
      setError(msg);
    } finally {
      setTestingOidc(false);
    }
  };

  const handleRestart = async () => {
    try {
      setRestarting(true);
      await settingsApi.restart();

      await new Promise(resolve => setTimeout(resolve, 3000));

      const maxAttempts = 15;

      const checkHealth = async (): Promise<boolean> => {
        for (let i = 0; i < maxAttempts; i++) {
          await new Promise(resolve => setTimeout(resolve, 2000));

          try {
            const response = await fetch('/api/health');
            if (response.ok) {
              return true;
            }
          } catch (e) {
          }
        }
        return false;
      };

      const success = await checkHealth();

      if (success) {
        setSuccessMessage('Application restarted successfully');
        window.location.reload();
      } else {
        setError('Restart is taking longer than expected. Please refresh the page manually.');
      }
    } catch (err) {
      setError('Failed to restart application. Please try again or restart manually.');
    } finally {
      setRestarting(false);
      setShowRestartModal(false);
    }
  };

  const tabs: { id: TabType; label: string }[] = [
    { id: 'servers', label: 'DNS Servers' },
    { id: 'notifications', label: 'Notifications' },
    { id: 'polling', label: 'Polling & Retention' },
    { id: 'sync', label: 'Sync' },
    ...(user?.is_admin ? [
      { id: 'users' as TabType, label: 'Users' },
      { id: 'oidc' as TabType, label: 'OIDC' },
      { id: 'api-keys' as TabType, label: 'API Keys' },
    ] : []),
    { id: 'advanced', label: 'Advanced' },
  ];

  if (loading) {
    return (
      <div className="p-6">
        <div className="flex items-center justify-center py-12">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold text-gray-900 dark:text-white mb-6">Settings</h1>

      {error && (
        <div className="mb-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 text-red-800 dark:text-red-200 px-4 py-3 rounded">
          {error}
        </div>
      )}

      {successMessage && (
        <div className="mb-4 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 text-green-800 dark:text-green-200 px-4 py-3 rounded">
          {successMessage}
        </div>
      )}

      <div className="border-b border-gray-200 dark:border-gray-700 mb-6">
        <nav className="-mb-px flex space-x-8">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => {
                setActiveTab(tab.id);
                setError(null);
              }}
              className={`${
                activeTab === tab.id
                  ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                  : 'border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300 hover:border-gray-300 dark:hover:border-gray-600'
              } whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm`}
            >
              {tab.label}
            </button>
          ))}
        </nav>
      </div>

      {activeTab === 'servers' && (
        <div>
          <div className="flex justify-between items-center mb-4">
            <h2 className="text-lg font-medium text-gray-900 dark:text-white">DNS Servers</h2>
            {!showServerForm && !editingServer && (
              <button
                onClick={() => setShowServerForm(true)}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-md text-sm font-medium"
              >
                Add Server
              </button>
            )}
          </div>

          {(showServerForm || editingServer) && (
            <form onSubmit={handleServerSubmit} className="mb-6 bg-gray-50 dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700">
              <h3 className="text-md font-medium text-gray-900 dark:text-white mb-4">
                {editingServer ? 'Edit Server' : 'Add New Server'}
              </h3>
              <div className="grid grid-cols-1 gap-4">
                <div>
                  <label htmlFor="server_name" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Name
                  </label>
                  <input
                    type="text"
                    id="server_name"
                    value={serverFormData.name}
                    onChange={(e) => setServerFormData({ ...serverFormData, name: e.target.value })}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  />
                </div>
                <div>
                  <label htmlFor="server_url" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    URL
                  </label>
                  <input
                    type="text"
                    id="server_url"
                    value={serverFormData.url}
                    onChange={(e) => setServerFormData({ ...serverFormData, url: e.target.value })}
                    placeholder={serverFormData.server_type === 'technitium' ? 'http://192.168.1.2:5380' : 'http://192.168.1.2'}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  />
                </div>
                <div>
                  <label htmlFor="server_type" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Server Type
                  </label>
                  <select
                    id="server_type"
                    value={serverFormData.server_type}
                    onChange={(e) => {
                      const newType = e.target.value as ServerType;
                      setServerFormData({
                        ...serverFormData,
                        server_type: newType,
                        username: newType === 'adguard' ? serverFormData.username : '',
                        extra_config: newType === 'technitium' ? (serverFormData.extra_config || {}) : {},
                      });
                    }}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  >
                    <option value="pihole">Pi-hole</option>
                    <option value="adguard">AdGuard Home</option>
                    <option value="technitium">Technitium DNS</option>
                  </select>
                </div>
                {serverFormData.server_type === 'adguard' && (
                  <div>
                    <label htmlFor="server_username" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Username
                    </label>
                    <input
                      type="text"
                      id="server_username"
                      value={serverFormData.username || ''}
                      onChange={(e) => setServerFormData({ ...serverFormData, username: e.target.value })}
                      placeholder="admin"
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                    />
                    <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                      AdGuard Home username (defaults to 'admin' if empty)
                    </p>
                  </div>
                )}
                <div>
                  <label htmlFor="server_password" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    {serverFormData.server_type === 'technitium' ? 'API Token' : 'Password'} {editingServer && <span className="text-blue-600 dark:text-blue-400 text-xs">(optional)</span>}
                  </label>
                  <input
                    type="password"
                    id="server_password"
                    value={serverFormData.password}
                    onChange={(e) => setServerFormData({ ...serverFormData, password: e.target.value })}
                    placeholder={
                      serverFormData.server_type === 'technitium'
                        ? (editingServer ? 'Leave empty to keep existing token' : 'Paste API token from Technitium UI')
                        : (editingServer ? 'Leave empty to keep existing password' : 'Enter password')
                    }
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  />
                </div>
                {serverFormData.server_type === 'technitium' && (
                  <>
                    <div>
                      <label htmlFor="log_app_name" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Query Log App Name
                      </label>
                      <input
                        type="text"
                        id="log_app_name"
                        value={String(serverFormData.extra_config?.log_app_name ?? '')}
                        onChange={(e) => setServerFormData({
                          ...serverFormData,
                          extra_config: { ...serverFormData.extra_config, log_app_name: e.target.value }
                        })}
                        placeholder="QueryLogsSqlite"
                        className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                      />
                      <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                        Name of the DNS App providing query logs (default: QueryLogsSqlite)
                      </p>
                    </div>
                    <div>
                      <label htmlFor="log_app_class_path" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Query Log App Class Path
                      </label>
                      <input
                        type="text"
                        id="log_app_class_path"
                        value={String(serverFormData.extra_config?.log_app_class_path ?? '')}
                        onChange={(e) => setServerFormData({
                          ...serverFormData,
                          extra_config: { ...serverFormData.extra_config, log_app_class_path: e.target.value }
                        })}
                        placeholder="QueryLogsSqlite.App"
                        className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                      />
                      <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                        Class path of the Query Log app (default: QueryLogsSqlite.App)
                      </p>
                    </div>
                  </>
                )}
                <div className="flex items-center">
                  <input
                    type="checkbox"
                    id="server_enabled"
                    checked={serverFormData.enabled}
                    onChange={(e) => setServerFormData({ ...serverFormData, enabled: e.target.checked })}
                    className="h-4 w-4 text-blue-600 border-gray-300 rounded"
                  />
                  <label htmlFor="server_enabled" className="ml-2 text-sm text-gray-700 dark:text-gray-300">
                    Enabled
                  </label>
                </div>
                <div className="flex items-center">
                  <input
                    type="checkbox"
                    id="server_skip_ssl_verify"
                    checked={serverFormData.skip_ssl_verify || false}
                    onChange={(e) => setServerFormData({ ...serverFormData, skip_ssl_verify: e.target.checked })}
                    className="h-4 w-4 text-blue-600 border-gray-300 rounded"
                  />
                  <label htmlFor="server_skip_ssl_verify" className="ml-2 text-sm text-gray-700 dark:text-gray-300">
                    Skip SSL verification (for self-signed certificates)
                  </label>
                </div>
                {/* Sync options - sync only works within the same server type */}
                {(() => {
                  const anotherServerIsSource = servers.some(s =>
                    s.is_source &&
                    s.server_type === serverFormData.server_type &&
                    (!editingServer || s.id !== editingServer.id)
                  );
                  const sourceDisabled = serverFormData.sync_enabled || anotherServerIsSource;
                  const targetDisabled = serverFormData.is_source;

                  return (
                    <>
                      <div className="flex items-center">
                        <input
                          type="checkbox"
                          id="server_is_source"
                          checked={serverFormData.is_source}
                          onChange={(e) => setServerFormData({
                            ...serverFormData,
                            is_source: e.target.checked,
                            sync_enabled: e.target.checked ? false : serverFormData.sync_enabled
                          })}
                          disabled={sourceDisabled}
                          className={`h-4 w-4 border-gray-300 rounded ${
                            sourceDisabled
                              ? 'text-gray-400 cursor-not-allowed'
                              : 'text-blue-600'
                          }`}
                        />
                        <label
                          htmlFor="server_is_source"
                          className={`ml-2 text-sm ${
                            sourceDisabled
                              ? 'text-gray-400 dark:text-gray-500'
                              : 'text-gray-700 dark:text-gray-300'
                          }`}
                        >
                          Source (sync from this server)
                          {anotherServerIsSource && !serverFormData.sync_enabled && (
                            <span className="text-xs text-gray-400 dark:text-gray-500 ml-1">
                              - another {serverFormData.server_type} server is source
                            </span>
                          )}
                        </label>
                      </div>
                      <div className="flex items-center">
                        <input
                          type="checkbox"
                          id="server_sync_enabled"
                          checked={serverFormData.sync_enabled}
                          onChange={(e) => setServerFormData({
                            ...serverFormData,
                            sync_enabled: e.target.checked,
                            is_source: e.target.checked ? false : serverFormData.is_source
                          })}
                          disabled={targetDisabled}
                          className={`h-4 w-4 border-gray-300 rounded ${
                            targetDisabled
                              ? 'text-gray-400 cursor-not-allowed'
                              : 'text-blue-600'
                          }`}
                        />
                        <label
                          htmlFor="server_sync_enabled"
                          className={`ml-2 text-sm ${
                            targetDisabled
                              ? 'text-gray-400 dark:text-gray-500'
                              : 'text-gray-700 dark:text-gray-300'
                          }`}
                        >
                          Sync target (receive syncs from source)
                        </label>
                      </div>
                      <p className="text-xs text-gray-500 dark:text-gray-400">
                        Note: Sync only works between servers of the same type ({SERVER_TYPE_LABELS[serverFormData.server_type || 'pihole']} to {SERVER_TYPE_LABELS[serverFormData.server_type || 'pihole']})
                      </p>
                    </>
                  );
                })()}
              </div>

              {testResult && (
                <div className={`mt-4 px-4 py-3 rounded ${
                  testResult.success
                    ? 'bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 text-green-800 dark:text-green-200'
                    : 'bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 text-red-800 dark:text-red-200'
                }`}>
                  {testResult.success ? '✓ ' : '✗ '}{testResult.message}
                </div>
              )}

              <div className="flex space-x-3 mt-4">
                <button
                  type="submit"
                  disabled={saving}
                  className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 text-white rounded-md text-sm font-medium"
                >
                  {saving ? 'Saving...' : 'Save'}
                </button>
                <button
                  type="button"
                  onClick={handleTestConnection}
                  disabled={testing || saving}
                  className="px-4 py-2 bg-green-600 hover:bg-green-700 disabled:bg-gray-400 text-white rounded-md text-sm font-medium"
                >
                  {testing ? 'Testing...' : 'Test Connection'}
                </button>
                <button
                  type="button"
                  onClick={handleCancelServerForm}
                  className="px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md text-sm font-medium text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700"
                >
                  Cancel
                </button>
              </div>
            </form>
          )}

          {!showServerForm && !editingServer && (
            <div className="space-y-3">
              {servers.length === 0 ? (
                <p className="text-gray-500 dark:text-gray-400 text-center py-8">
                  No DNS servers configured. Add your first server above.
                </p>
              ) : (
                servers.map((server) => (
                <div key={server.id} className="bg-white dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700 shadow-sm">
                  <div className="flex justify-between items-start">
                    <div>
                      <div className="flex items-center gap-2">
                        <h3 className="text-lg font-medium text-gray-900 dark:text-white">{server.name}</h3>
                        <span className={`px-2 py-0.5 text-xs font-medium rounded-full ${SERVER_TYPE_BADGE_COLORS[server.server_type]}`}>
                          {SERVER_TYPE_LABELS[server.server_type]}
                        </span>
                        {server.is_source && (
                          <span className="px-2 py-0.5 text-xs font-medium rounded-full bg-purple-100 dark:bg-purple-900/30 text-purple-800 dark:text-purple-300">
                            Source
                          </span>
                        )}
                        {server.sync_enabled && (
                          <span className="px-2 py-0.5 text-xs font-medium rounded-full bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-300">
                            Target
                          </span>
                        )}
                      </div>
                      <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">{server.url}</p>
                      <p className="text-xs text-gray-500 dark:text-gray-500 mt-1">
                        {server.enabled ? 'Enabled' : 'Disabled'}
                      </p>
                    </div>
                    <div className="flex space-x-2">
                      <button
                        onClick={() => handleEditServer(server)}
                        className="px-3 py-1 text-sm text-blue-600 dark:text-blue-400 hover:bg-blue-50 dark:hover:bg-blue-900/20 rounded"
                      >
                        Edit
                      </button>
                      <button
                        onClick={() => handleDeleteServer(server.id)}
                        disabled={saving}
                        className="px-3 py-1 text-sm text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 rounded"
                      >
                        Delete
                      </button>
                    </div>
                  </div>
                </div>
              ))
              )}
            </div>
          )}
        </div>
      )}

      {activeTab === 'notifications' && (
        <NotificationsSettings
          onError={setError}
          onSuccess={setSuccessMessage}
        />
      )}

      {activeTab === 'polling' && (
        <div className="max-w-2xl">
          <h2 className="text-lg font-medium text-gray-900 dark:text-white mb-4">Polling & Retention</h2>
          <div className="mb-4 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 text-yellow-800 dark:text-yellow-200 px-4 py-3 rounded text-sm">
            ⚠️ Changing poll interval or query lookback will restart the application
          </div>

          <div className="space-y-4">
            <div>
              <label htmlFor="poll_interval" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Poll Interval (seconds)
              </label>
              <input
                type="number"
                id="poll_interval"
                min="10"
                max="3600"
                value={pollingData.poll_interval_seconds}
                onChange={(e) => setPollingData({ ...pollingData, poll_interval_seconds: parseInt(e.target.value, 10) || 60 })}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              />
              <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">10 - 3600 seconds</p>
            </div>
            <div>
              <label htmlFor="query_lookback" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Query Lookback (seconds)
              </label>
              <input
                type="number"
                id="query_lookback"
                min="10"
                max="3600"
                value={pollingData.query_lookback_seconds}
                onChange={(e) => setPollingData({ ...pollingData, query_lookback_seconds: parseInt(e.target.value, 10) || 65 })}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              />
              <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">10 - 3600 seconds</p>
            </div>
            <div>
              <label htmlFor="retention_days" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Retention Days
              </label>
              <input
                type="number"
                id="retention_days"
                min="1"
                max="365"
                value={pollingData.retention_days}
                onChange={(e) => setPollingData({ ...pollingData, retention_days: parseInt(e.target.value, 10) || 60 })}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              />
              <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">1 - 365 days</p>
            </div>
            <div>
              <label htmlFor="max_catchup_seconds" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Max Catchup (seconds)
              </label>
              <input
                type="number"
                id="max_catchup_seconds"
                min="60"
                max="3600"
                value={pollingData.max_catchup_seconds}
                onChange={(e) => setPollingData({ ...pollingData, max_catchup_seconds: parseInt(e.target.value, 10) || 300 })}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              />
              <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                Maximum lookback after downtime (60 - 3600 seconds). Prevents fetching huge amounts of data after extended outages.
              </p>
            </div>
          </div>

          <button
            onClick={handleSavePolling}
            disabled={saving}
            className="mt-6 px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 text-white rounded-md text-sm font-medium"
          >
            {saving ? 'Saving...' : 'Save Polling Settings'}
          </button>
        </div>
      )}

      {activeTab === 'sync' && (
        <div className="max-w-2xl">
          <h2 className="text-lg font-medium text-gray-900 dark:text-white mb-4">Configuration Sync</h2>
          <p className="text-sm text-gray-600 dark:text-gray-400 mb-6">
            Sync configuration from a source server to target servers of the same type.
            Supports Pi-hole (Teleporter + config), AdGuard Home (rules, rewrites, filters, clients), and Technitium DNS (backup/restore).
          </p>

          <div className="mb-6 pb-6 border-b border-gray-200 dark:border-gray-700">
            <h3 className="text-md font-medium text-gray-900 dark:text-white mb-3">Sync Schedule</h3>
            <div className="mb-4 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 text-yellow-800 dark:text-yellow-200 px-4 py-3 rounded text-sm">
              ⚠️ Changing sync interval will restart the application
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Sync Interval (seconds)
              </label>
              <input
                type="number"
                min="60"
                max="86400"
                value={syncInterval}
                onChange={(e) => setSyncInterval(parseInt(e.target.value, 10) || 900)}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              />
              <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">60 - 86400 seconds (1 minute to 24 hours, default: 900 = 15 minutes)</p>
            </div>
            <button
              onClick={handleSaveSyncInterval}
              disabled={saving}
              className="mt-4 px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 text-white rounded-md text-sm font-medium"
            >
              {saving ? 'Saving...' : 'Save Sync Interval'}
            </button>
          </div>

          <div className="mb-6 pb-6 border-b border-gray-200 dark:border-gray-700">
            <h3 className="text-md font-medium text-gray-900 dark:text-white mb-3">Manual Sync</h3>
            <p className="text-sm text-gray-600 dark:text-gray-400 mb-4">
              Trigger an immediate sync from source to all enabled targets. Configure source and targets in the DNS Servers tab.
            </p>
            <div className="flex gap-3">
              <button
                onClick={handleLoadSyncPreview}
                disabled={loadingSync || syncing}
                className="px-4 py-2 bg-gray-600 hover:bg-gray-700 disabled:bg-gray-400 text-white rounded-md text-sm font-medium"
              >
                {loadingSync ? 'Loading...' : 'Preview Sync'}
              </button>
              <button
                onClick={handleExecuteSync}
                disabled={syncing || loadingSync}
                className="px-4 py-2 bg-green-600 hover:bg-green-700 disabled:bg-gray-400 text-white rounded-md text-sm font-medium"
              >
                {syncing ? 'Syncing...' : 'Sync Now'}
              </button>
              <button
                onClick={handleLoadSyncHistory}
                disabled={loadingSync || syncing}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 text-white rounded-md text-sm font-medium"
              >
                Refresh History
              </button>
            </div>

            {syncPreview && (
              <div className="mt-4 p-4 bg-gray-50 dark:bg-gray-700 rounded-md">
                <h4 className="font-medium text-gray-900 dark:text-white mb-2">Sync Preview</h4>
                {syncPreview.error && !syncPreview.sources && (
                  <p className="text-sm text-red-600 dark:text-red-400">{syncPreview.error}</p>
                )}
                {(syncPreview.sources || (!syncPreview.error ? [syncPreview as SyncPreviewSource] : [])).map((preview, idx) => (
                  <div key={idx} className={`text-sm text-gray-700 dark:text-gray-300 ${idx > 0 ? 'mt-4 pt-4 border-t border-gray-200 dark:border-gray-600' : ''}`}>
                    <p><strong>Source:</strong> {preview.source?.name} ({preview.source?.server_type || 'pihole'})</p>
                    {preview.error ? (
                      <p className="text-red-600 dark:text-red-400 mt-1">{preview.error}</p>
                    ) : (
                    <>
                    <p><strong>Targets:</strong> {preview.targets?.length > 0 ? preview.targets.map((t) => t.name).join(', ') : 'None'}</p>
                    {preview.teleporter && preview.teleporter.backup_size_bytes > 0 && (
                      <div className="mt-2">
                        <p><strong>Teleporter (Gravity Database):</strong></p>
                        <p className="ml-4 text-xs text-gray-500 dark:text-gray-400">
                          Backup size: {Math.round((preview.teleporter.backup_size_bytes || 0) / 1024)} KB
                        </p>
                        <ul className="list-disc list-inside ml-4 mt-1">
                          {preview.teleporter.includes?.map((item: string) => (
                            <li key={item}>{item.replace(/_/g, ' ')}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                    {preview.config && (
                      <div className="mt-2">
                        <p><strong>Config Settings:</strong></p>
                        <ul className="list-disc list-inside ml-4 mt-1">
                          {preview.config.keys && Object.entries(preview.config.keys as Record<string, string[]>).map(([section, keys]) => (
                            <li key={section}>{section.toUpperCase()}: {keys.join(', ')}</li>
                          ))}
                        </ul>
                        {preview.config.summary && (
                          <div className="mt-1 ml-4 text-xs text-gray-500 dark:text-gray-400">
                            {Object.entries(preview.config.summary as Record<string, unknown>)
                              .filter(([, value]) => (typeof value === 'number' && (value as number) > 0) || typeof value === 'boolean')
                              .map(([key, value], i, arr) => (
                                <span key={key}>{key.replace(/^dns_/, '').replace(/_/g, ' ')}: {typeof value === 'boolean' ? (value ? 'yes' : 'no') : value as number}{i < arr.length - 1 ? ' | ' : ''}</span>
                              ))}
                          </div>
                        )}
                      </div>
                    )}
                    </>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>

          <div>
            <h3 className="text-md font-medium text-gray-900 dark:text-white mb-3">Sync History</h3>
            {syncHistory.length === 0 ? (
              <p className="text-sm text-gray-500 dark:text-gray-400">No sync history yet</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                  <thead className="bg-gray-50 dark:bg-gray-700">
                    <tr>
                      <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase w-8"></th>
                      <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">Time</th>
                      <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">Type</th>
                      <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">Status</th>
                    </tr>
                  </thead>
                  <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                    {syncHistory.map((sync) => (
                      <React.Fragment key={sync.id}>
                        <tr
                          className="cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-700"
                          onClick={() => setExpandedSyncId(expandedSyncId === sync.id ? null : sync.id)}
                        >
                          <td className="px-3 py-2 text-sm text-gray-500">
                            <span className={`transform transition-transform ${expandedSyncId === sync.id ? 'rotate-90' : ''}`}>
                              ▶
                            </span>
                          </td>
                          <td className="px-3 py-2 text-sm text-gray-900 dark:text-gray-300 whitespace-nowrap">
                            {new Date(sync.started_at).toLocaleString()}
                          </td>
                          <td className="px-3 py-2 text-sm text-gray-900 dark:text-gray-300">{sync.sync_type}</td>
                          <td className="px-3 py-2 text-sm">
                            <span className={`px-2 py-1 rounded-full text-xs ${
                              sync.status === 'success' ? 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200' :
                              sync.status === 'partial' ? 'bg-yellow-100 dark:bg-yellow-900 text-yellow-800 dark:text-yellow-200' :
                              'bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200'
                            }`}>
                              {sync.status}
                            </span>
                          </td>
                        </tr>
                        {expandedSyncId === sync.id && (
                          <tr>
                            <td colSpan={4} className="px-3 py-3 bg-gray-50 dark:bg-gray-700">
                              <div className="text-xs text-gray-600 dark:text-gray-400 space-y-2">
                                {sync.completed_at && (
                                  <div>
                                    <span className="font-medium">Duration:</span>{' '}
                                    {Math.round((new Date(sync.completed_at).getTime() - new Date(sync.started_at).getTime()) / 1000)}s
                                  </div>
                                )}
                                {(sync.items_synced?._teleporter_size_bytes ?? 0) > 0 && (
                                  <div>
                                    <span className="font-medium">Teleporter backup:</span>{' '}
                                    {Math.round((sync.items_synced?._teleporter_size_bytes ?? 0) / 1024)} KB
                                  </div>
                                )}
                                {(sync.items_synced?._config_sections?.length ?? 0) > 0 && (
                                  <div>
                                    <span className="font-medium">Config sections:</span>{' '}
                                    {sync.items_synced?._config_sections?.join(', ')}
                                  </div>
                                )}
                                {sync.items_synced && (
                                  <div>
                                    <span className="font-medium">Items synced:</span>{' '}
                                    {Object.entries(sync.items_synced as Record<string, unknown>)
                                      .filter(([key]) => !key.startsWith('_'))
                                      .filter(([, value]) => typeof value === 'number' && (value as number) > 0)
                                      .map(([key, value]) => `${key.replace('dns_', '')}: ${value}`)
                                      .join(', ') || 'None'}
                                  </div>
                                )}
                                {sync.errors && sync.errors.length > 0 && (
                                  <div className="text-red-600 dark:text-red-400">
                                    <span className="font-medium">Errors:</span>
                                    <ul className="list-disc list-inside ml-2">
                                      {sync.errors.map((err: string, i: number) => (
                                        <li key={i}>{err}</li>
                                      ))}
                                    </ul>
                                  </div>
                                )}
                              </div>
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {activeTab === 'oidc' && (
        <div>
          <div className="flex justify-between items-center mb-4">
            <div>
              <h2 className="text-lg font-medium text-gray-900 dark:text-white">OIDC Providers</h2>
              <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
                Configure single sign-on with Authentik, Authelia, PocketID, or other OIDC providers
              </p>
            </div>
            {!showOidcForm && !editingOidc && (
              <button
                onClick={() => setShowOidcForm(true)}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-md text-sm font-medium"
              >
                Add Provider
              </button>
            )}
          </div>

          {!showOidcForm && !editingOidc && (
            <div className="mb-6 p-4 bg-gray-50 dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
              <div className="flex items-center justify-between">
                <div className="flex-1">
                  <h3 className="text-sm font-medium text-gray-900 dark:text-white">
                    Disable local password authentication
                  </h3>
                  <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                    When enabled, users must log in via OIDC. Ensure at least one OIDC provider is configured and working before enabling.
                  </p>
                  {!loadingOidc && oidcProviders !== null && oidcProviders.filter(p => p.enabled).length === 0 && (
                    <p className="text-sm text-yellow-600 dark:text-yellow-400 mt-2">
                      No OIDC providers are currently enabled. Add and enable at least one provider before disabling local authentication.
                    </p>
                  )}
                </div>
                <div className="ml-4">
                  <button
                    type="button"
                    onClick={() => handleToggleDisableLocalAuth(!disableLocalAuth)}
                    disabled={saving || loadingOidc || oidcProviders === null}
                    className={`relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 ${
                      disableLocalAuth ? 'bg-blue-600' : 'bg-gray-200 dark:bg-gray-600'
                    } ${saving || loadingOidc || oidcProviders === null ? 'opacity-50 cursor-not-allowed' : ''}`}
                    role="switch"
                    aria-checked={disableLocalAuth}
                  >
                    <span
                      className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${
                        disableLocalAuth ? 'translate-x-5' : 'translate-x-0'
                      }`}
                    />
                  </button>
                </div>
              </div>
              {disableLocalAuth && (
                <div className="mt-3 p-3 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded text-sm text-yellow-800 dark:text-yellow-200">
                  Local password authentication is currently disabled. Users must use OIDC to log in.
                </div>
              )}
            </div>
          )}

          {(showOidcForm || editingOidc) && (
            <form onSubmit={handleOidcSubmit} className="mb-6 bg-gray-50 dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700">
              <h3 className="text-md font-medium text-gray-900 dark:text-white mb-4">
                {editingOidc ? 'Edit OIDC Provider' : 'Add New OIDC Provider'}
              </h3>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label htmlFor="oidc_name" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Provider Name <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="text"
                    id="oidc_name"
                    value={oidcFormData.name}
                    onChange={(e) => setOidcFormData({ ...oidcFormData, name: e.target.value.toLowerCase().replace(/[^a-z0-9_-]/g, '') })}
                    placeholder="authentik"
                    disabled={!!editingOidc}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white disabled:opacity-50"
                  />
                  <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">Lowercase, alphanumeric, underscores and dashes</p>
                </div>

                <div>
                  <label htmlFor="oidc_display_name" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Display Name <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="text"
                    id="oidc_display_name"
                    value={oidcFormData.display_name}
                    onChange={(e) => setOidcFormData({ ...oidcFormData, display_name: e.target.value })}
                    placeholder="Login with Authentik"
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  />
                </div>

                {oidcFormData.name && (
                  <div className="md:col-span-2">
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Callback URL
                    </label>
                    <div className="flex items-center gap-2">
                      <input
                        type="text"
                        readOnly
                        value={`${window.location.origin}/api/auth/oidc/${oidcFormData.name}/callback`}
                        className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-gray-100 dark:bg-gray-600 text-gray-700 dark:text-gray-300 text-sm font-mono"
                      />
                      <button
                        type="button"
                        onClick={async () => {
                          const url = `${window.location.origin}/api/auth/oidc/${oidcFormData.name}/callback`;
                          try {
                            await copyToClipboard(url);
                            setSuccessMessage('Callback URL copied to clipboard');
                          } catch {
                            setError('Failed to copy to clipboard');
                          }
                        }}
                        className="px-3 py-2 text-sm bg-gray-200 dark:bg-gray-600 hover:bg-gray-300 dark:hover:bg-gray-500 rounded-md text-gray-700 dark:text-gray-300"
                        title="Copy to clipboard"
                      >
                        Copy
                      </button>
                    </div>
                    <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                      Configure this URL as the redirect/callback URI in your OIDC provider
                    </p>
                  </div>
                )}

                <div className="md:col-span-2">
                  <label htmlFor="oidc_issuer_url" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Issuer URL <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="text"
                    id="oidc_issuer_url"
                    value={oidcFormData.issuer_url}
                    onChange={(e) => setOidcFormData({ ...oidcFormData, issuer_url: e.target.value })}
                    placeholder="https://auth.example.com/application/o/dnsmon/"
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  />
                  <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">The OIDC issuer URL (discovery document will be fetched from .well-known/openid-configuration)</p>
                </div>

                <div>
                  <label htmlFor="oidc_client_id" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Client ID <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="text"
                    id="oidc_client_id"
                    value={oidcFormData.client_id}
                    onChange={(e) => setOidcFormData({ ...oidcFormData, client_id: e.target.value })}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  />
                </div>

                <div>
                  <label htmlFor="oidc_client_secret" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Client Secret <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="password"
                    id="oidc_client_secret"
                    value={oidcFormData.client_secret}
                    onChange={(e) => setOidcFormData({ ...oidcFormData, client_secret: e.target.value })}
                    placeholder={editingOidc ? "Enter new secret to change" : ""}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  />
                </div>

                <div>
                  <label htmlFor="oidc_scopes" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Scopes
                  </label>
                  <input
                    type="text"
                    id="oidc_scopes"
                    value={oidcFormData.scopes}
                    onChange={(e) => setOidcFormData({ ...oidcFormData, scopes: e.target.value })}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  />
                  <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">Default: openid profile email</p>
                </div>

                <div className="flex items-center">
                  <input
                    type="checkbox"
                    id="oidc_enabled"
                    checked={oidcFormData.enabled}
                    onChange={(e) => setOidcFormData({ ...oidcFormData, enabled: e.target.checked })}
                    className="h-4 w-4 text-blue-600 border-gray-300 rounded"
                  />
                  <label htmlFor="oidc_enabled" className="ml-2 text-sm text-gray-700 dark:text-gray-300">
                    Enabled
                  </label>
                </div>
              </div>

              <div className="mt-6 pt-4 border-t border-gray-200 dark:border-gray-600">
                <h4 className="text-sm font-medium text-gray-900 dark:text-white mb-3">Claim Mappings</h4>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div>
                    <label htmlFor="oidc_username_claim" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Username Claim
                    </label>
                    <input
                      type="text"
                      id="oidc_username_claim"
                      value={oidcFormData.username_claim}
                      onChange={(e) => setOidcFormData({ ...oidcFormData, username_claim: e.target.value })}
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                    />
                  </div>

                  <div>
                    <label htmlFor="oidc_email_claim" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Email Claim
                    </label>
                    <input
                      type="text"
                      id="oidc_email_claim"
                      value={oidcFormData.email_claim}
                      onChange={(e) => setOidcFormData({ ...oidcFormData, email_claim: e.target.value })}
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                    />
                  </div>

                  <div>
                    <label htmlFor="oidc_display_name_claim" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Display Name Claim
                    </label>
                    <input
                      type="text"
                      id="oidc_display_name_claim"
                      value={oidcFormData.display_name_claim}
                      onChange={(e) => setOidcFormData({ ...oidcFormData, display_name_claim: e.target.value })}
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                    />
                  </div>
                </div>
              </div>

              <div className="mt-6 pt-4 border-t border-gray-200 dark:border-gray-600">
                <h4 className="text-sm font-medium text-gray-900 dark:text-white mb-3">Group-based Admin Assignment (Optional)</h4>
                <p className="text-xs text-gray-500 dark:text-gray-400 mb-3">
                  Automatically grant admin privileges to users in a specific group
                </p>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label htmlFor="oidc_groups_claim" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Groups Claim
                    </label>
                    <input
                      type="text"
                      id="oidc_groups_claim"
                      value={oidcFormData.groups_claim}
                      onChange={(e) => setOidcFormData({ ...oidcFormData, groups_claim: e.target.value })}
                      placeholder="groups"
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                    />
                  </div>

                  <div>
                    <label htmlFor="oidc_admin_group" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Admin Group Name
                    </label>
                    <input
                      type="text"
                      id="oidc_admin_group"
                      value={oidcFormData.admin_group}
                      onChange={(e) => setOidcFormData({ ...oidcFormData, admin_group: e.target.value })}
                      placeholder="dnsmon-admins"
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                    />
                  </div>
                </div>
              </div>

              {oidcTestResult && (
                <div className={`mt-4 px-4 py-3 rounded ${
                  oidcTestResult.success
                    ? 'bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 text-green-800 dark:text-green-200'
                    : 'bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 text-red-800 dark:text-red-200'
                }`}>
                  {oidcTestResult.success ? '✓ ' : '✗ '}{oidcTestResult.message}
                </div>
              )}

              <div className="flex space-x-3 mt-6">
                <button
                  type="submit"
                  disabled={saving}
                  className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 text-white rounded-md text-sm font-medium"
                >
                  {saving ? 'Saving...' : 'Save'}
                </button>
                <button
                  type="button"
                  onClick={handleTestOidcProvider}
                  disabled={testingOidc || saving}
                  className="px-4 py-2 bg-green-600 hover:bg-green-700 disabled:bg-gray-400 text-white rounded-md text-sm font-medium"
                >
                  {testingOidc ? 'Testing...' : 'Test Connection'}
                </button>
                <button
                  type="button"
                  onClick={handleCancelOidcForm}
                  className="px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md text-sm font-medium text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700"
                >
                  Cancel
                </button>
              </div>
            </form>
          )}

          {!showOidcForm && !editingOidc && (
            <div className="space-y-3">
              {oidcProviders === null || loadingOidc ? (
                <p className="text-gray-500 dark:text-gray-400 text-center py-8">
                  Loading OIDC providers...
                </p>
              ) : oidcProviders.length === 0 ? (
                <p className="text-gray-500 dark:text-gray-400 text-center py-8">
                  No OIDC providers configured. Add your first provider to enable single sign-on.
                </p>
              ) : (
                oidcProviders.map((provider) => (
                  <div key={provider.id} className="bg-white dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700 shadow-sm">
                    <div className="flex justify-between items-start">
                      <div>
                        <div className="flex items-center gap-2">
                          <h3 className="text-lg font-medium text-gray-900 dark:text-white">{provider.display_name}</h3>
                          <span className={`px-2 py-0.5 text-xs font-medium rounded-full ${
                            provider.enabled
                              ? 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300'
                              : 'bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400'
                          }`}>
                            {provider.enabled ? 'Enabled' : 'Disabled'}
                          </span>
                        </div>
                        <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">{provider.issuer_url}</p>
                        <p className="text-xs text-gray-500 dark:text-gray-500 mt-1">
                          Name: {provider.name} | Client ID: {provider.client_id.substring(0, 20)}...
                        </p>
                        {provider.admin_group && (
                          <p className="text-xs text-purple-600 dark:text-purple-400 mt-1">
                            Admin group: {provider.admin_group}
                          </p>
                        )}
                      </div>
                      <div className="flex space-x-2">
                        <button
                          onClick={() => handleEditOidc(provider)}
                          className="px-3 py-1 text-sm text-blue-600 dark:text-blue-400 hover:bg-blue-50 dark:hover:bg-blue-900/20 rounded"
                        >
                          Edit
                        </button>
                        <button
                          onClick={() => handleDeleteOidc(provider.id)}
                          disabled={saving}
                          className="px-3 py-1 text-sm text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 rounded"
                        >
                          Delete
                        </button>
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          )}
        </div>
      )}

      {activeTab === 'advanced' && (
        <div className="max-w-2xl">
          <h2 className="text-lg font-medium text-gray-900 dark:text-white mb-4">Advanced Settings</h2>
          <div className="mb-4 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 text-yellow-800 dark:text-yellow-200 px-4 py-3 rounded text-sm">
            ⚠️ Changing CORS origins will restart the application
          </div>

          <div>
            <label htmlFor="cors_origins" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              CORS Origins (comma-separated)
            </label>
            <textarea
              id="cors_origins"
              rows={3}
              value={corsOrigins}
              onChange={(e) => setCorsOrigins(e.target.value)}
              placeholder="http://localhost:3000, http://192.168.1.100:8000"
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
            />
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
              Example: http://localhost:3000, http://192.168.1.100:8000
            </p>
          </div>

          <button
            onClick={handleSaveCors}
            disabled={saving}
            className="mt-6 px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 text-white rounded-md text-sm font-medium"
          >
            {saving ? 'Saving...' : 'Save CORS Settings'}
          </button>
        </div>
      )}

      {activeTab === 'users' && <Users />}

      {activeTab === 'api-keys' && <ApiKeys />}

      {showRestartModal && !restarting && (
        <div className="fixed inset-0 bg-gray-900 bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl p-6 max-w-md">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
              Restart Required
            </h3>
            <p className="text-sm text-gray-600 dark:text-gray-400 mb-6">
              Settings saved successfully. The application needs to restart for these changes to take effect.
              This will take about 10-15 seconds.
            </p>
            <div className="flex space-x-3 justify-end">
              <button
                onClick={() => setShowRestartModal(false)}
                className="px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md text-sm font-medium text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700"
              >
                Restart Later
              </button>
              <button
                onClick={handleRestart}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-md text-sm font-medium"
              >
                Restart Now
              </button>
            </div>
          </div>
        </div>
      )}

      {restarting && (
        <div className="fixed inset-0 bg-gray-900 bg-opacity-75 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl p-8 text-center">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
            <p className="text-lg font-medium text-gray-900 dark:text-white">
              Restarting application...
            </p>
            <p className="text-sm text-gray-500 dark:text-gray-400 mt-2">
              Please wait...
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
