import React, { useState, useEffect } from 'react';
import { settingsApi, syncApi } from '../utils/api';
import type { PiholeServer, PiholeServerCreate, ServerType } from '../types';

type TabType = 'servers' | 'telegram' | 'polling' | 'sync' | 'advanced';

export default function Settings() {
  const [activeTab, setActiveTab] = useState<TabType>('servers');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  // Pi-hole servers
  const [servers, setServers] = useState<PiholeServer[]>([]);
  const [showServerForm, setShowServerForm] = useState(false);
  const [editingServer, setEditingServer] = useState<PiholeServer | null>(null);
  const [serverFormData, setServerFormData] = useState<PiholeServerCreate>({
    name: '',
    url: '',
    password: '',
    username: '',
    server_type: 'pihole',
    enabled: true,
    is_source: false,
    sync_enabled: false
  });

  // Telegram settings
  const [telegramData, setTelegramData] = useState({
    bot_token: '',
    chat_id: ''
  });
  const [hasExistingToken, setHasExistingToken] = useState(false);

  // Polling & Retention settings
  const [pollingData, setPollingData] = useState({
    poll_interval_seconds: 60,
    query_lookback_seconds: 65,
    retention_days: 60
  });

  // Sync settings
  const [syncInterval, setSyncInterval] = useState(900); // 15 minutes default
  const [syncPreview, setSyncPreview] = useState<any>(null);
  const [syncHistory, setSyncHistory] = useState<any[]>([]);
  const [syncing, setSyncing] = useState(false);
  const [loadingSync, setLoadingSync] = useState(false);
  const [expandedSyncId, setExpandedSyncId] = useState<number | null>(null);

  // CORS settings
  const [corsOrigins, setCorsOrigins] = useState<string>('');

  // Restart modal state
  const [showRestartModal, setShowRestartModal] = useState(false);
  const [restarting, setRestarting] = useState(false);

  // Test connection state
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

  // Load sync history when sync tab becomes active
  useEffect(() => {
    if (activeTab === 'sync') {
      handleLoadSyncHistory();
    }
  }, [activeTab]);

  const loadSettings = async () => {
    try {
      setLoading(true);
      const data = await settingsApi.get();

      // Populate form states
      const existingToken = String(data.app_settings.telegram_bot_token?.value || '');
      setHasExistingToken(existingToken.length > 0);

      setTelegramData({
        bot_token: '',  // Don't show existing token for security
        chat_id: String(data.app_settings.telegram_chat_id?.value || ''),
      });

      setPollingData({
        poll_interval_seconds: Number(data.app_settings.poll_interval_seconds?.value || 60),
        query_lookback_seconds: Number(data.app_settings.query_lookback_seconds?.value || 65),
        retention_days: Number(data.app_settings.retention_days?.value || 60),
      });

      setSyncInterval(Number(data.app_settings.sync_interval_seconds?.value || 900));

      const origins = data.app_settings.cors_origins?.value as string[];
      setCorsOrigins(origins ? origins.join(', ') : '');

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

  // Server CRUD
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

    // Password is required only when creating (not when editing)
    if (!isEditing && (!data.password || data.password.trim().length === 0)) {
      errors.push('Password is required');
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
      setSuccessMessage('Pi-hole server saved successfully');
    } catch (err: unknown) {
      const error = err as { response?: { data?: { detail?: string } } };
      setError(error.response?.data?.detail || 'Failed to save server');
    } finally {
      setSaving(false);
    }
  };

  const handleEditServer = (server: PiholeServer) => {
    setEditingServer(server);
    setServerFormData({
      name: server.name,
      url: server.url,
      password: '', // Don't populate password when editing (it's masked in API response)
      username: server.username || '',
      server_type: server.server_type || 'pihole',
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
      const error = err as { response?: { data?: { detail?: string } } };
      setError(error.response?.data?.detail || 'Failed to delete server');
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
      enabled: true,
      is_source: false,
      sync_enabled: false
    });
    setError(null);
    setTestResult(null);
  };

  const handleTestConnection = async () => {
    const errors = validateServer(serverFormData);
    if (errors.length > 0) {
      setError(errors.join('. '));
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
      const error = err as { response?: { data?: { detail?: string } } };
      setTestResult({
        success: false,
        message: error.response?.data?.detail || 'Test connection failed'
      });
      setError(error.response?.data?.detail || 'Test connection failed');
    } finally {
      setTesting(false);
    }
  };

  // Settings save handlers
  const handleSaveTelegram = async () => {
    try {
      setSaving(true);
      setError(null);

      if (telegramData.bot_token.trim()) {
        await settingsApi.updateSetting('telegram_bot_token', telegramData.bot_token);
      }
      await settingsApi.updateSetting('telegram_chat_id', telegramData.chat_id);

      setSuccessMessage('Telegram settings saved successfully');
      await loadSettings();
    } catch (err: unknown) {
      const error = err as { response?: { data?: { detail?: string } } };
      setError(error.response?.data?.detail || 'Failed to save settings');
    } finally {
      setSaving(false);
    }
  };

  const handleTestTelegram = async () => {
    // If bot token field is empty but we have an existing token, we need to tell the user
    if (!telegramData.bot_token.trim() && hasExistingToken) {
      setError('Please enter your bot token to test the connection (existing token is hidden for security)');
      return;
    }

    if (!telegramData.bot_token.trim()) {
      setError('Bot token is required to test connection');
      return;
    }
    if (!telegramData.chat_id.trim()) {
      setError('Chat ID is required to test connection');
      return;
    }

    try {
      setTesting(true);
      setError(null);
      setTestResult(null);

      const result = await settingsApi.testTelegram(telegramData.bot_token, telegramData.chat_id);
      setTestResult(result);

      if (result.success) {
        setSuccessMessage(result.message);
      } else {
        setError(result.message);
      }
    } catch (err: unknown) {
      const error = err as { response?: { data?: { detail?: string } } };
      setTestResult({
        success: false,
        message: error.response?.data?.detail || 'Test connection failed'
      });
      setError(error.response?.data?.detail || 'Test connection failed');
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

      await settingsApi.updateSetting('retention_days', String(pollingData.retention_days));

      if (needsRestart) {
        setShowRestartModal(true);
      } else {
        setSuccessMessage('Settings saved successfully');
        await loadSettings();
      }
    } catch (err: unknown) {
      const error = err as { response?: { data?: { detail?: string } } };
      setError(error.response?.data?.detail || 'Failed to save settings');
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
      const error = err as { response?: { data?: { detail?: string } } };
      setError(error.response?.data?.detail || 'Failed to save sync interval');
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
      const error = err as { response?: { data?: { detail?: string } } };
      setError(error.response?.data?.detail || 'Failed to load sync preview');
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
      await handleLoadSyncPreview(); // Refresh preview
      await handleLoadSyncHistory(); // Refresh history
    } catch (err: unknown) {
      const error = err as { response?: { data?: { detail?: string } } };
      setError(error.response?.data?.detail || 'Failed to execute sync');
    } finally {
      setSyncing(false);
    }
  };

  const handleLoadSyncHistory = async () => {
    try {
      const history = await syncApi.getHistory(10);
      setSyncHistory(history);
    } catch (err: unknown) {
      const error = err as { response?: { data?: { detail?: string } } };
      console.error('Failed to load sync history:', error.response?.data?.detail);
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
      const error = err as { response?: { data?: { detail?: string } } };
      setError(error.response?.data?.detail || 'Failed to save settings');
    } finally {
      setSaving(false);
    }
  };

  const handleRestart = async () => {
    try {
      setRestarting(true);
      await settingsApi.restart();

      // Wait a bit before polling
      await new Promise(resolve => setTimeout(resolve, 3000));

      // Poll health check
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
            // Continue polling
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

  const tabs = [
    { id: 'servers' as TabType, label: 'DNS Servers' },
    { id: 'telegram' as TabType, label: 'Telegram' },
    { id: 'polling' as TabType, label: 'Polling & Retention' },
    { id: 'sync' as TabType, label: 'Sync' },
    { id: 'advanced' as TabType, label: 'Advanced' },
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

      {/* Tab Navigation */}
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

      {/* Tab Content */}
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
                    placeholder="http://192.168.1.2"
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
                        // Clear username when switching to Pi-hole (Pi-hole doesn't use username)
                        username: newType === 'pihole' ? '' : serverFormData.username
                      });
                    }}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  >
                    <option value="pihole">Pi-hole</option>
                    <option value="adguard">AdGuard Home</option>
                  </select>
                </div>
                <div>
                  <label htmlFor="server_password" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Password {editingServer && <span className="text-blue-600 dark:text-blue-400 text-xs">(optional)</span>}
                  </label>
                  <input
                    type="password"
                    id="server_password"
                    value={serverFormData.password}
                    onChange={(e) => setServerFormData({ ...serverFormData, password: e.target.value })}
                    placeholder={editingServer ? "Leave empty to keep existing password" : "Enter password"}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  />
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
                {/* Sync options - sync only works within the same server type */}
                {(() => {
                  // Check if another server of the same type is already source
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
                        Note: Sync only works between servers of the same type ({serverFormData.server_type === 'pihole' ? 'Pi-hole' : 'AdGuard'} to {serverFormData.server_type === 'pihole' ? 'Pi-hole' : 'AdGuard'})
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
                        <span className={`px-2 py-0.5 text-xs font-medium rounded-full ${
                          server.server_type === 'adguard'
                            ? 'bg-teal-100 dark:bg-teal-900/30 text-teal-800 dark:text-teal-300'
                            : 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300'
                        }`}>
                          {server.server_type === 'adguard' ? 'AdGuard' : 'Pi-hole'}
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

      {activeTab === 'telegram' && (
        <div className="max-w-2xl">
          <h2 className="text-lg font-medium text-gray-900 dark:text-white mb-4">Telegram Notifications</h2>
          <p className="text-sm text-gray-600 dark:text-gray-400 mb-4">
            Leave empty to disable Telegram notifications
          </p>

          <div className="space-y-4">
            <div>
              <label htmlFor="bot_token" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Bot Token {hasExistingToken && <span className="text-green-600 dark:text-green-400 text-xs">(configured ✓)</span>}
              </label>
              <input
                type="password"
                id="bot_token"
                value={telegramData.bot_token}
                onChange={(e) => setTelegramData({ ...telegramData, bot_token: e.target.value })}
                placeholder={hasExistingToken ? "Leave empty to keep existing token" : "Enter Telegram bot token"}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              />
              {hasExistingToken && (
                <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                  For security, the existing token is not displayed. Leave empty to keep it, or enter a new token to update.
                </p>
              )}
            </div>
            <div>
              <label htmlFor="chat_id" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Default Chat ID
              </label>
              <input
                type="text"
                id="chat_id"
                value={telegramData.chat_id}
                onChange={(e) => setTelegramData({ ...telegramData, chat_id: e.target.value })}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              />
            </div>
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

          <div className="flex space-x-3 mt-6">
            <button
              onClick={handleSaveTelegram}
              disabled={saving}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 text-white rounded-md text-sm font-medium"
            >
              {saving ? 'Saving...' : 'Save Telegram Settings'}
            </button>
            <button
              onClick={handleTestTelegram}
              disabled={testing || saving}
              className="px-4 py-2 bg-green-600 hover:bg-green-700 disabled:bg-gray-400 text-white rounded-md text-sm font-medium"
            >
              {testing ? 'Testing...' : 'Test Connection'}
            </button>
          </div>
        </div>
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
          <h2 className="text-lg font-medium text-gray-900 dark:text-white mb-4">Pi-hole Configuration Sync</h2>
          <p className="text-sm text-gray-600 dark:text-gray-400 mb-6">
            Sync configuration (adlists, whitelist, blacklist, groups, DNS settings) from a source Pi-hole to target Pi-holes.
            Each Pi-hole will download and compile gravity independently.
          </p>

          {/* Sync Interval Setting */}
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

          {/* Manual Sync */}
          <div className="mb-6 pb-6 border-b border-gray-200 dark:border-gray-700">
            <h3 className="text-md font-medium text-gray-900 dark:text-white mb-3">Manual Sync</h3>
            <p className="text-sm text-gray-600 dark:text-gray-400 mb-4">
              Trigger an immediate sync from source to all enabled targets. Configure source and targets in the Pi-hole Servers tab.
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

            {/* Sync Preview */}
            {syncPreview && (
              <div className="mt-4 p-4 bg-gray-50 dark:bg-gray-700 rounded-md">
                <h4 className="font-medium text-gray-900 dark:text-white mb-2">Sync Preview</h4>
                <div className="text-sm text-gray-700 dark:text-gray-300">
                  <p><strong>Source:</strong> {syncPreview.source?.name}</p>
                  <p><strong>Targets:</strong> {syncPreview.targets?.length > 0 ? syncPreview.targets.map((t: any) => t.name).join(', ') : 'None'}</p>
                  {syncPreview.teleporter && (
                    <div className="mt-2">
                      <p><strong>Teleporter (Gravity Database):</strong></p>
                      <p className="ml-4 text-xs text-gray-500 dark:text-gray-400">
                        Backup size: {Math.round((syncPreview.teleporter.backup_size_bytes || 0) / 1024)} KB
                      </p>
                      <ul className="list-disc list-inside ml-4 mt-1">
                        {syncPreview.teleporter.includes?.map((item: string) => (
                          <li key={item}>{item.replace(/_/g, ' ')}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                  {syncPreview.config && (
                    <div className="mt-2">
                      <p><strong>Config Settings:</strong></p>
                      <ul className="list-disc list-inside ml-4 mt-1">
                        {syncPreview.config.keys && Object.entries(syncPreview.config.keys as Record<string, string[]>).map(([section, keys]) => (
                          <li key={section}>{section.toUpperCase()}: {keys.join(', ')}</li>
                        ))}
                      </ul>
                      {syncPreview.config.summary && (
                        <div className="mt-1 ml-4 text-xs text-gray-500 dark:text-gray-400">
                          {syncPreview.config.summary.dns_hosts > 0 && <span>Local DNS: {syncPreview.config.summary.dns_hosts} | </span>}
                          {syncPreview.config.summary.dns_cnameRecords > 0 && <span>CNAME: {syncPreview.config.summary.dns_cnameRecords} | </span>}
                          {syncPreview.config.summary.dns_upstreams > 0 && <span>Upstreams: {syncPreview.config.summary.dns_upstreams} | </span>}
                          {syncPreview.config.summary.dns_revServers > 0 && <span>Reverse DNS: {syncPreview.config.summary.dns_revServers}</span>}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>

          {/* Sync History */}
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
                    {syncHistory.map((sync: any) => (
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
                                {/* Duration */}
                                {sync.completed_at && (
                                  <div>
                                    <span className="font-medium">Duration:</span>{' '}
                                    {Math.round((new Date(sync.completed_at).getTime() - new Date(sync.started_at).getTime()) / 1000)}s
                                  </div>
                                )}
                                {/* Teleporter size */}
                                {sync.items_synced?._teleporter_size_bytes > 0 && (
                                  <div>
                                    <span className="font-medium">Teleporter backup:</span>{' '}
                                    {Math.round(sync.items_synced._teleporter_size_bytes / 1024)} KB
                                  </div>
                                )}
                                {/* Config sections */}
                                {sync.items_synced?._config_sections?.length > 0 && (
                                  <div>
                                    <span className="font-medium">Config sections:</span>{' '}
                                    {sync.items_synced._config_sections.join(', ')}
                                  </div>
                                )}
                                {/* Items breakdown */}
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
                                {/* Errors */}
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

      {/* Restart Modal */}
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

      {/* Restarting Overlay */}
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
