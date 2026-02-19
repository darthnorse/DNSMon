import { useState, useEffect } from 'react';
import { apiKeyApi } from '../utils/api';
import { getErrorMessage } from '../utils/errors';
import { copyToClipboard } from '../utils/clipboard';
import type { ApiKey, ApiKeyCreate, ApiKeyCreateResponse } from '../types';

export default function ApiKeys() {
  const [apiKeys, setApiKeys] = useState<ApiKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  const [showForm, setShowForm] = useState(false);
  const [formData, setFormData] = useState<ApiKeyCreate>({
    name: '',
    is_admin: false,
  });

  const [newKeyData, setNewKeyData] = useState<ApiKeyCreateResponse | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    loadApiKeys();
  }, []);

  useEffect(() => {
    if (successMessage) {
      const timer = setTimeout(() => setSuccessMessage(null), 5000);
      return () => clearTimeout(timer);
    }
  }, [successMessage]);

  const loadApiKeys = async () => {
    try {
      setLoading(true);
      const data = await apiKeyApi.getAll();
      setApiKeys(data);
      setError(null);
    } catch (err: unknown) {
      setError(getErrorMessage(err, 'Failed to load API keys'));
    } finally {
      setLoading(false);
    }
  };

  const resetForm = () => {
    setFormData({ name: '', is_admin: false });
    setShowForm(false);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (!formData.name.trim()) {
      setError('Name is required');
      return;
    }

    try {
      setSaving(true);
      const result = await apiKeyApi.create(formData);
      setNewKeyData(result);
      await loadApiKeys();
      resetForm();
    } catch (err: unknown) {
      setError(getErrorMessage(err, 'Failed to create API key'));
    } finally {
      setSaving(false);
    }
  };

  const handleRevoke = async (key: ApiKey) => {
    if (!window.confirm(`Are you sure you want to revoke API key "${key.name}"? This cannot be undone.`)) {
      return;
    }

    try {
      await apiKeyApi.revoke(key.id);
      setSuccessMessage(`API key "${key.name}" revoked`);
      await loadApiKeys();
    } catch (err: unknown) {
      setError(getErrorMessage(err, 'Failed to revoke API key'));
    }
  };

  const handleCopyKey = async () => {
    if (newKeyData?.raw_key) {
      try {
        await copyToClipboard(newKeyData.raw_key);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      } catch {
        setError('Failed to copy to clipboard. Please copy the key manually.');
      }
    }
  };

  const isExpired = (key: ApiKey): boolean => {
    if (!key.expires_at) return false;
    return new Date(key.expires_at) < new Date();
  };

  if (loading) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h2 className="text-lg font-medium text-gray-900 dark:text-white">API Keys</h2>
        <button
          onClick={() => {
            resetForm();
            setShowForm(true);
          }}
          className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 text-sm font-medium"
        >
          Create API Key
        </button>
      </div>

      {error && (
        <div className="bg-red-50 dark:bg-red-900/30 text-red-800 dark:text-red-200 px-4 py-3 rounded">
          {error}
        </div>
      )}

      {successMessage && (
        <div className="bg-green-50 dark:bg-green-900/30 text-green-800 dark:text-green-200 px-4 py-3 rounded">
          {successMessage}
        </div>
      )}

      {/* One-time key reveal modal */}
      {newKeyData && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl p-6 max-w-lg w-full mx-4">
            <h2 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
              API Key Created
            </h2>
            <div className="bg-yellow-50 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-200 px-4 py-3 rounded mb-4 text-sm">
              Copy this key now. It will never be shown again.
            </div>
            <div className="mb-4">
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                API Key
              </label>
              <div className="flex items-center gap-2">
                <code className="flex-1 block px-3 py-2 bg-gray-100 dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-md text-sm font-mono text-gray-900 dark:text-white break-all">
                  {newKeyData.raw_key}
                </code>
                <button
                  onClick={handleCopyKey}
                  className="flex-shrink-0 px-3 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 text-sm font-medium"
                >
                  {copied ? 'Copied!' : 'Copy'}
                </button>
              </div>
            </div>
            <div className="text-sm text-gray-600 dark:text-gray-400 mb-4">
              <p><span className="font-medium">Name:</span> {newKeyData.name}</p>
              <p><span className="font-medium">Role:</span> {newKeyData.is_admin ? 'Admin' : 'Readonly'}</p>
              {newKeyData.expires_at && (
                <p><span className="font-medium">Expires:</span> {new Date(newKeyData.expires_at).toLocaleString()}</p>
              )}
            </div>
            <div className="text-sm text-gray-500 dark:text-gray-400 mb-4">
              Use this key in the <code className="bg-gray-100 dark:bg-gray-700 px-1 py-0.5 rounded text-xs">Authorization</code> header:
              <code className="block mt-1 bg-gray-100 dark:bg-gray-700 px-3 py-2 rounded text-xs break-all">
                Authorization: Bearer {newKeyData.raw_key.substring(0, 12)}...
              </code>
            </div>
            <button
              onClick={() => setNewKeyData(null)}
              className="w-full px-4 py-2 bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-md hover:bg-gray-300 dark:hover:bg-gray-600 text-sm font-medium"
            >
              Done
            </button>
          </div>
        </div>
      )}

      {/* Create Form */}
      {showForm && (
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <h2 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
            Create New API Key
          </h2>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Name <span className="text-red-500">*</span>
                </label>
                <input
                  type="text"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  placeholder='e.g. "Grafana", "Home Assistant"'
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Expires At <span className="text-gray-400 text-xs">(optional)</span>
                </label>
                <input
                  type="datetime-local"
                  value={formData.expires_at || ''}
                  onChange={(e) => setFormData({ ...formData, expires_at: e.target.value || undefined })}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                />
              </div>

              <div className="flex items-center">
                <label className="flex items-center">
                  <input
                    type="checkbox"
                    checked={formData.is_admin}
                    onChange={(e) => setFormData({ ...formData, is_admin: e.target.checked })}
                    className="h-4 w-4 text-blue-600 border-gray-300 rounded"
                  />
                  <span className="ml-2 text-sm text-gray-700 dark:text-gray-300">Administrator</span>
                </label>
                <span className="ml-2 text-xs text-gray-500 dark:text-gray-400">
                  (can modify settings, servers, alerts, etc.)
                </span>
              </div>
            </div>

            <div className="flex gap-3 pt-2">
              <button
                type="submit"
                disabled={saving}
                className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50 text-sm font-medium"
              >
                {saving ? 'Creating...' : 'Create API Key'}
              </button>
              <button
                type="button"
                onClick={resetForm}
                className="px-4 py-2 bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-md hover:bg-gray-300 dark:hover:bg-gray-600 text-sm font-medium"
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      )}

      {/* API Keys Table */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow overflow-hidden">
        <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
          <thead className="bg-gray-50 dark:bg-gray-700">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                Name
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                Key Prefix
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                Role
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                Expires
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                Last Used
              </th>
              <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
            {apiKeys.map((key) => (
              <tr key={key.id} className={isExpired(key) ? 'opacity-50' : ''}>
                <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900 dark:text-white">
                  {key.name}
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <code className="text-sm text-gray-600 dark:text-gray-400 bg-gray-100 dark:bg-gray-700 px-2 py-1 rounded font-mono">
                    {key.key_prefix}...
                  </code>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <span
                    className={`inline-flex px-2 py-1 text-xs font-medium rounded ${
                      key.is_admin
                        ? 'bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200'
                        : 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-300'
                    }`}
                  >
                    {key.is_admin ? 'Admin' : 'Readonly'}
                  </span>
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                  {key.expires_at ? (
                    <span className="flex items-center gap-1">
                      {new Date(key.expires_at).toLocaleDateString()}
                      {isExpired(key) && (
                        <span className="inline-flex px-1.5 py-0.5 text-xs font-medium rounded bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200">
                          Expired
                        </span>
                      )}
                    </span>
                  ) : (
                    'Never'
                  )}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                  {key.last_used_at
                    ? new Date(key.last_used_at).toLocaleString()
                    : 'Never'}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                  <button
                    onClick={() => handleRevoke(key)}
                    className="text-red-600 dark:text-red-400 hover:text-red-900 dark:hover:text-red-300"
                  >
                    Revoke
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {apiKeys.length === 0 && !error && (
          <div className="text-center py-8 text-gray-500 dark:text-gray-400">
            No API keys created yet
          </div>
        )}
      </div>
    </div>
  );
}
