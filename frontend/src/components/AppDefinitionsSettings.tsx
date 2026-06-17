import React, { useState, useEffect } from 'react';
import { appDefinitionApi } from '../utils/api';
import { getErrorMessage } from '../utils/errors';
import { sourceLabel } from '../utils/labels';
import type { AppDefinition, AppDefinitionCreate, FeedStatus } from '../types';

type SourceFilter = 'all' | 'adguard' | 'dnsmon' | 'manual';

interface Props {
  onError: (error: string | null) => void;
  onSuccess: (message: string) => void;
}

export default function AppDefinitionsSettings({ onError, onSuccess }: Props) {
  const [definitions, setDefinitions] = useState<AppDefinition[]>([]);
  const [feedStatus, setFeedStatus] = useState<FeedStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [sourceFilter, setSourceFilter] = useState<SourceFilter>('all');

  const [formData, setFormData] = useState<AppDefinitionCreate>({
    name: '',
    category: null,
    domains: [],
    enabled: true,
  });
  const [domainsText, setDomainsText] = useState('');

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      const [defs, status] = await Promise.all([
        appDefinitionApi.getAll(),
        appDefinitionApi.feedStatus(),
      ]);
      setDefinitions(defs);
      setFeedStatus(status);
      onError(null);
    } catch (err: unknown) {
      onError(getErrorMessage(err, 'Failed to load app definitions'));
    } finally {
      setLoading(false);
    }
  };

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    onError(null);

    const trimmedName = formData.name.trim();
    if (!trimmedName) {
      onError('App name is required');
      return;
    }

    const domains = domainsText
      .split(/[\n,]/)
      .map((d) => d.trim())
      .filter((d) => d.length > 0);

    if (domains.length === 0) {
      onError('At least one domain is required');
      return;
    }

    try {
      setSaving(true);
      await appDefinitionApi.create({
        name: trimmedName,
        category: formData.category?.trim() || null,
        domains,
        enabled: formData.enabled,
      });
      await loadData();
      setFormData({ name: '', category: null, domains: [], enabled: true });
      setDomainsText('');
      onSuccess('App definition created successfully');
    } catch (err: unknown) {
      onError(getErrorMessage(err, 'Failed to create app definition'));
    } finally {
      setSaving(false);
    }
  };

  const handleToggleEnabled = async (def: AppDefinition) => {
    onError(null);
    try {
      setSaving(true);
      await appDefinitionApi.update(def.id, { enabled: !def.enabled });
      await loadData();
    } catch (err: unknown) {
      onError(getErrorMessage(err, 'Failed to update app definition'));
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (def: AppDefinition) => {
    if (!window.confirm(`Delete "${def.name}"? This cannot be undone.`)) {
      return;
    }
    try {
      setSaving(true);
      await appDefinitionApi.delete(def.id);
      await loadData();
      onSuccess('App definition deleted');
    } catch (err: unknown) {
      onError(getErrorMessage(err, 'Failed to delete app definition'));
    } finally {
      setSaving(false);
    }
  };

  const formatDate = (dateStr: string | null): string => {
    if (!dateStr) return 'Never';
    return new Date(dateStr).toLocaleString();
  };

  const SOURCE_BADGE: Record<AppDefinition['source'], string> = {
    adguard: 'bg-teal-100 dark:bg-teal-900/30 text-teal-800 dark:text-teal-300',
    dnsmon: 'bg-purple-100 dark:bg-purple-900/30 text-purple-800 dark:text-purple-300',
    manual: 'bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-300',
  };

  const filteredDefinitions =
    sourceFilter === 'all'
      ? definitions
      : definitions.filter((d) => d.source === sourceFilter);

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div>
      <h2 className="text-lg font-medium text-gray-900 dark:text-white mb-2">App Definitions</h2>

      <p className="text-xs text-gray-500 dark:text-gray-400 mb-4">
        Manage runtime feeds (AdGuard, DNSMon, blocklists) under <span className="font-medium">Insight Sources</span>.
      </p>

      {/* Slim status summary */}
      {feedStatus && (
        <div className="mb-6 bg-gray-50 dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <dl className="grid grid-cols-2 sm:grid-cols-3 gap-3 text-sm">
            <div>
              <dt className="text-gray-500 dark:text-gray-400">Manual apps</dt>
              <dd className="font-medium text-gray-900 dark:text-white">{feedStatus.manual_app_count.toLocaleString()}</dd>
            </div>
            <div>
              <dt className="text-gray-500 dark:text-gray-400">Classified domains</dt>
              <dd className="font-medium text-gray-900 dark:text-white">{feedStatus.labeled_domain_count.toLocaleString()}</dd>
            </div>
            <div>
              <dt className="text-gray-500 dark:text-gray-400">Last refreshed</dt>
              <dd className="font-medium text-gray-900 dark:text-white">{formatDate(feedStatus.last_refreshed_at)}</dd>
            </div>
          </dl>
        </div>
      )}

      {/* Add custom app form */}
      <div className="mb-6 bg-gray-50 dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
        <h3 className="text-sm font-medium text-gray-900 dark:text-white mb-3">Add Custom App</h3>
        <form onSubmit={handleCreate}>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-4">
            <div>
              <label htmlFor="app_name" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Name <span className="text-red-500">*</span>
              </label>
              <input
                type="text"
                id="app_name"
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                placeholder="My App"
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
              />
            </div>
            <div>
              <label htmlFor="app_category" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Category <span className="text-gray-400 font-normal">(optional)</span>
              </label>
              <input
                type="text"
                id="app_category"
                value={formData.category ?? ''}
                onChange={(e) => setFormData({ ...formData, category: e.target.value || null })}
                placeholder="Social Media"
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
              />
            </div>
          </div>

          <div className="mb-4">
            <label htmlFor="app_domains" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Domains <span className="text-red-500">*</span>
            </label>
            <textarea
              id="app_domains"
              rows={4}
              value={domainsText}
              onChange={(e) => setDomainsText(e.target.value)}
              placeholder="example.com&#10;api.example.com&#10;cdn.example.com"
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm font-mono"
            />
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
              One domain per line, or comma-separated.
            </p>
          </div>

          <div className="flex items-center gap-4">
            <div className="flex items-center">
              <input
                type="checkbox"
                id="app_enabled"
                checked={formData.enabled ?? true}
                onChange={(e) => setFormData({ ...formData, enabled: e.target.checked })}
                className="h-4 w-4 text-blue-600 border-gray-300 rounded"
              />
              <label htmlFor="app_enabled" className="ml-2 text-sm text-gray-700 dark:text-gray-300">
                Enabled
              </label>
            </div>
            <button
              type="submit"
              disabled={saving}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 text-white rounded-md text-sm font-medium"
            >
              {saving ? 'Creating...' : 'Create App'}
            </button>
          </div>
        </form>
      </div>

      {/* Definitions table */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-medium text-gray-900 dark:text-white">
            All Definitions
            <span className="ml-2 text-gray-400 font-normal">({filteredDefinitions.length})</span>
          </h3>
          <select
            value={sourceFilter}
            onChange={(e) => setSourceFilter(e.target.value as SourceFilter)}
            className="px-3 py-1.5 text-sm border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
          >
            <option value="all">All sources</option>
            <option value="adguard">AdGuard</option>
            <option value="dnsmon">DNSMon</option>
            <option value="manual">Manual</option>
          </select>
        </div>

        {filteredDefinitions.length === 0 ? (
          <div className="text-center py-8 text-gray-500 dark:text-gray-400 text-sm">
            No app definitions found.
            {sourceFilter !== 'all' && (
              <> Try changing the source filter or{' '}
                <button
                  className="underline"
                  onClick={() => setSourceFilter('all')}
                >
                  show all
                </button>.
              </>
            )}
          </div>
        ) : (
          <div className="overflow-x-auto max-h-[36rem] overflow-y-auto border border-gray-200 dark:border-gray-700 rounded-lg">
            <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700 text-sm">
              <thead className="bg-gray-50 dark:bg-gray-700 sticky top-0 z-10">
                <tr>
                  <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wide">
                    Name
                  </th>
                  <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wide">
                    Category
                  </th>
                  <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wide">
                    Source
                  </th>
                  <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wide">
                    Domains
                  </th>
                  <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wide">
                    Enabled
                  </th>
                  <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wide">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                {filteredDefinitions.map((def) => (
                  <tr key={def.id} className={def.enabled ? '' : 'opacity-50'}>
                    <td className="px-3 py-2 font-medium text-gray-900 dark:text-white whitespace-nowrap">
                      {def.name}
                    </td>
                    <td className="px-3 py-2 text-gray-600 dark:text-gray-400 whitespace-nowrap">
                      {def.category ?? <span className="text-gray-400">—</span>}
                    </td>
                    <td className="px-3 py-2 whitespace-nowrap">
                      <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${SOURCE_BADGE[def.source]}`}>
                        {sourceLabel(def.source)}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-gray-600 dark:text-gray-400">
                      {def.domains.length > 2 ? (
                        <span title={def.domains.join(', ')}>
                          {def.domains.slice(0, 2).join(', ')}
                          <span className="text-gray-400 dark:text-gray-500">
                            {' '}+{def.domains.length - 2} more
                          </span>
                        </span>
                      ) : (
                        def.domains.join(', ')
                      )}
                    </td>
                    <td className="px-3 py-2">
                      <button
                        onClick={() => handleToggleEnabled(def)}
                        disabled={saving}
                        className={`relative inline-flex h-5 w-9 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent align-middle transition-colors duration-200 ease-in-out focus:outline-none ${
                          def.enabled ? 'bg-blue-600' : 'bg-gray-300 dark:bg-gray-600'
                        } ${saving ? 'opacity-50 cursor-not-allowed' : ''}`}
                        role="switch"
                        aria-checked={def.enabled}
                        title={def.enabled ? 'Disable' : 'Enable'}
                      >
                        <span
                          className={`pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${
                            def.enabled ? 'translate-x-4' : 'translate-x-0'
                          }`}
                        />
                      </button>
                    </td>
                    <td className="px-3 py-2 whitespace-nowrap">
                      {def.source === 'manual' && (
                        <button
                          onClick={() => handleDelete(def)}
                          disabled={saving}
                          className="px-2 py-1 text-xs text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 rounded disabled:opacity-50"
                        >
                          Delete
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
