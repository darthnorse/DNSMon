import { useState, useEffect, useRef } from 'react';
import { blocklistSourceApi } from '../utils/api';
import { getErrorMessage } from '../utils/errors';
import type { BlocklistSource } from '../types';

interface Props {
  onError: (error: string | null) => void;
  onSuccess: (message: string) => void;
}

export default function BlocklistSourcesSettings({ onError, onSuccess }: Props) {
  const [sources, setSources] = useState<BlocklistSource[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [refreshing, setRefreshing] = useState(false);

  const mountedRef = useRef(true);
  const refreshTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    loadData();
  }, []);

  useEffect(() => {
    return () => {
      mountedRef.current = false;
      if (refreshTimerRef.current) clearTimeout(refreshTimerRef.current);
    };
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      setSources(await blocklistSourceApi.getAll());
      onError(null);
    } catch (err: unknown) {
      onError(getErrorMessage(err, 'Failed to load blocklist sources'));
    } finally {
      setLoading(false);
    }
  };

  const handleToggle = async (src: BlocklistSource) => {
    onError(null);
    try {
      setSaving(true);
      await blocklistSourceApi.toggle(src.id, !src.enabled);
      onSuccess('Saved — categories update shortly');
      await loadData();
    } catch (err: unknown) {
      onError(getErrorMessage(err, 'Failed to update blocklist source'));
    } finally {
      setSaving(false);
    }
  };

  const handleRefresh = async () => {
    try {
      setRefreshing(true);
      onError(null);
      await blocklistSourceApi.refresh();
      onSuccess('Refresh started — categories update shortly');
      refreshTimerRef.current = setTimeout(async () => {
        if (!mountedRef.current) return;
        try {
          setSources(await blocklistSourceApi.getAll());
        } catch {
          // Best-effort reload after refresh
        }
        if (mountedRef.current) setRefreshing(false);
      }, 1500);
    } catch (err: unknown) {
      onError(getErrorMessage(err, 'Failed to trigger refresh'));
      setRefreshing(false);
    }
  };

  const formatDate = (dateStr: string | null): string =>
    dateStr ? new Date(dateStr).toLocaleString() : 'Never';

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-lg font-medium text-gray-900 dark:text-white">Blocklist Sources</h2>
        <button
          onClick={handleRefresh}
          disabled={refreshing || saving}
          className="px-3 py-1 text-sm bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 text-white rounded-md font-medium"
        >
          {refreshing ? 'Refreshing...' : 'Refresh now'}
        </button>
      </div>

      <p className="text-xs text-gray-500 dark:text-gray-400 mb-4">
        Themed blocklists fetched at runtime to label otherwise-uncategorized ad/tracking
        traffic by category. They never override a real app match.
      </p>

      {sources.length === 0 ? (
        <div className="text-center py-8 text-gray-500 dark:text-gray-400 text-sm">
          No blocklist sources configured.
        </div>
      ) : (
        <div className="overflow-x-auto max-h-[36rem] overflow-y-auto border border-gray-200 dark:border-gray-700 rounded-lg">
          <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700 text-sm">
            <thead className="bg-gray-50 dark:bg-gray-700">
              <tr>
                {['Name', 'Category', 'License', 'Domains', 'Last fetched', 'Status', 'Enabled'].map((h) => (
                  <th key={h} className="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wide">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
              {sources.map((src) => (
                <tr key={src.id} className={src.enabled ? '' : 'opacity-50'}>
                  <td className="px-3 py-2 font-medium text-gray-900 dark:text-white whitespace-nowrap">{src.name}</td>
                  <td className="px-3 py-2 text-gray-600 dark:text-gray-400 whitespace-nowrap">{src.category}</td>
                  <td className="px-3 py-2 text-gray-600 dark:text-gray-400 whitespace-nowrap">{src.license ?? '—'}</td>
                  <td className="px-3 py-2 text-gray-600 dark:text-gray-400 whitespace-nowrap">
                    {src.domain_count?.toLocaleString() ?? '—'}
                  </td>
                  <td className="px-3 py-2 text-gray-600 dark:text-gray-400 whitespace-nowrap">{formatDate(src.last_fetched_at)}</td>
                  <td className="px-3 py-2 whitespace-nowrap">
                    {src.last_status === 'error' ? (
                      <span className="text-red-600 dark:text-red-400">error</span>
                    ) : src.last_status === 'ok' ? (
                      <span className="text-green-600 dark:text-green-400">ok</span>
                    ) : (
                      <span className="text-gray-400">—</span>
                    )}
                  </td>
                  <td className="px-3 py-2">
                    <button
                      onClick={() => handleToggle(src)}
                      disabled={saving || refreshing}
                      className={`relative inline-flex h-5 w-9 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                        src.enabled ? 'bg-blue-600' : 'bg-gray-300 dark:bg-gray-600'
                      } ${saving || refreshing ? 'opacity-50 cursor-not-allowed' : ''}`}
                      role="switch"
                      aria-checked={src.enabled}
                      title={src.enabled ? 'Disable' : 'Enable'}
                    >
                      <span
                        className={`pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${
                          src.enabled ? 'translate-x-4' : 'translate-x-0'
                        }`}
                      />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
