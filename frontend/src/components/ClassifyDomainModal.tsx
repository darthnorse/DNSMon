import { useState, useEffect } from 'react';
import { classifyApi, insightsApi } from '../utils/api';
import { getErrorMessage } from '../utils/errors';
import type { DomainLabelInfo } from '../types';

interface Props {
  domain: string;
  onClose: () => void;
  onClassified: () => void;
}

export default function ClassifyDomainModal({ domain, onClose, onClassified }: Props) {
  const [info, setInfo] = useState<DomainLabelInfo | null>(null);
  const [appName, setAppName] = useState('');
  const [category, setCategory] = useState('');
  const [scope, setScope] = useState<'registrable' | 'exact'>('registrable');
  const [categoryOptions, setCategoryOptions] = useState<string[]>([]);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      try {
        const [lbl, cats] = await Promise.all([
          classifyApi.label(domain),
          insightsApi.categories(),
        ]);
        setInfo(lbl);
        setAppName(lbl.app_name ?? '');
        setCategory(lbl.category ?? '');
        setCategoryOptions(cats.map((c) => c.category).filter((c) => c && c !== 'Uncategorized'));
      } catch (err: unknown) {
        setError(getErrorMessage(err, 'Failed to load domain info'));
      }
    })();
  }, [domain]);

  const handleSave = async () => {
    if (!appName.trim() && !category.trim()) {
      setError('Enter an app name and/or a category');
      return;
    }
    try {
      setSaving(true);
      setError(null);
      await classifyApi.classify({
        domain,
        app_name: appName.trim() || undefined,
        category: category.trim() || undefined,
        scope,
      });
      onClassified();
      onClose();
    } catch (err: unknown) {
      setError(getErrorMessage(err, 'Failed to classify'));
    } finally {
      setSaving(false);
    }
  };

  const handleRemove = async () => {
    try {
      setSaving(true);
      setError(null);
      await classifyApi.remove(domain, scope);
      onClassified();
      onClose();
    } catch (err: unknown) {
      setError(getErrorMessage(err, 'Failed to remove'));
    } finally {
      setSaving(false);
    }
  };

  const isManual = info?.matched && info.matched_source === 'manual';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4" onClick={onClose}>
      <div className="w-full max-w-md rounded-lg bg-white dark:bg-gray-800 p-5 shadow-xl"
           onClick={(e) => e.stopPropagation()}>
        <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-1">Classify domain</h3>
        <p className="text-sm text-gray-500 dark:text-gray-400 break-all mb-4">{domain}</p>

        {info?.matched && (
          <p className="text-xs mb-3 text-gray-500 dark:text-gray-400">
            Currently: <span className="font-medium">{info.app_name ?? info.category}</span>
            {' '}(via {info.matched_source}){!isManual && ' — saving creates a manual override'}
          </p>
        )}

        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">App name (optional)</label>
        <input value={appName} onChange={(e) => setAppName(e.target.value)}
               placeholder="e.g. Notion — leave blank for a category-only tag"
               className="w-full mb-3 rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white px-3 py-2 text-sm" />

        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Category</label>
        <input value={category} onChange={(e) => setCategory(e.target.value)} list="dnsmon-category-options"
               placeholder="e.g. Productivity"
               className="w-full mb-3 rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white px-3 py-2 text-sm" />
        <datalist id="dnsmon-category-options">
          {categoryOptions.map((c) => <option key={c} value={c} />)}
        </datalist>

        <fieldset className="mb-4 text-sm">
          <label className="flex items-center gap-2 mb-1 text-gray-700 dark:text-gray-300">
            <input type="radio" checked={scope === 'registrable'} onChange={() => setScope('registrable')} />
            Whole domain <span className="font-mono text-xs">{info?.registrable ?? '…'}</span> (recommended)
          </label>
          <label className="flex items-center gap-2 text-gray-700 dark:text-gray-300">
            <input type="radio" checked={scope === 'exact'} onChange={() => setScope('exact')} />
            This exact host <span className="font-mono text-xs break-all">{domain}</span>
          </label>
        </fieldset>

        {error && <div className="mb-3 text-sm text-red-600 dark:text-red-400">{error}</div>}

        <div className="flex justify-between gap-2">
          {isManual ? (
            <button onClick={handleRemove} disabled={saving}
              className="px-3 py-2 text-sm rounded text-red-700 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 disabled:opacity-50">
              Remove
            </button>
          ) : <span />}
          <div className="flex gap-2">
            <button onClick={onClose} disabled={saving}
              className="px-3 py-2 text-sm rounded text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700">
              Cancel
            </button>
            <button onClick={handleSave} disabled={saving}
              className="px-3 py-2 text-sm rounded bg-blue-600 hover:bg-blue-700 text-white disabled:bg-gray-400">
              {saving ? 'Saving…' : 'Save'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
