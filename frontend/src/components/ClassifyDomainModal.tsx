import { useState, useEffect } from 'react';
import { classifyApi } from '../utils/api';
import { getErrorMessage } from '../utils/errors';
import { nearestSuggestion } from '../utils/typoGuard';
import AutocompleteInput from './AutocompleteInput';
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
  const [appNameOptions, setAppNameOptions] = useState<string[]>([]);
  const [categoryOptions, setCategoryOptions] = useState<string[]>([]);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [guardPrompt, setGuardPrompt] = useState<{ appSug: string | null; catSug: string | null } | null>(null);

  useEffect(() => {
    (async () => {
      try {
        const [lbl, sug] = await Promise.all([
          classifyApi.label(domain),
          classifyApi.suggestions(),
        ]);
        setInfo(lbl);
        setAppName(lbl.app_name ?? '');
        setCategory(lbl.category ?? '');
        setAppNameOptions(sug.app_names);
        setCategoryOptions(sug.categories.filter((c) => c && c !== 'Uncategorized'));
      } catch (err: unknown) {
        setError(getErrorMessage(err, 'Failed to load domain info'));
      }
    })();
  }, [domain]);

  const doClassify = async (appNameArg?: string, categoryArg?: string) => {
    try {
      setSaving(true);
      setError(null);
      setGuardPrompt(null);
      await classifyApi.classify({ domain, app_name: appNameArg, category: categoryArg, scope });
      onClassified();
      onClose();
    } catch (err: unknown) {
      setError(getErrorMessage(err, 'Failed to classify'));
    } finally {
      setSaving(false);
    }
  };

  const handleSave = () => {
    const an = appName.trim();
    const cat = category.trim();
    if (!an && !cat) {
      setError('Enter an app name and/or a category');
      return;
    }
    const appSug = an ? nearestSuggestion(an, appNameOptions) : null;
    const catSug = cat ? nearestSuggestion(cat, categoryOptions) : null;
    if (appSug || catSug) {
      setGuardPrompt({ appSug, catSug });
      return;
    }
    doClassify(an || undefined, cat || undefined);
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
        <AutocompleteInput
          value={appName}
          onChange={(v) => { setAppName(v); setGuardPrompt(null); }}
          options={appNameOptions}
          placeholder="e.g. Notion — leave blank for a category-only tag"
        />

        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Category</label>
        <AutocompleteInput
          value={category}
          onChange={(v) => { setCategory(v); setGuardPrompt(null); }}
          options={categoryOptions}
          placeholder="e.g. Productivity"
        />

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

        {guardPrompt && (
          <div className="mb-3 rounded border border-amber-300 dark:border-amber-700 bg-amber-50 dark:bg-amber-900/20 p-3 text-sm">
            {guardPrompt.appSug && (
              <p className="text-amber-800 dark:text-amber-300">App &ldquo;{appName.trim()}&rdquo; looks close to &ldquo;{guardPrompt.appSug}&rdquo;.</p>
            )}
            {guardPrompt.catSug && (
              <p className="text-amber-800 dark:text-amber-300">Category &ldquo;{category.trim()}&rdquo; looks close to &ldquo;{guardPrompt.catSug}&rdquo;.</p>
            )}
            <div className="mt-2 flex gap-2">
              <button
                onClick={() => {
                  const useApp = guardPrompt.appSug ?? appName.trim();
                  const useCat = guardPrompt.catSug ?? category.trim();
                  doClassify(useApp || undefined, useCat || undefined);
                }}
                disabled={saving}
                className="px-2 py-1 text-xs rounded bg-blue-600 hover:bg-blue-700 text-white disabled:bg-gray-400"
              >
                Use suggested
              </button>
              <button
                onClick={() => doClassify(appName.trim() || undefined, category.trim() || undefined)}
                disabled={saving}
                className="px-2 py-1 text-xs rounded text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700"
              >
                Keep as typed
              </button>
            </div>
          </div>
        )}

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
