import { useState, useEffect, useRef } from 'react';
import { geoipApi } from '../utils/api';
import { getErrorMessage } from '../utils/errors';
import type { GeoipStatus } from '../types';

interface Props {
  onError: (error: string | null) => void;
  onSuccess: (message: string) => void;
}

const POLL_INTERVAL_MS = 3000;
const POLL_LIMIT = 20;
const MAXMIND_URL = 'https://www.maxmind.com';
const SIGNUP_URL = 'https://www.maxmind.com/en/geolite2/signup';
// A text box followed by a password box looks like a login form, and password managers ignore
// autoComplete="off". These are the opt-outs 1Password, LastPass, Bitwarden and Dashlane read.
const NO_PASSWORD_MANAGER = {
  'data-1p-ignore': true,
  'data-lpignore': 'true',
  'data-bwignore': true,
  'data-form-type': 'other',
};

const formatTime = (value: string | null): string => (value ? new Date(value).toLocaleString() : 'Never');
const formatBuild = (epoch: number | null): string => (epoch ? new Date(epoch * 1000).toLocaleString() : 'None');

function ExternalLink({ href, children }: { href: string; children: string }) {
  return (
    <a href={href} target="_blank" rel="noopener noreferrer" className="text-blue-600 dark:text-blue-400 hover:underline">
      {children}
    </a>
  );
}

export default function GeoipSettings({ onError, onSuccess }: Props) {
  const [status, setStatus] = useState<GeoipStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [polling, setPolling] = useState(false);
  const [stillRunning, setStillRunning] = useState(false);
  const [accountId, setAccountId] = useState('');
  const [licenseKey, setLicenseKey] = useState('');

  const mountedRef = useRef(true);
  const pollTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const pollGenerationRef = useRef(0);

  useEffect(() => {
    mountedRef.current = true;
    loadStatus();
    return () => {
      mountedRef.current = false;
      if (pollTimerRef.current) clearTimeout(pollTimerRef.current);
    };
  }, []);

  const applyStatus = (next: GeoipStatus) => {
    setStatus(next);
    setAccountId(next.account_id ?? '');
  };

  const loadStatus = async () => {
    try {
      applyStatus(await geoipApi.get());
      onError(null);
    } catch (err: unknown) {
      onError(getErrorMessage(err, 'Failed to load GeoIP settings'));
    } finally {
      setLoading(false);
    }
  };

  const stopPolling = () => {
    if (pollTimerRef.current) clearTimeout(pollTimerRef.current);
    pollTimerRef.current = null;
    pollGenerationRef.current += 1;
    setPolling(false);
  };

  const pollUntilChecked = (previousCheck: string | null) => {
    if (pollTimerRef.current) clearTimeout(pollTimerRef.current);
    // A tick already awaiting its response when polling stops must not schedule another.
    const generation = ++pollGenerationRef.current;
    setPolling(true);
    setStillRunning(false);
    let attempts = 0;
    const tick = async () => {
      if (!mountedRef.current) return;
      attempts += 1;
      let next: GeoipStatus | null = null;
      try {
        next = await geoipApi.get();
      } catch {
        // A missed poll is retried; the bounded loop still ends.
      }
      if (!mountedRef.current || generation !== pollGenerationRef.current) return;
      if (next) {
        setStatus(next);
        if (next.last_checked_at !== previousCheck) {
          stopPolling();
          return;
        }
      }
      if (attempts >= POLL_LIMIT) {
        stopPolling();
        setStillRunning(true);
        return;
      }
      pollTimerRef.current = setTimeout(tick, POLL_INTERVAL_MS);
    };
    pollTimerRef.current = setTimeout(tick, POLL_INTERVAL_MS);
  };

  const handleSave = async () => {
    onError(null);
    const trimmedAccount = accountId.trim();
    const trimmedKey = licenseKey.trim();
    try {
      setBusy(true);
      const next = await geoipApi.update({
        ...(trimmedAccount ? { account_id: trimmedAccount } : {}),
        ...(trimmedKey ? { license_key: trimmedKey } : {}),
      });
      applyStatus(next);
      setLicenseKey('');
      if (next.refresh_started) {
        onSuccess('Saved. Downloading the databases in the background.');
        pollUntilChecked(status?.last_checked_at ?? null);
      } else {
        onSuccess('Saved');
      }
    } catch (err: unknown) {
      onError(getErrorMessage(err, 'Failed to save GeoIP settings. Check the account ID (digits only) and license key.'));
    } finally {
      setBusy(false);
    }
  };

  const handleRefresh = async () => {
    onError(null);
    try {
      setBusy(true);
      await geoipApi.refresh();
      onSuccess('Refresh started');
      pollUntilChecked(status?.last_checked_at ?? null);
    } catch (err: unknown) {
      onError(getErrorMessage(err, 'Failed to start refresh'));
    } finally {
      setBusy(false);
    }
  };

  const handleClear = async () => {
    if (!window.confirm('Remove the MaxMind credentials and delete the downloaded GeoIP databases?')) return;
    onError(null);
    try {
      setBusy(true);
      stopPolling();
      setStillRunning(false);
      applyStatus(await geoipApi.update({ clear: true }));
      setLicenseKey('');
      onSuccess('GeoIP credentials cleared');
    } catch (err: unknown) {
      onError(getErrorMessage(err, 'Failed to clear GeoIP settings'));
    } finally {
      setBusy(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  const configured = status?.configured ?? false;
  const inputClass = 'w-full px-3 py-2 text-sm rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white';
  const labelClass = 'block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1';

  return (
    <div className="max-w-2xl">
      <h2 className="text-lg font-medium text-gray-900 dark:text-white mb-4">GeoIP (MaxMind)</h2>

      <p className="text-xs text-gray-500 dark:text-gray-400 mb-4">
        Adds a country and network owner to the IP addresses in DNS answers, using the free GeoLite2 City and ASN
        databases. They are downloaded to this server and refreshed automatically. You need a free MaxMind account:{' '}
        <ExternalLink href={SIGNUP_URL}>sign up for GeoLite2</ExternalLink>.
      </p>

      <div className="space-y-4">
        <div>
          <label htmlFor="geoip-account-id" className={labelClass}>Account ID</label>
          <input
            id="geoip-account-id"
            type="text"
            inputMode="numeric"
            autoComplete="off"
            {...NO_PASSWORD_MANAGER}
            value={accountId}
            onChange={(e) => setAccountId(e.target.value)}
            className={inputClass}
          />
        </div>
        <div>
          <label htmlFor="geoip-license-key" className={labelClass}>License key</label>
          <input
            id="geoip-license-key"
            type="password"
            autoComplete="new-password"
            {...NO_PASSWORD_MANAGER}
            value={licenseKey}
            onChange={(e) => setLicenseKey(e.target.value)}
            placeholder={status?.has_license_key ? 'saved, leave blank to keep' : undefined}
            className={inputClass}
          />
          {status?.license_key_length != null && (
            <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
              Saved key: {status.license_key_length} characters
              {status.license_key_last4 ? `, ending in ${status.license_key_last4}` : ''}
            </p>
          )}
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            onClick={handleSave}
            disabled={busy}
            className="px-3 py-1 text-sm bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 text-white rounded-md font-medium"
          >
            Save
          </button>
          <button
            onClick={handleRefresh}
            disabled={busy || polling || !configured}
            className="px-3 py-1 text-sm bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 text-white rounded-md font-medium"
          >
            {polling ? 'Refreshing...' : 'Refresh now'}
          </button>
          <button
            onClick={handleClear}
            disabled={busy || (!status?.account_id && !status?.has_license_key)}
            className="px-3 py-1 text-sm text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 disabled:opacity-50 rounded"
          >
            Clear
          </button>
        </div>
      </div>

      <dl className="mt-6 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
        <dt className="text-gray-500 dark:text-gray-400">Last updated</dt>
        <dd className="text-gray-900 dark:text-white">{formatTime(status?.last_updated_at ?? null)}</dd>
        <dt className="text-gray-500 dark:text-gray-400">Last checked</dt>
        <dd className="text-gray-900 dark:text-white">{formatTime(status?.last_checked_at ?? null)}</dd>
        <dt className="text-gray-500 dark:text-gray-400">City database</dt>
        <dd className="text-gray-900 dark:text-white">{formatBuild(status?.city_build ?? null)}</dd>
        <dt className="text-gray-500 dark:text-gray-400">ASN database</dt>
        <dd className="text-gray-900 dark:text-white">{formatBuild(status?.asn_build ?? null)}</dd>
      </dl>

      {stillRunning && (
        <p className="mt-3 text-sm text-gray-600 dark:text-gray-400">
          The refresh is still running in the background. A large download can take a few minutes. Reload this page
          to see the result.
        </p>
      )}

      {status?.last_error && (
        <p className="mt-3 text-xs text-red-600 dark:text-red-400 break-all">{status.last_error}</p>
      )}

      <p className="mt-6 text-xs text-gray-500 dark:text-gray-400">
        This product includes GeoLite2 Data created by MaxMind, available from{' '}
        <ExternalLink href={MAXMIND_URL}>https://www.maxmind.com</ExternalLink>
      </p>
    </div>
  );
}
