import { useEffect, useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { format } from 'date-fns';

import { queryApi } from '../utils/api';
import { getErrorMessage } from '../utils/errors';
import { buildClientLink } from '../utils/clientLink';
import {
  CONTEXT_WINDOWS,
  collapseRepeats,
  formatOffset,
  parseContextLink,
  type ContextRow,
} from '../utils/queryContext';
import { queryRowClass } from '../utils/queryStatus';
import AnswerList from '../components/AnswerList';
import ClientDetailLink from '../components/ClientDetailLink';
import StatusBadge from '../components/StatusBadge';
import ThreatBadge from '../components/ThreatBadge';
import type { ContextScope, Query, QueryContext } from '../types';

const SEGMENT_BASE = 'px-3 py-2 text-sm font-medium transition-colors';
const SEGMENT_ON = 'bg-blue-600 text-white';
const SEGMENT_OFF = 'bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700';

export default function ContextPage() {
  const [urlParams, setUrlParams] = useSearchParams();
  const params = useMemo(() => parseContextLink(urlParams), [urlParams]);

  const [data, setData] = useState<QueryContext | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [collapse, setCollapse] = useState(true);

  const paramsKey = params ? JSON.stringify(params) : '';

  useEffect(() => {
    if (!params) {
      setLoading(false);
      return;
    }
    let cancelled = false;
    const load = async () => {
      try {
        setLoading(true);
        setError(null);
        const result = await queryApi.context(params);
        if (!cancelled) setData(result);
      } catch (err: unknown) {
        if (!cancelled) {
          const status = (err as { response?: { status?: number } }).response?.status;
          setData(null);
          setError(status === 404
            ? 'That query is no longer stored. DNSMon keeps queries for its retention period, then deletes them.'
            : getErrorMessage(err, 'Failed to load query context'));
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    load();
    return () => { cancelled = true; };
    // Keyed on paramsKey, not params: parsing makes a new object on every URL read even when nothing changed.
  }, [paramsKey]);

  const updateParam = (key: 'window' | 'scope', value: string) => {
    const next = new URLSearchParams(urlParams);
    next.set(key, value);
    setUrlParams(next, { replace: true });
  };

  if (!params) {
    return (
      <div className="space-y-4">
        <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Query context</h1>
        <div className="bg-yellow-50 dark:bg-yellow-900/30 border border-yellow-200 dark:border-yellow-800/50 text-yellow-800 dark:text-yellow-200 px-4 py-3 rounded">
          This link is incomplete. Open the context from a query in Search, the Dashboard or a client&apos;s Statistics,
          or link with <code>?client=&lt;ip&gt;&amp;at=&lt;time&gt;</code>.
        </div>
      </div>
    );
  }

  const anchor = data?.anchor ?? null;
  const clientName = anchor?.client_hostname;
  const clientIp = data?.client_ip ?? params.client_ip ?? '';
  const total = data ? data.before.length + data.after.length + (anchor ? 1 : 0) : 0;
  const range = data ? {
    from: new Date(new Date(data.center).getTime() - data.window * 60000),
    to: new Date(new Date(data.center).getTime() + data.window * 60000),
  } : null;
  const rangeLabel = range ? `${format(range.from, 'HH:mm:ss')} – ${format(range.to, 'HH:mm:ss')}` : '';
  const searchLink = range && data
    ? buildClientLink('/search', { client: data.scope === 'device' ? clientIp : null, ...range })
    : null;
  const truncationNote = data
    ? `Only the lookups closest to ${anchor ? 'the anchored query' : 'this moment'} are shown. Narrow the window${data.scope === 'all' ? ' or switch to this device' : ''} to see the rest.`
    : '';
  const toRows = (queries: Query[]): ContextRow[] => (collapse ? collapseRepeats(queries) : queries.map((query) => ({ query, repeat: 1 })));

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-3">
        <h1 className="text-3xl font-bold text-gray-900 dark:text-white break-all">
          Query context
          {clientIp && (
            <span className="font-normal text-gray-500 dark:text-gray-400">
              {' '}&ndash; {clientName ? `${clientName} (${clientIp})` : clientIp}
            </span>
          )}
        </h1>
        {searchLink && (
          <Link to={searchLink} className="text-sm font-medium text-blue-600 dark:text-blue-400 hover:underline">
            Open this range in Search &rarr;
          </Link>
        )}
      </div>

      {error && (
        <div className="bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800/50 text-red-700 dark:text-red-300 px-4 py-3 rounded">
          {error}
        </div>
      )}

      {data && (anchor ? <AnchorCard anchor={anchor} /> : (
        <div className="bg-white dark:bg-gray-800 shadow rounded-lg px-6 py-4 text-sm text-gray-700 dark:text-gray-300">
          No lookup from {clientIp}{params.domain ? ` for ${params.domain}` : ''} within &plusmn;{data.window} min of{' '}
          {format(new Date(data.center), 'MMM dd, HH:mm:ss')}. Showing everything around that moment instead.
        </div>
      ))}

      <div className="flex flex-wrap items-center gap-x-6 gap-y-3">
        <div className="flex items-center gap-2">
          <span className="text-sm text-gray-700 dark:text-gray-300">Window</span>
          <div className="flex rounded-lg overflow-hidden border border-gray-300 dark:border-gray-600">
            {CONTEXT_WINDOWS.map((w) => (
              <button
                key={w}
                type="button"
                aria-pressed={params.window === w}
                onClick={() => updateParam('window', String(w))}
                className={`${SEGMENT_BASE} ${params.window === w ? SEGMENT_ON : SEGMENT_OFF}`}
              >
                &plusmn;{w} min
              </button>
            ))}
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-sm text-gray-700 dark:text-gray-300">Devices</span>
          <div className="flex rounded-lg overflow-hidden border border-gray-300 dark:border-gray-600">
            {(['device', 'all'] as ContextScope[]).map((s) => (
              <button
                key={s}
                type="button"
                aria-pressed={params.scope === s}
                onClick={() => updateParam('scope', s)}
                className={`${SEGMENT_BASE} ${params.scope === s ? SEGMENT_ON : SEGMENT_OFF}`}
              >
                {s === 'device' ? 'This device' : 'All devices'}
              </button>
            ))}
          </div>
        </div>
        <label className="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300 cursor-pointer">
          <input
            type="checkbox"
            checked={collapse}
            onChange={(e) => setCollapse(e.target.checked)}
            className="rounded border-gray-300 dark:border-gray-600 text-blue-600 focus:ring-blue-500"
          />
          Collapse repeated lookups
        </label>
        {data && (
          <span className="text-sm text-gray-500 dark:text-gray-400">
            {rangeLabel} &middot; {total.toLocaleString()} lookups
          </span>
        )}
      </div>

      {loading && !data && (
        <div className="text-gray-500 dark:text-gray-400">Loading&hellip;</div>
      )}

      {data && (
        <div className={`bg-white dark:bg-gray-800 shadow rounded-lg overflow-x-auto ${loading ? 'opacity-60' : ''}`}>
          <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
            <thead className="bg-gray-50 dark:bg-gray-700">
              <tr>
                {['Time', 'Offset', 'Domain', ...(data.scope === 'all' ? ['Client'] : []), 'Type', 'Status'].map((h) => (
                  <th key={h} className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
              <SectionRows
                label={`Before · ${data.window} min`}
                truncated={data.truncated_before ? truncationNote : null}
                rows={toRows(data.before)}
                center={data.center}
                showClient={data.scope === 'all'}
              />
              {anchor && (
                <QueryRow row={{ query: anchor, repeat: 1 }} center={data.center} showClient={data.scope === 'all'} isAnchor />
              )}
              <SectionRows
                label={`After · ${data.window} min`}
                truncated={data.truncated_after ? truncationNote : null}
                rows={toRows(data.after)}
                center={data.center}
                showClient={data.scope === 'all'}
              />
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function AnchorCard({ anchor }: { anchor: Query }) {
  return (
    <div className="bg-white dark:bg-gray-800 shadow rounded-lg px-6 py-5 ring-2 ring-blue-500 flex flex-wrap items-center gap-x-8 gap-y-4">
      <div className="min-w-0">
        <div className="text-xs font-semibold uppercase tracking-wider text-blue-700 dark:text-blue-300">Anchored on</div>
        <div className="mt-1 flex flex-wrap items-center gap-2 text-xl font-semibold font-mono text-gray-900 dark:text-white break-all">
          {anchor.domain}
          <ThreatBadge threatType={anchor.threat_type} />
        </div>
      </div>
      <div>
        <div className="text-xs text-gray-500 dark:text-gray-400">Time</div>
        <div className="text-sm text-gray-900 dark:text-gray-200">{format(new Date(anchor.timestamp), 'MMM dd, HH:mm:ss')}</div>
      </div>
      <div>
        <div className="text-xs text-gray-500 dark:text-gray-400">Status</div>
        <div className="mt-0.5"><StatusBadge status={anchor.status} /></div>
      </div>
      <div>
        <div className="text-xs text-gray-500 dark:text-gray-400">Server</div>
        <div className="text-sm text-gray-900 dark:text-gray-200">{anchor.server}</div>
      </div>
    </div>
  );
}

function SectionRows({ label, truncated, rows, center, showClient }: {
  label: string;
  truncated: string | null;
  rows: ContextRow[];
  center: string;
  showClient: boolean;
}) {
  const span = showClient ? 6 : 5;
  return (
    <>
      <tr className="bg-gray-50 dark:bg-gray-900/40">
        <td colSpan={span} className="px-4 py-2 text-xs font-semibold uppercase tracking-wider text-gray-500 dark:text-gray-400">
          {label}
        </td>
      </tr>
      {truncated && (
        <tr>
          <td colSpan={span} className="px-4 py-2 text-sm text-yellow-800 dark:text-yellow-200 bg-yellow-50 dark:bg-yellow-900/30">
            {truncated}
          </td>
        </tr>
      )}
      {rows.length === 0 && (
        <tr>
          <td colSpan={span} className="px-4 py-3 text-sm text-gray-500 dark:text-gray-400">No lookups</td>
        </tr>
      )}
      {rows.map((row) => (
        <QueryRow key={row.query.id} row={row} center={center} showClient={showClient} />
      ))}
    </>
  );
}

function QueryRow({ row, center, showClient, isAnchor = false }: {
  row: ContextRow;
  center: string;
  showClient: boolean;
  isAnchor?: boolean;
}) {
  const { query, repeat } = row;
  const className = isAnchor ? 'bg-blue-50 dark:bg-blue-900/30 ring-2 ring-inset ring-blue-500' : queryRowClass(query.status);
  return (
    <tr className={className}>
      <td className="px-4 py-2 whitespace-nowrap text-sm text-gray-700 dark:text-gray-300 tabular-nums">
        {format(new Date(query.timestamp), 'HH:mm:ss')}
      </td>
      <td className={`px-4 py-2 whitespace-nowrap text-sm tabular-nums ${isAnchor ? 'font-semibold text-blue-700 dark:text-blue-300' : 'text-gray-500 dark:text-gray-400'}`}>
        {formatOffset(query.timestamp, center)}
      </td>
      <td className="px-4 py-2 text-sm text-gray-900 dark:text-gray-200">
        <span className="flex flex-wrap items-center gap-2 font-mono break-all">
          {query.domain}
          {repeat > 1 && (
            <span className="px-2 py-0.5 rounded-full text-xs font-sans bg-gray-200 dark:bg-gray-700 text-gray-800 dark:text-gray-200">&times;{repeat}</span>
          )}
          <ThreatBadge threatType={query.threat_type} />
          {isAnchor && (
            <span className="px-2 py-0.5 rounded-full text-xs font-sans bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200">this query</span>
          )}
        </span>
        <span className="mt-0.5 block"><AnswerList ips={query.answer_ips} cnames={query.answer_cnames} geo={query.answer_geo} compact /></span>
      </td>
      {showClient && (
        <td className="px-4 py-2 whitespace-nowrap text-sm">
          <ClientDetailLink clientIp={query.client_ip}>{query.client_hostname || query.client_ip}</ClientDetailLink>
        </td>
      )}
      <td className="px-4 py-2 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">{query.query_type || '-'}</td>
      <td className="px-4 py-2 whitespace-nowrap text-sm"><StatusBadge status={query.status} /></td>
    </tr>
  );
}
