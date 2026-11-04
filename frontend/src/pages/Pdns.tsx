import { useEffect, useState } from 'react';
import type { FormEvent, ReactNode } from 'react';
import { useSearchParams } from 'react-router-dom';
import { format } from 'date-fns';

import ClientDetailLink from '../components/ClientDetailLink';
import PdnsLink from '../components/PdnsLink';
import { pdnsApi } from '../utils/api';
import { getErrorMessage } from '../utils/errors';
import { isIpAddress } from '../utils/pdns';
import type { PdnsDomainResponse, PdnsIpResponse } from '../types';

// Mirrors PDNS_ROW_LIMIT in backend/routes/pdns.py, so a full list is labelled as cut off.
const ROW_LIMIT = 500;

const HEADER_CLASS = 'px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider';
const CELL_CLASS = 'px-4 py-2 whitespace-nowrap text-sm text-gray-700 dark:text-gray-300';

type LookupResult = { kind: 'ip'; data: PdnsIpResponse } | { kind: 'domain'; data: PdnsDomainResponse };

const formatTime = (value: string): string => format(new Date(value), 'MMM dd, yyyy HH:mm:ss');

function ResultTable({ title, headers, rowCount, empty, children }: {
  title: string;
  headers: string[];
  rowCount: number;
  empty: string;
  children: ReactNode;
}) {
  return (
    <div className="bg-white dark:bg-gray-800 shadow rounded-lg overflow-hidden">
      <div className="px-4 py-3 border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-700">
        <h2 className="text-lg font-medium text-gray-900 dark:text-white">{title}</h2>
      </div>
      {rowCount === 0 ? (
        <p className="px-4 py-3 text-sm text-gray-500 dark:text-gray-400">{empty}</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
            <thead className="bg-gray-50 dark:bg-gray-700">
              <tr>{headers.map((h) => <th key={h} className={HEADER_CLASS}>{h}</th>)}</tr>
            </thead>
            <tbody className="divide-y divide-gray-200 dark:divide-gray-700">{children}</tbody>
          </table>
          {rowCount >= ROW_LIMIT && (
            <p className="px-4 py-3 text-sm text-yellow-800 dark:text-yellow-200 bg-yellow-50 dark:bg-yellow-900/30">
              Only the {ROW_LIMIT} most recent are shown.
            </p>
          )}
        </div>
      )}
    </div>
  );
}

function IpView({ data }: { data: PdnsIpResponse }) {
  return (
    <>
      <ResultTable
        title="Domains that resolved to this IP"
        headers={['Domain', 'First seen', 'Last seen', 'Count', 'Servers']}
        rowCount={data.domains.length}
        empty="No stored lookup resolved to this IP."
      >
        {data.domains.map((row) => (
          <tr key={row.domain}>
            <td className="min-w-[14rem] px-4 py-2 text-sm"><PdnsLink value={row.domain} /></td>
            <td className={CELL_CLASS}>{formatTime(row.first_seen)}</td>
            <td className={CELL_CLASS}>{formatTime(row.last_seen)}</td>
            <td className={`${CELL_CLASS} tabular-nums`}>{row.count.toLocaleString()}</td>
            <td className={CELL_CLASS}>{row.servers.join(', ')}</td>
          </tr>
        ))}
      </ResultTable>
      <ResultTable
        title="Devices that looked them up"
        headers={['Client', 'Hostname', 'Last seen', 'Count']}
        rowCount={data.clients.length}
        empty="No devices."
      >
        {data.clients.map((row) => (
          <tr key={row.client_ip}>
            <td className={CELL_CLASS}><ClientDetailLink clientIp={row.client_ip}>{row.client_ip}</ClientDetailLink></td>
            <td className={CELL_CLASS}>{row.client_hostname || '-'}</td>
            <td className={CELL_CLASS}>{formatTime(row.last_seen)}</td>
            <td className={`${CELL_CLASS} tabular-nums`}>{row.count.toLocaleString()}</td>
          </tr>
        ))}
      </ResultTable>
    </>
  );
}

function AnswerTable({ title, column, rows, empty }: {
  title: string;
  column: string;
  rows: { value: string; first_seen: string; last_seen: string; count: number }[];
  empty: string;
}) {
  return (
    <ResultTable title={title} headers={[column, 'First seen', 'Last seen', 'Count']} rowCount={rows.length} empty={empty}>
      {rows.map((row) => (
        <tr key={row.value}>
          <td className="min-w-[14rem] px-4 py-2 text-sm"><PdnsLink value={row.value} /></td>
          <td className={CELL_CLASS}>{formatTime(row.first_seen)}</td>
          <td className={CELL_CLASS}>{formatTime(row.last_seen)}</td>
          <td className={`${CELL_CLASS} tabular-nums`}>{row.count.toLocaleString()}</td>
        </tr>
      ))}
    </ResultTable>
  );
}

function DomainView({ data }: { data: PdnsDomainResponse }) {
  if (!data.has_answer_data) {
    return (
      <div className="bg-white dark:bg-gray-800 shadow rounded-lg px-6 py-4 text-sm text-gray-700 dark:text-gray-300">
        No answers are stored for {data.domain}. It may not have been looked up within the retention period,
        or only through servers that don&apos;t report answers, such as Pi-hole.
      </div>
    );
  }
  return (
    <>
      <AnswerTable
        title="IPs"
        column="IP"
        rows={data.ips.map((row) => ({ ...row, value: row.ip }))}
        empty="No IPs in any stored answer."
      />
      <AnswerTable
        title="CNAMEs"
        column="CNAME"
        rows={data.cnames.map((row) => ({ ...row, value: row.cname }))}
        empty="No CNAMEs in any stored answer."
      />
    </>
  );
}

export default function Pdns() {
  const [urlParams, setUrlParams] = useSearchParams();
  const q = (urlParams.get('q') ?? '').trim();

  const [input, setInput] = useState(q);
  const [result, setResult] = useState<LookupResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setInput(q);
    setResult(null);
    setError(null);
    setLoading(false);
    if (!q) return;
    let cancelled = false;
    const load = async () => {
      try {
        setLoading(true);
        const next: LookupResult = isIpAddress(q)
          ? { kind: 'ip', data: await pdnsApi.ip(q) }
          : { kind: 'domain', data: await pdnsApi.domain(q) };
        if (!cancelled) setResult(next);
      } catch (err: unknown) {
        if (!cancelled) setError(getErrorMessage(err, 'Lookup failed'));
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    load();
    return () => { cancelled = true; };
  }, [q]);

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    const value = input.trim();
    setUrlParams(value ? { q: value } : {});
  };

  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold text-gray-900 dark:text-white">DNS Lookup</h1>

      <form onSubmit={handleSubmit} className="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
        <label htmlFor="pdns-q" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
          IP address or domain
        </label>
        <div className="mt-1 flex flex-col sm:flex-row gap-3">
          <input
            type="text"
            id="pdns-q"
            placeholder="e.g., 17.253.23.205 or apple.com"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            className="block w-full rounded-md border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm px-3 py-2 border"
          />
          <button
            type="submit"
            disabled={loading}
            className="inline-flex justify-center whitespace-nowrap rounded-md border border-transparent bg-blue-600 py-2 px-4 text-sm font-medium text-white shadow-sm hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 disabled:opacity-50"
          >
            {loading ? 'Looking up...' : 'Look up'}
          </button>
        </div>
        <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">
          Built from the answers stored with each query. Only servers that report answers contribute, so Pi-hole lookups don&apos;t appear here.
        </p>
      </form>

      {error && (
        <div className="bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800/50 text-red-700 dark:text-red-300 px-4 py-3 rounded">
          {error}
        </div>
      )}

      {loading && <div className="text-gray-500 dark:text-gray-400">Loading&hellip;</div>}

      {result && (
        <>
          <h2 className="text-xl font-semibold font-mono text-gray-900 dark:text-white break-all">{q}</h2>
          {result.kind === 'ip' ? <IpView data={result.data} /> : <DomainView data={result.data} />}
        </>
      )}
    </div>
  );
}
