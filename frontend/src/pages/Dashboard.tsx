import { useEffect, useState } from 'react';
import { statsApi, queryApi, domainApi } from '../utils/api';
import type { Stats, Query } from '../types';
import { format } from 'date-fns';

export default function Dashboard() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [queries, setQueries] = useState<Query[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [hideSystemQueries, setHideSystemQueries] = useState(true); // Hide system queries by default
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState<string | null>(null);

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 60000); // Refresh every minute
    return () => clearInterval(interval);
  }, []);

  // Debounced search as you type
  useEffect(() => {
    const delayDebounceFn = setTimeout(() => {
      if (searchTerm) {
        handleSearch();
      } else {
        // If search is cleared, reload all recent queries
        loadData();
      }
    }, 300); // Wait 300ms after user stops typing

    return () => clearTimeout(delayDebounceFn);
  }, [searchTerm]);

  const loadData = async () => {
    try {
      setLoading(true);
      const [statsData, queriesData] = await Promise.all([
        statsApi.get(),
        queryApi.search({ limit: 100 })
      ]);
      setStats(statsData);
      setQueries(queriesData);
      setError(null);
    } catch (err) {
      setError('Failed to load data');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = async () => {
    try {
      // Default to last 7 days for dashboard search
      const sevenDaysAgo = new Date();
      sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);

      const searchResults = await queryApi.search({
        search: searchTerm || undefined,
        from_date: sevenDaysAgo.toISOString(),
        limit: 100
      });
      setQueries(searchResults);
    } catch (err) {
      console.error('Search failed:', err);
    }
  };

  // Auto-dismiss success messages
  useEffect(() => {
    if (successMessage) {
      const timer = setTimeout(() => setSuccessMessage(null), 5000);
      return () => clearTimeout(timer);
    }
  }, [successMessage]);

  const handleWhitelist = async (domain: string) => {
    try {
      setActionLoading(`whitelist-${domain}`);
      setError(null);
      await domainApi.whitelist(domain);
      setSuccessMessage(`Added "${domain}" to whitelist`);
    } catch (err: unknown) {
      const error = err as { response?: { data?: { detail?: string } } };
      setError(error.response?.data?.detail || `Failed to whitelist ${domain}`);
    } finally {
      setActionLoading(null);
    }
  };

  const handleBlacklist = async (domain: string) => {
    try {
      setActionLoading(`blacklist-${domain}`);
      setError(null);
      await domainApi.blacklist(domain);
      setSuccessMessage(`Added "${domain}" to blacklist`);
    } catch (err: unknown) {
      const error = err as { response?: { data?: { detail?: string } } };
      setError(error.response?.data?.detail || `Failed to blacklist ${domain}`);
    } finally {
      setActionLoading(null);
    }
  };

  if (loading && !stats) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="text-gray-500">Loading...</div>
      </div>
    );
  }

  if (error && !stats) {
    return (
      <div className="bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800/50 text-red-700 dark:text-red-300 px-4 py-3 rounded">
        {error}
      </div>
    );
  }

  if (!stats) return null;

  // Filter out system/network discovery queries if enabled
  const filteredQueries = hideSystemQueries
    ? queries.filter(q => {
        const domain = q.domain.toLowerCase();
        return !(
          domain.endsWith('.arpa') ||                    // Reverse DNS (PTR records)
          domain.includes('_dns-sd._udp') ||             // DNS Service Discovery
          domain.endsWith('.local') ||                    // mDNS/Bonjour
          domain.startsWith('_') ||                       // Other service records
          domain.includes('._tcp.') ||                    // TCP service discovery
          domain.includes('._udp.')                       // UDP service discovery
        );
      })
    : queries;

  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Dashboard</h1>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 gap-4 sm:gap-5 sm:grid-cols-2">
        <div className="bg-white dark:bg-gray-800 overflow-hidden shadow rounded-lg">
          <div className="px-4 py-5 sm:p-6">
            <dt className="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">Queries (24h)</dt>
            <dd className="mt-1 text-3xl font-semibold text-gray-900 dark:text-white">
              {stats.queries_last_24h.toLocaleString()}
            </dd>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 overflow-hidden shadow rounded-lg">
          <div className="px-4 py-5 sm:p-6">
            <dt className="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">Blocks (24h)</dt>
            <dd className="mt-1 text-3xl font-semibold text-red-600 dark:text-red-500">
              {stats.blocks_last_24h.toLocaleString()}
            </dd>
          </div>
        </div>
      </div>

      {/* Error Message */}
      {error && (
        <div className="bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800/50 text-red-700 dark:text-red-300 px-4 py-3 rounded">
          {error}
        </div>
      )}

      {/* Success Message */}
      {successMessage && (
        <div className="bg-green-50 dark:bg-green-900/30 border border-green-200 dark:border-green-800/50 text-green-700 dark:text-green-300 px-4 py-3 rounded">
          {successMessage}
        </div>
      )}

      {/* Search and Query Table */}
      <div className="bg-white dark:bg-gray-800 shadow rounded-lg">
        <div className="px-4 py-5 sm:p-6">
          <div className="mb-4">
            <div className="flex gap-2">
              <input
                type="text"
                placeholder="Search domain, IP, or hostname..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="flex-1 border border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              <button
                onClick={loadData}
                className="bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 px-4 py-2 rounded-md hover:bg-gray-300 dark:hover:bg-gray-600 focus:outline-none focus:ring-2 focus:ring-gray-500"
              >
                Clear
              </button>
            </div>
            <div className="mt-2 flex items-center gap-4">
              <label className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-400 cursor-pointer">
                <input
                  type="checkbox"
                  checked={hideSystemQueries}
                  onChange={(e) => setHideSystemQueries(e.target.checked)}
                  className="rounded border-gray-300 dark:border-gray-600 text-blue-600 focus:ring-blue-500"
                />
                <span>Hide system queries (PTR, DNS-SD, mDNS)</span>
              </label>
              <p className="text-xs text-gray-500 dark:text-gray-400">Last 7 days</p>
            </div>
          </div>

          {/* Mobile Card View */}
          <div className="md:hidden space-y-3">
            {filteredQueries.length === 0 ? (
              <div className="px-4 py-8 text-center text-gray-500 dark:text-gray-400">
                No queries found
              </div>
            ) : (
              filteredQueries.map((query) => {
                const isBlocked = query.status?.toUpperCase().includes('GRAVITY') ||
                                  query.status?.toUpperCase().includes('BLACKLIST');
                return (
                <div
                  key={query.id}
                  className={`rounded-lg p-4 space-y-2 ${
                    isBlocked
                      ? 'bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800/50'
                      : 'bg-gray-50 dark:bg-gray-700'
                  }`}
                >
                  <div className="flex justify-between items-start">
                    <div className="flex-1 min-w-0">
                      <div className="font-medium text-gray-900 dark:text-white truncate">
                        {query.domain}
                      </div>
                      <div className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                        {format(new Date(query.timestamp), 'MMM dd, HH:mm:ss')}
                      </div>
                    </div>
                    <span
                      className={`ml-2 px-2 py-1 rounded-full text-xs whitespace-nowrap ${
                        isBlocked
                          ? 'bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200'
                          : 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200'
                      }`}
                    >
                      {query.status || 'unknown'}
                    </span>
                  </div>
                  <div className="text-sm text-gray-600 dark:text-gray-300">
                    <div className="truncate">{query.client_hostname || query.client_ip}</div>
                    {query.client_hostname && (
                      <div className="text-xs text-gray-500 dark:text-gray-400 truncate">{query.client_ip}</div>
                    )}
                  </div>
                  <div className="flex justify-between items-center">
                    <div className="text-xs text-gray-500 dark:text-gray-400">
                      {query.pihole_server}
                    </div>
                    <div className="flex space-x-2">
                      <button
                        onClick={() => handleWhitelist(query.domain)}
                        disabled={actionLoading !== null}
                        title="Add to whitelist"
                        className="inline-flex items-center justify-center w-8 h-8 rounded-full bg-green-100 dark:bg-green-900/30 text-green-600 dark:text-green-400 hover:bg-green-200 dark:hover:bg-green-800/50 disabled:opacity-50 transition-colors"
                      >
                        {actionLoading === `whitelist-${query.domain}` ? (
                          <svg className="animate-spin h-4 w-4" fill="none" viewBox="0 0 24 24">
                            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                          </svg>
                        ) : (
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                          </svg>
                        )}
                      </button>
                      <button
                        onClick={() => handleBlacklist(query.domain)}
                        disabled={actionLoading !== null}
                        title="Add to blacklist"
                        className="inline-flex items-center justify-center w-8 h-8 rounded-full bg-red-100 dark:bg-red-900/30 text-red-600 dark:text-red-400 hover:bg-red-200 dark:hover:bg-red-800/50 disabled:opacity-50 transition-colors"
                      >
                        {actionLoading === `blacklist-${query.domain}` ? (
                          <svg className="animate-spin h-4 w-4" fill="none" viewBox="0 0 24 24">
                            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                          </svg>
                        ) : (
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                          </svg>
                        )}
                      </button>
                    </div>
                  </div>
                </div>
                );
              })
            )}
          </div>

          {/* Desktop Table View */}
          <div className="hidden md:block overflow-x-auto">
            <table className="min-w-full table-fixed divide-y divide-gray-200 dark:divide-gray-700">
              <thead className="bg-gray-50 dark:bg-gray-700">
                <tr>
                  <th className="w-36 px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                    Timestamp
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                    Domain
                  </th>
                  <th className="w-48 px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                    Client
                  </th>
                  <th className="w-28 px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="w-32 px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                    Server
                  </th>
                  <th className="w-24 px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                {filteredQueries.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="px-6 py-4 text-center text-gray-500 dark:text-gray-400">
                      No queries found
                    </td>
                  </tr>
                ) : (
                  filteredQueries.map((query) => {
                    const isBlocked = query.status?.toUpperCase().includes('GRAVITY') ||
                                      query.status?.toUpperCase().includes('BLACKLIST');
                    return (
                      <tr
                        key={query.id}
                        className={`${
                          isBlocked
                            ? 'bg-red-50 dark:bg-red-900/30 hover:bg-red-100 dark:hover:bg-red-900/40'
                            : 'hover:bg-gray-50 dark:hover:bg-gray-700'
                        }`}
                      >
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-gray-300">
                          {format(new Date(query.timestamp), 'MMM dd, HH:mm:ss')}
                        </td>
                        <td className="px-6 py-4 text-sm text-gray-900 dark:text-gray-300 truncate">
                          {query.domain}
                        </td>
                        <td className="px-6 py-4 text-sm text-gray-900 dark:text-gray-300">
                          <div className="truncate">{query.client_hostname || query.client_ip}</div>
                          {query.client_hostname && (
                            <div className="text-xs text-gray-500 dark:text-gray-400 truncate">{query.client_ip}</div>
                          )}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm">
                          <span
                            className={`px-2 py-1 rounded-full text-xs ${
                              isBlocked
                                ? 'bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200'
                                : 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200'
                            }`}
                          >
                            {query.status || 'unknown'}
                          </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                          {query.pihole_server}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm">
                          <div className="flex space-x-2">
                            <button
                              onClick={() => handleWhitelist(query.domain)}
                              disabled={actionLoading !== null}
                              title="Add to whitelist"
                              className="inline-flex items-center justify-center w-7 h-7 rounded-full bg-green-100 dark:bg-green-900/30 text-green-600 dark:text-green-400 hover:bg-green-200 dark:hover:bg-green-800/50 disabled:opacity-50 transition-colors"
                            >
                              {actionLoading === `whitelist-${query.domain}` ? (
                                <svg className="animate-spin h-3 w-3" fill="none" viewBox="0 0 24 24">
                                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                                </svg>
                              ) : (
                                <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                                </svg>
                              )}
                            </button>
                            <button
                              onClick={() => handleBlacklist(query.domain)}
                              disabled={actionLoading !== null}
                              title="Add to blacklist"
                              className="inline-flex items-center justify-center w-7 h-7 rounded-full bg-red-100 dark:bg-red-900/30 text-red-600 dark:text-red-400 hover:bg-red-200 dark:hover:bg-red-800/50 disabled:opacity-50 transition-colors"
                            >
                              {actionLoading === `blacklist-${query.domain}` ? (
                                <svg className="animate-spin h-3 w-3" fill="none" viewBox="0 0 24 24">
                                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                                </svg>
                              ) : (
                                <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                                </svg>
                              )}
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
