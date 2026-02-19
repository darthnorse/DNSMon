import { useState, useEffect } from 'react';
import { format } from 'date-fns';
import { queryApi, domainApi } from '../utils/api';
import { getErrorMessage } from '../utils/errors';
import type { Query, QuerySearchParams } from '../types';

export default function Search() {
  const [queries, setQueries] = useState<Query[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [totalCount, setTotalCount] = useState(0);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState<string | null>(null);

  const [searchParams, setSearchParams] = useState<QuerySearchParams>({
    domain: '',
    client_ip: '',
    client_hostname: '',
    server: '',
    from_date: '',
    to_date: '',
    limit: 100,
    offset: 0,
  });

  const handleSearch = async (offset = 0) => {
    try {
      setLoading(true);
      setError(null);

      // Build params, excluding empty strings
      const params: QuerySearchParams = {
        limit: searchParams.limit,
        offset,
      };

      if (searchParams.domain) params.domain = searchParams.domain;
      if (searchParams.client_ip) params.client_ip = searchParams.client_ip;
      if (searchParams.client_hostname) params.client_hostname = searchParams.client_hostname;
      if (searchParams.server) params.server = searchParams.server;
      if (searchParams.from_date) params.from_date = searchParams.from_date;
      if (searchParams.to_date) params.to_date = searchParams.to_date;

      const [results, count] = await Promise.all([
        queryApi.search(params),
        queryApi.count(params),
      ]);

      setQueries(results);
      setTotalCount(count);
      setSearchParams({ ...searchParams, offset });
    } catch (err: unknown) {
      setError(getErrorMessage(err, 'Failed to search queries'));
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleClear = () => {
    setSearchParams({
      domain: '',
      client_ip: '',
      client_hostname: '',
      server: '',
      from_date: '',
      to_date: '',
      limit: 100,
      offset: 0,
    });
    setQueries([]);
    setTotalCount(0);
  };

  const handleNextPage = () => {
    handleSearch((searchParams.offset || 0) + (searchParams.limit || 100));
  };

  const handlePrevPage = () => {
    handleSearch(Math.max(0, (searchParams.offset || 0) - (searchParams.limit || 100)));
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
      setError(getErrorMessage(err, `Failed to whitelist ${domain}`));
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
      setError(getErrorMessage(err, `Failed to blacklist ${domain}`));
    } finally {
      setActionLoading(null);
    }
  };

  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Query Search</h1>

      <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <div>
            <label htmlFor="domain" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
              Domain
            </label>
            <input
              type="text"
              id="domain"
              placeholder="e.g., google.com"
              value={searchParams.domain}
              onChange={(e) => setSearchParams({ ...searchParams, domain: e.target.value })}
              className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm px-3 py-2 border"
            />
          </div>

          <div>
            <label htmlFor="client_ip" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
              Client IP
            </label>
            <input
              type="text"
              id="client_ip"
              placeholder="e.g., 192.168.1.100"
              value={searchParams.client_ip}
              onChange={(e) => setSearchParams({ ...searchParams, client_ip: e.target.value })}
              className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm px-3 py-2 border"
            />
          </div>

          <div>
            <label htmlFor="client_hostname" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
              Client Hostname
            </label>
            <input
              type="text"
              id="client_hostname"
              placeholder="e.g., laptop"
              value={searchParams.client_hostname}
              onChange={(e) => setSearchParams({ ...searchParams, client_hostname: e.target.value })}
              className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm px-3 py-2 border"
            />
          </div>

          <div>
            <label htmlFor="server" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
              Pihole Server
            </label>
            <input
              type="text"
              id="server"
              placeholder="e.g., pihole1"
              value={searchParams.server}
              onChange={(e) => setSearchParams({ ...searchParams, server: e.target.value })}
              className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm px-3 py-2 border"
            />
          </div>

          <div>
            <label htmlFor="from_date" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
              From Date
            </label>
            <input
              type="datetime-local"
              id="from_date"
              value={searchParams.from_date}
              onChange={(e) => setSearchParams({ ...searchParams, from_date: e.target.value })}
              className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm px-3 py-2 border"
            />
          </div>

          <div>
            <label htmlFor="to_date" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
              To Date
            </label>
            <input
              type="datetime-local"
              id="to_date"
              value={searchParams.to_date}
              onChange={(e) => setSearchParams({ ...searchParams, to_date: e.target.value })}
              className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm px-3 py-2 border"
            />
          </div>
        </div>

        <div className="mt-4 flex space-x-3">
          <button
            onClick={() => handleSearch(0)}
            disabled={loading}
            className="inline-flex justify-center rounded-md border border-transparent bg-blue-600 py-2 px-4 text-sm font-medium text-white shadow-sm hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 disabled:opacity-50"
          >
            {loading ? 'Searching...' : 'Search'}
          </button>
          <button
            onClick={handleClear}
            disabled={loading}
            className="inline-flex justify-center rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 py-2 px-4 text-sm font-medium text-gray-700 dark:text-gray-300 shadow-sm hover:bg-gray-50 dark:hover:bg-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2"
          >
            Clear
          </button>
        </div>
      </div>

      {error && (
        <div className="bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800/50 text-red-700 dark:text-red-300 px-4 py-3 rounded">
          {error}
        </div>
      )}

      {successMessage && (
        <div className="bg-green-50 dark:bg-green-900/30 border border-green-200 dark:border-green-800/50 text-green-700 dark:text-green-300 px-4 py-3 rounded">
          {successMessage}
        </div>
      )}

      {queries.length > 0 && (
        <div className="bg-white dark:bg-gray-800 shadow rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-700">
            <h2 className="text-lg font-medium text-gray-900 dark:text-white">
              Results ({totalCount.toLocaleString()} total)
            </h2>
          </div>

          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
              <thead className="bg-gray-50 dark:bg-gray-700">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                    Timestamp
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                    Domain
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                    Client IP
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                    Client Hostname
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                    Server
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                {queries.map((query) => (
                  <tr key={query.id} className="hover:bg-gray-50 dark:hover:bg-gray-700">
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-gray-300">
                      {format(new Date(query.timestamp), 'MMM dd, yyyy HH:mm:ss')}
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-900 dark:text-gray-300 break-all">
                      {query.domain}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-gray-300">
                      {query.client_ip}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                      {query.client_hostname || '-'}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                      {query.server}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm">
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
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="bg-white dark:bg-gray-800 px-4 py-3 flex items-center justify-between border-t border-gray-200 dark:border-gray-700 sm:px-6">
            <div className="flex-1 flex justify-between sm:hidden">
              <button
                onClick={handlePrevPage}
                disabled={searchParams.offset === 0}
                className="relative inline-flex items-center px-4 py-2 border border-gray-300 dark:border-gray-600 text-sm font-medium rounded-md text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600 disabled:opacity-50"
              >
                Previous
              </button>
              <button
                onClick={handleNextPage}
                disabled={(searchParams.offset || 0) + (searchParams.limit || 100) >= totalCount}
                className="ml-3 relative inline-flex items-center px-4 py-2 border border-gray-300 dark:border-gray-600 text-sm font-medium rounded-md text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600 disabled:opacity-50"
              >
                Next
              </button>
            </div>
            <div className="hidden sm:flex-1 sm:flex sm:items-center sm:justify-between">
              <div>
                <p className="text-sm text-gray-700 dark:text-gray-300">
                  Showing{' '}
                  <span className="font-medium">{(searchParams.offset || 0) + 1}</span> to{' '}
                  <span className="font-medium">
                    {Math.min((searchParams.offset || 0) + (searchParams.limit || 100), totalCount)}
                  </span>{' '}
                  of <span className="font-medium">{totalCount}</span> results
                </p>
              </div>
              <div>
                <nav className="relative z-0 inline-flex rounded-md shadow-sm -space-x-px">
                  <button
                    onClick={handlePrevPage}
                    disabled={searchParams.offset === 0}
                    className="relative inline-flex items-center px-2 py-2 rounded-l-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-sm font-medium text-gray-500 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-gray-600 disabled:opacity-50"
                  >
                    Previous
                  </button>
                  <button
                    onClick={handleNextPage}
                    disabled={(searchParams.offset || 0) + (searchParams.limit || 100) >= totalCount}
                    className="relative inline-flex items-center px-2 py-2 rounded-r-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-sm font-medium text-gray-500 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-gray-600 disabled:opacity-50"
                  >
                    Next
                  </button>
                </nav>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
