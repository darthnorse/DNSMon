import { useState, useEffect } from 'react';
import { domainApi } from '../utils/api';
import type { DomainEntry } from '../types';

type ListType = 'whitelist' | 'blacklist' | 'regex-whitelist' | 'regex-blacklist';

export default function Lists() {
  const [activeTab, setActiveTab] = useState<ListType>('whitelist');
  const [domains, setDomains] = useState<DomainEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [searchFilter, setSearchFilter] = useState('');
  const [newDomain, setNewDomain] = useState('');
  const [addingDomain, setAddingDomain] = useState(false);
  const [deletingId, setDeletingId] = useState<number | string | null>(null);

  // Load domains when tab changes
  useEffect(() => {
    loadDomains();
  }, [activeTab]);

  // Auto-dismiss success messages
  useEffect(() => {
    if (successMessage) {
      const timer = setTimeout(() => setSuccessMessage(null), 5000);
      return () => clearTimeout(timer);
    }
  }, [successMessage]);

  const loadDomains = async () => {
    try {
      setLoading(true);
      setError(null);
      let data: DomainEntry[];

      switch (activeTab) {
        case 'whitelist':
          data = await domainApi.getWhitelist();
          break;
        case 'blacklist':
          data = await domainApi.getBlacklist();
          break;
        case 'regex-whitelist':
          data = await domainApi.getRegexWhitelist();
          break;
        case 'regex-blacklist':
          data = await domainApi.getRegexBlacklist();
          break;
        default:
          data = [];
      }

      setDomains(data);
    } catch (err: unknown) {
      const error = err as { response?: { data?: { detail?: string } } };
      setError(error.response?.data?.detail || 'Failed to load domains');
    } finally {
      setLoading(false);
    }
  };

  const handleAddDomain = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newDomain.trim()) return;

    try {
      setAddingDomain(true);
      setError(null);

      if (activeTab === 'whitelist') {
        await domainApi.whitelist(newDomain.trim());
      } else if (activeTab === 'blacklist') {
        await domainApi.blacklist(newDomain.trim());
      } else {
        setError('Adding regex patterns is not yet supported');
        return;
      }

      setSuccessMessage(`Added "${newDomain.trim()}" to ${activeTab}`);
      setNewDomain('');
      await loadDomains();
    } catch (err: unknown) {
      const error = err as { response?: { data?: { detail?: string } } };
      setError(error.response?.data?.detail || 'Failed to add domain');
    } finally {
      setAddingDomain(false);
    }
  };

  const handleDelete = async (domain: DomainEntry) => {
    try {
      setDeletingId(domain.id);
      setError(null);

      switch (activeTab) {
        case 'whitelist':
          await domainApi.removeFromWhitelist(domain.domain);
          break;
        case 'blacklist':
          await domainApi.removeFromBlacklist(domain.domain);
          break;
        case 'regex-whitelist':
          await domainApi.removeFromRegexWhitelist(domain.id);
          break;
        case 'regex-blacklist':
          await domainApi.removeFromRegexBlacklist(domain.id);
          break;
      }

      setSuccessMessage(`Removed "${domain.domain}" from ${activeTab}`);
      await loadDomains();
    } catch (err: unknown) {
      const error = err as { response?: { data?: { detail?: string } } };
      setError(error.response?.data?.detail || 'Failed to remove domain');
    } finally {
      setDeletingId(null);
    }
  };

  const filteredDomains = domains.filter(d =>
    d.domain.toLowerCase().includes(searchFilter.toLowerCase())
  );

  const tabs: { id: ListType; label: string }[] = [
    { id: 'whitelist', label: 'Whitelist' },
    { id: 'blacklist', label: 'Blacklist' },
    { id: 'regex-whitelist', label: 'Regex Whitelist' },
    { id: 'regex-blacklist', label: 'Regex Blacklist' },
  ];

  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Domain Lists</h1>

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

      <div className="bg-white dark:bg-gray-800 shadow rounded-lg">
        {/* Tabs */}
        <div className="border-b border-gray-200 dark:border-gray-700">
          <nav className="flex -mb-px overflow-x-auto">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`whitespace-nowrap py-4 px-6 border-b-2 font-medium text-sm transition-colors ${
                  activeTab === tab.id
                    ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                    : 'border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300 hover:border-gray-300 dark:hover:border-gray-600'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </nav>
        </div>

        <div className="p-6">
          {/* Search and Add */}
          <div className="flex flex-col sm:flex-row gap-4 mb-6">
            <div className="flex-1">
              <input
                type="text"
                placeholder="Filter domains..."
                value={searchFilter}
                onChange={(e) => setSearchFilter(e.target.value)}
                className="w-full border border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>
            {(activeTab === 'whitelist' || activeTab === 'blacklist') && (
              <form onSubmit={handleAddDomain} className="flex gap-2">
                <input
                  type="text"
                  placeholder="Add domain..."
                  value={newDomain}
                  onChange={(e) => setNewDomain(e.target.value)}
                  className="border border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
                <button
                  type="submit"
                  disabled={addingDomain || !newDomain.trim()}
                  className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  {addingDomain ? 'Adding...' : 'Add'}
                </button>
              </form>
            )}
          </div>

          {/* Domain List */}
          {loading ? (
            <div className="text-center py-8 text-gray-500 dark:text-gray-400">
              Loading...
            </div>
          ) : filteredDomains.length === 0 ? (
            <div className="text-center py-8 text-gray-500 dark:text-gray-400">
              {searchFilter ? 'No domains match your filter' : 'No domains in this list'}
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                <thead className="bg-gray-50 dark:bg-gray-700">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                      Domain
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                      Status
                    </th>
                    {(activeTab === 'regex-whitelist' || activeTab === 'regex-blacklist') && (
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                        Comment
                      </th>
                    )}
                    <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                  {filteredDomains.map((domain) => (
                    <tr key={domain.id} className="hover:bg-gray-50 dark:hover:bg-gray-700">
                      <td className="px-6 py-4 text-sm text-gray-900 dark:text-gray-300 break-all">
                        {domain.domain}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm">
                        <span
                          className={`px-2 py-1 rounded-full text-xs ${
                            domain.enabled
                              ? 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200'
                              : 'bg-gray-100 dark:bg-gray-600 text-gray-800 dark:text-gray-200'
                          }`}
                        >
                          {domain.enabled ? 'Enabled' : 'Disabled'}
                        </span>
                      </td>
                      {(activeTab === 'regex-whitelist' || activeTab === 'regex-blacklist') && (
                        <td className="px-6 py-4 text-sm text-gray-500 dark:text-gray-400">
                          {domain.comment || '-'}
                        </td>
                      )}
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-right">
                        <button
                          onClick={() => handleDelete(domain)}
                          disabled={deletingId === domain.id}
                          className="text-red-600 dark:text-red-400 hover:text-red-900 dark:hover:text-red-300 disabled:opacity-50"
                        >
                          {deletingId === domain.id ? (
                            <svg className="animate-spin h-5 w-5 inline" fill="none" viewBox="0 0 24 24">
                              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                            </svg>
                          ) : (
                            'Delete'
                          )}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Summary */}
          {!loading && (
            <div className="mt-4 text-sm text-gray-500 dark:text-gray-400">
              {filteredDomains.length} {filteredDomains.length === 1 ? 'entry' : 'entries'}
              {searchFilter && ` (filtered from ${domains.length})`}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
