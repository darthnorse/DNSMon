import { useEffect, useState, useRef } from 'react';
import { statisticsApi, settingsApi } from '../utils/api';
import type { Statistics, PiholeServer, ClientInfo } from '../types';
import { format } from 'date-fns';
import {
  PieChart,
  Pie,
  Cell,
  LineChart,
  Line,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts';

type Period = '24h' | '7d' | '30d';

export default function StatisticsPage() {
  const [stats, setStats] = useState<Statistics | null>(null);
  const [servers, setServers] = useState<PiholeServer[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filter state
  const [period, setPeriod] = useState<Period>('24h');
  const [selectedServers, setSelectedServers] = useState<string[]>([]);
  const [serverDropdownOpen, setServerDropdownOpen] = useState(false);
  const serverDropdownRef = useRef<HTMLDivElement>(null);

  // Client filter state
  const [clients, setClients] = useState<ClientInfo[]>([]);
  const [selectedClients, setSelectedClients] = useState<string[]>([]);
  const [clientDropdownOpen, setClientDropdownOpen] = useState(false);
  const [clientSearch, setClientSearch] = useState('');
  const clientDropdownRef = useRef<HTMLDivElement>(null);

  // Load servers on mount
  useEffect(() => {
    loadServers();
  }, []);

  // Load clients when period or servers change
  useEffect(() => {
    loadClients();
  }, [period, selectedServers]);

  // Load stats when filters change
  useEffect(() => {
    loadStats();
  }, [period, selectedServers, selectedClients]);

  // Close dropdowns when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (serverDropdownRef.current && !serverDropdownRef.current.contains(event.target as Node)) {
        setServerDropdownOpen(false);
      }
      if (clientDropdownRef.current && !clientDropdownRef.current.contains(event.target as Node)) {
        setClientDropdownOpen(false);
        setClientSearch('');
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const loadServers = async () => {
    try {
      const serverList = await settingsApi.servers.getAll();
      setServers(serverList.filter(s => s.enabled));
    } catch (err) {
      console.error('Failed to load servers:', err);
    }
  };

  const loadClients = async () => {
    try {
      const params: { period: string; servers?: string } = { period };
      if (selectedServers.length > 0) {
        params.servers = selectedServers.join(',');
      }
      const clientList = await statisticsApi.getClients(params);
      setClients(clientList);
      // Select all clients by default
      setSelectedClients(clientList.map(c => c.client_ip));
    } catch (err) {
      console.error('Failed to load clients:', err);
    }
  };

  const loadStats = async () => {
    try {
      setLoading(true);
      const params: { period: string; servers?: string; clients?: string } = { period };
      if (selectedServers.length > 0) {
        params.servers = selectedServers.join(',');
      }
      if (selectedClients.length > 0) {
        params.clients = selectedClients.join(',');
      }
      const data = await statisticsApi.get(params);
      setStats(data);
      setError(null);
    } catch (err) {
      setError('Failed to load statistics');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const toggleServer = (serverName: string) => {
    setSelectedServers(prev =>
      prev.includes(serverName)
        ? prev.filter(s => s !== serverName)
        : [...prev, serverName]
    );
  };

  const selectAllServers = () => {
    // Always clear selection to show all servers
    setSelectedServers([]);
  };

  const toggleClient = (clientIp: string) => {
    setSelectedClients(prev =>
      prev.includes(clientIp)
        ? prev.filter(c => c !== clientIp)
        : [...prev, clientIp]
    );
  };

  const selectAllClients = () => {
    // Toggle between all selected and none selected
    if (selectedClients.length === clients.length && clients.length > 0) {
      setSelectedClients([]);
    } else {
      setSelectedClients(clients.map(c => c.client_ip));
    }
  };

  const getClientLabel = () => {
    if (clients.length === 0) return 'No Clients';
    if (selectedClients.length === 0) return 'None Selected';
    if (selectedClients.length === clients.length) return 'All Clients';
    if (selectedClients.length === 1) {
      const client = clients.find(c => c.client_ip === selectedClients[0]);
      return client?.client_hostname || selectedClients[0];
    }
    return `${selectedClients.length} clients`;
  };

  const filteredClients = clients.filter(client => {
    if (!clientSearch) return true;
    const search = clientSearch.toLowerCase();
    return (
      client.client_ip.toLowerCase().includes(search) ||
      (client.client_hostname?.toLowerCase().includes(search) ?? false)
    );
  });

  if (loading && !stats) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="text-gray-500 dark:text-gray-400">Loading statistics...</div>
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

  // Prepare pie chart data
  const allowedCount = period === '24h' ? stats.queries_today - stats.blocked_today
    : period === '7d' ? stats.queries_week - stats.blocked_today
    : stats.queries_month - stats.blocked_today;
  const pieData = [
    { name: 'Allowed', value: Math.max(0, allowedCount), color: '#10B981' },
    { name: 'Blocked', value: stats.blocked_today, color: '#EF4444' },
  ];

  // Prepare time series data (filter out entries with invalid timestamps)
  const timeData = period === '24h'
    ? stats.queries_hourly
        .filter(item => item.hour && item.hour !== '')
        .map(item => ({
          ...item,
          time: format(new Date(item.hour), 'HH:mm'),
          allowed: item.queries - item.blocked,
        }))
    : stats.queries_daily
        .filter(item => item.date && item.date !== '')
        .map(item => ({
          ...item,
          time: format(new Date(item.date), 'MM/dd'),
          allowed: item.queries - item.blocked,
        }));

  // Format large numbers
  const formatNumber = (num: number): string => {
    if (num >= 1000000) return `${(num / 1000000).toFixed(1)}M`;
    if (num >= 1000) return `${(num / 1000).toFixed(1)}K`;
    return num.toLocaleString();
  };

  // Get server dropdown label
  const getServerLabel = () => {
    if (selectedServers.length === 0) return 'All Servers';
    if (selectedServers.length === 1) return selectedServers[0];
    return `${selectedServers.length} servers`;
  };

  return (
    <div className="space-y-6">
      {/* Header with Filters */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Statistics</h1>

        <div className="flex flex-wrap items-center gap-3">
          {/* Period Selector */}
          <div className="flex rounded-lg overflow-hidden border border-gray-300 dark:border-gray-600">
            {(['24h', '7d', '30d'] as Period[]).map((p) => (
              <button
                key={p}
                onClick={() => setPeriod(p)}
                className={`px-4 py-2 text-sm font-medium transition-colors ${
                  period === p
                    ? 'bg-blue-600 text-white'
                    : 'bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700'
                }`}
              >
                {p}
              </button>
            ))}
          </div>

          {/* Server Dropdown */}
          <div className="relative" ref={serverDropdownRef}>
            <button
              onClick={() => setServerDropdownOpen(!serverDropdownOpen)}
              className="flex items-center gap-2 px-4 py-2 text-sm font-medium bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700"
            >
              <span>{getServerLabel()}</span>
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
              </svg>
            </button>

            {serverDropdownOpen && servers.length > 0 && (
              <div className="absolute right-0 mt-2 w-56 bg-white dark:bg-gray-800 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700 z-10">
                <div className="p-2">
                  {/* Select All Option */}
                  <label className="flex items-center gap-2 px-3 py-2 hover:bg-gray-100 dark:hover:bg-gray-700 rounded cursor-pointer">
                    <input
                      type="checkbox"
                      checked={selectedServers.length === 0}
                      onChange={selectAllServers}
                      className="rounded border-gray-300 dark:border-gray-600 text-blue-600 focus:ring-blue-500"
                    />
                    <span className="text-sm text-gray-700 dark:text-gray-300 font-medium">
                      All Servers
                    </span>
                  </label>

                  <div className="border-t border-gray-200 dark:border-gray-700 my-1" />

                  {/* Individual Servers */}
                  {servers.map((server) => (
                    <label
                      key={server.id}
                      className="flex items-center gap-2 px-3 py-2 hover:bg-gray-100 dark:hover:bg-gray-700 rounded cursor-pointer"
                    >
                      <input
                        type="checkbox"
                        checked={selectedServers.includes(server.name)}
                        onChange={() => toggleServer(server.name)}
                        className="rounded border-gray-300 dark:border-gray-600 text-blue-600 focus:ring-blue-500"
                      />
                      <span className="text-sm text-gray-700 dark:text-gray-300">{server.name}</span>
                    </label>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Client Dropdown */}
          <div className="relative" ref={clientDropdownRef}>
            <button
              onClick={() => setClientDropdownOpen(!clientDropdownOpen)}
              className="flex items-center gap-2 px-4 py-2 text-sm font-medium bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700"
            >
              <span>{getClientLabel()}</span>
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
              </svg>
            </button>

            {clientDropdownOpen && (
              <div className="absolute right-0 mt-2 w-72 bg-white dark:bg-gray-800 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700 z-10">
                {/* Search Input */}
                <div className="p-2 border-b border-gray-200 dark:border-gray-700">
                  <input
                    type="text"
                    placeholder="Search clients..."
                    value={clientSearch}
                    onChange={(e) => setClientSearch(e.target.value)}
                    className="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
                    autoFocus
                  />
                </div>

                <div className="p-2 max-h-64 overflow-y-auto">
                  {/* Select All Option */}
                  {!clientSearch && (
                    <>
                      <label className="flex items-center gap-2 px-3 py-2 hover:bg-gray-100 dark:hover:bg-gray-700 rounded cursor-pointer">
                        <input
                          type="checkbox"
                          checked={selectedClients.length === clients.length && clients.length > 0}
                          onChange={selectAllClients}
                          className="rounded border-gray-300 dark:border-gray-600 text-blue-600 focus:ring-blue-500"
                        />
                        <span className="text-sm text-gray-700 dark:text-gray-300 font-medium">
                          All Clients
                        </span>
                      </label>
                      <div className="border-t border-gray-200 dark:border-gray-700 my-1" />
                    </>
                  )}

                  {/* Individual Clients */}
                  {filteredClients.length === 0 ? (
                    <div className="px-3 py-2 text-sm text-gray-500 dark:text-gray-400">
                      {clientSearch ? 'No clients match your search' : 'No clients found'}
                    </div>
                  ) : (
                    filteredClients.map((client) => (
                      <label
                        key={client.client_ip}
                        className="flex items-center gap-2 px-3 py-2 hover:bg-gray-100 dark:hover:bg-gray-700 rounded cursor-pointer"
                      >
                        <input
                          type="checkbox"
                          checked={selectedClients.includes(client.client_ip)}
                          onChange={() => toggleClient(client.client_ip)}
                          className="rounded border-gray-300 dark:border-gray-600 text-blue-600 focus:ring-blue-500"
                        />
                        <div className="flex-1 min-w-0">
                          <div className="text-sm text-gray-900 dark:text-white truncate">
                            {client.client_hostname || client.client_ip}
                          </div>
                          {client.client_hostname && (
                            <div className="text-xs text-gray-500 dark:text-gray-400 truncate">
                              {client.client_ip}
                            </div>
                          )}
                        </div>
                        <span className="text-xs text-gray-400 dark:text-gray-500">
                          {client.count.toLocaleString()}
                        </span>
                      </label>
                    ))
                  )}
                </div>
              </div>
            )}
          </div>

          {/* Refresh Button */}
          <button
            onClick={loadStats}
            disabled={loading}
            className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50"
          >
            {loading ? 'Loading...' : 'Refresh'}
          </button>
        </div>
      </div>

      {/* Query Overview Cards */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <StatCard label="24 Hours" value={formatNumber(stats.queries_today)} highlight={period === '24h'} />
        <StatCard label="7 Days" value={formatNumber(stats.queries_week)} highlight={period === '7d'} />
        <StatCard label="30 Days" value={formatNumber(stats.queries_month)} highlight={period === '30d'} />
        <StatCard label="Total" value={formatNumber(stats.queries_total)} />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Blocked vs Allowed Pie Chart */}
        <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Blocked vs Allowed ({period})
          </h2>
          <div className="flex items-center justify-center">
            <ResponsiveContainer width="100%" height={250}>
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={100}
                  paddingAngle={2}
                  dataKey="value"
                  label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(1)}%`}
                >
                  {pieData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  formatter={(value: number) => value.toLocaleString()}
                  contentStyle={{
                    backgroundColor: '#1F2937',
                    border: '1px solid #374151',
                    borderRadius: '0.375rem',
                    color: '#fff',
                  }}
                  labelStyle={{ color: '#9CA3AF' }}
                  itemStyle={{ color: '#fff' }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="text-center mt-2">
            <span className="text-2xl font-bold text-red-600 dark:text-red-400">
              {stats.blocked_percentage.toFixed(1)}%
            </span>
            <span className="text-gray-500 dark:text-gray-400 ml-2">blocked</span>
          </div>
        </div>

        {/* Queries Over Time Line Chart */}
        <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Queries Over Time ({period})
          </h2>
          {timeData.length > 0 ? (
            <ResponsiveContainer width="100%" height={280}>
              <LineChart data={timeData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" opacity={0.3} />
                <XAxis
                  dataKey="time"
                  stroke="#9CA3AF"
                  fontSize={12}
                  tickLine={false}
                />
                <YAxis
                  stroke="#9CA3AF"
                  fontSize={12}
                  tickLine={false}
                  tickFormatter={(value) => formatNumber(value)}
                />
                <Tooltip
                  formatter={(value: number) => value.toLocaleString()}
                  contentStyle={{
                    backgroundColor: '#1F2937',
                    border: '1px solid #374151',
                    borderRadius: '0.375rem',
                    color: '#fff',
                  }}
                  labelStyle={{ color: '#9CA3AF' }}
                  itemStyle={{ color: '#fff' }}
                />
                <Legend />
                <Line
                  type="monotone"
                  dataKey="queries"
                  name="Total"
                  stroke="#3B82F6"
                  strokeWidth={2}
                  dot={false}
                />
                <Line
                  type="monotone"
                  dataKey="blocked"
                  name="Blocked"
                  stroke="#EF4444"
                  strokeWidth={2}
                  dot={false}
                />
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-64 text-gray-500 dark:text-gray-400">
              No data available for this period
            </div>
          )}
        </div>
      </div>

      {/* Top Lists */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Top Domains */}
        <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Top Domains
          </h2>
          <TopList
            items={stats.top_domains.map((d, i) => ({
              rank: i + 1,
              label: d.domain,
              value: d.count,
            }))}
          />
        </div>

        {/* Top Blocked Domains */}
        <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Top Blocked Domains
          </h2>
          <TopList
            items={stats.top_blocked_domains.map((d, i) => ({
              rank: i + 1,
              label: d.domain,
              value: d.count,
            }))}
            highlight="red"
          />
        </div>

        {/* Top Clients */}
        <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Top Clients
          </h2>
          <TopList
            items={stats.top_clients.map((c, i) => ({
              rank: i + 1,
              label: c.client_hostname || c.client_ip,
              sublabel: c.client_hostname ? c.client_ip : undefined,
              value: c.count,
            }))}
          />
        </div>
      </div>

      {/* Per Server Stats & Client Insights */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Per Server Bar Chart */}
        <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Queries by Server
          </h2>
          {stats.queries_by_server.length > 0 ? (
            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={stats.queries_by_server}>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" opacity={0.3} />
                <XAxis
                  dataKey="server"
                  stroke="#9CA3AF"
                  fontSize={12}
                  tickLine={false}
                />
                <YAxis
                  stroke="#9CA3AF"
                  fontSize={12}
                  tickLine={false}
                  tickFormatter={(value) => formatNumber(value)}
                />
                <Tooltip
                  formatter={(value: number) => value.toLocaleString()}
                  contentStyle={{
                    backgroundColor: '#1F2937',
                    border: '1px solid #374151',
                    borderRadius: '0.375rem',
                    color: '#fff',
                  }}
                  wrapperStyle={{
                    backgroundColor: '#1F2937',
                    borderRadius: '0.375rem',
                  }}
                  labelStyle={{ color: '#9CA3AF' }}
                  itemStyle={{ color: '#fff' }}
                  cursor={{ fill: 'rgba(55, 65, 81, 0.3)' }}
                />
                <Legend />
                <Bar dataKey="queries" name="Total" fill="#3B82F6" />
                <Bar dataKey="blocked" name="Blocked" fill="#EF4444" />
                <Bar dataKey="cached" name="Cached" fill="#10B981" />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="text-center text-gray-500 dark:text-gray-400 py-8">
              No server data available
            </div>
          )}
        </div>

        {/* Client Insights */}
        <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Client Insights
          </h2>
          <div className="space-y-4">
            <div className="flex justify-between items-center py-3 border-b border-gray-200 dark:border-gray-700">
              <span className="text-gray-600 dark:text-gray-400">Unique Clients</span>
              <span className="text-2xl font-semibold text-gray-900 dark:text-white">
                {stats.unique_clients.toLocaleString()}
              </span>
            </div>
            <div className="flex justify-between items-center py-3 border-b border-gray-200 dark:border-gray-700">
              <span className="text-gray-600 dark:text-gray-400">New Clients ({period})</span>
              <span className="text-2xl font-semibold text-blue-600 dark:text-blue-400">
                {stats.new_clients_24h.toLocaleString()}
              </span>
            </div>
            {stats.most_active_client && (
              <div className="py-3">
                <span className="text-gray-600 dark:text-gray-400 block mb-2">Most Active Client</span>
                <div className="bg-gray-50 dark:bg-gray-700 rounded-lg p-4">
                  <div className="font-semibold text-gray-900 dark:text-white">
                    {stats.most_active_client.client_hostname || stats.most_active_client.client_ip}
                  </div>
                  {stats.most_active_client.client_hostname && (
                    <div className="text-sm text-gray-500 dark:text-gray-400">
                      {stats.most_active_client.client_ip}
                    </div>
                  )}
                  <div className="text-lg font-semibold text-blue-600 dark:text-blue-400 mt-2">
                    {stats.most_active_client.count.toLocaleString()} queries
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// Stat Card Component
function StatCard({ label, value, highlight }: { label: string; value: string; highlight?: boolean }) {
  return (
    <div className={`overflow-hidden shadow rounded-lg ${
      highlight
        ? 'bg-blue-50 dark:bg-blue-900/30 ring-2 ring-blue-500'
        : 'bg-white dark:bg-gray-800'
    }`}>
      <div className="px-4 py-5 sm:p-6">
        <dt className={`text-sm font-medium truncate ${
          highlight ? 'text-blue-700 dark:text-blue-300' : 'text-gray-500 dark:text-gray-400'
        }`}>
          {label}
        </dt>
        <dd className={`mt-1 text-3xl font-semibold ${
          highlight ? 'text-blue-900 dark:text-blue-100' : 'text-gray-900 dark:text-white'
        }`}>
          {value}
        </dd>
      </div>
    </div>
  );
}

// Top List Component
interface TopListItem {
  rank: number;
  label: string;
  sublabel?: string;
  value: number;
}

function TopList({ items, highlight }: { items: TopListItem[]; highlight?: 'red' }) {
  if (items.length === 0) {
    return (
      <div className="text-center text-gray-500 dark:text-gray-400 py-4">
        No data available
      </div>
    );
  }

  const maxValue = Math.max(...items.map(i => i.value));

  return (
    <div className="space-y-2">
      {items.map((item) => (
        <div key={item.rank} className="flex items-center gap-3">
          <span className="text-sm text-gray-400 dark:text-gray-500 w-5 text-right">
            {item.rank}.
          </span>
          <div className="flex-1 min-w-0">
            <div className="flex justify-between items-center mb-1">
              <span
                className={`text-sm truncate ${
                  highlight === 'red'
                    ? 'text-red-700 dark:text-red-400'
                    : 'text-gray-900 dark:text-white'
                }`}
                title={item.label}
              >
                {item.label}
              </span>
              <span className="text-sm text-gray-500 dark:text-gray-400 ml-2">
                {item.value.toLocaleString()}
              </span>
            </div>
            {item.sublabel && (
              <div className="text-xs text-gray-500 dark:text-gray-400 truncate">
                {item.sublabel}
              </div>
            )}
            <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-1.5">
              <div
                className={`h-1.5 rounded-full ${
                  highlight === 'red' ? 'bg-red-500' : 'bg-blue-500'
                }`}
                style={{ width: `${(item.value / maxValue) * 100}%` }}
              />
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}
