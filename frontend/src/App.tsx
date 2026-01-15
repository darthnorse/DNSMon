import { BrowserRouter as Router, Routes, Route, Link, useLocation } from 'react-router-dom';
import { useState, useEffect, useRef } from 'react';
import Dashboard from './pages/Dashboard';
import Search from './pages/Search';
import Lists from './pages/Lists';
import AlertRules from './pages/AlertRules';
import Statistics from './pages/Statistics';
import Settings from './pages/Settings';
import { blockingApi } from './utils/api';
import type { BlockingStatus } from './types';

// Duration options for blocking disable
const DURATION_OPTIONS = [
  { label: 'Indefinitely', value: undefined },
  { label: '5 minutes', value: 5 },
  { label: '15 minutes', value: 15 },
  { label: '30 minutes', value: 30 },
  { label: '1 hour', value: 60 },
];

function Navigation({ darkMode, toggleDarkMode }: { darkMode: boolean; toggleDarkMode: () => void }) {
  const location = useLocation();

  // Blocking state
  const [blockingStatuses, setBlockingStatuses] = useState<BlockingStatus[]>([]);
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const [selectAll, setSelectAll] = useState(true);
  const [selectedServers, setSelectedServers] = useState<number[]>([]);
  const [selectedDuration, setSelectedDuration] = useState<number | undefined>(undefined);
  const [blockingLoading, setBlockingLoading] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  const navItems = [
    { path: '/', label: 'Dashboard' },
    { path: '/search', label: 'Search' },
    { path: '/statistics', label: 'Statistics' },
    { path: '/lists', label: 'Lists' },
    { path: '/alerts', label: 'Alert Rules' },
    { path: '/settings', label: 'Settings' },
  ];

  // Load blocking status on mount and poll every 10s
  useEffect(() => {
    loadBlockingStatus();
    const interval = setInterval(loadBlockingStatus, 10000);
    return () => clearInterval(interval);
  }, []);

  // Close dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setDropdownOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const loadBlockingStatus = async () => {
    try {
      const response = await blockingApi.getStatus();
      setBlockingStatuses(response.servers);
    } catch (err) {
      console.error('Failed to load blocking status:', err);
    }
  };

  const handleDisable = async () => {
    try {
      setBlockingLoading(true);
      if (selectAll) {
        await blockingApi.setAllBlocking({ enabled: false, duration_minutes: selectedDuration });
      } else {
        // Disable selected servers
        for (const serverId of selectedServers) {
          await blockingApi.setBlocking(serverId, { enabled: false, duration_minutes: selectedDuration });
        }
      }
      await loadBlockingStatus();
      setDropdownOpen(false);
    } catch (err) {
      console.error('Failed to disable blocking:', err);
    } finally {
      setBlockingLoading(false);
    }
  };

  const handleEnableAll = async () => {
    try {
      setBlockingLoading(true);
      await blockingApi.setAllBlocking({ enabled: true });
      await loadBlockingStatus();
      setDropdownOpen(false);
    } catch (err) {
      console.error('Failed to enable blocking:', err);
    } finally {
      setBlockingLoading(false);
    }
  };

  const toggleServerSelection = (serverId: number) => {
    setSelectedServers(prev =>
      prev.includes(serverId)
        ? prev.filter(id => id !== serverId)
        : [...prev, serverId]
    );
  };

  const handleSelectAllChange = (checked: boolean) => {
    setSelectAll(checked);
    if (checked) {
      setSelectedServers([]);
    }
  };

  // Compute status indicators
  const anyDisabled = blockingStatuses.some(s => s.blocking === false);
  const anyUnknown = blockingStatuses.some(s => s.blocking === null);
  const hasServers = blockingStatuses.length > 0;

  // Status priority: red (disabled) > yellow (unknown) > green (all enabled)
  const getStatusColor = () => {
    if (anyDisabled) return { button: 'bg-red-600 hover:bg-red-700 text-white', dot: 'bg-red-300' };
    if (anyUnknown) return { button: 'bg-yellow-600 hover:bg-yellow-700 text-white', dot: 'bg-yellow-300' };
    return { button: 'bg-gray-700 hover:bg-gray-600 text-gray-200', dot: 'bg-green-400' };
  };
  const statusColors = getStatusColor();

  return (
    <nav className="bg-gray-800 dark:bg-gray-900">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          <div className="flex items-center min-w-0 flex-1">
            <div className="flex-shrink-0">
              <h1 className="text-white text-lg sm:text-xl font-bold">DNSMon</h1>
            </div>
            <div className="ml-4 sm:ml-10 flex items-baseline space-x-2 sm:space-x-4 overflow-x-auto">
              {navItems.map((item) => (
                <Link
                  key={item.path}
                  to={item.path}
                  className={`${
                    location.pathname === item.path
                      ? 'bg-gray-900 dark:bg-gray-700 text-white'
                      : 'text-gray-300 hover:bg-gray-700 dark:hover:bg-gray-600 hover:text-white'
                  } px-2 sm:px-3 py-2 rounded-md text-xs sm:text-sm font-medium whitespace-nowrap`}
                >
                  {item.label}
                </Link>
              ))}
            </div>
          </div>
          <div className="flex items-center gap-2">
            {/* Blocking Control Dropdown */}
            {hasServers && (
              <div className="relative" ref={dropdownRef}>
                <button
                  onClick={() => setDropdownOpen(!dropdownOpen)}
                  disabled={blockingLoading}
                  className={`flex items-center gap-1.5 px-2 sm:px-3 py-1.5 rounded-md text-xs sm:text-sm font-medium transition-colors ${statusColors.button} disabled:opacity-50`}
                >
                  <span className={`w-2 h-2 rounded-full ${statusColors.dot}`} />
                  <span className="hidden sm:inline">Disable Pi-hole</span>
                  <span className="sm:hidden">Pi-hole</span>
                  <svg className="w-3 h-3 sm:w-4 sm:h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                  </svg>
                </button>

                {/* Dropdown Panel */}
                {dropdownOpen && (
                  <div className="absolute right-0 mt-2 w-64 bg-white dark:bg-gray-800 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700 z-50">
                    <div className="p-3 border-b border-gray-200 dark:border-gray-700">
                      <h3 className="font-medium text-gray-900 dark:text-white text-sm">Pi-hole Blocking</h3>
                    </div>

                    {/* Server Selection */}
                    <div className="p-3 border-b border-gray-200 dark:border-gray-700 space-y-2">
                      <label className="flex items-center gap-2 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={selectAll}
                          onChange={(e) => handleSelectAllChange(e.target.checked)}
                          className="rounded border-gray-300 dark:border-gray-600 text-blue-600 focus:ring-blue-500"
                        />
                        <span className="text-sm text-gray-700 dark:text-gray-300">All servers</span>
                      </label>
                      {blockingStatuses.map((server) => (
                        <label
                          key={server.id}
                          className={`flex items-center justify-between gap-2 cursor-pointer ${selectAll ? 'opacity-50' : ''}`}
                        >
                          <div className="flex items-center gap-2">
                            <input
                              type="checkbox"
                              checked={selectAll || selectedServers.includes(server.id)}
                              onChange={() => toggleServerSelection(server.id)}
                              disabled={selectAll}
                              className="rounded border-gray-300 dark:border-gray-600 text-blue-600 focus:ring-blue-500"
                            />
                            <span className="text-sm text-gray-700 dark:text-gray-300">{server.name}</span>
                          </div>
                          <div className="flex items-center gap-1">
                            <span
                              className={`w-2 h-2 rounded-full ${
                                server.blocking === null
                                  ? 'bg-gray-400'
                                  : server.blocking
                                  ? 'bg-green-500'
                                  : 'bg-red-500'
                              }`}
                            />
                            <span className="text-xs text-gray-500 dark:text-gray-400">
                              {server.blocking === null ? 'Unknown' : server.blocking ? 'On' : 'Off'}
                            </span>
                          </div>
                        </label>
                      ))}
                    </div>

                    {/* Duration Selection */}
                    <div className="p-3 border-b border-gray-200 dark:border-gray-700">
                      <label className="block text-sm text-gray-700 dark:text-gray-300 mb-1">Duration</label>
                      <select
                        value={selectedDuration ?? ''}
                        onChange={(e) => setSelectedDuration(e.target.value ? Number(e.target.value) : undefined)}
                        className="w-full px-2 py-1.5 text-sm border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-blue-500 focus:border-blue-500"
                      >
                        {DURATION_OPTIONS.map((option) => (
                          <option key={option.label} value={option.value ?? ''}>
                            {option.label}
                          </option>
                        ))}
                      </select>
                    </div>

                    {/* Action Buttons */}
                    <div className="p-3 flex gap-2">
                      {anyDisabled && (
                        <button
                          onClick={handleEnableAll}
                          disabled={blockingLoading}
                          className="flex-1 px-3 py-1.5 text-sm bg-green-600 text-white rounded-md hover:bg-green-700 disabled:opacity-50 transition-colors"
                        >
                          Enable All
                        </button>
                      )}
                      <button
                        onClick={handleDisable}
                        disabled={blockingLoading || (!selectAll && selectedServers.length === 0)}
                        className="flex-1 px-3 py-1.5 text-sm bg-red-600 text-white rounded-md hover:bg-red-700 disabled:opacity-50 transition-colors"
                      >
                        {blockingLoading ? 'Working...' : 'Disable'}
                      </button>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Dark Mode Toggle */}
            <button
              onClick={toggleDarkMode}
              className="flex-shrink-0 p-2 rounded-md text-gray-300 hover:bg-gray-700 dark:hover:bg-gray-600 hover:text-white focus:outline-none focus:ring-2 focus:ring-white"
              aria-label="Toggle dark mode"
            >
              {darkMode ? (
                <svg className="h-5 w-5 sm:h-6 sm:w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" />
                </svg>
              ) : (
                <svg className="h-5 w-5 sm:h-6 sm:w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" />
                </svg>
              )}
            </button>
          </div>
        </div>
      </div>
    </nav>
  );
}

function App() {
  const [darkMode, setDarkMode] = useState(() => {
    const saved = localStorage.getItem('darkMode');
    return saved ? JSON.parse(saved) : false;
  });

  useEffect(() => {
    if (darkMode) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
    localStorage.setItem('darkMode', JSON.stringify(darkMode));
  }, [darkMode]);

  const toggleDarkMode = () => {
    setDarkMode(!darkMode);
  };

  return (
    <Router>
      <div className="min-h-screen bg-gray-100 dark:bg-gray-900">
        <Navigation darkMode={darkMode} toggleDarkMode={toggleDarkMode} />
        <main className="max-w-7xl mx-auto py-4 px-4 sm:py-6 sm:px-6 lg:px-8">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/search" element={<Search />} />
            <Route path="/statistics" element={<Statistics />} />
            <Route path="/lists" element={<Lists />} />
            <Route path="/alerts" element={<AlertRules />} />
            <Route path="/settings" element={<Settings />} />
          </Routes>
        </main>
      </div>
    </Router>
  );
}

export default App;
