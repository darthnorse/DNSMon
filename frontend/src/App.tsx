import { BrowserRouter as Router, Routes, Route, Link, useLocation, useNavigate } from 'react-router-dom';
import { useState, useEffect, useRef } from 'react';
import Dashboard from './pages/Dashboard';
import Search from './pages/Search';
import Lists from './pages/Lists';
import AlertRules from './pages/AlertRules';
import Statistics from './pages/Statistics';
import Settings from './pages/Settings';
import Users from './pages/Users';
import Login from './pages/Login';
import Setup from './pages/Setup';
import { AuthProvider, useAuth } from './contexts/AuthContext';
import { ProtectedRoute } from './components/ProtectedRoute';
import { blockingApi } from './utils/api';
import type { BlockingStatus } from './types';

// Duration options for blocking disable
const DURATION_OPTIONS = [
  { label: '1 minute', value: 1 },
  { label: '5 minutes', value: 5 },
  { label: '15 minutes', value: 15 },
  { label: '30 minutes', value: 30 },
  { label: '1 hour', value: 60 },
  { label: 'Indefinitely', value: undefined },
];

function Navigation({ darkMode, toggleDarkMode }: { darkMode: boolean; toggleDarkMode: () => void }) {
  const location = useLocation();
  const navigate = useNavigate();
  const { user, logout } = useAuth();

  // Blocking state
  const [blockingStatuses, setBlockingStatuses] = useState<BlockingStatus[]>([]);
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const [userMenuOpen, setUserMenuOpen] = useState(false);
  const [selectedDuration, setSelectedDuration] = useState<number | undefined>(1); // Default to 1 minute
  const [blockingLoading, setBlockingLoading] = useState(false);
  const [countdown, setCountdown] = useState<string | null>(null);
  const dropdownRef = useRef<HTMLDivElement>(null);
  const userMenuRef = useRef<HTMLDivElement>(null);

  const navItems = [
    { path: '/', label: 'Dashboard' },
    { path: '/search', label: 'Search' },
    { path: '/statistics', label: 'Statistics' },
    ...(user?.is_admin ? [
      { path: '/lists', label: 'Lists' },
      { path: '/alerts', label: 'Alert Rules' },
      { path: '/settings', label: 'Settings' },
      { path: '/users', label: 'Users' },
    ] : []),
  ];

  // Load blocking status on mount and poll every 10s
  useEffect(() => {
    loadBlockingStatus();
    const interval = setInterval(loadBlockingStatus, 10000);
    return () => clearInterval(interval);
  }, []);

  // Update countdown timer every second when blocking is disabled
  useEffect(() => {
    const updateCountdown = () => {
      const disabledServer = blockingStatuses.find(s => s.blocking === false && s.auto_enable_at);
      if (disabledServer?.auto_enable_at) {
        const enableAt = new Date(disabledServer.auto_enable_at).getTime();
        const now = Date.now();
        const remaining = Math.max(0, Math.floor((enableAt - now) / 1000));
        if (remaining > 0) {
          const minutes = Math.floor(remaining / 60);
          const seconds = remaining % 60;
          setCountdown(minutes > 0 ? `${minutes}m ${seconds}s` : `${seconds}s`);
        } else {
          setCountdown(null);
        }
      } else {
        setCountdown(null);
      }
    };

    updateCountdown();
    const interval = setInterval(updateCountdown, 1000);
    return () => clearInterval(interval);
  }, [blockingStatuses]);

  // Close dropdowns when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setDropdownOpen(false);
      }
      if (userMenuRef.current && !userMenuRef.current.contains(event.target as Node)) {
        setUserMenuOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

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
      await blockingApi.setAllBlocking({ enabled: false, duration_minutes: selectedDuration });
      await loadBlockingStatus();
      setDropdownOpen(false);
    } catch (err) {
      console.error('Failed to disable blocking:', err);
    } finally {
      setBlockingLoading(false);
    }
  };

  const handleEnable = async () => {
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

  // Compute status
  const anyDisabled = blockingStatuses.some(s => s.blocking === false);
  const anyUnknown = blockingStatuses.some(s => s.blocking === null);
  const hasServers = blockingStatuses.length > 0;
  const serverCount = blockingStatuses.length;

  // Status priority: red (any disabled) > yellow (unknown) > green (all enabled)
  const getStatusColor = () => {
    if (anyDisabled) return { button: 'bg-red-600 hover:bg-red-700 text-white', dot: 'bg-red-400' };
    if (anyUnknown) return { button: 'bg-yellow-600 hover:bg-yellow-700 text-white', dot: 'bg-yellow-400' };
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
                  <span className="hidden sm:inline">
                    {anyDisabled ? (countdown ? `Disabled (${countdown})` : 'Disabled') : 'DNS Blocking'}
                  </span>
                  <span className="sm:hidden">
                    {anyDisabled ? (countdown ? countdown : 'Off') : 'DNS'}
                  </span>
                  <svg className="w-3 h-3 sm:w-4 sm:h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                  </svg>
                </button>

                {/* Dropdown Panel */}
                {dropdownOpen && (
                  <div className="absolute right-0 mt-2 w-64 bg-white dark:bg-gray-800 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700 z-50">
                    <div className="p-3 border-b border-gray-200 dark:border-gray-700">
                      <h3 className="font-medium text-gray-900 dark:text-white text-sm">DNS Blocking</h3>
                      <p className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">
                        {serverCount} server{serverCount !== 1 ? 's' : ''} configured
                      </p>
                    </div>

                    {/* Status Display */}
                    <div className="p-3 border-b border-gray-200 dark:border-gray-700">
                      <div className="flex items-center justify-between">
                        <span className="text-sm text-gray-700 dark:text-gray-300">Status</span>
                        <div className="flex items-center gap-1.5">
                          <span
                            className={`w-2 h-2 rounded-full ${
                              anyDisabled ? 'bg-red-500' : anyUnknown ? 'bg-yellow-500' : 'bg-green-500'
                            }`}
                          />
                          <span className={`text-sm font-medium ${
                            anyDisabled ? 'text-red-600 dark:text-red-400' :
                            anyUnknown ? 'text-yellow-600 dark:text-yellow-400' :
                            'text-green-600 dark:text-green-400'
                          }`}>
                            {anyDisabled ? 'Disabled' : anyUnknown ? 'Unknown' : 'Enabled'}
                          </span>
                        </div>
                      </div>
                      {countdown && (
                        <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                          Re-enables in {countdown}
                        </p>
                      )}
                      {anyDisabled && !countdown && (
                        <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                          Disabled indefinitely
                        </p>
                      )}
                    </div>

                    {/* Action Section - Admin only */}
                    {user?.is_admin ? (
                      anyDisabled ? (
                        /* Enable button when disabled */
                        <div className="p-3">
                          <button
                            onClick={handleEnable}
                            disabled={blockingLoading}
                            className="w-full px-3 py-2 text-sm bg-green-600 text-white rounded-md hover:bg-green-700 disabled:opacity-50 transition-colors font-medium"
                          >
                            {blockingLoading ? 'Enabling...' : 'Enable Blocking'}
                          </button>
                        </div>
                      ) : (
                        /* Disable controls when enabled */
                        <>
                          <div className="p-3 border-b border-gray-200 dark:border-gray-700">
                            <label className="block text-sm text-gray-700 dark:text-gray-300 mb-1">
                              Disable for
                            </label>
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
                          <div className="p-3">
                            <button
                              onClick={handleDisable}
                              disabled={blockingLoading}
                              className="w-full px-3 py-2 text-sm bg-red-600 text-white rounded-md hover:bg-red-700 disabled:opacity-50 transition-colors font-medium"
                            >
                              {blockingLoading ? 'Disabling...' : 'Disable Blocking'}
                            </button>
                          </div>
                        </>
                      )
                    ) : (
                      <div className="p-3 text-xs text-gray-500 dark:text-gray-400 text-center">
                        Admin privileges required to change blocking
                      </div>
                    )}
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

            {/* User Menu */}
            {user && (
              <div className="relative" ref={userMenuRef}>
                <button
                  onClick={() => setUserMenuOpen(!userMenuOpen)}
                  className="flex items-center gap-2 px-2 sm:px-3 py-1.5 rounded-md text-gray-300 hover:bg-gray-700 dark:hover:bg-gray-600 hover:text-white text-xs sm:text-sm font-medium"
                >
                  <svg className="w-4 h-4 sm:w-5 sm:h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                  </svg>
                  <span className="hidden sm:inline">{user.display_name || user.username}</span>
                  <svg className="w-3 h-3 sm:w-4 sm:h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                  </svg>
                </button>

                {userMenuOpen && (
                  <div className="absolute right-0 mt-2 w-48 bg-white dark:bg-gray-800 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700 z-50">
                    <div className="px-4 py-3 border-b border-gray-200 dark:border-gray-700">
                      <p className="text-sm font-medium text-gray-900 dark:text-white">
                        {user.display_name || user.username}
                      </p>
                      {user.email && (
                        <p className="text-xs text-gray-500 dark:text-gray-400 truncate">
                          {user.email}
                        </p>
                      )}
                      {user.is_admin && (
                        <span className="inline-block mt-1 px-2 py-0.5 text-xs bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200 rounded">
                          Admin
                        </span>
                      )}
                    </div>
                    <div className="py-1">
                      <button
                        onClick={handleLogout}
                        className="w-full text-left px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700"
                      >
                        Sign out
                      </button>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </nav>
  );
}

function AppLayout() {
  const [darkMode, setDarkMode] = useState(() => {
    const saved = localStorage.getItem('darkMode');
    return saved !== null ? JSON.parse(saved) : true;
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
    <div className="min-h-screen bg-gray-100 dark:bg-gray-900">
      <Navigation darkMode={darkMode} toggleDarkMode={toggleDarkMode} />
      <main className="max-w-7xl mx-auto py-4 px-4 sm:py-6 sm:px-6 lg:px-8">
        <Routes>
          <Route path="/" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
          <Route path="/search" element={<ProtectedRoute><Search /></ProtectedRoute>} />
          <Route path="/statistics" element={<ProtectedRoute><Statistics /></ProtectedRoute>} />
          <Route path="/lists" element={<ProtectedRoute requireAdmin><Lists /></ProtectedRoute>} />
          <Route path="/alerts" element={<ProtectedRoute requireAdmin><AlertRules /></ProtectedRoute>} />
          <Route path="/settings" element={<ProtectedRoute requireAdmin><Settings /></ProtectedRoute>} />
          <Route path="/users" element={<ProtectedRoute requireAdmin><Users /></ProtectedRoute>} />
        </Routes>
      </main>
    </div>
  );
}

function App() {
  return (
    <Router>
      <AuthProvider>
        <Routes>
          {/* Public routes */}
          <Route path="/login" element={<Login />} />
          <Route path="/setup" element={<Setup />} />

          {/* Protected routes - wrapped in layout */}
          <Route path="/*" element={<AppLayout />} />
        </Routes>
      </AuthProvider>
    </Router>
  );
}

export default App;
