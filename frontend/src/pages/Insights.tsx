import { useState, useEffect, useCallback } from 'react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  PieChart,
  Pie,
  Cell,
} from 'recharts';
import { insightsApi } from '../utils/api';
import type { AppUsage, CategoryUsage, DomainUsage } from '../types';
import ClassifyDomainModal from '../components/ClassifyDomainModal';

const COLORS = [
  '#3B82F6', '#EF4444', '#10B981', '#F59E0B',
  '#8B5CF6', '#EC4899', '#14B8A6', '#F97316',
  '#6366F1', '#84CC16', '#F43F5E', '#0EA5E9',
];

const TOOLTIP_CONTENT_STYLE = {
  backgroundColor: '#1F2937',
  border: '1px solid #374151',
  borderRadius: '0.375rem',
  color: '#fff',
};
const TOOLTIP_LABEL_STYLE = { color: '#9CA3AF' };
const TOOLTIP_ITEM_STYLE = { color: '#fff' };

function formatNumber(num: number): string {
  if (num >= 1000000) return `${(num / 1000000).toFixed(1)}M`;
  if (num >= 1000) return `${(num / 1000).toFixed(1)}K`;
  return num.toLocaleString();
}

type Period = '24h' | '7d' | '30d';

export default function Insights() {
  const [period, setPeriod] = useState<Period>('24h');
  const [apps, setApps] = useState<AppUsage[]>([]);
  const [categories, setCategories] = useState<CategoryUsage[]>([]);
  const [selectedApp, setSelectedApp] = useState<string | null>(null);
  const [appDomains, setAppDomains] = useState<DomainUsage[]>([]);
  const [uncat, setUncat] = useState<DomainUsage[]>([]);
  const [classifyTarget, setClassifyTarget] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [drillDownError, setDrillDownError] = useState<string | null>(null);

  const loadInsights = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const [a, c, u] = await Promise.all([
        insightsApi.apps({ period }),
        insightsApi.categories({ period }),
        insightsApi.uncategorized(period, 50).catch(() => [] as DomainUsage[]),
      ]);
      setApps(a);
      setCategories(c);
      setUncat(u);
    } catch {
      setError('Failed to load insights');
    } finally {
      setLoading(false);
    }
  }, [period]);

  useEffect(() => { loadInsights(); }, [loadInsights]);

  useEffect(() => {
    if (!selectedApp) { setAppDomains([]); setDrillDownError(null); return; }
    const loadDomains = async () => {
      try {
        setDrillDownError(null);
        const data = await insightsApi.appDomains(selectedApp, { period });
        setAppDomains(data);
      } catch {
        setAppDomains([]);
        setDrillDownError('Failed to load domains for this app');
      }
    };
    loadDomains();
  }, [selectedApp, period]);

  const topApps = apps.slice(0, 15);

  const totalCategoryQueries = categories.reduce((sum, c) => sum + c.total, 0);

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Insights</h1>

        <div className="flex rounded-lg overflow-hidden border border-gray-300 dark:border-gray-600">
          {(['24h', '7d', '30d'] as const).map((p) => (
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
      </div>

      {error && (
        <div className="bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800/50 text-red-700 dark:text-red-300 px-4 py-3 rounded">
          {error}
        </div>
      )}

      {loading ? (
        <div className="flex justify-center items-center h-64">
          <div className="text-gray-500 dark:text-gray-400">Loading insights...</div>
        </div>
      ) : (
        <>
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            {/* Top Apps panel */}
            <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
              <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-1">
                Top Apps
              </h2>
              <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">
                Click a bar to drill down into its domains
              </p>
              {topApps.length === 0 ? (
                <div className="flex items-center justify-center h-64 text-gray-500 dark:text-gray-400">
                  No app data available for this period
                </div>
              ) : (
                <ResponsiveContainer width="100%" height={Math.max(240, topApps.length * 32)}>
                  <BarChart
                    layout="vertical"
                    data={topApps}
                    margin={{ top: 0, right: 16, left: 8, bottom: 0 }}
                  >
                    <XAxis
                      type="number"
                      stroke="#9CA3AF"
                      fontSize={12}
                      tickLine={false}
                      tickFormatter={formatNumber}
                    />
                    <YAxis
                      type="category"
                      dataKey="app_name"
                      stroke="#9CA3AF"
                      fontSize={12}
                      tickLine={false}
                      width={110}
                    />
                    <Tooltip
                      formatter={(value: number) => value.toLocaleString()}
                      contentStyle={TOOLTIP_CONTENT_STYLE}
                      labelStyle={TOOLTIP_LABEL_STYLE}
                      itemStyle={TOOLTIP_ITEM_STYLE}
                      cursor={{ fill: 'rgba(55, 65, 81, 0.3)' }}
                    />
                    <Bar
                      dataKey="total"
                      name="Queries"
                      fill="#3B82F6"
                      radius={[0, 3, 3, 0]}
                      cursor="pointer"
                      onClick={(_data, index) => {
                        const app = topApps[index];
                        if (app) setSelectedApp(app.app_name);
                      }}
                    />
                  </BarChart>
                </ResponsiveContainer>
              )}
            </div>

            {/* Category Distribution panel */}
            <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
              <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
                Category Distribution
              </h2>
              {categories.length === 0 ? (
                <div className="flex items-center justify-center h-64 text-gray-500 dark:text-gray-400">
                  No category data available for this period
                </div>
              ) : (
                <ResponsiveContainer width="100%" height={280}>
                  <PieChart>
                    <Pie
                      data={categories}
                      cx="50%"
                      cy="50%"
                      outerRadius={100}
                      paddingAngle={2}
                      dataKey="total"
                      nameKey="category"
                      label={({ category, total }) =>
                        totalCategoryQueries > 0
                          ? `${category}: ${((total / totalCategoryQueries) * 100).toFixed(1)}%`
                          : category
                      }
                      labelLine={false}
                    >
                      {categories.map((_entry, index) => (
                        <Cell
                          key={`cell-${index}`}
                          fill={COLORS[index % COLORS.length]}
                        />
                      ))}
                    </Pie>
                    <Tooltip
                      formatter={(value: number) => value.toLocaleString()}
                      contentStyle={TOOLTIP_CONTENT_STYLE}
                      labelStyle={TOOLTIP_LABEL_STYLE}
                      itemStyle={TOOLTIP_ITEM_STYLE}
                    />
                  </PieChart>
                </ResponsiveContainer>
              )}
            </div>

            {/* Top Uncategorized Domains panel */}
            <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-6 lg:col-span-2">
              <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-1">Top Uncategorized Domains</h2>
              <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">Classify the heaviest hitters first to raise coverage fastest.</p>
              {uncat.length === 0 ? (
                <div className="flex items-center justify-center h-64 text-gray-500 dark:text-gray-400">
                  Nothing uncategorized in this period 🎉
                </div>
              ) : (
                <ul className="divide-y divide-gray-100 dark:divide-gray-700">
                  {uncat.map((d) => (
                    <li key={d.domain} className="flex items-center justify-between py-1.5 text-sm">
                      <span className="font-mono text-gray-800 dark:text-gray-200 break-all">{d.domain}</span>
                      <span className="flex items-center gap-3 shrink-0">
                        <span className="text-gray-500 dark:text-gray-400">{d.total.toLocaleString()}</span>
                        <button
                          onClick={() => setClassifyTarget(d.domain)}
                          className="px-2 py-0.5 text-xs rounded bg-blue-600 hover:bg-blue-700 text-white"
                        >
                          Classify
                        </button>
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>

          {/* App drill-down panel */}
          <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
            {selectedApp ? (
              <>
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                    Domains for{' '}
                    <span className="text-blue-600 dark:text-blue-400">{selectedApp}</span>
                  </h2>
                  <button
                    onClick={() => setSelectedApp(null)}
                    className="text-sm text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 flex items-center gap-1"
                  >
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
                    </svg>
                    Back to all apps
                  </button>
                </div>

                {drillDownError ? (
                  <div className="bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800/50 text-red-700 dark:text-red-300 px-4 py-3 rounded">
                    {drillDownError}
                  </div>
                ) : appDomains.length === 0 ? (
                  <div className="text-center text-gray-500 dark:text-gray-400 py-8">
                    No domain data available
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                      <thead>
                        <tr>
                          <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                            Domain
                          </th>
                          <th className="px-4 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                            Total
                          </th>
                          <th className="px-4 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                            Blocked
                          </th>
                          <th className="px-4 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                            Block rate
                          </th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                        {appDomains.map((row) => (
                          <tr
                            key={row.domain}
                            className="hover:bg-gray-50 dark:hover:bg-gray-700/50"
                          >
                            <td className="px-4 py-3 text-sm font-mono text-gray-900 dark:text-white">
                              {row.domain}
                            </td>
                            <td className="px-4 py-3 text-sm text-right text-gray-700 dark:text-gray-300">
                              {row.total.toLocaleString()}
                            </td>
                            <td className="px-4 py-3 text-sm text-right text-red-600 dark:text-red-400">
                              {row.blocked.toLocaleString()}
                            </td>
                            <td className="px-4 py-3 text-sm text-right text-gray-500 dark:text-gray-400">
                              {row.total > 0
                                ? `${((row.blocked / row.total) * 100).toFixed(1)}%`
                                : '—'}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </>
            ) : (
              <div className="flex flex-col items-center justify-center py-12 text-gray-500 dark:text-gray-400">
                <svg className="w-10 h-10 mb-3 opacity-40" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
                    d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
                <p className="text-sm">Click an app bar above to see its domain breakdown</p>
              </div>
            )}
          </div>
        </>
      )}

      {classifyTarget && (
        <ClassifyDomainModal
          domain={classifyTarget}
          onClose={() => setClassifyTarget(null)}
          onClassified={() => { setClassifyTarget(null); loadInsights(); }}
        />
      )}
    </div>
  );
}
