import { useState, useEffect } from 'react';
import { alertRuleApi } from '../utils/api';
import type { AlertRule, AlertRuleCreate } from '../types';

export default function AlertRules() {
  const [rules, setRules] = useState<AlertRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [editingRule, setEditingRule] = useState<AlertRule | null>(null);

  const [formData, setFormData] = useState<AlertRuleCreate>({
    name: '',
    description: '',
    domain_pattern: '',
    client_ip_pattern: '',
    client_hostname_pattern: '',
    exclude_domains: '',
    cooldown_minutes: 5,
    enabled: true,
  });

  useEffect(() => {
    loadRules();
  }, []);

  const loadRules = async () => {
    try {
      setLoading(true);
      const data = await alertRuleApi.getAll();
      setRules(data);
      setError(null);
    } catch (err) {
      setError('Failed to load alert rules');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    const errors: string[] = [];

    if (!formData.name || formData.name.trim().length === 0) {
      errors.push('Rule name is required');
    } else if (formData.name.length > 100) {
      errors.push('Rule name must be 100 characters or less');
    }

    if (formData.description && formData.description.length > 500) {
      errors.push('Description must be 500 characters or less');
    }

    if (formData.domain_pattern && formData.domain_pattern.length > 5000) {
      errors.push('Domain pattern must be 5000 characters or less');
    }

    if (formData.client_ip_pattern && formData.client_ip_pattern.length > 500) {
      errors.push('Client IP pattern must be 500 characters or less');
    }

    if (formData.client_hostname_pattern && formData.client_hostname_pattern.length > 500) {
      errors.push('Client hostname pattern must be 500 characters or less');
    }

    if (formData.exclude_domains && formData.exclude_domains.length > 5000) {
      errors.push('Exclude domains must be 5000 characters or less');
    }

    const cooldown = formData.cooldown_minutes ?? 5;
    if (cooldown < 0 || cooldown > 10080) {
      errors.push('Cooldown must be between 0 and 10080 minutes (7 days)');
    }

    if (!formData.domain_pattern && !formData.client_ip_pattern && !formData.client_hostname_pattern) {
      errors.push('At least one pattern (domain, IP, or hostname) must be specified');
    }

    if (errors.length > 0) {
      setError(errors.join('. '));
      return;
    }

    try {
      if (editingRule) {
        await alertRuleApi.update(editingRule.id, formData);
      } else {
        await alertRuleApi.create(formData);
      }
      await loadRules();
      handleCancel();
    } catch (err) {
      setError('Failed to save alert rule. Please check your input and try again.');
      console.error(err);
    }
  };

  const handleEdit = (rule: AlertRule) => {
    setEditingRule(rule);
    setFormData({
      name: rule.name,
      description: rule.description || '',
      domain_pattern: rule.domain_pattern || '',
      client_ip_pattern: rule.client_ip_pattern || '',
      client_hostname_pattern: rule.client_hostname_pattern || '',
      exclude_domains: rule.exclude_domains || '',
      cooldown_minutes: rule.cooldown_minutes,
      enabled: rule.enabled,
    });
    setShowForm(true);
  };

  const handleDelete = async (id: number) => {
    if (!confirm('Are you sure you want to delete this alert rule?')) return;

    try {
      await alertRuleApi.delete(id);
      await loadRules();
    } catch (err) {
      setError('Failed to delete alert rule');
      console.error(err);
    }
  };

  const handleCancel = () => {
    setShowForm(false);
    setEditingRule(null);
    setFormData({
      name: '',
      description: '',
      domain_pattern: '',
      client_ip_pattern: '',
      client_hostname_pattern: '',
      exclude_domains: '',
      cooldown_minutes: 5,
      enabled: true,
    });
  };

  if (loading && !showForm) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="text-gray-500 dark:text-gray-400">Loading...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Alert Rules</h1>
        {!showForm && (
          <button
            onClick={() => setShowForm(true)}
            className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700"
          >
            Create Rule
          </button>
        )}
      </div>

      {error && (
        <div className="bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800/50 text-red-700 dark:text-red-300 px-4 py-3 rounded">
          {error}
        </div>
      )}

      {showForm && (
        <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
          <h2 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
            {editingRule ? 'Edit Alert Rule' : 'Create Alert Rule'}
          </h2>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label htmlFor="name" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                Rule Name *
              </label>
              <input
                type="text"
                id="name"
                required
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm px-3 py-2 border"
              />
            </div>

            <div>
              <label htmlFor="description" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                Description
              </label>
              <textarea
                id="description"
                rows={2}
                value={formData.description}
                onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm px-3 py-2 border"
              />
            </div>

            <div>
              <label htmlFor="domain_pattern" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                Alert Keywords
              </label>
              <input
                type="text"
                id="domain_pattern"
                placeholder="google, facebook, *.adult.*"
                value={formData.domain_pattern}
                onChange={(e) => setFormData({ ...formData, domain_pattern: e.target.value })}
                className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm px-3 py-2 border"
              />
              <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                Comma-separated, auto-wildcard (*google* for "google")
                {formData.domain_pattern && (
                  <span className={formData.domain_pattern.length > 5000 ? 'text-red-600 dark:text-red-400' : ''}>
                    {' '}({formData.domain_pattern.length}/5000)
                  </span>
                )}
              </p>
            </div>

            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <div>
                <label htmlFor="client_ip_pattern" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                  Client IP Pattern
                </label>
                <input
                  type="text"
                  id="client_ip_pattern"
                  placeholder="192.168.1.*"
                  value={formData.client_ip_pattern}
                  onChange={(e) => setFormData({ ...formData, client_ip_pattern: e.target.value })}
                  className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm px-3 py-2 border"
                />
              </div>

              <div>
                <label htmlFor="client_hostname_pattern" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                  Client Hostname Pattern
                </label>
                <input
                  type="text"
                  id="client_hostname_pattern"
                  placeholder="*laptop*"
                  value={formData.client_hostname_pattern}
                  onChange={(e) => setFormData({ ...formData, client_hostname_pattern: e.target.value })}
                  className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm px-3 py-2 border"
                />
              </div>
            </div>

            <div>
              <label htmlFor="exclude_domains" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                Exclude Keywords
              </label>
              <input
                type="text"
                id="exclude_domains"
                placeholder="example.com, test.com"
                value={formData.exclude_domains}
                onChange={(e) => setFormData({ ...formData, exclude_domains: e.target.value })}
                className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm px-3 py-2 border"
              />
              <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                Comma-separated, substring matching
                {formData.exclude_domains && (
                  <span className={formData.exclude_domains.length > 5000 ? 'text-red-600 dark:text-red-400' : ''}>
                    {' '}({formData.exclude_domains.length}/5000)
                  </span>
                )}
              </p>
            </div>

            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <div>
                <label htmlFor="cooldown_minutes" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                  Cooldown (minutes)
                </label>
                <input
                  type="number"
                  id="cooldown_minutes"
                  min="0"
                  value={formData.cooldown_minutes}
                  onChange={(e) => setFormData({ ...formData, cooldown_minutes: parseInt(e.target.value, 10) || 0 })}
                  className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm px-3 py-2 border"
                />
              </div>

              <div className="flex items-center pt-6">
                <input
                  type="checkbox"
                  id="enabled"
                  checked={formData.enabled}
                  onChange={(e) => setFormData({ ...formData, enabled: e.target.checked })}
                  className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                />
                <label htmlFor="enabled" className="ml-2 block text-sm text-gray-900 dark:text-gray-300">
                  Enabled
                </label>
              </div>
            </div>

            <div className="flex space-x-3 pt-4">
              <button
                type="submit"
                className="inline-flex justify-center rounded-md border border-transparent bg-blue-600 py-2 px-4 text-sm font-medium text-white shadow-sm hover:bg-blue-700"
              >
                {editingRule ? 'Update Rule' : 'Create Rule'}
              </button>
              <button
                type="button"
                onClick={handleCancel}
                className="inline-flex justify-center rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 py-2 px-4 text-sm font-medium text-gray-700 dark:text-gray-300 shadow-sm hover:bg-gray-50 dark:hover:bg-gray-600"
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      )}

      {!showForm && rules.length > 0 && (
        <div className="bg-white dark:bg-gray-800 shadow overflow-hidden sm:rounded-md">
          <ul className="divide-y divide-gray-200 dark:divide-gray-700">
            {rules.map((rule) => (
              <li key={rule.id}>
                <div className="px-4 py-4 sm:px-6 hover:bg-gray-50 dark:hover:bg-gray-700">
                  <div className="flex items-center justify-between">
                    <div className="flex-1">
                      <div className="flex items-center">
                        <p className="text-lg font-medium text-blue-600 dark:text-blue-400 truncate">{rule.name}</p>
                        {!rule.enabled && (
                          <span className="ml-2 px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-300">
                            Disabled
                          </span>
                        )}
                      </div>
                      {rule.description && (
                        <p className="mt-1 text-sm text-gray-600 dark:text-gray-400">{rule.description}</p>
                      )}
                      <div className="mt-2 flex flex-wrap gap-2 text-sm text-gray-500 dark:text-gray-400">
                        {rule.domain_pattern && (
                          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-blue-100 text-blue-800">
                            Domain: {rule.domain_pattern}
                          </span>
                        )}
                        {rule.client_ip_pattern && (
                          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800">
                            IP: {rule.client_ip_pattern}
                          </span>
                        )}
                        {rule.client_hostname_pattern && (
                          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-purple-100 text-purple-800">
                            Hostname: {rule.client_hostname_pattern}
                          </span>
                        )}
                      </div>
                      <div className="mt-2 text-xs text-gray-500 dark:text-gray-400">
                        Cooldown: {rule.cooldown_minutes} min
                      </div>
                    </div>
                    <div className="ml-4 flex space-x-2">
                      <button
                        onClick={() => handleEdit(rule)}
                        className="inline-flex items-center px-3 py-1.5 border border-gray-300 dark:border-gray-600 shadow-sm text-xs font-medium rounded text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600"
                      >
                        Edit
                      </button>
                      <button
                        onClick={() => handleDelete(rule.id)}
                        className="inline-flex items-center px-3 py-1.5 border border-transparent shadow-sm text-xs font-medium rounded text-white bg-red-600 hover:bg-red-700"
                      >
                        Delete
                      </button>
                    </div>
                  </div>
                </div>
              </li>
            ))}
          </ul>
        </div>
      )}

      {!showForm && rules.length === 0 && !loading && (
        <div className="text-center py-12">
          <p className="text-gray-500 dark:text-gray-400">No alert rules yet. Create one to get started.</p>
        </div>
      )}
    </div>
  );
}
