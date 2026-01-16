import React, { useState, useEffect } from 'react';
import { notificationChannelApi } from '../utils/api';
import type {
  NotificationChannel,
  NotificationChannelCreate,
  NotificationChannelType,
  ChannelTypeInfo,
  TemplateVariable,
} from '../types';

interface Props {
  onError: (error: string | null) => void;
  onSuccess: (message: string) => void;
}

export default function NotificationsSettings({ onError, onSuccess }: Props) {
  const [channels, setChannels] = useState<NotificationChannel[]>([]);
  const [channelTypes, setChannelTypes] = useState<ChannelTypeInfo[]>([]);
  const [templateVariables, setTemplateVariables] = useState<TemplateVariable[]>([]);
  const [defaultTemplate, setDefaultTemplate] = useState('');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState<number | null>(null);

  // Form state
  const [showForm, setShowForm] = useState(false);
  const [editingChannel, setEditingChannel] = useState<NotificationChannel | null>(null);
  const [formData, setFormData] = useState<NotificationChannelCreate>({
    name: '',
    channel_type: 'telegram',
    config: {},
    message_template: '',
    enabled: true,
  });

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      const [channelsData, typesData, variablesData] = await Promise.all([
        notificationChannelApi.getAll(),
        notificationChannelApi.getChannelTypes(),
        notificationChannelApi.getTemplateVariables(),
      ]);
      setChannels(channelsData);
      setChannelTypes(typesData.channel_types);
      setTemplateVariables(variablesData.variables);
      setDefaultTemplate(variablesData.default_template);
    } catch (err) {
      onError('Failed to load notification channels');
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    onError(null);

    if (!formData.name.trim()) {
      onError('Channel name is required');
      return;
    }

    try {
      setSaving(true);

      if (editingChannel) {
        await notificationChannelApi.update(editingChannel.id, {
          name: formData.name,
          config: formData.config,
          message_template: formData.message_template || undefined,
          enabled: formData.enabled,
        });
      } else {
        await notificationChannelApi.create(formData);
      }

      await loadData();
      handleCancelForm();
      onSuccess(`Channel ${editingChannel ? 'updated' : 'created'} successfully`);
    } catch (err: unknown) {
      const error = err as { response?: { data?: { detail?: string } } };
      onError(error.response?.data?.detail || 'Failed to save channel');
    } finally {
      setSaving(false);
    }
  };

  const handleEdit = (channel: NotificationChannel) => {
    setEditingChannel(channel);
    setFormData({
      name: channel.name,
      channel_type: channel.channel_type,
      config: { ...channel.config } as Record<string, unknown>,
      message_template: channel.message_template || '',
      enabled: channel.enabled,
    });
    setShowForm(true);
    onError(null);
  };

  const handleDelete = async (id: number) => {
    if (!window.confirm('Are you sure you want to delete this notification channel?')) {
      return;
    }

    try {
      setSaving(true);
      await notificationChannelApi.delete(id);
      await loadData();
      onSuccess('Channel deleted successfully');
    } catch (err: unknown) {
      const error = err as { response?: { data?: { detail?: string } } };
      onError(error.response?.data?.detail || 'Failed to delete channel');
    } finally {
      setSaving(false);
    }
  };

  const handleTest = async (id: number) => {
    try {
      setTesting(id);
      onError(null);
      const result = await notificationChannelApi.test(id);
      if (result.success) {
        onSuccess('Test notification sent successfully');
        await loadData(); // Refresh to show updated last_success_at
      } else {
        onError(result.message);
        await loadData(); // Refresh to show error
      }
    } catch (err: unknown) {
      const error = err as { response?: { data?: { detail?: string } } };
      onError(error.response?.data?.detail || 'Test failed');
      await loadData();
    } finally {
      setTesting(null);
    }
  };

  const handleCancelForm = () => {
    setShowForm(false);
    setEditingChannel(null);
    setFormData({
      name: '',
      channel_type: 'telegram',
      config: {},
      message_template: '',
      enabled: true,
    });
    onError(null);
  };

  const handleChannelTypeChange = (type: NotificationChannelType) => {
    setFormData({
      ...formData,
      channel_type: type,
      config: {}, // Reset config when changing type
    });
  };

  const getChannelTypeInfo = (type: NotificationChannelType): ChannelTypeInfo | undefined => {
    return channelTypes.find(t => t.type === type);
  };

  const getChannelIcon = (type: string): string => {
    const icons: Record<string, string> = {
      telegram: 'M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm4.64 6.8c-.15 1.58-.8 5.42-1.13 7.19-.14.75-.42 1-.68 1.03-.58.05-1.02-.38-1.58-.75-.88-.58-1.38-.94-2.23-1.5-.99-.65-.35-1.01.22-1.59.15-.15 2.71-2.48 2.76-2.69a.2.2 0 0 0-.05-.18c-.06-.05-.14-.03-.21-.02-.09.02-1.49.95-4.22 2.79-.4.27-.76.41-1.08.4-.36-.01-1.04-.2-1.55-.37-.63-.2-1.12-.31-1.08-.66.02-.18.27-.36.74-.55 2.92-1.27 4.86-2.11 5.83-2.51 2.78-1.16 3.35-1.36 3.73-1.36.08 0 .27.02.39.12.1.08.13.19.14.27-.01.06.01.24 0 .38z',
      pushover: 'M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z',
      ntfy: 'M12 22c1.1 0 2-.9 2-2h-4c0 1.1.89 2 2 2zm6-6v-5c0-3.07-1.64-5.64-4.5-6.32V4c0-.83-.67-1.5-1.5-1.5s-1.5.67-1.5 1.5v.68C7.63 5.36 6 7.92 6 11v5l-2 2v1h16v-1l-2-2z',
      discord: 'M19.27 5.33C17.94 4.71 16.5 4.26 15 4a.09.09 0 0 0-.07.03c-.18.33-.39.76-.53 1.09a16.09 16.09 0 0 0-4.8 0c-.14-.34-.35-.76-.54-1.09-.01-.02-.04-.03-.07-.03-1.5.26-2.93.71-4.27 1.33-.01 0-.02.01-.03.02-2.72 4.07-3.47 8.03-3.1 11.95 0 .02.01.04.03.05 1.8 1.32 3.53 2.12 5.24 2.65.03.01.06 0 .07-.02.4-.55.76-1.13 1.07-1.74.02-.04 0-.08-.04-.09-.57-.22-1.11-.48-1.64-.78-.04-.02-.04-.08-.01-.11.11-.08.22-.17.33-.25.02-.02.05-.02.07-.01 3.44 1.57 7.15 1.57 10.55 0 .02-.01.05-.01.07.01.11.09.22.17.33.26.04.03.04.09-.01.11-.52.31-1.07.56-1.64.78-.04.01-.05.06-.04.09.32.61.68 1.19 1.07 1.74.03.01.06.02.09.01 1.72-.53 3.45-1.33 5.25-2.65.02-.01.03-.03.03-.05.44-4.53-.73-8.46-3.1-11.95-.01-.01-.02-.02-.04-.02zM8.52 14.91c-1.03 0-1.89-.95-1.89-2.12s.84-2.12 1.89-2.12c1.06 0 1.9.96 1.89 2.12 0 1.17-.84 2.12-1.89 2.12zm6.97 0c-1.03 0-1.89-.95-1.89-2.12s.84-2.12 1.89-2.12c1.06 0 1.9.96 1.89 2.12 0 1.17-.83 2.12-1.89 2.12z',
      webhook: 'M4.5 11h3v6h-3zm6 0h3v6h-3zm6 0h3v6h-3zM21 19H3v2h18zM21 3H3v2h18z',
    };
    return icons[type] || icons.webhook;
  };

  const formatDate = (dateStr: string | null): string => {
    if (!dateStr) return 'Never';
    const date = new Date(dateStr);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins} minute${diffMins === 1 ? '' : 's'} ago`;
    if (diffHours < 24) return `${diffHours} hour${diffHours === 1 ? '' : 's'} ago`;
    if (diffDays < 7) return `${diffDays} day${diffDays === 1 ? '' : 's'} ago`;
    return date.toLocaleDateString();
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div>
      <div className="flex justify-between items-center mb-4">
        <h2 className="text-lg font-medium text-gray-900 dark:text-white">Notification Channels</h2>
        {!showForm && (
          <button
            onClick={() => setShowForm(true)}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-md text-sm font-medium"
          >
            Add Channel
          </button>
        )}
      </div>

      {/* Channel Form */}
      {showForm && (
        <form onSubmit={handleSubmit} className="mb-6 bg-gray-50 dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700">
          <h3 className="text-md font-medium text-gray-900 dark:text-white mb-4">
            {editingChannel ? 'Edit Channel' : 'Add New Channel'}
          </h3>

          <div className="space-y-4">
            {/* Channel Type (only for new channels) */}
            {!editingChannel && (
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Channel Type
                </label>
                <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
                  {channelTypes.map((type) => (
                    <button
                      key={type.type}
                      type="button"
                      onClick={() => handleChannelTypeChange(type.type)}
                      className={`flex items-center justify-center px-3 py-2 rounded-md text-sm font-medium ${
                        formData.channel_type === type.type
                          ? 'bg-blue-600 text-white'
                          : 'bg-white dark:bg-gray-700 text-gray-700 dark:text-gray-300 border border-gray-300 dark:border-gray-600 hover:bg-gray-50 dark:hover:bg-gray-600'
                      }`}
                    >
                      <svg className="w-4 h-4 mr-2" viewBox="0 0 24 24" fill="currentColor">
                        <path d={getChannelIcon(type.type)} />
                      </svg>
                      {type.name}
                    </button>
                  ))}
                </div>
              </div>
            )}

            {/* Channel Name */}
            <div>
              <label htmlFor="channel_name" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Name
              </label>
              <input
                type="text"
                id="channel_name"
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                placeholder="My Telegram Channel"
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              />
            </div>

            {/* Channel-specific Config Fields */}
            {getChannelTypeInfo(formData.channel_type)?.config_fields.map((field) => (
              <div key={field.name}>
                <label htmlFor={`config_${field.name}`} className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  {field.label}
                  {field.required && <span className="text-red-500 ml-1">*</span>}
                </label>
                {field.type === 'select' ? (
                  <select
                    id={`config_${field.name}`}
                    value={(formData.config[field.name] as string) || ''}
                    onChange={(e) => setFormData({
                      ...formData,
                      config: { ...formData.config, [field.name]: e.target.value }
                    })}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  >
                    <option value="">{field.placeholder || 'Select...'}</option>
                    {field.options?.map((opt) => (
                      <option key={opt} value={opt}>{opt}</option>
                    ))}
                  </select>
                ) : (
                  <input
                    type={field.type === 'password' ? 'password' : field.type === 'number' ? 'number' : 'text'}
                    id={`config_${field.name}`}
                    value={(formData.config[field.name] as string) || ''}
                    onChange={(e) => setFormData({
                      ...formData,
                      config: { ...formData.config, [field.name]: field.type === 'number' ? parseInt(e.target.value, 10) || '' : e.target.value }
                    })}
                    placeholder={editingChannel && field.type === 'password' ? 'Leave empty to keep existing' : field.placeholder}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  />
                )}
              </div>
            ))}

            {/* Message Template */}
            <div>
              <label htmlFor="message_template" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Message Template (optional)
              </label>
              <textarea
                id="message_template"
                rows={4}
                value={formData.message_template || ''}
                onChange={(e) => setFormData({ ...formData, message_template: e.target.value })}
                placeholder={defaultTemplate}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white font-mono text-sm"
              />
              <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                Leave empty to use the default template. Available variables:
              </p>
              <div className="flex flex-wrap gap-1 mt-1">
                {templateVariables.map((v) => (
                  <span
                    key={v.name}
                    className="inline-block px-2 py-0.5 text-xs bg-gray-200 dark:bg-gray-600 text-gray-700 dark:text-gray-300 rounded cursor-pointer hover:bg-gray-300 dark:hover:bg-gray-500"
                    title={`${v.description} (e.g., ${v.example})`}
                    onClick={() => setFormData({ ...formData, message_template: (formData.message_template || '') + v.name })}
                  >
                    {v.name}
                  </span>
                ))}
              </div>
            </div>

            {/* Enabled */}
            <div className="flex items-center">
              <input
                type="checkbox"
                id="channel_enabled"
                checked={formData.enabled}
                onChange={(e) => setFormData({ ...formData, enabled: e.target.checked })}
                className="h-4 w-4 text-blue-600 border-gray-300 rounded"
              />
              <label htmlFor="channel_enabled" className="ml-2 text-sm text-gray-700 dark:text-gray-300">
                Enabled
              </label>
            </div>
          </div>

          {/* Form Actions */}
          <div className="flex space-x-3 mt-6">
            <button
              type="submit"
              disabled={saving}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 text-white rounded-md text-sm font-medium"
            >
              {saving ? 'Saving...' : (editingChannel ? 'Update Channel' : 'Create Channel')}
            </button>
            <button
              type="button"
              onClick={handleCancelForm}
              disabled={saving}
              className="px-4 py-2 bg-gray-200 hover:bg-gray-300 dark:bg-gray-700 dark:hover:bg-gray-600 text-gray-700 dark:text-gray-300 rounded-md text-sm font-medium"
            >
              Cancel
            </button>
          </div>
        </form>
      )}

      {/* Channel List */}
      {channels.length === 0 ? (
        <div className="text-center py-8 text-gray-500 dark:text-gray-400">
          <p>No notification channels configured.</p>
          <p className="text-sm mt-1">Click "Add Channel" to create one.</p>
        </div>
      ) : (
        <div className="space-y-3">
          {channels.map((channel) => (
            <div
              key={channel.id}
              className={`bg-white dark:bg-gray-800 border rounded-lg p-4 ${
                channel.enabled
                  ? 'border-gray-200 dark:border-gray-700'
                  : 'border-gray-200 dark:border-gray-700 opacity-60'
              }`}
            >
              <div className="flex items-start justify-between">
                <div className="flex items-start space-x-3">
                  <div className={`p-2 rounded-lg ${channel.enabled ? 'bg-blue-100 dark:bg-blue-900' : 'bg-gray-100 dark:bg-gray-700'}`}>
                    <svg className={`w-5 h-5 ${channel.enabled ? 'text-blue-600 dark:text-blue-400' : 'text-gray-400'}`} viewBox="0 0 24 24" fill="currentColor">
                      <path d={getChannelIcon(channel.channel_type)} />
                    </svg>
                  </div>
                  <div>
                    <div className="flex items-center space-x-2">
                      <h4 className="font-medium text-gray-900 dark:text-white">{channel.name}</h4>
                      <span className="text-xs px-2 py-0.5 rounded bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400">
                        {channel.channel_type}
                      </span>
                      {!channel.enabled && (
                        <span className="text-xs px-2 py-0.5 rounded bg-yellow-100 dark:bg-yellow-900 text-yellow-700 dark:text-yellow-300">
                          Disabled
                        </span>
                      )}
                    </div>
                    {/* Status */}
                    <div className="mt-1 text-sm">
                      {channel.consecutive_failures > 0 ? (
                        <span className="text-red-600 dark:text-red-400">
                          {channel.consecutive_failures} failure{channel.consecutive_failures > 1 ? 's' : ''} - {channel.last_error}
                        </span>
                      ) : channel.last_success_at ? (
                        <span className="text-green-600 dark:text-green-400">
                          Last success: {formatDate(channel.last_success_at)}
                        </span>
                      ) : (
                        <span className="text-gray-500 dark:text-gray-400">
                          Never sent
                        </span>
                      )}
                    </div>
                  </div>
                </div>
                <div className="flex space-x-2">
                  <button
                    onClick={() => handleTest(channel.id)}
                    disabled={testing === channel.id || saving}
                    className="px-3 py-1 text-sm bg-green-600 hover:bg-green-700 disabled:bg-gray-400 text-white rounded"
                  >
                    {testing === channel.id ? 'Testing...' : 'Test'}
                  </button>
                  <button
                    onClick={() => handleEdit(channel)}
                    disabled={saving}
                    className="px-3 py-1 text-sm bg-gray-200 hover:bg-gray-300 dark:bg-gray-700 dark:hover:bg-gray-600 text-gray-700 dark:text-gray-300 rounded"
                  >
                    Edit
                  </button>
                  <button
                    onClick={() => handleDelete(channel.id)}
                    disabled={saving}
                    className="px-3 py-1 text-sm bg-red-600 hover:bg-red-700 disabled:bg-gray-400 text-white rounded"
                  >
                    Delete
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
