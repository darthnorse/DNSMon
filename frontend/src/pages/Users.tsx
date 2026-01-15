import { useState, useEffect } from 'react';
import { userApi } from '../utils/api';
import { useAuth } from '../contexts/AuthContext';
import type { User, UserCreate, UserUpdate } from '../types';

export default function Users() {
  const { user: currentUser } = useAuth();
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  // Form state
  const [showForm, setShowForm] = useState(false);
  const [editingUser, setEditingUser] = useState<User | null>(null);
  const [formData, setFormData] = useState<UserCreate & { confirmPassword?: string }>({
    username: '',
    password: '',
    confirmPassword: '',
    email: '',
    display_name: '',
    is_admin: false,
  });

  useEffect(() => {
    loadUsers();
  }, []);

  useEffect(() => {
    if (successMessage) {
      const timer = setTimeout(() => setSuccessMessage(null), 5000);
      return () => clearTimeout(timer);
    }
  }, [successMessage]);

  const loadUsers = async () => {
    try {
      setLoading(true);
      const data = await userApi.getAll();
      setUsers(data);
      setError(null);
    } catch (err: unknown) {
      const error = err as { response?: { data?: { detail?: string } } };
      setError(error.response?.data?.detail || 'Failed to load users');
    } finally {
      setLoading(false);
    }
  };

  const resetForm = () => {
    setFormData({
      username: '',
      password: '',
      confirmPassword: '',
      email: '',
      display_name: '',
      is_admin: false,
    });
    setEditingUser(null);
    setShowForm(false);
  };

  const handleEdit = (user: User) => {
    setEditingUser(user);
    setFormData({
      username: user.username,
      password: '',
      confirmPassword: '',
      email: user.email || '',
      display_name: user.display_name || '',
      is_admin: user.is_admin,
    });
    setShowForm(true);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    // Validation
    if (!editingUser && !formData.username.trim()) {
      setError('Username is required');
      return;
    }

    if (!editingUser && formData.username.trim().length < 3) {
      setError('Username must be at least 3 characters');
      return;
    }

    if (!editingUser && !formData.password) {
      setError('Password is required for new users');
      return;
    }

    if (formData.password && formData.password.length < 8) {
      setError('Password must be at least 8 characters');
      return;
    }

    if (formData.password && formData.password !== formData.confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    try {
      setSaving(true);

      if (editingUser) {
        const updateData: UserUpdate = {};
        if (formData.email !== (editingUser.email || '')) {
          updateData.email = formData.email || undefined;
        }
        if (formData.display_name !== (editingUser.display_name || '')) {
          updateData.display_name = formData.display_name || undefined;
        }
        if (formData.is_admin !== editingUser.is_admin) {
          updateData.is_admin = formData.is_admin;
        }
        if (formData.password) {
          updateData.password = formData.password;
        }

        await userApi.update(editingUser.id, updateData);
        setSuccessMessage('User updated successfully');
      } else {
        await userApi.create({
          username: formData.username.trim(),
          password: formData.password,
          email: formData.email || undefined,
          display_name: formData.display_name || undefined,
          is_admin: formData.is_admin,
        });
        setSuccessMessage('User created successfully');
      }

      await loadUsers();
      resetForm();
    } catch (err: unknown) {
      const error = err as { response?: { data?: { detail?: string } } };
      setError(error.response?.data?.detail || 'Failed to save user');
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (user: User) => {
    if (user.id === currentUser?.id) {
      setError('You cannot delete your own account');
      return;
    }

    if (!window.confirm(`Are you sure you want to delete user "${user.username}"?`)) {
      return;
    }

    try {
      await userApi.delete(user.id);
      setSuccessMessage('User deleted successfully');
      await loadUsers();
    } catch (err: unknown) {
      const error = err as { response?: { data?: { detail?: string } } };
      setError(error.response?.data?.detail || 'Failed to delete user');
    }
  };

  const handleToggleActive = async (user: User) => {
    if (user.id === currentUser?.id) {
      setError('You cannot deactivate your own account');
      return;
    }

    try {
      await userApi.update(user.id, { is_active: !user.is_active });
      setSuccessMessage(`User ${user.is_active ? 'deactivated' : 'activated'} successfully`);
      await loadUsers();
    } catch (err: unknown) {
      const error = err as { response?: { data?: { detail?: string } } };
      setError(error.response?.data?.detail || 'Failed to update user');
    }
  };

  if (loading) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">User Management</h1>
        <button
          onClick={() => {
            resetForm();
            setShowForm(true);
          }}
          className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 text-sm font-medium"
        >
          Add User
        </button>
      </div>

      {error && (
        <div className="bg-red-50 dark:bg-red-900/30 text-red-800 dark:text-red-200 px-4 py-3 rounded">
          {error}
        </div>
      )}

      {successMessage && (
        <div className="bg-green-50 dark:bg-green-900/30 text-green-800 dark:text-green-200 px-4 py-3 rounded">
          {successMessage}
        </div>
      )}

      {/* User Form */}
      {showForm && (
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <h2 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
            {editingUser ? 'Edit User' : 'Add New User'}
          </h2>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Username {!editingUser && <span className="text-red-500">*</span>}
                </label>
                <input
                  type="text"
                  value={formData.username}
                  onChange={(e) => setFormData({ ...formData, username: e.target.value })}
                  disabled={!!editingUser}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white disabled:opacity-50 disabled:bg-gray-100 dark:disabled:bg-gray-800"
                  placeholder="username"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Email
                </label>
                <input
                  type="email"
                  value={formData.email}
                  onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  placeholder="user@example.com"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Display Name
                </label>
                <input
                  type="text"
                  value={formData.display_name}
                  onChange={(e) => setFormData({ ...formData, display_name: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  placeholder="John Doe"
                />
              </div>

              <div className="flex items-center">
                <label className="flex items-center">
                  <input
                    type="checkbox"
                    checked={formData.is_admin}
                    onChange={(e) => setFormData({ ...formData, is_admin: e.target.checked })}
                    className="h-4 w-4 text-blue-600 border-gray-300 rounded"
                  />
                  <span className="ml-2 text-sm text-gray-700 dark:text-gray-300">Administrator</span>
                </label>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Password {!editingUser && <span className="text-red-500">*</span>}
                  {editingUser && <span className="text-gray-400 text-xs ml-1">(leave blank to keep current)</span>}
                </label>
                <input
                  type="password"
                  value={formData.password}
                  onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  placeholder="Min 8 characters"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Confirm Password
                </label>
                <input
                  type="password"
                  value={formData.confirmPassword}
                  onChange={(e) => setFormData({ ...formData, confirmPassword: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  placeholder="Re-enter password"
                />
              </div>
            </div>

            <div className="flex gap-3 pt-2">
              <button
                type="submit"
                disabled={saving}
                className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50 text-sm font-medium"
              >
                {saving ? 'Saving...' : editingUser ? 'Update User' : 'Create User'}
              </button>
              <button
                type="button"
                onClick={resetForm}
                className="px-4 py-2 bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-md hover:bg-gray-300 dark:hover:bg-gray-600 text-sm font-medium"
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Users Table */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow overflow-hidden">
        <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
          <thead className="bg-gray-50 dark:bg-gray-700">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                User
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                Email
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                Role
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                Status
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                Last Login
              </th>
              <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
            {users.map((user) => (
              <tr key={user.id} className={!user.is_active ? 'opacity-50' : ''}>
                <td className="px-6 py-4 whitespace-nowrap">
                  <div className="flex items-center">
                    <div className="flex-shrink-0 h-8 w-8 bg-gray-200 dark:bg-gray-600 rounded-full flex items-center justify-center">
                      <span className="text-sm font-medium text-gray-600 dark:text-gray-300">
                        {(user.display_name || user.username).charAt(0).toUpperCase()}
                      </span>
                    </div>
                    <div className="ml-3">
                      <div className="text-sm font-medium text-gray-900 dark:text-white">
                        {user.display_name || user.username}
                      </div>
                      <div className="text-sm text-gray-500 dark:text-gray-400">
                        @{user.username}
                      </div>
                    </div>
                  </div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                  {user.email || '-'}
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <span
                    className={`inline-flex px-2 py-1 text-xs font-medium rounded ${
                      user.is_admin
                        ? 'bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200'
                        : 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-300'
                    }`}
                  >
                    {user.is_admin ? 'Admin' : 'User'}
                  </span>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <span
                    className={`inline-flex px-2 py-1 text-xs font-medium rounded ${
                      user.is_active
                        ? 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200'
                        : 'bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200'
                    }`}
                  >
                    {user.is_active ? 'Active' : 'Inactive'}
                  </span>
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                  {user.last_login_at
                    ? new Date(user.last_login_at).toLocaleDateString()
                    : 'Never'}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium space-x-2">
                  <button
                    onClick={() => handleEdit(user)}
                    className="text-blue-600 dark:text-blue-400 hover:text-blue-900 dark:hover:text-blue-300"
                  >
                    Edit
                  </button>
                  {user.id !== currentUser?.id && (
                    <>
                      <button
                        onClick={() => handleToggleActive(user)}
                        className={`${
                          user.is_active
                            ? 'text-yellow-600 dark:text-yellow-400 hover:text-yellow-900'
                            : 'text-green-600 dark:text-green-400 hover:text-green-900'
                        }`}
                      >
                        {user.is_active ? 'Deactivate' : 'Activate'}
                      </button>
                      <button
                        onClick={() => handleDelete(user)}
                        className="text-red-600 dark:text-red-400 hover:text-red-900 dark:hover:text-red-300"
                      >
                        Delete
                      </button>
                    </>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {users.length === 0 && (
          <div className="text-center py-8 text-gray-500 dark:text-gray-400">
            No users found
          </div>
        )}
      </div>
    </div>
  );
}
