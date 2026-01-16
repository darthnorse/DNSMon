import { createContext, useContext, useState, useEffect, useCallback, ReactNode } from 'react';
import type { User, AuthCheckResponse } from '../types';
import { authApi } from '../utils/api';

interface AuthContextType {
  user: User | null;
  authenticated: boolean;
  loading: boolean;
  setupComplete: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  checkAuth: () => Promise<AuthCheckResponse>;
  setUser: (user: User | null) => void;
  setSetupComplete: (complete: boolean) => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

interface AuthProviderProps {
  children: ReactNode;
}

export function AuthProvider({ children }: AuthProviderProps) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [setupComplete, setSetupComplete] = useState(true);

  const checkAuth = useCallback(async (): Promise<AuthCheckResponse> => {
    try {
      const response = await authApi.check();
      setUser(response.user);
      setSetupComplete(response.setup_complete);
      return response;
    } catch (err) {
      setUser(null);
      setSetupComplete(true);
      return { authenticated: false, user: null, setup_complete: true };
    }
  }, []);

  // Check authentication status on mount
  useEffect(() => {
    const initAuth = async () => {
      try {
        await checkAuth();
      } finally {
        setLoading(false);
      }
    };
    initAuth();
  }, [checkAuth]);

  const login = async (username: string, password: string): Promise<void> => {
    const loggedInUser = await authApi.login({ username, password });
    setUser(loggedInUser);
    setSetupComplete(true);
  };

  const logout = async (): Promise<void> => {
    try {
      await authApi.logout();
    } finally {
      setUser(null);
    }
  };

  const authenticated = user !== null;

  return (
    <AuthContext.Provider
      value={{
        user,
        authenticated,
        loading,
        setupComplete,
        login,
        logout,
        checkAuth,
        setUser,
        setSetupComplete,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextType {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
