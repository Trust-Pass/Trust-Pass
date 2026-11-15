import { useQuery, useQueryClient } from '@tanstack/react-query';
import { createContext, useCallback, useContext, useMemo, type ReactNode } from 'react';
import { api, setCsrfToken } from './api';
import type { Me } from './types';

interface AuthState {
  me: Me | null;
  loading: boolean;
  refresh: () => Promise<void>;
  signedIn: (data: Pick<Me, 'user' | 'organizations' | 'csrfToken'>) => void;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthState | null>(null);

async function fetchMe(): Promise<Me | null> {
  const res = await api<(Me & { authenticated: true }) | { authenticated: false }>('/api/auth/session');
  if (!res.authenticated) {
    setCsrfToken(null);
    return null;
  }
  setCsrfToken(res.csrfToken);
  return res;
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const query = useQuery({ queryKey: ['me'], queryFn: fetchMe, staleTime: 30_000, refetchInterval: 60_000, retry: false });

  const refresh = useCallback(async () => {
    await queryClient.invalidateQueries({ queryKey: ['me'] });
  }, [queryClient]);

  const signedIn = useCallback(
    (data: Pick<Me, 'user' | 'organizations' | 'csrfToken'>) => {
      setCsrfToken(data.csrfToken);
      queryClient.setQueryData<Me>(['me'], { ...data, unreadNotifications: 0 });
      void queryClient.invalidateQueries({ queryKey: ['me'] });
    },
    [queryClient],
  );

  const logout = useCallback(async () => {
    try {
      await api('/api/auth/logout', { method: 'POST' });
    } finally {
      setCsrfToken(null);
      queryClient.clear();
      queryClient.setQueryData(['me'], null);
    }
  }, [queryClient]);

  const value = useMemo<AuthState>(
    () => ({ me: query.data ?? null, loading: query.isLoading, refresh, signedIn, logout }),
    [query.data, query.isLoading, refresh, signedIn, logout],
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider');
  return ctx;
}

export function useMe(): Me {
  const { me } = useAuth();
  if (!me) throw new Error('Signed-in user expected');
  return me;
}
