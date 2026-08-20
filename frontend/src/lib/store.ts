/** Client-side state that outlives a single screen: session and toasts. */

import { create } from 'zustand';
import { tokenStore } from '@/api/client';
import { auth } from '@/api/resources';
import type { User } from '@/types/api';

interface AuthState {
  user: User | null;
  status: 'unknown' | 'authenticated' | 'anonymous';
  error: string | null;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
  restore: () => Promise<void>;
  hasRole: (...roles: string[]) => boolean;
}

export const useAuth = create<AuthState>((set, get) => ({
  user: null,
  status: 'unknown',
  error: null,

  login: async (email, password) => {
    set({ error: null });
    try {
      tokenStore.set(await auth.login(email, password));
      set({ user: await auth.me(), status: 'authenticated' });
    } catch (error) {
      tokenStore.clear();
      set({
        status: 'anonymous',
        error: error instanceof Error ? error.message : 'Sign-in failed.',
      });
      throw error;
    }
  },

  logout: () => {
    tokenStore.clear();
    set({ user: null, status: 'anonymous', error: null });
  },

  /** Called once on boot: a stored token means the session may still be live. */
  restore: async () => {
    if (!tokenStore.access) {
      set({ status: 'anonymous' });
      return;
    }
    try {
      set({ user: await auth.me(), status: 'authenticated' });
    } catch {
      tokenStore.clear();
      set({ user: null, status: 'anonymous' });
    }
  },

  hasRole: (...roles) => {
    const role = get().user?.role;
    return role !== undefined && roles.includes(role);
  },
}));

export interface Toast {
  id: string;
  message: string;
  tone: 'success' | 'error' | 'warning';
}

interface ToastState {
  toasts: Toast[];
  push: (message: string, tone?: Toast['tone']) => void;
  dismiss: (id: string) => void;
}

export const useToasts = create<ToastState>((set) => ({
  toasts: [],
  push: (message, tone = 'success') => {
    const id = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    set((state) => ({ toasts: [...state.toasts, { id, message, tone }] }));
    setTimeout(() => {
      set((state) => ({ toasts: state.toasts.filter((toast) => toast.id !== id) }));
    }, 4000);
  },
  dismiss: (id) => set((state) => ({ toasts: state.toasts.filter((t) => t.id !== id) })),
}));

/** Convenience for reporting an API failure without repeating the narrowing. */
export function toastError(error: unknown, fallback = 'Something went wrong.'): void {
  useToasts.getState().push(error instanceof Error ? error.message : fallback, 'error');
}
