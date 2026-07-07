/** UI state management with Zustand */
import { create } from 'zustand';

interface UIState {
  sidebarOpen: boolean;
  activeModal: string | null;
  theme: 'light' | 'dark';
  toggleSidebar: () => void;
  setSidebarOpen: (open: boolean) => void;
  openModal: (modal: string) => void;
  closeModal: () => void;
  toggleTheme: () => void;
}

export const useUIStore = create<UIState>((set) => ({
  sidebarOpen: true,
  activeModal: null,
  theme: 'light',
  toggleSidebar: () => set((state) => ({ sidebarOpen: !state.sidebarOpen })),
  setSidebarOpen: (open) => set({ sidebarOpen: open }),
  openModal: (modal) => set({ activeModal: modal }),
  closeModal: () => set({ activeModal: null }),
  toggleTheme: () => set((state) => ({ theme: state.theme === 'light' ? 'dark' : 'light' })),
}));

