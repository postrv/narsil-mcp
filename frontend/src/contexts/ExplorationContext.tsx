import { createContext, useContext, useState, useCallback, type ReactNode } from 'react';

interface ExplorationState {
  sidebarOpen: boolean;
  darkMode: boolean;
  presentationMode: boolean;
}

interface ExplorationContextValue extends ExplorationState {
  toggleSidebar: () => void;
  setSidebarOpen: (open: boolean) => void;
  toggleDarkMode: () => void;
  togglePresentationMode: () => void;
}

const ExplorationContext = createContext<ExplorationContextValue | null>(null);

export function ExplorationProvider({ children }: { children: ReactNode }) {
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [darkMode, setDarkMode] = useState(
    () => window.matchMedia('(prefers-color-scheme: dark)').matches
  );
  const [presentationMode, setPresentationMode] = useState(false);

  const toggleSidebar = useCallback(() => setSidebarOpen(prev => !prev), []);
  const toggleDarkMode = useCallback(() => {
    setDarkMode(prev => {
      const next = !prev;
      document.documentElement.classList.toggle('dark', next);
      return next;
    });
  }, []);
  const togglePresentationMode = useCallback(() => setPresentationMode(prev => !prev), []);

  return (
    <ExplorationContext.Provider
      value={{
        sidebarOpen,
        darkMode,
        presentationMode,
        toggleSidebar,
        setSidebarOpen,
        toggleDarkMode,
        togglePresentationMode,
      }}
    >
      {children}
    </ExplorationContext.Provider>
  );
}

export function useExploration(): ExplorationContextValue {
  const ctx = useContext(ExplorationContext);
  if (!ctx) {
    throw new Error('useExploration must be used within ExplorationProvider');
  }
  return ctx;
}
