import { describe, it, expect, beforeEach } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import type { ReactNode } from 'react';
import { ExplorationProvider, useExploration } from './ExplorationContext';

function wrapper({ children }: { children: ReactNode }) {
  return <ExplorationProvider>{children}</ExplorationProvider>;
}

beforeEach(() => {
  // Reset dark mode class between tests
  document.documentElement.classList.remove('dark');
});

describe('ExplorationContext', () => {
  it('provides default state', () => {
    const { result } = renderHook(() => useExploration(), { wrapper });
    expect(result.current.sidebarOpen).toBe(true);
    expect(result.current.presentationMode).toBe(false);
  });

  it('toggles sidebar', () => {
    const { result } = renderHook(() => useExploration(), { wrapper });

    act(() => result.current.toggleSidebar());
    expect(result.current.sidebarOpen).toBe(false);

    act(() => result.current.toggleSidebar());
    expect(result.current.sidebarOpen).toBe(true);
  });

  it('sets sidebar open state directly', () => {
    const { result } = renderHook(() => useExploration(), { wrapper });

    act(() => result.current.setSidebarOpen(false));
    expect(result.current.sidebarOpen).toBe(false);

    act(() => result.current.setSidebarOpen(true));
    expect(result.current.sidebarOpen).toBe(true);
  });

  it('toggles dark mode and updates document class', () => {
    const { result } = renderHook(() => useExploration(), { wrapper });
    const initialDarkMode = result.current.darkMode;

    act(() => result.current.toggleDarkMode());
    expect(result.current.darkMode).toBe(!initialDarkMode);

    if (!initialDarkMode) {
      expect(document.documentElement.classList.contains('dark')).toBe(true);
    }
  });

  it('toggles presentation mode', () => {
    const { result } = renderHook(() => useExploration(), { wrapper });

    act(() => result.current.togglePresentationMode());
    expect(result.current.presentationMode).toBe(true);

    act(() => result.current.togglePresentationMode());
    expect(result.current.presentationMode).toBe(false);
  });

  it('throws when used outside provider', () => {
    // Suppress console.error from React for the expected error
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(() => {
      renderHook(() => useExploration());
    }).toThrow('useExploration must be used within ExplorationProvider');
    spy.mockRestore();
  });
});
