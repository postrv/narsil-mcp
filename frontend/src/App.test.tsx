import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { Component, type ReactNode } from 'react';

describe('ErrorBoundary', () => {
  it('catches errors and shows recovery UI', () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});

    function ThrowingComponent(): never {
      throw new Error('Test error for boundary');
    }

    class TestErrorBoundary extends Component<
      { children: ReactNode },
      { error: Error | null }
    > {
      state = { error: null as Error | null };
      static getDerivedStateFromError(error: Error) {
        return { error };
      }
      render() {
        if (this.state.error) {
          return <div data-testid="error-ui">{this.state.error.message}</div>;
        }
        return this.props.children;
      }
    }

    render(
      <TestErrorBoundary>
        <ThrowingComponent />
      </TestErrorBoundary>
    );

    expect(screen.getByTestId('error-ui')).toHaveTextContent('Test error for boundary');
    spy.mockRestore();
  });

  it('renders children when no error occurs', () => {
    class TestErrorBoundary extends Component<
      { children: ReactNode },
      { error: Error | null }
    > {
      state = { error: null as Error | null };
      static getDerivedStateFromError(error: Error) {
        return { error };
      }
      render() {
        if (this.state.error) {
          return <div>Error occurred</div>;
        }
        return this.props.children;
      }
    }

    render(
      <TestErrorBoundary>
        <div data-testid="child">Hello</div>
      </TestErrorBoundary>
    );

    expect(screen.getByTestId('child')).toHaveTextContent('Hello');
  });
});
