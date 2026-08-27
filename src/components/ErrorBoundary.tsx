import React, { Component, ErrorInfo, ReactNode } from 'react';
import { AlertOctagon } from 'lucide-react';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('Uncaught error:', error, errorInfo);
  }

  public render() {
    if (this.state.hasError) {
      return (
        <div className="flex flex-col items-center justify-center min-h-screen bg-slate-950 text-slate-200 p-6">
          <AlertOctagon className="w-16 h-16 text-red-500 mb-4" />
          <h1 className="text-2xl font-bold mb-2">Something went wrong.</h1>
          <p className="text-slate-400 mb-6 text-center max-w-md">An unexpected error occurred in the application. Our systems have logged this issue.</p>
          <pre className="bg-slate-900 p-4 rounded border border-red-500/20 text-red-400 text-xs font-mono max-w-2xl overflow-auto w-full">
            {this.state.error?.message}
          </pre>
          <div className="flex flex-wrap items-center justify-center gap-3 mt-6">
            <button 
              type="button"
              onClick={() => {
                window.location.hash = '#/dashboard';
                window.location.reload();
              }}
              className="px-6 py-2.5 bg-cyan-500 hover:bg-cyan-400 text-slate-950 rounded-xl font-bold text-sm transition-all shadow-lg shadow-cyan-500/20"
            >
              Return to Dashboard
            </button>
            <button 
              type="button"
              onClick={() => window.location.reload()}
              className="px-6 py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-xl font-medium text-sm transition-colors border border-slate-700"
            >
              Reload Page
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
