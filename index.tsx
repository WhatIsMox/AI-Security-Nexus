
import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import './bootstrap-grid.scss';
import './index.css';

declare global {
  interface Window {
    plausible?: ((...args: unknown[]) => void) & {
      init?: (options?: Record<string, unknown>) => void;
      o?: Record<string, unknown>;
      q?: unknown[][];
    };
  }
}

window.plausible = window.plausible || function (...args: unknown[]) {
  (window.plausible!.q = window.plausible!.q || []).push(args);
};
window.plausible.init = window.plausible.init || function (options?: Record<string, unknown>) {
  window.plausible!.o = options || {};
};
window.plausible.init();

import { ErrorBoundary } from './components/ErrorBoundary';

const rootElement = document.getElementById('root');
if (!rootElement) {
  throw new Error("Could not find root element to mount to");
}

const root = ReactDOM.createRoot(rootElement);
root.render(
  <React.StrictMode>
    <ErrorBoundary>
      <App />
    </ErrorBoundary>
  </React.StrictMode>
);
