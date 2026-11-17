import {createRoot} from 'react-dom/client';
import App from './App.tsx';
import './index.css';

if (import.meta.env.PROD && typeof window !== 'undefined') {
  try {
    const win = window as unknown as Record<string, unknown>;
    const noopHook = Object.freeze({
      isDisabled: true,
      supportsFiber: true,
      inject: () => -1,
      onCommitFiberRoot: () => {},
      onCommitFiberUnmount: () => {},
    });
    const desc = Object.getOwnPropertyDescriptor(win, '__REACT_DEVTOOLS_GLOBAL_HOOK__');
    if (!desc || desc.configurable) {
      Object.defineProperty(win, '__REACT_DEVTOOLS_GLOBAL_HOOK__', {
        value: noopHook,
        writable: false,
        configurable: false,
      });
    }
  } catch {
    // Ignore read-only environments
  }
}

createRoot(document.getElementById('root')!).render(<App />);
