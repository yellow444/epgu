import React from 'react';
import App from './App';
import { createRoot } from 'react-dom/client';
import AuthGate from './components/Auth/AuthGate';
import AccountMenu from './components/Auth/AccountMenu';

// Приложение открывается только после входа. Меню учётной записи живёт в
// шапке приложения.
const rootElement = document.getElementById('root');
const root = createRoot(rootElement);
root.render(<AuthGate>{() => <App headerExtra={<AccountMenu />} />}</AuthGate>);
