// Рабочий раздел: приложение открывается только после входа. Меню учётной
// записи живёт в шапке приложения.
import React from 'react';
import App from './App';
import AuthGate from './components/Auth/AuthGate';
import AccountMenu from './components/Auth/AccountMenu';

export default function ProtectedWorkspace() {
  return <AuthGate>{() => <App headerExtra={<AccountMenu />} />}</AuthGate>;
}
