import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import AuthGate from './AuthGate';
import AccountMenu from './AccountMenu';

const ADMIN = { id: 'acc_' + 'a'.repeat(32), login: 'admin', display_name: 'Администратор', installation_admin: true };
const OPERATOR = { id: 'acc_' + 'b'.repeat(32), login: 'operator', display_name: 'Оператор', installation_admin: false };
const PASSWORD = 'correct horse battery staple';

function installServer({ signedIn = null, bootstrap = false } = {}) {
  const calls = [];
  const state = { session: signedIn ? { account: signedIn } : null, accounts: [
    { account_id: ADMIN.id, login: 'admin', display_name: 'Администратор', installation_admin: true, disabled: false },
  ] };
  global.fetch = jest.fn(async (url, options = {}) => {
    const method = (options.method || 'GET').toUpperCase();
    const path = new URL(url, 'http://localhost').pathname;
    const body = options.body ? JSON.parse(options.body) : undefined;
    calls.push({ method, path, body, credentials: options.credentials });
    let status = 200;
    let payload = {};
    if (path === '/api/auth/session') {
      if (state.session) payload = state.session;
      else { status = 401; payload = { detail: 'Нужен вход' }; }
    } else if (path === '/api/auth/mode') {
      payload = { auth: true, bootstrap_required: bootstrap };
    } else if (path === '/api/auth/login') {
      if (body.password === PASSWORD) { state.session = { account: body.login === 'admin' ? ADMIN : OPERATOR }; payload = state.session; }
      else { status = 401; payload = { detail: 'Неверный логин или пароль' }; }
    } else if (path === '/api/auth/logout') {
      state.session = null;
      payload = { logged_out: true };
    } else if (path === '/api/auth/accounts' && method === 'GET') {
      payload = { accounts: state.accounts };
    } else if (path === '/api/auth/accounts' && method === 'POST') {
      state.accounts.push({ account_id: 'acc_' + 'c'.repeat(32), login: body.login, display_name: body.display_name, installation_admin: body.installation_admin, disabled: false });
      payload = { id: 'acc_' + 'c'.repeat(32), login: body.login };
    } else if (path === '/api/auth/password') {
      state.session = null;
      payload = { changed: true, relogin: true };
    } else {
      status = 404;
      payload = { detail: 'нет' };
    }
    return { ok: status < 400, status, json: async () => payload };
  });
  return { calls, state };
}

function Protected() {
  return (
    <AuthGate>
      {() => (
        <div>
          <div>приложение открыто</div>
          <AccountMenu />
        </div>
      )}
    </AuthGate>
  );
}

afterEach(() => {
  delete global.fetch;
});

test('the application is hidden until the user signs in', async () => {
  const { calls } = installServer();
  render(<Protected />);
  expect(await screen.findByText('Вход в установку')).toBeInTheDocument();
  expect(screen.queryByText('приложение открыто')).not.toBeInTheDocument();
  fireEvent.change(screen.getByLabelText('Логин'), { target: { value: 'admin' } });
  fireEvent.change(screen.getByLabelText('Пароль'), { target: { value: 'wrong password!!' } });
  fireEvent.click(screen.getByRole('button', { name: /Войти/ }));
  expect(await screen.findByText('Неверный логин или пароль')).toBeInTheDocument();
  fireEvent.change(screen.getByLabelText('Пароль'), { target: { value: PASSWORD } });
  fireEvent.click(screen.getByRole('button', { name: /Войти/ }));
  expect(await screen.findByText('приложение открыто')).toBeInTheDocument();
  expect(calls.every((call) => call.credentials === 'same-origin')).toBe(true);
  expect(JSON.stringify({ ...localStorage, ...sessionStorage })).not.toMatch(/battery/);
});

test('a session that ended while the page was open brings back the login form', async () => {
  const { state } = installServer({ signedIn: ADMIN });
  render(<Protected />);
  expect(await screen.findByText('приложение открыто')).toBeInTheDocument();
  // Сессия погасла на сервере: по сроку, смене пароля или перезапуску.
  state.session = null;
  fireEvent.focus(window);
  expect(await screen.findByText('Сессия закончилась. Войдите снова.')).toBeInTheDocument();
  expect(screen.getByLabelText('Пароль')).toBeInTheDocument();
  expect(screen.queryByText('приложение открыто')).not.toBeInTheDocument();
});

test('an installation without an administrator shows the local command', async () => {
  installServer({ bootstrap: true });
  render(<Protected />);
  expect(await screen.findByText('Установка ещё не настроена')).toBeInTheDocument();
  expect(screen.getByText(/create-admin/)).toBeInTheDocument();
  expect(screen.queryByLabelText('Пароль')).not.toBeInTheDocument();
});

test('logout returns to the login form', async () => {
  installServer({ signedIn: ADMIN });
  render(<Protected />);
  expect(await screen.findByText('приложение открыто')).toBeInTheDocument();
  fireEvent.click(screen.getByTestId('account-menu'));
  fireEvent.click(await screen.findByText('Выйти'));
  expect(await screen.findByText('Вход в установку')).toBeInTheDocument();
});

test('only an administrator sees users, and can create one', async () => {
  const { calls } = installServer({ signedIn: ADMIN });
  render(<Protected />);
  expect(await screen.findByText('приложение открыто')).toBeInTheDocument();
  fireEvent.click(screen.getByTestId('account-menu'));
  fireEvent.click(await screen.findByText('Пользователи'));
  expect(await screen.findByTestId('account-admin')).toBeInTheDocument();
  fireEvent.change(screen.getByLabelText('Логин нового пользователя'), { target: { value: 'operator' } });
  fireEvent.change(screen.getByLabelText('Пароль нового пользователя'), { target: { value: PASSWORD } });
  fireEvent.click(screen.getByRole('button', { name: /Создать пользователя/ }));
  expect(await screen.findByText('Пользователь создан')).toBeInTheDocument();
  const created = calls.find((call) => call.path === '/api/auth/accounts' && call.method === 'POST');
  expect(created.body).toMatchObject({ login: 'operator', installation_admin: false });
});

test('an operator has no users item', async () => {
  installServer({ signedIn: OPERATOR });
  render(<Protected />);
  expect(await screen.findByText('приложение открыто')).toBeInTheDocument();
  fireEvent.click(screen.getByTestId('account-menu'));
  expect(await screen.findByText('Сменить пароль')).toBeInTheDocument();
  expect(screen.queryByText('Пользователи')).not.toBeInTheDocument();
});

test('changing the password asks to sign in again', async () => {
  const { calls } = installServer({ signedIn: ADMIN });
  render(<Protected />);
  expect(await screen.findByText('приложение открыто')).toBeInTheDocument();
  fireEvent.click(screen.getByTestId('account-menu'));
  fireEvent.click(await screen.findByText('Сменить пароль'));
  fireEvent.change(await screen.findByLabelText('Текущий пароль'), { target: { value: PASSWORD } });
  fireEvent.change(screen.getByLabelText('Новый пароль'), { target: { value: 'another long password' } });
  fireEvent.change(screen.getByLabelText('Повтор нового пароля'), { target: { value: 'another long password' } });
  fireEvent.click(screen.getByRole('button', { name: /Сменить/ }));
  expect(await screen.findByText('Пароль изменён. Войдите с новым паролем.')).toBeInTheDocument();
  await waitFor(() => expect(calls.some((call) => call.path === '/api/auth/password')).toBe(true));
});
