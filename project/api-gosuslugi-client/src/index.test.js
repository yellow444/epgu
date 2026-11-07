// Проверки от настоящей входной точки (src/index.js), а не от отдельного
// компонента: гайд доступен без backend и без входа, рабочий раздел закрыт.
// index.js выполняется один раз на файл; сценарии меняют адрес и ответы сервера.
import { act, fireEvent, screen, waitFor, within } from '@testing-library/react';

// Рабочее приложение заменено заглушкой: так видно, монтировалось ли оно, и
// не нужны его собственные запросы к сертификатам и услугам.
const mockAppMounts = jest.fn();
jest.mock('./App', () => {
  const React = require('react');
  const { useAuth } = require('./components/Auth/AuthGate');
  return function ProtectedApp() {
    mockAppMounts();
    const { logout } = useAuth();
    return React.createElement('div', null,
      React.createElement('div', null, 'Рабочее приложение'),
      React.createElement('button', { type: 'button', onClick: () => logout() }, 'Выйти из установки'));
  };
});

jest.setTimeout(30000);

const DATASET_PATH = '/api/v1/knowledge/dataset';
const json = (status, body) => ({ ok: status >= 200 && status < 300, status, json: () => Promise.resolve(body) });
const offline = () => { throw new TypeError('Failed to fetch'); };

// Сервер по сценарию: функция получает путь и возвращает ответ или бросает ошибку сети.
function serve(handler) {
  global.fetch = jest.fn((url) => Promise.resolve().then(() => handler(String(url))));
}
const calledPaths = () => (global.fetch ? global.fetch.mock.calls.map(([url]) => String(url)) : []);
const protectedCalls = () => calledPaths().filter((url) => url !== DATASET_PATH);
const sections = () => within(screen.getByRole('navigation', { name: 'Разделы' }));
const settle = () => act(async () => { await new Promise((resolve) => setTimeout(resolve, 0)); });

// Переход на адрес так, как это делает браузер: сначала уводим со всех
// разделов с состоянием, затем меняем адрес и ждём hashchange.
async function open(hash, handler) {
  await act(async () => {
    window.location.hash = '#manual';
    window.dispatchEvent(new HashChangeEvent('hashchange'));
  });
  if (handler) serve(handler); else delete global.fetch;
  mockAppMounts.mockClear();
  await act(async () => {
    window.history.replaceState(null, '', `/${hash}`);
    window.dispatchEvent(new HashChangeEvent('hashchange'));
  });
  await settle();
}

beforeAll(async () => {
  serve(offline);
  window.history.replaceState(null, '', '/');
  document.body.innerHTML = '<div id="root"></div>';
  await act(async () => {
    require('./index');
  });
  await settle();
});

afterAll(() => {
  delete global.fetch;
  window.history.replaceState(null, '', '/');
});

test('a clean start with the backend down opens the guide, not the login', async () => {
  // Первый запуск index.js в beforeAll: сервер недоступен, адрес пустой.
  expect(screen.getByRole('heading', { name: 'Гайд по интеграциям' })).toBeInTheDocument();
  expect(await screen.findByText(/сервер недоступен, показана встроенная копия/)).toBeInTheDocument();
  expect(protectedCalls()).toEqual([]);
  expect(screen.queryByText('Вход в установку')).not.toBeInTheDocument();
});

test('with the backend down the guide search and source links work', async () => {
  await open('#guide', offline);
  fireEvent.change(screen.getByRole('searchbox', { name: 'Поиск по всем маршрутам' }), { target: { value: 'Webhook' } });
  expect(within(screen.getByRole('region', { name: 'Результаты поиска' })).getAllByRole('button').length).toBeGreaterThan(0);
  fireEvent.change(screen.getByRole('searchbox', { name: 'Поиск по всем маршрутам' }), { target: { value: '' } });
  fireEvent.click(screen.getByRole('button', { name: 'Нет реальной организации' }));
  const links = within(screen.getByRole('region', { name: 'Нет реальной организации' })).getAllByRole('link');
  expect(links.length).toBeGreaterThan(0);
  links.forEach((link) => {
    expect(link.getAttribute('href')).toMatch(/^https:\/\//);
    expect(link).toHaveAttribute('rel', 'noopener noreferrer');
  });
  expect(window.location.hash).toBe('#guide/epgu-vendor/no-org');
  expect(protectedCalls()).toEqual([]);
  expect(mockAppMounts).not.toHaveBeenCalled();
});

test('without fetch at all the guide still renders', async () => {
  await open('#guide', null);
  expect(screen.getByText('Встроенная копия')).toBeInTheDocument();
});

test('a direct hash opens the requested step without authorization', async () => {
  await open('#guide/max/webhook', offline);
  expect(screen.getByRole('region', { name: 'HTTPS Webhook и повторы' })).toBeInTheDocument();
  await waitFor(() => expect(global.fetch).toHaveBeenCalledTimes(1));
  expect(calledPaths()).toEqual([DATASET_PATH]);
  expect(mockAppMounts).not.toHaveBeenCalled();
});

test('manual preparation is public and does not call the backend', async () => {
  await open('#manual', offline);
  expect(screen.getByRole('heading', { name: 'Ручная настройка подключения' })).toBeInTheDocument();
  expect(global.fetch).not.toHaveBeenCalled();
  expect(mockAppMounts).not.toHaveBeenCalled();
});

test.each([
  ['no administrator yet', (url) => (url.endsWith('/auth/session') ? json(401, {}) : json(200, { auth: true, bootstrap_required: true })), 'Установка ещё не настроена'],
  ['no session', (url) => (url.endsWith('/auth/session') ? json(401, {}) : json(200, { auth: true, bootstrap_required: false })), 'Вход в установку'],
  ['backend down', offline, 'Сервер установки недоступен'],
])('%s: the workspace stays closed and the guide is one click away', async (_, handler, gateText) => {
  await open('#workspace', handler);
  expect(await screen.findByText(gateText)).toBeInTheDocument();
  expect(mockAppMounts).not.toHaveBeenCalled();
  fireEvent.click(sections().getByRole('button', { name: 'Гайд по интеграциям' }));
  expect(screen.getByRole('heading', { name: 'Гайд по интеграциям' })).toBeInTheDocument();
  expect(screen.queryByText(gateText)).not.toBeInTheDocument();
  expect(window.location.hash).toBe('#guide');
  expect(mockAppMounts).not.toHaveBeenCalled();
  await settle();
});

test('switching between public sections does not start workspace requests', async () => {
  await open('#guide/epgu-vendor/no-org', (url) => (url === DATASET_PATH ? json(503, {}) : json(401, {})));
  expect(await screen.findByText(/сервер ответил ошибкой 503/)).toBeInTheDocument();
  fireEvent.click(sections().getByRole('button', { name: 'Ручная подготовка' }));
  fireEvent.click(sections().getByRole('button', { name: 'Гайд по интеграциям' }));
  await waitFor(() => expect(global.fetch).toHaveBeenCalledTimes(2));
  expect(protectedCalls()).toEqual([]);
  expect(mockAppMounts).not.toHaveBeenCalled();
});

test('an expired session closes the workspace and leaves the guide available', async () => {
  let sessionAlive = true;
  await open('#workspace', (url) => {
    if (url.endsWith('/auth/session')) return sessionAlive ? json(200, { login: 'user' }) : json(401, {});
    if (url.endsWith('/auth/mode')) return json(200, { auth: true, bootstrap_required: false });
    return offline();
  });
  expect(await screen.findByText('Рабочее приложение')).toBeInTheDocument();
  sessionAlive = false;
  await act(async () => { window.dispatchEvent(new Event('focus')); });
  expect(await screen.findByText('Сессия закончилась. Войдите снова.')).toBeInTheDocument();
  expect(screen.queryByText('Рабочее приложение')).not.toBeInTheDocument();
  fireEvent.click(sections().getByRole('button', { name: 'Гайд по интеграциям' }));
  expect(screen.getByRole('heading', { name: 'Гайд по интеграциям' })).toBeInTheDocument();
  await settle();
});

test('after logout the guide can be opened and the workspace asks to sign in again', async () => {
  let loggedIn = true;
  await open('#workspace', (url) => {
    if (url.endsWith('/auth/logout')) { loggedIn = false; return json(200, {}); }
    if (url.endsWith('/auth/session')) return loggedIn ? json(200, { login: 'user' }) : json(401, {});
    if (url.endsWith('/auth/mode')) return json(200, { auth: true, bootstrap_required: false });
    return offline();
  });
  fireEvent.click(await screen.findByRole('button', { name: 'Выйти из установки' }));
  expect(await screen.findByText('Вход в установку')).toBeInTheDocument();
  fireEvent.click(sections().getByRole('button', { name: 'Гайд по интеграциям' }));
  expect(screen.getByRole('heading', { name: 'Гайд по интеграциям' })).toBeInTheDocument();
  mockAppMounts.mockClear();
  fireEvent.click(sections().getByRole('button', { name: 'Рабочий раздел' }));
  expect(await screen.findByText('Вход в установку')).toBeInTheDocument();
  expect(mockAppMounts).not.toHaveBeenCalled();
});
