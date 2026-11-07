// Тесты экрана «Гайд по интеграциям». Основа - тесты из repos/public (исходная
// работа не зафиксирована в git), адаптированные к общей модели знаний.
import React from 'react';
import fs from 'fs';
import path from 'path';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import IntegrationGuide from './IntegrationGuide';
import bundled from './knowledge.v1.json';
import { buildGuideModel, findGuideLocation, validateDataset } from './knowledgeModel';

const { FLOWS, SOURCES } = buildGuideModel(bundled);

const clone = () => JSON.parse(JSON.stringify(bundled));
const okResponse = (data, status = 200) => ({ ok: true, status, json: () => Promise.resolve(data) });

beforeEach(() => {
  window.history.replaceState(null, '', '/');
  // по умолчанию сервер не отвечает вовсе, поэтому экран остаётся на встроенной копии
  global.fetch = jest.fn(() => new Promise(() => {}));
});

afterEach(() => {
  delete global.fetch;
});

test('bundled copy is byte-identical to the canonical knowledge model', () => {
  const project = path.resolve(__dirname, '../../../..');
  const canonical = fs.readFileSync(path.join(project, 'knowledge/src/epgu_knowledge/data/knowledge.v1.json'));
  const copy = fs.readFileSync(path.join(__dirname, 'knowledge.v1.json'));
  expect(copy.equals(canonical)).toBe(true);
});

test('every graph has valid unique nodes, edges, sources and reachable steps', () => {
  expect(validateDataset(bundled)).toBe(true);
  expect(new Set(FLOWS.map((flow) => flow.id)).size).toBe(FLOWS.length);
  FLOWS.forEach((flow) => {
    const ids = new Set(flow.nodes.map((item) => item.id));
    expect(ids.size).toBe(flow.nodes.length);
    expect(ids.has(flow.entry)).toBe(true);
    const visited = new Set();
    const visit = (id) => {
      if (visited.has(id)) return;
      visited.add(id);
      flow.nodes.find((item) => item.id === id).next.forEach((edge) => visit(edge.to));
    };
    flow.nodes.forEach((item) => {
      item.next.forEach((edge) => expect(ids.has(edge.to)).toBe(true));
      expect(item.sources.length).toBeGreaterThan(0);
      item.sources.forEach((source) => expect(SOURCES[source].url).toMatch(/^https:\/\//));
    });
    visit(flow.entry);
    expect(visited.size).toBe(ids.size);
  });
});

test('free guide offers a no-organization branch without claiming authorization', () => {
  render(<IntegrationGuide />);
  expect(screen.getByText(/Бесплатный раздел без платных дополнений/)).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Нет реальной организации' }));
  const detail = screen.getByRole('region', { name: 'Нет реальной организации' });
  expect(within(detail).getByText(/Подтверждённого общего маршрута/)).toBeInTheDocument();
  expect(window.location.hash).toBe('#guide/epgu-vendor/no-org');
  expect(within(detail).getByRole('link', { name: /ЛК API ЕПГУ/ })).toHaveAttribute('rel', 'noopener noreferrer');
});

test('search navigates across all flows, not only the currently selected one', () => {
  render(<IntegrationGuide />);
  fireEvent.change(screen.getByRole('searchbox', { name: 'Поиск по всем маршрутам' }), { target: { value: 'X-Max-Bot-Api-Secret' } });
  const results = screen.getByRole('region', { name: 'Результаты поиска' });
  fireEvent.click(within(results).getByRole('button', { name: /HTTPS Webhook/ }));
  expect(screen.getByRole('region', { name: 'HTTPS Webhook и повторы' })).toBeInTheDocument();
  expect(window.location.hash).toBe('#guide/max/webhook');
});

test('search works offline and never calls the server search', async () => {
  render(<IntegrationGuide />);
  fireEvent.change(screen.getByRole('searchbox', { name: 'Поиск по всем маршрутам' }), { target: { value: 'Webhook' } });
  expect(within(screen.getByRole('region', { name: 'Результаты поиска' })).getAllByRole('button').length).toBeGreaterThan(0);
  await waitFor(() => expect(global.fetch).toHaveBeenCalledTimes(1));
  expect(global.fetch.mock.calls[0][0]).toMatch(/\/v1\/knowledge\/dataset$/);
});

test('deep links and hash navigation select known steps and reject invalid routes', () => {
  window.history.replaceState(null, '', '#guide/digital-ruble/messages');
  render(<IntegrationGuide />);
  expect(screen.getByRole('region', { name: 'Альбомы, XSD и даты действия' })).toBeInTheDocument();
  expect(findGuideLocation('#guide/unknown/messages', FLOWS)).toEqual({ flowId: 'epgu-vendor', nodeId: 'start' });
  expect(findGuideLocation('#guide/max/unknown', FLOWS)).toEqual({ flowId: 'epgu-vendor', nodeId: 'start' });
  expect(findGuideLocation('', FLOWS)).toEqual({ flowId: 'epgu-vendor', nodeId: 'start' });
  expect(findGuideLocation('#guide/max/webhook', FLOWS)).toEqual({ flowId: 'max', nodeId: 'webhook' });
});

test('hashchange switches the selected step', () => {
  render(<IntegrationGuide />);
  act(() => {
    window.history.replaceState(null, '', '#guide/max/webhook');
    window.dispatchEvent(new HashChangeEvent('hashchange'));
  });
  expect(screen.getByRole('region', { name: 'HTTPS Webhook и повторы' })).toBeInTheDocument();
});

test('all topic buttons switch the diagram and the detail panel', () => {
  render(<IntegrationGuide />);
  const navigation = screen.getByRole('navigation', { name: 'Маршруты интеграций' });
  FLOWS.forEach((flow) => {
    fireEvent.click(within(navigation).getByRole('button', { name: flow.title }));
    expect(screen.getByRole('region', { name: `Блок-схема: ${flow.title}` })).toBeInTheDocument();
    expect(screen.getByRole('region', { name: flow.nodes[0].title })).toBeInTheDocument();
  });
});

test('current regulation independent route is preserved instead of declaring cabinet mandatory for all cases', () => {
  window.history.replaceState(null, '', '#guide/transition/outside-lk');
  render(<IntegrationGuide />);
  const detail = screen.getByRole('region', { name: 'Вне ЛК: регламентный маршрут' });
  expect(within(detail).getByText(/Разделы 2.1 и 3 действующего регламента/)).toBeInTheDocument();
  expect(within(detail).getByText(/не означает разрешение подключать синтетическую организацию/)).toBeInTheDocument();
  expect(within(detail).getByRole('link', { name: /Регламент подключения API ЕПГУ/ })).toHaveAttribute('href', SOURCES.apiRegulation.url);
});

describe('data origin', () => {
  test('starts from the bundled copy and keeps it when the server is unreachable', async () => {
    global.fetch.mockImplementation(() => Promise.reject(new Error('offline')));
    render(<IntegrationGuide />);
    expect(screen.getByText('Встроенная копия')).toBeInTheDocument();
    expect(screen.getByText(`Сверка: ${bundled.dataset.reviewed_at}`)).toBeInTheDocument();
    expect(await screen.findByText(/сервер недоступен/)).toBeInTheDocument();
    expect(screen.getByText('Встроенная копия')).toBeInTheDocument();
    expect(screen.queryByText('Данные сервера')).not.toBeInTheDocument();
    expect(global.fetch).toHaveBeenCalledTimes(1);
  });

  test('shows a valid modified server dataset and marks its origin', async () => {
    const data = clone();
    data.dataset.reviewed_at = '2027-01-15';
    data.routes[1].nodes.find((item) => item.id === 'start').title = 'Серверный входной шаг';
    global.fetch.mockImplementation(() => Promise.resolve(okResponse(data)));
    render(<IntegrationGuide />);
    expect(await screen.findByText('Данные сервера')).toBeInTheDocument();
    expect(screen.getByText('Сверка: 2027-01-15')).toBeInTheDocument();
    expect(screen.getByRole('region', { name: 'Серверный входной шаг' })).toBeInTheDocument();
    expect(screen.queryByText('Встроенная копия')).not.toBeInTheDocument();
  });

  test('ignores a server dataset with another schema version', async () => {
    const data = clone();
    data.schema_version = '2.0';
    global.fetch.mockImplementation(() => Promise.resolve(okResponse(data)));
    render(<IntegrationGuide />);
    await waitFor(() => expect(global.fetch).toHaveBeenCalled());
    await act(async () => { await Promise.resolve(); });
    expect(screen.getByText('Встроенная копия')).toBeInTheDocument();
    expect(screen.queryByText('Данные сервера')).not.toBeInTheDocument();
  });

  test('ignores a server dataset with a dangling edge', async () => {
    const data = clone();
    data.routes[0].nodes[0].next.push({ to: 'no-such-node', label: 'Битая ссылка' });
    expect(validateDataset(data)).toBe(false);
    global.fetch.mockImplementation(() => Promise.resolve(okResponse(data)));
    render(<IntegrationGuide />);
    await waitFor(() => expect(global.fetch).toHaveBeenCalled());
    await act(async () => { await Promise.resolve(); });
    expect(screen.getByText('Встроенная копия')).toBeInTheDocument();
    expect(screen.queryByText('Битая ссылка')).not.toBeInTheDocument();
  });

  test('ignores a server dataset with an unknown source reference', async () => {
    const data = clone();
    data.routes[0].nodes[0].sources = ['noSuchSource'];
    expect(validateDataset(data)).toBe(false);
  });

  test('keeps the bundled copy on 304 and on an error status', async () => {
    global.fetch.mockImplementation(() => Promise.resolve({ ok: false, status: 304, json: () => Promise.reject(new Error('empty')) }));
    const first = render(<IntegrationGuide />);
    await waitFor(() => expect(global.fetch).toHaveBeenCalledTimes(1));
    await act(async () => { await Promise.resolve(); });
    expect(screen.getByText('Встроенная копия')).toBeInTheDocument();
    first.unmount();

    global.fetch.mockImplementation(() => Promise.resolve({ ok: false, status: 500, json: () => Promise.resolve({}) }));
    render(<IntegrationGuide />);
    await waitFor(() => expect(global.fetch).toHaveBeenCalledTimes(2));
    await act(async () => { await Promise.resolve(); });
    expect(screen.getByText('Встроенная копия')).toBeInTheDocument();
  });

  test('falls back to the entry step when the server dataset drops the selected step', async () => {
    window.history.replaceState(null, '', '#guide/epgu-vendor/no-org');
    const data = clone();
    const route = data.routes.find((item) => item.id === 'epgu-vendor');
    route.nodes = route.nodes.filter((item) => item.id !== 'no-org');
    route.nodes.forEach((item) => { item.next = item.next.filter((edge) => edge.to !== 'no-org'); });
    expect(validateDataset(data)).toBe(true);
    global.fetch.mockImplementation(() => Promise.resolve(okResponse(data)));
    render(<IntegrationGuide />);
    expect(await screen.findByText('Данные сервера')).toBeInTheDocument();
    expect(screen.getByRole('region', { name: 'Есть реальная организация?' })).toBeInTheDocument();
  });

  test('works without fetch at all', () => {
    delete global.fetch;
    render(<IntegrationGuide />);
    expect(screen.getByText('Встроенная копия')).toBeInTheDocument();
  });
});

describe('rejected server payloads', () => {
  const BAD = { unexpected: 'object' };
  const PAYLOADS = [
    ['an object in checks', (data) => { data.routes[0].nodes[0].checks[0] = BAD; }, /не соответствуют схеме/],
    ['an object as note text', (data) => { data.notes[0].text = BAD; }, /не соответствуют схеме/],
    ['an object as edge label', (data) => { data.routes[0].nodes.find((node) => node.next.length).next[0].label = BAD; }, /не соответствуют схеме/],
    ['an object as note status', (data) => { data.notes[0].status = BAD; }, /не соответствуют схеме/],
    ['an object as source title', (data) => { data.sources[0].title = BAD; }, /не соответствуют схеме/],
    ['a missing summary', (data) => { delete data.routes[0].summary; }, /не соответствуют схеме/],
    ['a non-string source reference', (data) => { data.routes[0].nodes[0].sources = [7]; }, /не соответствуют схеме/],
    ['duplicate node ids', (data) => { data.routes[0].nodes[1].id = data.routes[0].nodes[0].id; }, /битые ссылки/],
    ['another schema version', (data) => { data.schema_version = '2.0'; }, /несовместимая версия схемы/],
  ];

  test.each(PAYLOADS)('%s keeps the bundled copy, explains why and stays usable', async (_, mutate, reason) => {
    const data = clone();
    mutate(data);
    global.fetch.mockImplementation(() => Promise.resolve(okResponse(data)));
    render(<IntegrationGuide />);
    const note = await screen.findByRole('status');
    expect(note).toHaveTextContent(reason);
    expect(note).toHaveTextContent(/показана встроенная копия/);
    expect(note).not.toHaveTextContent(/сервер недоступен/);
    expect(screen.getByText('Встроенная копия')).toBeInTheDocument();
    expect(screen.queryByText('Данные сервера')).not.toBeInTheDocument();
    fireEvent.change(screen.getByRole('searchbox', { name: 'Поиск по всем маршрутам' }), { target: { value: 'X-Max-Bot-Api-Secret' } });
    fireEvent.click(within(screen.getByRole('region', { name: 'Результаты поиска' })).getByRole('button', { name: /HTTPS Webhook/ }));
    expect(screen.getByRole('region', { name: 'HTTPS Webhook и повторы' })).toBeInTheDocument();
    const vendor = FLOWS.find((item) => item.id === 'epgu-vendor');
    fireEvent.click(within(screen.getByRole('navigation', { name: 'Маршруты интеграций' })).getByRole('button', { name: vendor.title }));
    fireEvent.click(screen.getByRole('button', { name: 'Нет реальной организации' }));
    expect(window.location.hash).toBe('#guide/epgu-vendor/no-org');
  });

  test('a body that is not JSON is reported as rejected, not as an unreachable server', async () => {
    global.fetch.mockImplementation(() => Promise.resolve({ ok: true, status: 200, json: () => Promise.reject(new SyntaxError('bad')) }));
    render(<IntegrationGuide />);
    expect(await screen.findByRole('status')).toHaveTextContent(/ответ не является JSON/);
    expect(screen.getByText('Встроенная копия')).toBeInTheDocument();
  });

  test('an error status is reported with its code', async () => {
    global.fetch.mockImplementation(() => Promise.resolve({ ok: false, status: 503, json: () => Promise.resolve({}) }));
    render(<IntegrationGuide />);
    expect(await screen.findByRole('status')).toHaveTextContent(/сервер ответил ошибкой 503/);
  });

  test('a wider valid layout is shown with a computed chart width', async () => {
    const data = clone();
    const route = data.routes.find((item) => item.id === 'epgu-vendor');
    route.nodes.find((item) => item.id === 'no-org').layout = { column: 3, row: 0 };
    global.fetch.mockImplementation(() => Promise.resolve(okResponse(data)));
    render(<IntegrationGuide />);
    expect(await screen.findByText('Данные сервера')).toBeInTheDocument();
    const chart = screen.getByRole('region', { name: `Блок-схема: ${route.title}` }).firstChild;
    expect(chart.style.width).toBe('1040px');
  });
});

describe('validateDataset', () => {
  test('rejects non-objects and incomplete datasets', () => {
    expect(validateDataset(null)).toBe(false);
    expect(validateDataset('x')).toBe(false);
    expect(validateDataset({})).toBe(false);
    const noNotes = clone();
    delete noNotes.notes;
    expect(validateDataset(noNotes)).toBe(false);
    const badEntry = clone();
    badEntry.routes[0].entry_node = 'nope';
    expect(validateDataset(badEntry)).toBe(false);
  });

  test('rejects server sources with non-https links', () => {
    ['javascript:alert(1)', 'http://example.org/', 'data:text/html,x', ' https://x'].forEach((url) => {
      const data = clone();
      data.sources[0].url = url;
      expect(validateDataset(data)).toBe(false);
    });
  });
});
