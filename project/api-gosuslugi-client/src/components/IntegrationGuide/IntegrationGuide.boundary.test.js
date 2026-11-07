// Последняя защита экрана: набор, который прошёл проверку, но не отрисовался,
// не роняет страницу, а возвращает встроенную копию с понятной причиной.
import React from 'react';
import { render, screen } from '@testing-library/react';
import bundled from './knowledge.v1.json';
import IntegrationGuide from './IntegrationGuide';

// jest.mock поднимается выше импортов, поэтому компонент получает подменённую проверку.
jest.mock('./knowledgeModel', () => {
  const actual = jest.requireActual('./knowledgeModel');
  return { ...actual, checkDataset: () => ({ ok: true, reason: null, errors: [], total: 0 }) };
});

let errorSpy;

beforeEach(() => {
  window.history.replaceState(null, '', '/');
  // React сообщает о пойманной ошибке рендера в console.error; здесь это ожидаемо.
  errorSpy = jest.spyOn(global.console, 'error').mockImplementation(() => {});
});

afterEach(() => {
  delete global.fetch;
  errorSpy.mockRestore();
});

test('a server dataset that fails to render falls back to the bundled copy', async () => {
  const data = JSON.parse(JSON.stringify(bundled));
  data.routes.find((item) => item.id === 'epgu-vendor').nodes[0].checks[0] = { unexpected: 'object' };
  global.fetch = jest.fn(() => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(data) }));
  render(<IntegrationGuide />);
  expect(await screen.findByRole('status')).toHaveTextContent(/данные сервера отклонены: не отображаются/);
  expect(screen.getByText('Встроенная копия')).toBeInTheDocument();
  expect(screen.getByRole('region', { name: 'Есть реальная организация?' })).toBeInTheDocument();
});
