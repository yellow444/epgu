// Список источников под шагом и заметкой гайда на синтетических данных.
// Модель с плохими значениями собирается в обход проверки набора: компонент
// не должен полагаться только на неё.
import React from 'react';
import { render, screen, within } from '@testing-library/react';
import IntegrationGuide, { checkedAtLabel, safeHttpsUrl, SourceLinks } from './IntegrationGuide';
import bundled from './knowledge.v1.json';

const SOURCES = {
  synthA: { title: 'Синтетический регламент А', url: 'https://example.invalid/a', kind: 'Регламент',
    section: 'Раздел 1', officiality: 'official', checkedAt: '2026-11-03' },
  synthB: { title: 'Синтетическая памятка Б', url: 'javascript:alert(1)', kind: 'Памятка',
    section: 'Раздел 2', officiality: 'developer_experience', checkedAt: '2026-02-30' },
  synthC: { title: 'Синтетический источник В', url: 'http://example.invalid/c', kind: 'Статья',
    section: 'Раздел 3', officiality: 'something_new' },
};

const renderList = (ids) => render(<SourceLinks ids={ids} sources={SOURCES} />);

test('a valid source is a safe link with its status and check date', () => {
  renderList(['synthA']);
  const link = screen.getByRole('link', { name: 'Синтетический регламент А' });
  expect(link).toHaveAttribute('href', 'https://example.invalid/a');
  expect(link).toHaveAttribute('rel', 'noopener noreferrer');
  expect(link).toHaveAttribute('target', '_blank');
  const item = link.closest('li');
  expect(within(item).getByText('статус: официальный')).toBeInTheDocument();
  expect(within(item).getByText('Дата сверки: 03.11.2026')).toBeInTheDocument();
  expect(screen.getByText(/не подтверждают сами по себе каждое утверждение/)).toBeInTheDocument();
});

test('an empty list says so instead of rendering nothing', () => {
  const { container } = renderList([]);
  expect(screen.getByText('Источники не указаны.')).toBeInTheDocument();
  expect(container.querySelector('ul')).toBeNull();
});

test('a non-https or script url is shown as plain text, not as a link', () => {
  renderList(['synthB', 'synthC']);
  expect(screen.queryAllByRole('link')).toHaveLength(0);
  expect(screen.getByText('Синтетическая памятка Б')).toBeInTheDocument();
  expect(screen.getByText('Синтетический источник В')).toBeInTheDocument();
});

test('an impossible or missing date is labelled honestly, unknown status too', () => {
  renderList(['synthB', 'synthC']);
  expect(screen.getAllByText('Дата сверки не указана')).toHaveLength(2);
  expect(screen.queryByText(/Invalid Date|NaN/)).toBeNull();
  expect(screen.getByText('статус: опыт разработчиков')).toBeInTheDocument();
  expect(screen.getByText('статус не указан')).toBeInTheDocument();
});

test('an unknown source id does not crash and does not become a link', () => {
  renderList(['synthGhost', 'synthA']);
  expect(screen.getByText('Источник synthGhost не найден в наборе.')).toBeInTheDocument();
  expect(screen.getAllByRole('link')).toHaveLength(1);
});

test.each(['__proto__', 'constructor', 'toString', 'hasOwnProperty'])(
  'inherited key %s as a source id is reported as not found, not rendered',
  (id) => {
    renderList([id]);
    expect(screen.getByText(`Источник ${id} не найден в наборе.`)).toBeInTheDocument();
    expect(screen.queryAllByRole('link')).toHaveLength(0);
  },
);

test.each(['__proto__', 'constructor', 'toString', 'valueOf'])(
  'inherited key %s as officiality falls back to an unknown status',
  (officiality) => {
    render(<SourceLinks ids={['synthA']} sources={{ synthA: { ...SOURCES.synthA, officiality } }} />);
    expect(screen.getByText('статус не указан')).toBeInTheDocument();
  },
);

test('a source really stored under its own key "constructor" is rendered normally', () => {
  const sources = JSON.parse('{"constructor": {"title": "Синтетический источник Г", "url": "https://example.invalid/g", '
    + '"kind": "Регламент", "section": "Раздел 4", "officiality": "operator_docs", "checkedAt": "2026-11-05"}}');
  render(<SourceLinks ids={['constructor']} sources={sources} />);
  expect(screen.getByRole('link', { name: 'Синтетический источник Г' })).toHaveAttribute('href', 'https://example.invalid/g');
  expect(screen.getByText('статус: документация оператора')).toBeInTheDocument();
  expect(screen.queryByText(/не найден в наборе/)).toBeNull();
});

test('url and date helpers reject what the schema would reject', () => {
  ['https://example.invalid/x', 'https://example.invalid/путь?q=1'].forEach((url) => expect(safeHttpsUrl(url)).toBe(url));
  [' https://example.invalid/x', 'https://', 'http://example.invalid', 'data:text/html,x', null, 42]
    .forEach((url) => expect(safeHttpsUrl(url)).toBeNull());
  expect(checkedAtLabel('2024-02-29')).toBe('Дата сверки: 29.02.2024');
  ['2023-02-29', '2026-13-01', '2026-1-01', '', undefined].forEach((value) => (
    expect(checkedAtLabel(value)).toBe('Дата сверки не указана')));
});

test('every bundled source shows a real check date and a known status', () => {
  window.history.replaceState(null, '', '/');
  global.fetch = jest.fn(() => new Promise(() => {}));
  try {
    render(<IntegrationGuide />);
    const detail = screen.getByRole('region', { name: 'Есть реальная организация?' });
    expect(within(detail).getAllByText(/^Дата сверки: \d{2}\.\d{2}\.\d{4}$/).length).toBeGreaterThan(0);
    expect(within(detail).queryByText('статус не указан')).toBeNull();
    bundled.sources.forEach((source) => expect(checkedAtLabel(source.checked_at)).toMatch(/^Дата сверки: /));
  } finally {
    delete global.fetch;
  }
});
