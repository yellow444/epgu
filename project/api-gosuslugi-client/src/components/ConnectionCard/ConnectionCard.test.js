import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import fs from 'fs';
import path from 'path';
import ConnectionCard, { EXAMPLES } from './ConnectionCard';
import definition from './connection_card.v1.json';

function choose(label, option) {
  const select = screen.getByLabelText(label);
  const selectedOption = Array.from(select.options).find((item) => item.textContent === option);
  fireEvent.change(select, { target: { value: selectedOption.value } });
}

test('renders only facts selected by the chosen goal and labels them as caller reported', () => {
  render(<ConnectionCard />);
  expect(screen.getByLabelText('Цель разбора')).toHaveValue('request_power');
  definition.goals[0].facts.forEach((id) => {
    const fact = definition.facts.find((item) => item.id === id);
    expect(screen.getByLabelText(fact.title)).toBeInTheDocument();
  });
  expect(screen.queryByLabelText('Локальная проверка подписи прошла')).not.toBeInTheDocument();
  expect(screen.getByText('Основание — ваши отметки, без проверки системой.'))
    .toBeInTheDocument();
  expect(screen.getByText(/Ссылки дают контекст маршрута/)).toBeInTheDocument();
  expect(screen.getByText(/Ссылки ведут к основаниям этого шага/)).toBeInTheDocument();
  expect(screen.getAllByText(/статус: официальный/).length).toBeGreaterThan(0);
  expect(screen.getAllByText(/Дата сверки:/).length).toBeGreaterThan(0);
  expect(screen.getByRole('link', { name: 'Открыть ручную подготовку' })).toHaveAttribute('href', '#manual');
  for (const name of ['Открыть ручную подготовку', 'Открыть узел маршрута']) {
    expect(screen.getByRole('link', { name })).toHaveAttribute('target', '_blank');
    expect(screen.getByRole('link', { name })).toHaveAttribute('rel', 'noopener noreferrer');
  }
});

test('goal changes clear state and reset clears the selected facts', () => {
  render(<ConnectionCard />);
  choose('Сведения относятся одному случаю TEST', 'По моим сведениям — нет');
  expect(screen.getByText('Сведения относятся разным контекстам.')).toBeInTheDocument();

  choose('Цель разбора', 'Разобрать отказ подписи');
  expect(screen.getByLabelText('Цель разбора')).toHaveValue('check_signature');
  expect(screen.getByText('Недостаточно сведений о контексте.')).toBeInTheDocument();
  expect(screen.queryByLabelText('Заявка отправлена')).not.toBeInTheDocument();

  choose('Сведения относятся одному случаю TEST', 'По моим сведениям — нет');
  expect(screen.getByText('Сведения относятся разным контекстам.')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Сбросить отметки' }));
  expect(screen.getByText('Недостаточно сведений о контексте.')).toBeInTheDocument();
});

test('is a copy of the canonical definition and has no fetch or browser storage code', () => {
  const canonicalPath = path.resolve(__dirname, '../../../../knowledge/src/epgu_knowledge/data/connection_card.v1.json');
  const uiPath = path.join(__dirname, 'connection_card.v1.json');
  expect(fs.readFileSync(uiPath)).toEqual(fs.readFileSync(canonicalPath));
  const component = fs.readFileSync(path.join(__dirname, 'ConnectionCard.js'), 'utf8');
  const evaluator = fs.readFileSync(path.join(__dirname, 'evaluateConnectionCard.js'), 'utf8');
  expect(`${component}\n${evaluator}`).not.toMatch(/\b(fetch|localStorage|sessionStorage|indexedDB)\b/);
});

test('rendering and using the card does not call network or browser storage APIs', () => {
  const previousFetch = global.fetch;
  const fetchSpy = jest.fn();
  const xhrOpenSpy = jest.spyOn(XMLHttpRequest.prototype, 'open');
  const storageSetSpy = jest.spyOn(Storage.prototype, 'setItem');
  global.fetch = fetchSpy;
  try {
    render(<ConnectionCard />);
    choose('Сведения относятся одному случаю TEST', 'По моим сведениям — нет');
    choose('Цель разбора', 'Разобрать отказ подписи');
    choose('Локальная проверка подписи прошла', 'По моим сведениям — да');
    EXAMPLES.forEach((example) => fireEvent.click(screen.getByRole('button', { name: example.label })));
    fireEvent.click(screen.getByRole('button', { name: 'Сбросить отметки' }));

    expect(fetchSpy).not.toHaveBeenCalled();
    expect(xhrOpenSpy).not.toHaveBeenCalled();
    expect(storageSetSpy).not.toHaveBeenCalled();
  } finally {
    xhrOpenSpy.mockRestore();
    storageSetSpy.mockRestore();
    if (previousFetch === undefined) delete global.fetch;
    else global.fetch = previousFetch;
  }
});

test.each([
  ['ИС есть, заявки нет', 'request_power', 'По вашим сведениям ИС и привязка есть, заявки ещё нет.'],
  ['Сервер отклонил подпись', 'check_signature', 'Вы сообщили о сверенных условиях, но причина отказа остаётся неизвестной.'],
  ['Анкета принята, ждём ответ', 'obtain_api_key', 'Отправленная заявка не подтверждает выдачу полномочия.'],
])('synthetic example %s uses the common evaluator and is clearly labelled', (label, goal, summary) => {
  render(<ConnectionCard />);
  fireEvent.click(screen.getByRole('button', { name: label }));
  expect(screen.getByLabelText('Цель разбора')).toHaveValue(goal);
  expect(screen.getByRole('status')).toHaveTextContent(summary);
  expect(screen.getByRole('note')).toHaveTextContent('Учебный пример, а не состояние вашей ИС.');
  expect(screen.getByRole('button', { name: label })).toHaveAttribute('aria-pressed', 'true');
});

test('editing an example keeps its warning; starting your own case clears all example facts', () => {
  render(<ConnectionCard />);
  fireEvent.click(screen.getByRole('button', { name: 'ИС есть, заявки нет' }));
  choose('Заявка отправлена', 'По моим сведениям — да');
  expect(screen.getByRole('note')).toBeInTheDocument();
  expect(screen.getByRole('status')).toHaveTextContent('Вы сообщили об отправленной заявке.');
  fireEvent.click(screen.getByRole('button', { name: 'Начать свой разбор' }));
  expect(screen.queryByRole('note')).not.toBeInTheDocument();
  expect(screen.getByRole('status')).toHaveTextContent('Недостаточно сведений о контексте.');
  expect(screen.getByLabelText('Заявка отправлена')).toHaveValue('unknown');
  EXAMPLES.forEach((example) => expect(screen.getByRole('button', { name: example.label }))
    .toHaveAttribute('aria-pressed', 'false'));
});

test('jump buttons focus the named region without changing the application hash', () => {
  render(<ConnectionCard />);
  const hash = window.location.hash;
  fireEvent.click(screen.getByRole('button', { name: 'Изменить отметки' }));
  expect(screen.getByRole('region', { name: 'Ваши отметки' })).toHaveFocus();
  fireEvent.click(screen.getByRole('button', { name: 'К разбору' }));
  expect(screen.getByRole('region', { name: 'Разбор по вашим сведениям' })).toHaveFocus();
  expect(window.location.hash).toBe(hash);
});
