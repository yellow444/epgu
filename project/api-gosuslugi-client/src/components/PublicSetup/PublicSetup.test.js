import React from 'react';
import { fireEvent, render, screen, within } from '@testing-library/react';
import fs from 'fs';
import path from 'path';
import PublicSetup from './PublicSetup';
import manualPath from './manual_path.v1.json';

test('shows official test and production links', () => {
  render(<PublicSetup />);

  expect(screen.getByText('TEST: «Мои системы»').closest('a')).toHaveAttribute(
    'href',
    'https://svcdev-partners.test.gosuslugi.ru/systems'
  );
  expect(screen.getByText('PROD: «Мои системы»').closest('a')).toHaveAttribute(
    'href',
    'https://partners.gosuslugi.ru/systems'
  );
});

test('keeps facts in visible editable fields without automatic capture controls', () => {
  render(<PublicSetup />);

  const field = screen.getByLabelText('Что отображается в карточке ИС');
  fireEvent.change(field, { target: { value: 'Мнемоника системы TESTEP' } });
  expect(field).toHaveValue('Мнемоника системы TESTEP');
  expect(screen.queryByText(/Скачать.*расширение/i)).not.toBeInTheDocument();
  expect(screen.queryByText(/Разобрать буфер/i)).not.toBeInTheDocument();
});

test('does not prefill a support recipient', () => {
  render(<PublicSetup />);
  expect(screen.getByLabelText('Кому')).toHaveValue('');
  expect(screen.getByText('Открыть в почтовом клиенте').closest('a')).toHaveAttribute(
    'aria-disabled',
    'true'
  );
});

// ---------- Один канон: всё на экране приходит из набора manual_path ----------

test('the interface copy is byte-identical to the canonical bundle', () => {
  const project = path.resolve(__dirname, '../../../..');
  const canonical = fs.readFileSync(path.join(project, 'knowledge/src/epgu_knowledge/data/manual_path.v1.json'));
  const copy = fs.readFileSync(path.join(__dirname, 'manual_path.v1.json'));
  expect(copy.equals(canonical)).toBe(true);
});

test('every bundle link is on the screen with its contour', () => {
  render(<PublicSetup />);
  expect(manualPath.links).toHaveLength(6);
  manualPath.links.forEach((link) => {
    const button = screen.getByText(link.label).closest('a');
    expect(button).toHaveAttribute('href', link.url);
    expect(link.label.startsWith(`${link.contour}:`)).toBe(true);
    expect(screen.getByText(link.url)).toBeInTheDocument();
  });
});

test('every bundle field is an editable input with its hint', () => {
  render(<PublicSetup />);
  expect(manualPath.fields.length).toBeGreaterThanOrEqual(9);
  manualPath.fields.forEach((field) => {
    const input = screen.getByLabelText(field.label);
    expect(input).toHaveAttribute('placeholder', field.hint);
    expect(input).toHaveValue('');
  });
  ['Название организации', 'OID организации', 'OID внешней ИС (ext-app)', 'Идентификатор карточки ИС'].forEach((label) => {
    expect(screen.getByLabelText(label)).toBeInTheDocument();
  });
});

test('the five steps say what to do, what to collect and what should come out', () => {
  render(<PublicSetup />);
  expect(manualPath.steps).toHaveLength(5);
  manualPath.steps.forEach((step) => {
    const row = screen.getByTestId(`manual-step-${step.id}`);
    expect(row).toHaveTextContent(step.title);
    expect(row).toHaveTextContent(`Действие: ${step.action}`);
    expect(row).toHaveTextContent(`Что собрать: ${step.collect}`);
    expect(row).toHaveTextContent(`Что должно получиться: ${step.result}`);
    const kinds = manualPath.links.filter((link) => step.link_kinds.includes(link.kind));
    const anchors = within(row).queryAllByRole('link');
    expect(anchors.map((a) => a.getAttribute('href')).sort()).toEqual(kinds.map((link) => link.url).sort());
    anchors.forEach((a) => expect(a.textContent).toMatch(/^(TEST|PROD)$/));
  });
});

test('the letter starts from the unfilled template and has no recipient', () => {
  render(<PublicSetup />);
  expect(screen.getByLabelText('Текст письма')).toHaveValue(manualPath.letter_template.body);
  expect(manualPath.letter_template.body).toContain('Контур: <TEST или PROD, заполните вручную>');
  expect(screen.getByLabelText('Кому')).toHaveValue('');
  expect(screen.getByLabelText('Копия')).toHaveValue('');
  expect(screen.getByLabelText('Тема')).toHaveValue('');
});

test('both warnings from the bundle are on the screen', () => {
  render(<PublicSetup />);
  expect(screen.getByText(manualPath.warnings[0])).toBeInTheDocument();
  expect(screen.getByText(new RegExp(manualPath.warnings[1]))).toBeInTheDocument();
});

test('shows that the external links were not checked and explains how to choose the contour', () => {
  render(<PublicSetup />);
  expect(screen.getByText(manualPath.provenance.note)).toBeInTheDocument();
  expect(screen.getByTestId('manual-step-organization')).toHaveTextContent(
    'Выберите TEST или PROD по подписи ссылки ниже.'
  );
});

test('values stay local: no network and nothing stored', () => {
  global.fetch = jest.fn();
  try {
    render(<PublicSetup />);
    fireEvent.change(screen.getByLabelText('OID организации'), { target: { value: 'VALUE_MARKER' } });
    expect(global.fetch).not.toHaveBeenCalled();
    expect(JSON.stringify({ ...localStorage, ...sessionStorage })).not.toContain('VALUE_MARKER');
  } finally {
    delete global.fetch;
  }
});

test('the component keeps no own copy of the links, fields or template', () => {
  const source = fs.readFileSync(path.join(__dirname, 'PublicSetup.js'), 'utf8');
  manualPath.links.forEach((link) => expect(source).not.toContain(link.url));
  manualPath.fields.forEach((field) => expect(source).not.toContain(field.label));
  expect(source).not.toContain('Здравствуйте!');
});
