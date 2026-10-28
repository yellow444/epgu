import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import PublicSetup from './PublicSetup';

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
