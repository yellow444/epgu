import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import PublicEntry, { sectionFromHash } from './PublicEntry';

test('connection card has a dedicated address and public navigation entry', () => {
  expect(sectionFromHash('#connection')).toBe('connection');
  window.history.replaceState(null, '', '#connection');
  render(<PublicEntry />);
  expect(screen.getByRole('button', { name: 'Карточка подключения TEST' })).toHaveAttribute('aria-pressed', 'true');
  expect(screen.getByRole('heading', { name: 'Карточка подключения TEST' })).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Гайд по интеграциям' }));
  expect(window.location.hash).toBe('#guide');
});
