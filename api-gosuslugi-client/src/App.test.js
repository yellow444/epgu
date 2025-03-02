import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import App from './App';

// Мокаем axios, чтобы методы get и post всегда возвращали промисы с фиктивными данными
jest.mock('axios');

import axios from 'axios';

beforeEach(() => {
  jest.clearAllMocks();
  axios.get.mockResolvedValue({ data: [] });
  axios.post.mockResolvedValue({ data: {} });
});
// Мокаем idb для IndexedDB (возвращаем простые реализации)
jest.mock('idb', () => ({
  openDB: jest.fn(() =>
    Promise.resolve({
      transaction: jest.fn(() => ({
        store: { put: jest.fn() },
        done: Promise.resolve(),
      })),
      getAll: jest.fn(() => Promise.resolve([])),
    })
  ),
}));

// Мокаем jwt-decode, возвращая токен с длительным сроком действия
jest.mock('jwt-decode', () =>
  jest.fn(() => ({ exp: Date.now() / 1000 + 3600 }))
);

// Мокаем компонент FileDropzone – его внутренности не важны для простых тестов
jest.mock('./components/FileDropzone/FileDropzone', () => {
  return function DummyFileDropzone() {
    return <div data-testid="file-dropzone">FileDropzone</div>;
  };
});

// Для файловых диалогов – если они используются (например, при сохранении XML) можно добавить заглушку:
global.showSaveFilePicker = jest.fn().mockResolvedValue({
  createWritable: jest.fn().mockResolvedValue({
    write: jest.fn(),
    close: jest.fn(),
  }),
});

describe('App Component Basic Rendering Tests', () => {
  test('renders main heading and tab buttons', () => {
    render(<App />);
    expect(screen.getByText('API Client')).toBeInTheDocument();
    expect(screen.getByText('Главная')).toBeInTheDocument();
    expect(screen.getByText('Редактор XML')).toBeInTheDocument();
    expect(screen.getByText('Запросы')).toBeInTheDocument();
  });

  test('switches to XML tab on click', () => {
    render(<App />);
    fireEvent.click(screen.getByText('Редактор XML'));
    // Вкладка "Редактор XML" должна содержать элемент "Список XML"
    expect(screen.getByText('Список XML')).toBeInTheDocument();
  });

  test('switches to Requests tab on click', () => {
    render(<App />);
    fireEvent.click(screen.getByText('Запросы'));
    // Вкладка "Запросы" должна содержать кнопку для получения запросов
    expect(screen.getByText('Получить все запросы')).toBeInTheDocument();
  });
});
