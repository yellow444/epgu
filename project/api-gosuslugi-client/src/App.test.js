import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';

// Мокаем axios, чтобы методы get и post всегда возвращали промисы с фиктивными данными
jest.mock('axios');

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
jest.mock('jwt-decode', () => ({
  jwtDecode: jest.fn(() => ({ exp: Date.now() / 1000 + 3600 })),
}));

// Мокаем компонент FileDropzone - его внутренности не важны для простых тестов
jest.mock('./components/FileDropzone/FileDropzone', () => {
  return function DummyFileDropzone() {
    return <div data-testid="file-dropzone">FileDropzone</div>;
  };
});

// Для файловых диалогов - если они используются (например, при сохранении XML) можно добавить заглушку:
global.showSaveFilePicker = jest.fn().mockResolvedValue({
  createWritable: jest.fn().mockResolvedValue({
    write: jest.fn(),
    close: jest.fn(),
  }),
});

import axios from 'axios';
import App from './App';

beforeEach(() => {
  jest.clearAllMocks();
  localStorage.clear();
  sessionStorage.clear();
  axios.get.mockResolvedValue({ data: [] });
  axios.post.mockResolvedValue({ data: {} });
  axios.create.mockReturnValue({
    get: axios.get,
    post: axios.post,
  });
});

describe('App Component Basic Rendering Tests', () => {
  test('renders main heading and tab buttons', () => {
    render(<App />);
    expect(screen.getByText('API Client')).toBeInTheDocument();
    expect(screen.getByText('Главная')).toBeInTheDocument();
    expect(screen.getByText('Настройка')).toBeInTheDocument();
    expect(screen.getByText('Редактор XML')).toBeInTheDocument();
    expect(screen.getByText('Запросы')).toBeInTheDocument();
    expect(screen.getByLabelText('API key')).toHaveAttribute('type', 'password');
    expect(screen.getByLabelText('API key')).toHaveAttribute('autocomplete', 'off');
  });

  test('switches to Setup tab on click', () => {
    render(<App />);
    fireEvent.click(screen.getByText('Настройка'));
    expect(screen.getByText('Ручная настройка подключения')).toBeInTheDocument();
    expect(screen.getByText('Фактические данные — заполните вручную')).toBeInTheDocument();
    expect(screen.queryByText(/Мастер настройки/)).not.toBeInTheDocument();
  });

  test('shows a back to top control only after the page is scrolled', async () => {
    render(<App />);
    expect(screen.queryByLabelText('Наверх')).not.toBeInTheDocument();

    Object.defineProperty(window, 'pageYOffset', {
      value: 600,
      writable: true,
      configurable: true,
    });
    fireEvent.scroll(window);

    expect(await screen.findByLabelText('Наверх')).toBeInTheDocument();
  });

  test('switches to Inbound tab and shows the registration addresses', async () => {
    render(<App />);
    fireEvent.click(screen.getByText('Входящие'));

    expect(await screen.findByText('Адреса для регистрации ИС')).toBeInTheDocument();
    expect(screen.getByText('Входящие запросы')).toBeInTheDocument();
    await waitFor(() =>
      expect(axios.get).toHaveBeenCalledWith('/inbound/messages', {
        params: { limit: 100 },
      })
    );
  });

  test('shows Gospochta tab with quota, warning and stored notifications', async () => {
    const scheduler = {
      running: true,
      enabled: false,
      interval_seconds: 900,
      target_range: {
        startDateTime: '2026-08-16T00:00:00.000+03:00',
        endDateTime: '2026-08-17T00:00:00.000+03:00',
      },
      last_report: {},
      last_skip: '',
      quota: {
        date: '2026-08-17',
        limits: {
          search: { limit: 5, used: 1, remaining: 4 },
          result: { limit: 15, used: 2, remaining: 13 },
        },
      },
      counts: { messages: 1, unread: 1, attachments_saved: 0 },
    };
    const stored = {
      messages: [
        {
          message_uuid: '91160bbb-f997-11ef-8080-808080808080',
          thread_uuid: '6c7a5efd-2a8c-11f0-8080-808080808080',
          sender: 'ФССП',
          subject: 'Извещение о возбуждении',
          is_read: false,
          create_date: '2026-08-16T10:20:00+03:00',
          attachments: [{ attachment_uuid: 'a1', file_name: 'postanovlenie.pdf' }],
        },
      ],
      total: 1,
      offset: 0,
      limit: 10,
      counts: scheduler.counts,
    };
    axios.get.mockImplementation((url) => {
      if (url === '/geps/scheduler') return Promise.resolve({ data: scheduler });
      if (url === '/geps/jobs') return Promise.resolve({ data: { jobs: [] } });
      if (url === '/geps/messages') return Promise.resolve({ data: stored });
      return Promise.resolve({ data: [] });
    });

    render(<App />);
    fireEvent.click(screen.getByText('Госпочта'));

    expect(await screen.findByText('Чтение Госпочты запускает сроки')).toBeInTheDocument();
    // Остаток суточных попыток виден до любого обращения к ЕПГУ.
    expect(await screen.findByText('4 из 5')).toBeInTheDocument();
    expect(screen.getByText('13 из 15')).toBeInTheDocument();
    expect(await screen.findByText('Извещение о возбуждении')).toBeInTheDocument();

    await waitFor(() =>
      expect(axios.get).toHaveBeenCalledWith('/geps/messages', {
        params: { offset: 0, limit: 10, only_unread: false },
      })
    );
  }, 20000);

  test('Gospochta asks before touching the mailbox', async () => {
    axios.get.mockImplementation((url) => {
      if (url === '/geps/scheduler') {
        return Promise.resolve({
          data: { running: true, enabled: false, quota: { limits: {} }, counts: {} },
        });
      }
      if (url === '/geps/messages') {
        return Promise.resolve({ data: { messages: [], total: 0, offset: 0, counts: {} } });
      }
      return Promise.resolve({ data: { jobs: [] } });
    });

    render(<App />);
    fireEvent.click(screen.getByText('Госпочта'));

    fireEvent.click(await screen.findByText('Забрать сейчас'));

    // Забор почты - осознанное действие: сначала предупреждение о сроках.
    // antd показывает заголовок диалога в нескольких узлах, хватит любого.
    expect((await screen.findAllByText('Забрать почту сейчас?')).length).toBeGreaterThan(0);
    expect(axios.post).not.toHaveBeenCalledWith('/geps/scheduler/run');
  }, 20000);

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

  test('reserves an order relative to the configured axios base URL', async () => {
    const service = {
      serviceCode: '60010153',
      title: 'ФССП',
      protocol: 'gusmev-order',
      status: 'verified',
      available: true,
      targetCode: '10001505301',
      eServiceCode: '60010153',
      serviceTargetCode: '-60010153',
      submission: { mode: 'chunked', documents: [] },
      spec: { version: 'v1.14' },
    };
    axios.get.mockImplementation((url) =>
      Promise.resolve({ data: url.endsWith('/services') ? [service] : [] })
    );
    axios.post.mockResolvedValue({ data: { orderId: 42 } });

    render(<App />);

    const reserveButton = await screen.findByRole('button', {
      name: /Зарезервировать/,
    });
    expect(reserveButton).toBeDisabled();
    fireEvent.change(screen.getByRole('textbox', { name: 'Регион ОКАТО пользователя' }), {
      target: { value: '45000000000' },
    });
    expect(reserveButton).toBeEnabled();
    fireEvent.click(reserveButton);

    await waitFor(() =>
      expect(axios.post).toHaveBeenCalledWith(
        '/order',
        expect.objectContaining({
          region: '45000000000',
          serviceCode: '60010153',
        }),
        expect.any(Object)
      )
    );
  }, 20000);

  test('does not select a signing certificate implicitly', async () => {
    const certificate = {
      id: 'AA BB CC',
      subject: 'Иванов Иван',
      common_name: 'Иван Иванов',
      organization: 'ООО Ромашка',
      valid_from: '2026-01-01',
      valid_to: '2027-01-01',
      selected: false,
    };
    axios.post.mockImplementation((url) =>
      Promise.resolve({ data: url === '/get_certificates' ? [certificate] : {} })
    );

    render(<App />);
    const apiKey = screen.getByLabelText('API key');
    fireEvent.change(apiKey, { target: { value: 'operator-secret' } });

    await waitFor(() =>
      expect(axios.post).toHaveBeenCalledWith('/get_certificates')
    );
    expect(screen.getByRole('button', { name: /Получить токен/ })).toBeDisabled();
    expect(screen.queryByTestId('selected-certificate-details')).not.toBeInTheDocument();
    expect(axios.post).not.toHaveBeenCalledWith(
      '/set_current_certificate',
      expect.anything(),
      expect.anything()
    );
  });

  test('selects a certificate explicitly and renders its identity and validity', async () => {
    sessionStorage.setItem('token', 'session-token');
    const certificate = {
      id: 'AA BB CC',
      subject: 'Иванов Иван',
      common_name: 'Иван Иванов',
      organization: 'ООО Ромашка',
      valid_from: '2026-01-01',
      valid_to: '2027-01-01',
      selected: false,
    };
    axios.post.mockImplementation((url) =>
      Promise.resolve({ data: url === '/get_certificates' ? [certificate] : {} })
    );

    render(<App />);
    expect(screen.queryByText('session-token')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Показать токен' }));
    expect(screen.getByText('session-token')).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('API key'), {
      target: { value: 'operator-secret' },
    });
    await waitFor(() =>
      expect(axios.post).toHaveBeenCalledWith('/get_certificates')
    );
    const certificateInput = screen.getByLabelText('Сертификат подписи');
    fireEvent.keyDown(certificateInput, { key: 'Enter', code: 'Enter' });
    const certificateLabels = await screen.findAllByText(
      /Иван Иванов - ООО Ромашка/
    );
    fireEvent.click(
      certificateLabels.find((element) =>
        element.classList.contains('ant-select-item-option-content')
      ) || certificateLabels[certificateLabels.length - 1]
    );

    await waitFor(() =>
      expect(axios.post).toHaveBeenCalledWith(
        '/set_current_certificate',
        null,
        { params: { cert_id: 'AA BB CC' } }
      )
    );
    expect(await screen.findByTestId('selected-certificate-details')).toHaveTextContent(
      '2026-01-01 - 2027-01-01'
    );
    expect(sessionStorage.getItem('token')).toBeNull();
    expect(screen.queryByText('session-token')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Получить токен/ })).toBeEnabled();
  }, 20000);

  test('clears the server session before removing local credentials', async () => {
    sessionStorage.setItem('token', 'session-token');
    render(<App />);
    fireEvent.change(screen.getByLabelText('API key'), {
      target: { value: 'operator-secret' },
    });
    // По тексту, а не по роли: дерево большое, и разбор ролей в jsdom очень долгий.
    fireEvent.click(screen.getByText('Удалить токен'));

    await waitFor(() => expect(axios.post).toHaveBeenCalledWith('/session/clear'));
    expect(sessionStorage.getItem('token')).toBeNull();
    expect(screen.getByLabelText('API key')).toHaveValue('');
  });

  // Тест проходит два круга удаления и ждёт всплывающие сообщения antd,
  // поэтому пяти секунд по умолчанию ему не хватает.
  test('warns when local purge succeeds but server session clearing fails', async () => {
    sessionStorage.setItem('token', 'session-token');
    axios.post.mockImplementation((url) =>
      url === '/session/clear'
        ? Promise.reject(new Error('backend unavailable'))
        : Promise.resolve({ data: {} })
    );

    render(<App />);
    fireEvent.change(screen.getByLabelText('API key'), {
      target: { value: 'operator-secret' },
    });
    // По тексту, а не по роли: дерево большое, и разбор ролей в jsdom очень долгий.
    fireEvent.click(screen.getByText('Удалить токен'));

    expect(
      await screen.findByText(/server-side токен\/сертификат могли сохраниться/)
    ).toBeInTheDocument();
    expect(sessionStorage.getItem('token')).toBeNull();
    expect(screen.getByLabelText('API key')).toHaveValue('');

    fireEvent.click(screen.getByText('Удалить все локальные данные и сессию'));
    expect(
      await screen.findByText(/Локальные данные удалены, но server-side/)
    ).toBeInTheDocument();
  }, 20000);

  test('uses the official no-body contract for details, download lookup, and cancel', async () => {
    const service = {
      serviceCode: '60010153',
      title: 'ФССП',
      protocol: 'gusmev-order',
      status: 'verified',
      available: true,
      targetCode: '10001505301',
      eServiceCode: '60010153',
      serviceTargetCode: '-60010153',
      submission: { mode: 'chunked', documents: [] },
      spec: { version: 'v1.14' },
    };
    axios.get.mockImplementation((url) =>
      Promise.resolve({ data: url.endsWith('/services') ? [service] : [] })
    );
    let detailsCalls = 0;
    axios.post.mockImplementation((url) => {
      if (url === '/order/9007199254740993') {
        detailsCalls += 1;
        return Promise.resolve({
          data: {
            message: 'ok',
            orderDetails: {},
            fileDetails: detailsCalls === 1 ? [{}] : [],
          },
        });
      }
      if (url === '/order/9007199254740993/cancel') {
        return Promise.resolve({ data: { message: 'cancelled', orderDetails: {} } });
      }
      return Promise.resolve({ data: {} });
    });

    render(<App />);
    const orderId = await screen.findByRole('textbox', { name: 'Order ID запроса' });
    fireEvent.change(orderId, { target: { value: '123/cancel' } });
    expect(screen.getByRole('button', { name: /Проверить статус/ })).toBeDisabled();
    expect(screen.getByRole('button', { name: /Отменить$/ })).toBeDisabled();
    expect(axios.post).not.toHaveBeenCalledWith(
      '/order/123/cancel',
      expect.anything(),
      expect.anything()
    );

    fireEvent.change(orderId, { target: { value: '9007199254740993' } });
    fireEvent.click(screen.getByRole('button', { name: /Проверить статус/ }));
    const download = screen.getByRole('button', { name: /Скачать файл ответа/ });
    await waitFor(() => expect(download).toBeEnabled());
    fireEvent.click(download);
    fireEvent.click(screen.getByRole('button', { name: /Отменить$/ }));

    await waitFor(() => expect(detailsCalls).toBe(2));
    const detailRequests = axios.post.mock.calls.filter(
      ([url]) => url === '/order/9007199254740993'
    );
    expect(detailRequests).toHaveLength(2);
    detailRequests.forEach((request) => expect(request[1]).toBeNull());
    expect(axios.post).toHaveBeenCalledWith(
      '/order/9007199254740993/cancel',
      null,
      expect.any(Object)
    );
  }, 60000);
});
