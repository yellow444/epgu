// Запросы к методам входа. Сессия живёт в HttpOnly cookie: скрипт её не
// видит и не хранит, браузер сам отправляет её на тот же адрес.

export const BACKEND_URL = process.env.REACT_APP_BACKEND_URL || '/api';

export class AuthApiError extends Error {
  constructor(status, detail) {
    super(detail || `HTTP ${status}`);
    this.status = status;
    this.detail = detail || '';
  }
}

export async function authRequest(path, { method = 'GET', body } = {}) {
  const options = {
    method,
    credentials: 'same-origin',
    headers: { Accept: 'application/json' },
  };
  if (body !== undefined) {
    options.headers['Content-Type'] = 'application/json';
    options.body = JSON.stringify(body);
  }
  const response = await fetch(`${BACKEND_URL}${path}`, options);
  let payload = null;
  try {
    payload = await response.json();
  } catch (error) {
    payload = null;
  }
  if (!response.ok) {
    const detail = payload && typeof payload.detail === 'string' ? payload.detail : '';
    throw new AuthApiError(response.status, detail);
  }
  return payload;
}
