import { logError, sanitizeDiagnostic } from './safeLogging';

describe('safe diagnostic logging', () => {
  const axiosError = {
    name: 'AxiosError',
    message: 'Request failed with status code 401',
    code: 'ERR_BAD_REQUEST',
    config: {
      headers: { Authorization: 'Bearer TOP-SECRET-TOKEN' },
      data: 'FORM-DATA-SECRET',
    },
    request: { body: 'REQUEST-SECRET' },
    response: {
      status: 401,
      data: { detail: 'RESPONSE-SECRET' },
      headers: { authorization: 'Bearer RESPONSE-TOKEN' },
    },
  };

  test('retains only non-sensitive scalar error metadata', () => {
    expect(sanitizeDiagnostic(axiosError)).toEqual({
      type: 'AxiosError',
      message: 'Request failed with status code 401',
      code: 'ERR_BAD_REQUEST',
      status: 401,
    });
  });

  test('never forwards Axios config, request, response, body, or bearer data', () => {
    const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    logError('Ошибка запроса', axiosError);

    const serialized = JSON.stringify(consoleSpy.mock.calls);
    expect(serialized).not.toMatch(/TOP-SECRET|FORM-DATA|REQUEST-SECRET|RESPONSE-SECRET/);
    const loggedDiagnostic = consoleSpy.mock.calls[0][1];
    expect(loggedDiagnostic).not.toHaveProperty('config');
    expect(loggedDiagnostic).not.toHaveProperty('request');
    expect(loggedDiagnostic).not.toHaveProperty('response');
    expect(consoleSpy).toHaveBeenCalledWith('Ошибка запроса', {
      type: 'AxiosError',
      message: 'Request failed with status code 401',
      code: 'ERR_BAD_REQUEST',
      status: 401,
    });
    consoleSpy.mockRestore();
  });
});
