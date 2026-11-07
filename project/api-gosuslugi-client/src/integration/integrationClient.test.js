import {
  Conflict,
  Forbidden,
  IntegrationConfigError,
  InvalidRequest,
  OutcomeUnknown,
  PlanExpired,
  PlanNotFound,
  ServiceUnavailable,
  TransportError,
  Unauthenticated,
  UnexpectedResponse,
  createIntegrationClient,
} from './integrationClient';

const BASE = 'https://backend.test/api';
const SECRET = `epgu_ik_${'S'.repeat(40)}`;
const PLAN_ID = `plan_${'a'.repeat(32)}`;
const HASH = 'b'.repeat(64);
const PLAN = {
  plan_id: PLAN_ID, plan_hash: HASH, status: 'planned', expires_at: '2026-11-02T10:00:00Z',
  preview: { capability_id: 'svc.send' }, result: null, error_code: null, steps: [],
};

const reply = (status, body, contentType = 'application/json', type = 'basic') => ({
  status,
  type,
  ok: status >= 200 && status < 300,
  headers: { get: (name) => (name.toLowerCase() === 'content-type' ? contentType : null) },
  json: async () => (typeof body === 'string' ? JSON.parse(body) : body),
});

const problem = (status, code, extra = {}) => reply(status, {
  type: `https://epgu.local/problems/${code}`, title: 'заголовок', status, code,
  detail: 'текст', ...extra,
}, 'application/problem+json');

const setup = (...responses) => {
  const calls = [];
  const fetchImpl = jest.fn(async (url, options) => {
    calls.push({ url, options });
    const next = responses.shift();
    if (next instanceof Error) throw next;
    return next;
  });
  const api = createIntegrationClient({ baseUrl: BASE, credential: SECRET, fetchImpl });
  return { api, calls, fetchImpl };
};

describe('запрос', () => {
  test('prepare: точный запрос, Bearer, без cookie и кеша', async () => {
    const { api, calls } = setup(reply(201, PLAN), reply(200, PLAN));
    const payload = new Uint8Array([0, 255, 100]);
    const plan = await api.preparePlan({
      capabilityId: 'svc.send', target: 'target-1', payload, idempotencyKey: 'idem-0001',
      attachments: [{ name: 'a.bin', content: new Uint8Array([1, 2]) }],
    });
    expect(plan.created).toBe(true);
    expect(plan.planId).toBe(PLAN_ID);
    const { url, options } = calls[0];
    expect(url).toBe(`${BASE}/v1/operations/plans`);
    expect(options.method).toBe('POST');
    expect(options.headers.Authorization).toBe(`Bearer ${SECRET}`);
    expect(options.credentials).toBe('omit');
    expect(options.redirect).toBe('manual');
    expect(options.cache).toBe('no-store');
    expect(Object.keys(options.headers).map((k) => k.toLowerCase())).not.toContain('cookie');
    expect(JSON.parse(options.body)).toEqual({
      capability_id: 'svc.send', target: 'target-1', payload_b64: 'AP9k',
      attachments: [{ name: 'a.bin', content_b64: 'AQI=' }], idempotency_key: 'idem-0001',
    });
    const again = await api.preparePlan({
      capabilityId: 'svc.send', target: 'target-1', payload, idempotencyKey: 'idem-0001',
      attachments: [{ name: 'a.bin', content: new Uint8Array([1, 2]) }],
    });
    expect(again.created).toBe(false);
    expect(calls[1].options.body).toBe(calls[0].options.body);
  });

  test('get и execute: фиксированные пути, ключа нет в URL', async () => {
    const { api, calls } = setup(
      reply(200, { ...PLAN, status: 'approved' }),
      reply(200, { plan_id: PLAN_ID, status: 'succeeded', result: { n: 1 } }),
    );
    expect((await api.getPlan(PLAN_ID)).status).toBe('approved');
    expect(await api.executePlan(PLAN_ID, HASH))
      .toEqual({ planId: PLAN_ID, status: 'succeeded', result: { n: 1 } });
    expect(calls.map((c) => [c.options.method, c.url])).toEqual([
      ['GET', `${BASE}/v1/operations/plans/${PLAN_ID}`],
      ['POST', `${BASE}/v1/operations/plans/${PLAN_ID}/execute`],
    ]);
    expect(JSON.parse(calls[1].options.body)).toEqual({ plan_hash: HASH });
    calls.forEach((c) => expect(c.url).not.toContain(SECRET));
  });

  test('нет approve и admin; ключа нет в свойствах и JSON', () => {
    const { api } = setup();
    expect(Object.keys(api).sort()).toEqual(['baseUrl', 'executePlan', 'getPlan', 'preparePlan']);
    expect(JSON.stringify(api)).not.toContain(SECRET);
    expect(Object.isFrozen(api)).toBe(true);
  });

  test('ключ не пишется в хранилище и журнал', async () => {
    const setItem = jest.spyOn(Storage.prototype, 'setItem');
    const logs = ['log', 'info', 'warn', 'error', 'debug'].map((m) => jest.spyOn(console, m));
    const { api } = setup(reply(200, PLAN), problem(403, 'forbidden'));
    await api.getPlan(PLAN_ID);
    await expect(api.getPlan(PLAN_ID)).rejects.toBeInstanceOf(Forbidden);
    expect(setItem).not.toHaveBeenCalled();
    logs.forEach((spy) => expect(spy).not.toHaveBeenCalled());
    setItem.mockRestore();
    logs.forEach((spy) => spy.mockRestore());
  });
});

describe('настройка', () => {
  test.each([
    'http://backend.test/api', 'ftp://backend.test', 'backend.test/api', '',
    'https://user:pw@backend.test', 'https://backend.test/api?x=1', 'https://backend.test/#f',
  ])('baseUrl %s отклоняется', (baseUrl) => {
    expect(() => createIntegrationClient({ baseUrl, credential: SECRET }))
      .toThrow(IntegrationConfigError);
  });

  test('http только по явному флагу разработки', () => {
    const api = createIntegrationClient({
      baseUrl: 'http://127.0.0.1:8000', credential: SECRET, allowInsecureHttp: true,
      fetchImpl: jest.fn(),
    });
    expect(api.baseUrl).toBe('http://127.0.0.1:8000');
  });

  test.each(['', 'short', 'with space'.repeat(4), `${SECRET}\r\nX: y`, undefined])(
    'плохой ключ отклоняется без эха', (credential) => {
      let error;
      try {
        createIntegrationClient({ baseUrl: BASE, credential });
      } catch (caught) {
        error = caught;
      }
      expect(error).toBeInstanceOf(IntegrationConfigError);
      if (credential) expect(error.message).not.toContain(credential);
    },
  );

  test.each(['plan_x', '../admin', `plan_${'A'.repeat(32)}`, `${PLAN_ID}/`])(
    'planId %s проверяется до запроса', async (planId) => {
      const { api, fetchImpl } = setup();
      await expect(api.getPlan(planId)).rejects.toBeInstanceOf(IntegrationConfigError);
      await expect(api.executePlan(planId, HASH)).rejects.toBeInstanceOf(IntegrationConfigError);
      expect(fetchImpl).not.toHaveBeenCalled();
    },
  );
});

describe('ошибки problem+json', () => {
  test.each([
    [400, 'invalid_parameter', InvalidRequest],
    [401, 'unauthenticated', Unauthenticated],
    [403, 'forbidden', Forbidden],
    [404, 'plan_not_found', PlanNotFound],
    [409, 'policy_changed', Conflict],
    [410, 'plan_expired', PlanExpired],
    [422, 'invalid_parameter', InvalidRequest],
    [503, 'executor_unavailable', ServiceUnavailable],
  ])('%i %s отдельным типом', async (status, code, Kind) => {
    const { api } = setup(problem(status, code), problem(status, code));
    const error = await api.getPlan(PLAN_ID).catch((e) => e);
    expect(error).toBeInstanceOf(Kind);
    expect([error.status, error.code]).toEqual([status, code]);
    await expect(api.executePlan(PLAN_ID, HASH)).rejects.toBeInstanceOf(Kind);
  });

  test('ключ в ответе сервера вымарывается', async () => {
    const { api } = setup(problem(403, 'forbidden', { detail: `ключ ${SECRET} не подходит` }));
    const error = await api.getPlan(PLAN_ID).catch((e) => e);
    expect(error.message).not.toContain(SECRET);
    expect(error.detail).not.toContain(SECRET);
  });

  test('ошибка без problem+json не по контракту', async () => {
    const { api } = setup(reply(403, '<html>', 'text/html'));
    await expect(api.getPlan(PLAN_ID)).rejects.toBeInstanceOf(UnexpectedResponse);
  });
});

describe('неизвестный исход', () => {
  test('502 с outcome отдаёт списки сервера', async () => {
    const outcome = { plan_id: PLAN_ID, completed_calls: ['reserve_number'],
      uncertain_calls: ['send'] };
    const { api, fetchImpl } = setup(problem(502, 'outcome_unknown', { outcome }));
    const error = await api.executePlan(PLAN_ID, HASH).catch((e) => e);
    expect(error).toBeInstanceOf(OutcomeUnknown);
    expect(error.partialKnown).toBe(true);
    expect(error.completedCalls).toEqual(['reserve_number']);
    expect(error.uncertainCalls).toEqual(['send']);
    expect([error.planId, error.status]).toEqual([PLAN_ID, 502]);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  test.each([
    [{}],
    [{ outcome: { plan_id: `plan_${'c'.repeat(32)}`, completed_calls: [], uncertain_calls: [] } }],
    [{ outcome: { plan_id: PLAN_ID, completed_calls: 'reserve', uncertain_calls: [] } }],
  ])('502 без годного outcome: не пустые списки, а неизвестно', async (extra) => {
    const { api } = setup(problem(502, 'outcome_unknown',
      { detail: 'точно выполнены: reserve_number', ...extra }));
    const error = await api.executePlan(PLAN_ID, HASH).catch((e) => e);
    expect(error).toBeInstanceOf(OutcomeUnknown);
    expect(error.completedCalls).toBeNull();
    expect(error.uncertainCalls).toBeNull();
    expect(error.partialKnown).toBe(false);
  });

  test('обрыв execute: неизвестно и без повтора', async () => {
    const { api, fetchImpl } = setup(new TypeError('Failed to fetch'));
    const error = await api.executePlan(PLAN_ID, HASH).catch((e) => e);
    expect(error).toBeInstanceOf(OutcomeUnknown);
    expect(error.status).toBeNull();
    expect(error.completedCalls).toBeNull();
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  test('таймаут execute: неизвестно и без повтора', async () => {
    const fetchImpl = jest.fn((url, options) => new Promise((resolve, reject) => {
      options.signal.addEventListener('abort', () => reject(new Error('aborted')));
    }));
    const api = createIntegrationClient({
      baseUrl: BASE, credential: SECRET, fetchImpl, timeoutMs: 5 });
    await expect(api.executePlan(PLAN_ID, HASH)).rejects.toBeInstanceOf(OutcomeUnknown);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  test.each([
    [reply(500, 'internal', 'text/plain')],
    [reply(504, 'gateway', 'text/plain')],
    [reply(503, '<html>', 'text/html')],
    [reply(200, 'not json', 'text/plain')],
    [reply(401, 'proxy', 'text/plain')],
    [reply(0, null, '', 'opaqueredirect')],
  ])('ответ execute вне контракта: неизвестно', async (response) => {
    const { api, fetchImpl } = setup(response);
    const error = await api.executePlan(PLAN_ID, HASH).catch((e) => e);
    expect(error).toBeInstanceOf(OutcomeUnknown);
    expect(error.completedCalls).toBeNull();
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  test('обрыв prepare: ошибка транспорта без повтора', async () => {
    const { api, fetchImpl } = setup(new TypeError('Failed to fetch'));
    const error = await api.preparePlan({
      capabilityId: 'svc.send', target: 't', payload: new Uint8Array([1]),
      idempotencyKey: 'idem-0002' }).catch((e) => e);
    expect(error).toBeInstanceOf(TransportError);
    expect(error.mayHaveReachedServer).toBe(true);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });
});

describe('редиректы', () => {
  test('на другой адрес не переходит', async () => {
    const { api, calls } = setup(
      reply(307, null, ''), reply(0, null, '', 'opaqueredirect'));
    const error = await api.getPlan(PLAN_ID).catch((e) => e);
    expect(error).toBeInstanceOf(UnexpectedResponse);
    expect(error.status).toBe(307);
    await expect(api.executePlan(PLAN_ID, HASH)).rejects.toBeInstanceOf(OutcomeUnknown);
    expect(calls.map((c) => new URL(c.url).host)).toEqual(['backend.test', 'backend.test']);
    calls.forEach((c) => expect(c.options.redirect).toBe('manual'));
  });
});

// ---------- срез 4a, вторая редакция: замечания R11-R14 ----------

const OTHER_ID = `plan_${'2'.repeat(32)}`;

const noSecret = (error) => [
  String(error), error.message, error.code, error.title, error.detail,
  JSON.stringify(error.errors ?? null), JSON.stringify(error.completedCalls ?? null),
  JSON.stringify(error.uncertainCalls ?? null),
].every((text) => !String(text).includes(SECRET));

describe('ответ 200 подтверждает только наш план', () => {
  test.each([
    [{ plan_id: OTHER_ID, status: 'succeeded', result: {} }],
    [{ plan_id: PLAN_ID, status: 'unknown', result: null }],
    [{ plan_id: PLAN_ID, status: 'failed', result: null }],
    [{ plan_id: null, status: null }],
    [{ plan_id: PLAN_ID }],
    [{ plan_id: PLAN_ID, status: 'succeeded', result: ['not', 'object'] }],
    [{ plan_id: PLAN_ID, status: 'succeeded', result: 'ok' }],
  ])('execute 200 без нашего успеха: неизвестно', async (body) => {
    const { api, fetchImpl } = setup(reply(200, body));
    const error = await api.executePlan(PLAN_ID, HASH).catch((e) => e);
    expect(error).toBeInstanceOf(OutcomeUnknown);
    expect(error.planId).toBe(PLAN_ID);
    expect(error.status).toBe(200);
    expect(error.partialKnown).toBe(false);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  test('execute 200 нашего плана: успех', async () => {
    const { api } = setup(reply(200, { plan_id: PLAN_ID, status: 'succeeded', result: null }));
    await expect(api.executePlan(PLAN_ID, HASH)).resolves.toEqual(
      { planId: PLAN_ID, status: 'succeeded', result: null });
  });

  test.each([
    [{ plan_id: OTHER_ID }], [{ plan_id: null }], [{ plan_id: 'plan_x' }],
    [{ plan_hash: null }], [{ plan_hash: '' }], [{ status: 'done' }], [{ status: null }],
    [{ expires_at: 5 }], [{ preview: 'text' }], [{ result: [] }], [{ error_code: 7 }],
    [{ steps: 'none' }], [{ steps: [{ name: 'send' }] }], [{ steps: [null] }],
  ])('get вне контракта PlanOut: UnexpectedResponse', async (change) => {
    const { api } = setup(reply(200, { ...PLAN, ...change }));
    await expect(api.getPlan(PLAN_ID)).rejects.toBeInstanceOf(UnexpectedResponse);
  });

  test('prepare с чужим видом plan_id: UnexpectedResponse', async () => {
    const { api } = setup(reply(201, { ...PLAN, plan_id: '../admin' }));
    await expect(api.preparePlan({ capabilityId: 'svc.send', target: 't',
      payload: new Uint8Array([1]), idempotencyKey: 'idem-0003' }))
      .rejects.toBeInstanceOf(UnexpectedResponse);
  });
});

describe('ключ не попадает в ошибку ни через одно поле', () => {
  test('code и errors с ключом', async () => {
    const { api } = setup(problem(409, SECRET, {
      errors: [{ loc: ['body', SECRET], msg: `bad ${SECRET}`, [SECRET]: SECRET, n: 1 }] }));
    const error = await api.getPlan(PLAN_ID).catch((e) => e);
    expect(error).toBeInstanceOf(Conflict);
    expect(error.status).toBe(409);
    expect(error.code).toBe('unrecognized_code');
    expect(error.errors[0].loc).toEqual(['body', '***']);
    expect(error.errors[0].n).toBe(1);
    expect(noSecret(error)).toBe(true);
  });

  test('code и outcome ответа 502 с ключом', async () => {
    const { api } = setup(problem(502, SECRET, { outcome: {
      plan_id: PLAN_ID, completed_calls: [SECRET], uncertain_calls: [`send-${SECRET}`] } }));
    const error = await api.executePlan(PLAN_ID, HASH).catch((e) => e);
    expect(error).toBeInstanceOf(OutcomeUnknown);
    expect(error.code).toBe('unrecognized_code');
    expect(error.partialKnown).toBe(true);
    expect(error.completedCalls).toEqual(['***']);
    expect(noSecret(error)).toBe(true);
  });

  test.each([['Plan State'], ['x'.repeat(65)], ['1abc'], ['код']])(
    'не машинный code не передаётся: %s', async (code) => {
      const { api } = setup(problem(409, code));
      const error = await api.getPlan(PLAN_ID).catch((e) => e);
      expect(error).toBeInstanceOf(Conflict);
      expect(error.code).toBe('unrecognized_code');
    });
});

describe('срок действует и на чтение тела', () => {
  const headersNow = (bodyDelayMs) => {
    const aborts = [];
    const fetchImpl = jest.fn(async (url, options) => {
      options.signal.addEventListener('abort', () => aborts.push(true));
      return {
        ...reply(200, { plan_id: PLAN_ID, status: 'succeeded', result: null }),
        json: () => (bodyDelayMs === null ? new Promise(() => {}) : new Promise((resolve) => {
          setTimeout(() => resolve({ ...PLAN, plan_id: PLAN_ID, status: 'succeeded',
            result: null }), bodyDelayMs);
        })),
      };
    });
    const api = createIntegrationClient({
      baseUrl: BASE, credential: SECRET, fetchImpl, timeoutMs: 20 });
    return { api, fetchImpl, aborts };
  };

  test.each([[120], [null]])('execute: заголовки сразу, тело %s ms: неизвестно', async (delay) => {
    const { api, fetchImpl, aborts } = headersNow(delay);
    const error = await api.executePlan(PLAN_ID, HASH).catch((e) => e);
    expect(error).toBeInstanceOf(OutcomeUnknown);
    expect(error.code).toBe('transport_error');
    expect(aborts).toEqual([true]);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(noSecret(error)).toBe(true);
  });

  test.each([['get', 120], ['get', null], ['prepare', 120], ['prepare', null]])(
    '%s: заголовки сразу, тело %s ms: ошибка транспорта', async (call, delay) => {
      const { api, fetchImpl } = headersNow(delay);
      const run = call === 'get' ? api.getPlan(PLAN_ID) : api.preparePlan({
        capabilityId: 'svc.send', target: 't', payload: new Uint8Array([1]),
        idempotencyKey: 'idem-0004' });
      const error = await run.catch((e) => e);
      expect(error).toBeInstanceOf(TransportError);
      expect(error.mayHaveReachedServer).toBe(true);
      expect(error.message).not.toContain(SECRET);
      expect(fetchImpl).toHaveBeenCalledTimes(1);
    });
});

describe('http только для loopback', () => {
  test.each([
    ['http://remote.invalid/api'], ['http://10.0.0.5:8000'], ['http://backend:8000'],
    ['http://localhost.evil.invalid'], ['http://127.0.0.1.nip.invalid'], ['http://[2001:db8::1]'],
  ])('удалённый %s не принимается и с флагом', (baseUrl) => {
    expect(() => createIntegrationClient({ baseUrl, credential: SECRET, allowInsecureHttp: true }))
      .toThrow(IntegrationConfigError);
  });

  test.each([
    ['http://localhost:8000'], ['http://api.localhost'], ['http://127.0.0.1'],
    ['http://127.1.2.3:9'], ['http://[::1]:8000'],
  ])('loopback %s принимается по флагу', (baseUrl) => {
    expect(createIntegrationClient({ baseUrl, credential: SECRET, allowInsecureHttp: true })
      .baseUrl).toBe(new URL(baseUrl).href.replace(/\/+$/, ''));
  });
});
