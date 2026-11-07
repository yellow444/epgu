// Машинный клиент планов операций НАШЕГО backend по ключу интеграции.
//
// Это не запросы интерфейса: у них своя cookie-сессия человека (authApi.js).
// Здесь только ключ в Authorization: Bearer, credentials=omit, без перехода
// по редиректам и без кеша. Ключ живёт в замыкании: его нет в свойствах
// объекта, URL, localStorage, журнале и тексте ошибок.
//
// Методы только машинные: preparePlan, getPlan, executePlan. Одобрения нет:
// одобряет человек в интерфейсе установки. Повторов нет ни по таймауту, ни
// по 5xx. После обрыва executePlan нельзя считать, что сервер план не
// принял: это OutcomeUnknown без списков вызовов.
//
// Срок timeoutMs общий на запрос и чтение тела. http:// только явно и только
// для loopback. Ответ проверяется по контракту, включая plan_id запроса.
// Известный ключ вырезается из всех полей ошибки, сырое тело к ней не
// прикрепляется.

export const PLANS_PATH = '/v1/operations/plans';
const PROBLEM_MEDIA_TYPE = 'application/problem+json';
const PLAN_ID_RE = /^plan_[0-9a-f]{32}$/;
const CODE_RE = /^[a-z][a-z0-9_]{0,63}$/;
const PLAN_STATUSES = new Set(['planned', 'approved', 'inflight', 'succeeded', 'failed',
  'unknown']);
const SUCCEEDED = 'succeeded';
const UNRECOGNIZED_CODE = 'unrecognized_code';
const CREDENTIAL_RE = /^[\x21-\x7e]{16,4096}$/;
const REDACTED = '***';

export class IntegrationError extends Error {
  constructor(message) {
    super(message);
    this.name = new.target.name;
  }
}

export class IntegrationConfigError extends IntegrationError {}

export class TransportError extends IntegrationError {
  constructor(message, { mayHaveReachedServer }) {
    super(message);
    this.mayHaveReachedServer = mayHaveReachedServer;
  }
}

export class UnexpectedResponse extends IntegrationError {
  constructor(message, { status }) {
    super(message);
    this.status = status;
  }
}

export class ProblemError extends IntegrationError {
  constructor({ status, code, title, detail, errors }) {
    super(`${status} ${code}: ${detail || title}`);
    this.status = status;
    this.code = code;
    this.title = title;
    this.detail = detail;
    this.errors = Array.isArray(errors) ? errors : [];
  }
}

export class InvalidRequest extends ProblemError {}
export class Unauthenticated extends ProblemError {}
export class Forbidden extends ProblemError {}
export class PlanNotFound extends ProblemError {}
export class Conflict extends ProblemError {}
export class PlanExpired extends ProblemError {}
export class ServiceUnavailable extends ProblemError {}

// completedCalls и uncertainCalls берутся только из поля outcome ответа 502.
// Нет поля или ответа: оба null, частичный результат неизвестен.
export class OutcomeUnknown extends ProblemError {
  constructor({ planId, status, code, title, detail, completedCalls = null,
    uncertainCalls = null }) {
    super({ status, code, title, detail });
    this.planId = planId;
    this.completedCalls = completedCalls;
    this.uncertainCalls = uncertainCalls;
  }

  get partialKnown() {
    return Array.isArray(this.completedCalls) && Array.isArray(this.uncertainCalls);
  }
}

const BY_STATUS = {
  400: InvalidRequest,
  401: Unauthenticated,
  403: Forbidden,
  404: PlanNotFound,
  409: Conflict,
  410: PlanExpired,
  422: InvalidRequest,
  503: ServiceUnavailable,
};

const isLoopback = (host) => host === 'localhost' || host.endsWith('.localhost')
  || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host) || host === '[::1]';

const checkBaseUrl = (baseUrl, allowInsecureHttp) => {
  let url;
  try {
    url = new URL(baseUrl);
  } catch (error) {
    throw new IntegrationConfigError('baseUrl: нужен абсолютный адрес backend установки');
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new IntegrationConfigError('baseUrl: нужен адрес https://');
  }
  if (url.protocol === 'http:' && !allowInsecureHttp) {
    throw new IntegrationConfigError(
      'baseUrl: http:// только явно, allowInsecureHttp для разработки');
  }
  if (url.protocol === 'http:' && !isLoopback(url.hostname)) {
    throw new IntegrationConfigError(
      'baseUrl: http:// только для loopback (localhost, 127.0.0.0/8, ::1)');
  }
  if (url.username || url.password || url.search || url.hash || /[?#]/.test(baseUrl)) {
    throw new IntegrationConfigError('baseUrl: без учётных данных, query и fragment');
  }
  return url.href.replace(/\/+$/, '');
};

const checkPlanId = (planId) => {
  if (typeof planId !== 'string' || !PLAN_ID_RE.test(planId)) {
    throw new IntegrationConfigError('planId: ожидается plan_ и 32 hex-символа');
  }
  return planId;
};

const toBase64 = (bytes) => {
  if (!(bytes instanceof Uint8Array)) {
    throw new IntegrationConfigError('ожидаются байты (Uint8Array)');
  }
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary);
};

const mediaType = (response) =>
  (response.headers.get('content-type') || '').split(';')[0].trim().toLowerCase();

const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);

// План по контракту PlanOut. expectedId для getPlan: ответ о том же плане.
const toPlan = (data, created, expectedId) => {
  const bad = (what) => new UnexpectedResponse(`план не по контракту: ${what}`, { status: 200 });
  if (typeof data.plan_id !== 'string' || !PLAN_ID_RE.test(data.plan_id)) throw bad('plan_id');
  if (expectedId !== null && data.plan_id !== expectedId) {
    throw bad('plan_id не тот, что запрошен');
  }
  for (const key of ['plan_hash', 'expires_at']) {
    if (typeof data[key] !== 'string' || !data[key]) throw bad(key);
  }
  if (!PLAN_STATUSES.has(data.status)) throw bad('status');
  if (!isObject(data.preview)) throw bad('preview');
  const result = data.result ?? null;
  const errorCode = data.error_code ?? null;
  if (result !== null && !isObject(result)) throw bad('result');
  if (errorCode !== null && typeof errorCode !== 'string') throw bad('error_code');
  const steps = data.steps ?? [];
  if (!Array.isArray(steps) || !steps.every((step) => isObject(step)
    && typeof step.name === 'string' && typeof step.state === 'string')) {
    throw bad('steps');
  }
  return {
    planId: data.plan_id,
    planHash: data.plan_hash,
    status: data.status,
    expiresAt: data.expires_at,
    preview: data.preview,
    result,
    errorCode,
    steps,
    created,
  };
};

export function createIntegrationClient({
  baseUrl, credential, allowInsecureHttp = false, timeoutMs = 30000, fetchImpl,
} = {}) {
  const base = checkBaseUrl(baseUrl, allowInsecureHttp);
  if (typeof credential !== 'string' || !CREDENTIAL_RE.test(credential)) {
    throw new IntegrationConfigError('credential: нужен секрет ключа интеграции');
  }
  const doFetch = fetchImpl || globalThis.fetch.bind(globalThis);
  const clean = (text) => (typeof text === 'string' ? text.split(credential).join(REDACTED) : '');
  const machineCode = (code) => (code.includes(credential) || !CODE_RE.test(code)
    ? UNRECOGNIZED_CODE : code);
  // Копия подробностей 422 без ключа: только JSON-значения, строки очищены.
  const scrub = (value, depth = 0) => {
    if (depth > 8) return null;
    if (typeof value === 'string') return clean(value);
    if (Array.isArray(value)) return value.map((item) => scrub(item, depth + 1));
    if (isObject(value)) {
      return Object.fromEntries(Object.entries(value)
        .map(([key, item]) => [clean(key), scrub(item, depth + 1)]));
    }
    if (value === null || typeof value === 'boolean' || typeof value === 'number') return value;
    return null;
  };
  const scrubErrors = (errors) => (Array.isArray(errors)
    ? errors.filter(isObject).map((item) => scrub(item)) : []);

  // Один запрос с общим сроком на заголовки и чтение тела: handle читает и
  // проверяет ответ до истечения срока. Ошибки handle проходят как есть.
  const request = async (method, path, body, handle) => {
    const controller = new AbortController();
    let timer;
    const deadline = new Promise((resolve, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        reject(new TransportError('таймаут запроса', { mayHaveReachedServer: true }));
      }, timeoutMs);
    });
    const headers = { Accept: 'application/json', Authorization: `Bearer ${credential}` };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    try {
      let response;
      try {
        response = await Promise.race([doFetch(`${base}${path}`, {
          method,
          headers,
          body: body === undefined ? undefined : JSON.stringify(body),
          credentials: 'omit',
          redirect: 'manual',
          cache: 'no-store',
          referrerPolicy: 'no-referrer',
          signal: controller.signal,
        }), deadline]);
      } catch (error) {
        if (error instanceof TransportError) throw error;
        // fetch не говорит, ушёл ли запрос: считаем, что мог уйти.
        throw new TransportError('ошибка транспорта', { mayHaveReachedServer: true });
      }
      try {
        return await Promise.race([handle(response), deadline]);
      } catch (error) {
        if (error instanceof IntegrationError) throw error;
        throw new TransportError(controller.signal.aborted ? 'таймаут чтения ответа'
          : 'ошибка чтения ответа', { mayHaveReachedServer: true });
      }
    } finally {
      clearTimeout(timer);
    }
  };

  const problemBody = async (response) => {
    if (mediaType(response) !== PROBLEM_MEDIA_TYPE) {
      throw new UnexpectedResponse(`ответ ${response.status} без problem+json`,
        { status: response.status });
    }
    let data;
    try {
      data = await response.json();
    } catch (error) {
      throw new UnexpectedResponse('problem+json не разбирается', { status: response.status });
    }
    if (!data || typeof data !== 'object' || typeof data.code !== 'string') {
      throw new UnexpectedResponse('problem+json без code', { status: response.status });
    }
    return data;
  };

  const readJson = async (response, ok) => {
    const { status } = response;
    if (response.type === 'opaqueredirect' || (status >= 300 && status < 400)) {
      throw new UnexpectedResponse(`редирект ${status} не выполняется`, { status });
    }
    if (!ok.includes(status)) {
      const data = await problemBody(response);
      const Kind = BY_STATUS[status] || ProblemError;
      throw new Kind({ status, code: machineCode(data.code), title: clean(data.title),
        detail: clean(data.detail), errors: scrubErrors(data.errors) });
    }
    let data;
    try {
      data = await response.json();
    } catch (error) {
      throw new UnexpectedResponse(`ответ ${status} не JSON`, { status });
    }
    if (!data || typeof data !== 'object' || Array.isArray(data)) {
      throw new UnexpectedResponse(`ответ ${status} не объект`, { status });
    }
    return data;
  };

  const unknownFrom502 = async (planId, response) => {
    let data;
    try {
      data = await problemBody(response);
    } catch (error) {
      return new OutcomeUnknown({ planId, status: 502, code: 'outcome_unknown',
        title: 'Результат внешней операции неизвестен', detail: 'ответ 502 не по контракту' });
    }
    let completedCalls = null;
    let uncertainCalls = null;
    const { outcome } = data;
    const names = (value) => Array.isArray(value) && value.every((item) => typeof item === 'string');
    if (outcome && outcome.plan_id === planId && names(outcome.completed_calls)
      && names(outcome.uncertain_calls)) {
      completedCalls = outcome.completed_calls.map(clean);
      uncertainCalls = outcome.uncertain_calls.map(clean);
    }
    return new OutcomeUnknown({ planId, status: 502, code: machineCode(data.code),
      title: clean(data.title),
      detail: clean(data.detail), completedCalls, uncertainCalls });
  };

  const unexpected = (planId, status) => new OutcomeUnknown({
    planId, status, code: status === null ? 'transport_error' : 'unexpected_response',
    title: 'Ответ на execute не по контракту',
    detail: 'сервер мог исполнить план, повтор не выполняется',
  });

  return Object.freeze({
    baseUrl: base,

    async preparePlan({ capabilityId, target, payload, idempotencyKey, attachments = [] }) {
      const body = {
        capability_id: capabilityId,
        target,
        payload_b64: toBase64(payload),
        attachments: attachments.map(({ name, content }) => ({
          name, content_b64: toBase64(content) })),
        idempotency_key: idempotencyKey,
      };
      return request('POST', PLANS_PATH, body, async (response) =>
        toPlan(await readJson(response, [200, 201]), response.status === 201, null));
    },

    async getPlan(planId) {
      const id = checkPlanId(planId);
      return request('GET', `${PLANS_PATH}/${id}`, undefined, async (response) =>
        toPlan(await readJson(response, [200]), null, id));
    },

    async executePlan(planId, planHash) {
      const path = `${PLANS_PATH}/${checkPlanId(planId)}/execute`;
      const handle = async (response) => {
        const { status } = response;
        if (status === 200) {
          // Успех только наш: тот же plan_id, status=succeeded, result объект
          // или null. Иначе исход неизвестен, ответ не доказывает исполнение.
          let data = {};
          try {
            data = await readJson(response, [200]);
          } catch (error) {
            if (!(error instanceof IntegrationError)) throw error;
          }
          const result = data.result ?? null;
          if (data.plan_id === planId && data.status === SUCCEEDED
            && (result === null || isObject(result))) {
            return { planId, status: SUCCEEDED, result };
          }
          return unexpected(planId, status);
        }
        if (status === 502) return unknownFrom502(planId, response);
        // Отказ до исполнения бывает только по контракту: 4xx или 503 с problem+json.
        if (response.type !== 'opaqueredirect'
          && ((status >= 400 && status < 500) || status === 503)
          && mediaType(response) === PROBLEM_MEDIA_TYPE) {
          try {
            await readJson(response, []);
          } catch (error) {
            if (error instanceof ProblemError) return error;
            if (!(error instanceof IntegrationError)) throw error;
          }
        }
        return unexpected(planId, status);
      };
      let outcome;
      try {
        outcome = await request('POST', path, { plan_hash: planHash }, handle);
      } catch (error) {
        throw unexpected(planId, null);
      }
      if (outcome instanceof Error) throw outcome;
      return outcome;
    },
  });
}
