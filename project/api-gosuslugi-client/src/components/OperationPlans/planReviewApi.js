// Запросы администратора установки к планам операций. Работают по обычной
// сессии (HttpOnly cookie), ключ интеграции здесь не нужен и не передаётся.
// В ответе точные байты плана, поэтому браузеру запрещено его кешировать.
import { BACKEND_URL } from '../Auth/authApi';

export const PLAN_ID_RE = /^plan_[0-9a-f]{32}$/;

export class PlanReviewError extends Error {
  constructor(status, code = '', detail = '') {
    super(detail || code || `HTTP ${status}`);
    this.status = status;
    this.code = code;
    this.detail = detail;
  }
}

const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const isText = (value) => typeof value === 'string' && value !== '';
const isCount = (value) => Number.isInteger(value) && value >= 0;
const isTexts = (value) => Array.isArray(value) && value.every((item) => typeof item === 'string');
const isOptionalText = (value) => value === null || value === undefined || isText(value);
const HEX64_RE = /^[0-9a-f]{64}$/;
const STATUSES = ['planned', 'approved', 'inflight', 'succeeded', 'failed', 'unknown'];

const isAttachmentInfo = (item) =>
  isObject(item) && typeof item.name === 'string' && HEX64_RE.test(item.sha256) && isCount(item.size);

// Всё, на что человек смотрит при решении, обязано быть в ответе. Пустое
// место на экране не должно выглядеть как «нет вызовов» или «нет вложений».
function previewComplete(preview) {
  if (!isObject(preview)) return false;
  const { context, target_policy: policy } = preview;
  return (
    isText(preview.capability_id) &&
    isText(preview.target) &&
    HEX64_RE.test(preview.payload_sha256) &&
    isCount(preview.payload_size) &&
    Array.isArray(preview.attachments) &&
    preview.attachments.every(isAttachmentInfo) &&
    isObject(context) &&
    isText(context.contour) &&
    isText(context.organization_ref) &&
    isOptionalText(context.is_ref) &&
    isText(context.certificate_thumbprint) &&
    isCount(context.generation) &&
    isCount(context.binding_epoch) &&
    Array.isArray(preview.external_calls) &&
    preview.external_calls.every((call) => isObject(call) && isText(call.name) && isTexts(call.side_effects)) &&
    isObject(policy) &&
    policy.capability_id === preview.capability_id &&
    isText(policy.effect) &&
    isTexts(policy.scopes) &&
    isTexts(policy.gates) &&
    isTexts(policy.side_effects)
  );
}

// Байты каждого вложения соответствуют его описанию в предпросмотре: то же
// число, тот же порядок, имя, размер и SHA-256. Проверяются все заявленные
// вложения, а не только пришедшие.
function contentsMatch(preview, contents) {
  return (
    Array.isArray(contents) &&
    contents.length === preview.attachments.length &&
    contents.every((item, index) => {
      const meta = preview.attachments[index];
      return (
        isObject(item) &&
        item.name === meta.name &&
        item.sha256 === meta.sha256 &&
        item.size === meta.size &&
        typeof item.content_b64 === 'string'
      );
    })
  );
}

// Ответ, по которому человек принимает решение, проверяется по форме: без
// этого кнопка одобрения могла бы отправить хеш другого или неполного плана.
// Хеш плана здесь не пересчитывается: его сверяет сервер (hash_verified).
function checkView(data, planId) {
  const ok =
    isObject(data) &&
    data.plan_id === planId &&
    HEX64_RE.test(data.plan_hash) &&
    STATUSES.includes(data.status) &&
    isText(data.expires_at) &&
    !Number.isNaN(Date.parse(data.expires_at)) &&
    isText(data.client_id) &&
    isText(data.created_at) &&
    isOptionalText(data.approved_by) &&
    isOptionalText(data.approved_at) &&
    isOptionalText(data.error_code) &&
    typeof data.hash_verified === 'boolean' &&
    typeof data.payload_b64 === 'string' &&
    Array.isArray(data.steps) &&
    data.steps.every((step) => isObject(step) && isText(step.name) && isText(step.state)) &&
    previewComplete(data.preview) &&
    contentsMatch(data.preview, data.attachment_contents);
  if (!ok) throw new PlanReviewError(0, 'unexpected_response', 'Ответ сервера не похож на полный предпросмотр этого плана');
  return data;
}

async function call(planId, suffix, { method = 'GET', body } = {}) {
  if (!PLAN_ID_RE.test(planId)) {
    throw new PlanReviewError(0, 'invalid_plan_id', 'Идентификатор плана имеет вид plan_ и 32 шестнадцатеричных знака');
  }
  const options = {
    method,
    credentials: 'same-origin',
    cache: 'no-store',
    headers: { Accept: 'application/json, application/problem+json' },
  };
  if (body !== undefined) {
    options.headers['Content-Type'] = 'application/json';
    options.body = JSON.stringify(body);
  }
  let response;
  try {
    response = await fetch(`${BACKEND_URL}/v1/admin/operations/plans/${planId}${suffix}`, options);
  } catch (err) {
    throw new PlanReviewError(0, 'network_error', 'Сервер установки недоступен');
  }
  let payload = null;
  try {
    payload = await response.json();
  } catch (err) {
    payload = null;
  }
  if (!response.ok) {
    const code = isObject(payload) && typeof payload.code === 'string' ? payload.code : '';
    const detail = isObject(payload) && typeof payload.detail === 'string' ? payload.detail : '';
    throw new PlanReviewError(response.status, code, detail);
  }
  return checkView(payload, planId);
}

export async function fetchPlan(planId) {
  const view = decodePlan(await call(planId, ''));
  if (view === null) throw new PlanReviewError(0, 'unexpected_response', 'Байты плана в ответе сервера повреждены');
  return view;
}

export const UNCONFIRMED = 'unconfirmed_approval';

// Одобрение подтверждено, только если сервер вернул целый предпросмотр того
// же плана с тем же хешем в состоянии approved. Иначе неизвестно, что сделал
// сервер: это не успех и не отказ.
export async function approvePlan(planId, planHash) {
  let data;
  try {
    data = await call(planId, '/approve', { method: 'POST', body: { plan_hash: planHash } });
  } catch (err) {
    // Обрыв связи, непонятный ответ или ошибка сервера: одобрение могло
    // состояться. Отказы 401, 403, 404, 409, 410 и 422 однозначны.
    const unknown = (err.status === 0 && err.code !== 'invalid_plan_id') || err.status >= 500;
    if (unknown) throw new PlanReviewError(err.status, UNCONFIRMED, err.detail);
    throw err;
  }
  const view = decodePlan(data);
  if (data.plan_hash !== planHash || data.status !== 'approved' || view === null) {
    throw new PlanReviewError(0, UNCONFIRMED, 'Ответ сервера не подтверждает одобрение показанного плана');
  }
  return view;
}

// Точные байты из base64. Ошибка разбора не превращается в пустые данные.
export function decodeBase64(text) {
  let binary;
  try {
    binary = atob(text);
  } catch (err) {
    return null;
  }
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

// Текст показывается, только если байты целиком корректный UTF-8.
export function utf8Text(bytes) {
  if (typeof TextDecoder === 'undefined') return null;
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch (err) {
    return null;
  }
}

// Проверенный план с декодированными байтами, иначе null. Размеры байтов
// сверяет окно: при расхождении план показывается, но не одобряется.
export function decodePlan(plan) {
  const payload = decodeBase64(plan.payload_b64);
  const attachments = plan.attachment_contents.map((item) => ({ ...item, bytes: decodeBase64(item.content_b64) }));
  if (payload === null || attachments.some((item) => item.bytes === null)) return null;
  return { plan, payload, attachments };
}
