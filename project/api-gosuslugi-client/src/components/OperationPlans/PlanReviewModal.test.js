import React from 'react';
import { createHash } from 'crypto';
import { TextDecoder } from 'util';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import AuthGate from '../Auth/AuthGate';
import AccountMenu from '../Auth/AccountMenu';
import { decodeBase64 } from './planReviewApi';
import { notifyWorkspaceContextChanged } from '../../workspaceContext';

global.TextDecoder = TextDecoder;
// Окно antd с полным предпросмотром рисуется медленно, особенно в общем прогоне.
jest.setTimeout(30000);

const ADMIN = { id: 'acc_' + 'a'.repeat(32), login: 'admin', display_name: 'Администратор', installation_admin: true };
const OPERATOR = { id: 'acc_' + 'b'.repeat(32), login: 'operator', display_name: 'Оператор', installation_admin: false };
const PLAN_ID = 'plan_' + '1'.repeat(32);
const OTHER_ID = 'plan_' + '2'.repeat(32);
const HASH = 'a'.repeat(64);
const PAYLOAD = Buffer.from('<b>жирный</b><script>window.__pwned = 1</script> личные данные', 'utf8');
const BINARY = Buffer.from([0xff, 0x00, 0x80, 0xfe, 0x0a, 0xc3, 0x28, 0x00]);

const sha = (bytes) => createHash('sha256').update(Buffer.from(bytes)).digest('hex');
const REFUSED = 'Ответ сервера не похож на полный предпросмотр этого плана';
const UNCONFIRMED = /Результат одобрения не удалось подтвердить/;
const SECOND = Buffer.from('второе вложение', 'utf8');

function planView(over = {}) {
  return {
    plan_id: PLAN_ID,
    plan_hash: HASH,
    status: 'planned',
    expires_at: new Date(Date.now() + 10 * 60000).toISOString(),
    preview: {
      capability_id: 'test.operation',
      target: 'target-1',
      payload_sha256: sha(PAYLOAD),
      payload_size: PAYLOAD.length,
      attachments: [{ name: 'scan<img src=x>.bin', sha256: sha(BINARY), size: BINARY.length }],
      context: {
        contour: 'TEST',
        organization_ref: 'org-1',
        is_ref: null,
        certificate_thumbprint: 'c'.repeat(40),
        generation: 1,
        binding_epoch: 2,
      },
      external_calls: [{ name: 'send', side_effects: ['external_write'] }],
      target_policy: {
        capability_id: 'test.operation',
        effect: 'write',
        implemented: true,
        machine: 'enforced',
        mcp_profile: 'none',
        scopes: ['external:execute'],
        gates: ['operator_context'],
        side_effects: ['external_write'],
      },
    },
    result: null,
    error_code: null,
    steps: [],
    client_id: 'int_' + 'd'.repeat(32),
    created_at: new Date().toISOString(),
    approved_by: null,
    approved_at: null,
    hash_verified: true,
    payload_b64: PAYLOAD.toString('base64'),
    attachment_contents: [
      { name: 'scan<img src=x>.bin', sha256: sha(BINARY), size: BINARY.length, content_b64: BINARY.toString('base64') },
    ],
    ...over,
  };
}

function installServer({ account = ADMIN, plan = planView(), approveReply, reviewReply } = {}) {
  const calls = [];
  const state = { session: { account }, plan };
  global.fetch = jest.fn(async (url, options = {}) => {
    const method = (options.method || 'GET').toUpperCase();
    const path = new URL(url, 'http://localhost').pathname;
    const body = options.body ? JSON.parse(options.body) : undefined;
    calls.push({ method, path, body, cache: options.cache, credentials: options.credentials });
    let status = 200;
    let payload = {};
    if (path === '/api/auth/session') {
      if (state.session) payload = state.session;
      else { status = 401; payload = { detail: 'Нужен вход' }; }
    } else if (path === '/api/auth/mode') {
      payload = { auth: true, bootstrap_required: false };
    } else if (path === '/api/auth/login') {
      state.session = { account: ADMIN };
      payload = state.session;
    } else if (path === '/api/auth/logout') {
      state.session = null;
      payload = { logged_out: true };
    } else if (path === `/api/v1/admin/operations/plans/${PLAN_ID}` && method === 'GET') {
      if (reviewReply) return reviewReply();
      payload = state.plan;
    } else if (path === `/api/v1/admin/operations/plans/${PLAN_ID}/approve` && method === 'POST') {
      if (approveReply) return approveReply(body);
      payload = { ...state.plan, status: 'approved', approved_by: ADMIN.id, approved_at: new Date().toISOString() };
    } else {
      status = 404;
      payload = { type: 'about:blank', title: 'Not Found', status: 404, code: 'plan_not_found', detail: 'План не найден' };
    }
    return { ok: status < 400, status, json: async () => payload };
  });
  return { calls, state };
}

function problem(status, code, detail = '') {
  return { ok: false, status, json: async () => ({ type: 'about:blank', title: code, status, code, detail }) };
}

function Workspace() {
  return <AuthGate>{() => <AccountMenu />}</AuthGate>;
}

async function openPlans() {
  render(<Workspace />);
  fireEvent.click(await screen.findByTestId('account-menu'));
  fireEvent.click(await screen.findByText('Одобрение планов'));
  return screen.findByRole('dialog');
}

async function loadPlan(id = PLAN_ID) {
  fireEvent.change(screen.getByLabelText('Идентификатор плана'), { target: { value: id } });
  fireEvent.click(screen.getByRole('button', { name: /Загрузить план/ }));
}

const planCalls = (calls) => calls.filter((call) => call.path.startsWith('/api/v1/admin/operations/'));
const approveCalls = (calls) => calls.filter((call) => call.method === 'POST' && call.path.endsWith('/approve'));

function readBlob(blob) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(new Uint8Array(reader.result));
    reader.onerror = reject;
    reader.readAsArrayBuffer(blob);
  });
}

let blobs;

beforeEach(() => {
  blobs = [];
  window.URL.createObjectURL = jest.fn((blob) => {
    blobs.push(blob);
    return `blob:test-${blobs.length}`;
  });
  window.URL.revokeObjectURL = jest.fn();
  delete window.__pwned;
});

afterEach(() => {
  delete global.fetch;
  delete window.URL.createObjectURL;
  delete window.URL.revokeObjectURL;
});

test('the section is offered only to an installation administrator', async () => {
  installServer({ account: OPERATOR });
  render(<Workspace />);
  fireEvent.click(await screen.findByTestId('account-menu'));
  expect(await screen.findByText('Сменить пароль')).toBeInTheDocument();
  expect(screen.queryByText('Одобрение планов')).not.toBeInTheDocument();
});

test('opening and loading never approve and ask the server not to cache', async () => {
  const { calls } = installServer();
  const dialog = await openPlans();
  expect(planCalls(calls)).toHaveLength(0);
  expect(within(dialog).getByText(/а не независимое согласование/)).toBeInTheDocument();
  await loadPlan();
  expect(await within(dialog).findByTestId('plan-hash')).toHaveTextContent(HASH);
  expect(planCalls(calls)).toEqual([
    { method: 'GET', path: `/api/v1/admin/operations/plans/${PLAN_ID}`, body: undefined, cache: 'no-store', credentials: 'same-origin' },
  ]);
  expect(within(dialog).getByText('подготовлен, ждёт одобрения')).toBeInTheDocument();
  expect(within(dialog).getByText('байты совпадают с хешем')).toBeInTheDocument();
  expect(within(dialog).getByText(/send: external_write/)).toBeInTheDocument();
  expect(within(dialog).getByText(/TEST, организация org-1/)).toBeInTheDocument();
  expect(within(dialog).getByText(`SHA-256 ${sha(BINARY)}`)).toBeInTheDocument();
  expect(approveCalls(calls)).toHaveLength(0);
});

test('untrusted bytes are shown as text and never executed', async () => {
  installServer();
  const dialog = await openPlans();
  await loadPlan();
  const text = await within(dialog).findByTestId(`${PLAN_ID}-payload.bin-text`);
  expect(text.textContent).toBe(PAYLOAD.toString('utf8'));
  expect(text.querySelector('b, script')).toBeNull();
  expect(document.querySelector('img[src="x"]')).toBeNull();
  expect(window.__pwned).toBeUndefined();
  expect(within(dialog).getByText('Вложение 1: scan<img src=x>.bin')).toBeInTheDocument();
  expect(within(dialog).getByText(/Не текст UTF-8/)).toBeInTheDocument();
});

test('downloads keep the exact decoded bytes, including non UTF-8 data', async () => {
  installServer();
  const dialog = await openPlans();
  await loadPlan();
  const buttons = await within(dialog).findAllByRole('button', { name: /Скачать точные байты/ });
  expect(buttons).toHaveLength(2);
  fireEvent.click(buttons[0]);
  fireEvent.click(buttons[1]);
  expect(blobs).toHaveLength(2);
  const payload = await readBlob(blobs[0]);
  const binary = await readBlob(blobs[1]);
  expect(payload.length).toBe(PAYLOAD.length);
  expect(sha(payload)).toBe(sha(PAYLOAD));
  expect(binary.length).toBe(BINARY.length);
  expect(sha(binary)).toBe(sha(BINARY));
  expect(Array.from(binary)).toEqual(Array.from(BINARY));
  expect(window.URL.revokeObjectURL).toHaveBeenCalledTimes(2);
});

test('approve sends the visible hash once, even on a double click', async () => {
  let release;
  const { calls } = installServer({
    approveReply: () =>
      new Promise((resolve) => {
        release = () =>
          resolve({ ok: true, status: 200, json: async () => ({ ...planView(), status: 'approved', approved_by: ADMIN.id, approved_at: 'now' }) });
      }),
  });
  const dialog = await openPlans();
  await loadPlan();
  const button = await within(dialog).findByRole('button', { name: /Одобрить этот план/ });
  fireEvent.click(button);
  fireEvent.click(button);
  await waitFor(() => expect(approveCalls(calls)).toHaveLength(1));
  expect(approveCalls(calls)[0].body).toEqual({ plan_hash: within(dialog).getByTestId('plan-hash').textContent });
  expect(approveCalls(calls)[0].cache).toBe('no-store');
  await act(async () => release());
  expect(await within(dialog).findByText('План одобрен')).toBeInTheDocument();
  expect(within(dialog).getByText('одобрен')).toBeInTheDocument();
  expect(within(dialog).queryByRole('button', { name: /Одобрить этот план/ })).not.toBeInTheDocument();
  expect(approveCalls(calls)).toHaveLength(1);
});

test.each([
  [409, 'plan_hash_mismatch', /Хеш на экране не совпадает/],
  [409, 'plan_state', /План уже не ждёт одобрения/],
  [410, 'plan_expired', /Срок плана истёк/],
  [403, 'forbidden', /Нужны права администратора установки/],
])('a %s %s answer is shown and nothing is retried or reloaded', async (status, code, message) => {
  const { calls } = installServer({ approveReply: () => problem(status, code) });
  const dialog = await openPlans();
  await loadPlan();
  fireEvent.click(await within(dialog).findByRole('button', { name: /Одобрить этот план/ }));
  expect(await within(dialog).findByText(message)).toBeInTheDocument();
  expect(planCalls(calls).map((call) => call.method)).toEqual(['GET', 'POST']);
});

test.each([
  ['changed bytes', { hash_verified: false }],
  ['a past deadline', { expires_at: new Date(Date.now() - 1000).toISOString() }],
  [
    'attachment bytes of another size than declared',
    {
      attachment_contents: [
        {
          name: 'scan<img src=x>.bin',
          sha256: sha(BINARY),
          size: BINARY.length,
          content_b64: Buffer.concat([BINARY, Buffer.from([1])]).toString('base64'),
        },
      ],
    },
  ],
])('a plan with %s cannot be approved', async (_name, over) => {
  const { calls } = installServer({ plan: planView(over) });
  const dialog = await openPlans();
  await loadPlan();
  const button = await within(dialog).findByRole('button', { name: /Одобрить этот план/ });
  expect(button).toBeDisabled();
  fireEvent.click(button);
  expect(approveCalls(calls)).toHaveLength(0);
});

test('an answer about another plan is refused instead of being shown', async () => {
  const { calls } = installServer({ plan: planView({ plan_id: OTHER_ID }) });
  const dialog = await openPlans();
  await loadPlan();
  expect(await within(dialog).findByText(REFUSED)).toBeInTheDocument();
  expect(within(dialog).queryByRole('button', { name: /Одобрить этот план/ })).not.toBeInTheDocument();
  expect(approveCalls(calls)).toHaveLength(0);
});

test('another plan id drops the shown preview and nothing is stored in the browser', async () => {
  installServer();
  const dialog = await openPlans();
  await loadPlan();
  expect(await within(dialog).findByTestId('plan-hash')).toBeInTheDocument();
  expect(JSON.stringify({ ...localStorage, ...sessionStorage })).not.toMatch(/личные|plan_1/);
  expect(typeof window.caches === 'undefined' || window.caches === null).toBe(true);
  fireEvent.change(screen.getByLabelText('Идентификатор плана'), { target: { value: OTHER_ID } });
  expect(within(dialog).queryByTestId('plan-hash')).not.toBeInTheDocument();
  expect(within(dialog).queryByText(/личные данные/)).not.toBeInTheDocument();
});

test('closing the window drops the preview', async () => {
  installServer();
  const dialog = await openPlans();
  await loadPlan();
  expect(await within(dialog).findByTestId('plan-hash')).toBeInTheDocument();
  fireEvent.click(within(dialog).getByRole('button', { name: /Close|Закрыть/ }));
  await waitFor(() => expect(screen.queryByTestId('plan-hash')).not.toBeInTheDocument());
  fireEvent.click(screen.getByTestId('account-menu'));
  fireEvent.click(await screen.findByText('Одобрение планов'));
  const input = await screen.findByLabelText('Идентификатор плана');
  expect(input).toHaveValue('');
});

test('logout drops the preview together with the workspace', async () => {
  installServer();
  const dialog = await openPlans();
  await loadPlan();
  expect(await within(dialog).findByTestId('plan-hash')).toBeInTheDocument();
  fireEvent.click(screen.getByTestId('account-menu'));
  fireEvent.click(await screen.findByText('Выйти'));
  expect(await screen.findByText('Вход в установку')).toBeInTheDocument();
  expect(screen.queryByTestId('plan-hash')).not.toBeInTheDocument();
  expect(document.body.textContent).not.toMatch(/личные данные/);
});

test('a session that ended is sent back to sign in', async () => {
  const { state } = installServer({
    approveReply: () => {
      state.session = null;
      return problem(401, 'unauthenticated');
    },
  });
  const dialog = await openPlans();
  await loadPlan();
  fireEvent.click(await within(dialog).findByRole('button', { name: /Одобрить этот план/ }));
  expect(await screen.findByText('Вход в установку')).toBeInTheDocument();
});

test('decodeBase64 rejects broken input instead of returning empty bytes', () => {
  expect(decodeBase64('***')).toBeNull();
  expect(Array.from(decodeBase64(BINARY.toString('base64')))).toEqual(Array.from(BINARY));
});

// ---------- полнота предпросмотра ----------

const meta = (name, bytes) => ({ name, sha256: sha(bytes), size: bytes.length });
const content = (name, bytes) => ({ ...meta(name, bytes), content_b64: bytes.toString('base64') });

function withPreview(over) {
  const base = planView();
  return { preview: { ...base.preview, ...over } };
}

function twoAttachments(contents) {
  const base = planView();
  return {
    preview: { ...base.preview, attachments: [meta('a.bin', BINARY), meta('b.txt', SECOND)] },
    attachment_contents: contents,
  };
}

test.each([
  ['a declared attachment without its bytes', { attachment_contents: [] }],
  ['bytes of an undeclared attachment', { attachment_contents: [content('scan<img src=x>.bin', BINARY), content('extra.bin', SECOND)] }],
  ['bytes under another name', { attachment_contents: [content('other.bin', BINARY)] }],
  ['bytes with another SHA-256', { attachment_contents: [{ ...content('scan<img src=x>.bin', BINARY), sha256: sha(SECOND) }] }],
  ['bytes with another declared size', { attachment_contents: [{ ...content('scan<img src=x>.bin', BINARY), size: BINARY.length + 1 }] }],
  ['attachments in another order', twoAttachments([content('b.txt', SECOND), content('a.bin', BINARY)])],
  ['no attachment list in the preview', withPreview({ attachments: undefined })],
  ['no target policy', withPreview({ target_policy: undefined })],
  ['no context', withPreview({ context: undefined })],
  ['a context without an organization', withPreview({ context: { ...planView().preview.context, organization_ref: '' } })],
  ['no external calls list', withPreview({ external_calls: undefined })],
  ['an empty preview', { preview: {} }],
  ['an unknown status', { status: 'done' }],
])('a preview with %s is refused and cannot be approved', async (_name, over) => {
  const { calls } = installServer({ plan: planView(over) });
  const dialog = await openPlans();
  await loadPlan();
  expect(await within(dialog).findByText(REFUSED)).toBeInTheDocument();
  expect(within(dialog).queryByTestId('plan-hash')).not.toBeInTheDocument();
  expect(within(dialog).queryByRole('button', { name: /Одобрить этот план/ })).not.toBeInTheDocument();
  expect(approveCalls(calls)).toHaveLength(0);
});

test('two attachments in the declared order are shown and can be approved', async () => {
  const { calls } = installServer({ plan: planView(twoAttachments([content('a.bin', BINARY), content('b.txt', SECOND)])) });
  const dialog = await openPlans();
  await loadPlan();
  expect(await within(dialog).findByText('Вложение 2: b.txt')).toBeInTheDocument();
  const button = within(dialog).getByRole('button', { name: /Одобрить этот план/ });
  expect(button).toBeEnabled();
  fireEvent.click(button);
  expect(await within(dialog).findByText('План одобрен')).toBeInTheDocument();
  expect(approveCalls(calls)).toHaveLength(1);
});

// ---------- подтверждение одобрения ----------

const reply = (body) => () => ({ ok: true, status: 200, json: async () => body });
const approvedView = (over = {}) => planView({ status: 'approved', approved_by: ADMIN.id, approved_at: 'now', ...over });

test.each([
  ['the previous planned state', reply(planView())],
  ['approved with broken bytes', reply(approvedView({ payload_b64: '***' }))],
  ['approved with another hash', reply(approvedView({ plan_hash: 'b'.repeat(64) }))],
  ['approved for another plan', reply(approvedView({ plan_id: OTHER_ID }))],
  ['approved without attachment bytes', reply(approvedView({ attachment_contents: [] }))],
  ['a server error', () => problem(500, 'internal_error')],
  [
    'a broken connection',
    () => {
      throw new TypeError('Failed to fetch');
    },
  ],
])('an answer with %s is not reported as approved', async (_name, approveReply) => {
  const { calls } = installServer({ approveReply });
  const dialog = await openPlans();
  await loadPlan();
  fireEvent.click(await within(dialog).findByRole('button', { name: /Одобрить этот план/ }));
  expect(await within(dialog).findByText(UNCONFIRMED)).toBeInTheDocument();
  expect(within(dialog).queryByText('План одобрен')).not.toBeInTheDocument();
  expect(within(dialog).queryByTestId('plan-hash')).not.toBeInTheDocument();
  expect(within(dialog).queryByRole('button', { name: /Одобрить этот план/ })).not.toBeInTheDocument();
  expect(planCalls(calls).map((call) => call.method)).toEqual(['GET', 'POST']);
  // Состояние узнаётся только явной повторной загрузкой.
  fireEvent.click(within(dialog).getByRole('button', { name: /Загрузить план/ }));
  expect(await within(dialog).findByTestId('plan-hash')).toHaveTextContent(HASH);
  expect(planCalls(calls).map((call) => call.method)).toEqual(['GET', 'POST', 'GET']);
});

// ---------- смена рабочего контекста ----------

test('a context change on the same account drops the preview until an explicit reload', async () => {
  const { calls } = installServer();
  const dialog = await openPlans();
  await loadPlan();
  expect(await within(dialog).findByTestId('plan-hash')).toBeInTheDocument();
  act(() => notifyWorkspaceContextChanged());
  expect(within(dialog).queryByTestId('plan-hash')).not.toBeInTheDocument();
  expect(within(dialog).queryByText(/личные данные/)).not.toBeInTheDocument();
  expect(within(dialog).getByText(/Рабочий контекст изменился/)).toBeInTheDocument();
  expect(within(dialog).queryByRole('button', { name: /Одобрить этот план/ })).not.toBeInTheDocument();
  expect(approveCalls(calls)).toHaveLength(0);
  fireEvent.click(within(dialog).getByRole('button', { name: /Загрузить план/ }));
  expect(await within(dialog).findByRole('button', { name: /Одобрить этот план/ })).toBeEnabled();
  expect(approveCalls(calls)).toHaveLength(0);
});

test('a preview requested before a context change is not shown when it arrives', async () => {
  let release;
  const { calls } = installServer({
    reviewReply: () =>
      new Promise((resolve) => {
        release = () => resolve({ ok: true, status: 200, json: async () => planView() });
      }),
  });
  const dialog = await openPlans();
  await loadPlan();
  await waitFor(() => expect(release).toBeDefined());
  act(() => notifyWorkspaceContextChanged());
  await act(async () => release());
  expect(within(dialog).queryByTestId('plan-hash')).not.toBeInTheDocument();
  expect(within(dialog).getByText(/Рабочий контекст изменился/)).toBeInTheDocument();
  expect(approveCalls(calls)).toHaveLength(0);
});

test('an approval answer after a context change does not bring the old preview back', async () => {
  let release;
  const { calls } = installServer({
    approveReply: () =>
      new Promise((resolve) => {
        release = () => resolve({ ok: true, status: 200, json: async () => approvedView() });
      }),
  });
  const dialog = await openPlans();
  await loadPlan();
  fireEvent.click(await within(dialog).findByRole('button', { name: /Одобрить этот план/ }));
  await waitFor(() => expect(release).toBeDefined());
  act(() => notifyWorkspaceContextChanged());
  await act(async () => release());
  expect(within(dialog).queryByTestId('plan-hash')).not.toBeInTheDocument();
  expect(within(dialog).queryByText('План одобрен')).not.toBeInTheDocument();
  expect(within(dialog).getByText(/Ответ на одобрение пришёл после сброса окна/)).toBeInTheDocument();
  expect(approveCalls(calls)).toHaveLength(1);
});

// ---------- Итог исполнения ----------

const step = (name, state, extra = {}) => ({ name, state, ...extra });
const NO_RETRY = /Повтор|Исполнить|Запустить/i;
const NO_EFFECTS_PROMISE = /не выполнен|не исполнен|эффектов нет|ничего не выполн/i;

async function showOutcome(over) {
  const { calls } = installServer({ plan: planView(over) });
  const dialog = await openPlans();
  await loadPlan();
  const block = await within(dialog).findByTestId('execution-outcome');
  return { calls, dialog, block };
}

test('unknown shows the need to reconcile and lists done and unconfirmed steps apart', async () => {
  const { dialog, block } = await showOutcome({
    status: 'unknown',
    error_code: 'outcome_unknown',
    steps: [step('reserve_number', 'completed'), step('send', 'started')],
  });
  expect(block).toHaveTextContent('Исход неизвестен. Часть шагов могла выполниться');
  expect(block).toHaveTextContent('нужна ручная сверка с внешней системой');
  expect(block).toHaveTextContent('Подтверждённо выполнены:reserve_number');
  expect(block).toHaveTextContent('Исход не подтверждён:send');
  expect(block).toHaveTextContent('Этот план повторно не исполняется');
  expect(within(dialog).getByText('send: начат, исход не подтверждён')).toBeInTheDocument();
  expect(within(dialog).getByText('reserve_number: выполнен')).toBeInTheDocument();
  expect(within(dialog).queryByRole('button', { name: /Одобрить этот план/ })).not.toBeInTheDocument();
  expect(within(dialog).queryByRole('button', { name: NO_RETRY })).not.toBeInTheDocument();
  expect(dialog.textContent).not.toMatch(NO_EFFECTS_PROMISE);
});

test('an interrupted plan names the server restart', async () => {
  const { block } = await showOutcome({ status: 'unknown', error_code: 'interrupted', steps: [step('send', 'started')] });
  expect(block).toHaveTextContent('Код: interrupted (исполнение прервано перезапуском сервера)');
});

test('unknown with an empty journal does not read as no effects', async () => {
  const { block } = await showOutcome({ status: 'unknown', error_code: 'outcome_unknown', steps: [] });
  expect(block).toHaveTextContent('Шаги не записаны. Это не доказывает отсутствие эффектов.');
  expect(block).not.toHaveTextContent('Подтверждённо выполнены');
  expect(block).not.toHaveTextContent('Исход не подтверждён:');
});

test('failed with a finished step says its effects could remain', async () => {
  const { dialog, block } = await showOutcome({
    status: 'failed',
    error_code: 'not_sent',
    steps: [step('reserve_number', 'completed'), step('send', 'not_sent')],
  });
  expect(within(dialog).getByText('завершён с ошибкой')).toBeInTheDocument();
  expect(block).toHaveTextContent('Исполнение завершилось ошибкой.');
  expect(block).toHaveTextContent('Эти шаги выполнены, их эффекты могли остаться:reserve_number');
  expect(block).not.toHaveTextContent('Завершённых шагов в журнале нет');
  expect(block).not.toHaveTextContent('Исход не подтверждён:');
  expect(within(dialog).getByText('send: не отправлен, исполнитель это подтвердил')).toBeInTheDocument();
  expect(within(dialog).queryByRole('button', { name: NO_RETRY })).not.toBeInTheDocument();
  expect(dialog.textContent).not.toMatch(NO_EFFECTS_PROMISE);
});

test.each([
  ['no steps', []],
  ['only a step that was not sent', [step('send', 'not_sent')]],
])('failed with %s promises nothing about effects', async (_name, steps) => {
  const { dialog, block } = await showOutcome({ status: 'failed', error_code: 'context_changed', steps });
  expect(block).toHaveTextContent('Завершённых шагов в журнале нет.');
  expect(block).toHaveTextContent('контекст оператора изменился');
  expect(dialog.textContent).not.toMatch(NO_EFFECTS_PROMISE);
});

test('a started step of a failed plan is not hidden', async () => {
  const { dialog, block } = await showOutcome({ status: 'failed', error_code: 'aborted', steps: [step('send', 'started')] });
  expect(block).toHaveTextContent('Исход не подтверждён:send');
  expect(within(dialog).getByText('send: начат, исход не подтверждён')).toBeInTheDocument();
});

test.each(['__proto__', 'constructor', 'toString', 'hasOwnProperty', '<img src=x onerror="window.__pwned=1">'])(
  'an unknown step state and error code %s stay plain text',
  async (value) => {
    const { dialog, block } = await showOutcome({ status: 'unknown', error_code: value, steps: [step('send', value)] });
    expect(block).toHaveTextContent(`Код: ${value}`);
    expect(block.textContent).not.toContain(`Код: ${value} (`);
    expect(block).toHaveTextContent('Исход не подтверждён:send');
    expect(within(dialog).getByText(`send: неизвестное состояние: ${value}`)).toBeInTheDocument();
    expect(dialog.querySelector('img[src="x"]')).toBeNull();
    expect(window.__pwned).toBeUndefined();
  },
);

test('a missing error code is reported as missing', async () => {
  const { block } = await showOutcome({ status: 'failed', error_code: null, steps: [] });
  expect(block).toHaveTextContent('Код не передан');
});

test.each([[42], [true], [{ code: 'x' }], [['x']], ['']])('an error code %j is refused as an incomplete answer', async (value) => {
  installServer({ plan: planView({ status: 'unknown', error_code: value }) });
  const dialog = await openPlans();
  await loadPlan();
  expect(await within(dialog).findByText(REFUSED)).toBeInTheDocument();
  expect(within(dialog).queryByTestId('execution-outcome')).not.toBeInTheDocument();
  expect(within(dialog).queryByTestId('plan-hash')).not.toBeInTheDocument();
});

test('result, reference and detail never reach the window', async () => {
  const { dialog } = await showOutcome({
    status: 'unknown',
    error_code: 'outcome_unknown',
    result: { completed_calls: ['RESULT_MARKER'], reference: 'REFERENCE_MARKER' },
    reference: 'REFERENCE_MARKER',
    detail: 'DETAIL_MARKER',
    steps: [step('send', 'started', { reference: 'STEP_REFERENCE_MARKER', detail: 'STEP_DETAIL_MARKER' })],
  });
  expect(dialog.textContent).not.toMatch(/_MARKER/);
});

test('a 403 on read shows no snapshot and drops the shown outcome', async () => {
  let refuse = false;
  const plan = planView({ status: 'unknown', error_code: 'outcome_unknown', steps: [step('send', 'started')] });
  const { calls } = installServer({ plan, reviewReply: () => (refuse ? problem(403, 'forbidden') : { ok: true, status: 200, json: async () => plan }) });
  const dialog = await openPlans();
  await loadPlan();
  expect(await within(dialog).findByTestId('execution-outcome')).toBeInTheDocument();
  refuse = true;
  fireEvent.click(within(dialog).getByRole('button', { name: /Загрузить план/ }));
  expect(await within(dialog).findByText(/Нового снимка плана нет, текущее состояние этим ответом не подтверждено/)).toBeInTheDocument();
  expect(within(dialog).getByText(/Нужны права администратора установки/)).toBeInTheDocument();
  expect(within(dialog).queryByTestId('execution-outcome')).not.toBeInTheDocument();
  expect(within(dialog).queryByTestId('plan-hash')).not.toBeInTheDocument();
  expect(dialog.textContent).not.toMatch(/send/);
  expect(planCalls(calls).map((call) => call.method)).toEqual(['GET', 'GET']);
});

test('a 403 refusal to approve does not get the read text', async () => {
  installServer({ approveReply: () => problem(403, 'forbidden') });
  const dialog = await openPlans();
  await loadPlan();
  fireEvent.click(await within(dialog).findByRole('button', { name: /Одобрить этот план/ }));
  expect(await within(dialog).findByText(/Нужны права администратора установки/)).toBeInTheDocument();
  expect(within(dialog).queryByText(/Нового снимка плана нет/)).not.toBeInTheDocument();
});

const SHOWN_OUTCOME = { status: 'failed', error_code: 'aborted', steps: [step('reserve_number', 'completed')] };

test('another plan id drops the outcome and nothing is stored in the browser', async () => {
  const { dialog } = await showOutcome(SHOWN_OUTCOME);
  expect(JSON.stringify({ ...localStorage, ...sessionStorage })).not.toMatch(/reserve_number|aborted/);
  fireEvent.change(screen.getByLabelText('Идентификатор плана'), { target: { value: OTHER_ID } });
  expect(within(dialog).queryByTestId('execution-outcome')).not.toBeInTheDocument();
});

test('a context change drops the outcome', async () => {
  const { dialog } = await showOutcome(SHOWN_OUTCOME);
  act(() => notifyWorkspaceContextChanged());
  expect(within(dialog).queryByTestId('execution-outcome')).not.toBeInTheDocument();
});

test('closing the window drops the outcome', async () => {
  const { dialog } = await showOutcome(SHOWN_OUTCOME);
  fireEvent.click(within(dialog).getByRole('button', { name: /Close|Закрыть/ }));
  await waitFor(() => expect(screen.queryByTestId('execution-outcome')).not.toBeInTheDocument());
});

test('logout drops the outcome', async () => {
  await showOutcome(SHOWN_OUTCOME);
  fireEvent.click(screen.getByTestId('account-menu'));
  fireEvent.click(await screen.findByText('Выйти'));
  expect(await screen.findByText('Вход в установку')).toBeInTheDocument();
  expect(screen.queryByTestId('execution-outcome')).not.toBeInTheDocument();
});

test.each([
  ['planned', [], 'подготовлен, ждёт одобрения', null],
  ['approved', [], 'одобрен', null],
  ['inflight', [step('send', 'started')], 'исполняется', 'send: начат, исполняется'],
  ['succeeded', [step('send', 'completed')], 'исполнен', 'send: выполнен'],
])('%s has no outcome block', async (status, steps, label, row) => {
  installServer({ plan: planView({ status, steps }) });
  const dialog = await openPlans();
  await loadPlan();
  expect(await within(dialog).findByText(label)).toBeInTheDocument();
  if (row) expect(within(dialog).getByText(row)).toBeInTheDocument();
  expect(within(dialog).queryByTestId('execution-outcome')).not.toBeInTheDocument();
  const approve = within(dialog).queryByRole('button', { name: /Одобрить этот план/ });
  if (status === 'planned') expect(approve).toBeEnabled();
  else expect(approve).not.toBeInTheDocument();
});

// ---------- Код конфликта с сервера ----------

test.each(['constructor', 'toString', '__proto__', 'hasOwnProperty', 'unknown_code'])(
  'a 409 with the code %s shows the server detail as text',
  async (code) => {
    installServer({ approveReply: () => problem(409, code, 'Подробность от сервера') });
    const dialog = await openPlans();
    await loadPlan();
    fireEvent.click(await within(dialog).findByRole('button', { name: /Одобрить этот план/ }));
    expect(await within(dialog).findByText('Подробность от сервера')).toBeInTheDocument();
  },
);

test.each(['constructor', 'toString', '__proto__', 'unknown_code'])(
  'a 409 with the code %s and no detail shows the general conflict text',
  async (code) => {
    installServer({ reviewReply: () => problem(409, code) });
    const dialog = await openPlans();
    await loadPlan();
    expect(await within(dialog).findByText('Конфликт состояния плана.')).toBeInTheDocument();
  },
);

test('a 409 detail that looks like HTML stays text', async () => {
  const markup = '<img src=x onerror="window.__pwned=1">';
  installServer({ approveReply: () => problem(409, 'constructor', markup) });
  const dialog = await openPlans();
  await loadPlan();
  fireEvent.click(await within(dialog).findByRole('button', { name: /Одобрить этот план/ }));
  expect(await within(dialog).findByText(markup)).toBeInTheDocument();
  expect(dialog.querySelector('img[src="x"]')).toBeNull();
  expect(window.__pwned).toBeUndefined();
});
