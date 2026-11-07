// Предпросмотр и одобрение плана операции администратором установки.
//
// План загружается и одобряется только явным нажатием. На сервер уходит хеш
// того предпросмотра, который сейчас на экране; после ответа об ошибке план
// не перезагружается сам. Содержимое плана недоверенное: оно выводится как
// текст, HTML и XML не исполняются. Документы не сохраняются ни в браузере,
// ни в кеше: состояние живёт только в открытом окне и сбрасывается при его
// закрытии, смене идентификатора, смене рабочего контекста в этой вкладке и
// выходе.
import React, { useEffect, useRef, useState } from 'react';
import { Alert, Button, Descriptions, Input, List, Modal, Space, Tag, Typography } from 'antd';
import { DownloadOutlined } from '@ant-design/icons';
import { saveBlobResponse } from '../../downloads';
import { useAuth } from '../Auth/AuthGate';
import { useWorkspaceContextVersion } from '../../workspaceContext';
import { approvePlan, fetchPlan, PLAN_ID_RE, UNCONFIRMED, utf8Text } from './planReviewApi';

const { Text, Paragraph } = Typography;

const TEXT_LIMIT = 20000;

const STATUS_LABELS = {
  planned: 'подготовлен, ждёт одобрения',
  approved: 'одобрен',
  inflight: 'исполняется',
  succeeded: 'исполнен',
  // failed может сохранять выполненные шаги, отсутствие эффектов не обещается.
  failed: 'завершён с ошибкой',
  unknown: 'исход неизвестен',
};

// Значения приходят с сервера: подписи берутся из Map, чтобы __proto__,
// constructor и toString не находили наследуемые свойства объекта.
const STEP_LABELS = new Map([
  ['completed', 'выполнен'],
  ['not_sent', 'не отправлен, исполнитель это подтвердил'],
]);

const ERROR_CODE_LABELS = new Map([
  ['outcome_unknown', 'исход внешнего вызова не подтверждён'],
  ['interrupted', 'исполнение прервано перезапуском сервера'],
  ['aborted', 'исполнение прервано, следующий внешний вызов не начат'],
  ['not_sent', 'следующий внешний вызов не начат'],
  ['context_changed', 'контекст оператора изменился, следующий внешний вызов не начат'],
]);

const NO_SNAPSHOT_TEXT = 'Нового снимка плана нет, текущее состояние этим ответом не подтверждено.';

function stepLabel(state, planStatus) {
  if (state === 'started') return planStatus === 'inflight' ? 'начат, исполняется' : 'начат, исход не подтверждён';
  return STEP_LABELS.get(state) ?? `неизвестное состояние: ${state}`;
}

const ERROR_TEXTS = {
  401: 'Сессия закончилась. Войдите снова.',
  403: 'Нужны права администратора установки.',
  404: 'План не найден.',
  410: 'Срок плана истёк. Одобрить его нельзя.',
};

// Код приходит с сервера: Map не находит наследуемые свойства объекта.
const CONFLICT_TEXTS = new Map([
  ['plan_hash_mismatch', 'Хеш на экране не совпадает с сохранёнными байтами плана. План не одобрен. Загрузите его заново и проверьте ещё раз.'],
  ['plan_state', 'План уже не ждёт одобрения. Загрузите его заново, чтобы увидеть текущее состояние.'],
]);

const UNCONFIRMED_TEXT =
  'Результат одобрения не удалось подтвердить: ответ сервера не показывает одобренный план с этим хешем. План мог быть одобрен. Загрузите его заново, чтобы увидеть текущее состояние.';

function errorText(err) {
  if (err.code === UNCONFIRMED) return UNCONFIRMED_TEXT;
  if (err.status === 409) return CONFLICT_TEXTS.get(err.code) || err.detail || 'Конфликт состояния плана.';
  return ERROR_TEXTS[err.status] || err.detail || `Сервер ответил HTTP ${err.status}`;
}

function Bytes({ label, bytes, size, sha256, filename }) {
  const text = utf8Text(bytes);
  const sizeOk = bytes.length === size;
  return (
    <Space direction="vertical" style={{ width: '100%' }}>
      <Space wrap>
        <Text strong>{label}</Text>
        <Text>{bytes.length} байт</Text>
        {!sizeOk && <Tag color="red">размер не совпадает с заявленным ({size})</Tag>}
        <Button
          size="small"
          icon={<DownloadOutlined />}
          onClick={() => saveBlobResponse({ data: new Blob([bytes], { type: 'application/octet-stream' }), headers: {} }, { fallbackFilename: filename })}
        >
          Скачать точные байты
        </Button>
      </Space>
      <Text type="secondary" copyable>
        SHA-256 {sha256}
      </Text>
      {text === null ? (
        <Text type="secondary">Не текст UTF-8: содержимое доступно только скачиванием.</Text>
      ) : (
        <pre data-testid={`${filename}-text`} style={{ maxHeight: 240, overflow: 'auto', whiteSpace: 'pre-wrap', margin: 0 }}>
          {text.length > TEXT_LIMIT ? `${text.slice(0, TEXT_LIMIT)}\n... показаны первые ${TEXT_LIMIT} знаков, полностью в файле` : text}
        </pre>
      )}
    </Space>
  );
}

function StepNames({ title, names }) {
  if (names.length === 0) return null;
  return (
    <div>
      <Text strong>{title}</Text>
      <ul style={{ margin: 0 }}>
        {names.map((name, index) => (
          <li key={index}>{name}</li>
        ))}
      </ul>
    </div>
  );
}

// Итог считается только из status, error_code и steps текущего снимка. result,
// reference и тексты ошибок сюда не попадают. Шаг, про который неизвестно, что
// он выполнен или не отправлен, считается неподтверждённым.
function ExecutionOutcome({ plan }) {
  if (plan.status !== 'failed' && plan.status !== 'unknown') return null;
  const isUnknown = plan.status === 'unknown';
  const completed = plan.steps.filter((step) => step.state === 'completed').map((step) => step.name);
  const unconfirmed = plan.steps
    .filter((step) => step.state !== 'completed' && step.state !== 'not_sent')
    .map((step) => step.name);
  const code = plan.error_code;
  return (
    <Alert
      data-testid="execution-outcome"
      type={isUnknown ? 'warning' : 'error'}
      showIcon
      message="Итог исполнения"
      description={
        <Space direction="vertical" style={{ width: '100%' }}>
          <Text>
            {isUnknown
              ? 'Исход неизвестен. Часть шагов могла выполниться. Автоматического повтора нет, нужна ручная сверка с внешней системой.'
              : 'Исполнение завершилось ошибкой.'}
          </Text>
          <StepNames
            title={isUnknown ? 'Подтверждённо выполнены:' : 'Эти шаги выполнены, их эффекты могли остаться:'}
            names={completed}
          />
          <StepNames title="Исход не подтверждён:" names={unconfirmed} />
          {!isUnknown && completed.length === 0 && <Text>Завершённых шагов в журнале нет.</Text>}
          {isUnknown && plan.steps.length === 0 && <Text>Шаги не записаны. Это не доказывает отсутствие эффектов.</Text>}
          <Text>Этот план повторно не исполняется. Новый план создаётся только после сверки и с отдельным одобрением.</Text>
          <Text type="secondary">
            {code ? `Код: ${code}` : 'Код не передан'}
            {code && ERROR_CODE_LABELS.has(code) ? ` (${ERROR_CODE_LABELS.get(code)})` : ''}
          </Text>
        </Space>
      }
    />
  );
}

function PlanView({ plan, payload, attachments }) {
  const preview = plan.preview;
  const { context, target_policy: policy } = preview;
  // Списки уже проверены по форме: пустой список здесь действительно пуст.
  const join = (items) => (items.length ? items.join(', ') : 'нет');
  return (
    <Space direction="vertical" style={{ width: '100%' }}>
      <Descriptions size="small" bordered column={1}>
        <Descriptions.Item label="План">{plan.plan_id}</Descriptions.Item>
        <Descriptions.Item label="Состояние">{STATUS_LABELS[plan.status] || plan.status}</Descriptions.Item>
        <Descriptions.Item label="Действует до">{plan.expires_at}</Descriptions.Item>
        <Descriptions.Item label="Создан">{plan.created_at}</Descriptions.Item>
        <Descriptions.Item label="Ключ интеграции">{plan.client_id}</Descriptions.Item>
        <Descriptions.Item label="Проверка хеша на сервере">
          {plan.hash_verified ? <Tag color="green">байты совпадают с хешем</Tag> : <Tag color="red">байты изменены</Tag>}
        </Descriptions.Item>
        <Descriptions.Item label="Хеш плана">
          <Text code data-testid="plan-hash">{plan.plan_hash}</Text>
        </Descriptions.Item>
        {plan.approved_by && (
          <Descriptions.Item label="Одобрил">
            {plan.approved_by} {plan.approved_at || ''}
          </Descriptions.Item>
        )}
        <Descriptions.Item label="Возможность">{preview.capability_id}</Descriptions.Item>
        <Descriptions.Item label="Адресат">{preview.target}</Descriptions.Item>
        <Descriptions.Item label="Контекст">
          {`${context.contour}, организация ${context.organization_ref}`}
          {context.is_ref ? `, ИС ${context.is_ref}` : ''}
          {`, сертификат ${context.certificate_thumbprint}, поколение ${context.generation}, привязка ${context.binding_epoch}`}
        </Descriptions.Item>
        <Descriptions.Item label="Политика цели">
          {`${policy.effect}; scopes: ${join(policy.scopes)}; gates: ${join(policy.gates)}; последствия: ${join(policy.side_effects)}`}
        </Descriptions.Item>
      </Descriptions>
      <Text strong>Внешние вызовы</Text>
      <List
        size="small"
        bordered
        dataSource={preview.external_calls}
        locale={{ emptyText: 'нет' }}
        renderItem={(item, index) => (
          <List.Item key={index}>
            {item.name}: {join(item.side_effects)}
          </List.Item>
        )}
      />
      <ExecutionOutcome plan={plan} />
      {plan.steps.length > 0 && (
        <>
          <Text strong>Шаги исполнения</Text>
          <List
            size="small"
            bordered
            dataSource={plan.steps}
            renderItem={(item, index) => (
              <List.Item key={index}>
                {item.name}: {stepLabel(item.state, plan.status)}
              </List.Item>
            )}
          />
        </>
      )}
      <Bytes
        label="Данные запроса"
        bytes={payload}
        size={preview.payload_size}
        sha256={preview.payload_sha256}
        filename={`${plan.plan_id}-payload.bin`}
      />
      {attachments.map((item, index) => (
        <Bytes
          key={index}
          label={`Вложение ${index + 1}: ${item.name}`}
          bytes={item.bytes}
          size={item.size}
          sha256={item.sha256}
          filename={`${plan.plan_id}-attachment-${index + 1}.bin`}
        />
      ))}
    </Space>
  );
}

// Всё состояние живёт в теле окна: destroyOnHidden уничтожает его при закрытии.
function PlanReviewBody() {
  const { refresh } = useAuth();
  const contextVersion = useWorkspaceContextVersion();
  const [planId, setPlanId] = useState('');
  const [view, setView] = useState(null);
  const [error, setError] = useState('');
  const [done, setDone] = useState('');
  const [loading, setLoading] = useState(false);
  const [approving, setApproving] = useState(false);
  const sending = useRef(false);
  const generation = useRef(0);
  const seenContext = useRef(contextVersion);

  const clear = () => {
    generation.current += 1;
    setView(null);
    setError('');
    setDone('');
    setLoading(false);
  };

  const reset = (next) => {
    clear();
    setPlanId(next);
  };

  // Контекст сменился в этой вкладке: прежний предпросмотр и поздние ответы
  // на него больше не показываются, одобрить можно только после новой загрузки.
  useEffect(() => {
    if (seenContext.current === contextVersion) return;
    seenContext.current = contextVersion;
    clear();
    setError('Рабочий контекст изменился. Предпросмотр сброшен: загрузите план заново.');
  }, [contextVersion]);

  const fail = (err, note = '') => {
    setError(note ? `${errorText(err)} ${note}` : errorText(err));
    if (err.status === 401) refresh();
  };

  const load = async () => {
    const id = planId.trim();
    const current = ++generation.current;
    const loadedContext = contextVersion;
    setLoading(true);
    setView(null);
    setError('');
    setDone('');
    try {
      const loaded = await fetchPlan(id);
      if (current !== generation.current) return;
      setView({ ...loaded, contextVersion: loadedContext });
    } catch (err) {
      // Прежний снимок уже снят, новый журнал не придумывается.
      if (current === generation.current) fail(err, err.status === 403 ? NO_SNAPSHOT_TEXT : '');
    } finally {
      if (current === generation.current) setLoading(false);
    }
  };

  // Одобряется ровно тот план, что на экране, с его хешем. Повторное нажатие,
  // пока запрос идёт, ничего не отправляет.
  const approve = async (shown) => {
    if (sending.current) return;
    sending.current = true;
    const current = generation.current;
    setApproving(true);
    setError('');
    setDone('');
    try {
      const approved = await approvePlan(shown.plan.plan_id, shown.plan.plan_hash);
      if (current !== generation.current) {
        // Окно уже сброшено: прежний предпросмотр не возвращается.
        setError('Ответ на одобрение пришёл после сброса окна. Загрузите план заново, чтобы увидеть его состояние.');
        return;
      }
      setView({ ...approved, contextVersion: shown.contextVersion });
      setDone('План одобрен');
    } catch (err) {
      if (current !== generation.current) {
        setError('Ответ на одобрение пришёл после сброса окна. Загрузите план заново, чтобы увидеть его состояние.');
      } else {
        // Неподтверждённый результат: старый предпросмотр снимается, чтобы
        // не выдавать прежнее состояние за текущее.
        if (err.code === UNCONFIRMED) setView(null);
        fail(err);
      }
    } finally {
      sending.current = false;
      setApproving(false);
    }
  };

  const expired = view !== null && !(Date.parse(view.plan.expires_at) > Date.now());
  const sizesOk =
    view !== null &&
    view.payload.length === view.plan.preview.payload_size &&
    view.attachments.every((item) => item.bytes.length === item.size);
  const canApprove =
    view !== null &&
    view.contextVersion === contextVersion &&
    view.plan.status === 'planned' &&
    view.plan.hash_verified &&
    !expired &&
    sizesOk;

  return (
    <Space direction="vertical" style={{ width: '100%' }}>
      <Alert
        type="info"
        showIcon
        message="Одобрение человеком, а не независимое согласование"
        description="План одобряет администратор установки, в том числе план ключа, который он сам выпустил. Второго независимого согласующего нет. Перед одобрением проверьте байты, вложения, контекст и внешние вызовы."
      />
      <Space.Compact style={{ width: '100%' }}>
        <Input
          aria-label="Идентификатор плана"
          placeholder="plan_..."
          value={planId}
          onChange={(event) => reset(event.target.value)}
        />
        <Button onClick={load} loading={loading} disabled={!PLAN_ID_RE.test(planId.trim())}>
          Загрузить план
        </Button>
      </Space.Compact>
      {view !== null && <PlanView plan={view.plan} payload={view.payload} attachments={view.attachments} />}
      {view !== null && !view.plan.hash_verified && (
        <Alert type="error" showIcon message="Сохранённые байты плана не совпадают с его хешем. Одобрение недоступно." />
      )}
      {view !== null && expired && view.plan.status === 'planned' && (
        <Alert type="warning" showIcon message="Срок плана по часам этого компьютера истёк. Одобрение недоступно." />
      )}
      {view !== null && !sizesOk && (
        <Alert type="error" showIcon message="Размер байтов в ответе не совпадает с заявленным. Одобрение недоступно." />
      )}
      {view !== null && view.plan.status === 'planned' && (
        <Space direction="vertical" style={{ width: '100%' }}>
          <Paragraph style={{ margin: 0 }}>
            На сервер будет отправлен хеш, показанный выше. Сервер заново считает его по сохранённым байтам.
          </Paragraph>
          <Button type="primary" danger disabled={!canApprove} loading={approving} onClick={() => approve(view)}>
            Одобрить этот план
          </Button>
        </Space>
      )}
      {error && <Alert type="error" showIcon message={error} />}
      {done && <Alert type="success" showIcon message={done} />}
    </Space>
  );
}

export default function PlanReviewModal({ open, onClose }) {
  return (
    <Modal open={open} title="Одобрение плана операции" footer={null} onCancel={onClose} width={760} destroyOnHidden>
      <PlanReviewBody />
    </Modal>
  );
}
