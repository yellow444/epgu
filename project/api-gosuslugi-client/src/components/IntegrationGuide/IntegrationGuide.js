// Экран «Гайд по интеграциям». Компонент исходно написан в repos/public
// (незафиксированная работа, guideData.js sha256
// 9a32cc1178b85eb3f95d56176f35f22ae7004c223b7901c87afd39ada2e972a0) и адаптирован:
// данные берутся из общей модели знаний knowledge.v1 (встроенная копия
// knowledge.v1.json, при наличии сервера - его набор данных).
import React, { useEffect, useId, useMemo, useState } from 'react';
import { Alert, Button, Card, Col, Input, Row, Space, Tag, Typography } from 'antd';
import bundledDataset from './knowledge.v1.json';
import { buildGuideModel, checkDataset, findGuideLocation } from './knowledgeModel';
import './IntegrationGuide.css';

const { Paragraph, Text, Title } = Typography;

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL || '/api';

// Статус самого источника, а не оценка продукта и не подтверждение каждого утверждения.
const OFFICIALITY_LABELS = {
  official: 'статус: официальный',
  official_historical: 'статус: официальный, исторический',
  official_catalog: 'статус: официальный каталог',
  operator_docs: 'статус: документация оператора',
  unofficial_implementation: 'статус: неофициальный',
  developer_experience: 'статус: опыт разработчиков',
};

// Ссылка только на корректный https-адрес; иначе название показывается текстом.
export function safeHttpsUrl(value) {
  if (typeof value !== 'string' || value !== value.trim()) return null;
  try {
    return new URL(value).protocol === 'https:' ? value : null;
  } catch (error) {
    return null;
  }
}

// ГГГГ-ММ-ДД, только существующая календарная дата; Date с часовым поясом не нужен.
export function checkedAtLabel(value) {
  const match = typeof value === 'string' ? /^(\d{4})-(\d{2})-(\d{2})$/.exec(value) : null;
  if (!match) return 'Дата сверки не указана';
  const [year, month, day] = match.slice(1).map(Number);
  const probe = new Date(Date.UTC(year, month - 1, day));
  if (probe.getUTCFullYear() !== year || probe.getUTCMonth() !== month - 1 || probe.getUTCDate() !== day) {
    return 'Дата сверки не указана';
  }
  return `Дата сверки: ${match[3]}.${match[2]}.${match[1]}`;
}

// Только собственные ключи: унаследованные (__proto__, constructor, toString) считаются неизвестными.
const own = (table, key) => (table && typeof key === 'string' && Object.prototype.hasOwnProperty.call(table, key) ? table[key] : undefined);

export function SourceLinks({ ids, sources }) {
  const list = Array.isArray(ids) ? ids : [];
  if (!list.length) return <Paragraph type="secondary">Источники не указаны.</Paragraph>;
  return (
    <>
      <Text type="secondary" className="integration-sources-note">Ссылки ведут к основаниям этого шага или заметки. Они не подтверждают сами по себе каждое утверждение.</Text>
      <ul className="integration-sources">
        {list.map((id) => {
          const source = own(sources, id);
          if (!source) return <li key={id}><Text type="secondary">Источник {id} не найден в наборе.</Text></li>;
          const url = safeHttpsUrl(source.url);
          return (
            <li key={id}>
              {url ? <a href={url} target="_blank" rel="noopener noreferrer">{source.title}</a> : <Text>{source.title}</Text>}
              <div>
                <Text type="secondary">{source.kind}, {source.section}</Text>
              </div>
              <div>
                <Tag>{own(OFFICIALITY_LABELS, source.officiality) || 'статус не указан'}</Tag>
                <Text type="secondary">{checkedAtLabel(source.checkedAt)}</Text>
              </div>
            </li>
          );
        })}
      </ul>
    </>
  );
}

function Flowchart({ flow, selected, onSelect }) {
  const markerId = useId().replace(/:/g, '');
  const height = (Math.max(...flow.nodes.map((item) => item.layout.row)) + 1) * 140;
  // Ширина по числу колонок; предел колонок проверяет checkDataset.
  const width = (Math.max(...flow.nodes.map((item) => item.layout.column)) + 1) * 260;
  const position = (item) => ({ horizontal: 130 + item.layout.column * 260, vertical: 55 + item.layout.row * 140 });
  return (
    <div className="integration-chart-scroll" role="region" aria-label={`Блок-схема: ${flow.title}`} tabIndex={0}>
      <div className="integration-chart" style={{ height, width }}>
        <svg width={width} height={height} aria-hidden="true" className="integration-chart-lines">
          <defs><marker id={markerId} markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M 0 0 L 8 4 L 0 8 z" fill="#6a7f9b" /></marker></defs>
          {flow.nodes.flatMap((item) => item.next.map((link) => {
            const from = position(item);
            const target = position(flow.nodes.find((candidate) => candidate.id === link.to));
            const middle = (from.vertical + target.vertical) / 2;
            return <path key={`${item.id}-${link.to}`} d={`M ${from.horizontal} ${from.vertical + 40} C ${from.horizontal} ${middle}, ${target.horizontal} ${middle}, ${target.horizontal} ${target.vertical - 44}`} fill="none" stroke="#6a7f9b" strokeWidth="2" markerEnd={`url(#${markerId})`} />;
          }))}
        </svg>
        {flow.nodes.map((item) => (
          <button key={item.id} type="button" className="integration-node" aria-pressed={selected === item.id} style={{ left: 20 + item.layout.column * 260, top: 15 + item.layout.row * 140 }} onClick={() => onSelect(item.id)}>
            {item.title}
          </button>
        ))}
      </div>
    </div>
  );
}

// Одна попытка получить набор данных с сервера. Результат:
// { status: 'server', dataset } - набор принят;
// { status: 'unavailable' } - сервер не ответил (сеть, нет fetch);
// { status: 'http', code } - сервер ответил ошибкой;
// { status: 'rejected', reason, total } - ответ не прошёл проверку схемой и ссылками.
async function fetchServerDataset(signal) {
  if (typeof fetch !== 'function') return { status: 'unavailable' };
  let response;
  try {
    response = await fetch(`${BACKEND_URL}/v1/knowledge/dataset`, {
      headers: { Accept: 'application/json' },
      signal,
    });
  } catch (err) {
    return { status: 'unavailable' };
  }
  if (!response) return { status: 'unavailable' };
  if (!response.ok) return { status: 'http', code: response.status };
  let data;
  try {
    data = await response.json();
  } catch (err) {
    return { status: 'rejected', reason: 'not_json', total: 1 };
  }
  const verdict = checkDataset(data);
  return verdict.ok ? { status: 'server', dataset: data } : { status: 'rejected', reason: verdict.reason, total: verdict.total };
}

const REJECT_REASONS = {
  not_json: 'ответ не является JSON',
  schema_version: 'несовместимая версия схемы',
  schema: 'не соответствуют схеме knowledge.v1',
  integrity: 'битые ссылки или неподдержанная раскладка схемы',
  validator: 'проверка не выполнена',
  render: 'не отображаются',
};

// Почему показана встроенная копия. null - причин сообщать нет (ответ ещё не пришёл).
function fallbackNote(outcome) {
  if (!outcome) return null;
  if (outcome.status === 'unavailable') return 'сервер недоступен, показана встроенная копия';
  if (outcome.status === 'http') {
    return outcome.code === 304 ? null : `сервер ответил ошибкой ${outcome.code}, показана встроенная копия`;
  }
  if (outcome.status === 'rejected') {
    const count = outcome.total > 1 ? ` (замечаний: ${outcome.total})` : '';
    return `данные сервера отклонены: ${REJECT_REASONS[outcome.reason] || 'неизвестная причина'}${count}; показана встроенная копия`;
  }
  return null;
}

// Последняя защита: если серверный набор прошёл проверку, но всё же не
// отрисовался, экран возвращается к встроенной копии, а не падает целиком.
class GuideBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { failed: false };
  }

  static getDerivedStateFromError() {
    return { failed: true };
  }

  componentDidCatch() {
    this.props.onError();
  }

  render() {
    if (this.state.failed) {
      return this.props.fallback;
    }
    return this.props.children;
  }
}

export default function IntegrationGuide() {
  // Пока сервер не ответил или его ответ отклонён, показывается встроенная копия.
  const [source, setSource] = useState({ dataset: bundledDataset, origin: 'bundled', outcome: null });

  useEffect(() => {
    let active = true;
    const controller = typeof AbortController === 'function' ? new AbortController() : null;
    fetchServerDataset(controller && controller.signal).then((outcome) => {
      if (!active) return;
      if (outcome.status === 'server') setSource({ dataset: outcome.dataset, origin: 'server', outcome });
      else setSource((current) => ({ ...current, outcome }));
    });
    return () => {
      active = false;
      if (controller) controller.abort();
    };
  }, []);

  const fallbackToBundled = () => setSource({
    dataset: bundledDataset,
    origin: 'bundled',
    outcome: { status: 'rejected', reason: 'render', total: 1 },
  });

  const broken = (
    <Alert type="error" showIcon title="Гайд не удалось показать" description="Встроенная копия набора знаний не отображается. Это ошибка сборки, сообщите разработчикам." />
  );
  return (
    <GuideBoundary key={source.origin} onError={source.origin === 'server' ? fallbackToBundled : () => {}} fallback={source.origin === 'server' ? null : broken}>
      <GuideView source={source} />
    </GuideBoundary>
  );
}

function GuideView({ source }) {
  const { FLOWS, SOURCES, PRACTICAL_NOTES, REVIEWED_AT } = useMemo(() => buildGuideModel(source.dataset), [source.dataset]);
  const [rawLocation, setRawLocation] = useState(() => findGuideLocation(window.location.hash, FLOWS));
  const [query, setQuery] = useState('');
  // Если набор данных сменился и шага больше нет, возвращаемся ко входному шагу.
  const location = FLOWS.some((item) => item.id === rawLocation.flowId && item.nodes.some((step) => step.id === rawLocation.nodeId))
    ? rawLocation
    : findGuideLocation('', FLOWS);
  const flow = FLOWS.find((item) => item.id === location.flowId);
  const selected = flow.nodes.find((item) => item.id === location.nodeId);

  useEffect(() => {
    const handleHash = () => setRawLocation(findGuideLocation(window.location.hash, FLOWS));
    window.addEventListener('hashchange', handleHash);
    return () => window.removeEventListener('hashchange', handleHash);
  }, [FLOWS]);

  const navigate = (flowId, nodeId) => {
    const target = FLOWS.find((item) => item.id === flowId);
    const step = nodeId || target.entry;
    setRawLocation({ flowId, nodeId: step });
    window.history.replaceState(null, '', `#guide/${flowId}/${step}`);
  };

  const results = useMemo(() => {
    const term = query.trim().toLocaleLowerCase('ru');
    return term ? FLOWS.flatMap((item) => item.nodes
      .filter((step) => [item.title, step.title, step.body, step.warning, ...step.checks].join(' ').toLocaleLowerCase('ru').includes(term))
      .map((step) => ({ flowId: item.id, flowTitle: item.title, step }))) : [];
  }, [query, FLOWS]);

  return (
    <Space orientation="vertical" size="large" style={{ width: '100%' }}>
      <Card>
        <Title level={2}>Гайд по интеграциям</Title>
        <Paragraph>Бесплатный раздел без платных дополнений. Кликайте блоки схемы: в карточке откроются проверки, развилки и ссылки на источники. Ссылку на выбранный шаг можно сохранить из адресной строки.</Paragraph>
        <Tag color="blue">Сверка: {REVIEWED_AT}</Tag><Tag>{FLOWS.length} маршрутов</Tag>
        <Tag color={source.origin === 'server' ? 'green' : 'default'}>{source.origin === 'server' ? 'Данные сервера' : 'Встроенная копия'}</Tag>
        {source.origin === 'bundled' && fallbackNote(source.outcome) && <Text type="secondary" className="integration-origin-note" role="status">{fallbackNote(source.outcome)}</Text>}
        <Alert style={{ marginTop: 12 }} type="warning" showIcon title="Это навигатор, а не обещание доступа" description="Схемы не охватывают все ведомственные исключения. TEST и PROD разделены; синтетические реквизиты не подтверждают полномочия. Неофициальные примеры служат подсказками для проверки и не заменяют регламент. MAX и цифровой рубль здесь документированы, но их рабочие коннекторы этим не заявлены." />
        <Input.Search style={{ marginTop: 16 }} aria-label="Поиск по всем маршрутам" placeholder="Например: нет организации, подпись, scope, Webhook, Ack" value={query} onChange={(event) => setQuery(event.target.value)} allowClear />
        {query.trim() && <div role="region" aria-label="Результаты поиска">
          <Paragraph style={{ marginTop: 12 }}>Найдено шагов: {results.length}</Paragraph>
          <Space wrap>{results.map((result) => <Button key={`${result.flowId}-${result.step.id}`} onClick={() => { navigate(result.flowId, result.step.id); setQuery(''); }}>{result.flowTitle}: {result.step.title}</Button>)}</Space>
        </div>}
      </Card>
      <nav aria-label="Маршруты интеграций"><Space wrap>{FLOWS.map((item) => <Button key={item.id} type={flow.id === item.id ? 'primary' : 'default'} aria-pressed={flow.id === item.id} onClick={() => navigate(item.id)}>{item.title}</Button>)}</Space></nav>
      <Card title={flow.title}>
        <Paragraph>{flow.summary}</Paragraph>
        <Flowchart flow={flow} selected={selected.id} onSelect={(nodeId) => navigate(flow.id, nodeId)} />
      </Card>
      <Card className="integration-detail" title={<h3 id="integration-step-title" style={{ margin: 0 }}>{selected.title}</h3>}>
        <section aria-labelledby="integration-step-title" aria-live="polite">
          <Paragraph>{selected.body}</Paragraph>
          {selected.warning && <Alert type="warning" showIcon title={selected.warning} />}
          <Title level={5}>Что проверить</Title>
          <ul>{selected.checks.map((check) => <li key={check}>{check}</li>)}</ul>
          <Title level={5}>Следующий шаг</Title>
          {selected.next.length ? <Space wrap>{selected.next.map((link) => <Button key={link.to} onClick={() => navigate(flow.id, link.to)}>{link.label}</Button>)}</Space> : <Paragraph>Конечная точка этой ветки. Выполните перечисленные проверки или получите уточнение оператора.</Paragraph>}
          <Title level={5}>Основания и источники</Title>
          <SourceLinks ids={selected.sources} sources={SOURCES} />
        </section>
      </Card>
      <Card title="Практические нюансы и расхождения">
        <Paragraph>Это отдельный слой знаний: объяснения авторов SDK, опыт внедрения и инженерные выводы. Проверяйте версию, контур и фактический обмен; воспроизводимость не подменяет разрешение оператора.</Paragraph>
        <Row gutter={[16, 16]}>{PRACTICAL_NOTES.map((note) => <Col xs={24} lg={12} key={note.id}><Card size="small" title={note.title}><Tag>{note.status}</Tag><Paragraph style={{ marginTop: 8 }}>{note.text}</Paragraph><SourceLinks ids={note.sources} sources={SOURCES} /></Card></Col>)}</Row>
      </Card>
    </Space>
  );
}
