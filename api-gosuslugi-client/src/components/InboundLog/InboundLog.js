import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Alert,
  Button,
  Card,
  Descriptions,
  Empty,
  Input,
  Space,
  Switch,
  Table,
  Tag,
  Tooltip,
  Typography,
} from 'antd';
import {
  CopyOutlined,
  DeleteOutlined,
  InboxOutlined,
  ReloadOutlined,
} from '@ant-design/icons';
import axios from 'axios';

const { Title, Text, Paragraph } = Typography;

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL || '/api';
const PUBLIC_URL_KEY = 'inbound.publicUrl';
const REFRESH_MS = 5000;

// Адреса, которые указываются в техпортале при регистрации ИС.
const SYSTEM_PATH = '/is';
const PUSH_PATH = '/push';

function normalizeBase(value) {
  const trimmed = (value || '').trim().replace(/\/+$/, '');
  if (!trimmed) return '';
  return /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
}

function formatSize(size) {
  if (size === null || size === undefined) return '';
  if (size < 1024) return `${size} Б`;
  return `${(size / 1024).toFixed(1)} КБ`;
}

function formatTime(value) {
  if (!value) return '';
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toLocaleString('ru-RU');
}

function prettyBody(record) {
  const body = record.body_text;
  if (!body) return record.size ? 'Тело не текстовое, смотрите размер и хэш.' : 'Пустое тело.';
  try {
    return JSON.stringify(JSON.parse(body), null, 2);
  } catch (error) {
    return body;
  }
}

function CopyField({ label, value }) {
  const [copied, setCopied] = useState(false);
  const onCopy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch (error) {
      setCopied(false);
    }
  };
  return (
    <Space.Compact style={{ width: '100%' }}>
      <Input readOnly value={value} addonBefore={label} />
      <Tooltip title={copied ? 'Скопировано' : 'Скопировать'}>
        <Button icon={<CopyOutlined />} onClick={onCopy} disabled={!value} />
      </Tooltip>
    </Space.Compact>
  );
}

export default function InboundLog() {
  const api = useMemo(() => axios.create({ baseURL: BACKEND_URL, timeout: 20000 }), []);
  const [messages, setMessages] = useState([]);
  const [total, setTotal] = useState(0);
  const [journal, setJournal] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [auto, setAuto] = useState(true);
  const [checking, setChecking] = useState(false);
  const [checkResult, setCheckResult] = useState(null);
  const [publicUrl, setPublicUrl] = useState(
    () => localStorage.getItem(PUBLIC_URL_KEY) || ''
  );
  const timer = useRef(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await api.get('/inbound/messages', { params: { limit: 100 } });
      setMessages(res.data.messages || []);
      setTotal(res.data.total || 0);
      setJournal(res.data.journal || '');
      setError('');
    } catch (requestError) {
      setError(
        requestError.response
          ? `Backend ответил ${requestError.response.status}. Журнал прочитать не удалось.`
          : 'Backend не отвечает. Поднимите стенд: docker compose up -d.'
      );
    } finally {
      setLoading(false);
    }
  }, [api]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    if (!auto) {
      if (timer.current) clearInterval(timer.current);
      return undefined;
    }
    timer.current = setInterval(load, REFRESH_MS);
    return () => clearInterval(timer.current);
  }, [auto, load]);

  const onPublicUrlChange = (event) => {
    const value = event.target.value;
    setPublicUrl(value);
    localStorage.setItem(PUBLIC_URL_KEY, value);
  };

  const clearJournal = async () => {
    try {
      await api.post('/inbound/clear');
      await load();
    } catch (requestError) {
      setError('Очистить журнал не удалось.');
    }
  };

  const base = normalizeBase(publicUrl);

  // Единственная честная проверка адреса: уйти в интернет и вернуться к себе.
  // Локальный запрос на 58080 не скажет ничего про домен, сертификат и прокси.
  const checkPublic = async () => {
    if (!base) {
      setError('Укажите внешний адрес: https://ваш-хост');
      return;
    }
    setChecking(true);
    setError('');
    try {
      const res = await axios.post(`${BACKEND_URL}/inbound/check-public`, null, {
        params: { url: base },
        timeout: 60000,
      });
      setCheckResult(res.data);
    } catch (requestError) {
      const detail = requestError.response && requestError.response.data;
      setError((detail && detail.detail) || 'Проверить адрес не удалось.');
      setCheckResult(null);
    } finally {
      setChecking(false);
    }
  };

  const columns = [
    {
      title: 'Время',
      dataIndex: 'received_at',
      width: 190,
      render: (value) => formatTime(value),
    },
    {
      title: 'Метод',
      dataIndex: 'method',
      width: 90,
      render: (value) => <Tag color="blue">{value}</Tag>,
    },
    { title: 'Путь', dataIndex: 'path', ellipsis: true },
    {
      title: 'Размер',
      dataIndex: 'size',
      width: 110,
      render: (value, record) => (
        <span>
          {formatSize(value)}
          {record.truncated ? <Tag color="orange" style={{ marginLeft: 6 }}>обрезано</Tag> : null}
        </span>
      ),
    },
    { title: 'Отправитель', dataIndex: 'client', width: 150 },
  ];

  return (
    <Space direction="vertical" size={24} style={{ width: '100%' }}>
      <Card
        title={
          <Space>
            <InboxOutlined />
            <span>Адреса для регистрации ИС</span>
          </Space>
        }
      >
        <Paragraph type="secondary" style={{ marginTop: 0 }}>
          Эти адреса указываются в техпортале ЕСИА при регистрации системы.
          Приёмник слушает порт 58080 контейнера inbound, внешний трафик нужно
          направить на него.
        </Paragraph>
        <Space direction="vertical" size={12} style={{ width: '100%' }}>
          <Input
            addonBefore="Внешний адрес"
            placeholder="https://ваш-хост"
            value={publicUrl}
            onChange={onPublicUrlChange}
          />
          <CopyField label="URL системы" value={base ? base + SYSTEM_PATH : ''} />
          <CopyField label="URL push" value={base ? base + PUSH_PATH : ''} />
          <Space wrap>
            <Button type="primary" loading={checking} onClick={checkPublic} disabled={!base}>
              Проверить адрес снаружи
            </Button>
            <Text type="secondary">
              Запрос уйдёт в интернет и должен вернуться на этот же приёмник.
            </Text>
          </Space>
          {checkResult ? (
            <Alert
              type={checkResult.reachable ? 'success' : 'warning'}
              showIcon
              message={
                checkResult.reachable
                  ? 'Адрес отвечает нашим приёмником'
                  : 'Адрес до приёмника не довёл'
              }
              description={
                <Space direction="vertical" size={4} style={{ width: '100%' }}>
                  {(checkResult.checks || []).map((item) => (
                    <Text key={item.path}>
                      {item.path}: {item.status ? `HTTP ${item.status}` : 'нет ответа'}
                      {item.error ? ` (${item.error})` : ''}
                      {item.ours ? ' - это мы' : ''}
                      {typeof item.seconds === 'number' ? `, ${item.seconds} с` : ''}
                    </Text>
                  ))}
                  {(checkResult.hints || []).map((hint) => (
                    <Text key={hint} type="secondary">
                      {hint}
                    </Text>
                  ))}
                  {checkResult.token_set ? (
                    <Text type="warning">
                      Задан INBOUND_TOKEN. ЕПГУ про него не знает и получит 401: для
                      публичного адреса общий секрет не годится.
                    </Text>
                  ) : null}
                  <Text type="secondary">
                    Доверенные прокси: {checkResult.trusted_proxies || 'не заданы'}
                  </Text>
                </Space>
              }
            />
          ) : null}
        </Space>
      </Card>

      <Card
        title={
          <Space>
            <span>Входящие запросы</span>
            <Text type="secondary" style={{ fontWeight: 400 }}>
              всего в журнале: {total}
            </Text>
          </Space>
        }
        extra={
          <Space>
            <Space size={6}>
              <Text type="secondary">Автообновление</Text>
              <Switch size="small" checked={auto} onChange={setAuto} />
            </Space>
            <Button icon={<ReloadOutlined />} onClick={load} loading={loading}>
              Обновить
            </Button>
            <Button icon={<DeleteOutlined />} danger onClick={clearJournal} disabled={!total}>
              Очистить
            </Button>
          </Space>
        }
      >
        {error ? <Alert type="error" showIcon message={error} style={{ marginBottom: 16 }} /> : null}
        {journal ? (
          <Paragraph type="secondary" style={{ marginTop: 0 }}>
            Журнал: <Text code>{journal}</Text>
          </Paragraph>
        ) : null}
        <Table
          rowKey="id"
          size="small"
          columns={columns}
          dataSource={messages}
          pagination={{ pageSize: 20, hideOnSinglePage: true }}
          locale={{
            emptyText: (
              <Empty
                description={
                  <Space direction="vertical" size={4}>
                    <Text>Входящих запросов пока не было.</Text>
                    <Text type="secondary">
                      Проверить приём можно так: curl -X POST http://localhost:58080/push -d
                      &quot;{'{'}&quot;orderId&quot;:1{'}'}&quot;
                    </Text>
                  </Space>
                }
              />
            ),
          }}
          expandable={{
            expandedRowRender: (record) => (
              <Space direction="vertical" size={12} style={{ width: '100%' }}>
                <Descriptions size="small" column={2} bordered>
                  <Descriptions.Item label="Идентификатор">{record.id}</Descriptions.Item>
                  <Descriptions.Item label="Content-Type">
                    {record.content_type || 'не указан'}
                  </Descriptions.Item>
                  <Descriptions.Item label="Мнемоника">
                    {record.mnemonic || 'не задана'}
                  </Descriptions.Item>
                  <Descriptions.Item label="SHA-256 тела">
                    {record.body_sha256 || 'нет тела'}
                  </Descriptions.Item>
                  {record.query ? (
                    <Descriptions.Item label="Параметры запроса" span={2}>
                      {record.query}
                    </Descriptions.Item>
                  ) : null}
                </Descriptions>
                <div>
                  <Title level={5} style={{ marginBottom: 8 }}>
                    Тело
                  </Title>
                  <pre
                    style={{
                      background: '#f8f9fa',
                      padding: 12,
                      borderRadius: 6,
                      maxHeight: 320,
                      overflow: 'auto',
                      margin: 0,
                    }}
                  >
                    {prettyBody(record)}
                  </pre>
                </div>
                <div>
                  <Title level={5} style={{ marginBottom: 8 }}>
                    Заголовки
                  </Title>
                  <pre
                    style={{
                      background: '#f8f9fa',
                      padding: 12,
                      borderRadius: 6,
                      maxHeight: 240,
                      overflow: 'auto',
                      margin: 0,
                    }}
                  >
                    {Object.entries(record.headers || {})
                      .map(([name, value]) => `${name}: ${value}`)
                      .join('\n')}
                  </pre>
                </div>
              </Space>
            ),
          }}
        />
      </Card>
    </Space>
  );
}
