import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Badge,
  Button,
  Card,
  Descriptions,
  Drawer,
  Empty,
  Modal,
  Space,
  Switch,
  Table,
  Tag,
  Tooltip,
  Typography,
} from 'antd';
import {
  CloudDownloadOutlined,
  FileTextOutlined,
  MailOutlined,
  ReloadOutlined,
  SafetyCertificateOutlined,
} from '@ant-design/icons';
import axios from 'axios';

const { Title, Text, Paragraph } = Typography;

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL || '/api';
const PAGE_SIZE = 10;

const JOB_STATE = {
  ordered: { color: 'processing', label: 'Готовится' },
  ready: { color: 'success', label: 'Получен' },
  failed: { color: 'error', label: 'Ошибка' },
  expired: { color: 'default', label: 'Просрочен' },
};

const ATTACHMENT_STATE = {
  READY: { color: 'success', label: 'Доступен' },
  DOWNLOADING: { color: 'processing', label: 'Загружается' },
  DELETED: { color: 'default', label: 'Удалён' },
  UNKNOWN: { color: 'warning', label: 'Неизвестно' },
};

function formatTime(value) {
  if (!value) return '';
  const moment = new Date(value);
  if (Number.isNaN(moment.getTime())) return String(value);
  return moment.toLocaleString('ru-RU');
}

function formatSize(size) {
  if (!size && size !== 0) return '';
  if (size < 1024) return `${size} Б`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} КБ`;
  return `${(size / 1024 / 1024).toFixed(2)} МБ`;
}

function errorText(error, fallback) {
  const detail = error && error.response && error.response.data && error.response.data.detail;
  return detail || fallback;
}

export default function Gospochta() {
  const api = useMemo(() => axios.create({ baseURL: BACKEND_URL, timeout: 60000 }), []);

  const [state, setState] = useState(null);
  const [jobs, setJobs] = useState([]);
  const [messages, setMessages] = useState([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [onlyUnread, setOnlyUnread] = useState(false);
  const [card, setCard] = useState(null);
  const [busy, setBusy] = useState('');
  const [notice, setNotice] = useState(null);

  const loadState = useCallback(async () => {
    try {
      const res = await api.get('/geps/scheduler');
      setState(res.data);
    } catch (error) {
      setNotice({ type: 'error', text: errorText(error, 'Состояние планировщика не прочиталось.') });
    }
  }, [api]);

  const loadJobs = useCallback(async () => {
    try {
      const res = await api.get('/geps/jobs', { params: { limit: 20 } });
      setJobs(res.data.jobs || []);
    } catch (error) {
      setJobs([]);
    }
  }, [api]);

  const loadMessages = useCallback(
    async (nextOffset = 0, unread = onlyUnread) => {
      try {
        const res = await api.get('/geps/messages', {
          params: { offset: nextOffset, limit: PAGE_SIZE, only_unread: unread },
        });
        setMessages(res.data.messages || []);
        setTotal(res.data.total || 0);
        setOffset(res.data.offset || 0);
      } catch (error) {
        setNotice({ type: 'error', text: errorText(error, 'Уведомления не прочитались.') });
      }
    },
    [api, onlyUnread]
  );

  useEffect(() => {
    // Читаем с тома, в ЕПГУ при этом не ходим: показать уже полученное можно
    // сколько угодно раз, а вот обращение к ГЭПС стоит суточной попытки.
    loadState();
    loadJobs();
    loadMessages(0);
  }, [loadState, loadJobs, loadMessages]);

  const switchSchedule = async (enabled) => {
    setBusy('switch');
    try {
      const res = await api.post('/geps/scheduler', { enabled });
      setState(res.data);
      setNotice(
        enabled
          ? {
              type: 'warning',
              text:
                'Автоматический забор включён. Каждое обращение к Госпочте равнозначно входу ' +
                'на портал: уведомления считаются вручёнными, и с этого момента идут сроки.',
            }
          : { type: 'info', text: 'Автоматический забор выключен.' }
      );
    } catch (error) {
      setNotice({ type: 'error', text: errorText(error, 'Переключить не удалось.') });
    } finally {
      setBusy('');
    }
  };

  const runNow = () => {
    Modal.confirm({
      title: 'Забрать почту сейчас?',
      icon: <MailOutlined />,
      content: (
        <Space direction="vertical" size={6}>
          <Text>
            Обращение к Госпочте равнозначно входу на портал. Уведомления за запрошенный
            период будут считаться вручёнными, и с этого момента пойдут процессуальные сроки.
          </Text>
          <Text type="secondary">
            Заказов списка в сутки всего пять, получений результата пятнадцать.
          </Text>
        </Space>
      ),
      okText: 'Забрать',
      cancelText: 'Отмена',
      onOk: async () => {
        setBusy('run');
        try {
          const res = await api.post('/geps/scheduler/run');
          if (res.data.skipped) {
            setNotice({ type: 'warning', text: `Такт пропущен: ${res.data.skipped}` });
          } else {
            const report = res.data;
            setNotice({
              type: 'success',
              text:
                `Заказано списков: ${report.ordered}, получено: ${report.ready}, ` +
                `новых уведомлений: ${report.new_messages}, карточек: ${report.details}.`,
            });
          }
          await Promise.all([loadState(), loadJobs(), loadMessages(0)]);
        } catch (error) {
          setNotice({ type: 'error', text: errorText(error, 'Такт не выполнился.') });
        } finally {
          setBusy('');
        }
      },
    });
  };

  const openCard = async (record) => {
    setBusy(`card:${record.message_uuid}`);
    try {
      const res = await api.get(`/geps/messages/${record.message_uuid}`);
      setCard(res.data);
    } catch (error) {
      setNotice({ type: 'error', text: errorText(error, 'Карточка не открылась.') });
    } finally {
      setBusy('');
    }
  };

  const saveAttachment = async (attachment, fileType) => {
    setBusy(`file:${attachment.attachment_uuid}:${fileType}`);
    try {
      const res = await api.post(
        `/geps/messages/${card.message_uuid}/attachments/${attachment.attachment_uuid}/save`,
        null,
        { params: { file_type: fileType } }
      );
      setNotice({
        type: 'success',
        text: `Сохранено на диск: ${res.data.path} (${formatSize(res.data.size)})`,
      });
      const fresh = await api.get(`/geps/messages/${card.message_uuid}`);
      setCard(fresh.data);
    } catch (error) {
      setNotice({ type: 'error', text: errorText(error, 'Скачать вложение не удалось.') });
    } finally {
      setBusy('');
    }
  };

  const counts = (state && state.counts) || {};
  const quota = (state && state.quota && state.quota.limits) || {};
  const lastReport = (state && state.last_report) || {};

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Card>
        <Space direction="vertical" size={12} style={{ width: '100%' }}>
          <Space align="center" wrap>
            <Title level={4} style={{ margin: 0 }}>
              <MailOutlined /> Госпочта организации
            </Title>
            {counts.unread ? <Badge count={counts.unread} overflowCount={999} /> : null}
          </Space>
          <Paragraph type="secondary" style={{ marginBottom: 0 }}>
            Уведомления ведомств из личного кабинета организации на ЕПГУ. Забираются по
            официальному API ГЭПС: список за сутки готовится около часа, потом читаются
            карточки и вложения. Всё полученное лежит на диске стенда, поэтому смотреть
            его можно сколько угодно, не обращаясь к ЕПГУ.
          </Paragraph>

          <Alert
            type="warning"
            showIcon
            message="Чтение Госпочты запускает сроки"
            description={
              'Обращение к ГЭПС приравнивается ко входу на портал: с этого момента ' +
              'уведомление считается вручённым (постановления Правительства № 606 и № 947). ' +
              'Поэтому автоматический забор выключен по умолчанию и включается вручную.'
            }
          />

          {notice ? (
            <Alert
              type={notice.type}
              showIcon
              closable
              message={notice.text}
              onClose={() => setNotice(null)}
            />
          ) : null}

          <Space wrap size={16}>
            <Space>
              <Text strong>Автоматический забор</Text>
              <Switch
                checked={Boolean(state && state.enabled)}
                loading={busy === 'switch'}
                onChange={switchSchedule}
              />
              <Text type="secondary">
                {state && state.enabled ? 'раз в сутки за предыдущий день' : 'выключен'}
              </Text>
            </Space>
            <Button
              icon={<ReloadOutlined />}
              onClick={runNow}
              loading={busy === 'run'}
              type="primary"
            >
              Забрать сейчас
            </Button>
            <Button onClick={() => { loadState(); loadJobs(); loadMessages(offset); }}>
              Обновить с диска
            </Button>
          </Space>

          <Descriptions size="small" column={{ xs: 1, sm: 2, md: 3 }} bordered>
            <Descriptions.Item label="Планировщик">
              {state && state.running ? 'работает' : 'остановлен'}
            </Descriptions.Item>
            <Descriptions.Item label="Период забора">
              {state && state.target_range
                ? `${formatTime(state.target_range.startDateTime)} - ${formatTime(
                    state.target_range.endDateTime
                  )}`
                : ''}
            </Descriptions.Item>
            <Descriptions.Item label="Заказов списка осталось">
              {quota.search ? `${quota.search.remaining} из ${quota.search.limit}` : ''}
            </Descriptions.Item>
            <Descriptions.Item label="Получений результата осталось">
              {quota.result ? `${quota.result.remaining} из ${quota.result.limit}` : ''}
            </Descriptions.Item>
            <Descriptions.Item label="Уведомлений на диске">
              {counts.messages ?? 0}
              {counts.unread ? `, непрочитанных ${counts.unread}` : ''}
            </Descriptions.Item>
            <Descriptions.Item label="Вложений сохранено">
              {counts.attachments_saved ?? 0}
            </Descriptions.Item>
          </Descriptions>

          {state && state.last_skip ? (
            <Alert type="info" showIcon message={`Последний такт пропущен: ${state.last_skip}`} />
          ) : null}
          {lastReport.at ? (
            <Text type="secondary">
              Последний такт {formatTime(lastReport.at)}: заказано {lastReport.ordered},
              получено {lastReport.ready}, новых уведомлений {lastReport.new_messages},
              карточек {lastReport.details}.
            </Text>
          ) : null}
        </Space>
      </Card>

      <Card title="Заказанные списки" size="small">
        <Table
          rowKey="id"
          size="small"
          dataSource={jobs}
          pagination={false}
          locale={{ emptyText: <Empty description="Списков ещё не заказывали" /> }}
          columns={[
            {
              title: 'Период',
              render: (_, record) =>
                `${formatTime(record.range && record.range.startDateTime)} - ${formatTime(
                  record.range && record.range.endDateTime
                )}`,
            },
            {
              title: 'Состояние',
              dataIndex: 'state',
              width: 140,
              render: (value) => {
                const view = JOB_STATE[value] || { color: 'default', label: value };
                return <Tag color={view.color}>{view.label}</Tag>;
              },
            },
            { title: 'Уведомлений', dataIndex: 'message_count', width: 120 },
            { title: 'Проверок', dataIndex: 'checks', width: 100 },
            {
              title: 'Следующая проверка',
              dataIndex: 'next_check_at',
              width: 200,
              render: (value) => formatTime(value),
            },
            {
              title: 'Причина',
              dataIndex: 'error',
              ellipsis: true,
              render: (value) => (value ? <Text type="danger">{value}</Text> : ''),
            },
          ]}
        />
      </Card>

      <Card
        title="Уведомления"
        size="small"
        extra={
          <Space>
            <Text type="secondary">Только непрочитанные</Text>
            <Switch
              checked={onlyUnread}
              onChange={(value) => {
                setOnlyUnread(value);
                loadMessages(0, value);
              }}
            />
          </Space>
        }
      >
        <Table
          rowKey="message_uuid"
          size="small"
          dataSource={messages}
          pagination={{
            current: Math.floor(offset / PAGE_SIZE) + 1,
            pageSize: PAGE_SIZE,
            total,
            showSizeChanger: false,
            size: 'small',
            onChange: (page) => loadMessages((page - 1) * PAGE_SIZE),
          }}
          locale={{
            emptyText: (
              <Empty description="Пока ничего не забирали. Нажмите «Забрать сейчас»." />
            ),
          }}
          columns={[
            {
              title: 'Отправитель',
              dataIndex: 'sender',
              width: 180,
              render: (value, record) => (
                <Space size={4}>
                  {record.is_read ? null : <Badge status="processing" />}
                  <Text strong={!record.is_read}>{value || 'без имени'}</Text>
                </Space>
              ),
            },
            { title: 'Тема', dataIndex: 'subject', ellipsis: true },
            {
              title: 'Получено',
              dataIndex: 'create_date',
              width: 180,
              render: (value) => formatTime(value),
            },
            {
              title: 'Вложения',
              width: 120,
              render: (_, record) => {
                const list = record.attachments || [];
                if (!list.length) return '';
                const saved = list.filter((item) => item.saved_path).length;
                return (
                  <Tooltip title={list.map((item) => item.file_name).join(', ')}>
                    <Tag color={saved ? 'success' : 'default'}>
                      {saved ? `${saved} из ${list.length}` : list.length}
                    </Tag>
                  </Tooltip>
                );
              },
            },
            {
              title: '',
              width: 120,
              render: (_, record) => (
                <Button
                  size="small"
                  icon={<FileTextOutlined />}
                  loading={busy === `card:${record.message_uuid}`}
                  onClick={() => openCard(record)}
                >
                  Открыть
                </Button>
              ),
            },
          ]}
        />
      </Card>

      <Drawer
        title={card ? card.subject || 'Уведомление' : 'Уведомление'}
        width={720}
        open={Boolean(card)}
        onClose={() => setCard(null)}
      >
        {card ? (
          <Space direction="vertical" size={12} style={{ width: '100%' }}>
            <Descriptions size="small" column={1} bordered>
              <Descriptions.Item label="Отправитель">{card.sender}</Descriptions.Item>
              <Descriptions.Item label="Получено">
                {formatTime(card.create_date)}
              </Descriptions.Item>
              <Descriptions.Item label="Прочитано в ЕПГУ">
                {card.is_read ? 'да' : 'нет'}
              </Descriptions.Item>
            </Descriptions>

            <div>
              <Text strong>Текст уведомления</Text>
              <Paragraph type="secondary" style={{ marginBottom: 8 }}>
                Разметка приходит из ЕПГУ как есть, поэтому показывается в изолированной
                рамке: скрипты и доступ к странице в ней запрещены.
              </Paragraph>
              <iframe
                title="Текст уведомления"
                sandbox=""
                srcDoc={card.detail ? card.detail.html : ''}
                style={{
                  width: '100%',
                  minHeight: 240,
                  border: '1px solid #f0f0f0',
                  borderRadius: 6,
                  background: '#fff',
                }}
              />
            </div>

            {card.attachments && card.attachments.length ? (
              <Table
                rowKey="attachment_uuid"
                size="small"
                pagination={false}
                dataSource={card.attachments}
                columns={[
                  { title: 'Файл', dataIndex: 'file_name', ellipsis: true },
                  {
                    title: 'Размер',
                    dataIndex: 'file_size',
                    width: 100,
                    render: (value) => formatSize(value),
                  },
                  {
                    title: 'Состояние',
                    dataIndex: 'status',
                    width: 130,
                    render: (value) => {
                      const view = ATTACHMENT_STATE[value] || { color: 'default', label: value };
                      return <Tag color={view.color}>{view.label}</Tag>;
                    },
                  },
                  {
                    title: '',
                    width: 220,
                    render: (_, item) => (
                      <Space size={4}>
                        <Button
                          size="small"
                          icon={<CloudDownloadOutlined />}
                          disabled={!item.downloadable}
                          loading={busy === `file:${item.attachment_uuid}:file`}
                          onClick={() => saveAttachment(item, 'file')}
                        >
                          {item.saved_path ? 'Скачать снова' : 'Сохранить'}
                        </Button>
                        {item.signed ? (
                          <Tooltip title="Отсоединённая подпись файла">
                            <Button
                              size="small"
                              icon={<SafetyCertificateOutlined />}
                              loading={busy === `file:${item.attachment_uuid}:sig`}
                              onClick={() => saveAttachment(item, 'sig')}
                            >
                              Подпись
                            </Button>
                          </Tooltip>
                        ) : null}
                      </Space>
                    ),
                  },
                ]}
                expandable={{
                  expandedRowRender: (item) => (
                    <Space direction="vertical" size={2}>
                      {item.saved_path ? (
                        <Text code>{item.saved_path}</Text>
                      ) : (
                        <Text type="secondary">На диск ещё не сохранялся</Text>
                      )}
                      {item.signature_path ? <Text code>{item.signature_path}</Text> : null}
                      {item.status_description ? (
                        <Text type="secondary">{item.status_description}</Text>
                      ) : null}
                    </Space>
                  ),
                }}
              />
            ) : (
              <Empty description="Вложений нет" />
            )}

            {card.statuses && card.statuses.length ? (
              <div>
                <Text strong>История статусов</Text>
                <Table
                  rowKey={(item, index) => `${item.mnemonic}-${index}`}
                  size="small"
                  pagination={false}
                  dataSource={card.statuses}
                  columns={[
                    { title: 'Статус', dataIndex: 'description', ellipsis: true },
                    {
                      title: 'Когда',
                      dataIndex: 'createDate',
                      width: 180,
                      render: (value) => formatTime(value),
                    },
                    { title: 'Кто', dataIndex: 'originator', width: 160 },
                  ]}
                />
              </div>
            ) : null}
          </Space>
        ) : null}
      </Drawer>
    </Space>
  );
}
