import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Button,
  Card,
  Checkbox,
  Descriptions,
  Empty,
  Input,
  Modal,
  Result,
  Select,
  Space,
  Steps,
  Switch,
  Table,
  Tag,
  Tooltip,
  Typography,
} from 'antd';
import {
  CheckCircleOutlined,
  ClearOutlined,
  CloseCircleOutlined,
  CopyOutlined,
  DownloadOutlined,
  ExclamationCircleOutlined,
  FolderOpenOutlined,
  KeyOutlined,
  MailOutlined,
  MinusCircleOutlined,
  ReloadOutlined,
  SafetyCertificateOutlined,
  SearchOutlined,
  SaveOutlined,
  SendOutlined,
  UsbOutlined,
} from '@ant-design/icons';
import axios from 'axios';
import { LETTERS, SENDER_HINT } from '../SetupGuide/letters';

const { Title, Text, Paragraph } = Typography;
const { TextArea } = Input;

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL || '/api';
const STEP_KEY = 'wizard.step';

const OK = 'ok';
const WARN = 'warn';
const FAIL = 'fail';
const IDLE = 'idle';

const STATUS_VIEW = {
  [OK]: { color: 'success', icon: <CheckCircleOutlined />, label: 'готово' },
  [WARN]: { color: 'warning', icon: <ExclamationCircleOutlined />, label: 'внимание' },
  [FAIL]: { color: 'error', icon: <CloseCircleOutlined />, label: 'ошибка' },
  [IDLE]: { color: 'default', icon: <MinusCircleOutlined />, label: 'не проверено' },
};

function StatusTag({ state }) {
  const view = STATUS_VIEW[state] || STATUS_VIEW[IDLE];
  return (
    <Tag color={view.color} icon={view.icon}>
      {view.label}
    </Tag>
  );
}

function CopyButton({ value, title = 'Скопировать' }) {
  const [done, setDone] = useState(false);
  return (
    <Tooltip title={done ? 'Скопировано' : title}>
      <Button
        size="small"
        icon={<CopyOutlined />}
        onClick={async () => {
          try {
            await navigator.clipboard.writeText(value);
            setDone(true);
            setTimeout(() => setDone(false), 1500);
          } catch (error) {
            setDone(false);
          }
        }}
      />
    </Tooltip>
  );
}

function formatTime(value) {
  if (!value) return '';
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toLocaleTimeString('ru-RU');
}

function errorText(error, fallback) {
  if (error.response) {
    const detail = error.response.data && error.response.data.detail;
    if (typeof detail === 'string') return detail;
    return `Backend ответил ${error.response.status}.`;
  }
  return fallback;
}

export default function SetupWizard() {
  const api = useMemo(
    () => axios.create({ baseURL: BACKEND_URL, timeout: 60000 }),
    []
  );
  const [step, setStep] = useState(() => Number(localStorage.getItem(STEP_KEY) || 0));
  const [busy, setBusy] = useState('');
  const [notice, setNotice] = useState(null);

  // Шаг 1: контур
  const [version, setVersion] = useState(null);
  // Шаг 2: сертификаты
  const [certificates, setCertificates] = useState([]);
  const [currentCert, setCurrentCert] = useState(null);
  const [sources, setSources] = useState(null);
  const [linkContainer, setLinkContainer] = useState('');
  // Шаг 3: API-Key
  const [apiKey, setApiKey] = useState('');
  const [tokenState, setTokenState] = useState({ state: IDLE, detail: '' });
  // Шаг 4: почта
  const [mailConfig, setMailConfig] = useState(null);
  const [mailCheck, setMailCheck] = useState(null);
  const [mailForm, setMailForm] = useState({
    imap_host: '',
    imap_port: '993',
    smtp_host: '',
    smtp_port: '465',
    user: '',
    sender: '',
    use_ssl: true,
    password: '',
  });
  const [dotenv, setDotenv] = useState('');
  const [discovery, setDiscovery] = useState(null);
  const [messages, setMessages] = useState([]);
  const [letterId, setLetterId] = useState('testCert');
  const [letter, setLetter] = useState(LETTERS.testCert);
  // Шаг 5: итог
  const [health, setHealth] = useState({ hc: IDLE, status: IDLE, detail: '' });

  useEffect(() => {
    localStorage.setItem(STEP_KEY, String(step));
  }, [step]);

  const run = useCallback(
    async (name, action) => {
      setBusy(name);
      setNotice(null);
      try {
        return await action();
      } finally {
        setBusy('');
      }
    },
    []
  );

  const loadEnvironment = useCallback(
    () =>
      run('env', async () => {
        try {
          const res = await api.get('/version');
          // Отвечать может и старый backend, и заглушка: без hosts шаг не
          // отрисовать, поэтому считаем такой ответ отсутствием данных.
          setVersion(res.data && res.data.hosts ? res.data : null);
        } catch (error) {
          setNotice({ type: 'error', text: errorText(error, 'Backend не отвечает.') });
        }
      }),
    [api, run]
  );

  const loadCertificates = useCallback(
    () =>
      run('certs', async () => {
        try {
          const list = await api.post('/get_certificates');
          setCertificates(list.data || []);
        } catch (error) {
          setCertificates([]);
        }
        try {
          const current = await api.post('/get_current_certificate');
          setCurrentCert(current.data);
        } catch (error) {
          setCurrentCert(null);
        }
        try {
          const res = await api.get('/certsources');
          setSources(res.data && res.data.folder ? res.data : null);
        } catch (error) {
          setSources(null);
        }
      }),
    [api, run]
  );

  const loadMail = useCallback(
    () =>
      run('mail', async () => {
        try {
          const res = await api.get('/mail/config');
          const config = res.data && res.data.imap ? res.data : null;
          setMailConfig(config);
          if (config) {
            // Форма показывает то, что действует сейчас, включая значения из
            // окружения. Пароль не приходит с сервера и остаётся пустым.
            setMailForm((previous) => ({
              ...previous,
              imap_host: config.imap.host || '',
              imap_port: String(config.imap.port || 993),
              smtp_host: config.smtp.host || '',
              smtp_port: String(config.smtp.port || 465),
              user: config.user || '',
              sender: config.sender === config.user ? '' : config.sender || '',
              use_ssl: Boolean(config.use_ssl),
              password: '',
            }));
          }
        } catch (error) {
          setMailConfig(null);
        }
      }),
    [api, run]
  );

  useEffect(() => {
    loadEnvironment();
    loadCertificates();
    loadMail();
  }, [loadEnvironment, loadCertificates, loadMail]);

  // ---------- Состояния шагов ----------

  const envState = version ? OK : IDLE;
  const certState = currentCert && currentCert.certId ? OK : certificates.length ? WARN : FAIL;
  const mailState = (() => {
    if (!mailConfig) return IDLE;
    if (!mailConfig.configured) return WARN;
    if (!mailCheck) return IDLE;
    return mailCheck.imap.ok && mailCheck.smtp.ok ? OK : FAIL;
  })();
  const finalState = health.hc === OK && certState === OK && tokenState.state === OK ? OK : IDLE;

  const steps = [
    { key: 'env', title: 'Контур', icon: <ReloadOutlined />, state: envState },
    { key: 'cert', title: 'Сертификат', icon: <SafetyCertificateOutlined />, state: certState },
    { key: 'apikey', title: 'API-Key', icon: <KeyOutlined />, state: tokenState.state },
    { key: 'mail', title: 'Почта', icon: <MailOutlined />, state: mailState },
    { key: 'check', title: 'Проверка', icon: <CheckCircleOutlined />, state: finalState },
  ];

  // ---------- Действия ----------

  const selectCertificate = async (certId) => {
    await run('select', async () => {
      try {
        await api.post('/set_current_certificate', null, { params: { cert_id: certId } });
        await loadCertificates();
        setNotice({ type: 'success', text: 'Сертификат выбран текущим.' });
      } catch (error) {
        setNotice({ type: 'error', text: errorText(error, 'Выбрать сертификат не удалось.') });
      }
    });
  };

  const importCertificate = async (path) => {
    await run('import', async () => {
      try {
        const res = await api.post('/certsources/import', {
          path,
          store: 'uMy',
          link_container: linkContainer,
        });
        setNotice({
          type: 'success',
          text: `Установлен ${res.data.file}. Чтобы бэкенд увидел его в списке, перезапустите контейнер api.`,
        });
        await loadCertificates();
      } catch (error) {
        setNotice({ type: 'error', text: errorText(error, 'Установить сертификат не удалось.') });
      }
    });
  };

  const checkApiKey = async () => {
    await run('apikey', async () => {
      if (!apiKey.trim()) {
        setTokenState({ state: FAIL, detail: 'Введите API-Key: это GUID из личного кабинета ИЭП.' });
        return;
      }
      try {
        const res = await api.post('/accessTkn_esia', { api_key: apiKey.trim() });
        setTokenState({
          state: OK,
          detail: `Маркер получен, действует до ${new Date(res.data.exp * 1000).toLocaleString('ru-RU')}.`,
        });
      } catch (error) {
        setTokenState({
          state: FAIL,
          detail: errorText(error, 'Сетевая ошибка при запросе маркера.'),
        });
      }
    });
  };

  const saveMailSettings = async () => {
    await run('mailsave', async () => {
      try {
        const res = await api.post('/mail/settings', mailForm);
        setMailConfig(res.data.config);
        setDotenv(res.data.dotenv || '');
        setMailForm((previous) => ({ ...previous, password: '' }));
        setNotice({
          type: 'success',
          text: 'Настройки сохранены и действуют сразу, перезапуск не нужен.',
        });
      } catch (error) {
        setNotice({ type: 'error', text: errorText(error, 'Сохранить настройки не удалось.') });
      }
    });
  };

  const checkMail = async () => {
    // Прошлый результат убираем сразу: иначе непонятно, старая это ошибка
    // или уже новая.
    setMailCheck(null);
    await run('mailcheck', async () => {
      try {
        const res = await api.post('/mail/check');
        setMailCheck(res.data);
      } catch (error) {
        setNotice({ type: 'error', text: errorText(error, 'Проверить почту не удалось.') });
      }
    });
  };

  const resetEverything = async (options) => {
    await run('reset', async () => {
      try {
        const res = await api.post('/setup/reset', options);
        // Сессия оператора живёт в памяти основного приложения, поэтому
        // маркер и выбор сертификата чистятся отдельным вызовом.
        try {
          await api.post('/session/clear');
        } catch (error) {
          // Если сессии не было, это не ошибка сброса.
        }
        setMailConfig(res.data.config);
        setMailCheck(null);
        setDiscovery(null);
        setDotenv('');
        setMessages([]);
        setApiKey('');
        setTokenState({ state: IDLE, detail: '' });
        setHealth({ hc: IDLE, status: IDLE, detail: '' });
        setLinkContainer('');
        setMailForm({
          imap_host: '',
          imap_port: '993',
          smtp_host: '',
          smtp_port: '465',
          user: '',
          sender: '',
          use_ssl: true,
          password: '',
        });
        setStep(0);
        await loadCertificates();
        const cleared = res.data.cleared || {};
        setNotice({
          type: 'success',
          text:
            `Сброшено. Настроек стёрто: ${cleared.settings || 0}` +
            (cleared.files !== undefined ? `, файлов: ${cleared.files}` : '') +
            (cleared.inbound_messages !== undefined
              ? `, записей журнала: ${cleared.inbound_messages}`
              : '') +
            '. Вводите заново с первого шага.',
        });
      } catch (error) {
        setNotice({ type: 'error', text: errorText(error, 'Сбросить не удалось.') });
      }
    });
  };

  const confirmReset = () => {
    // Значения читаются на момент подтверждения, поэтому храним их снаружи.
    const options = { clear_inbound: false, clear_files: false };
    Modal.confirm({
      title: 'Сбросить настройку стенда',
      icon: <ExclamationCircleOutlined />,
      width: 620,
      content: (
        <Space direction="vertical" size={12} style={{ width: '100%', marginTop: 12 }}>
          <Text>Будет стёрто в любом случае:</Text>
          <ul style={{ margin: 0, paddingLeft: 20 }}>
            <li>настройки почты, включая сохранённый пароль</li>
            <li>маркер доступа ЕСИА и выбор текущего сертификата</li>
            <li>введённый API-Key и результаты проверок в этом окне</li>
          </ul>
          <Text>Дополнительно, если отметить:</Text>
          <Checkbox
            onChange={(event) => {
              options.clear_files = event.target.checked;
            }}
          >
            удалить файлы из папки сертификатов
          </Checkbox>
          <Alert
            type="warning"
            showIcon
            message="Файлы удаляются безвозвратно"
            description="Там может лежать единственная копия сертификата организации из письма УЦ."
          />
          <Checkbox
            onChange={(event) => {
              options.clear_inbound = event.target.checked;
            }}
          >
            очистить журнал входящих запросов от ЕПГУ
          </Checkbox>
          <Text type="secondary">
            Не трогаем: ключевые контейнеры КриптоПро, установленные сертификаты
            в хранилище и переменные из .env.
          </Text>
        </Space>
      ),
      okText: 'Сбросить',
      okButtonProps: { danger: true },
      cancelText: 'Отмена',
      onOk: () => resetEverything(options),
    });
  };

  const discoverMail = async () => {
    const address = mailForm.user || (mailConfig && mailConfig.user) || '';
    if (!address.includes('@') && !address.includes('.')) {
      setNotice({ type: 'error', text: 'Сначала укажите адрес ящика, по нему ищем серверы.' });
      return;
    }
    setDiscovery(null);
    await run('discover', async () => {
      try {
        const res = await api.post('/mail/discover', { address });
        setDiscovery(res.data);
        const suggested = res.data.suggested || {};
        if (res.data.found) {
          setMailForm((previous) => ({
            ...previous,
            imap_host: suggested.imap_host || previous.imap_host,
            imap_port: String(suggested.imap_port || previous.imap_port),
            smtp_host: suggested.smtp_host || previous.smtp_host,
            smtp_port: String(suggested.smtp_port || previous.smtp_port),
          }));
          setNotice({
            type: 'success',
            text: 'Серверы найдены и подставлены в форму. Проверьте и сохраните.',
          });
        } else {
          setNotice({
            type: 'warning',
            text: 'Автоматически не нашлось. Ниже видно, что проверяли и почему не подошло.',
          });
        }
      } catch (error) {
        setNotice({ type: 'error', text: errorText(error, 'Определить серверы не удалось.') });
      }
    });
  };

  const loadMessages = async () => {
    await run('messages', async () => {
      try {
        const res = await api.get('/mail/messages', { params: { limit: 30 } });
        setMessages(res.data.messages || []);
      } catch (error) {
        setNotice({ type: 'error', text: errorText(error, 'Прочитать ящик не удалось.') });
      }
    });
  };

  const sendLetter = () => {
    Modal.confirm({
      title: 'Отправить письмо?',
      icon: <SendOutlined />,
      content: (
        <Space direction="vertical" size={4}>
          <Text>Кому: {letter.to}</Text>
          <Text>Тема: {letter.subject}</Text>
          <Text type="secondary">
            Письмо уйдёт с ящика, указанного в настройках. Проверьте, что все
            плейсхолдеры в угловых скобках заменены.
          </Text>
        </Space>
      ),
      okText: 'Отправить',
      cancelText: 'Отмена',
      onOk: async () => {
        try {
          await api.post('/mail/send', {
            to: letter.to,
            subject: letter.subject,
            body: letter.body,
            cc: letter.cc || '',
          });
          setNotice({ type: 'success', text: `Письмо отправлено на ${letter.to}.` });
        } catch (error) {
          setNotice({ type: 'error', text: errorText(error, 'Отправить письмо не удалось.') });
          throw error;
        }
      },
    });
  };

  const saveAttachment = async (uid, index) => {
    await run('attachment', async () => {
      try {
        const res = await api.post(`/mail/messages/${uid}/attachments/${index}/save`);
        setNotice({
          type: 'success',
          text: `Сохранено: ${res.data.name}. Файл появился в папке сертификатов.`,
        });
        await loadCertificates();
      } catch (error) {
        setNotice({ type: 'error', text: errorText(error, 'Сохранить вложение не удалось.') });
      }
    });
  };

  const runFinalCheck = async () => {
    await run('final', async () => {
      const result = { hc: FAIL, status: FAIL, detail: '' };
      try {
        await api.get('/hc');
        result.hc = OK;
      } catch (error) {
        result.detail = errorText(error, 'Backend не отвечает.');
      }
      try {
        const res = await api.get('/status');
        result.status = OK;
        result.detail = `PyCades ${res.data.Version}`;
      } catch (error) {
        result.status = FAIL;
        if (!result.detail) {
          result.detail = 'КриптоПро в этом образе недоступен, подпись работать не будет.';
        }
      }
      setHealth(result);
    });
  };

  // ---------- Отрисовка шагов ----------

  const renderEnvironment = () => (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Paragraph type="secondary" style={{ margin: 0 }}>
        Контур определяется парой хостов ЕСИА и ЕПГУ из окружения. Ключ и хосты
        должны быть от одного контура, иначе ЕСИА ответит отказом.
      </Paragraph>
      {version ? (
        <Descriptions size="small" bordered column={1}>
          <Descriptions.Item label="Контур">{version.environment}</Descriptions.Item>
          <Descriptions.Item label="ЕСИА">{version.hosts.esia_host}</Descriptions.Item>
          <Descriptions.Item label="ЕПГУ">{version.hosts.svcdev_host}</Descriptions.Item>
          <Descriptions.Item label="Спецификация">{version.spec_version}</Descriptions.Item>
          <Descriptions.Item label="Услуг в каталоге">{version.services_count}</Descriptions.Item>
        </Descriptions>
      ) : (
        <Empty description="Backend не ответил. Поднимите стенд: docker compose up -d." />
      )}
      <Button icon={<ReloadOutlined />} onClick={loadEnvironment} loading={busy === 'env'}>
        Проверить заново
      </Button>
    </Space>
  );

  const renderCertificates = () => {
    const folder = sources && sources.folder;
    const readers = sources && sources.readers;
    return (
      <Space direction="vertical" size={20} style={{ width: '100%' }}>
        <div>
          <Title level={5}>Сертификаты в хранилище</Title>
          {certificates.length ? (
            <Table
              rowKey="id"
              size="small"
              pagination={false}
              dataSource={certificates}
              columns={[
                { title: 'Владелец', dataIndex: 'common_name' },
                { title: 'Организация', dataIndex: 'organization' },
                { title: 'Действует до', dataIndex: 'valid_to', width: 180 },
                {
                  title: '',
                  width: 150,
                  render: (_, record) =>
                    record.selected ? (
                      <Tag color="success">текущий</Tag>
                    ) : (
                      <Button size="small" onClick={() => selectCertificate(record.id)}>
                        Сделать текущим
                      </Button>
                    ),
                },
              ]}
            />
          ) : (
            <Alert
              type="warning"
              showIcon
              message="Сертификатов нет"
              description="Положите файл в папку ниже или заберите его из письма УЦ на шаге Почта."
            />
          )}
        </div>

        <div>
          <Title level={5}>
            <FolderOpenOutlined /> Папка с сертификатами
          </Title>
          {folder ? (
            <Space direction="vertical" size={12} style={{ width: '100%' }}>
              <Space>
                <Text code>{folder.folder}</Text>
                <CopyButton value={folder.folder} />
                <Button size="small" icon={<ReloadOutlined />} onClick={loadCertificates}>
                  Обновить
                </Button>
              </Space>
              {folder.containers && folder.containers.length ? (
                <Select
                  style={{ minWidth: 320 }}
                  allowClear
                  placeholder="Связать с ключевым контейнером, если он уже есть"
                  value={linkContainer || undefined}
                  onChange={(value) => setLinkContainer(value || '')}
                  options={(readers && readers.containers ? readers.containers : []).map((name) => ({
                    value: name,
                    label: name,
                  }))}
                />
              ) : null}
              <Table
                rowKey="path"
                size="small"
                pagination={false}
                dataSource={folder.files || []}
                locale={{ emptyText: 'В папке пока пусто' }}
                columns={[
                  { title: 'Файл', dataIndex: 'name' },
                  { title: 'Владелец', dataIndex: 'subject', ellipsis: true },
                  { title: 'Действует до', dataIndex: 'valid_to', width: 170 },
                  {
                    title: '',
                    width: 130,
                    render: (_, record) =>
                      record.kind === 'certificate' ? (
                        <Button
                          size="small"
                          type="primary"
                          loading={busy === 'import'}
                          onClick={() => importCertificate(record.path)}
                        >
                          Установить
                        </Button>
                      ) : (
                        <Tag>архив, распакуйте</Tag>
                      ),
                  },
                ]}
              />
            </Space>
          ) : (
            <Empty description="Список источников недоступен" />
          )}
        </div>

        <div>
          <Title level={5}>
            <UsbOutlined /> USB-токен
          </Title>
          {readers && readers.token_visible ? (
            <Alert
              type="success"
              showIcon
              message="Токен виден контейнеру"
              description={`Ридеры: ${readers.readers.join(', ')}`}
            />
          ) : (
            <Alert
              type="info"
              showIcon
              message="Токен контейнеру не виден, это ожидаемо"
              description="Docker Desktop на Windows не пробрасывает USB. Ниже команды для хоста: они достают с токена открытую часть сертификата, закрытый ключ при этом остаётся на токене."
            />
          )}
          <Space direction="vertical" size={12} style={{ width: '100%', marginTop: 12 }}>
            {(sources && sources.usb_guide ? sources.usb_guide : []).map((item) => (
              <Card key={item.id} size="small" title={item.title}>
                <Paragraph type="secondary" style={{ marginBottom: item.commands.length ? 12 : 0 }}>
                  {item.text}
                </Paragraph>
                {item.commands.map((command) => (
                  <Space key={command} style={{ width: '100%', marginBottom: 8 }}>
                    <Text code copyable={false} style={{ wordBreak: 'break-all' }}>
                      {command}
                    </Text>
                    <CopyButton value={command} title="Скопировать команду" />
                  </Space>
                ))}
              </Card>
            ))}
          </Space>
        </div>
      </Space>
    );
  };

  const renderApiKey = () => (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Paragraph type="secondary" style={{ margin: 0 }}>
        API-Key это GUID организации-потребителя из личного кабинета ИЭП.
        Проверка подписывает его выбранным сертификатом и просит маркер у ЕСИА,
        то есть проверяет сразу и ключ, и подпись.
      </Paragraph>
      <Space.Compact style={{ width: '100%', maxWidth: 640 }}>
        <Input
          value={apiKey}
          onChange={(event) => setApiKey(event.target.value)}
          placeholder="00000000-0000-0000-0000-000000000000"
          aria-label="API-Key организации"
        />
        <Button type="primary" onClick={checkApiKey} loading={busy === 'apikey'}>
          Проверить
        </Button>
      </Space.Compact>
      {tokenState.detail ? (
        <Alert
          type={tokenState.state === OK ? 'success' : 'error'}
          showIcon
          message={tokenState.detail}
        />
      ) : null}
      {certState !== OK ? (
        <Alert
          type="warning"
          showIcon
          message="Сначала выберите сертификат"
          description="Без выбранного сертификата подписывать ключ нечем, ЕСИА вернёт отказ."
        />
      ) : null}
    </Space>
  );

  const renderMail = () => (
    <Space direction="vertical" size={20} style={{ width: '100%' }}>
      <div>
        <Title level={5}>Ящик</Title>
        {mailConfig ? (
          <Descriptions size="small" bordered column={1}>
            <Descriptions.Item label="IMAP">
              {mailConfig.imap.host ? `${mailConfig.imap.host}:${mailConfig.imap.port}` : 'не задан'}
            </Descriptions.Item>
            <Descriptions.Item label="SMTP">
              {mailConfig.smtp.host ? `${mailConfig.smtp.host}:${mailConfig.smtp.port}` : 'не задан'}
            </Descriptions.Item>
            <Descriptions.Item label="Логин">{mailConfig.user || 'не задан'}</Descriptions.Item>
            <Descriptions.Item label="Пароль">
              {mailConfig.password.configured
                ? `задан, ${mailConfig.password.length} символов, источник: ${mailConfig.password.source}`
                : 'не задан'}
            </Descriptions.Item>
            <Descriptions.Item label="Вложения падают в">{mailConfig.inbox_dir}</Descriptions.Item>
          </Descriptions>
        ) : (
          <Empty description="Настройки почты недоступны" />
        )}
        <Title level={5} style={{ marginTop: 20 }}>
          Настроить отсюда
        </Title>
        <Paragraph type="secondary" style={{ marginBottom: 12 }}>
          Сохранённое здесь действует сразу и переживает перезапуск: значения
          ложатся в файл на томе и считаются важнее переменных окружения, с
          которыми стартовал контейнер. Пароль нужен от приложения почтового
          сервиса, а не основной пароль аккаунта.
        </Paragraph>
        <Space direction="vertical" size={8} style={{ width: '100%', maxWidth: 760 }}>
          <Space.Compact style={{ width: '100%' }}>
            <Input
              addonBefore="IMAP"
              placeholder="imap.example.ru"
              value={mailForm.imap_host}
              onChange={(event) => setMailForm({ ...mailForm, imap_host: event.target.value })}
            />
            <Input
              style={{ maxWidth: 120 }}
              addonBefore="порт"
              value={mailForm.imap_port}
              onChange={(event) => setMailForm({ ...mailForm, imap_port: event.target.value })}
            />
          </Space.Compact>
          <Space.Compact style={{ width: '100%' }}>
            <Input
              addonBefore="SMTP"
              placeholder="smtp.example.ru"
              value={mailForm.smtp_host}
              onChange={(event) => setMailForm({ ...mailForm, smtp_host: event.target.value })}
            />
            <Input
              style={{ maxWidth: 120 }}
              addonBefore="порт"
              value={mailForm.smtp_port}
              onChange={(event) => setMailForm({ ...mailForm, smtp_port: event.target.value })}
            />
          </Space.Compact>
          <Input
            addonBefore="Логин"
            placeholder="smev@домен организации"
            value={mailForm.user}
            onChange={(event) => setMailForm({ ...mailForm, user: event.target.value })}
          />
          <Input
            addonBefore="Адрес в поле От"
            placeholder="пусто - совпадает с логином"
            value={mailForm.sender}
            onChange={(event) => setMailForm({ ...mailForm, sender: event.target.value })}
          />
          <Input.Password
            addonBefore="Пароль"
            placeholder={
              mailConfig && mailConfig.password.configured
                ? `сохранён, ${mailConfig.password.length} символов, источник: ${mailConfig.password.source}. Оставьте пустым, чтобы не менять`
                : 'пароль приложения почтового сервиса'
            }
            autoComplete="new-password"
            value={mailForm.password}
            onChange={(event) => setMailForm({ ...mailForm, password: event.target.value })}
          />
          <Space>
            <Button
              icon={<SearchOutlined />}
              onClick={discoverMail}
              loading={busy === 'discover'}
            >
              Определить серверы по адресу
            </Button>
            <Text type="secondary">
              Спросим DNS домена: SRV-записи, потом MX, потом привычные имена
            </Text>
          </Space>
          <Space>
            <Text type="secondary">Шифрование SSL</Text>
            <Switch
              size="small"
              checked={mailForm.use_ssl}
              onChange={(value) => setMailForm({ ...mailForm, use_ssl: value })}
            />
          </Space>
        </Space>
        <Space style={{ marginTop: 12 }}>
          <Button
            type="primary"
            icon={<SaveOutlined />}
            onClick={saveMailSettings}
            loading={busy === 'mailsave'}
          >
            Сохранить
          </Button>
          <Button icon={<ReloadOutlined />} onClick={loadMail} loading={busy === 'mail'}>
            Обновить
          </Button>
          <Button onClick={checkMail} loading={busy === 'mailcheck'}>
            Проверить связь
          </Button>
        </Space>
        {dotenv ? (
          <div style={{ marginTop: 16 }}>
            <Space style={{ marginBottom: 8 }}>
              <Text type="secondary">
                То же самое для .env, если нужно перенести на другую машину
              </Text>
              <CopyButton value={dotenv} title="Скопировать для .env" />
            </Space>
            <pre
              style={{
                background: '#f8f9fa',
                padding: 12,
                borderRadius: 6,
                margin: 0,
                overflow: 'auto',
              }}
            >
              {dotenv}
            </pre>
          </div>
        ) : null}
        {mailConfig && !mailConfig.configured ? (
          <Alert
            style={{ marginTop: 12 }}
            type="info"
            showIcon
            message="Почта не настроена"
            description="Заполните MAIL_IMAP_HOST, MAIL_SMTP_HOST, MAIL_USER и MAIL_PASSWORD в .env и перезапустите контейнер api. Пароль нужен от приложения, а не основной пароль аккаунта."
          />
        ) : null}
        {busy === 'mailcheck' ? (
          <Alert style={{ marginTop: 12 }} type="info" message="Проверяю связь..." />
        ) : null}
        {mailCheck ? (
          <Space direction="vertical" size={8} style={{ marginTop: 12, width: '100%' }}>
            <Text type="secondary">
              Проверено {formatTime(mailCheck.checked_at)}
            </Text>
            <Space align="start">
              <StatusTag state={mailCheck.imap.ok ? OK : FAIL} />
              <Text>
                IMAP {mailCheck.imap_host}: {mailCheck.imap.detail}
              </Text>
            </Space>
            <Space align="start">
              <StatusTag state={mailCheck.smtp.ok ? OK : FAIL} />
              <Text>
                SMTP {mailCheck.smtp_host}: {mailCheck.smtp.detail}
              </Text>
            </Space>
          </Space>
        ) : null}
        {discovery ? (
          <div style={{ marginTop: 16 }}>
            <Text type="secondary">
              Поиск по домену {discovery.domain}, {formatTime(discovery.checked_at)}
              {discovery.dns_available ? '' : '. DNS-резолвер недоступен, работали только привычные имена'}
            </Text>
            <Table
              style={{ marginTop: 8 }}
              rowKey={(item) => `${item.protocol}-${item.host}-${item.port}`}
              size="small"
              pagination={false}
              dataSource={discovery.candidates}
              columns={[
                { title: 'Протокол', dataIndex: 'protocol', width: 100 },
                { title: 'Сервер', dataIndex: 'host' },
                { title: 'Порт', dataIndex: 'port', width: 80 },
                { title: 'Откуда', dataIndex: 'source', width: 170 },
                {
                  title: 'Результат',
                  width: 230,
                  render: (_, item) => (
                    <Space>
                      <StatusTag state={item.reachable ? OK : FAIL} />
                      <Text type="secondary">{item.detail}</Text>
                    </Space>
                  ),
                },
              ]}
            />
          </div>
        ) : null}
      </div>

      <div>
        <Title level={5}>Письмо в поддержку</Title>
        <Paragraph type="secondary">
          Отправляется с вашего ящика. Регламент ждёт адрес формата {SENDER_HINT}.
          Плейсхолдеры в угловых скобках заменяются перед отправкой.
        </Paragraph>
        <Space direction="vertical" size={12} style={{ width: '100%' }}>
          <Select
            style={{ minWidth: 360 }}
            value={letterId}
            onChange={(value) => {
              setLetterId(value);
              setLetter(LETTERS[value]);
            }}
            options={Object.values(LETTERS).map((item) => ({ value: item.id, label: item.name }))}
          />
          <Input
            addonBefore="Кому"
            value={letter.to}
            onChange={(event) => setLetter({ ...letter, to: event.target.value })}
          />
          <Input
            addonBefore="Тема"
            value={letter.subject}
            onChange={(event) => setLetter({ ...letter, subject: event.target.value })}
          />
          <TextArea
            rows={12}
            value={letter.body}
            onChange={(event) => setLetter({ ...letter, body: event.target.value })}
          />
          <Space>
            <Button
              type="primary"
              icon={<SendOutlined />}
              onClick={sendLetter}
              disabled={!mailConfig || !mailConfig.configured}
            >
              Отправить
            </Button>
            <CopyButton value={letter.body} title="Скопировать текст" />
          </Space>
        </Space>
      </div>

      <div>
        <Title level={5}>Ответы</Title>
        <Space style={{ marginBottom: 12 }}>
          <Button icon={<ReloadOutlined />} onClick={loadMessages} loading={busy === 'messages'}>
            Проверить почту
          </Button>
          <Text type="secondary">
            Показываются письма с адресов ведомств: {(mailConfig && mailConfig.watched ? mailConfig.watched : []).join(', ')}
          </Text>
        </Space>
        <Table
          rowKey="uid"
          size="small"
          dataSource={messages}
          pagination={{ pageSize: 10, hideOnSinglePage: true }}
          locale={{ emptyText: 'Ответов пока нет' }}
          columns={[
            { title: 'От', dataIndex: 'from', ellipsis: true },
            { title: 'Тема', dataIndex: 'subject', ellipsis: true },
            { title: 'Получено', dataIndex: 'received_at', width: 190 },
            {
              title: 'Вложения',
              width: 110,
              render: (_, record) => record.attachments.length || '',
            },
          ]}
          expandable={{
            expandedRowRender: (record) => (
              <Space direction="vertical" size={12} style={{ width: '100%' }}>
                {record.attachments.length ? (
                  <Table
                    rowKey="index"
                    size="small"
                    pagination={false}
                    dataSource={record.attachments}
                    columns={[
                      { title: 'Файл', dataIndex: 'name' },
                      { title: 'Тип', dataIndex: 'content_type', width: 200 },
                      {
                        title: '',
                        width: 150,
                        render: (_, item) => (
                          <Button
                            size="small"
                            icon={<DownloadOutlined />}
                            disabled={item.too_large}
                            loading={busy === 'attachment'}
                            onClick={() => saveAttachment(record.uid, item.index)}
                          >
                            Сохранить
                          </Button>
                        ),
                      },
                    ]}
                  />
                ) : (
                  <Text type="secondary">Вложений нет</Text>
                )}
                <pre
                  style={{
                    background: '#f8f9fa',
                    padding: 12,
                    borderRadius: 6,
                    maxHeight: 280,
                    overflow: 'auto',
                    margin: 0,
                  }}
                >
                  {record.body}
                </pre>
              </Space>
            ),
          }}
        />
      </div>
    </Space>
  );

  const renderFinal = () => (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Button type="primary" onClick={runFinalCheck} loading={busy === 'final'}>
        Проверить всё
      </Button>
      <Descriptions size="small" bordered column={1}>
        <Descriptions.Item label="Backend">
          <Space>
            <StatusTag state={health.hc} />
            <Text>{health.hc === OK ? 'отвечает' : 'не проверено'}</Text>
          </Space>
        </Descriptions.Item>
        <Descriptions.Item label="КриптоПро">
          <Space>
            <StatusTag state={health.status} />
            <Text>{health.detail || 'не проверено'}</Text>
          </Space>
        </Descriptions.Item>
        <Descriptions.Item label="Сертификат">
          <Space>
            <StatusTag state={certState} />
            <Text>
              {currentCert && currentCert.certId
                ? `выбран ${(currentCert.subject || {}).CN || currentCert.certId}`
                : 'не выбран'}
            </Text>
          </Space>
        </Descriptions.Item>
        <Descriptions.Item label="Маркер ЕСИА">
          <Space>
            <StatusTag state={tokenState.state} />
            <Text>{tokenState.detail || 'не проверялся'}</Text>
          </Space>
        </Descriptions.Item>
        <Descriptions.Item label="Почта">
          <Space>
            <StatusTag state={mailState} />
            <Text>
              {mailConfig && mailConfig.configured ? 'настроена' : 'не настроена'}
            </Text>
          </Space>
        </Descriptions.Item>
      </Descriptions>
      {finalState === OK ? (
        <Result
          status="success"
          title="Стенд готов к работе"
          subTitle="Контур определён, сертификат выбран, маркер получен."
        />
      ) : null}
    </Space>
  );

  const content = [
    renderEnvironment,
    renderCertificates,
    renderApiKey,
    renderMail,
    renderFinal,
  ][step];

  return (
    <Card
      title={
        <Space>
          <span>Мастер настройки</span>
          <StatusTag state={steps[step].state} />
        </Space>
      }
      extra={
        <Space>
          <Button
            danger
            icon={<ClearOutlined />}
            onClick={confirmReset}
            loading={busy === 'reset'}
          >
            Сбросить всё
          </Button>
          <Button disabled={step === 0} onClick={() => setStep(step - 1)}>
            Назад
          </Button>
          <Button
            type="primary"
            disabled={step === steps.length - 1}
            onClick={() => setStep(step + 1)}
          >
            Дальше
          </Button>
        </Space>
      }
      style={{ marginBottom: 24 }}
    >
      <Steps
        current={step}
        onChange={setStep}
        style={{ marginBottom: 24 }}
        items={steps.map((item) => ({
          title: item.title,
          icon: item.icon,
          status:
            item.state === FAIL ? 'error' : item.state === OK ? 'finish' : 'wait',
        }))}
      />
      {notice ? (
        <Alert
          style={{ marginBottom: 16 }}
          type={notice.type}
          showIcon
          closable
          message={notice.text}
          onClose={() => setNotice(null)}
        />
      ) : null}
      {content()}
    </Card>
  );
}
