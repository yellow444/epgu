import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Alert,
  Badge,
  Button,
  Card,
  Checkbox,
  Col,
  Collapse,
  Descriptions,
  Drawer,
  Empty,
  Input,
  message,
  Upload,
  Modal,
  Result,
  Row,
  Segmented,
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
  EyeOutlined,
  ExclamationCircleOutlined,
  FolderOpenOutlined,
  FormOutlined,
  DeleteOutlined,
  KeyOutlined,
  FileTextOutlined,
  UploadOutlined,
  MailOutlined,
  MinusCircleOutlined,
  ReloadOutlined,
  SafetyCertificateOutlined,
  SearchOutlined,
  SaveOutlined,
  SendOutlined,
  ThunderboltOutlined,
  UsbOutlined,
} from '@ant-design/icons';
import axios from 'axios';
import {
  LETTERS,
  REPLIES,
  SENDER_HINT,
  daysLeft,
  letterToEml,
  letterToMailto,
  letterToText,
} from '../SetupGuide/letters';

const { Title, Text, Paragraph } = Typography;
const { TextArea } = Input;

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL || '/api';
const STEP_KEY = 'wizard.step';
const PAGE_SIZE = 10;

// Как раскрашивать статус запроса. Красным только то, что ждёт нас.
const THREAD_STATUS_COLOR = {
  action: 'error',
  done: 'success',
  progress: 'processing',
  new: 'default',
  file: 'warning',
  comment: 'default',
};

// Как называть вложение по-русски. Тип определяется по имени файла.
const ATTACHMENT_KIND = {
  certificate: 'сертификат',
  key: 'ключ',
  archive: 'архив',
  pdf: 'PDF',
  docx: 'документ',
  unknown: 'файл',
};

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

// Письмо можно унести в свой почтовый клиент: файл .eml открывают все.
function downloadLetter(letter) {
  const blob = new Blob([letterToEml(letter)], { type: 'message/rfc822' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `${letter.id}.eml`;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
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

// Поля реквизитов в порядке показа. Ключи совпадают с тем, что ждёт backend.
const PROFILE_FIELDS = [
  { key: 'ORG_FULL_NAME', label: 'Полное наименование', placeholder: 'ООО "Ромашка"' },
  { key: 'ORG_SHORT_NAME', label: 'Краткое наименование', placeholder: 'Ромашка' },
  { key: 'ORG_INN', label: 'ИНН', placeholder: '1906302363' },
  { key: 'ORG_OGRN', label: 'ОГРН', placeholder: '1137746099046' },
  { key: 'ORG_OKTMO', label: 'ОКТМО', placeholder: 'нужен не во всех письмах' },
  { key: 'ORG_ROLE', label: 'Роль', placeholder: 'потребитель или вендор' },
  { key: 'IS_MNEMONIC', label: 'Мнемоника ИС', placeholder: 'из техпортала ЕСИА' },
  { key: 'CONTACT_NAME', label: 'ФИО ответственного', placeholder: 'Иванов Иван Иванович' },
  { key: 'CONTACT_ROLE', label: 'Должность', placeholder: 'руководитель проекта' },
  { key: 'CONTACT_SNILS', label: 'СНИЛС', placeholder: 'нужен в запросе на сертификат' },
  { key: 'CONTACT_PHONE', label: 'Телефон', placeholder: '+7 900 000-00-00' },
  { key: 'CONTACT_EMAIL', label: 'Почта организации', placeholder: 'smev@домен' },
];

const EMPTY_PROFILE = PROFILE_FIELDS.reduce(
  (accumulator, field) => ({ ...accumulator, [field.key]: '' }),
  {}
);

/** Что осталось незаполненным: любые угловые скобки в тексте. */
function remainingPlaceholders(text) {
  return Array.from(new Set((text || '').match(/<[^<>]{1,80}>/g) || []));
}

/**
 * Подставить реквизиты в текст письма.
 *
 * Плейсхолдер, для которого нет значения, остаётся как был: пустая строка в
 * письме Оператору хуже, чем видимая незаполненная скобка.
 */
function applyProfile(text, profile, placeholderMap, extras) {
  let result = text || '';
  Object.entries(placeholderMap).forEach(([key, names]) => {
    const value = (profile[key] || '').trim();
    if (!value) return;
    names.forEach((name) => {
      result = result.split(`<${name}>`).join(value);
    });
  });
  Object.entries(extras || {}).forEach(([name, value]) => {
    if (value) result = result.split(`<${name}>`).join(value);
  });
  return result;
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

function formatMoment(value) {
  if (!value) return '';
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return String(value);
  const today = new Date();
  const sameDay = parsed.toDateString() === today.toDateString();
  const time = parsed.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
  if (sameDay) return `сегодня ${time}`;
  return `${parsed.toLocaleDateString('ru-RU', { day: '2-digit', month: '2-digit' })} ${time}`;
}

// Как называть действия автоматики в журнале.
const AUTO_KIND = {
  collect: 'забран файл',
  confirm: 'ответ отправлен',
  error: 'ошибка',
};

const AUTO_KIND_COLOR = {
  collect: 'processing',
  confirm: 'success',
  error: 'error',
};

function formatBytes(size) {
  if (!size && size !== 0) return '';
  if (size < 1024) return `${size} Б`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} КБ`;
  return `${(size / 1024 / 1024).toFixed(2)} МБ`;
}

export default function SetupWizard() {
  const api = useMemo(
    () => axios.create({ baseURL: BACKEND_URL, timeout: 60000 }),
    []
  );
  const [step, setStep] = useState(() => Number(localStorage.getItem(STEP_KEY) || 0));
  // Занятость считается по ключам: параллельные загрузки не должны гасить
  // чужие индикаторы, а вложенный вызов - индикатор внешнего.
  const [busy, setBusy] = useState({});
  const [notice, setNotice] = useState(null);

  // Шаг 1: контур
  const [version, setVersion] = useState(null);
  // Шаг 2: сертификаты
  const [certificates, setCertificates] = useState([]);
  const [currentCert, setCurrentCert] = useState(null);
  const [sources, setSources] = useState(null);
  // Разбор вложения: что нашли внутри файла и что из этого можно достать.
  const [inspected, setInspected] = useState(null);
  // Вложения из писем плоским списком: что прислали и что из этого забрано.
  const [mailFiles, setMailFiles] = useState(null);
  // Запрос на сертификат для удостоверяющего центра: имя владельца и результат.
  const [certRdn, setCertRdn] = useState('');
  const [certRequest, setCertRequest] = useState(null);
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
  const [messagesTotal, setMessagesTotal] = useState(0);
  const [messagesOffset, setMessagesOffset] = useState(0);
  // Письма видно сразу: прятать переписку за кнопкой оказалось неудобно.
  const [showLetters, setShowLetters] = useState(true);
  const [threads, setThreads] = useState([]);
  const [threadsAt, setThreadsAt] = useState('');
  const [threadsError, setThreadsError] = useState('');
  const [threadsTotal, setThreadsTotal] = useState(0);
  const [threadsOffset, setThreadsOffset] = useState(0);
  const [threadCounts, setThreadCounts] = useState({});
  const [threadState, setThreadState] = useState('attention');
  const [ticketFilter, setTicketFilter] = useState('');
  // Какому запросу принадлежит показанная страница писем. Нужен, чтобы
  // ответ медленного нефильтрованного запроса не подменял выбранный.
  const [messagesTicket, setMessagesTicket] = useState('');
  const [messagesError, setMessagesError] = useState('');
  const [expandedThreads, setExpandedThreads] = useState([]);
  const [expandedLetters, setExpandedLetters] = useState([]);
  const [threadLetters, setThreadLetters] = useState({});
  const [onlyWatched, setOnlyWatched] = useState(true);
  // Просмотр вложения: что нашли внутри, без сохранения на диск.
  const [preview, setPreview] = useState(null);
  // Ответ на письмо поддержки.
  const [reply, setReply] = useState(null);
  const [signature, setSignature] = useState({ name: '', org: '' });
  // Автоматическая обработка почты и её журнал.
  const [autoState, setAutoState] = useState(null);
  const [deadlines, setDeadlines] = useState([]);
  const [expandedDeadlines, setExpandedDeadlines] = useState([]);
  const [deadlineLetters, setDeadlineLetters] = useState({});
  const [letterId, setLetterId] = useState('testCert');
  const [letter, setLetter] = useState(LETTERS.testCert);
  // Реквизиты организации: одни и те же во всех письмах Оператору.
  const [profile, setProfile] = useState(EMPTY_PROFILE);
  const [placeholders, setPlaceholders] = useState({});
  // Шаг 5: итог
  const [health, setHealth] = useState({ hc: IDLE, status: IDLE, detail: '' });

  useEffect(() => {
    localStorage.setItem(STEP_KEY, String(step));
  }, [step]);

  // Сообщения показываем плавающим тостом. Alert в шапке карточки остаётся,
  // но шаг почты длиннее экрана, и до шапки оператор не доскроллит.
  useEffect(() => {
    if (!notice || !notice.text) return;
    const kind = ['error', 'warning', 'info'].includes(notice.type) ? notice.type : 'success';
    message[kind](notice.text, kind === 'error' ? 8 : 4);
  }, [notice]);

  const run = useCallback(
    async (name, action) => {
      setBusy((prev) => ({ ...prev, [name]: (prev[name] || 0) + 1 }));
      try {
        return await action();
      } finally {
        setBusy((prev) => {
          const left = (prev[name] || 1) - 1;
          const next = { ...prev };
          if (left > 0) next[name] = left;
          else delete next[name];
          return next;
        });
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

  // Объявлять до useEffect ниже: он ссылается на этот колбэк, а const в теле
  // компонента до объявления недоступен, и приложение падает целиком.
  const loadProfile = useCallback(
    () =>
      run('profile', async () => {
        try {
          const res = await api.get('/setup/profile');
          setProfile({ ...EMPTY_PROFILE, ...(res.data.profile || {}) });
          setPlaceholders(res.data.placeholders || {});
        } catch (error) {
          setPlaceholders({});
        }
      }),
    [api, run]
  );

  useEffect(() => {
    loadEnvironment();
    loadCertificates();
    loadMail();
    loadProfile();
  }, [loadEnvironment, loadCertificates, loadMail, loadProfile]);

  const autoLoadedRef = useRef(false);
  // Блок писем лежит ниже таблицы запросов на целый экран: без прокрутки
  // нажатие "Письма" выглядело как будто ничего не произошло.
  const lettersRef = useRef(null);

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

  // Имя владельца для запроса собирается из реквизитов организации: те же
  // поля, что и в письмах Оператору, вводить их второй раз незачем.
  const buildRdn = () => {
    const org = profile.ORG_FULL_NAME || profile.ORG_SHORT_NAME || '';
    const person = (profile.CONTACT_NAME || '').trim().split(/\s+/).filter(Boolean);
    const parts = [];
    if (org) parts.push(`CN=${org}`, `O=${org}`);
    if (profile.CONTACT_ROLE) parts.push(`T=${profile.CONTACT_ROLE}`);
    if (profile.CONTACT_EMAIL) parts.push(`E=${profile.CONTACT_EMAIL}`);
    if (profile.ORG_INN) parts.push(`INN=${profile.ORG_INN}`);
    if (profile.ORG_OGRN) parts.push(`OGRN=${profile.ORG_OGRN}`);
    if (profile.CONTACT_SNILS) parts.push(`SNILS=${profile.CONTACT_SNILS}`);
    if (person.length) parts.push(`SN=${person[0]}`);
    if (person.length > 1) parts.push(`G=${person.slice(1).join(' ')}`);
    parts.push('C=RU');
    return parts.join(',');
  };

  const trustTestCa = async () => {
    await run('catrust', async () => {
      try {
        const res = await api.post('/certificates/trust-test-ca');
        const names = (res.data.installed || []).map((item) => item.title).join(', ');
        setNotice({ type: 'success', text: `Корни тестового УЦ установлены: ${names}.` });
        await loadCertificates();
      } catch (error) {
        setNotice({ type: 'error', text: errorText(error, 'Корни установить не удалось.') });
      }
    });
  };

  const createCertificateRequest = async () => {
    await run('request', async () => {
      try {
        const res = await api.post(
          '/certificates/request',
          { rdn: certRdn || buildRdn() },
          { timeout: 420000 }
        );
        setCertRequest(res.data);
        setCertRdn(res.data.rdn || certRdn);
        setNotice({
          type: 'success',
          text: `Запрос готов: ${res.data.name}. Ключ лежит в контейнере ${res.data.container}.`,
        });
        await loadCertificates();
      } catch (error) {
        setNotice({ type: 'error', text: errorText(error, 'Собрать запрос не удалось.') });
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

  const saveProfile = async () => {
    await run('profilesave', async () => {
      const payload = {};
      PROFILE_FIELDS.forEach((field) => {
        payload[field.key.toLowerCase()] = profile[field.key] || '';
      });
      try {
        const res = await api.post('/setup/profile', payload);
        setProfile({ ...EMPTY_PROFILE, ...(res.data.profile || {}) });
        setNotice({ type: 'success', text: 'Реквизиты сохранены.' });
      } catch (error) {
        setNotice({ type: 'error', text: errorText(error, 'Сохранить реквизиты не удалось.') });
      }
    });
  };

  const fillLetter = () => {
    // Контур подставляем сам: он уже определён на первом шаге.
    const extras = {
      'тестовая SVCDEV / промышленная':
        version && version.environment
          ? version.environment.startsWith('test')
            ? 'тестовая SVCDEV'
            : 'промышленная'
          : '',
      'домен организации': (profile.CONTACT_EMAIL || '').split('@')[1] || '',
      домен: (profile.CONTACT_EMAIL || '').split('@')[1] || '',
    };
    const filled = {
      ...letter,
      subject: applyProfile(letter.subject, profile, placeholders, extras),
      body: applyProfile(letter.body, profile, placeholders, extras),
    };
    setLetter(filled);
    const left = remainingPlaceholders(`${filled.subject}\n${filled.body}`);
    setNotice({
      type: left.length ? 'warning' : 'success',
      text: left.length
        ? `Подставлено. Осталось заполнить руками: ${left.join(', ')}`
        : 'Подставлено, незаполненных полей не осталось.',
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

  const loadThreads = useCallback(
    async (options = {}) => {
      const offset = options.offset ?? threadsOffset;
      const state = options.state ?? threadState;
      const refresh = options.refresh ?? false;
      await run('threads', async () => {
        try {
          const res = await api.get('/mail/threads', {
            params: { scan: 200, limit: PAGE_SIZE, offset, state, refresh },
          });
          setThreads(res.data.threads || []);
          setThreadsTotal(res.data.total || 0);
          setThreadsOffset(res.data.offset || 0);
          setThreadCounts(res.data.counts || {});
          setThreadsAt(res.data.checked_at || '');
          setThreadsError('');
        } catch (error) {
          if (error.response && error.response.status === 400) {
            // Почта не настроена: это не ошибка, просто нечего показывать.
            setThreads([]);
            setThreadsTotal(0);
            setThreadsError('');
            return;
          }
          const text = errorText(error, 'Прочитать ящик не удалось.');
          setThreadsError(text);
          setNotice({ type: 'error', text });
        }
      });
    },
    [api, run, threadsOffset, threadState]
  );

  const markThreads = async (tickets, read) => {
    const key = tickets.length === 1 ? `mark:${tickets[0]}` : 'mark';
    await run(key, async () => {
      try {
        const res = await api.post(
          read ? '/mail/threads/read' : '/mail/threads/unread',
          { tickets }
        );
        await loadThreads({});
        const marked = res.data && res.data.marked;
        setNotice({
          type: 'success',
          text: read
            ? `Отмечено прочитанными: ${marked ?? tickets.length}.`
            : `Возвращено в непрочитанные: ${marked ?? tickets.length}.`,
        });
      } catch (error) {
        setNotice({ type: 'error', text: errorText(error, 'Отметить не удалось.') });
      }
    });
  };

  const deleteCertificate = (record) => {
    Modal.confirm({
      title: 'Удалить сертификат?',
      icon: <DeleteOutlined />,
      content: (
        <Space direction="vertical" size={6}>
          <Text>{record.common_name || record.id}</Text>
          <Text type="warning" strong>
            КриптоПро удаляет сертификат вместе с привязанным ключевым контейнером.
            Закрытый ключ пропадёт, и восстановить его будет неоткуда.
          </Text>
          <Text type="secondary">
            Перед удалением стенд сам скопирует каталог ключей и покажет путь к копии.
            Если ключ ещё нужен, его можно вернуть из неё.
          </Text>
          <Text type="secondary">
            Маркер доступа ЕСИА погаснет, его надо будет получить заново.
          </Text>
        </Space>
      ),
      okText: 'Удалить',
      okButtonProps: { danger: true },
      cancelText: 'Отмена',
      onOk: async () => {
        await run(`delete:${record.id}`, async () => {
          try {
            const res = await api.post('/certificates/delete', null, {
              params: { cert_id: record.id },
            });
            const backup = res.data.keys_backup;
            setNotice({
              type: backup ? 'warning' : 'success',
              text:
                `Сертификат удалён. Осталось в хранилище: ${(res.data.left || []).length}.` +
                (backup ? ` Копия каталога ключей: ${backup}` : '') +
                (res.data.keys_left && res.data.keys_left.length
                  ? ` Контейнеры на месте: ${res.data.keys_left.join(', ')}`
                  : ' Ключевых контейнеров не осталось.'),
            });
            await loadCertificates();
          } catch (error) {
            setNotice({ type: 'error', text: errorText(error, 'Удалить не удалось.') });
          }
        });
      },
    });
  };

  const uploadFiles = async (fileList, target) => {
    // Почта нужна не всем: тот же файл можно принести руками, дальше путь общий.
    const form = new FormData();
    fileList.forEach((file) => form.append('files', file));
    form.append('target', target);
    await run('upload', async () => {
      try {
        const res = await api.post('/certsources/upload', form);
        const saved = res.data.saved || [];
        setInspected(saved.length === 1 ? saved[0] : null);
        setNotice({
          type: 'success',
          text: `Загружено файлов: ${saved.length}. ${
            target === 'keys' ? 'Ключевой контейнер положен в каталог ключей.' : ''
          }`,
        });
        await loadCertificates();
      } catch (error) {
        setNotice({ type: 'error', text: errorText(error, 'Загрузить не удалось.') });
      }
    });
  };

  const inspectFile = async (path) => {
    await run(`inspect:${path}`, async () => {
      try {
        const res = await api.get('/certsources/inspect', { params: { path } });
        setInspected(res.data);
      } catch (error) {
        setNotice({ type: 'error', text: errorText(error, 'Разобрать файл не удалось.') });
      }
    });
  };

  const extractFile = async (path, only) => {
    await run('extract', async () => {
      try {
        const res = await api.post('/certsources/extract', { path, only: only || [] });
        setNotice({
          type: 'success',
          text: `Извлечено файлов: ${(res.data.extracted || []).length}`,
        });
        await loadCertificates();
        await inspectFile(path);
      } catch (error) {
        setNotice({ type: 'error', text: errorText(error, 'Извлечь не удалось.') });
      }
    });
  };

  const messagesSeq = useRef(0);

  const loadMessages = useCallback(
    async (offset = 0, ticket = '', watchedOnly = true) => {
      // Ответы приходят не в том порядке, в каком уходили запросы: список
      // писем тянется из IMAP секундами, и медленный нефильтрованный ответ
      // затирал выбранный запрос. Считаем поколения и берём только своё.
      const seq = (messagesSeq.current += 1);
      setMessagesOffset(offset);
      setMessagesTicket(ticket || '');
      await run('messages', async () => {
        try {
          const res = await api.get('/mail/messages', {
            params: {
              limit: PAGE_SIZE,
              offset,
              ticket: ticket || '',
              only_watched: ticket ? false : watchedOnly,
            },
          });
          if (seq !== messagesSeq.current) return;
          setMessages(res.data.messages || []);
          setMessagesTotal(res.data.total || 0);
          setMessagesOffset(res.data.offset || 0);
          setMessagesError('');
        } catch (error) {
          if (seq !== messagesSeq.current) return;
          const text = errorText(error, 'Прочитать письма не удалось.');
          setMessages([]);
          setMessagesTotal(0);
          setMessagesError(text);
          setNotice({ type: 'error', text });
        }
      });
    },
    [api, run]
  );

  // Открыть переписку по запросу: раскрыть строку, показать письма и
  // прокрутить к ним. Одна точка для кнопки, клика по строке и сброса тега.
  const showLettersFor = useCallback(
    (ticket) => {
      setTicketFilter(ticket || '');
      setShowLetters(true);
      setExpandedLetters([]);
      loadMessages(0, ticket || '', onlyWatched);
      if (lettersRef.current) {
        lettersRef.current.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    },
    [loadMessages, onlyWatched]
  );

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

  const saveAttachment = async (uid, index, target = 'certs') => {
    await run(`attachment:${uid}:${index}:${target}`, async () => {
      try {
        const res = await api.post(
          `/mail/messages/${uid}/attachments/${index}/save`,
          null,
          { params: { target } }
        );
        await loadCertificates();
        await loadMailFiles();
        setNotice({
          type: 'success',
          text: `Файл ${res.data.name} лежит на стенде: ${res.data.path}`,
        });
      } catch (error) {
        setNotice({ type: 'error', text: errorText(error, 'Сохранить вложение не удалось.') });
      }
    });
  };

  // ---------- Вложения из писем ----------

  const loadMailFiles = useCallback(
    () =>
      run('mailfiles', async () => {
        try {
          const res = await api.get('/mail/attachments', { params: { letters: 10 } });
          setMailFiles(res.data && res.data.configured ? res.data.attachments || [] : []);
        } catch (error) {
          setMailFiles([]);
          setNotice({
            type: 'error',
            text: errorText(error, 'Прочитать вложения из писем не удалось.'),
          });
        }
      }),
    [api, run]
  );

  const restoreKeys = async (name) => {
    await run(`restore:${name}`, async () => {
      try {
        const res = await api.post('/certificates/restore-keys', null, { params: { name } });
        const restored = res.data.restored || [];
        setNotice({
          type: restored.length ? 'success' : 'info',
          text: restored.length
            ? `Возвращено файлов: ${restored.length}. Сертификат из контейнера снова виден.`
            : `Возвращать нечего: ${(res.data.skipped || []).slice(0, 3).join('; ')}`,
        });
        await loadCertificates();
      } catch (error) {
        setNotice({ type: 'error', text: errorText(error, 'Восстановить ключи не удалось.') });
      }
    });
  };

  const collectMailFiles = async () => {
    await run('collect', async () => {
      try {
        const res = await api.post('/mail/attachments/collect', null, {
          params: { letters: 10 },
        });
        const saved = res.data.saved || [];
        const skipped = res.data.skipped || [];
        setNotice({
          type: saved.length ? 'success' : 'info',
          text: saved.length
            ? `Забрано из писем: ${saved.map((item) => item.name).join(', ')}. ` +
              'Сертификаты в папке сертификатов, ключи в каталоге ключей. Установка ниже.'
            : `Забирать нечего. ${skipped.slice(0, 3).join('; ')}`,
        });
        await loadCertificates();
        await loadMailFiles();
      } catch (error) {
        setNotice({ type: 'error', text: errorText(error, 'Забрать вложения не удалось.') });
      }
    });
  };

  // ---------- Вложения: посмотреть, забрать, скачать ----------

  const attachmentUrl = (uid, index, download) =>
    `${BACKEND_URL}/mail/messages/${uid}/attachments/${index}/raw${download ? '?download=1' : ''}`;

  const previewAttachment = async (record, item) => {
    await run(`preview:${record.uid}:${item.index}`, async () => {
      try {
        const res = await api.get(`/mail/messages/${record.uid}/attachments/${item.index}/preview`);
        setPreview({
          ...res.data,
          uid: record.uid,
          index: item.index,
          ticket: record.ticket || '',
          source: 'mail',
        });
      } catch (error) {
        setNotice({ type: 'error', text: errorText(error, 'Посмотреть вложение не удалось.') });
      }
    });
  };

  const previewSaved = async (path, name) => {
    await run(`preview:${path}`, async () => {
      try {
        const res = await api.get('/certsources/inspect', { params: { path } });
        setPreview({ ...res.data, name: name || res.data.name, source: 'folder', path });
      } catch (error) {
        setNotice({ type: 'error', text: errorText(error, 'Разобрать файл не удалось.') });
      }
    });
  };

  // ---------- Ответ на письмо ----------

  const fillReply = (body, ticket) => {
    const values = {
      '<номер запроса>': ticket ? `SCR#${ticket}` : '<номер запроса>',
      '<ФИО>': profile.CONTACT_NAME || '<ФИО>',
      '<организация>': profile.ORG_SHORT_NAME || profile.ORG_FULL_NAME || '<организация>',
    };
    return Object.entries(values).reduce(
      (text, [key, value]) => text.split(key).join(value),
      body
    );
  };

  const openReply = async (uid, ticket, kind) => {
    await run(`reply:${uid}`, async () => {
      try {
        const res = await api.get(`/mail/messages/${uid}/reply`);
        // По запросу уточнения подтверждать нечего: там ждут ответа по существу.
        const template = kind === 'action' ? REPLIES.clarify : REPLIES.confirm;
        setSignature({
          name: profile.CONTACT_NAME || '',
          org: profile.ORG_SHORT_NAME || profile.ORG_FULL_NAME || '',
        });
        setReply({
          uid,
          ticket: res.data.ticket || ticket || '',
          to: res.data.to,
          toReplaced: res.data.to_replaced,
          from: res.data.from,
          subject: res.data.subject,
          quoteText: res.data.quote || '',
          receivedAt: res.data.received_at || '',
          files: res.data.files || [],
          attach: [],
          templateId: template.id,
          quote: true,
          body: fillReply(template.body, res.data.ticket || ticket || ''),
        });
      } catch (error) {
        setNotice({
          type: 'error',
          text: errorText(error, 'Заготовку ответа получить не удалось.'),
        });
      }
    });
  };

  // Реквизиты для подписи письма. Руками их вводить не нужно: они либо уже
  // сохранены, либо лежат в сертификате организации.
  const applyProfileToReply = (next) => {
    const values = next || profile;
    const filled = {
      '<ФИО>': values.CONTACT_NAME || '<ФИО>',
      '<организация>': values.ORG_SHORT_NAME || values.ORG_FULL_NAME || '<организация>',
    };
    setReply((current) =>
      current
        ? {
            ...current,
            body: Object.entries(filled).reduce(
              (text, [key, value]) => text.split(key).join(value),
              current.body
            ),
          }
        : current
    );
  };

  const fillProfileFromCertificate = async () => {
    await run('fromcert', async () => {
      try {
        const res = await api.post('/setup/profile/from-certificate');
        const saved = res.data.profile || {};
        const next = saved;
        setProfile({ ...profile, ...next });
        applyProfileToReply(next);
        setNotice({
          type: 'success',
          text: `Из сертификата взято: ${(res.data.filled || []).join(', ') || 'ничего'}`,
        });
      } catch (error) {
        setNotice({
          type: 'error',
          text: errorText(error, 'В сертификате реквизитов не нашлось.'),
        });
      }
    });
  };

  const saveReplySignature = async (name, org) => {
    await run('signature', async () => {
      try {
        const res = await api.post('/setup/profile', {
          contact_name: name,
          org_short_name: org,
        });
        const saved = res.data.profile || {};
        const next = saved;
        setProfile({ ...profile, ...next });
        applyProfileToReply(next);
        setNotice({ type: 'success', text: 'Реквизиты сохранены и подставлены в письмо.' });
      } catch (error) {
        setNotice({ type: 'error', text: errorText(error, 'Сохранить реквизиты не удалось.') });
      }
    });
  };

  const sendReply = () => {
    if (!reply) return;
    Modal.confirm({
      title: 'Отправить ответ?',
      icon: <SendOutlined />,
      content: (
        <Space direction="vertical" size={4}>
          <Text>Кому: {reply.to}</Text>
          <Text>Тема: {reply.subject}</Text>
          <Text type="secondary">
            Тему менять нельзя: по ней поддержка сшивает переписку в один запрос.
          </Text>
          {reply.attach.length ? (
            <Text type="secondary">Вложения: {reply.attach.join(', ')}</Text>
          ) : null}
        </Space>
      ),
      okText: 'Отправить',
      cancelText: 'Отмена',
      onOk: async () => {
        await run('sendreply', async () => {
          try {
            const res = await api.post('/mail/reply', {
              uid: reply.uid,
              body: reply.body,
              quote: reply.quote,
              attach: reply.attach,
            });
            setReply(null);
            setNotice({
              type: 'success',
              text: `Ответ ушёл на ${(res.data.recipients || []).join(', ')}.`,
            });
            await loadThreads({ offset: 0, refresh: true });
            await loadMessages(0, ticketFilter, onlyWatched);
            await loadAuto();
          } catch (error) {
            setNotice({ type: 'error', text: errorText(error, 'Отправить ответ не удалось.') });
          }
        });
      },
    });
  };

  const replyLetter = () =>
    reply
      ? {
          id: `reply-${reply.ticket || reply.uid}`,
          to: reply.to,
          cc: '',
          subject: reply.subject,
          // Заголовки ветки: ответ из стороннего клиента должен попасть в тот
          // же тикет, а не завести новый.
          in_reply_to: reply.messageId,
          references: reply.references,
          body: reply.quote ? `${reply.body}\n\n${reply.quoteText}` : reply.body,
        }
      : null;

  // ---------- Автоматическая обработка почты ----------

  const loadAuto = useCallback(
    () =>
      run('auto', async () => {
        try {
          const res = await api.get('/mail/auto');
          setAutoState(res.data);
        } catch (error) {
          setAutoState(null);
        }
        try {
          const res = await api.get('/mail/deadlines');
          setDeadlines(res.data.waiting || []);
        } catch (error) {
          setDeadlines([]);
        }
      }),
    [api, run]
  );

  const loadDeadlineLetter = async (record) => {
    if (!record.uid) return;
    await run(`deadline:${record.ticket}`, async () => {
      try {
        const res = await api.get(`/mail/messages/${record.uid}`);
        setDeadlineLetters((prev) => ({ ...prev, [record.ticket]: res.data }));
      } catch (error) {
        setNotice({ type: 'error', text: errorText(error, 'Письмо прочитать не удалось.') });
      }
    });
  };

  const saveAuto = async (patch) => {
    const current = autoState || {};
    const next = {
      enabled: current.enabled || false,
      collect: current.collect !== false,
      confirm: current.confirm || false,
      confirm_after_hours: current.confirm_after_hours || 48,
      ...patch,
    };
    await run('autosave', async () => {
      try {
        const res = await api.post('/mail/auto', next);
        setAutoState(res.data);
        setNotice({
          type: 'success',
          text: next.enabled
            ? 'Автоматическая обработка почты включена.'
            : 'Автоматическая обработка почты выключена.',
        });
      } catch (error) {
        setNotice({ type: 'error', text: errorText(error, 'Сохранить настройку не удалось.') });
      }
    });
  };

  const runAuto = () => {
    Modal.confirm({
      title: 'Обработать почту сейчас?',
      icon: <ReloadOutlined />,
      width: 560,
      content: (
        <Space direction="vertical" size={4}>
          <Text>
            Стенд перечитает ящик, разложит вложения по каталогам и посчитает сроки ответа.
          </Text>
          <Text type="secondary">
            {autoState && autoState.confirm
              ? 'Подтверждение решений включено: по запросам, у которых подошёл срок, уйдёт письмо в поддержку.'
              : 'Письма наружу не уйдут: подтверждение решений выключено.'}
          </Text>
        </Space>
      ),
      okText: 'Обработать',
      cancelText: 'Отмена',
      onOk: async () => {
        await run('autorun', async () => {
          try {
            const res = await api.post('/mail/auto/run');
            const report = res.data || {};
            setNotice({
              type: 'success',
              text:
                `Запросов: ${report.threads || 0}. ` +
                `Забрано файлов: ${(report.collected || []).length}. ` +
                `Ждут ответа: ${(report.waiting || []).length}. ` +
                `Подтверждений отправлено: ${(report.confirmed || []).length}.`,
            });
            await loadAuto();
            await loadThreads({ offset: 0, refresh: true });
            await loadCertificates();
          } catch (error) {
            setNotice({ type: 'error', text: errorText(error, 'Обработать почту не удалось.') });
          }
        });
      },
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
      <Button icon={<ReloadOutlined />} onClick={loadEnvironment} loading={Boolean(busy['env'])}>
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
                  width: 260,
                  render: (_, record) => (
                    <Space size={4}>
                      {record.selected ? (
                        <Tag color="success">текущий</Tag>
                      ) : (
                        <Button size="small" onClick={() => selectCertificate(record.id)}>
                          Сделать текущим
                        </Button>
                      )}
                      <Button
                        size="small"
                        danger
                        icon={<DeleteOutlined />}
                        loading={Boolean(busy[`delete:${record.id}`])}
                        onClick={() => deleteCertificate(record)}
                      >
                        Удалить
                      </Button>
                    </Space>
                  ),
                },
              ]}
            />
          ) : (
            <Alert
              type="warning"
              showIcon
              message="Сертификатов нет"
              description="Заберите файл из письма УЦ блоком ниже, положите его в папку или принесите вручную."
            />
          )}
        </div>

        <div>
          <Title level={5}>
            <SafetyCertificateOutlined /> Получить тестовый сертификат
          </Title>
          <Paragraph type="secondary" style={{ marginBottom: 12 }}>
            Инструкция Оператора по работе с тестовой средой предлагает выпускать
            сертификат в тестовом удостоверяющем центре, а не просить письмом. Стенд
            собирает запрос сам: ключ остаётся здесь, наружу уходит только открытая
            часть внутри запроса. Письмом тоже можно, шаблон лежит на шаге «Почта»,
            но там ждать ответа сутками.
          </Paragraph>

          <Space direction="vertical" size={10} style={{ width: '100%' }}>
            <Space wrap>
              <Button
                icon={<SafetyCertificateOutlined />}
                loading={Boolean(busy.catrust)}
                onClick={trustTestCa}
              >
                0. Доверять тестовому УЦ
              </Button>
              <Text type="secondary">
                Скачивает корневой и промежуточный сертификаты удостоверяющего центра
                и ставит их в доверенные. Без этого выпущенный сертификат считается
                недоверенным, и подпись падает на проверке цепочки.
              </Text>
            </Space>

            <div>
              <Space wrap style={{ marginBottom: 6 }}>
                <Text strong>1. Имя владельца в запросе</Text>
                <Button size="small" onClick={() => setCertRdn(buildRdn())}>
                  Собрать из реквизитов
                </Button>
                <Button size="small" onClick={() => setStep(3)}>
                  Поправить реквизиты
                </Button>
              </Space>
              <Input.TextArea
                value={certRdn}
                onChange={(event) => setCertRdn(event.target.value)}
                autoSize={{ minRows: 2, maxRows: 4 }}
                placeholder="CN=..., O=..., INN=..., OGRN=..., SNILS=..., SN=..., G=..., C=RU"
              />
              <Text type="secondary">
                Проверьте ИНН, ОГРН и СНИЛС: удостоверяющий центр сверяет их формат, а
                ЕСИА потом сверяет с профилем организации.
              </Text>
            </div>

            <Space wrap>
              <Button
                type="primary"
                icon={<KeyOutlined />}
                loading={Boolean(busy.request)}
                onClick={createCertificateRequest}
              >
                2. Создать запрос
              </Button>
              <Text type="secondary">
                Генерация ключа занимает около минуты: датчик случайных чисел в
                контейнере программный.
              </Text>
            </Space>

            {certRequest ? (
              <Card size="small" title={`Запрос готов: ${certRequest.name}`}>
                <Space direction="vertical" size={8} style={{ width: '100%' }}>
                  <Space wrap>
                    <Text>Контейнер ключа: </Text>
                    <Text code>{certRequest.container}</Text>
                    <CopyButton value={certRequest.request} title="Скопировать запрос" />
                    <Button
                      size="small"
                      icon={<DownloadOutlined />}
                      href={`${BACKEND_URL}/certsources/file?path=${encodeURIComponent(certRequest.path)}&download=1`}
                      target="_blank"
                      rel="noreferrer"
                    >
                      Скачать .req
                    </Button>
                    <Button
                      size="small"
                      type="primary"
                      href={certRequest.ca_url}
                      target="_blank"
                      rel="noreferrer"
                    >
                      3. Открыть тестовый УЦ
                    </Button>
                  </Space>
                  <Input.TextArea
                    readOnly
                    value={certRequest.request}
                    autoSize={{ minRows: 4, maxRows: 10 }}
                    style={{ fontSize: 12 }}
                  />
                  <Alert
                    type="info"
                    showIcon
                    message="Что делать в удостоверяющем центре"
                    description={
                      <Space direction="vertical" size={2}>
                        <Text>
                          На странице УЦ выберите выпуск по готовому запросу, вставьте
                          текст выше или приложите файл .req, дождитесь выпуска и
                          скачайте сертификат файлом .cer.
                        </Text>
                        <Text type="secondary">
                          4. Файл принесите сюда кнопкой «Загрузить документы и
                          сертификаты» ниже, затем «Установить» и свяжите его с
                          контейнером {certRequest.container}.
                        </Text>
                        <Text type="secondary">
                          5. Тот же файл загрузите в карточку своей ИС на
                          технологическом портале ЕСИА: без этого ЕПГУ не узнает
                          подпись.
                        </Text>
                        <Text type="secondary">
                          В кабинете удостоверяющего центра нужна регистрация, а
                          браузеру - КриптоПро CSP с плагином и поддержкой ГОСТ TLS.
                          Стенд туда не ходит: он только готовит запрос и принимает
                          готовый сертификат.
                        </Text>
                      </Space>
                    }
                  />
                </Space>
              </Card>
            ) : null}
          </Space>
        </div>

        <div>
          <Title level={5}>
            <MailOutlined /> Из писем
          </Title>
          <Paragraph type="secondary" style={{ marginBottom: 12 }}>
            Вложения последних писем от поддержки и УЦ одним списком, без обхода
            переписки. Кнопка забирает сертификаты и архивы в папку сертификатов,
            ключевой контейнер - в каталог ключей. Установка остаётся отдельным
            шагом ниже: файл сначала виден, потом ставится.
          </Paragraph>
          <Space wrap style={{ marginBottom: 12 }}>
            <Button
              type="primary"
              icon={<DownloadOutlined />}
              loading={Boolean(busy['collect'])}
              disabled={!mailConfig || !mailConfig.configured}
              onClick={collectMailFiles}
            >
              Забрать всё из писем
            </Button>
            <Button
              icon={<ReloadOutlined />}
              loading={Boolean(busy['mailfiles'])}
              disabled={!mailConfig || !mailConfig.configured}
              onClick={loadMailFiles}
            >
              Обновить список
            </Button>
            <Button icon={<MailOutlined />} onClick={() => setStep(3)}>
              Открыть письма целиком
            </Button>
          </Space>
          {mailConfig && mailConfig.configured ? (
            <Table
              rowKey={(record) => `${record.uid}:${record.index}`}
              size="small"
              pagination={false}
              loading={Boolean(busy['mailfiles']) || Boolean(busy['collect'])}
              dataSource={mailFiles || []}
              locale={{
                emptyText: 'Вложений в последних письмах нет',
              }}
              columns={[
                {
                  title: 'Запрос',
                  dataIndex: 'ticket',
                  width: 120,
                  render: (value) => (value ? <Text code>SCR#{value}</Text> : ''),
                },
                { title: 'Письмо', dataIndex: 'subject', ellipsis: true },
                { title: 'Файл', dataIndex: 'name', width: 220, ellipsis: true },
                {
                  title: 'Что это',
                  dataIndex: 'kind',
                  width: 130,
                  render: (value) => <Tag>{ATTACHMENT_KIND[value] || value}</Tag>,
                },
                {
                  title: 'Размер',
                  dataIndex: 'size',
                  width: 100,
                  render: (value) => formatBytes(value),
                },
                {
                  title: '',
                  width: 470,
                  render: (_, record) => (
                    <Space size={4} wrap>
                      {record.saved ? <Tag color="success">забрано</Tag> : null}
                      {attachmentActions({ uid: record.uid, ticket: record.ticket }, record)}
                    </Space>
                  ),
                },
              ]}
            />
          ) : (
            <Alert
              type="info"
              showIcon
              message="Почта не настроена"
              description="Ящик задаётся на шаге Почта. Без него вложения можно принести вручную блоком ниже."
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
                  { title: 'Файл', dataIndex: 'name', ellipsis: true },
                  {
                    title: 'Что это',
                    dataIndex: 'kind',
                    width: 120,
                    render: (value) => <Tag>{ATTACHMENT_KIND[value] || value || 'файл'}</Tag>,
                  },
                  { title: 'Владелец', dataIndex: 'subject', ellipsis: true },
                  { title: 'Действует до', dataIndex: 'valid_to', width: 170 },
                  {
                    title: '',
                    width: 320,
                    render: (_, record) => (
                      <Space size={4} wrap>
                        {record.kind === 'certificate' ? (
                          <Button
                            size="small"
                            type="primary"
                            loading={Boolean(busy['import'])}
                            onClick={() => importCertificate(record.path)}
                          >
                            Установить
                          </Button>
                        ) : null}
                        {['pdf', 'docx', 'archive'].includes(record.kind) ? (
                          <Button
                            size="small"
                            icon={<EyeOutlined />}
                            loading={Boolean(busy[`preview:${record.path}`])}
                            onClick={() => previewSaved(record.path, record.name)}
                          >
                            Посмотреть
                          </Button>
                        ) : (
                          <Button
                            size="small"
                            icon={<FileTextOutlined />}
                            loading={Boolean(busy[`inspect:${record.path}`])}
                            onClick={() => inspectFile(record.path)}
                          >
                            Свойства
                          </Button>
                        )}
                        <Tooltip title="Скачать файл себе в браузер">
                          <Button
                            size="small"
                            icon={<DownloadOutlined />}
                            href={`${BACKEND_URL}/certsources/file?path=${encodeURIComponent(record.path)}&download=1`}
                            target="_blank"
                            rel="noreferrer"
                          />
                        </Tooltip>
                      </Space>
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
            <UploadOutlined /> Файлы вручную
          </Title>
          <Paragraph type="secondary" style={{ marginBottom: 12 }}>
            Почта нужна не всегда. Инструкцию, сертификат, архив или ключевой контейнер
            можно принести файлом, и дальше путь тот же: разбор, извлечение вложений,
            установка. Ключевой контейнер кладите отдельной кнопкой, он должен попасть
            в каталог ключей, а не к документам.
          </Paragraph>
          <Space wrap size={12}>
            <Upload
              multiple
              showUploadList={false}
              beforeUpload={(file, list) => {
                if (file === list[0]) uploadFiles(list, 'certs');
                return false;
              }}
            >
              <Button icon={<UploadOutlined />} loading={Boolean(busy['upload'])}>
                Загрузить документы и сертификаты
              </Button>
            </Upload>
            <Upload
              multiple
              showUploadList={false}
              beforeUpload={(file, list) => {
                if (file === list[0]) uploadFiles(list, 'keys');
                return false;
              }}
            >
              <Button icon={<KeyOutlined />} loading={Boolean(busy['upload'])}>
                Загрузить ключевой контейнер
              </Button>
            </Upload>
          </Space>

          {inspected ? (
            <Card size="small" style={{ marginTop: 12 }} title={`Разбор: ${inspected.name}`}>
              <Space direction="vertical" size={10} style={{ width: '100%' }}>
                <Space wrap>
                  <Tag>{inspected.kind}</Tag>
                  {inspected.pages ? <Tag>страниц: {inspected.pages}</Tag> : null}
                  <Text type="secondary">{formatBytes(inspected.size)}</Text>
                  <Button size="small" onClick={() => setInspected(null)}>
                    Свернуть
                  </Button>
                </Space>

                {(inspected.hints || []).map((hint) => (
                  <Alert key={hint} type="info" showIcon message={hint} />
                ))}

                {inspected.links && inspected.links.length ? (
                  <div>
                    <Text strong>Ссылки из документа</Text>
                    <Space direction="vertical" size={2} style={{ width: '100%', marginTop: 6 }}>
                      {inspected.links.slice(0, 12).map((link) => (
                        <a key={link} href={link} target="_blank" rel="noreferrer">
                          {link}
                        </a>
                      ))}
                    </Space>
                  </div>
                ) : null}

                {inspected.entries && inspected.entries.length ? (
                  <div>
                    <Space style={{ marginBottom: 6 }}>
                      <Text strong>Вложенные файлы</Text>
                      <Button
                        size="small"
                        loading={Boolean(busy['extract'])}
                        onClick={() => extractFile(inspected.path)}
                      >
                        Извлечь все
                      </Button>
                    </Space>
                    <Table
                      rowKey="name"
                      size="small"
                      pagination={false}
                      dataSource={inspected.entries}
                      columns={[
                        { title: 'Имя', dataIndex: 'name', ellipsis: true },
                        {
                          title: 'Размер',
                          dataIndex: 'size',
                          width: 110,
                          render: (value) => formatBytes(value),
                        },
                      ]}
                    />
                  </div>
                ) : null}

                {inspected.text ? (
                  <div>
                    <Text strong>Текст документа</Text>
                    <Input.TextArea
                      readOnly
                      value={inspected.text}
                      autoSize={{ minRows: 6, maxRows: 18 }}
                      style={{ marginTop: 6, fontSize: 12 }}
                    />
                  </div>
                ) : null}
              </Space>
            </Card>
          ) : null}
        </div>

        {sources && sources.key_backups && sources.key_backups.length ? (
          <div>
            <Title level={5}>
              <SafetyCertificateOutlined /> Копии ключей
            </Title>
            <Paragraph type="secondary" style={{ marginBottom: 12 }}>
              Копия каталога ключей делается сама перед каждым удалением
              сертификата. Сертификат лежит внутри контейнера, поэтому вместе с
              ключами возвращается и он. Уже лежащие на месте файлы не
              затираются.
            </Paragraph>
            <Table
              rowKey="name"
              size="small"
              pagination={false}
              dataSource={sources.key_backups}
              columns={[
                { title: 'Сделана', dataIndex: 'made_at', width: 200 },
                {
                  title: 'Контейнеры',
                  render: (_, record) =>
                    (record.containers || [])
                      .map((item) => `${item.name} (${item.keys.length})`)
                      .join(', ') || 'пусто',
                },
                {
                  title: '',
                  width: 160,
                  render: (_, record) => (
                    <Button
                      size="small"
                      icon={<ReloadOutlined />}
                      loading={Boolean(busy[`restore:${record.name}`])}
                      onClick={() => restoreKeys(record.name)}
                    >
                      Восстановить
                    </Button>
                  ),
                },
              ]}
            />
          </div>
        ) : null}

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
        <Button type="primary" onClick={checkApiKey} loading={Boolean(busy['apikey'])}>
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

  const renderMailbox = () => (
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
              loading={Boolean(busy['discover'])}
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
            loading={Boolean(busy['mailsave'])}
          >
            Сохранить
          </Button>
          <Button icon={<ReloadOutlined />} onClick={loadMail} loading={Boolean(busy['mail'])}>
            Обновить
          </Button>
          <Button onClick={checkMail} loading={Boolean(busy['mailcheck'])}>
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
        {busy['mailcheck'] ? (
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
  );

  const renderProfileBlock = () => (
      <div>
        <Title level={5}>Реквизиты организации</Title>
        <Paragraph type="secondary" style={{ marginBottom: 12 }}>
          Эти данные повторяются во всех письмах Оператору. Введите один раз, и
          кнопка под письмом подставит их в шаблон. Править письмо руками при
          этом никто не мешает.
        </Paragraph>
        <Row gutter={[12, 12]}>
          {PROFILE_FIELDS.map((field) => (
            <Col key={field.key} xs={24} md={12} xl={8}>
              <Input
                addonBefore={field.label}
                placeholder={field.placeholder}
                value={profile[field.key] || ''}
                onChange={(event) =>
                  setProfile({ ...profile, [field.key]: event.target.value })
                }
              />
            </Col>
          ))}
        </Row>
        <Space style={{ marginTop: 12 }}>
          <Button
            type="primary"
            icon={<SaveOutlined />}
            onClick={saveProfile}
            loading={Boolean(busy['profilesave'])}
          >
            Сохранить реквизиты
          </Button>
          <Button icon={<ReloadOutlined />} onClick={loadProfile} loading={Boolean(busy['profile'])}>
            Обновить
          </Button>
        </Space>
      </div>
  );

  const renderComposer = () => (
      <div>
        <Title level={5}>Письмо в поддержку</Title>
        <Paragraph type="secondary">
          Отправляется с вашего ящика. Регламент ждёт адрес формата {SENDER_HINT}.
          Плейсхолдеры в угловых скобках заменяются перед отправкой.
        </Paragraph>
        <Space direction="vertical" size={12} style={{ width: '100%' }}>
          {/* Шаблоны видно все сразу: за выпадающим списком их не искали. */}
          <Space wrap size={8}>
            {Object.values(LETTERS).map((item) => (
              <Button
                key={item.id}
                size="small"
                type={item.id === letterId ? 'primary' : 'default'}
                onClick={() => {
                  setLetterId(item.id);
                  setLetter(LETTERS[item.id]);
                }}
              >
                {item.name}
              </Button>
            ))}
          </Space>
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
          <Space wrap>
            <Button icon={<FormOutlined />} onClick={fillLetter}>
              Заполнить реквизитами
            </Button>
            <Button
              icon={<ReloadOutlined />}
              onClick={() => {
                setLetter(LETTERS[letterId]);
                setNotice({ type: 'info', text: 'Вернул исходный шаблон письма.' });
              }}
            >
              Вернуть шаблон
            </Button>
            <Button
              type="primary"
              icon={<SendOutlined />}
              onClick={sendLetter}
              disabled={!mailConfig || !mailConfig.configured}
            >
              Отправить
            </Button>
            <CopyButton value={letter.body} title="Скопировать текст" />
            <CopyButton
              value={letterToText(letter)}
              title="Скопировать письмо целиком, с адресом и темой"
            />
            <Button icon={<DownloadOutlined />} onClick={() => downloadLetter(letter)}>
              Скачать .eml
            </Button>
          </Space>
          {remainingPlaceholders(`${letter.subject}\n${letter.body}`).length ? (
            <Alert
              type="warning"
              showIcon
              message="Осталось заполнить"
              description={remainingPlaceholders(
                `${letter.subject}\n${letter.body}`
              ).join(', ')}
            />
          ) : null}
        </Space>
      </div>
  );

  // Запросы, письма и вложения подтягиваются сами при открытии: ответ
  // поддержки не должен ждать, пока оператор вспомнит нажать кнопку. Backend
  // отдаёт запросы из кэша, поэтому лишнего похода в IMAP не будет. Эффект
  // стоит ниже колбэков намеренно: они объявлены через const и до объявления
  // недоступны.
  useEffect(() => {
    if (!autoLoadedRef.current && mailConfig && mailConfig.configured) {
      autoLoadedRef.current = true;
      loadThreads({ offset: 0 });
      // Письма и вложения подтягиваем сразу: оператор пришёл именно за ними.
      loadMessages(0, '', true);
      loadMailFiles();
      loadAuto();
    }
  }, [mailConfig, loadThreads, loadMessages, loadMailFiles, loadAuto]);

  // ---------- Почта: запросы, письма, вложения ----------

  const loadThreadLetters = async (ticket) => {
    await run(`letters:${ticket}`, async () => {
      try {
        const res = await api.get('/mail/messages', {
          params: { limit: 50, offset: 0, ticket, only_watched: false },
        });
        setThreadLetters((prev) => ({ ...prev, [ticket]: res.data.messages || [] }));
      } catch (error) {
        setThreadLetters((prev) => ({ ...prev, [ticket]: [] }));
        setNotice({
          type: 'error',
          text: errorText(error, `Переписку по SCR#${ticket} прочитать не удалось.`),
        });
      }
    });
  };

  const toggleThread = (ticket) => {
    setExpandedThreads((keys) => {
      if (keys.includes(ticket)) return keys.filter((key) => key !== ticket);
      if (!threadLetters[ticket]) loadThreadLetters(ticket);
      return [...keys, ticket];
    });
  };

  // Действия у вложения зависят от того, что это за файл: класть инструкцию
  // в каталог ключей КриптоПро незачем, а забирать её на стенд - наоборот.
  const attachmentActions = (record, item) => {
    const kind = item.kind || 'unknown';
    const keyLike = kind === 'key' || kind === 'archive';
    return (
      <Space size={4} wrap>
        <Button
          size="small"
          icon={<EyeOutlined />}
          loading={Boolean(busy[`preview:${record.uid}:${item.index}`])}
          onClick={(event) => {
            event.stopPropagation();
            previewAttachment(record, item);
          }}
        >
          Посмотреть
        </Button>
        <Tooltip title={item.too_large ? 'Файл больше допустимого размера, заберите его почтовым клиентом' : 'Файл ляжет в папку на стенде, а не в загрузки браузера'}>
          <Button
            size="small"
            icon={<FolderOpenOutlined />}
            disabled={item.too_large}
            loading={Boolean(busy[`attachment:${record.uid}:${item.index}:certs`])}
            onClick={(event) => {
              event.stopPropagation();
              saveAttachment(record.uid, item.index);
            }}
          >
            Забрать на стенд
          </Button>
        </Tooltip>
        {keyLike ? (
          <Tooltip title="Положить в каталог ключевых контейнеров КриптоПро">
            <Button
              size="small"
              icon={<KeyOutlined />}
              disabled={item.too_large}
              loading={Boolean(busy[`attachment:${record.uid}:${item.index}:keys`])}
              onClick={(event) => {
                event.stopPropagation();
                saveAttachment(record.uid, item.index, 'keys');
              }}
            >
              В ключи
            </Button>
          </Tooltip>
        ) : null}
        <Tooltip title="Скачать себе в браузер">
          <Button
            size="small"
            icon={<DownloadOutlined />}
            disabled={item.too_large}
            href={attachmentUrl(record.uid, item.index, true)}
            target="_blank"
            rel="noreferrer"
            onClick={(event) => event.stopPropagation()}
          />
        </Tooltip>
      </Space>
    );
  };

  const letterCard = (record) => (
    <Space direction="vertical" size={12} style={{ width: '100%' }}>
      <Space wrap>
        <Button
          size="small"
          type="primary"
          icon={<SendOutlined />}
          loading={Boolean(busy[`reply:${record.uid}`])}
          onClick={() => openReply(record.uid, record.ticket)}
        >
          Ответить
        </Button>
        <CopyButton value={record.body || ''} title="Скопировать текст письма" />
        <Text type="secondary">
          Кому: {record.to || 'нам'} | От: {record.from}
        </Text>
      </Space>

      {record.attachments && record.attachments.length ? (
        <Table
          rowKey="index"
          size="small"
          pagination={false}
          dataSource={record.attachments}
          columns={[
            { title: 'Файл', dataIndex: 'name', ellipsis: true },
            {
              title: 'Что это',
              dataIndex: 'kind',
              width: 120,
              render: (value) => <Tag>{ATTACHMENT_KIND[value] || value || 'файл'}</Tag>,
            },
            {
              title: 'Размер',
              dataIndex: 'size',
              width: 100,
              render: (value) => formatBytes(value),
            },
            {
              title: '',
              width: 430,
              render: (_, item) => attachmentActions(record, item),
            },
          ]}
        />
      ) : (
        <Text type="secondary">Вложений нет</Text>
      )}

      {record.body ? (
        <div
          style={{
            background: 'rgba(0, 0, 0, 0.03)',
            padding: 12,
            borderRadius: 6,
            whiteSpace: 'pre-wrap',
            overflowWrap: 'anywhere',
            lineHeight: 1.6,
            maxWidth: '72em',
          }}
        >
          {record.body}
        </div>
      ) : (
        <Alert
          type="info"
          showIcon
          message="Текстовой части в письме нет"
          description="Письмо пришло только в HTML. Вложения выше доступны, текст откройте в почтовом клиенте."
        />
      )}
    </Space>
  );

  const letterColumns = [
    {
      title: 'Запрос',
      dataIndex: 'ticket',
      width: 110,
      render: (value) => (value ? <Text code>SCR#{value}</Text> : ''),
    },
    { title: 'От', dataIndex: 'from', ellipsis: true, width: 220 },
    { title: 'Тема', dataIndex: 'subject', ellipsis: true },
    {
      title: 'О чём',
      dataIndex: 'body',
      ellipsis: true,
      render: (value) => (
        <Text type="secondary">{(value || '').replace(/\s+/g, ' ').slice(0, 120)}</Text>
      ),
    },
    {
      title: 'Получено',
      dataIndex: 'received_at',
      width: 160,
      render: (value) => formatMoment(value),
    },
    {
      title: 'Вложения',
      width: 90,
      render: (_, record) => (record.attachments || []).length || '',
    },
    {
      title: '',
      width: 120,
      render: (_, record) => (
        <Button
          size="small"
          icon={<SendOutlined />}
          loading={Boolean(busy[`reply:${record.uid}`])}
          onClick={(event) => {
            event.stopPropagation();
            openReply(record.uid, record.ticket);
          }}
        >
          Ответить
        </Button>
      ),
    },
  ];

  const lettersTable = (records, options = {}) => (
    <Table
      rowKey="uid"
      size="small"
      dataSource={records}
      loading={options.loading}
      pagination={options.pagination || false}
      locale={{ emptyText: options.emptyText || 'Писем нет' }}
      columns={letterColumns}
      onRow={(record) => ({
        style: { cursor: 'pointer' },
        onClick: () =>
          setExpandedLetters((keys) =>
            keys.includes(record.uid)
              ? keys.filter((key) => key !== record.uid)
              : [...keys, record.uid]
          ),
      })}
      expandable={{
        expandedRowKeys: expandedLetters,
        onExpandedRowsChange: (keys) => setExpandedLetters([...keys]),
        expandedRowRender: (record) => letterCard(record),
      }}
    />
  );

  const renderThreads = () => (
    <div>
      <Title level={5}>Запросы в поддержку</Title>
      <Paragraph type="secondary" style={{ marginBottom: 12 }}>
        Поддержка ведёт переписку тикетами: номер SCR стоит в теме каждого
        письма, статус написан там же. Нажмите на строку - переписка по запросу
        раскроется прямо под ней, с вложениями и кнопкой ответа.
      </Paragraph>
      <Space style={{ marginBottom: 12 }} wrap>
        <Segmented
          value={threadState}
          onChange={(value) => {
            setThreadState(value);
            setThreadsOffset(0);
            loadThreads({ state: value, offset: 0 });
          }}
          options={[
            { label: `Требуют внимания ${threadCounts.attention ?? 0}`, value: 'attention' },
            { label: `Активные ${threadCounts.active ?? 0}`, value: 'active' },
            { label: `Непрочитанные ${threadCounts.unread ?? 0}`, value: 'unread' },
            { label: `Все ${threadCounts.all ?? 0}`, value: 'all' },
          ]}
        />
        <Button
          icon={<ReloadOutlined />}
          onClick={() => loadThreads({ offset: 0, refresh: true })}
          loading={Boolean(busy.threads)}
        >
          Проверить почту
        </Button>
        <Button
          onClick={() =>
            Modal.confirm({
              title: 'Отметить все прочитанными?',
              icon: <ExclamationCircleOutlined />,
              content: `Из списка "Требуют внимания" уйдёт запросов: ${threadCounts.unread ?? 0}. Вернуть отметку можно во вкладке "Все".`,
              okText: 'Отметить',
              cancelText: 'Отмена',
              onOk: () => markThreads([], true),
            })
          }
          loading={Boolean(busy.mark)}
          disabled={!threadCounts.unread}
        >
          Отметить все прочитанными
        </Button>
        {threadsAt ? <Text type="secondary">Проверено {formatTime(threadsAt)}</Text> : null}
      </Space>
      {threadsError ? (
        <Alert
          type="error"
          showIcon
          style={{ marginBottom: 12 }}
          message={threadsError}
          action={
            <Button size="small" onClick={() => loadThreads({ offset: 0, refresh: true })}>
              Повторить
            </Button>
          }
        />
      ) : null}
      <Table
        rowKey="ticket"
        size="small"
        dataSource={threads}
        loading={Boolean(busy.threads)}
        pagination={{
          current: Math.floor(threadsOffset / PAGE_SIZE) + 1,
          pageSize: PAGE_SIZE,
          total: threadsTotal,
          showSizeChanger: false,
          size: 'small',
          onChange: (page) => loadThreads({ offset: (page - 1) * PAGE_SIZE }),
        }}
        locale={{
          emptyText:
            mailConfig && mailConfig.configured
              ? threadState === 'attention'
                ? 'Ничего не ждёт внимания. Закрытые запросы смотрите в "Все".'
                : 'Запросов нет'
              : 'Почта не настроена: заполните ящик в блоке ниже.',
        }}
        rowClassName={(record) =>
          record.ticket === ticketFilter ? 'ant-table-row-selected' : ''
        }
        onRow={(record) => ({
          style: { cursor: 'pointer' },
          onClick: () => toggleThread(record.ticket),
        })}
        expandable={{
          expandedRowKeys: expandedThreads,
          onExpandedRowsChange: (keys) => {
            const next = [...keys];
            next.forEach((ticket) => {
              if (!threadLetters[ticket]) loadThreadLetters(ticket);
            });
            setExpandedThreads(next);
          },
          expandedRowRender: (record) => (
            <Space direction="vertical" size={8} style={{ width: '100%' }}>
              <Space wrap>
                <Text strong>Переписка по SCR#{record.ticket}</Text>
                <Button
                  size="small"
                  icon={<ReloadOutlined />}
                  loading={Boolean(busy[`letters:${record.ticket}`])}
                  onClick={(event) => {
                    event.stopPropagation();
                    loadThreadLetters(record.ticket);
                  }}
                >
                  Обновить
                </Button>
                <Text type="secondary">Нажмите на письмо, чтобы прочитать его целиком</Text>
              </Space>
              {lettersTable(threadLetters[record.ticket] || [], {
                loading: Boolean(busy[`letters:${record.ticket}`]),
                emptyText: 'Писем по этому запросу не нашлось',
              })}
            </Space>
          ),
        }}
        columns={[
          {
            title: 'Запрос',
            dataIndex: 'ticket',
            width: 130,
            render: (value, record) => (
              <Space size={4}>
                {record.unread ? <Badge status="processing" /> : null}
                <Text code>SCR#{value}</Text>
              </Space>
            ),
          },
          { title: 'Тема', dataIndex: 'topic', ellipsis: true },
          {
            title: 'Статус',
            dataIndex: 'status',
            width: 170,
            render: (value, record) => (
              <Tag color={THREAD_STATUS_COLOR[record.status_kind] || 'default'}>{value}</Tag>
            ),
          },
          {
            title: 'Последнее движение',
            width: 200,
            render: (_, record) => (
              <Space direction="vertical" size={0}>
                <Text>{record.last_event}</Text>
                <Text type="secondary">{formatMoment(record.last_at)}</Text>
              </Space>
            ),
          },
          {
            title: 'Ответить до',
            width: 170,
            render: (_, record) => {
              if (record.status !== 'Выполнен') return '';
              const left = daysLeft(record.status_at);
              if (left === null) return '';
              if (left < 0) return <Tag color="error">срок прошёл</Tag>;
              return (
                <Tag color={left <= 1 ? 'warning' : 'default'}>
                  {left === 0 ? 'последний день' : `осталось ${left} дн.`}
                </Tag>
              );
            },
          },
          {
            title: 'Писем',
            dataIndex: 'messages',
            width: 90,
            render: (value, record) => (
              <Space size={4}>
                <Text>{value}</Text>
                {record.has_files ? <Tag color="warning">файл</Tag> : null}
              </Space>
            ),
          },
          {
            title: '',
            width: 260,
            render: (_, record) => (
              <Space size={4}>
                <Button
                  size="small"
                  type={expandedThreads.includes(record.ticket) ? 'primary' : 'default'}
                  loading={Boolean(busy[`letters:${record.ticket}`])}
                  onClick={(event) => {
                    event.stopPropagation();
                    toggleThread(record.ticket);
                  }}
                >
                  Письма
                </Button>
                <Button
                  size="small"
                  icon={<SendOutlined />}
                  loading={Boolean(busy[`reply:${(record.uids || []).slice(-1)[0]}`])}
                  disabled={!(record.uids || []).length}
                  onClick={(event) => {
                    event.stopPropagation();
                    openReply(
                      record.status_uid || (record.uids || []).slice(-1)[0],
                      record.ticket,
                      record.status_kind
                    );
                  }}
                >
                  Ответить
                </Button>
                <Button
                  size="small"
                  type={record.unread ? 'primary' : 'default'}
                  loading={Boolean(busy[`mark:${record.ticket}`])}
                  onClick={(event) => {
                    event.stopPropagation();
                    markThreads([record.ticket], record.unread);
                  }}
                >
                  {record.unread ? 'Прочитано' : 'В непрочитанные'}
                </Button>
              </Space>
            ),
          },
        ]}
      />
    </div>
  );

  const renderLetters = () => (
    <div ref={lettersRef}>
      <Space style={{ marginBottom: 12 }} wrap>
        <Title level={5} style={{ margin: 0 }}>
          {ticketFilter ? `Письма запроса SCR#${ticketFilter}` : 'Весь ящик'}
        </Title>
        <Button
          icon={showLetters ? <MinusCircleOutlined /> : <MailOutlined />}
          onClick={() => {
            const next = !showLetters;
            setShowLetters(next);
            if (next && (!messages.length || messagesTicket !== ticketFilter)) {
              loadMessages(0, ticketFilter, onlyWatched);
            }
          }}
        >
          {showLetters ? 'Скрыть письма' : 'Показать письма'}
        </Button>
        {ticketFilter ? (
          <Tag closable onClose={() => showLettersFor('')}>
            только SCR#{ticketFilter}
          </Tag>
        ) : null}
        <Checkbox
          checked={onlyWatched}
          onChange={(event) => {
            setOnlyWatched(event.target.checked);
            loadMessages(0, ticketFilter, event.target.checked);
          }}
        >
          Только письма ведомств
        </Checkbox>
        <Tooltip title={(mailConfig && mailConfig.watched ? mailConfig.watched : []).join(', ')}>
          <Text type="secondary">какие адреса считаются ведомственными</Text>
        </Tooltip>
      </Space>
      {messagesError ? (
        <Alert
          type="error"
          showIcon
          style={{ marginBottom: 12 }}
          message={messagesError}
          action={
            <Button size="small" onClick={() => loadMessages(0, ticketFilter, onlyWatched)}>
              Повторить
            </Button>
          }
        />
      ) : null}
      {!showLetters
        ? null
        : lettersTable(messages, {
            loading: Boolean(busy.messages),
            emptyText: ticketFilter
              ? `По запросу SCR#${ticketFilter} писем не нашлось. Снимите фильтр, чтобы увидеть весь ящик.`
              : onlyWatched
              ? 'Писем от ведомственных адресов нет. Снимите галочку, чтобы увидеть весь ящик.'
              : 'Писем нет',
            pagination: {
              current: Math.floor(messagesOffset / PAGE_SIZE) + 1,
              pageSize: PAGE_SIZE,
              total: messagesTotal,
              showSizeChanger: false,
              size: 'small',
              onChange: (page) =>
                loadMessages((page - 1) * PAGE_SIZE, ticketFilter, onlyWatched),
            },
          })}
    </div>
  );

  const renderAutoCard = () => {
    const state = autoState || {};
    const log = state.log || [];
    return (
      <Card
        size="small"
        title={
          <Space>
            <ThunderboltOutlined />
            <Text strong>Автоматическая обработка почты</Text>
            {state.enabled ? <Tag color="success">включена</Tag> : <Tag>выключена</Tag>}
          </Space>
        }
        extra={
          <Space>
            <Button
              type="primary"
              icon={<ReloadOutlined />}
              loading={Boolean(busy.autorun)}
              disabled={!mailConfig || !mailConfig.configured}
              onClick={runAuto}
            >
              Обработать сейчас
            </Button>
            <Button icon={<ReloadOutlined />} loading={Boolean(busy.auto)} onClick={loadAuto}>
              Обновить
            </Button>
          </Space>
        }
      >
        <Space direction="vertical" size={12} style={{ width: '100%' }}>
          <Paragraph type="secondary" style={{ margin: 0 }}>
            Такт перечитывает ящик, раскладывает вложения по каталогам и считает
            срок ответа: робот поддержки просит подтвердить решение запроса в
            течение трёх календарных дней, иначе закрывает его сам. Устанавливать
            сертификаты и удалять письма автоматика не умеет.
          </Paragraph>

          <Space wrap size={24}>
            <Space>
              <Switch
                checked={Boolean(state.enabled)}
                loading={Boolean(busy.autosave)}
                onChange={(value) => saveAuto({ enabled: value })}
              />
              <Text>Работать по расписанию</Text>
              <Text type="secondary">
                раз в {Math.round((state.interval_seconds || 900) / 60)} мин
              </Text>
            </Space>
            <Space>
              <Switch
                checked={state.collect !== false}
                loading={Boolean(busy.autosave)}
                onChange={(value) => saveAuto({ collect: value })}
              />
              <Text>Забирать вложения</Text>
            </Space>
            <Space>
              <Switch
                checked={Boolean(state.confirm)}
                loading={Boolean(busy.autosave)}
                onChange={(value) => saveAuto({ confirm: value })}
              />
              <Tooltip title="Письмо уйдёт наружу от имени организации. Подтверждение означает согласие с решением поддержки.">
                <Text>Подтверждать решения письмом</Text>
              </Tooltip>
            </Space>
          </Space>

          {state.confirm ? (
            <Alert
              type="warning"
              showIcon
              message="Автоматика будет отправлять письма в поддержку"
              description={`Подтверждение уходит через ${state.confirm_after_hours || 48} ч после письма о решении и только по запросам, которые действительно выполнены. Каждое отправленное письмо попадает в журнал ниже.`}
            />
          ) : null}

          {deadlines.length ? (
            <div>
              <Space wrap style={{ marginBottom: 8 }}>
                <Text strong>Требуют ответа от нас</Text>
                <Badge count={deadlines.filter((item) => !item.answered).length} />
              </Space>
              <Alert
                type="warning"
                showIcon
                style={{ marginBottom: 12 }}
                message="Почему это обязательно"
                description={
                  <Space direction="vertical" size={2}>
                    <Text>
                      Робот поддержки пишет в каждом решённом запросе: «Просим Вас в течение
                      3-х календарных дней ответным письмом подтвердить решение запроса. Если
                      Вы не согласны с решением, в течение 3-х календарных дней отправьте в
                      ответном письме причину возобновления работ».
                    </Text>
                    <Text type="secondary">
                      Не ответили - запрос закрывается сам, и по тому же вопросу приходится
                      заводить новый. Тему письма менять нельзя: по ней сшивается тикет.
                    </Text>
                  </Space>
                }
              />
              <Table
                rowKey="ticket"
                size="small"
                pagination={false}
                dataSource={deadlines}
                expandable={{
                  expandedRowKeys: expandedDeadlines,
                  onExpandedRowsChange: (keys) => {
                    const next = [...keys];
                    next.forEach((ticket) => {
                      const item = deadlines.find((row) => row.ticket === ticket);
                      if (item && !deadlineLetters[ticket]) loadDeadlineLetter(item);
                    });
                    setExpandedDeadlines(next);
                  },
                  expandedRowRender: (record) => {
                    const letter = deadlineLetters[record.ticket];
                    if (!letter) {
                      return <Text type="secondary">Читаю письмо...</Text>;
                    }
                    return (
                      <Space direction="vertical" size={8} style={{ width: '100%' }}>
                        <Space wrap>
                          <Text strong>{letter.subject}</Text>
                          <Text type="secondary">от {letter.from}</Text>
                          <Text type="secondary">{formatMoment(letter.received_at)}</Text>
                          <CopyButton value={letter.body || ''} title="Скопировать текст письма" />
                        </Space>
                        <div
                          style={{
                            background: 'rgba(0, 0, 0, 0.03)',
                            padding: 12,
                            borderRadius: 6,
                            whiteSpace: 'pre-wrap',
                            overflowWrap: 'anywhere',
                            lineHeight: 1.6,
                            maxWidth: '72em',
                          }}
                        >
                          {letter.body || 'Текстовой части в письме нет.'}
                        </div>
                      </Space>
                    );
                  },
                }}
                columns={[
                  {
                    title: 'Запрос',
                    dataIndex: 'ticket',
                    width: 130,
                    render: (value) => <Text code>SCR#{value}</Text>,
                  },
                  {
                    title: 'Чего ждут',
                    width: 200,
                    render: (_, record) => (
                      <Space direction="vertical" size={0}>
                        <Tag color={record.kind === 'action' ? 'error' : 'processing'}>
                          {record.status_label}
                        </Tag>
                        <Text type="secondary">
                          {record.kind === 'action'
                            ? 'ответ по существу вопроса'
                            : 'подтвердить решение'}
                        </Text>
                      </Space>
                    ),
                  },
                  {
                    title: 'Письмо',
                    ellipsis: true,
                    render: (_, record) => (
                      <Space direction="vertical" size={0}>
                        <Text ellipsis>{record.subject || record.topic}</Text>
                        <Text type="secondary">{formatMoment(record.status_at)}</Text>
                      </Space>
                    ),
                  },
                  {
                    title: 'Срок',
                    width: 150,
                    render: (_, record) =>
                      record.overdue ? (
                        <Tag color="error">срок прошёл</Tag>
                      ) : (
                        <Tag color={record.hours_left < 24 ? 'warning' : 'default'}>
                          осталось {Math.max(0, Math.round(record.hours_left))} ч
                        </Tag>
                      ),
                  },
                  {
                    title: '',
                    width: 330,
                    render: (_, record) => (
                      <Space size={4} wrap>
                        {record.answered ? <Tag color="success">ответили</Tag> : null}
                        <Button
                          size="small"
                          icon={<FileTextOutlined />}
                          loading={Boolean(busy[`deadline:${record.ticket}`])}
                          onClick={() => {
                            if (!deadlineLetters[record.ticket]) loadDeadlineLetter(record);
                            setExpandedDeadlines((keys) =>
                              keys.includes(record.ticket)
                                ? keys.filter((key) => key !== record.ticket)
                                : [...keys, record.ticket]
                            );
                          }}
                        >
                          Текст письма
                        </Button>
                        <Button
                          size="small"
                          type="primary"
                          icon={<SendOutlined />}
                          loading={Boolean(busy[`reply:${record.uid}`])}
                          disabled={!record.uid}
                          onClick={() => openReply(record.uid, record.ticket, record.kind)}
                        >
                          {record.kind === 'action' ? 'Ответить' : 'Подтвердить решение'}
                        </Button>
                        <Button
                          size="small"
                          icon={<MailOutlined />}
                          onClick={() => {
                            showLettersFor(record.ticket);
                            setExpandedThreads((keys) =>
                              keys.includes(record.ticket) ? keys : [...keys, record.ticket]
                            );
                            if (!threadLetters[record.ticket]) loadThreadLetters(record.ticket);
                          }}
                        >
                          Переписка
                        </Button>
                      </Space>
                    ),
                  },
                ]}
              />
              <Paragraph type="secondary" style={{ marginTop: 8, marginBottom: 0 }}>
                Кнопка «Подтвердить решение» открывает готовое письмо: тема из запроса,
                текст шаблоном, цитата ниже. Отправка - отдельным нажатием. Чтобы стенд
                подтверждал сам, включите «Подтверждать решения письмом» выше.
              </Paragraph>
            </div>
          ) : (
            <Alert
              type="success"
              showIcon
              message="Запросов, ждущих нашего ответа, нет"
              description="Здесь появятся запросы, по которым поддержка ждёт подтверждения решения или ответа по существу. На это даётся три календарных дня."
            />
          )}

          <div>
            <Text strong>Что сделала автоматика</Text>
            <Table
              style={{ marginTop: 8 }}
              rowKey={(record) => `${record.at}:${record.text}`}
              size="small"
              pagination={{ pageSize: 5, size: 'small', showSizeChanger: false }}
              dataSource={log}
              locale={{
                emptyText: 'Автоматика ещё ничего не делала. Нажмите "Обработать сейчас".',
              }}
              columns={[
                {
                  title: 'Когда',
                  dataIndex: 'at',
                  width: 170,
                  render: (value) => formatMoment(value),
                },
                {
                  title: 'Что',
                  dataIndex: 'kind',
                  width: 140,
                  render: (value) => <Tag color={AUTO_KIND_COLOR[value] || 'default'}>{AUTO_KIND[value] || value}</Tag>,
                },
                {
                  title: 'Запрос',
                  dataIndex: 'ticket',
                  width: 130,
                  render: (value) => (value ? <Text code>SCR#{value}</Text> : ''),
                },
                { title: 'Подробности', dataIndex: 'text', ellipsis: true },
              ]}
            />
            {state.last_run ? (
              <Text type="secondary">Последний такт: {formatMoment(state.last_run)}</Text>
            ) : null}
          </div>
        </Space>
      </Card>
    );
  };

  const renderPreview = () => (
    <Drawer
      open={Boolean(preview)}
      onClose={() => setPreview(null)}
      width={720}
      title={preview ? preview.name : ''}
      extra={
        preview && preview.source === 'mail' ? (
          <Space>
            <Button
              icon={<DownloadOutlined />}
              href={attachmentUrl(preview.uid, preview.index, true)}
              target="_blank"
              rel="noreferrer"
            >
              Скачать себе
            </Button>
            <Button
              type="primary"
              icon={<FolderOpenOutlined />}
              loading={Boolean(busy[`attachment:${preview.uid}:${preview.index}:certs`])}
              onClick={() => saveAttachment(preview.uid, preview.index)}
            >
              Забрать на стенд
            </Button>
          </Space>
        ) : null
      }
    >
      {preview ? (
        <Space direction="vertical" size={12} style={{ width: '100%' }}>
          <Space wrap>
            <Tag>{ATTACHMENT_KIND[preview.kind] || preview.kind}</Tag>
            {preview.pages ? <Tag>страниц: {preview.pages}</Tag> : null}
            <Text type="secondary">{formatBytes(preview.size)}</Text>
            {preview.ticket ? <Text code>SCR#{preview.ticket}</Text> : null}
          </Space>

          {(preview.hints || []).map((hint) => (
            <Alert key={hint} type="info" showIcon message={hint} />
          ))}

          {preview.kind === 'pdf' && preview.source === 'mail' ? (
            <iframe
              title={preview.name}
              src={attachmentUrl(preview.uid, preview.index, false)}
              style={{ width: '100%', height: 420, border: '1px solid rgba(0,0,0,0.1)', borderRadius: 6 }}
            />
          ) : null}
          {preview.kind === 'pdf' && preview.source === 'folder' ? (
            <iframe
              title={preview.name}
              src={`${BACKEND_URL}/certsources/file?path=${encodeURIComponent(preview.path)}`}
              style={{ width: '100%', height: 420, border: '1px solid rgba(0,0,0,0.1)', borderRadius: 6 }}
            />
          ) : null}

          {preview.links && preview.links.length ? (
            <div>
              <Text strong>Ссылки из документа</Text>
              <Space direction="vertical" size={2} style={{ width: '100%', marginTop: 6 }}>
                {preview.links.map((link) => (
                  <Space key={link}>
                    <a href={link} target="_blank" rel="noreferrer">
                      {link}
                    </a>
                    <CopyButton value={link} title="Скопировать ссылку" />
                  </Space>
                ))}
              </Space>
            </div>
          ) : null}

          {preview.entries && preview.entries.length ? (
            <div>
              <Space style={{ marginBottom: 6 }}>
                <Text strong>Вложенные файлы</Text>
                {preview.source === 'folder' ? (
                  <Button
                    size="small"
                    loading={Boolean(busy.extract)}
                    onClick={() => extractFile(preview.path)}
                  >
                    Извлечь все
                  </Button>
                ) : (
                  <Text type="secondary">
                    Чтобы извлечь, сначала заберите файл на стенд
                  </Text>
                )}
              </Space>
              <Table
                rowKey="name"
                size="small"
                pagination={false}
                dataSource={preview.entries}
                columns={[
                  { title: 'Имя', dataIndex: 'name', ellipsis: true },
                  {
                    title: 'Размер',
                    dataIndex: 'size',
                    width: 110,
                    render: (value) => formatBytes(value),
                  },
                ]}
              />
            </div>
          ) : null}

          {preview.text ? (
            <div>
              <Space style={{ marginBottom: 6 }}>
                <Text strong>Текст документа</Text>
                <CopyButton value={preview.text} title="Скопировать текст" />
              </Space>
              <Input.TextArea
                readOnly
                value={preview.text}
                autoSize={{ minRows: 8, maxRows: 24 }}
                style={{ fontSize: 13 }}
              />
            </div>
          ) : preview.kind === 'pdf' ? null : (
            <Alert
              type="info"
              showIcon
              message="Текст из файла не извлекается"
              description="Скорее всего это скан или картинка. Скачайте файл и откройте его на своей машине."
            />
          )}
        </Space>
      ) : null}
    </Drawer>
  );

  const renderReply = () => (
    <Modal
      open={Boolean(reply)}
      onCancel={() => setReply(null)}
      width={760}
      title={reply ? `Ответ по запросу SCR#${reply.ticket}` : 'Ответ'}
      footer={null}
    >
      {reply ? (
        <Space direction="vertical" size={12} style={{ width: '100%' }}>
          {reply.toReplaced ? (
            <Alert
              type="info"
              showIcon
              message={`Письмо пришло с адреса ${reply.from}, отвечать туда бесполезно`}
              description={`Ответ уйдёт на адрес поддержки ${reply.to}.`}
            />
          ) : null}
          <Descriptions size="small" column={1} bordered>
            <Descriptions.Item label="Кому">{reply.to}</Descriptions.Item>
            <Descriptions.Item label="Тема">
              <Space direction="vertical" size={0}>
                <Text>{reply.subject}</Text>
                <Text type="secondary">
                  Тему не меняем: по ней поддержка сшивает переписку в один запрос.
                </Text>
              </Space>
            </Descriptions.Item>
          </Descriptions>

          <Collapse
            size="small"
            items={[
              {
                key: 'original',
                label: 'Письмо, на которое отвечаем',
                children: (
                  <div
                    style={{
                      whiteSpace: 'pre-wrap',
                      overflowWrap: 'anywhere',
                      lineHeight: 1.6,
                      maxHeight: 260,
                      overflow: 'auto',
                    }}
                  >
                    {reply.quoteText.replace(/^> ?/gm, '')}
                  </div>
                ),
              },
            ]}
          />

          <Space wrap size={8}>
            {Object.values(REPLIES).map((item) => (
              <Button
                key={item.id}
                size="small"
                type={item.id === reply.templateId ? 'primary' : 'default'}
                onClick={() =>
                  setReply({
                    ...reply,
                    templateId: item.id,
                    body: fillReply(item.body, reply.ticket),
                  })
                }
              >
                {item.name}
              </Button>
            ))}
          </Space>

          <TextArea
            rows={10}
            value={reply.body}
            onChange={(event) => setReply({ ...reply, body: event.target.value })}
          />

          <Checkbox
            checked={reply.quote}
            onChange={(event) => setReply({ ...reply, quote: event.target.checked })}
          >
            Процитировать письмо ниже ответа (робот просит писать ответ выше цитаты)
          </Checkbox>

          {reply.files && reply.files.length ? (
            <div>
              <Text strong>Приложить файлы из папки вложений</Text>
              <Select
                mode="multiple"
                allowClear
                style={{ width: '100%', marginTop: 6 }}
                placeholder="Например, подписанное заявление"
                value={reply.attach}
                onChange={(value) => setReply({ ...reply, attach: value })}
                options={reply.files.map((name) => ({ value: name, label: name }))}
              />
            </div>
          ) : null}

          {remainingPlaceholders(reply.body).length ? (
            <Alert
              type="warning"
              showIcon
              message="В подписи не хватает реквизитов"
              description={
                <Space direction="vertical" size={8} style={{ width: '100%' }}>
                  <Text type="secondary">
                    Осталось подставить: {remainingPlaceholders(reply.body).join(', ')}. Вводить
                    руками не нужно: возьмите из сертификата или заполните один раз, дальше
                    подставится само.
                  </Text>
                  <Space wrap>
                    <Input
                      style={{ width: 260 }}
                      addonBefore="ФИО"
                      value={signature.name}
                      placeholder="Ситников Максим Валериевич"
                      onChange={(event) =>
                        setSignature({ ...signature, name: event.target.value })
                      }
                    />
                    <Input
                      style={{ width: 300 }}
                      addonBefore="Организация"
                      value={signature.org}
                      placeholder="ООО КВИК РЕСТО"
                      onChange={(event) =>
                        setSignature({ ...signature, org: event.target.value })
                      }
                    />
                  </Space>
                  <Space wrap>
                    <Button
                      type="primary"
                      icon={<SaveOutlined />}
                      loading={Boolean(busy.signature)}
                      disabled={!signature.name && !signature.org}
                      onClick={() => saveReplySignature(signature.name, signature.org)}
                    >
                      Сохранить и подставить
                    </Button>
                    <Button
                      icon={<SafetyCertificateOutlined />}
                      loading={Boolean(busy.fromcert)}
                      onClick={fillProfileFromCertificate}
                    >
                      Взять из сертификата
                    </Button>
                    <Button onClick={() => applyProfileToReply()}>
                      Подставить сохранённые
                    </Button>
                  </Space>
                </Space>
              }
            />
          ) : null}

          <Space wrap>
            <Button
              type="primary"
              icon={<SendOutlined />}
              loading={Boolean(busy.sendreply)}
              disabled={!mailConfig || !mailConfig.configured}
              onClick={sendReply}
            >
              Отправить ответ
            </Button>
            <CopyButton value={letterToText(replyLetter())} title="Скопировать письмо целиком" />
            <Button icon={<DownloadOutlined />} onClick={() => downloadLetter(replyLetter())}>
              Скачать .eml
            </Button>
            <Button href={letterToMailto(replyLetter())}>Открыть в почтовом клиенте</Button>
          </Space>
          <Text type="secondary">
            Если отвечаете из другого клиента, не меняйте тему и поместите текст выше цитаты.
          </Text>
        </Space>
      ) : null}
    </Modal>
  );

  const renderMail = () => (
    <Space direction="vertical" size={20} style={{ width: '100%' }}>
      {renderAutoCard()}
      {renderThreads()}
      {renderLetters()}
      <Collapse
        defaultActiveKey={mailConfig && mailConfig.configured ? [] : ['box']}
        items={[
          { key: 'box', label: 'Настройка ящика', children: renderMailbox() },
          { key: 'profile', label: 'Реквизиты организации', children: renderProfileBlock() },
          { key: 'letter', label: 'Новое письмо в поддержку', children: renderComposer() },
        ]}
      />
      {renderPreview()}
      {renderReply()}
    </Space>
  );


  const renderFinal = () => (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Button type="primary" onClick={runFinalCheck} loading={Boolean(busy['final'])}>
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
            loading={Boolean(busy['reset'])}
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
