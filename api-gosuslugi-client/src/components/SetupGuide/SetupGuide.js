import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Alert,
  Button,
  Card,
  Col,
  Descriptions,
  Divider,
  Input,
  Modal,
  Radio,
  Row,
  Select,
  Space,
  Steps,
  Table,
  Tag,
  Tooltip,
  Typography,
} from 'antd';
import {
  ApiOutlined,
  CheckCircleOutlined,
  CloseCircleOutlined,
  CodeOutlined,
  CopyOutlined,
  DownloadOutlined,
  ExclamationCircleOutlined,
  ExportOutlined,
  FolderOpenOutlined,
  KeyOutlined,
  LinkOutlined,
  LoadingOutlined,
  MailOutlined,
  MinusCircleOutlined,
  ReloadOutlined,
  SafetyCertificateOutlined,
  SettingOutlined,
  UnorderedListOutlined,
} from '@ant-design/icons';
import axios from 'axios';
import { jwtDecode } from 'jwt-decode';
import { LETTERS, SENDER_HINT, letterToEml, letterToMailto, letterToText } from './letters';
import {
  CURL_ESIA_SNIPPET,
  CURL_TOKEN_SNIPPET,
  PROD_STEPS,
  REFERENCE_LINKS,
  TEST_STEPS,
} from './playbook';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL || '/api';

const { Title, Text, Paragraph } = Typography;

const codeStyle = {
  background: '#f8f9fa',
  border: '1px solid #edf0f5',
  padding: 12,
  borderRadius: 6,
  margin: '8px 0 0',
  fontFamily: 'Consolas, Menlo, Monaco, monospace',
  fontSize: 13,
  whiteSpace: 'pre-wrap',
  wordBreak: 'break-word',
  userSelect: 'text',
};

const mutedBlockStyle = {
  background: '#f8f9fa',
  border: '1px solid #edf0f5',
  padding: 16,
  borderRadius: 6,
  height: '100%',
};

const stepRowStyle = {
  display: 'flex',
  flexDirection: 'column',
  gap: 8,
  padding: '14px 0',
  borderTop: '1px solid #edf0f5',
};

const publicRuntimeSnippet = `docker compose up -d --build
docker compose logs -f api frontend
curl http://localhost:55000/version
curl http://localhost:55000/hc
curl http://localhost:55000/status`;

const ENV_PRESETS = {
  test: {
    label: 'Тестовый контур SVCDEV',
    TSAAddress: 'http://testca2012.cryptopro.ru/tsp/tsp.srf',
    esia_host: 'https://esia-portal1.test.gosuslugi.ru',
    svcdev_host: 'https://svcdev-gostapi.test.gosuslugi.ru',
    production: '',
  },
  prod: {
    label: 'Промышленный контур',
    TSAAddress: 'http://www.cryptopro.ru/tsp/tsp.srf',
    esia_host: 'https://esia.gosuslugi.ru',
    svcdev_host: 'https://www.gosuslugi.ru',
    production: '1',
  },
};

// ---------------------------------------------------------------------------
// Утилиты
// ---------------------------------------------------------------------------

function copyText(text) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    return navigator.clipboard.writeText(text);
  }
  return new Promise((resolve, reject) => {
    try {
      const area = document.createElement('textarea');
      area.value = text;
      area.style.position = 'fixed';
      area.style.opacity = '0';
      document.body.appendChild(area);
      area.select();
      document.execCommand('copy');
      document.body.removeChild(area);
      resolve();
    } catch (e) {
      reject(e);
    }
  });
}

function downloadText(filename, text, mime = 'text/plain;charset=utf-8') {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

const abbreviatedIdentifier = (value) => {
  const text = String(value || '');
  return text.length > 12 ? `${text.slice(0, 6)}...${text.slice(-4)}` : text;
};

/** Кнопка копирования, которая сама сообщает об успехе. */
function CopyButton({ text, label = 'Копировать', size = 'small', type = 'default', icon = true }) {
  const [done, setDone] = useState(false);
  const timer = useRef(null);

  useEffect(() => () => clearTimeout(timer.current), []);

  const handle = () => {
    copyText(text).then(
      () => {
        setDone(true);
        clearTimeout(timer.current);
        timer.current = setTimeout(() => setDone(false), 1800);
      },
      () => {
        setDone(false);
      },
    );
  };

  return (
    <Button
      size={size}
      type={type}
      onClick={handle}
      icon={icon ? (done ? <CheckCircleOutlined /> : <CopyOutlined />) : undefined}
    >
      {done ? 'Скопировано' : label}
    </Button>
  );
}

function CopyableCode({ children }) {
  return (
    <div>
      <Paragraph style={codeStyle}>{children}</Paragraph>
      <Space size={8} style={{ marginTop: 8 }}>
        <CopyButton text={children} />
        <Button
          size="small"
          icon={<DownloadOutlined />}
          onClick={() => downloadText('snippet.txt', children)}
        >
          Скачать
        </Button>
      </Space>
    </div>
  );
}

/** Ссылка, которую можно открыть, скопировать или выделить руками. */
function ActionLink({ url, label, primary = false }) {
  return (
    <Space size={6} wrap>
      <Button
        type={primary ? 'primary' : 'default'}
        size="small"
        icon={<ExportOutlined />}
        href={url}
        target="_blank"
        rel="noreferrer"
      >
        {label}
      </Button>
      <Tooltip title={url}>
        <span>
          <CopyButton text={url} label="Ссылка" />
        </span>
      </Tooltip>
      <Text copyable={{ text: url }} type="secondary" style={{ fontSize: 12, userSelect: 'text' }}>
        {url}
      </Text>
    </Space>
  );
}

// ---------------------------------------------------------------------------
// Модальное окно письма
// ---------------------------------------------------------------------------

function LetterModal({ letter, open, onClose }) {
  if (!letter) return null;

  const fullText = letterToText(letter);

  return (
    <Modal
      open={open}
      onCancel={onClose}
      width={780}
      title={
        <>
          <MailOutlined style={{ marginRight: 8 }} />
          {letter.name}
        </>
      }
      footer={[
        <Button key="close" onClick={onClose}>
          Закрыть
        </Button>,
        <Button
          key="eml"
          icon={<DownloadOutlined />}
          onClick={() => downloadText(`${letter.id}.eml`, letterToEml(letter), 'message/rfc822')}
        >
          Скачать .eml
        </Button>,
        <Button key="copy-all" type="primary" onClick={() => copyText(fullText)} icon={<CopyOutlined />}>
          Копировать письмо
        </Button>,
      ]}
    >
      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 16 }}
        message="Отправлять с почты организации"
        description={
          <Space wrap>
            <Text code style={{ userSelect: 'text' }}>
              {SENDER_HINT}
            </Text>
            <CopyButton text={SENDER_HINT} label="Скопировать формат" />
          </Space>
        }
      />

      <Descriptions
        size="small"
        bordered
        column={1}
        items={[
          {
            key: 'to',
            label: 'Кому',
            children: (
              <Space wrap>
                <Text style={{ userSelect: 'text' }}>{letter.to}</Text>
                <CopyButton text={letter.to} label="Адрес" />
              </Space>
            ),
          },
          ...(letter.cc
            ? [
                {
                  key: 'cc',
                  label: 'Копия',
                  children: (
                    <Space wrap>
                      <Text style={{ userSelect: 'text' }}>{letter.cc}</Text>
                      <CopyButton text={letter.cc} label="Адрес" />
                    </Space>
                  ),
                },
              ]
            : []),
          {
            key: 'subject',
            label: 'Тема',
            children: (
              <Space wrap>
                <Text style={{ userSelect: 'text' }}>{letter.subject}</Text>
                <CopyButton text={letter.subject} label="Тему" />
              </Space>
            ),
          },
        ]}
      />

      <div style={{ marginTop: 16 }}>
        <Space style={{ marginBottom: 8 }} wrap>
          <Text strong>Текст письма</Text>
          <CopyButton text={letter.body} label="Только текст" />
          <Button
            size="small"
            icon={<MailOutlined />}
            href={letterToMailto(letter)}
            target="_blank"
            rel="noreferrer"
          >
            Открыть в почтовом клиенте
          </Button>
        </Space>
        <Paragraph style={{ ...codeStyle, maxHeight: 320, overflowY: 'auto' }}>{letter.body}</Paragraph>
      </div>
    </Modal>
  );
}

// ---------------------------------------------------------------------------
// Шаг сценария
// ---------------------------------------------------------------------------

function StepRow({ index, step, resolveUrl, onLetter }) {
  const url = step.url ? resolveUrl(step) : null;

  return (
    <div style={stepRowStyle}>
      <Space align="start" size={10}>
        <Tag color="blue" style={{ marginTop: 2 }}>
          {index}
        </Tag>
        <div>
          <Text strong>{step.title}</Text>
          <Paragraph type="secondary" style={{ margin: '4px 0 0' }}>
            {step.text}
          </Paragraph>
        </div>
      </Space>

      <Space direction="vertical" size={8} style={{ width: '100%', paddingLeft: 42 }}>
        {url && <ActionLink url={url} label={step.linkLabel || 'Открыть'} primary />}

        {(step.extraLinks || []).map((extra) => (
          <ActionLink key={extra.url} url={extra.url} label={extra.label} />
        ))}

        {step.letter && (
          <Space wrap>
            <Button
              size="small"
              type="primary"
              ghost
              icon={<MailOutlined />}
              onClick={() => onLetter(step.letter)}
            >
              {step.letterLabel || 'Открыть шаблон письма'}
            </Button>
            <Text type="secondary" style={{ fontSize: 12 }}>
              {LETTERS[step.letter].to}
            </Text>
            <CopyButton text={LETTERS[step.letter].to} label="Адрес" />
          </Space>
        )}

        {step.code && (
          <div style={{ width: '100%' }}>
            <Text type="secondary" style={{ fontSize: 12 }}>
              {step.codeLabel}
            </Text>
            <CopyableCode>{step.code}</CopyableCode>
          </div>
        )}
      </Space>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Диагностика
// ---------------------------------------------------------------------------

function explainError(error, scope) {
  if (axios.isCancel(error)) return 'Проверка отменена.';
  if (error?.code === 'ERR_NETWORK' || !error?.response) {
    return 'Backend не отвечает. Поднимите контейнер: docker compose up -d api, затем docker compose logs -f api.';
  }

  const status = error.response.status;
  const detail = error.response.data?.detail;
  const tail = typeof detail === 'string' && detail ? ` Ответ сервера: ${detail}` : '';

  if (scope === 'token') {
    if (status === 400) {
      return `API-Key пустой или не похож на GUID. Возьмите ключ из ЛК ИЭП, раздел «Мои системы».${tail}`;
    }
    if (status === 401 || status === 403) {
      return `ЕСИА отклонила подпись. Обычно причина в одном из трёх: истёк срок API-Key, неверный KeyPin, либо подписывает не тот сертификат, что зарегистрирован для ИС.${tail}`;
    }
    if (status === 404) {
      return `ЕСИА не знает такой ИС. Сверьте мнемонику и то, что ключ выпущен для того же контура, что и esia_host.${tail}`;
    }
    if (status >= 500) {
      return `Ошибка на стороне ЕСИА или КриптоПро. Посмотрите docker compose logs -f api - там будет трассировка подписи.${tail}`;
    }
  }

  if (status === 400 && scope === 'currentCert') {
    return 'Текущий сертификат не выбран. Выберите его в разделе «Сертификат подписи» ниже.';
  }

  return `HTTP ${status}.${tail || ' Подробности в логах backend.'}`;
}

const STATE_META = {
  idle: { color: 'default', icon: <MinusCircleOutlined />, label: 'не проверялось' },
  run: { color: 'processing', icon: <LoadingOutlined />, label: 'проверяю' },
  ok: { color: 'success', icon: <CheckCircleOutlined />, label: 'готово' },
  warn: { color: 'warning', icon: <ExclamationCircleOutlined />, label: 'внимание' },
  fail: { color: 'error', icon: <CloseCircleOutlined />, label: 'ошибка' },
};

function StateTag({ state }) {
  const meta = STATE_META[state] || STATE_META.idle;
  return (
    <Tag color={meta.color} icon={meta.icon}>
      {meta.label}
    </Tag>
  );
}

const CHECK_ROWS = [
  { key: 'version', name: 'Backend API отвечает', endpoint: 'GET /version' },
  { key: 'hc', name: 'Signing runtime готов', endpoint: 'GET /hc' },
  { key: 'status', name: 'КриптоПро и PyCades', endpoint: 'GET /status' },
  { key: 'env', name: 'Контур определён', endpoint: 'GET /version' },
  { key: 'cors', name: 'CORS ограничен', endpoint: 'GET /version' },
  { key: 'certs', name: 'Сертификаты видны', endpoint: 'POST /get_certificates' },
  { key: 'currentCert', name: 'Текущий сертификат выбран', endpoint: 'POST /get_current_certificate' },
  { key: 'token', name: 'Маркер доступа ЕСИА', endpoint: 'GET /version' },
  { key: 'services', name: 'Каталог услуг', endpoint: 'GET /services' },
  { key: 'envLeak', name: 'Файл .env не раздаётся наружу', endpoint: 'GET /.env' },
];

const INITIAL_CHECKS = CHECK_ROWS.reduce((acc, row) => {
  acc[row.key] = { state: 'idle' };
  return acc;
}, {});

// ---------------------------------------------------------------------------

export default function SetupGuide() {
  const api = useMemo(() => axios.create({ baseURL: BACKEND_URL, timeout: 20000 }), []);

  const [checks, setChecks] = useState(INITIAL_CHECKS);
  const [certificates, setCertificates] = useState([]);
  const [currentCertId, setCurrentCertId] = useState(null);
  const [services, setServices] = useState([]);
  const [version, setVersion] = useState(null);
  const [environments, setEnvironments] = useState(null);
  const [busy, setBusy] = useState(false);
  const [activeLetter, setActiveLetter] = useState(null);

  const patch = useCallback((key, value) => {
    setChecks((prev) => ({ ...prev, [key]: value }));
  }, []);

  const runChecks = useCallback(async () => {
    setBusy(true);

    patch('version', { state: 'run' });
    let backendAlive = false;
    let versionData = {};
    try {
      const res = await api.get('/version');
      backendAlive = true;
      versionData = res.data || {};
      setVersion(versionData);
      patch('version', {
        state: 'ok',
        summary: `Backend API отвечает, спецификация ${versionData.spec_version || 'не указана'}.`,
      });
    } catch (e) {
      patch('version', { state: 'fail', summary: explainError(e, 'version') });
    }

    if (!backendAlive) {
      CHECK_ROWS.filter((r) => r.key !== 'version').forEach((r) =>
        patch(r.key, { state: 'idle', summary: 'Пропущено: backend не отвечает.' }),
      );
      setBusy(false);
      return;
    }

    patch('hc', { state: 'run' });
    try {
      const res = await api.get('/hc');
      const signingReady = res.data?.status === 'Ok';
      patch('hc', {
        state: signingReady ? 'ok' : 'warn',
        summary: signingReady
          ? 'Signing runtime и КриптоПро готовы.'
          : 'Backend API работает, но signing runtime не готов.',
      });
    } catch (e) {
      patch('hc', {
        state: 'warn',
        summary: 'Backend API работает, но signing runtime недоступен. Для подписи нужен лицензированный custom image с PyCades/КриптоПро.',
      });
    }

    patch('status', { state: 'run' });
    try {
      const res = await api.get('/status');
      patch('status', {
        state: 'ok',
        summary: `PyCades ${res.data?.Version ?? '?'}, модуль ${res.data?.ModuleVersion ?? '?'}.`,
      });
    } catch (e) {
      patch('status', {
        state: 'warn',
        summary: 'PyCades/КриптоПро не доступны в публичном образе; настройте лицензированный signing runtime для отправки.',
      });
    }

    // /version закрывает три пункта, которые раньше числились «непроверяемыми»:
    // контур, ширину CORS и наличие живого маркера доступа.
    patch('env', { state: 'run' });
    patch('cors', { state: 'run' });
    patch('token', { state: 'run' });
    {
      const data = versionData;
      const envName = data.environment;
      const hosts = data.hosts || {};
      patch('env', {
        state: envName === 'custom' ? 'warn' : 'ok',
        summary:
          envName === 'custom'
            ? `Хосты не совпадают ни с одним известным контуром: ${hosts.esia_host} + ${hosts.svcdev_host}. Легко перепутать тест и прод.`
            : `Контур ${envName === 'prod' ? 'промышленный' : 'тестовый'}, спецификация ${data.spec_version}.`,
        env: envName,
      });

      const origins = data.runtime?.allowed_origins || [];
      const wildcard = origins.includes('*');
      patch('cors', {
        state: wildcard && envName === 'prod' ? 'fail' : wildcard ? 'warn' : 'ok',
        summary: wildcard
          ? `CORS открыт всем: allowed_origins = ${JSON.stringify(origins)}.${
              envName === 'prod' ? ' В проде так нельзя.' : ' Для теста допустимо, в прод так не выкатывать.'
            }`
          : `CORS ограничен: ${JSON.stringify(origins)}.`,
      });

      const hasToken = data.runtime?.has_access_tkn;
      const exp = data.runtime?.access_tkn_exp || 0;
      const leftMin = exp ? Math.round((exp * 1000 - Date.now()) / 60000) : 0;
      patch('token', {
        state: hasToken && leftMin > 0 ? 'ok' : 'warn',
        summary: hasToken
          ? leftMin > 0
            ? `Маркер получен, осталось ${leftMin} мин.`
            : 'Маркер получен, но уже истёк. Запросите заново.'
          : 'Маркер ещё не запрашивался. Проверьте API-Key ниже.',
      });
    }

    patch('certs', { state: 'run' });
    try {
      const res = await api.post('/get_certificates');
      const list = Array.isArray(res.data) ? res.data : [];
      setCertificates(list);
      patch('certs', {
        state: list.length ? 'ok' : 'warn',
        summary: list.length
          ? `Видно сертификатов: ${list.length}.`
          : 'Сертификаты не найдены. Публичный образ не включает лицензированный signing runtime; для подписи нужен собственный образ с PyCades/КриптоПро и внешним хранилищем ключей.',
      });
    } catch (e) {
      patch('certs', {
        state: 'warn',
        summary: 'Сертификаты недоступны: настройте лицензированный custom signing runtime для операций подписи.',
      });
    }

    patch('currentCert', { state: 'run' });
    try {
      const res = await api.post('/get_current_certificate');
      const certId = res.data?.certId ?? null;
      setCurrentCertId(certId);
      patch('currentCert', {
        state: certId ? 'ok' : 'warn',
        summary: certId ? `Текущий сертификат: ${certId}.` : 'Сертификат ещё не выбран.',
      });
    } catch (e) {
      setCurrentCertId(null);
      patch('currentCert', { state: 'warn', summary: explainError(e, 'currentCert') });
    }

    patch('services', { state: 'run' });
    try {
      const res = await api.get('/services');
      const list = Array.isArray(res.data) ? res.data : [];
      setServices(list);
      patch('services', {
        state: list.length ? 'ok' : 'warn',
        summary: list.length
          ? `Услуг сконфигурировано: ${list.length}.`
          : 'Backend вернул пустой каталог. В обычной сборке используется встроенный versioned-каталог; SERVICES_OVERRIDE нужен только для явного overlay.',
      });
    } catch (e) {
      patch('services', { state: 'fail', summary: explainError(e, 'services') });
    }

    // Проверяем не конфиг, а факт: отдаёт ли веб-сервер .env наружу.
    patch('envLeak', { state: 'run' });
    try {
      const res = await fetch('/.env', { method: 'GET', cache: 'no-store' });
      const body = res.ok ? await res.text() : '';
      const looksLikeEnv = /(^|\n)\s*(apikey|KeyPin|SERVICES)\s*=/.test(body);
      let summary;
      if (res.ok && looksLikeEnv) {
        summary =
          'Файл .env отдаётся по HTTP - apikey и KeyPin доступны любому. Уберите его из корня раздачи nginx.';
      } else if (res.ok) {
        summary = 'Отдаётся страница приложения, а не .env: сработала SPA-заглушка nginx. Секреты наружу не уходят.';
      } else {
        summary = `Веб-сервер не отдаёт .env (HTTP ${res.status}).`;
      }
      patch('envLeak', { state: res.ok && looksLikeEnv ? 'fail' : 'ok', summary });
    } catch (e) {
      patch('envLeak', {
        state: 'warn',
        summary: 'Проверить не удалось - запрос к /.env не прошёл. Это не значит, что файл закрыт.',
      });
    }

    // Справочник контуров - чтобы ссылки в сценарии брались с backend.
    try {
      const res = await api.get('/environments');
      setEnvironments(res.data || null);
    } catch (e) {
      setEnvironments(null);
    }

    setBusy(false);
  }, [api, patch]);

  useEffect(() => {
    runChecks();
  }, [runChecks]);

  // ---- сертификат ---------------------------------------------------------

  const [certPick, setCertPick] = useState(null);
  const [certSaving, setCertSaving] = useState(false);
  const [certNotice, setCertNotice] = useState(null);

  const applyCertificate = async () => {
    if (!certPick) return;
    setCertSaving(true);
    setCertNotice(null);
    try {
      // Backend объявляет cert_id query-параметром, поэтому не тело, а params
      await api.post('/set_current_certificate', null, { params: { cert_id: certPick } });
      setCurrentCertId(certPick);
      setTokenState({ state: 'idle' });
      patch('currentCert', {
        state: 'ok',
        summary: `Текущий сертификат: ${abbreviatedIdentifier(certPick)}.`,
      });
      setCertNotice({ type: 'success', text: 'Сертификат выбран. Теперь им подписывается API-Key.' });
    } catch (e) {
      setCertNotice({ type: 'error', text: explainError(e, 'setCert') });
    } finally {
      setCertSaving(false);
    }
  };

  // ---- API-Key ------------------------------------------------------------

  const [apiKey, setApiKey] = useState('');
  const [tokenState, setTokenState] = useState({ state: 'idle' });

  const checkApiKey = async () => {
    const key = apiKey.trim();
    if (!key) {
      setTokenState({ state: 'fail', summary: 'Введите API-Key - GUID из ЛК ИЭП.' });
      return;
    }
    setTokenState({ state: 'run' });
    try {
      const res = await api.post('/accessTkn_esia', { api_key: key });
      const accessTkn = res.data?.accessTkn;
      if (!accessTkn) {
        setTokenState({
          state: 'fail',
          summary: 'ЕСИА ответила без accessTkn. Скорее всего, ИС не разрешено получать маркер доступа.',
        });
        return;
      }
      let claims = {};
      try {
        claims = jwtDecode(accessTkn) || {};
      } catch (e) {
        claims = {};
      }
      setTokenState({
        state: 'ok',
        summary: 'Маркер доступа получен - связка сертификат + KeyPin + API-Key рабочая.',
        claims,
      });
      setApiKey('');
      runChecks();
    } catch (e) {
      setTokenState({ state: 'fail', summary: explainError(e, 'token') });
    }
  };

  const tokenRows = useMemo(() => {
    const claims = tokenState.claims;
    if (!claims) return [];
    const rows = [];
    if (claims.iss) rows.push({ label: 'Издатель', value: String(claims.iss) });
    if (claims.sbj) rows.push({ label: 'Субъект', value: String(claims.sbj) });
    if (claims.scope) rows.push({ label: 'Scope', value: String(claims.scope) });
    if (claims.exp) {
      const expMs = claims.exp * 1000;
      const left = Math.round((expMs - Date.now()) / 60000);
      rows.push({
        label: 'Действует до',
        value: `${new Date(expMs).toLocaleString('ru-RU')} (${left > 0 ? `осталось ${left} мин` : 'истёк'})`,
      });
    }
    return rows;
  }, [tokenState]);

  // ---- автоматическая диагностика 401 ------------------------------------

  const [triage, setTriage] = useState({ state: 'idle', items: [] });

  const runTriage = async () => {
    setTriage({ state: 'run', items: [] });
    const items = [];

    items.push(
      currentCertId
        ? {
            state: 'ok',
            text: `Сертификат подписи выбран: ${abbreviatedIdentifier(currentCertId)}.`,
          }
        : {
            state: 'fail',
            text: 'Сертификат подписи не выбран - подписать API-Key нечем. Это причина №1 для 401.',
          },
    );

    // Не проверяем env-ключ пустым POST: это был запрос на подпись и
    // внешний вызов, а его ошибка не доказывала наличие или отсутствие apikey.
    const hasToken = Boolean(version?.runtime?.has_access_tkn);
    items.push(
      hasToken
        ? {
            state: 'ok',
            text: 'Текущий backend уже получал маркер ЕСИА; это подтверждает прежнюю успешную связку с API-Key.',
          }
        : {
            state: 'warn',
            text: 'Наличие apikey в окружении backend удалённо не раскрывается. Введите API-Key выше и запустите явную проверку.',
          }
    );

    const envCheck = checks.env;
    items.push(
      envCheck?.env === 'custom'
        ? {
            state: 'warn',
            text: 'Хосты не совпадают с известными контурами: ключ теста, отправленный в прод, всегда даёт 401.',
          }
        : { state: 'ok', text: `Ключ и хосты должны быть от одного контура: сейчас ${envCheck?.env}.` },
    );

    const exp = version?.runtime?.access_tkn_exp || 0;
    if (exp) {
      const leftMin = Math.round((exp * 1000 - Date.now()) / 60000);
      items.push(
        leftMin > 0
          ? { state: 'ok', text: `Текущий маркер жив ещё ${leftMin} мин.` }
          : { state: 'warn', text: 'Текущий маркер истёк - запросите новый перед отправкой заявления.' },
      );
    }

    setTriage({ state: 'done', items });
  };

  // ---- генератор .env -----------------------------------------------------

  const [envMode, setEnvMode] = useState('test');
  const [generatedEnvVisible, setGeneratedEnvVisible] = useState(false);
  const [envForm, setEnvForm] = useState({
    apikey: '',
    KeyPin: '',
    API_PORT: '55000',
    FRONTEND_PORT: '50080',
  });
  const [envServices, setEnvServices] = useState('');

  const setEnvField = (field) => (event) => {
    const value = event?.target ? event.target.value : event;
    setEnvForm((prev) => ({ ...prev, [field]: value }));
  };

  const switchEnvMode = (mode) => {
    setEnvMode(mode);
  };

  const pullServicesFromStand = () => {
    const dict = services.reduce((acc, item) => {
      const entry = {
        description: item.description || '',
        req_file: item.req_file || '',
        piev_epgu_file: item.piev_epgu_file || '',
      };
      if (item.targetCode) entry.targetCode = item.targetCode;
      if (item.eServiceCode) entry.eServiceCode = item.eServiceCode;
      if (item.serviceTargetCode) entry.serviceTargetCode = item.serviceTargetCode;
      if (item.region) entry.region = item.region;
      acc[item.serviceCode] = entry;
      return acc;
    }, {});
    setEnvServices(JSON.stringify(dict));
  };

  const generatedEnv = useMemo(() => {
    const preset = ENV_PRESETS[envMode];
    return [
      `apikey=${envForm.apikey || '<GUID-API-KEY>'}`,
      `KeyPin=${envForm.KeyPin || '<PIN-код контейнера>'}`,
      `TSAAddress=${preset.TSAAddress}`,
      `esia_host=${preset.esia_host}`,
      `svcdev_host=${preset.svcdev_host}`,
      `production=${preset.production}`,
      'BACKEND_URL=/api',
      'BACKEND_API=http://api:5000',
      `API_PORT=${envForm.API_PORT}`,
      `FRONTEND_PORT=${envForm.FRONTEND_PORT}`,
      `SERVICES_OVERRIDE=${envServices}`,
    ].join('\n');
  }, [envMode, envForm, envServices]);

  // ---- ссылки из живого справочника контуров -----------------------------

  const detectedEnv = checks.env?.env === 'prod' ? 'prod' : 'test';

  const resolveUrl = useCallback(
    (step) => {
      if (step.envKey && environments) {
        const scope = step.id.startsWith('p') ? 'prod' : 'test';
        const value = environments[scope]?.[step.envKey];
        if (value) return value;
      }
      return step.url;
    },
    [environments],
  );

  const referenceLinks = useMemo(
    () =>
      REFERENCE_LINKS.map((item) => {
        if (item.envKey && environments && item.env !== 'both') {
          const value = environments[item.env]?.[item.envKey];
          if (value) return { ...item, url: value };
        }
        return item;
      }),
    [environments],
  );

  // ---- шаги готовности ----------------------------------------------------

  const anchors = {
    docker: useRef(null),
    env: useRef(null),
    cert: useRef(null),
    key: useRef(null),
    services: useRef(null),
    playbook: useRef(null),
  };

  const scrollTo = (name) => {
    const node = anchors[name]?.current;
    if (node) node.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  const stepStatus = (state) => {
    if (state === 'ok') return 'finish';
    if (state === 'fail') return 'error';
    if (state === 'run') return 'process';
    return 'wait';
  };

  const stepItems = [
    {
      title: 'Стенд поднят',
      description: checks.version.summary || 'Backend API доступен.',
      status: stepStatus(checks.version.state),
      icon: <FolderOpenOutlined />,
    },
    {
      title: 'Окружение',
      description: checks.env.summary || 'Контур и переменные .env.',
      status: stepStatus(checks.env.state === 'warn' ? 'idle' : checks.env.state),
      icon: <CodeOutlined />,
    },
    {
      title: 'Сертификат',
      description: checks.currentCert.summary || 'Подпись API-Key.',
      status: stepStatus(checks.currentCert.state === 'warn' ? 'idle' : checks.currentCert.state),
      icon: <SafetyCertificateOutlined />,
    },
    {
      title: 'API-Key ЕПГУ',
      description: tokenState.summary || checks.token.summary || 'Маркер доступа ЕСИА.',
      status: stepStatus(tokenState.state),
      icon: <KeyOutlined />,
    },
    {
      title: 'Услуги',
      description: checks.services.summary || 'Встроенный versioned-каталог услуг.',
      status: stepStatus(checks.services.state === 'warn' ? 'idle' : checks.services.state),
      icon: <UnorderedListOutlined />,
    },
    {
      title: 'Подключение',
      description: 'Письма и кабинеты Оператора.',
      status: 'wait',
      icon: <MailOutlined />,
    },
  ];

  const stepAnchors = ['docker', 'env', 'cert', 'key', 'services', 'playbook'];

  const blockers = Object.values(checks).filter((c) => c.state === 'fail').length;
  const warnings = Object.values(checks).filter((c) => c.state === 'warn').length;
  const ready = blockers === 0 && checks.version.state === 'ok';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <LetterModal
        letter={activeLetter ? LETTERS[activeLetter] : null}
        open={Boolean(activeLetter)}
        onClose={() => setActiveLetter(null)}
      />

      <div
        style={{
          background: '#fff',
          border: '1px solid #edf0f5',
          borderRadius: 8,
          padding: '24px 28px',
        }}
      >
        <Space align="start" size="middle">
          <SettingOutlined style={{ fontSize: 26, color: '#1677ff', marginTop: 4 }} />
          <div>
            <Title level={3} style={{ marginTop: 0, marginBottom: 8 }}>
              Настройка работы
            </Title>
            <Paragraph style={{ marginBottom: 12, maxWidth: 960 }}>
              Всё, что можно нажать, нажимается отсюда: проверки идут реальными запросами,
              ссылки открываются и копируются, письма Оператору открываются шаблоном с
              адресом, темой и текстом. Ничего не отправляется без вас.
            </Paragraph>
            <Space wrap>
              <Tag color="blue">HOWTO.md</Tag>
              <Tag color="blue">docs/deployment.md</Tag>
              <Tag color="blue">docs/SERVICES.md</Tag>
              <Tag color="blue">docs/security.md</Tag>
              <Tag color="blue">step/STEP.md</Tag>
              <Tag>регламенты ЕПГУ / ЕСИА</Tag>
            </Space>
          </div>
        </Space>
      </div>

      {/* ---------- живая диагностика ---------- */}
      <Card
        title={
          <>
            <ApiOutlined style={{ marginRight: 8 }} />
            Состояние стенда
          </>
        }
        extra={
          <Button icon={<ReloadOutlined />} onClick={runChecks} loading={busy}>
            Проверить заново
          </Button>
        }
      >
        {ready ? (
          <Alert
            type={warnings ? 'warning' : 'success'}
            showIcon
            message={warnings ? `Стенд работает, замечаний: ${warnings}` : 'Стенд готов к работе'}
            description={
              warnings
                ? 'Жёлтые строки не блокируют работу, но в прод с ними выкатываться не стоит.'
                : 'Осталось проверить API-Key - тогда можно подавать заявления на вкладке «Главная».'
            }
            style={{ marginBottom: 16 }}
          />
        ) : (
          <Alert
            type={blockers ? 'error' : 'info'}
            showIcon
            message={blockers ? `Проверок не прошло: ${blockers}` : 'Идёт проверка стенда'}
            description={
              blockers
                ? 'Разберите красные строки сверху вниз - каждая следующая зависит от предыдущей.'
                : 'Результаты появятся через пару секунд.'
            }
            style={{ marginBottom: 16 }}
          />
        )}

        <Steps
          direction="horizontal"
          responsive
          size="small"
          items={stepItems}
          onChange={(index) => scrollTo(stepAnchors[index])}
          style={{ marginBottom: 20 }}
        />

        <Table
          size="small"
          pagination={false}
          rowKey="key"
          dataSource={CHECK_ROWS}
          columns={[
            { title: 'Проверка', dataIndex: 'name', width: 230 },
            {
              title: 'Запрос',
              dataIndex: 'endpoint',
              width: 210,
              render: (value) => <Text code>{value}</Text>,
            },
            {
              title: 'Статус',
              width: 130,
              render: (_, row) => <StateTag state={checks[row.key]?.state} />,
            },
            {
              title: 'Результат',
              render: (_, row) => (
                <Text type={checks[row.key]?.state === 'fail' ? 'danger' : undefined}>
                  {checks[row.key]?.summary || '-'}
                </Text>
              ),
            },
          ]}
        />

        <Divider style={{ margin: '20px 0 16px' }} />

        <Space direction="vertical" size={12} style={{ width: '100%' }}>
          <Space wrap align="center">
            <Button onClick={runTriage} loading={triage.state === 'run'} icon={<KeyOutlined />}>
              Разобрать причину 401
            </Button>
            <Text type="secondary">
              Пройдёт по всем причинам отказа ЕСИА и скажет, какая именно ваша.
            </Text>
          </Space>

          {triage.state === 'done' && (
            <div style={mutedBlockStyle}>
              {triage.items.map((item, index) => (
                <div key={index} style={{ display: 'flex', gap: 10, padding: '4px 0' }}>
                  <StateTag state={item.state} />
                  <Text type={item.state === 'fail' ? 'danger' : undefined}>{item.text}</Text>
                </div>
              ))}
            </div>
          )}

          {version && (
            <details>
              <summary style={{ cursor: 'pointer', color: '#1677ff' }}>
                Сырой ответ GET /version - проверьте сами, что мы ничего не выдумали
              </summary>
              <CopyableCode>{JSON.stringify(version, null, 2)}</CopyableCode>
            </details>
          )}
        </Space>
      </Card>

      {/* ---------- 1. контейнер и docker ---------- */}
      <div ref={anchors.docker}>
        <Card
          title={
            <>
              <FolderOpenOutlined style={{ marginRight: 8 }} />
              Docker и signing runtime
            </>
          }
          extra={<StateTag state={checks.hc.state} />}
        >
          <Row gutter={[16, 16]}>
            <Col xs={24} lg={8}>
              <div style={mutedBlockStyle}>
                <Title level={5} style={{ marginTop: 0 }}>
                  1. Публичный образ
                </Title>
                <Paragraph>
                  Публикуемый backend намеренно не содержит проприетарные КриптоПро и
                  PyCades. Каталог, XML и безопасные API доступны без них; подпись - нет.
                </Paragraph>
                <CopyableCode>{publicRuntimeSnippet}</CopyableCode>
              </div>
            </Col>
            <Col xs={24} lg={8}>
              <div style={mutedBlockStyle}>
                <Title level={5} style={{ marginTop: 0 }}>
                  2. Подключить подпись
                </Title>
                <Paragraph>
                  Для отправки используйте собственный лицензированный образ backend с
                  совместимыми PyCades/КриптоПро. Хранилище ключей подключайте явно по
                  документации поставщика и держите вне репозитория.
                </Paragraph>
                <Alert
                  type="warning"
                  showIcon
                  message="Один key mount не превращает публичный образ в signing runtime"
                />
              </div>
            </Col>
            <Col xs={24} lg={8}>
              <div style={mutedBlockStyle}>
                <Title level={5} style={{ marginTop: 0 }}>
                  3. Запустить и проверить
                </Title>
                <Paragraph>
                  UI доступен на `:50080`, Swagger backend - на `:55000/docs`.
                  `/version` проверяет liveness API; `/hc` и `/status` отдельно показывают
                  готовность лицензированного signing runtime.
                </Paragraph>
                <CopyableCode>{publicRuntimeSnippet}</CopyableCode>
              </div>
            </Col>
          </Row>
        </Card>
      </div>

      {/* ---------- 2. генератор .env ---------- */}
      <div ref={anchors.env}>
        <Card
          title={
            <>
              <CodeOutlined style={{ marginRight: 8 }} />
              Переменные окружения
            </>
          }
          extra={
            <Radio.Group
              value={envMode}
              onChange={(e) => switchEnvMode(e.target.value)}
              optionType="button"
              buttonStyle="solid"
              options={[
                { label: 'Тест', value: 'test' },
                { label: 'Прод', value: 'prod' },
              ]}
            />
          }
        >
          {checks.env?.env && checks.env.env !== envMode && checks.env.env !== 'custom' && (
            <Alert
              type="info"
              showIcon
              style={{ marginBottom: 16 }}
              message={`Стенд сейчас работает в контуре «${checks.env.env}», а в генераторе выбран «${envMode}»`}
              description="Это нормально, если вы готовите конфиг для другой среды. Просто не перепутайте при выкладке."
            />
          )}
          <Row gutter={[20, 20]}>
            <Col xs={24} lg={10}>
              <Title level={5} style={{ marginTop: 0 }}>
                {ENV_PRESETS[envMode].label}
              </Title>
              <Paragraph type="secondary" style={{ marginBottom: 16 }}>
                Хосты, TSA и признак `production` подставляются под выбранный контур.
                Заполните остальное - справа соберётся готовый файл.
              </Paragraph>

              <Space direction="vertical" size={12} style={{ width: '100%' }}>
                <div>
                  <Text strong>apikey</Text>
                  <Input.Password
                    autoComplete="off"
                    value={envForm.apikey}
                    onChange={setEnvField('apikey')}
                    placeholder="GUID из ЛК ИЭП"
                  />
                </div>
                <div>
                  <Text strong>KeyPin</Text>
                  <Input.Password
                    value={envForm.KeyPin}
                    onChange={setEnvField('KeyPin')}
                    placeholder="PIN контейнера"
                  />
                </div>
                <Row gutter={8}>
                  <Col span={12}>
                    <Text strong>API_PORT</Text>
                    <Input value={envForm.API_PORT} onChange={setEnvField('API_PORT')} />
                  </Col>
                  <Col span={12}>
                    <Text strong>FRONTEND_PORT</Text>
                    <Input value={envForm.FRONTEND_PORT} onChange={setEnvField('FRONTEND_PORT')} />
                  </Col>
                </Row>
                <div>
                  <Space align="baseline" style={{ justifyContent: 'space-between', width: '100%' }}>
                    <Text strong>SERVICES_OVERRIDE (необязательно)</Text>
                    <Button size="small" onClick={pullServicesFromStand} disabled={!services.length}>
                      Подставить с текущего стенда ({services.length})
                    </Button>
                  </Space>
                  <Input.TextArea
                    value={envServices}
                    onChange={(e) => setEnvServices(e.target.value)}
                    autoSize={{ minRows: 2, maxRows: 6 }}
                    placeholder='Пусто - используется встроенный service_profiles.json'
                  />
                </div>
              </Space>
            </Col>

            <Col xs={24} lg={14}>
              <Space style={{ marginBottom: 8 }} wrap>
                <Title level={5} style={{ margin: 0 }}>
                  Готовый .env
                </Title>
                <Button
                  size="small"
                  icon={<DownloadOutlined />}
                  onClick={() => {
                    if (
                      window.confirm(
                        'Скачать .env с API-Key и PIN в открытом виде на локальный диск?'
                      )
                    ) {
                      downloadText('.env', generatedEnv);
                    }
                  }}
                >
                  Скачать .env
                </Button>
                <Button
                  size="small"
                  onClick={() => setGeneratedEnvVisible((visible) => !visible)}
                >
                  {generatedEnvVisible ? 'Скрыть секреты' : 'Показать готовый .env'}
                </Button>
              </Space>
              <Paragraph type="secondary" style={{ marginBottom: 8 }}>
                Положите файл в корень репозитория рядом с `docker-compose.yml`.
              </Paragraph>
              {generatedEnvVisible ? (
                <CopyableCode>{generatedEnv}</CopyableCode>
              ) : (
                <Alert
                  type="info"
                  showIcon
                  message="Готовый .env скрыт: он содержит API-Key и PIN"
                />
              )}
              <Alert
                type="warning"
                showIcon
                style={{ marginTop: 16 }}
                message="`.env` не коммитить"
                description="Файл содержит apikey и KeyPin. Проверка «Файл .env не раздаётся наружу» выше следит за тем, чтобы его хотя бы не отдавал веб-сервер."
              />
            </Col>
          </Row>
        </Card>
      </div>

      {/* ---------- 3. сертификат ---------- */}
      <div ref={anchors.cert}>
        <Card
          title={
            <>
              <SafetyCertificateOutlined style={{ marginRight: 8 }} />
              Сертификат подписи
            </>
          }
          extra={<StateTag state={checks.currentCert.state} />}
        >
          <Paragraph>
            Этим сертификатом backend подписывает API-Key перед обращением в ЕСИА. Список
            предоставляет лицензированный signing runtime. Публичный образ без
            PyCades/КриптоПро закономерно вернёт пустой список или 503.
          </Paragraph>

          <Space wrap align="start" style={{ width: '100%' }}>
            <Select
              style={{ minWidth: 380 }}
              placeholder={certificates.length ? 'Выберите сертификат' : 'Сертификаты не найдены'}
              value={certPick ?? currentCertId ?? undefined}
              onChange={setCertPick}
              disabled={!certificates.length}
              options={certificates.map((cert) => ({
                value: cert.id,
                label: `${cert.subject} - ${cert.id}`,
              }))}
            />
            <Button
              type="primary"
              onClick={applyCertificate}
              loading={certSaving}
              disabled={!certPick || certPick === currentCertId}
            >
              Сделать текущим
            </Button>
          </Space>

          {currentCertId && (
            <Paragraph style={{ marginTop: 12, marginBottom: 0 }}>
              Сейчас выбран: <Text code>{currentCertId}</Text>
            </Paragraph>
          )}

          {certNotice && (
            <Alert type={certNotice.type} showIcon style={{ marginTop: 12 }} message={certNotice.text} />
          )}
        </Card>
      </div>

      {/* ---------- 4. API-Key ---------- */}
      <div ref={anchors.key}>
        <Card
          title={
            <>
              <KeyOutlined style={{ marginRight: 8 }} />
              Проверка API-Key ЕПГУ
            </>
          }
          extra={<StateTag state={tokenState.state} />}
        >
          <Paragraph>
            Кнопка делает настоящий запрос: backend подписывает ключ выбранным сертификатом
            и просит у ЕСИА маркер доступа. Это самая честная проверка связки
            «сертификат + KeyPin + API-Key».
          </Paragraph>

          <Space.Compact style={{ width: '100%', maxWidth: 720 }}>
            <Input.Password
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder="API-Key из ЛК ИЭП, раздел «Мои системы»"
              onPressEnter={checkApiKey}
            />
            <Button type="primary" onClick={checkApiKey} loading={tokenState.state === 'run'}>
              Проверить ключ
            </Button>
          </Space.Compact>

          {tokenState.state === 'ok' && (
            <>
              <Alert type="success" showIcon style={{ marginTop: 16 }} message={tokenState.summary} />
              {tokenRows.length > 0 && (
                <Descriptions
                  size="small"
                  bordered
                  column={1}
                  style={{ marginTop: 16 }}
                  items={tokenRows.map((row, index) => ({
                    key: String(index),
                    label: row.label,
                    children: row.value,
                  }))}
                />
              )}
            </>
          )}

          {tokenState.state === 'fail' && (
            <Alert
              type="error"
              showIcon
              style={{ marginTop: 16 }}
              message="Маркер доступа не получен"
              description={tokenState.summary}
            />
          )}

          <Alert
            type="info"
            showIcon
            style={{ marginTop: 16 }}
            message="Ключ никуда не сохраняется, и это можно проверить"
            description="Значение живёт только в поле на этой странице. Ниже - те же запросы в curl: выполните их сами и сверьте, что уходит ровно это и никуда больше."
          />

          <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
            <Col xs={24} lg={12}>
              <Text strong>Через наш backend</Text>
              <CopyableCode>{CURL_TOKEN_SNIPPET}</CopyableCode>
            </Col>
            <Col xs={24} lg={12}>
              <Text strong>Напрямую в ЕСИА, мимо нас</Text>
              <CopyableCode>{CURL_ESIA_SNIPPET}</CopyableCode>
            </Col>
          </Row>
        </Card>
      </div>

      {/* ---------- 5. услуги ---------- */}
      <div ref={anchors.services}>
        <Card
          title={
            <>
              <UnorderedListOutlined style={{ marginRight: 8 }} />
              Услуги, доступные стенду
            </>
          }
          extra={
            <Space>
              <StateTag state={checks.services.state} />
              {services.length > 0 && (
                <Button
                  size="small"
                  icon={<DownloadOutlined />}
                  onClick={() => downloadText('services.json', JSON.stringify(services, null, 2))}
                >
                  Скачать JSON
                </Button>
              )}
            </Space>
          }
        >
          {services.length ? (
            <Table
              size="small"
              rowKey="serviceCode"
              pagination={false}
              scroll={{ x: true }}
              dataSource={services}
              columns={[
                { title: 'Код', dataIndex: 'serviceCode', width: 130 },
                { title: 'Описание', dataIndex: 'description' },
                { title: 'targetCode', dataIndex: 'targetCode', width: 140 },
                { title: 'Регион', dataIndex: 'region', width: 120 },
                { title: 'req', dataIndex: 'req_file', width: 100 },
                { title: 'piev_epgu', dataIndex: 'piev_epgu_file', width: 120 },
              ]}
            />
          ) : (
            <Alert
              type="warning"
              showIcon
              message="Каталог услуг пуст"
              description="Обычная сборка использует встроенный versioned-каталог. Проверьте целостность service_profiles.json; SERVICES_OVERRIDE нужен только для явного overlay."
            />
          )}
        </Card>
      </div>

      {/* ---------- 6. сценарий подключения ---------- */}
      <div ref={anchors.playbook}>
        <Card
          title={
            <>
              <SafetyCertificateOutlined style={{ marginRight: 8 }} />
              Подключение: кабинеты, ключи, письма
            </>
          }
          extra={
            <Tag color={detectedEnv === 'prod' ? 'red' : 'blue'}>
              стенд в контуре {detectedEnv === 'prod' ? 'прод' : 'тест'}
            </Tag>
          }
        >
          <Paragraph type="secondary">
            Выпуск API-Key - процесс на стороне Оператора, кнопкой его не заменить. Но всё
            остальное здесь нажимается: кабинет открывается, адрес копируется, письмо
            открывается готовым - с адресом, темой и текстом, который можно скачать .eml
            или отдать почтовому клиенту.
          </Paragraph>

          <Row gutter={[24, 24]}>
            <Col xs={24} xl={12}>
              <Title level={5} style={{ marginTop: 0 }}>
                Тестовый контур
              </Title>
              {TEST_STEPS.map((step, index) => (
                <StepRow
                  key={step.id}
                  index={index + 1}
                  step={step}
                  resolveUrl={resolveUrl}
                  onLetter={setActiveLetter}
                />
              ))}
            </Col>
            <Col xs={24} xl={12}>
              <Title level={5} style={{ marginTop: 0 }}>
                Промышленный контур
              </Title>
              {PROD_STEPS.map((step, index) => (
                <StepRow
                  key={step.id}
                  index={index + 1}
                  step={step}
                  resolveUrl={resolveUrl}
                  onLetter={setActiveLetter}
                />
              ))}
            </Col>
          </Row>

          <Divider />

          <Paragraph style={{ marginBottom: 12 }}>
            Для внутреннего сценария вендор и потребитель могут быть одной организацией. Для
            внешнего потребителя вендор выдаёт доступ к полномочию на формирование API-Key.
          </Paragraph>
        </Card>
      </div>

      {/* ---------- письма ---------- */}
      <Card
        title={
          <>
            <MailOutlined style={{ marginRight: 8 }} />
            Все шаблоны писем
          </>
        }
      >
        <Paragraph type="secondary">
          Каждое письмо открывается с заполненными адресом, темой и текстом. Скопировать
          можно любую часть, весь текст целиком или скачать .eml и открыть в своей почте.
          Отправку мы не делаем - это ваша почта и ваша подпись.
        </Paragraph>
        <Row gutter={[16, 16]}>
          {Object.values(LETTERS).map((letter) => (
            <Col xs={24} md={12} xl={8} key={letter.id}>
              <div style={mutedBlockStyle}>
                <Title level={5} style={{ marginTop: 0, marginBottom: 6 }}>
                  {letter.name}
                </Title>
                <Paragraph type="secondary" style={{ marginBottom: 12, fontSize: 13 }}>
                  Кому: <Text style={{ userSelect: 'text' }}>{letter.to}</Text>
                  {letter.cc && (
                    <>
                      <br />
                      Копия: <Text style={{ userSelect: 'text' }}>{letter.cc}</Text>
                    </>
                  )}
                </Paragraph>
                <Space wrap size={6}>
                  <Button
                    size="small"
                    type="primary"
                    ghost
                    icon={<MailOutlined />}
                    onClick={() => setActiveLetter(letter.id)}
                  >
                    Открыть
                  </Button>
                  <CopyButton text={letterToText(letter)} label="Письмо" />
                  <Button
                    size="small"
                    icon={<DownloadOutlined />}
                    onClick={() => downloadText(`${letter.id}.eml`, letterToEml(letter), 'message/rfc822')}
                  >
                    .eml
                  </Button>
                </Space>
              </div>
            </Col>
          ))}
        </Row>
      </Card>

      {/* ---------- ссылки ---------- */}
      <Card
        title={
          <>
            <LinkOutlined style={{ marginRight: 8 }} />
            Кабинеты и документация
          </>
        }
        extra={
          <CopyButton
            text={referenceLinks.map((item) => `${item.label}: ${item.url}`).join('\n')}
            label="Скопировать все ссылки"
          />
        }
      >
        <Row gutter={[16, 16]}>
          {referenceLinks.map((item) => (
            <Col xs={24} lg={12} key={item.url}>
              <div style={{ ...mutedBlockStyle, padding: 12 }}>
                <Space direction="vertical" size={6} style={{ width: '100%' }}>
                  <Space size={8}>
                    <Tag color={item.env === 'prod' ? 'red' : item.env === 'test' ? 'blue' : 'default'}>
                      {item.env === 'both' ? 'общее' : item.env}
                    </Tag>
                    <Text strong>{item.label}</Text>
                  </Space>
                  <ActionLink url={item.url} label="Открыть" />
                </Space>
              </div>
            </Col>
          ))}
        </Row>
        {environments && (
          <details style={{ marginTop: 16 }}>
            <summary style={{ cursor: 'pointer', color: '#1677ff' }}>
              Справочник контуров с backend, GET /environments
            </summary>
            <CopyableCode>{JSON.stringify(environments, null, 2)}</CopyableCode>
          </details>
        )}
      </Card>

      {/* ---------- что осталось на человека ---------- */}
      <Card
        title={
          <>
            <CheckCircleOutlined style={{ marginRight: 8 }} />
            Что осталось на человека
          </>
        }
      >
        <Paragraph type="secondary">
          Всё, что поддавалось автоматизации, автоматизировано и лежит в «Состоянии стенда».
          Здесь - только то, чего наш код физически не видит.
        </Paragraph>
        <Row gutter={[16, 16]}>
          <Col xs={24} lg={12}>
            <div style={mutedBlockStyle}>
              <Title level={5} style={{ marginTop: 0 }}>
                Согласие пользователя
              </Title>
              <Paragraph style={{ marginBottom: 12 }}>
                Часть услуг требует, чтобы гражданин выдал согласие вашей ИС. Со стороны
                backend это не видно - проверяется только в личном кабинете.
              </Paragraph>
              <ActionLink
                url={
                  environments?.[detectedEnv]?.agreements ||
                  'https://lk.gosuslugi.ru/settings/third-party/agreements/acting'
                }
                label="Открыть раздел согласий"
              />
            </div>
          </Col>
          <Col xs={24} lg={12}>
            <div style={mutedBlockStyle}>
              <Title level={5} style={{ marginTop: 0 }}>
                Логи КриптоПро при старте
              </Title>
              <Paragraph style={{ marginBottom: 12 }}>
                Health-check ловит не всё: часть ошибок CSP видна только в выводе
                контейнера. Скопируйте команду и посмотрите глазами.
              </Paragraph>
              <CopyableCode>{'docker compose logs -f api | grep -iE "cprocsp|pycades|error"'}</CopyableCode>
            </div>
          </Col>
        </Row>
      </Card>
    </div>
  );
}
