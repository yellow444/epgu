import React, { useMemo, useState } from 'react';
import {
  Alert,
  Button,
  Card,
  Col,
  Input,
  Row,
  Space,
  Typography,
} from 'antd';
import {
  CopyOutlined,
  DownloadOutlined,
  ExportOutlined,
  MailOutlined,
} from '@ant-design/icons';

const { Paragraph, Text, Title } = Typography;
const { TextArea } = Input;

const LINKS = [
  {
    key: 'test-systems',
    label: 'TEST: «Мои системы»',
    url: 'https://svcdev-partners.test.gosuslugi.ru/systems',
  },
  {
    key: 'test-powers',
    label: 'TEST: «Полномочия»',
    url: 'https://svcdev-partners.test.gosuslugi.ru/powers',
  },
  {
    key: 'prod-systems',
    label: 'PROD: «Мои системы»',
    url: 'https://partners.gosuslugi.ru/systems',
  },
  {
    key: 'prod-powers',
    label: 'PROD: «Полномочия»',
    url: 'https://partners.gosuslugi.ru/powers',
  },
  {
    key: 'test-tech',
    label: 'TEST: техническая консоль ЕСИА',
    url: 'https://esia-portal1.test.gosuslugi.ru/console/tech/',
  },
  {
    key: 'prod-tech',
    label: 'PROD: техническая консоль ЕСИА',
    url: 'https://esia.gosuslugi.ru/console/tech',
  },
];

const FACT_FIELDS = [
  {
    key: 'organizationOid',
    label: 'OID организации',
    placeholder: 'Введите вручную, если он отображается в ЛК',
    rows: 1,
  },
  {
    key: 'systemOid',
    label: 'OID внешней ИС (ext-app)',
    placeholder: 'Введите вручную из адреса или карточки ИС',
    rows: 1,
  },
  {
    key: 'mnemonic',
    label: 'Мнемоника ИС',
    placeholder: 'Например, TESTEP',
    rows: 1,
  },
  {
    key: 'systemCard',
    label: 'Что отображается в карточке ИС',
    placeholder: 'Откройте конкретную ИС и перенесите сюда нужные видимые строки вручную',
    rows: 5,
  },
  {
    key: 'powers',
    label: 'Что отображается на странице «Полномочия»',
    placeholder: 'Например: «У вас пока нет полномочий»',
    rows: 4,
  },
  {
    key: 'request',
    label: 'Метод и URL запроса',
    placeholder: 'Только метод и URL без Cookie, Authorization, API-Key и токенов',
    rows: 3,
  },
  {
    key: 'response',
    label: 'HTTP-код и безопасный текст ответа',
    placeholder: 'Например: 404 Not Found. Не вставляйте секреты и служебные заголовки',
    rows: 4,
  },
];

const EMPTY_FACTS = FACT_FIELDS.reduce(
  (result, field) => ({ ...result, [field.key]: '' }),
  {}
);

const DEFAULT_BODY = `Здравствуйте!

Организация: <заполните вручную>
OID организации: <заполните вручную>
Мнемоника ИС: <заполните вручную>
OID внешней ИС (ext-app): <заполните вручную>

Что отображается в карточке ИС:
<заполните вручную>

Что отображается на странице «Полномочия»:
<заполните вручную>

Метод и URL запроса без Cookie и токенов:
<заполните вручную>

HTTP-код и безопасный текст ответа:
<заполните вручную>

Просим проверить указанные сведения и сообщить официальный порядок дальнейших действий.

С уважением,
<заполните вручную>`;

function copyText(value) {
  return navigator.clipboard.writeText(String(value || ''));
}

function downloadText(filename, content, type) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

function encodeSubject(value) {
  const text = String(value || '');
  if (/^[\x20-\x7e]*$/.test(text)) return text;
  const bytes = new TextEncoder().encode(text);
  let binary = '';
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return `=?utf-8?B?${btoa(binary)}?=`;
}

function toEml(letter) {
  const headers = [
    `Date: ${new Date().toUTCString()}`,
    `To: ${letter.to}`,
    letter.cc ? `Cc: ${letter.cc}` : null,
    `Subject: ${encodeSubject(letter.subject)}`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: 8bit',
  ].filter(Boolean);
  return `${headers.join('\r\n')}\r\n\r\n${letter.body.replace(/\n/g, '\r\n')}\r\n`;
}

function letterText(letter) {
  return [
    `Кому: ${letter.to}`,
    letter.cc ? `Копия: ${letter.cc}` : null,
    `Тема: ${letter.subject}`,
    '',
    letter.body,
  ].filter((value) => value !== null).join('\n');
}

export default function PublicSetup() {
  const [facts, setFacts] = useState(EMPTY_FACTS);
  const [letter, setLetter] = useState({
    to: '',
    cc: '',
    subject: '',
    body: DEFAULT_BODY,
  });
  const [notice, setNotice] = useState('');

  const mailto = useMemo(() => {
    const query = [
      `subject=${encodeURIComponent(letter.subject)}`,
      `body=${encodeURIComponent(letter.body)}`,
    ];
    if (letter.cc) query.push(`cc=${encodeURIComponent(letter.cc)}`);
    return `mailto:${letter.to}?${query.join('&')}`;
  }, [letter]);

  const copy = async (value, label) => {
    try {
      await copyText(value);
      setNotice(`${label} скопировано.`);
    } catch (error) {
      setNotice('Браузер не разрешил доступ к буферу. Выделите текст и скопируйте вручную.');
    }
  };

  return (
    <Space direction="vertical" size={20} style={{ width: '100%' }}>
      <Card>
        <Title level={3} style={{ marginTop: 0 }}>Ручная настройка подключения</Title>
        <Alert
          type="info"
          showIcon
          message="Публичная версия ничего не читает из соседних вкладок и ничего не отправляет автоматически"
          description="Все значения остаются в редактируемых полях этой страницы. Проверяйте актуальные адреса и требования по официальным каналам Оператора."
        />
      </Card>

      <Card title="Официальные кабинеты и консоли">
        <Row gutter={[12, 12]}>
          {LINKS.map((item) => (
            <Col xs={24} md={12} xl={8} key={item.key}>
              <Space direction="vertical" size={6} style={{ width: '100%' }}>
                <Button
                  block
                  href={item.url}
                  target="_blank"
                  rel="noreferrer"
                  icon={<ExportOutlined />}
                >
                  {item.label}
                </Button>
                <Space size={4}>
                  <Text code style={{ fontSize: 11, wordBreak: 'break-all' }}>{item.url}</Text>
                  <Button
                    size="small"
                    aria-label={`Скопировать ${item.label}`}
                    icon={<CopyOutlined />}
                    onClick={() => copy(item.url, 'Ссылка')}
                  />
                </Space>
              </Space>
            </Col>
          ))}
        </Row>
      </Card>

      <Card title="Фактические данные — заполните вручную">
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 16 }}
          message="Не вставляйте Cookie, Authorization, API-Key, KeyPin, пароли и токены"
        />
        <Row gutter={[16, 16]}>
          {FACT_FIELDS.map((field) => (
            <Col xs={24} xl={field.rows === 1 ? 8 : 12} key={field.key}>
              <Space direction="vertical" size={4} style={{ width: '100%' }}>
                <Space>
                  <Text strong>{field.label}</Text>
                  <Button
                    size="small"
                    aria-label={`Скопировать поле ${field.label}`}
                    icon={<CopyOutlined />}
                    onClick={() => copy(facts[field.key], `Поле «${field.label}»`)}
                  />
                </Space>
                {field.rows === 1 ? (
                  <Input
                    aria-label={field.label}
                    placeholder={field.placeholder}
                    value={facts[field.key]}
                    onChange={(event) => setFacts({ ...facts, [field.key]: event.target.value })}
                  />
                ) : (
                  <TextArea
                    aria-label={field.label}
                    rows={field.rows}
                    placeholder={field.placeholder}
                    value={facts[field.key]}
                    onChange={(event) => setFacts({ ...facts, [field.key]: event.target.value })}
                  />
                )}
              </Space>
            </Col>
          ))}
        </Row>
      </Card>

      <Card title="Ручное письмо">
        <Paragraph type="secondary">
          Здесь нет банка неофициальных шаблонов и автоподстановки. Заполните
          адрес, тему и текст сами, проверьте письмо и откройте его в вашем
          почтовом клиенте либо скачайте `.eml`.
        </Paragraph>
        <Space direction="vertical" size={10} style={{ width: '100%' }}>
          <Input
            addonBefore="Кому"
            aria-label="Кому"
            value={letter.to}
            onChange={(event) => setLetter({ ...letter, to: event.target.value })}
          />
          <Input
            addonBefore="Копия"
            aria-label="Копия"
            value={letter.cc}
            onChange={(event) => setLetter({ ...letter, cc: event.target.value })}
          />
          <Input
            addonBefore="Тема"
            aria-label="Тема"
            value={letter.subject}
            onChange={(event) => setLetter({ ...letter, subject: event.target.value })}
          />
          <TextArea
            aria-label="Текст письма"
            rows={18}
            value={letter.body}
            onChange={(event) => setLetter({ ...letter, body: event.target.value })}
          />
          <Space wrap>
            <Button icon={<CopyOutlined />} onClick={() => copy(letterText(letter), 'Письмо')}>
              Копировать письмо
            </Button>
            <Button
              icon={<DownloadOutlined />}
              onClick={() => downloadText('support-request.eml', toEml(letter), 'message/rfc822')}
            >
              Скачать .eml
            </Button>
            <Button
              type="primary"
              icon={<MailOutlined />}
              href={mailto}
              disabled={!letter.to.trim()}
            >
              Открыть в почтовом клиенте
            </Button>
          </Space>
          {notice ? <Alert type="success" showIcon message={notice} closable onClose={() => setNotice('')} /> : null}
        </Space>
      </Card>
    </Space>
  );
}
