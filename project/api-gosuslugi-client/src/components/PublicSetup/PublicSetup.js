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
import manualPath from './manual_path.v1.json';

const { Paragraph, Text, Title } = Typography;
const { TextArea } = Input;

// Все тексты приходят из ручного маршрута: своих копий здесь нет.
const KIND_LABELS = new Map(manualPath.link_kinds.map((kind) => [kind.id, kind.label]));

const EMPTY_FACTS = manualPath.fields.reduce(
  (result, field) => ({ ...result, [field.id]: '' }),
  {}
);

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
    body: manualPath.letter_template.body,
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
          description={`Все значения остаются в редактируемых полях этой страницы. ${manualPath.warnings[1]}`}
        />
        <Paragraph type="secondary" style={{ marginTop: 12, marginBottom: 0 }}>
          {manualPath.provenance.note}
        </Paragraph>
      </Card>

      <Card title="Порядок действий">
        <ol style={{ margin: 0, paddingLeft: 20 }}>
          {manualPath.steps.map((step) => (
            <li key={step.id} data-testid={`manual-step-${step.id}`} style={{ marginBottom: 12 }}>
              <Text strong>{step.title}</Text>
              <Paragraph style={{ margin: 0 }}>Действие: {step.action}</Paragraph>
              <Paragraph style={{ margin: 0 }}>Что собрать: {step.collect}</Paragraph>
              <Paragraph style={{ margin: 0 }}>Что должно получиться: {step.result}</Paragraph>
              {step.link_kinds.map((kind) => (
                <Paragraph style={{ margin: 0 }} key={kind}>
                  {KIND_LABELS.get(kind)}:{' '}
                  {manualPath.links.filter((link) => link.kind === kind).map((link) => (
                    <a key={link.id} href={link.url} target="_blank" rel="noreferrer" aria-label={link.label} style={{ marginRight: 8 }}>
                      {link.contour}
                    </a>
                  ))}
                </Paragraph>
              ))}
            </li>
          ))}
        </ol>
      </Card>

      <Card title="Официальные кабинеты и консоли">
        <Row gutter={[12, 12]}>
          {manualPath.links.map((item) => (
            <Col xs={24} md={12} xl={8} key={item.id}>
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

      <Card title="Фактические данные - заполните вручную">
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 16 }}
          message={manualPath.warnings[0]}
        />
        <Row gutter={[16, 16]}>
          {manualPath.fields.map((field) => (
            <Col xs={24} xl={field.rows === 1 ? 8 : 12} key={field.id}>
              <Space direction="vertical" size={4} style={{ width: '100%' }}>
                <Space>
                  <Text strong>{field.label}</Text>
                  <Button
                    size="small"
                    aria-label={`Скопировать поле ${field.label}`}
                    icon={<CopyOutlined />}
                    onClick={() => copy(facts[field.id], `Поле «${field.label}»`)}
                  />
                </Space>
                {field.rows === 1 ? (
                  <Input
                    aria-label={field.label}
                    placeholder={field.hint}
                    value={facts[field.id]}
                    onChange={(event) => setFacts({ ...facts, [field.id]: event.target.value })}
                  />
                ) : (
                  <TextArea
                    aria-label={field.label}
                    rows={field.rows}
                    placeholder={field.hint}
                    value={facts[field.id]}
                    onChange={(event) => setFacts({ ...facts, [field.id]: event.target.value })}
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
