import React, { useEffect, useMemo, useState } from 'react';
import { Alert, Button, Col, Input, Row, Select, Space, Tag, Typography } from 'antd';
import { CodeOutlined, SendOutlined } from '@ant-design/icons';

const { Text } = Typography;

export const GOSKEY_ROUTES = Object.freeze({
  capabilities: '/goskey/capabilities',
  preview: '/goskey/preview',
  submit: '/goskey/submit',
});

const GOSKEY_CODES = new Set([
  '10000000374',
  '60025907',
  '60079416',
  '60080470',
]);

const OPERATION_IDS = Object.freeze({
  'sign-individual': 'unep',
  'sign-legal-entity': 'legal-entity',
  decipher: 'decipher',
  'sign-treasury': 'treasury',
});

const OPERATION_LABELS = Object.freeze({
  'sign-individual': 'Подписание физическим лицом',
  'sign-legal-entity': 'УКЭП юридического лица или ИП',
  decipher: 'Расшифрование документов',
  'sign-treasury': 'УКЭП с сертификатом Федерального казначейства',
});

const SNILS_RE = /^\d{3}-\d{3}-\d{3} \d{2}$/;
const OKATO_RE = /^\d{2,11}$/;
const OGRN_RE = /^(?:\d{11}|\d{13}|\d{15})$/;
const RAFP_RE = /^\d{11}$/;
const INN_USER_RE = /^\d{12}$/;

const valueOf = (...values) =>
  values.find((value) => value !== undefined && value !== null && value !== '');

const compact = (value) => (typeof value === 'string' ? value.trim() : value);

const validOid = (value) =>
  typeof value === 'string' &&
  value.length >= 1 &&
  value.length <= 20 &&
  Array.from(value).every((character) => {
    const codePoint = character.codePointAt(0);
    return codePoint >= 32 && codePoint !== 127;
  });

const moscowParts = (date) => {
  const formatter = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Europe/Moscow',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hourCycle: 'h23',
  });
  return Object.fromEntries(
    formatter
      .formatToParts(date)
      .filter(({ type }) => type !== 'literal')
      .map(({ type, value }) => [type, value])
  );
};

/** Return an ISO-8601 instant expressed with Moscow's fixed UTC+03:00 offset. */
export const toMoscowIso = (date) => {
  const parts = moscowParts(date);
  return `${parts.year}-${parts.month}-${parts.day}T${parts.hour}:${parts.minute}:${parts.second}+03:00`;
};

export const defaultGoskeyExpiration = (now = new Date()) =>
  toMoscowIso(new Date(now.getTime() + 60 * 60 * 1000));

export const isGoskeyServiceProfile = (service = {}) => {
  const documents = service.documents || service.submission?.documents || [];
  return (
    GOSKEY_CODES.has(String(service.serviceCode || '')) &&
    documents.some((document) => document.generator === 'goskey')
  );
};

const profileCapabilities = (service) =>
  Array.isArray(service?.capabilities) ? service.capabilities : [];

const capabilityId = (capability) =>
  valueOf(
    capability.id,
    capability.variant,
    OPERATION_IDS[capability.operation],
    capability.operation,
    ''
  );

const capabilityReason = (capability, profile) => {
  const contradictions = valueOf(
    capability.contradictions,
    capability.contradiction,
    []
  );
  return valueOf(
    profile?.reason,
    capability.reason,
    Array.isArray(contradictions) ? contradictions.join(' ') : contradictions,
    ''
  );
};

/** Merge the service profile's localized metadata with the live SDK registry. */
export const getGoskeyCapabilities = (service = {}, registry = []) => {
  const serviceCode = String(service.serviceCode || '');
  const profiles = profileCapabilities(service);
  const live = (Array.isArray(registry) ? registry : []).filter(
    (item) => String(valueOf(item.serviceCode, item.service_code, '')) === serviceCode
  );
  const source = live.length > 0 ? live : profiles;

  return source.map((capability) => {
    const id = capabilityId(capability);
    const profile = profiles.find((item) => capabilityId(item) === id);
    const operation = valueOf(capability.operation, profile?.operation, '');
    const state = valueOf(capability.state, profile?.state, 'reference');
    return {
      ...profile,
      ...capability,
      id,
      state,
      label: valueOf(
        profile?.label,
        capability.label,
        id === 'unep' ? 'УНЭП физического лица' : undefined,
        id === 'ukep' ? 'УКЭП физического лица' : undefined,
        OPERATION_LABELS[operation],
        id
      ),
      reason: capabilityReason(capability, profile),
      maxDocuments: Number(
        valueOf(capability.maxDocuments, capability.max_documents, profile?.maxDocuments, 0)
      ),
      allowedExtensions: valueOf(
        capability.allowedExtensions,
        capability.allowed_extensions,
        profile?.allowedExtensions,
        []
      ),
    };
  });
};

export const getGoskeyCapabilityOptions = (service, registry) =>
  getGoskeyCapabilities(service, registry).map((capability) => ({
    value: capability.id,
    label:
      capability.state === 'verified'
        ? capability.label
        : `${capability.label} - справочно: ${capability.reason || 'контракт не проверен'}`,
    disabled: capability.state !== 'verified',
    capability,
  }));

export const createGoskeyFormValue = (
  service = {},
  now = new Date(),
  registry = []
) => {
  const serviceCode = String(service.serviceCode || '');
  const firstVerified = getGoskeyCapabilities(service, registry).find(
    (capability) => capability.state === 'verified'
  );
  return {
    serviceCode,
    region: service.region || '',
    variant:
      serviceCode === '10000000374'
        ? valueOf(firstVerified?.id, 'unep')
        : undefined,
    recipientType:
      serviceCode === '60025907' || serviceCode === '60079416'
        ? 'russian-legal'
        : 'individual',
    identifierType: 'snils',
    snils: '',
    oid: '',
    ogrn: '',
    rafp: '',
    innUser: '',
    signExpiration: defaultGoskeyExpiration(now),
    description: '',
    orgName: '',
    orgInn: '',
    backlink: '',
  };
};

const expirationFromInput = (value) => {
  if (!value) return '';
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(value)) {
    return `${value}:00+03:00`;
  }
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$/.test(value)) {
    return `${value}+03:00`;
  }
  return value;
};

/** Convert the form into the exact JSON DTO accepted by the backend. */
export const buildGoskeyPayload = (form, orderId) => {
  const serviceCode = String(form.serviceCode || '');
  const payload = {
    serviceCode,
    region: compact(form.region),
    recipientType: form.recipientType,
    signExpiration: expirationFromInput(form.signExpiration),
    description: compact(form.description),
    orgName: compact(form.orgName),
    orgInn: compact(form.orgInn),
  };

  if (serviceCode === '10000000374') payload.variant = form.variant;
  if (form.recipientType === 'individual') {
    payload[form.identifierType === 'oid' ? 'oid' : 'snils'] = compact(
      form.identifierType === 'oid' ? form.oid : form.snils
    );
  } else if (form.recipientType === 'russian-legal') {
    payload.ogrn = compact(form.ogrn);
    payload[form.identifierType === 'oid' ? 'oid' : 'snils'] = compact(
      form.identifierType === 'oid' ? form.oid : form.snils
    );
  } else if (form.recipientType === 'foreign-legal') {
    payload.rafp = compact(form.rafp);
    payload.innUser = compact(form.innUser);
  }

  if (compact(form.backlink)) payload.backlink = compact(form.backlink);
  const normalizedOrderId = String(orderId ?? '').trim();
  // Keep the decimal representation exact: EPGU identifiers can exceed the
  // IEEE-754 safe-integer range used by JavaScript Number.
  if (normalizedOrderId) payload.orderId = normalizedOrderId;
  return payload;
};

/** Build the endpoint's exact multipart shape without adding req.xml or .sig files. */
export const createGoskeySubmissionFormData = (payload, files, FormDataType = FormData) => {
  const formData = new FormDataType();
  formData.append('request', JSON.stringify(payload));
  (files || []).forEach((file) => formData.append('documents', file, file.name));
  return formData;
};

const selectedCapability = (form, service, registry) => {
  const capabilities = getGoskeyCapabilities(service, registry);
  if (form.serviceCode === '10000000374') {
    return capabilities.find((capability) => capability.id === form.variant);
  }
  return capabilities[0];
};

/** Client-side guard; the backend remains authoritative and validates again. */
export const validateGoskeyForm = ({
  form,
  service,
  registry = [],
  files = [],
  orderId = '',
  now = new Date(),
  requireDocuments = true,
  signingCertificateSelected = false,
}) => {
  const errors = [];
  const capability = selectedCapability(form, service, registry);
  const payload = buildGoskeyPayload(form, orderId);
  if (!service?.available) {
    errors.push(service?.unavailableReason || 'Профиль услуги недоступен для отправки.');
  }
  if (!capability || capability.state !== 'verified') {
    errors.push(capability?.reason || 'Выбранный контракт Госключа не проверен.');
  }
  if (!OKATO_RE.test(payload.region || '')) {
    errors.push('ОКАТО должен содержать от 2 до 11 цифр.');
  }
  if (!payload.description) errors.push('Укажите описание документов.');
  if (!payload.orgName) errors.push('Укажите название организации-отправителя.');
  if (!payload.orgInn) errors.push('Укажите ИНН организации-отправителя.');
  if (payload.description?.length > 250) errors.push('Описание не должно превышать 250 символов.');
  if (payload.orgName?.length > 250) errors.push('Название организации не должно превышать 250 символов.');
  if (payload.orgInn?.length > 250) errors.push('ИНН не должен превышать 250 символов.');
  if (payload.backlink?.length > 250) errors.push('Обратная ссылка не должна превышать 250 символов.');

  if (payload.recipientType === 'individual') {
    if (payload.snils !== undefined && !SNILS_RE.test(payload.snils)) {
      errors.push('СНИЛС должен иметь формат XXX-XXX-XXX XX.');
    }
    if (payload.oid !== undefined && !validOid(payload.oid)) {
      errors.push('OID должен содержать от 1 до 20 символов.');
    }
  } else if (payload.recipientType === 'russian-legal') {
    if (!OGRN_RE.test(payload.ogrn || '')) errors.push('ОГРН/ОГРНИП должен содержать 11, 13 или 15 цифр.');
    if (payload.snils !== undefined && !SNILS_RE.test(payload.snils)) {
      errors.push('СНИЛС должен иметь формат XXX-XXX-XXX XX.');
    }
    if (payload.oid !== undefined && !validOid(payload.oid)) {
      errors.push('OID должен содержать от 1 до 20 символов.');
    }
  } else if (payload.recipientType === 'foreign-legal') {
    if (!RAFP_RE.test(payload.rafp || '')) errors.push('РАФП должен содержать 11 цифр.');
    if (!INN_USER_RE.test(payload.innUser || '')) errors.push('ИНН пользователя должен содержать 12 цифр.');
  }

  const expiration = Date.parse(payload.signExpiration);
  const remaining = expiration - now.getTime();
  if (!Number.isFinite(expiration) || !payload.signExpiration.endsWith('+03:00')) {
    errors.push('Срок подписи должен быть задан по московскому времени UTC+03:00.');
  } else if (remaining <= 0 || remaining > 24 * 60 * 60 * 1000) {
    errors.push('Срок подписи должен быть в пределах следующих 24 часов.');
  }
  if (
    payload.orderId !== undefined &&
    !/^[1-9]\d*$/.test(String(payload.orderId))
  ) {
    errors.push('Order ID должен быть положительным целым числом.');
  }

  if (requireDocuments) {
    if (!signingCertificateSelected) {
      errors.push('Выберите сертификат подписи перед отправкой в Госключ.');
    }
    if (!Array.isArray(files) || files.length === 0) {
      errors.push('Добавьте хотя бы один документ для подписания.');
    }
    const names = new Set();
    (files || []).forEach((file) => {
      const name = String(file.name || '');
      const folded = name.toLocaleLowerCase('ru-RU');
      if (!name || names.has(folded)) errors.push('Имена документов должны быть непустыми и уникальными.');
      names.add(folded);
      if (folded.endsWith('.sig')) errors.push('Не добавляйте .sig: backend создаёт отсоединённые подписи сам.');
      if (!file.size) errors.push(`Документ ${name || '(без имени)'} пуст.`);
      const allowed = Array.isArray(capability?.allowedExtensions)
        ? capability.allowedExtensions.map((extension) => extension.toLowerCase())
        : [];
      const extension = name.includes('.') ? `.${name.split('.').pop().toLowerCase()}` : '';
      if (allowed.length > 0 && !allowed.includes(extension)) {
        errors.push(`Расширение ${extension || '(нет)'} не разрешено выбранным контрактом.`);
      }
    });
    if (capability?.maxDocuments > 0 && files.length > capability.maxDocuments) {
      errors.push(`Допустимо не более ${capability.maxDocuments} документов.`);
    }
  }

  return { valid: errors.length === 0, errors, payload, capability };
};

const Field = ({ label, children }) => (
  <div>
    <Text strong style={{ display: 'block', marginBottom: 6 }}>
      {label}
    </Text>
    {children}
  </div>
);

/** Service-specific input form; req.xml and CAdES signatures stay server-owned. */
export default function GoskeyForm({
  service,
  capabilityRegistry = [],
  files = [],
  orderId = '',
  previewing = false,
  submitting = false,
  signingCertificateSelected = false,
  onPreview,
  onSubmit,
}) {
  const [form, setForm] = useState(() =>
    createGoskeyFormValue(service, new Date(), capabilityRegistry)
  );
  const capabilityOptions = useMemo(
    () => getGoskeyCapabilityOptions(service, capabilityRegistry),
    [service, capabilityRegistry]
  );

  useEffect(() => {
    setForm(createGoskeyFormValue(service, new Date(), capabilityRegistry));
  }, [service.serviceCode]);

  useEffect(() => {
    if (form.serviceCode !== '10000000374') return;
    const current = capabilityOptions.find((option) => option.value === form.variant);
    if (current && !current.disabled) return;
    const verified = capabilityOptions.find((option) => !option.disabled);
    if (verified) setForm((previous) => ({ ...previous, variant: verified.value }));
  }, [capabilityOptions, form.serviceCode, form.variant]);

  const update = (name, value) => setForm((previous) => ({ ...previous, [name]: value }));
  const previewValidation = validateGoskeyForm({
    form,
    service,
    registry: capabilityRegistry,
    files,
    orderId,
    requireDocuments: false,
  });
  const submitValidation = validateGoskeyForm({
    form,
    service,
    registry: capabilityRegistry,
    files,
    orderId,
    requireDocuments: true,
    signingCertificateSelected,
  });
  const selected = previewValidation.capability;
  const disabledCapabilities = capabilityOptions.filter((option) => option.disabled);
  const datetimeValue = String(form.signExpiration || '').slice(0, 16);

  const identifierFields = (
    <>
      <Col xs={24} md={8}>
        <Field label="Идентификатор получателя">
          <Select
            aria-label="Идентификатор получателя"
            value={form.identifierType}
            onChange={(value) => update('identifierType', value)}
            style={{ width: '100%' }}
            options={[
              { value: 'snils', label: 'СНИЛС' },
              { value: 'oid', label: 'OID ЕСИА' },
            ]}
          />
        </Field>
      </Col>
      <Col xs={24} md={16}>
        <Field label={form.identifierType === 'oid' ? 'OID ЕСИА' : 'СНИЛС'}>
          <Input
            aria-label={form.identifierType === 'oid' ? 'OID ЕСИА' : 'СНИЛС'}
            value={form.identifierType === 'oid' ? form.oid : form.snils}
            placeholder={form.identifierType === 'oid' ? 'Идентификатор ЕСИА' : '000-000-000 00'}
            onChange={(event) =>
              update(form.identifierType === 'oid' ? 'oid' : 'snils', event.target.value)
            }
          />
        </Field>
      </Col>
    </>
  );

  return (
    <div
      data-testid="goskey-form"
      style={{ border: '1px solid #d9e8ff', borderRadius: 8, padding: 16, background: '#f7fbff' }}
    >
      <Space direction="vertical" size="middle" style={{ width: '100%' }}>
        <div>
          <Text strong>Параметры Госключа</Text>
          <br />
          <Text type="secondary">
            `req.xml` и отсоединённые CAdES-подписи создаёт backend. Загружайте только исходные документы.
          </Text>
        </div>

        {service.serviceCode === '10000000374' ? (
          <Field label="Вариант подписи">
            <Select
              aria-label="Вариант подписи Госключа"
              value={form.variant}
              onChange={(value) => update('variant', value)}
              options={capabilityOptions}
              style={{ width: '100%' }}
            />
          </Field>
        ) : (
          selected && (
            <Space wrap>
              <Tag color={selected.state === 'verified' ? 'success' : 'warning'}>
                {selected.label}
              </Tag>
              <Text type="secondary">{selected.reason}</Text>
            </Space>
          )
        )}

        {disabledCapabilities.length > 0 && (
          <Alert
            type="warning"
            showIcon
            message="Справочные варианты заблокированы"
            description={disabledCapabilities
              .map((option) => `${option.capability.label}: ${option.capability.reason}`)
              .join(' ')}
          />
        )}

        <Row gutter={[12, 12]}>
          <Col xs={24} md={12}>
            <Field label="Регион (ОКАТО)">
              <Input
                aria-label="Регион ОКАТО"
                value={form.region}
                inputMode="numeric"
                maxLength={11}
                onChange={(event) =>
                  update('region', event.target.value.replace(/\D/g, ''))
                }
                placeholder="Например, 45000000000"
              />
            </Field>
          </Col>
          <Col xs={24} md={12}>
            <Field label="Подписать до (Москва, максимум 24 часа)">
              <Input
                aria-label="Срок подписи"
                type="datetime-local"
                value={datetimeValue}
                onChange={(event) => update('signExpiration', expirationFromInput(event.target.value))}
              />
            </Field>
          </Col>
        </Row>

        {(form.serviceCode === '60025907' || form.serviceCode === '60079416') && (
          <Field label="Тип получателя">
            <Select
              aria-label="Тип получателя Госключа"
              value={form.recipientType}
              onChange={(value) => update('recipientType', value)}
              style={{ width: '100%' }}
              options={[
                { value: 'russian-legal', label: 'Российское юридическое лицо / ИП' },
                { value: 'foreign-legal', label: 'Иностранное юридическое лицо' },
              ]}
            />
          </Field>
        )}

        <Row gutter={[12, 12]}>
          {form.recipientType === 'russian-legal' && (
            <Col xs={24}>
              <Field label="ОГРН / ОГРНИП">
                <Input
                  aria-label="ОГРН или ОГРНИП"
                  value={form.ogrn}
                  onChange={(event) => update('ogrn', event.target.value)}
                  placeholder="11, 13 или 15 цифр"
                />
              </Field>
            </Col>
          )}
          {(form.recipientType === 'individual' || form.recipientType === 'russian-legal') &&
            identifierFields}
          {form.recipientType === 'foreign-legal' && (
            <>
              <Col xs={24} md={12}>
                <Field label="РАФП">
                  <Input
                    aria-label="РАФП"
                    value={form.rafp}
                    onChange={(event) => update('rafp', event.target.value)}
                    placeholder="11 цифр"
                  />
                </Field>
              </Col>
              <Col xs={24} md={12}>
                <Field label="ИНН пользователя">
                  <Input
                    aria-label="ИНН пользователя"
                    value={form.innUser}
                    onChange={(event) => update('innUser', event.target.value)}
                    placeholder="12 цифр"
                  />
                </Field>
              </Col>
            </>
          )}
        </Row>

        <Row gutter={[12, 12]}>
          <Col xs={24} md={12}>
            <Field label="Организация-отправитель">
              <Input
                aria-label="Организация-отправитель"
                value={form.orgName}
                maxLength={250}
                onChange={(event) => update('orgName', event.target.value)}
              />
            </Field>
          </Col>
          <Col xs={24} md={12}>
            <Field label="ИНН организации-отправителя">
              <Input
                aria-label="ИНН организации-отправителя"
                value={form.orgInn}
                maxLength={250}
                onChange={(event) => update('orgInn', event.target.value)}
              />
            </Field>
          </Col>
        </Row>

        <Field label="Описание документов">
          <Input.TextArea
            aria-label="Описание документов Госключа"
            value={form.description}
            maxLength={250}
            showCount
            onChange={(event) => update('description', event.target.value)}
          />
        </Field>
        <Field label="Обратная ссылка (необязательно)">
          <Input
            aria-label="Обратная ссылка Госключа"
            value={form.backlink}
            maxLength={250}
            onChange={(event) => update('backlink', event.target.value)}
          />
        </Field>

        {orderId && (
          <Alert
            type="info"
            showIcon
            message={`Order ID ${orderId} передан: backend принудительно использует chunked-отправку.`}
          />
        )}
        {!submitValidation.valid && (
          <Text type="secondary">{submitValidation.errors[0]}</Text>
        )}
        <Space wrap>
          <Button
            icon={<CodeOutlined />}
            loading={previewing}
            disabled={!previewValidation.valid || submitting}
            onClick={() => onPreview(previewValidation.payload)}
          >
            Предпросмотр req.xml
          </Button>
          <Button
            type="primary"
            icon={<SendOutlined />}
            loading={submitting}
            disabled={!submitValidation.valid || previewing}
            onClick={() => onSubmit(submitValidation.payload)}
          >
            Подписать и отправить
          </Button>
        </Space>
      </Space>
    </div>
  );
}
