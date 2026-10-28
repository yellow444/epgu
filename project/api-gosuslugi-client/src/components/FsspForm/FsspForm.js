import React, { useEffect, useState } from 'react';
import { Alert, Button, Checkbox, Col, Input, Row, Select, Space, Typography } from 'antd';
import { CodeOutlined, SendOutlined } from '@ant-design/icons';

const { Text } = Typography;

export const FSSP_ROUTES = Object.freeze({
  contracts: '/fssp/contracts',
  preview: '/fssp/preview',
  submit: '/fssp/submit',
});

const CASE_NUMBER_SERVICE = '10000000352';
const INCLUDE_CLOSED_SERVICE = '60010153';

// Коды вида доверенности из XSD ФССП. 07 (руководитель ЮЛ) ставится сам при
// подаче от организации, 09 (доверенность в ЕСИА) требует authority.xml с
// подписью и в форме не поддерживается.
export const POWER_DOCUMENTS = Object.freeze([
  { value: '01', label: 'Общая доверенность' },
  { value: '02', label: 'Специальная доверенность' },
  { value: '03', label: 'Разовая доверенность' },
  { value: '04', label: 'Свидетельство о рождении' },
  { value: '06', label: 'Судебное решение об усыновлении, опеке, попечительстве' },
  { value: '08', label: 'Судебное решение о признании должника банкротом' },
]);

const OKATO_RE = /^\d{2,11}$/;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const CASE_NUMBER_RE = /^\d{1,12}\/\d{2}\/(?:\d{2}\/\d{2}|\d{5}-ИП)$/;

const digits = (value) => String(value || '').replace(/\D/g, '');
const compact = (value) => String(value || '').trim().replace(/\s+/g, ' ');

export const isFsspServiceProfile = (service = {}) => {
  const documents = service.documents || service.submission?.documents || [];
  return documents.some((document) => document.generator === 'fssp');
};

const emptyPerson = () => ({ fullName: '', gender: '1', birthDate: '', snils: '' });

export const createFsspFormValue = (service = {}, organizationName = '') => ({
  serviceCode: String(service.serviceCode || ''),
  region: service.region || '',
  side: '1',
  representation: 'organization',
  applicant: emptyPerson(),
  organization: { name: organizationName || '', address: '', inn: '', ogrn: '' },
  representative: {
    document: '01',
    issuedBy: '',
    number: '',
    issuedOn: '',
    principal: emptyPerson(),
  },
  includeClosed: true,
  caseNumber: '',
});

const personPayload = (person) => ({
  fullName: compact(person.fullName),
  gender: person.gender,
  birthDate: person.birthDate,
  snils: compact(person.snils),
});

/** Привести форму к JSON, который принимает /fssp/preview и /fssp/submit. */
export const buildFsspPayload = (form) => {
  const payload = {
    serviceCode: form.serviceCode,
    region: digits(form.region),
    side: form.side,
    representation: form.representation,
    applicant: personPayload(form.applicant),
  };
  if (form.representation === 'organization') {
    payload.organization = {
      name: compact(form.organization.name),
      address: compact(form.organization.address),
      inn: digits(form.organization.inn),
      ogrn: digits(form.organization.ogrn),
    };
  } else if (form.representation === 'person') {
    const representative = form.representative;
    payload.representative = {
      document: representative.document,
      issuedBy: compact(representative.issuedBy),
      number: compact(representative.number),
      issuedOn: representative.issuedOn,
      principal: personPayload(representative.principal),
    };
  }
  if (form.serviceCode === CASE_NUMBER_SERVICE) payload.caseNumber = compact(form.caseNumber);
  if (form.serviceCode === INCLUDE_CLOSED_SERVICE) payload.includeClosed = Boolean(form.includeClosed);
  return payload;
};

const checkPerson = (errors, prefix, person, today) => {
  if (!person.fullName) errors[`${prefix}.fullName`] = 'Укажите ФИО';
  else if (person.fullName.split(' ').length < 2) {
    errors[`${prefix}.fullName`] = 'Фамилия, имя и, если есть, отчество через пробел';
  }
  if (!DATE_RE.test(person.birthDate || '')) errors[`${prefix}.birthDate`] = 'Укажите дату рождения';
  else if (person.birthDate > today) errors[`${prefix}.birthDate`] = 'Дата в будущем';
  if (digits(person.snils).length !== 11) errors[`${prefix}.snils`] = 'СНИЛС: 11 цифр';
};

const isoToday = (now) => {
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Europe/Moscow',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  }).formatToParts(now);
  const value = (type) => parts.find((part) => part.type === type).value;
  return `${value('year')}-${value('month')}-${value('day')}`;
};

/**
 * Проверка формы до запроса. Сервер проверяет всё заново, включая контрольные
 * цифры и значения из примеров спецификации, и возвращает ошибки по полям.
 */
export const validateFsspForm = (form, now = new Date()) => {
  const payload = buildFsspPayload(form);
  const today = isoToday(now);
  const errors = {};
  if (!OKATO_RE.test(payload.region)) errors.region = 'ОКАТО: от 2 до 11 цифр';
  checkPerson(errors, 'applicant', payload.applicant, today);
  if (payload.organization) {
    const organization = payload.organization;
    if (!organization.name) errors['organization.name'] = 'Укажите наименование';
    if (!organization.address) errors['organization.address'] = 'Укажите адрес';
    if (organization.inn.length !== 10) errors['organization.inn'] = 'ИНН организации: 10 цифр';
    if (organization.ogrn.length !== 13) errors['organization.ogrn'] = 'ОГРН: 13 цифр';
  }
  if (payload.representative) {
    const representative = payload.representative;
    if (!representative.issuedBy) errors['representative.issuedBy'] = 'Укажите, кем выдан документ';
    if (!representative.number) errors['representative.number'] = 'Укажите номер документа';
    if (!DATE_RE.test(representative.issuedOn || '')) {
      errors['representative.issuedOn'] = 'Укажите дату документа';
    } else if (representative.issuedOn > today) {
      errors['representative.issuedOn'] = 'Дата в будущем';
    }
    checkPerson(errors, 'principal', representative.principal, today);
  }
  if (payload.caseNumber !== undefined) {
    if (!payload.caseNumber) errors.caseNumber = 'Укажите номер исполнительного производства';
    else if (!CASE_NUMBER_RE.test(payload.caseNumber)) {
      errors.caseNumber = 'В виде 12345/20/69025-ИП или 12345/20/12/34';
    }
  }
  return { valid: Object.keys(errors).length === 0, errors, payload };
};

/**
 * Разобрать ответ 422: ошибки построителя приходят как detail.errors с полями
 * формы, ошибки разбора JSON - как список FastAPI с путём loc.
 */
export const fieldErrorsFromResponse = (error) => {
  const detail = error?.response?.data?.detail;
  const result = {};
  if (Array.isArray(detail?.errors)) {
    detail.errors.forEach(({ field, message }) => {
      if (field && !result[field]) result[field] = message;
    });
  } else if (Array.isArray(detail)) {
    detail.forEach((item) => {
      const path = (item.loc || []).filter((part) => part !== 'body').join('.');
      const field = path.replace(/^representative\.principal\./, 'principal.');
      if (field && !result[field]) result[field] = item.msg || 'Неверное значение';
    });
  }
  return Object.keys(result).length > 0 ? result : null;
};

const Field = ({ label, error, children }) => (
  <div>
    <Text strong style={{ display: 'block', marginBottom: 6 }}>
      {label}
    </Text>
    {children}
    {error && (
      <Text type="danger" style={{ display: 'block', marginTop: 4 }}>
        {error}
      </Text>
    )}
  </div>
);

const PersonFields = ({ prefix, title, person, errors, onChange }) => {
  const error = (name) => errors[`${prefix}.${name}`];
  const status = (name) => (error(name) ? 'error' : undefined);
  return (
    <Space direction="vertical" size={8} style={{ width: '100%' }}>
      <Text strong>{title}</Text>
      <Row gutter={[12, 12]}>
        <Col xs={24}>
          <Field label="ФИО" error={error('fullName')}>
            <Input
              aria-label={`${title}: ФИО`}
              value={person.fullName}
              maxLength={1000}
              status={status('fullName')}
              onChange={(event) => onChange('fullName', event.target.value)}
            />
          </Field>
        </Col>
        <Col xs={8}>
          <Field label="Пол" error={error('gender')}>
            <Select
              aria-label={`${title}: пол`}
              value={person.gender}
              onChange={(value) => onChange('gender', value)}
              style={{ width: '100%' }}
              options={[
                { value: '1', label: 'Мужской' },
                { value: '2', label: 'Женский' },
              ]}
            />
          </Field>
        </Col>
        <Col xs={16}>
          <Field label="Дата рождения" error={error('birthDate')}>
            <Input
              aria-label={`${title}: дата рождения`}
              type="date"
              value={person.birthDate}
              status={status('birthDate')}
              onChange={(event) => onChange('birthDate', event.target.value)}
            />
          </Field>
        </Col>
        <Col xs={24}>
          <Field label="СНИЛС" error={error('snils')}>
            <Input
              aria-label={`${title}: СНИЛС`}
              value={person.snils}
              placeholder="000-000-000 00"
              maxLength={20}
              status={status('snils')}
              onChange={(event) => onChange('snils', event.target.value)}
            />
          </Field>
        </Col>
      </Row>
    </Space>
  );
};

const PERSON_FIELDS = ['fullName', 'gender', 'birthDate', 'snils'];
// Поля, у которых в форме есть своё место для ошибки. Остальные ошибки
// (например, расхождение с XSD) показываются общим списком.
const FORM_FIELDS = new Set([
  'side',
  'representation',
  'region',
  'caseNumber',
  ...PERSON_FIELDS.map((name) => `applicant.${name}`),
  ...PERSON_FIELDS.map((name) => `principal.${name}`),
  ...['name', 'address', 'inn', 'ogrn'].map((name) => `organization.${name}`),
  ...['document', 'issuedBy', 'number', 'issuedOn'].map((name) => `representative.${name}`),
]);

export const generalFsspErrors = (errors = {}) =>
  Object.entries(errors)
    .filter(([field]) => !FORM_FIELDS.has(field))
    .map(([, message]) => message);

const APPLICANT_TITLES = Object.freeze({
  organization: 'Руководитель организации (подаёт заявление)',
  person: 'Представитель (подаёт заявление)',
  self: 'Заявитель',
});

/**
 * Форма заявления ФССП. XML собирает и проверяет сервер; номер заявления
 * резервируется только после успешной проверки.
 */
export default function FsspForm({
  service,
  organizationName = '',
  previewing = false,
  submitting = false,
  onPreview,
  onSubmit,
}) {
  const [form, setForm] = useState(() => createFsspFormValue(service, organizationName));
  const [shownErrors, setShownErrors] = useState({});

  useEffect(() => {
    setForm((previous) => ({ ...previous, serviceCode: String(service.serviceCode || '') }));
    setShownErrors({});
  }, [service.serviceCode]);

  useEffect(() => {
    if (!organizationName) return;
    setForm((previous) =>
      previous.organization.name
        ? previous
        : { ...previous, organization: { ...previous.organization, name: organizationName } }
    );
  }, [organizationName]);

  const clearError = (field) =>
    setShownErrors((previous) => {
      if (!previous[field]) return previous;
      const next = { ...previous };
      delete next[field];
      return next;
    });
  const update = (name, value) => {
    setForm((previous) => ({ ...previous, [name]: value }));
    clearError(name);
  };
  const updateIn = (group, name, value, field = `${group}.${name}`) => {
    setForm((previous) => ({ ...previous, [group]: { ...previous[group], [name]: value } }));
    clearError(field);
  };
  const updatePrincipal = (name, value) => {
    setForm((previous) => ({
      ...previous,
      representative: {
        ...previous.representative,
        principal: { ...previous.representative.principal, [name]: value },
      },
    }));
    clearError(`principal.${name}`);
  };

  const run = async (action) => {
    const validation = validateFsspForm(form);
    setShownErrors(validation.errors);
    if (!validation.valid) return;
    const result = await action(validation.payload);
    setShownErrors(result?.fieldErrors || {});
  };

  const busy = previewing || submitting;
  const unavailable = !service.available;
  const generalErrors = generalFsspErrors(shownErrors);
  const fieldErrorCount = Object.keys(shownErrors).length - generalErrors.length;
  const orgError = (name) => shownErrors[`organization.${name}`];
  const repError = (name) => shownErrors[`representative.${name}`];

  return (
    <div
      data-testid="fssp-form"
      style={{ border: '1px solid #d9e8ff', borderRadius: 8, padding: 16, background: '#f7fbff' }}
    >
      <Space direction="vertical" size="middle" style={{ width: '100%' }}>
        <div>
          <Text strong>Заявление в ФССП</Text>
          <br />
          <Text type="secondary">
            req.xml и piev_epgu.xml собирает сервер по этим полям и проверяет по XSD ФССП. Номер
            заявления резервируется только после проверки.
          </Text>
        </div>
        {unavailable && (
          <Alert type="warning" showIcon message={service.unavailableReason || 'Услуга недоступна.'} />
        )}

        <Row gutter={[12, 12]}>
          <Col xs={12}>
            <Field label="Сторона производства" error={shownErrors.side}>
              <Select
                aria-label="Сторона производства"
                value={form.side}
                onChange={(value) => update('side', value)}
                style={{ width: '100%' }}
                options={[
                  { value: '1', label: 'Взыскатель' },
                  { value: '2', label: 'Должник' },
                ]}
              />
            </Field>
          </Col>
          <Col xs={12}>
            <Field label="Регион (ОКАТО)" error={shownErrors.region}>
              <Input
                aria-label="Регион ОКАТО заявления ФССП"
                value={form.region}
                inputMode="numeric"
                maxLength={11}
                placeholder="Например, 45000000000"
                status={shownErrors.region ? 'error' : undefined}
                onChange={(event) => update('region', event.target.value.replace(/\D/g, ''))}
              />
            </Field>
          </Col>
          <Col xs={24}>
            <Field label="От чьего имени" error={shownErrors.representation}>
              <Select
                aria-label="От чьего имени подаётся заявление"
                value={form.representation}
                onChange={(value) => update('representation', value)}
                style={{ width: '100%' }}
                options={[
                  { value: 'organization', label: 'Организация (руководитель)' },
                  { value: 'person', label: 'Представитель физического лица' },
                  { value: 'self', label: 'Лично' },
                ]}
              />
            </Field>
          </Col>
        </Row>

        {form.representation === 'organization' && (
          <Space direction="vertical" size={8} style={{ width: '100%' }}>
            <Text strong>Организация</Text>
            <Row gutter={[12, 12]}>
              <Col xs={24}>
                <Field label="Наименование" error={orgError('name')}>
                  <Input
                    aria-label="Наименование организации"
                    value={form.organization.name}
                    maxLength={1000}
                    status={orgError('name') ? 'error' : undefined}
                    onChange={(event) => updateIn('organization', 'name', event.target.value)}
                  />
                </Field>
              </Col>
              <Col xs={24}>
                <Field label="Адрес" error={orgError('address')}>
                  <Input
                    aria-label="Адрес организации"
                    value={form.organization.address}
                    maxLength={200}
                    status={orgError('address') ? 'error' : undefined}
                    onChange={(event) => updateIn('organization', 'address', event.target.value)}
                  />
                </Field>
              </Col>
              <Col xs={12}>
                <Field label="ИНН" error={orgError('inn')}>
                  <Input
                    aria-label="ИНН организации"
                    value={form.organization.inn}
                    inputMode="numeric"
                    maxLength={12}
                    status={orgError('inn') ? 'error' : undefined}
                    onChange={(event) => updateIn('organization', 'inn', event.target.value)}
                  />
                </Field>
              </Col>
              <Col xs={12}>
                <Field label="ОГРН" error={orgError('ogrn')}>
                  <Input
                    aria-label="ОГРН организации"
                    value={form.organization.ogrn}
                    inputMode="numeric"
                    maxLength={15}
                    status={orgError('ogrn') ? 'error' : undefined}
                    onChange={(event) => updateIn('organization', 'ogrn', event.target.value)}
                  />
                </Field>
              </Col>
            </Row>
          </Space>
        )}

        <PersonFields
          prefix="applicant"
          title={APPLICANT_TITLES[form.representation]}
          person={form.applicant}
          errors={shownErrors}
          onChange={(name, value) => updateIn('applicant', name, value)}
        />

        {form.representation === 'person' && (
          <>
            <Space direction="vertical" size={8} style={{ width: '100%' }}>
              <Text strong>Документ о полномочиях</Text>
              <Row gutter={[12, 12]}>
                <Col xs={24}>
                  <Field label="Вид документа" error={repError('document')}>
                    <Select
                      aria-label="Вид документа о полномочиях"
                      value={form.representative.document}
                      onChange={(value) => updateIn('representative', 'document', value)}
                      style={{ width: '100%' }}
                      options={POWER_DOCUMENTS}
                    />
                  </Field>
                </Col>
                <Col xs={24}>
                  <Field label="Кем выдан" error={repError('issuedBy')}>
                    <Input
                      aria-label="Кем выдан документ о полномочиях"
                      value={form.representative.issuedBy}
                      maxLength={1000}
                      status={repError('issuedBy') ? 'error' : undefined}
                      onChange={(event) =>
                        updateIn('representative', 'issuedBy', event.target.value)
                      }
                    />
                  </Field>
                </Col>
                <Col xs={12}>
                  <Field label="Номер" error={repError('number')}>
                    <Input
                      aria-label="Номер документа о полномочиях"
                      value={form.representative.number}
                      maxLength={25}
                      status={repError('number') ? 'error' : undefined}
                      onChange={(event) => updateIn('representative', 'number', event.target.value)}
                    />
                  </Field>
                </Col>
                <Col xs={12}>
                  <Field label="Дата" error={repError('issuedOn')}>
                    <Input
                      aria-label="Дата документа о полномочиях"
                      type="date"
                      value={form.representative.issuedOn}
                      status={repError('issuedOn') ? 'error' : undefined}
                      onChange={(event) =>
                        updateIn('representative', 'issuedOn', event.target.value)
                      }
                    />
                  </Field>
                </Col>
              </Row>
            </Space>
            <PersonFields
              prefix="principal"
              title="Доверитель"
              person={form.representative.principal}
              errors={shownErrors}
              onChange={updatePrincipal}
            />
          </>
        )}

        {form.serviceCode === CASE_NUMBER_SERVICE && (
          <Field label="Номер исполнительного производства" error={shownErrors.caseNumber}>
            <Input
              aria-label="Номер исполнительного производства"
              value={form.caseNumber}
              maxLength={25}
              placeholder="12345/20/69025-ИП"
              status={shownErrors.caseNumber ? 'error' : undefined}
              onChange={(event) => update('caseNumber', event.target.value)}
            />
          </Field>
        )}
        {form.serviceCode === INCLUDE_CLOSED_SERVICE && (
          <Checkbox
            checked={form.includeClosed}
            onChange={(event) => update('includeClosed', event.target.checked)}
          >
            Включать оконченные производства
          </Checkbox>
        )}

        {fieldErrorCount > 0 && (
          <Text type="danger">
            Заявление не прошло проверку: исправьте отмеченные поля ({fieldErrorCount}).
          </Text>
        )}
        {generalErrors.length > 0 && (
          <Alert type="error" showIcon message={generalErrors.join(' ')} />
        )}
        <Space wrap>
          <Button
            icon={<CodeOutlined />}
            loading={previewing}
            disabled={unavailable || busy}
            onClick={() => run(onPreview)}
          >
            Проверить и показать XML
          </Button>
          <Button
            type="primary"
            icon={<SendOutlined />}
            loading={submitting}
            disabled={unavailable || busy}
            onClick={() => run(onSubmit)}
          >
            Отправить в ФССП
          </Button>
        </Space>
      </Space>
    </div>
  );
}
