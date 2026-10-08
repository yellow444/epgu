import React from 'react';
import { act, fireEvent, render, screen } from '@testing-library/react';
import FsspForm, {
  FSSP_ROUTES,
  buildFsspPayload,
  createFsspFormValue,
  fieldErrorsFromResponse,
  generalFsspErrors,
  isFsspServiceProfile,
  validateFsspForm,
} from './FsspForm';

const SERVICE = {
  serviceCode: '60010153',
  available: true,
  documents: [
    { id: 'transport', outputName: 'req.xml', generator: 'fssp' },
    { id: 'request', outputName: 'piev_epgu.xml', generator: 'fssp' },
  ],
};

const NOW = new Date('2026-10-08T09:00:00Z');

const person = (overrides = {}) => ({
  fullName: 'Петров Пётр Петрович',
  gender: '1',
  birthDate: '1985-03-04',
  snils: '112-233-445 95',
  ...overrides,
});

const completeForm = (overrides = {}) => ({
  ...createFsspFormValue(SERVICE),
  region: '45000000000',
  applicant: person(),
  organization: {
    name: 'ООО «Ромашка»',
    address: '101000, г. Москва, ул. Примерная, д. 1',
    inn: '7700000016',
    ogrn: '1027700000019',
  },
  ...overrides,
});

describe('FSSP form contract', () => {
  test('uses the dedicated backend routes', () => {
    expect(FSSP_ROUTES).toEqual({
      contracts: '/fssp/contracts',
      preview: '/fssp/preview',
      submit: '/fssp/submit',
    });
  });

  test('recognizes a profile by the fssp generator only', () => {
    expect(isFsspServiceProfile(SERVICE)).toBe(true);
    expect(isFsspServiceProfile({ ...SERVICE, documents: [{ id: 'x', sourceFile: 'req.xml' }] })).toBe(
      false
    );
    expect(isFsspServiceProfile({ submission: { documents: SERVICE.documents } })).toBe(true);
  });

  test('builds the organization payload with digits only and no foreign fields', () => {
    const payload = buildFsspPayload(
      completeForm({ organization: { name: ' ООО  «Ромашка» ', address: 'Москва', inn: '77 0000 0016', ogrn: '1027700000019' } })
    );
    expect(payload).toEqual({
      serviceCode: '60010153',
      region: '45000000000',
      side: '1',
      representation: 'organization',
      applicant: person(),
      organization: { name: 'ООО «Ромашка»', address: 'Москва', inn: '7700000016', ogrn: '1027700000019' },
      includeClosed: true,
    });
  });

  test('sends the case number only for 10000000352 and the representative only for a person', () => {
    const course = buildFsspPayload(
      completeForm({ serviceCode: '10000000352', caseNumber: ' 23545/20/69025-ИП ' })
    );
    expect(course.caseNumber).toBe('23545/20/69025-ИП');
    expect(course).not.toHaveProperty('includeClosed');

    const base = createFsspFormValue(SERVICE);
    const representative = buildFsspPayload({
      ...completeForm(),
      representation: 'person',
      representative: { ...base.representative, issuedBy: 'ЗАГС', number: '1', issuedOn: '2015-07-10', principal: person({ snils: '12345678964' }) },
    });
    expect(representative).not.toHaveProperty('organization');
    expect(representative.representative.principal.snils).toBe('12345678964');

    const personal = buildFsspPayload({ ...completeForm(), representation: 'self' });
    expect(personal).not.toHaveProperty('organization');
    expect(personal).not.toHaveProperty('representative');
  });

  test('a complete form passes the client check', () => {
    expect(validateFsspForm(completeForm(), NOW)).toMatchObject({ valid: true, errors: {} });
  });

  test('client check marks missing and malformed fields by name', () => {
    const { valid, errors } = validateFsspForm(
      completeForm({
        region: '4',
        serviceCode: '10000000352',
        caseNumber: '23545-ИП',
        applicant: person({ fullName: 'Петров', birthDate: '2026-10-09', snils: '123' }),
        organization: { name: '', address: '', inn: '77', ogrn: '1' },
      }),
      NOW
    );
    expect(valid).toBe(false);
    expect(Object.keys(errors).sort()).toEqual(
      [
        'applicant.birthDate',
        'applicant.fullName',
        'applicant.snils',
        'caseNumber',
        'organization.address',
        'organization.inn',
        'organization.name',
        'organization.ogrn',
        'region',
      ].sort()
    );
  });

  test('reads builder errors and FastAPI body errors from a 422 response', () => {
    expect(
      fieldErrorsFromResponse({
        response: {
          status: 422,
          data: {
            detail: {
              message: 'Заявление не прошло проверку',
              errors: [
                { field: 'applicant.snils', message: 'СНИЛС из примера спецификации' },
                { field: 'organization.inn', message: 'ИНН организации: 10 цифр' },
              ],
            },
          },
        },
      })
    ).toEqual({
      'applicant.snils': 'СНИЛС из примера спецификации',
      'organization.inn': 'ИНН организации: 10 цифр',
    });
    expect(
      fieldErrorsFromResponse({
        response: {
          status: 422,
          data: {
            detail: [
              { loc: ['body', 'representative', 'principal', 'birthDate'], msg: 'Input should be a valid date' },
            ],
          },
        },
      })
    ).toEqual({ 'principal.birthDate': 'Input should be a valid date' });
    expect(fieldErrorsFromResponse({ response: { status: 401, data: { detail: 'Маркер' } } })).toBeNull();
    expect(generalFsspErrors({ 'piev_epgu.xml': 'XSD', region: 'ОКАТО' })).toEqual(['XSD']);
  });
});

describe('FsspForm', () => {
  const fill = (label, value) =>
    fireEvent.change(screen.getByLabelText(label), { target: { value } });

  const fillOrganizationForm = () => {
    fill('Регион ОКАТО заявления ФССП', '45000000000');
    fill('Наименование организации', 'ООО «Ромашка»');
    fill('Адрес организации', '101000, г. Москва, ул. Примерная, д. 1');
    fill('ИНН организации', '7700000016');
    fill('ОГРН организации', '1027700000019');
    const title = 'Руководитель организации (подаёт заявление)';
    fill(`${title}: ФИО`, 'Петров Пётр Петрович');
    fill(`${title}: дата рождения`, '1985-03-04');
    fill(`${title}: СНИЛС`, '112-233-445 95');
  };

  test('shows client errors and does not call the backend for an empty form', async () => {
    const onPreview = jest.fn();
    render(<FsspForm service={SERVICE} onPreview={onPreview} onSubmit={jest.fn()} />);
    await act(async () => {
      fireEvent.click(screen.getByText('Проверить и показать XML'));
    });
    expect(onPreview).not.toHaveBeenCalled();
    expect(screen.getByText('ОКАТО: от 2 до 11 цифр')).toBeInTheDocument();
    expect(screen.getByText(/исправьте отмеченные поля/)).toBeInTheDocument();
  });

  test('submits the payload and shows the field errors the server returned', async () => {
    const onSubmit = jest.fn().mockResolvedValue({
      fieldErrors: {
        'applicant.snils': 'СНИЛС (заявитель): неверный СНИЛС, проверьте цифры',
        'piev_epgu.xml': 'Бизнес-запрос не прошёл проверку по XSD ФССП',
      },
    });
    render(
      <FsspForm
        service={SERVICE}
        organizationName="ООО «Из сертификата»"
        onPreview={jest.fn()}
        onSubmit={onSubmit}
      />
    );
    expect(screen.getByLabelText('Наименование организации')).toHaveValue('ООО «Из сертификата»');
    fillOrganizationForm();
    await act(async () => {
      fireEvent.click(screen.getByText('Отправить в ФССП'));
    });
    expect(onSubmit).toHaveBeenCalledWith(
      expect.objectContaining({
        serviceCode: '60010153',
        representation: 'organization',
        organization: expect.objectContaining({ inn: '7700000016', name: 'ООО «Ромашка»' }),
        includeClosed: true,
      })
    );
    expect(
      screen.getByText('СНИЛС (заявитель): неверный СНИЛС, проверьте цифры')
    ).toBeInTheDocument();
    expect(screen.getByText('Бизнес-запрос не прошёл проверку по XSD ФССП')).toBeInTheDocument();
  });

  test('an unavailable profile blocks both actions', () => {
    render(
      <FsspForm
        service={{ ...SERVICE, available: false, unavailableReason: 'Только для физических лиц' }}
        onPreview={jest.fn()}
        onSubmit={jest.fn()}
      />
    );
    expect(screen.getByText('Только для физических лиц')).toBeInTheDocument();
    expect(screen.getByText('Отправить в ФССП').closest('button')).toBeDisabled();
    expect(screen.getByText('Проверить и показать XML').closest('button')).toBeDisabled();
  });
});
