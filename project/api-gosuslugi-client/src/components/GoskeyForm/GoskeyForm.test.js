import {
  GOSKEY_ROUTES,
  buildGoskeyPayload,
  createGoskeyFormValue,
  createGoskeySubmissionFormData,
  defaultGoskeyExpiration,
  getGoskeyCapabilityOptions,
  isGoskeyServiceProfile,
  validateGoskeyForm,
} from './GoskeyForm';

const SERVICE = {
  serviceCode: '10000000374',
  region: '45000000000',
  available: true,
  documents: [{ id: 'request', generator: 'goskey' }],
  capabilities: [
    {
      id: 'unep',
      label: 'УНЭП физического лица',
      state: 'verified',
      reason: 'Проверено по XSD.',
      allowedExtensions: ['.pdf'],
      maxDocuments: 20,
    },
    {
      id: 'ukep',
      label: 'УКЭП физического лица',
      state: 'reference',
      reason: 'Для опубликованного namespace отсутствует XSD.',
    },
  ],
};

const completeIndividualForm = () => ({
  ...createGoskeyFormValue(SERVICE, new Date('2026-08-12T12:00:00Z')),
  variant: 'unep',
  snils: '123-456-789 00',
  description: 'Подписание договора',
  orgName: 'ООО Ромашка',
  orgInn: '7700000000',
  backlink: 'https://example.test/result',
});

describe('Goskey frontend contract', () => {
  test('uses the three dedicated backend routes', () => {
    expect(GOSKEY_ROUTES).toEqual({
      capabilities: '/goskey/capabilities',
      preview: '/goskey/preview',
      submit: '/goskey/submit',
    });
  });

  test('recognizes only a profile with the Goskey generator', () => {
    expect(isGoskeyServiceProfile(SERVICE)).toBe(true);
    expect(isGoskeyServiceProfile({ ...SERVICE, documents: [] })).toBe(false);
    expect(
      isGoskeyServiceProfile({
        ...SERVICE,
        serviceCode: '60010153',
      })
    ).toBe(false);
  });

  test('defaults expiration to one hour ahead in Moscow UTC+03:00', () => {
    expect(defaultGoskeyExpiration(new Date('2026-08-12T12:00:00Z'))).toBe(
      '2026-08-12T16:00:00+03:00'
    );
  });

  test('keeps UKEP visible but disabled with the official-contract reason', () => {
    const options = getGoskeyCapabilityOptions(SERVICE, []);
    expect(options).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ value: 'unep', disabled: false }),
        expect.objectContaining({
          value: 'ukep',
          disabled: true,
          label: expect.stringContaining('отсутствует XSD'),
        }),
      ])
    );
  });

  test('maps an individual request and optional Order ID to the backend DTO', () => {
    expect(buildGoskeyPayload(completeIndividualForm(), '12345')).toEqual({
      serviceCode: '10000000374',
      region: '45000000000',
      variant: 'unep',
      recipientType: 'individual',
      snils: '123-456-789 00',
      signExpiration: '2026-08-12T16:00:00+03:00',
      description: 'Подписание договора',
      orgName: 'ООО Ромашка',
      orgInn: '7700000000',
      backlink: 'https://example.test/result',
      orderId: '12345',
    });
  });

  test('keeps an Order ID above Number.MAX_SAFE_INTEGER exact', () => {
    const orderId = '9007199254740993';
    const payload = buildGoskeyPayload(completeIndividualForm(), orderId);

    expect(payload.orderId).toBe(orderId);
    expect(
      validateGoskeyForm({
        form: completeIndividualForm(),
        service: SERVICE,
        files: [{ name: 'contract.pdf', size: 42 }],
        orderId,
        now: new Date('2026-08-12T12:30:00Z'),
        signingCertificateSelected: true,
      })
    ).toMatchObject({ valid: true, payload: { orderId } });
  });

  test.each(['', '1', '123456789012', '12A45'])(
    'rejects an invalid runtime OKATO value %p',
    (region) => {
      const result = validateGoskeyForm({
        form: { ...completeIndividualForm(), region },
        service: SERVICE,
        files: [{ name: 'contract.pdf', size: 42 }],
        now: new Date('2026-08-12T12:30:00Z'),
        signingCertificateSelected: true,
      });

      expect(result.valid).toBe(false);
      expect(result.errors).toContain('ОКАТО должен содержать от 2 до 11 цифр.');
    }
  );

  test('accepts a two-digit regional OKATO from the official contract', () => {
    const result = validateGoskeyForm({
      form: { ...completeIndividualForm(), region: '36' },
      service: SERVICE,
      files: [{ name: 'contract.pdf', size: 42 }],
      now: new Date('2026-08-12T12:30:00Z'),
      signingCertificateSelected: true,
    });

    expect(result).toMatchObject({ valid: true, payload: { region: '36' } });
  });

  test('builds multipart with JSON request and repeated documents fields only', () => {
    const payload = buildGoskeyPayload(completeIndividualForm(), '12345');
    const documents = [
      new File(['one'], 'contract.pdf', { type: 'application/pdf' }),
      new File(['two'], 'appendix.pdf', { type: 'application/pdf' }),
    ];
    const body = createGoskeySubmissionFormData(payload, documents);

    expect(JSON.parse(body.get('request'))).toEqual(payload);
    expect(body.getAll('documents').map((file) => file.name)).toEqual([
      'contract.pdf',
      'appendix.pdf',
    ]);
    expect(body.has('files_upload')).toBe(false);
    expect(body.has('req.xml')).toBe(false);
  });

  test('maps only fields for a foreign legal recipient', () => {
    const form = {
      ...completeIndividualForm(),
      serviceCode: '60025907',
      variant: undefined,
      recipientType: 'foreign-legal',
      rafp: '12345678901',
      innUser: '123456789012',
      snils: '123-456-789 00',
    };
    const payload = buildGoskeyPayload(form, '');

    expect(payload).toMatchObject({
      serviceCode: '60025907',
      recipientType: 'foreign-legal',
      rafp: '12345678901',
      innUser: '123456789012',
    });
    expect(payload).not.toHaveProperty('variant');
    expect(payload).not.toHaveProperty('snils');
    expect(payload).not.toHaveProperty('orderId');
  });

  test('blocks submission without a document and accepts an unsigned source file', () => {
    const form = completeIndividualForm();
    const base = {
      form,
      service: SERVICE,
      registry: [],
      now: new Date('2026-08-12T12:30:00Z'),
      signingCertificateSelected: true,
    };

    const missing = validateGoskeyForm({ ...base, files: [] });
    expect(missing.valid).toBe(false);
    expect(missing.errors).toContain('Добавьте хотя бы один документ для подписания.');

    const ready = validateGoskeyForm({
      ...base,
      files: [{ name: 'contract.pdf', size: 42 }],
    });
    expect(ready).toMatchObject({ valid: true });
  });

  test('rejects manually supplied detached signatures', () => {
    const result = validateGoskeyForm({
      form: completeIndividualForm(),
      service: SERVICE,
      files: [{ name: 'contract.sig', size: 42 }],
      now: new Date('2026-08-12T12:30:00Z'),
      signingCertificateSelected: true,
    });

    expect(result.valid).toBe(false);
    expect(result.errors.join(' ')).toContain('backend создаёт отсоединённые подписи сам');
  });

  test('allows preview but blocks submission until a signing certificate is selected', () => {
    const input = {
      form: completeIndividualForm(),
      service: SERVICE,
      files: [{ name: 'contract.pdf', size: 42 }],
      now: new Date('2026-08-12T12:30:00Z'),
    };

    const preview = validateGoskeyForm({ ...input, requireDocuments: false });
    const submit = validateGoskeyForm({ ...input, requireDocuments: true });

    expect(preview.valid).toBe(true);
    expect(submit.valid).toBe(false);
    expect(submit.errors).toContain(
      'Выберите сертификат подписи перед отправкой в Госключ.'
    );
  });
});
