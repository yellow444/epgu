import {
  applyServiceTransforms,
  buildXmlFilesForService,
  createLatestRequestGate,
  createTemplateContext,
  getDefaultSubmissionMode,
  getSubmissionModes,
  normalizeServiceProfile,
  renderDocumentName,
  selectInitialService,
  toScalarSubmissionContext,
} from './serviceProfiles';

describe('service profile contract', () => {
  test('does not infer executable capability from a legacy service code', () => {
    const legacy = normalizeServiceProfile({
      serviceCode: '60010153',
      description: 'Наличие ИП',
      submissionMode: 'push',
    });
    const unknown = normalizeServiceProfile({
      serviceCode: '10000000000',
      description: 'Не проверена',
    });

    const verified = normalizeServiceProfile({
      serviceCode: '60025907',
      protocol: 'gusmev-order',
      status: 'verified',
      available: true,
    });

    expect(legacy).toMatchObject({
      available: false,
      protocol: 'reference',
      status: 'reference',
    });
    expect(verified).toMatchObject({
      available: true,
      protocol: 'gusmev-order',
      status: 'verified',
    });
    expect(unknown.available).toBe(false);
    expect(selectInitialService([unknown, verified])).toBe('60025907');
  });

  test('normalizes capability DTO, adaptive mode and rendered output names', () => {
    const service = normalizeServiceProfile({
      serviceCode: '60010153',
      protocol: 'gusmev-order',
      status: 'verified',
      available: true,
      submission: {
        mode: 'adaptive',
        defaultMode: 'chunked',
        archiveNameTemplate: '{orderId}-archive.zip',
      },
      documents: [
        { id: 'req', sourceFile: 'req.xml', outputName: 'req_{guid}.xml' },
      ],
    });
    const context = createTemplateContext({
      service,
      submissionContext: { guid: 'abc-123' },
      orderId: '42',
    });

    expect(getSubmissionModes(service)).toEqual(['push', 'chunked']);
    expect(getDefaultSubmissionMode(service)).toBe('chunked');
    expect(toScalarSubmissionContext({ guid: 'abc-123' })).toBe('abc-123');
    expect(
      renderDocumentName({ id: 'req', name: 'req.xml' }, service, context)
    ).toBe('req_abc-123.xml');
  });

  test('disables a reference-only or unsupported transport with an actionable reason', () => {
    const service = normalizeServiceProfile({
      serviceCode: '60079416',
      protocol: 'equeue',
      status: 'reference',
      available: true,
    });

    expect(service.available).toBe(false);
    expect(service.unavailableReason).toContain('equeue');
  });

  test('loads profiled XML with its rendered filename', () => {
    const service = normalizeServiceProfile({
      serviceCode: '60010153',
      documents: [
        { id: 'req', sourceFile: 'req.xml', outputName: 'req_{guid}.xml' },
      ],
    });

    expect(
      buildXmlFilesForService(
        { req: '<Request />' },
        service,
        { guid: 'guid-1' }
      )
    ).toEqual([
      { id: 'req', name: 'req_guid-1.xml', content: '<Request />' },
    ]);
  });
});

describe('service XML transformations', () => {
  test('changes only the document and namespace declared by the service profile', () => {
    const service = normalizeServiceProfile({
      serviceCode: '60010153',
      protocol: 'gusmev-order',
      status: 'verified',
      available: true,
      transforms: [
        {
          documentId: 'req',
          selector: { namespace: 'urn:request', localName: 'OrderId' },
          value: '{orderId}',
        },
      ],
    });
    const documents = [
      {
        id: 'req',
        name: 'req.xml',
        content: '<r:Request xmlns:r="urn:request"><r:OrderId>old</r:OrderId></r:Request>',
      },
      {
        id: 'other',
        name: 'other.xml',
        content: '<OrderId>untouched</OrderId>',
      },
    ];

    const result = applyServiceTransforms(documents, service, { orderId: 'new-id' });

    expect(result[0].content).toContain('>new-id<');
    expect(result[1]).toEqual(documents[1]);
  });
});

describe('latest XML request gate', () => {
  test('cancels the previous request and rejects its late response', () => {
    const firstCancel = jest.fn();
    const secondCancel = jest.fn();
    const gate = createLatestRequestGate();

    const first = gate.begin(firstCancel);
    const second = gate.begin(secondCancel);

    expect(firstCancel).toHaveBeenCalledTimes(1);
    expect(gate.isCurrent(first)).toBe(false);
    expect(gate.isCurrent(second)).toBe(true);

    gate.cancel();
    expect(secondCancel).toHaveBeenCalledTimes(1);
    expect(gate.isCurrent(second)).toBe(false);
  });
});

