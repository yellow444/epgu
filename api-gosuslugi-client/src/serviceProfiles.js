const SUPPORTED_PROTOCOLS = new Set(['gusmev-order']);
const SUBMISSION_MODES = new Set(['push', 'chunked']);

const firstDefined = (...values) =>
  values.find((value) => value !== undefined && value !== null && value !== '');

const asArray = (value) => (Array.isArray(value) ? value : []);

const normalizeDocument = (document) => ({
  ...document,
  id: firstDefined(document.id, document.documentId, document.name, ''),
  sourceFile: firstDefined(
    document.sourceFile,
    document.source_file,
    document.templateFile,
    ''
  ),
  outputName: firstDefined(
    document.outputName,
    document.templateFile,
    document.template_file,
    document.name,
    document.sourceFile,
    document.source_file,
    document.id,
    ''
  ),
  required: document.required !== false,
  mediaType: firstDefined(document.mediaType, document.media_type, 'application/xml'),
  schemaFile: firstDefined(document.schemaFile, document.schema_file, ''),
  signature: firstDefined(document.signature, 'none'),
});

export const normalizeServiceProfile = (raw = {}) => {
  const serviceCode = String(firstDefined(raw.serviceCode, raw.code, ''));
  const submissionSource = raw.submission || raw.profile?.submission || {};
  const declaredMode = firstDefined(
    submissionSource.mode,
    raw.submissionMode,
    'push'
  );
  const declaredModes = asArray(
    firstDefined(
      submissionSource.modes,
      submissionSource.supportedModes,
      raw.supportedSubmissionModes,
      []
    )
  ).filter((mode) => SUBMISSION_MODES.has(mode));
  const submissionModes = [
    ...new Set(
      declaredMode === 'adaptive'
        ? declaredModes.length > 0
          ? declaredModes
          : ['push', 'chunked']
        : SUBMISSION_MODES.has(declaredMode)
          ? [declaredMode, ...declaredModes]
          : declaredModes
    ),
  ];
  if (submissionModes.length === 0) submissionModes.push('push');

  const explicitAvailability =
    typeof raw.available === 'boolean'
      ? raw.available
      : typeof raw.enabled === 'boolean'
        ? raw.enabled
        : undefined;
  const status = firstDefined(
    raw.status,
    explicitAvailability === true ? 'verified' : undefined,
    'reference'
  );
  const protocol = firstDefined(
    raw.protocol,
    raw.transport,
    'reference'
  );
  const advertisedAvailable = firstDefined(
    explicitAvailability,
    status === 'verified',
    false
  );
  const protocolSupported = SUPPORTED_PROTOCOLS.has(protocol);
  const available = Boolean(
    advertisedAvailable && status === 'verified' && protocolSupported
  );

  const documentsSource = firstDefined(
    raw.documents,
    submissionSource.documents,
    raw.submissionDocuments,
    raw.profile?.documents,
    []
  );
  const transforms = asArray(
    firstDefined(
      raw.transforms,
      raw.xmlTransforms,
      raw.profile?.transforms,
      []
    )
  );
  const specSource = raw.spec || {};
  const unavailableReason = firstDefined(
    raw.unavailableReason,
    raw.reason,
    raw.capability?.reason,
    !protocolSupported
      ? `Транспорт ${protocol} пока не поддерживается этим интерфейсом.`
      : undefined,
    status !== 'verified'
      ? 'Профиль опубликован только для справки и ещё не прошёл проверку отправки.'
      : undefined,
    !available ? 'Отправка для этой услуги отключена.' : ''
  );

  return {
    ...raw,
    serviceCode,
    description: firstDefined(raw.title, raw.description, serviceCode),
    agency: firstDefined(raw.agency, ''),
    protocol,
    status,
    available,
    unavailableReason,
    spec: {
      ...specSource,
      version: firstDefined(specSource.version, raw.specVersion, ''),
      published: firstDefined(specSource.published, raw.specPublished, ''),
      source: firstDefined(specSource.source, raw.specSource, ''),
      sha256: firstDefined(specSource.sha256, raw.specSha256, ''),
    },
    submission: {
      ...submissionSource,
      mode: declaredMode,
      modes: submissionModes,
      defaultMode: firstDefined(
        submissionSource.defaultMode,
        submissionSource.default_mode,
        submissionModes[0]
      ),
      archiveNameTemplate: firstDefined(
        submissionSource.archiveNameTemplate,
        submissionSource.archive_name_template,
        raw.archiveNameTemplate,
        'piev_epgu.zip'
      ),
      chunkSize: firstDefined(
        submissionSource.chunkSize,
        submissionSource.chunk_size,
        raw.chunkSize,
        null
      ),
    },
    documents: asArray(documentsSource).map(normalizeDocument),
    transforms,
  };
};

export const normalizeServices = (services) =>
  asArray(services).map(normalizeServiceProfile).filter((service) => service.serviceCode);

export const selectInitialService = (services) =>
  services.find((service) => service.available)?.serviceCode ||
  services[0]?.serviceCode ||
  '';

export const getSubmissionModes = (service) =>
  asArray(service?.submission?.modes).filter((mode) => SUBMISSION_MODES.has(mode));

export const getDefaultSubmissionMode = (service) => {
  const modes = getSubmissionModes(service);
  const requested = service?.submission?.defaultMode;
  return modes.includes(requested) ? requested : modes[0] || 'push';
};

export const toScalarSubmissionContext = (context) => {
  if (context === undefined || context === null || context === '') return null;
  if (['string', 'number', 'boolean'].includes(typeof context)) return context;
  if (typeof context === 'object') {
    return firstDefined(context.guid, context.value, context.id, context.context, null);
  }
  return null;
};

export const renderTemplateName = (template, context = {}) => {
  if (typeof template !== 'string') return template || '';
  return template.replace(/\{([^{}]+)\}/g, (match, key) => {
    const value = context[key];
    return value === undefined || value === null || value === '' ? match : String(value);
  });
};

export const createTemplateContext = ({ service, submissionContext, orderId }) => ({
  guid: toScalarSubmissionContext(submissionContext) || '',
  orderId: orderId || '',
  serviceCode: service?.eServiceCode || service?.serviceCode || '',
  targetCode: service?.serviceTargetCode || service?.targetCode || '',
  today: new Date().toISOString().slice(0, 10),
  timestamp: new Date().toISOString(),
});

const documentProfileFor = (service, document) =>
  service?.documents?.find(
    (profile) =>
      profile.id === document.id ||
      profile.outputName === document.name ||
      profile.sourceFile === document.name
  );

export const renderDocumentName = (document, service, context) => {
  const profile = documentProfileFor(service, document);
  const rendered = renderTemplateName(
    profile?.outputName || document.name || profile?.sourceFile || 'document.xml',
    context
  );
  return rendered.includes('{') ? document.name || rendered : rendered;
};

export const buildXmlFilesForService = (payload = {}, service, context = {}) => {
  if (Array.isArray(payload.files) && payload.files.length > 0) {
    return payload.files
      .map((file) => ({
        id: firstDefined(file.id, file.documentId, file.name, ''),
        name: renderTemplateName(
          firstDefined(file.outputName, file.templateFile, file.name, file.id, ''),
          context
        ),
        content: firstDefined(file.content, ''),
      }))
      .filter((file) => file.name && file.content !== undefined);
  }

  const profiledFiles = asArray(service?.documents)
    .map((document) => {
      const content = firstDefined(
        payload[document.id],
        payload[document.sourceFile],
        payload[document.outputName]
      );
      if (content === undefined) return null;
      return {
        id: document.id,
        name: renderTemplateName(document.outputName, context),
        content,
      };
    })
    .filter(Boolean);
  if (profiledFiles.length > 0) return profiledFiles;

  return [
    payload.req === undefined
      ? null
      : { id: 'req', name: 'req.xml', content: payload.req },
    payload.piev_epgu === undefined
      ? null
      : { id: 'piev_epgu', name: 'piev_epgu.xml', content: payload.piev_epgu },
  ].filter(Boolean);
};

export const getServiceTransforms = (service) => service?.transforms || [];

const selectNodes = (dom, selector = {}) => {
  if (selector.xpath && typeof dom.evaluate === 'function') {
    const namespaces = selector.namespaces || {};
    const result = dom.evaluate(
      selector.xpath,
      dom,
      (prefix) => namespaces[prefix] || null,
      XPathResult.ORDERED_NODE_SNAPSHOT_TYPE,
      null
    );
    return Array.from({ length: result.snapshotLength }, (_, index) =>
      result.snapshotItem(index)
    );
  }
  if (selector.localName) {
    return Array.from(
      dom.getElementsByTagNameNS(selector.namespace || '*', selector.localName)
    );
  }
  if (selector.tagName) return Array.from(dom.getElementsByTagName(selector.tagName));
  return [];
};

export const applyServiceTransforms = (documents, service, context) => {
  const transforms = getServiceTransforms(service);
  if (transforms.length === 0) return documents;

  return documents.map((document) => {
    const matching = transforms.filter(
      (transform) =>
        transform.documentId === '*' ||
        transform.documentId === document.id ||
        transform.documentId === document.name
    );
    if (matching.length === 0) return document;

    const dom = new DOMParser().parseFromString(document.content, 'application/xml');
    if (dom.getElementsByTagName('parsererror').length > 0) {
      throw new Error(`XML ${document.name} содержит синтаксическую ошибку.`);
    }
    matching.forEach((transform) => {
      const valueTemplate = firstDefined(
        transform.value,
        transform.valueTemplate,
        transform.valueFrom ? `{${transform.valueFrom}}` : undefined,
        ''
      );
      const value = renderTemplateName(valueTemplate, context);
      if (/\{[^{}]+\}/.test(value)) return;
      selectNodes(dom, transform.selector).forEach((node) => {
        const attribute = transform.attribute || transform.selector?.attribute;
        if (attribute && typeof node.setAttribute === 'function') {
          node.setAttribute(attribute, value);
        } else {
          node.textContent = value;
        }
      });
    });
    return { ...document, content: new XMLSerializer().serializeToString(dom) };
  });
};

export const createLatestRequestGate = () => {
  let sequence = 0;
  let cancelCurrent = null;
  return {
    begin(cancel) {
      if (cancelCurrent) cancelCurrent();
      sequence += 1;
      cancelCurrent = typeof cancel === 'function' ? cancel : null;
      return sequence;
    },
    isCurrent(requestSequence) {
      return requestSequence === sequence;
    },
    finish(requestSequence) {
      if (requestSequence === sequence) cancelCurrent = null;
    },
    cancel() {
      if (cancelCurrent) cancelCurrent();
      cancelCurrent = null;
      sequence += 1;
    },
  };
};

