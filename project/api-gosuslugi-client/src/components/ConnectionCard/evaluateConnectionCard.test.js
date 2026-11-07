import { evaluateConnectionCard } from './evaluateConnectionCard';

test('unknown application history never turns an empty powers list into advice to resubmit', () => {
  const result = evaluateConnectionCard({
    goal: 'request_power',
    facts: {
      same_context: 'reported_yes',
      system_registered: 'reported_yes',
      cert_bound: 'reported_yes',
      power_visible: 'reported_no',
    },
  });
  expect(result.rule.id).toBe('application_history_unknown');
  expect(result.rule.next_step).toContain('Пустой список полномочий не доказывает');
  expect(result.reported_facts.application_submitted).toBe('unknown');
  expect(result.unknown_facts).toContain('application_submitted');
});

test('accepted application is not issuance and contradictory receipt is surfaced first', () => {
  const result = evaluateConnectionCard({
    goal: 'request_power',
    facts: {
      same_context: 'reported_yes',
      application_submitted: 'reported_no',
      application_received: 'reported_yes',
    },
  });
  expect(result.rule.id).toBe('receipt_vs_submission');
  expect(result.rule.next_step).toContain('Не отправляйте новую анкету');
  expect(result.reported_facts.power_issued).toBe('unknown');
  expect(result.basis).toBe('caller_reported');
});

test('local signature validity does not override reported server rejection', () => {
  const result = evaluateConnectionCard({
    goal: 'check_signature',
    facts: {
      same_context: 'reported_yes',
      local_signature_valid: 'reported_yes',
      server_signature_accepted: 'reported_no',
      error_recorded: 'unknown',
    },
  });
  expect(result.rule.id).toBe('error_not_recorded');
  expect(result.rule.summary).toContain('причина неизвестна');
  expect(result.unknown_facts).toContain('cert_bound');
});

test('unknown API key does not block the manual request route', () => {
  const result = evaluateConnectionCard({
    goal: 'obtain_api_key',
    facts: {
      same_context: 'reported_yes',
      application_submitted: 'reported_no',
      power_issued: 'reported_no',
      key_configured: 'unknown',
    },
  });
  expect(result.rule.id).toBe('request_route');
  expect(result.rule.next_step).toContain('Неизвестный ключ не мешает');
});

test('accepts any known fact but ignores facts irrelevant to the selected goal', () => {
  const baseline = evaluateConnectionCard({ goal: 'request_power' });
  const withIrrelevantFacts = evaluateConnectionCard({
    goal: 'request_power',
    facts: { local_signature_valid: 'reported_yes', key_configured: 'reported_no' },
  });
  expect(withIrrelevantFacts).toEqual(baseline);
  expect(withIrrelevantFacts.reported_facts).not.toHaveProperty('local_signature_valid');
  expect(withIrrelevantFacts.reported_facts).not.toHaveProperty('key_configured');
});

test('all unknown inputs remain unknown and output only relevant facts', () => {
  const result = evaluateConnectionCard({ goal: 'check_signature' });
  expect(result.rule.id).toBe('context_unknown');
  expect(result.unknown_facts).toEqual([
    'same_context', 'local_signature_valid', 'server_signature_accepted',
    'cert_bound', 'signature_context_checked', 'error_recorded',
  ]);
  expect(Object.keys(result.reported_facts)).toEqual(result.unknown_facts);
  expect(result).toMatchObject({
    schema_version: 'connection-card-assessment.v1',
    definition_version: '1.0.0',
    contour: 'TEST',
    basis: 'caller_reported',
    goal: 'check_signature',
  });
});

test.each([
  ['unknown goal', { goal: '__proto__' }],
  ['unknown field', { goal: 'request_power', facts: { tax_id: 'x' } }],
  ['invalid state', { goal: 'request_power', facts: { same_context: 'yes' } }],
  ['extra top-level key', { goal: 'request_power', action: 'send' }],
  ['constructor field', { goal: 'request_power', facts: JSON.parse('{"constructor":"reported_yes"}') }],
  ['prototype field', { goal: 'request_power', facts: JSON.parse('{"__proto__":"reported_yes"}') }],
])('rejects %s with a generic Error', (_name, input) => {
  expect(() => evaluateConnectionCard(input)).toThrow(new Error('Invalid input'));
});

test('returns a detached rule object', () => {
  const result = evaluateConnectionCard({ goal: 'request_power' });
  result.rule.when.injected = 'reported_yes';
  expect(evaluateConnectionCard({ goal: 'request_power' }).rule.when.injected).toBeUndefined();
});
