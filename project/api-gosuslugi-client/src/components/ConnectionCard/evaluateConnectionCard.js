import definition from './connection_card.v1.json';

const STATES = new Set(['unknown', 'reported_yes', 'reported_no']);
const isRecord = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const isPlainRecord = (value) => isRecord(value)
  && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);

function assertClosedKeys(value, allowed) {
  if (!isPlainRecord(value)) throw new Error('Invalid input');
  Object.keys(value).forEach((key) => {
    if (key === '__proto__' || key === 'constructor' || !allowed.has(key)) throw new Error('Invalid input');
  });
}

function matches(facts, conditions) {
  return Object.entries(conditions).every(([factId, expected]) => (
    Array.isArray(expected) ? expected.includes(facts[factId]) : facts[factId] === expected
  ));
}

export default definition;

export function evaluateConnectionCard(payload) {
  assertClosedKeys(payload, new Set(['goal', 'facts']));
  if (typeof payload.goal !== 'string') throw new Error('Invalid input');
  const goal = definition.goals.find((item) => item.id === payload.goal);
  if (!goal) throw new Error('Invalid input');

  const inputFacts = payload.facts === undefined ? {} : payload.facts;
  assertClosedKeys(inputFacts, new Set(definition.facts.map((fact) => fact.id)));
  Object.values(inputFacts).forEach((value) => {
    if (!STATES.has(value)) throw new Error('Invalid input');
  });

  const facts = {};
  goal.facts.forEach((id) => { facts[id] = inputFacts[id] || 'unknown'; });
  const rule = goal.rules.find((item) => matches(facts, item.when));
  if (!rule) throw new Error('Invalid input');

  return {
    schema_version: 'connection-card-assessment.v1',
    definition_version: definition.version,
    contour: 'TEST',
    basis: 'caller_reported',
    notice: definition.notice,
    goal: goal.id,
    reported_facts: { ...facts },
    unknown_facts: goal.facts.filter((id) => facts[id] === 'unknown'),
    rule: JSON.parse(JSON.stringify(rule)),
  };
}
