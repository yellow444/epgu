// Проверка производного валидатора UI против канонической JSON Schema.
// Мутации строятся обходом самой схемы, поэтому новое поле схемы без проверки
// в UI сразу даёт падение теста.
import fs from 'fs';
import path from 'path';
import bundled from './knowledge.v1.json';
import schema from './knowledge.v1.schema.json';
import { checkDataset, LAYOUT_LIMITS, UnsupportedSchema, validateAgainstSchema, validateDataset } from './knowledgeModel';

const clone = () => JSON.parse(JSON.stringify(bundled));
const BAD = { unexpected: 'object' };

const resolve = (node) => (node.$ref ? { ...schema.$defs[node.$ref.slice('#/$defs/'.length)], ...node } : node);

// Все пути к значениям в bundled, которые описывает схема, вместе с подсхемой.
function collectPaths(node, value, at, out) {
  const sub = resolve(node);
  out.push({ at, sub });
  if (Array.isArray(value) && sub.items && value.length) collectPaths(sub.items, value[0], [...at, 0], out);
  if (value && typeof value === 'object' && !Array.isArray(value) && sub.properties) {
    Object.keys(sub.properties).forEach((name) => {
      if (name in value) collectPaths(sub.properties[name], value[name], [...at, name], out);
    });
  }
  return out;
}

function setAt(data, at, mutate) {
  const parent = at.slice(0, -1).reduce((obj, key) => obj[key], data);
  mutate(parent, at[at.length - 1]);
  return data;
}

const ALL = collectPaths(schema, bundled, [], []);
const PATHS = ALL.filter((item) => item.at.length > 0);
const subAt = (at) => ALL.find((item) => item.at.join('/') === at.join('/')).sub;
const allowsObject = (sub) => sub.type === 'object' || (Array.isArray(sub.type) && sub.type.includes('object'));

test('the bundled schema is byte-identical to the canonical one', () => {
  const project = path.resolve(__dirname, '../../../..');
  const canonical = fs.readFileSync(path.join(project, 'knowledge/src/epgu_knowledge/schema/knowledge.v1.schema.json'));
  expect(fs.readFileSync(path.join(__dirname, 'knowledge.v1.schema.json')).equals(canonical)).toBe(true);
});

test('the bundled dataset passes the schema and integrity checks', () => {
  expect(checkDataset(bundled)).toEqual({ ok: true, reason: null, errors: [], total: 0 });
});

test('mutation walk covers the fields the screen renders', () => {
  const covered = new Set(PATHS.map((item) => item.at.filter((key) => typeof key === 'string').join('.')));
  ['routes.nodes.checks', 'routes.nodes.next.label', 'routes.summary', 'routes.nodes.warning',
    'notes.text', 'notes.status', 'sources.title', 'sources.section', 'sources.kind_label',
    'sources.url', 'sources.officiality', 'sources.checked_at']
    .forEach((field) => expect(covered).toContain(field));
});

test.each(PATHS.filter((item) => !allowsObject(item.sub)).map((item) => [item.at.join('/'), item]))(
  'an object instead of the value at /%s is rejected',
  (_, item) => {
    const data = setAt(clone(), item.at, (parent, key) => { parent[key] = BAD; });
    expect(validateDataset(data)).toBe(false);
  },
);

test.each(PATHS
  .filter((item) => typeof item.at[item.at.length - 1] === 'string')
  .filter((item) => (subAt(item.at.slice(0, -1)).required || []).includes(item.at[item.at.length - 1]))
  .map((item) => [item.at.join('/'), item]))(
  'a missing required field /%s is rejected',
  (_, item) => {
    const data = setAt(clone(), item.at, (parent, key) => { delete parent[key]; });
    const verdict = checkDataset(data);
    expect(verdict.ok).toBe(false);
    expect(verdict.reason).toBe(item.at.join('/') === 'schema_version' ? 'schema_version' : 'schema');
  },
);

test('unknown fields are rejected like in the canonical schema', () => {
  const data = clone();
  data.routes[0].nodes[0].extra = 'x';
  expect(checkDataset(data)).toMatchObject({ ok: false, reason: 'schema' });
});

test('the three payloads from the review are rejected', () => {
  const cases = [
    (data) => { data.routes[0].nodes[0].checks[0] = BAD; },
    (data) => { data.notes[0].text = BAD; },
    (data) => { data.routes[0].nodes.find((node) => node.next.length).next[0].label = BAD; },
  ];
  cases.forEach((mutate) => {
    const data = clone();
    mutate(data);
    expect(checkDataset(data)).toMatchObject({ ok: false, reason: 'schema' });
  });
});

test('duplicate ids, unknown sources and broken edges fail integrity', () => {
  const dupSource = clone();
  dupSource.sources[1].id = dupSource.sources[0].id;
  const dupRoute = clone();
  dupRoute.routes[1].id = dupRoute.routes[0].id;
  const dupNode = clone();
  dupNode.routes[0].nodes[1].id = dupNode.routes[0].nodes[0].id;
  const dupNote = clone();
  dupNote.notes[1].id = dupNote.notes[0].id;
  const unknownSource = clone();
  unknownSource.notes[0].sources = ['noSuchSource'];
  const edge = clone();
  edge.routes[0].nodes[0].next.push({ to: 'no-such-node', label: 'Битая ссылка' });
  const entry = clone();
  entry.routes[0].entry_node = 'nope';
  [dupSource, dupRoute, dupNode, dupNote, unknownSource, edge, entry].forEach((data) => {
    expect(checkDataset(data)).toMatchObject({ ok: false, reason: 'integrity' });
  });
});

test('non-string source references are rejected by the schema', () => {
  const data = clone();
  data.routes[0].nodes[0].sources = [42];
  expect(checkDataset(data)).toMatchObject({ ok: false, reason: 'schema' });
});

test('another schema version and non-objects are rejected', () => {
  const data = clone();
  data.schema_version = '2.0';
  expect(checkDataset(data).reason).toBe('schema_version');
  [null, 'x', [], 1].forEach((value) => expect(checkDataset(value).reason).toBe('schema_version'));
});

test('non-https and padded links are rejected', () => {
  ['javascript:alert(1)', 'http://example.org/', 'data:text/html,x', ' https://x', 'https://x y'].forEach((url) => {
    const data = clone();
    data.sources[0].url = url;
    expect(validateDataset(data)).toBe(false);
  });
});

test('layouts outside the screen grid or in an occupied cell are rejected', () => {
  const wide = clone();
  wide.routes[0].nodes[0].layout.column = LAYOUT_LIMITS.maxColumn + 1;
  const tall = clone();
  tall.routes[0].nodes[0].layout.row = LAYOUT_LIMITS.maxRow + 1;
  const overlap = clone();
  overlap.routes[0].nodes[1].layout = { ...overlap.routes[0].nodes[0].layout };
  [wide, tall, overlap].forEach((data) => expect(checkDataset(data)).toMatchObject({ ok: false, reason: 'integrity' }));
  const fourColumns = clone();
  fourColumns.routes[0].nodes[0].layout = { column: 3, row: 0 };
  expect(validateDataset(fourColumns)).toBe(true);
});

test('error messages carry paths and keywords, never values', () => {
  const data = clone();
  data.routes[0].nodes[0].title = { secret: 'значение-из-ответа' };
  const verdict = checkDataset(data);
  expect(verdict.errors.join(' ')).not.toMatch(/значение-из-ответа|secret/);
  expect(verdict.errors[0]).toBe('/routes/0/nodes/0/title: type');
});

test('an unsupported schema keyword is an error, not a silent pass', () => {
  expect(() => validateAgainstSchema({ type: 'string', format: 'uri' }, 'x')).toThrow(UnsupportedSchema);
  expect(() => validateAgainstSchema({ $ref: 'https://example.org/s.json' }, 'x')).toThrow(UnsupportedSchema);
  expect(() => validateAgainstSchema({ type: 'object', additionalProperties: true }, {})).toThrow(UnsupportedSchema);
});
