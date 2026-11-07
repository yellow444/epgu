// Адаптер общей модели знаний (knowledge.v1) к виду, который нужен экрану гайда.
// Компонент гайда исходно написан в repos/public (незафиксированная работа,
// guideData.js sha256 9a32cc1178b85eb3f95d56176f35f22ae7004c223b7901c87afd39ada2e972a0)
// и адаптирован: вместо ручного guideData.js данные читаются из knowledge.v1.json.
import canonicalSchema from './knowledge.v1.schema.json';

export const SCHEMA_VERSION = '1.0';

// Ограничения экрана, а не общей схемы: блок-схема раскладывается по сетке,
// ширина считается по числу колонок, но слишком широкую или длинную схему,
// как и два блока в одной клетке, экран не показывает.
export const LAYOUT_LIMITS = { maxColumn: 7, maxRow: 39 };

const MAX_REPORTED = 20;

const isArray = Array.isArray;
const isObject = (value) => value !== null && typeof value === 'object' && !isArray(value);

// Проверка JSON Schema для подмножества ключевых слов, которое использует
// каноническая схема knowledge.v1. Схема та же, что у пакета knowledge и сервера
// (побайтовая копия). Неизвестное ключевое слово - ошибка проверки, а не повод
// пропустить ограничение молча.
const ANNOTATIONS = new Set(['$schema', '$id', 'title', 'description', '$defs']);
const KEYWORDS = new Set([
  '$ref', 'type', 'const', 'enum', 'required', 'properties', 'additionalProperties',
  'items', 'minItems', 'uniqueItems', 'minLength', 'pattern', 'minimum', 'anyOf',
]);

export class UnsupportedSchema extends Error {}

function assertSupported(schema, where = '#') {
  if (!isObject(schema)) throw new UnsupportedSchema(`${where}: схема не объект`);
  Object.keys(schema).forEach((key) => {
    if (!ANNOTATIONS.has(key) && !KEYWORDS.has(key)) {
      throw new UnsupportedSchema(`${where}: ключевое слово ${key} не поддержано`);
    }
  });
  if ('additionalProperties' in schema && schema.additionalProperties !== false) {
    throw new UnsupportedSchema(`${where}: поддержано только additionalProperties: false`);
  }
  if ('$ref' in schema && !/^#\/\$defs\/[A-Za-z0-9]+$/.test(schema.$ref)) {
    throw new UnsupportedSchema(`${where}: поддержаны только локальные ссылки #/$defs`);
  }
  Object.entries(schema.$defs || {}).forEach(([name, sub]) => assertSupported(sub, `${where}/$defs/${name}`));
  Object.entries(schema.properties || {}).forEach(([name, sub]) => assertSupported(sub, `${where}/properties/${name}`));
  if ('items' in schema) assertSupported(schema.items, `${where}/items`);
  (schema.anyOf || []).forEach((sub, index) => assertSupported(sub, `${where}/anyOf/${index}`));
}

const TYPE_CHECKS = {
  object: isObject,
  array: isArray,
  string: (value) => typeof value === 'string',
  integer: (value) => Number.isInteger(value),
  number: (value) => typeof value === 'number' && Number.isFinite(value),
  boolean: (value) => typeof value === 'boolean',
  null: (value) => value === null,
};

// Сравнение значений JSON без учёта порядка ключей.
function canonical(value) {
  if (isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (isObject(value)) return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}

function validateNode(root, schema, value, path, errors) {
  if (schema.$ref) {
    validateNode(root, root.$defs[schema.$ref.slice('#/$defs/'.length)], value, path, errors);
  }
  const fail = (keyword) => errors.push(`${path || '/'}: ${keyword}`);
  if ('type' in schema) {
    const types = isArray(schema.type) ? schema.type : [schema.type];
    if (!types.some((type) => TYPE_CHECKS[type] && TYPE_CHECKS[type](value))) {
      fail('type');
      return;
    }
  }
  if ('const' in schema && canonical(value) !== canonical(schema.const)) fail('const');
  if ('enum' in schema && !schema.enum.some((item) => canonical(item) === canonical(value))) fail('enum');
  if (typeof value === 'string') {
    if ('minLength' in schema && [...value].length < schema.minLength) fail('minLength');
    if ('pattern' in schema && !new RegExp(schema.pattern, 'u').test(value)) fail('pattern');
  }
  if (typeof value === 'number' && 'minimum' in schema && value < schema.minimum) fail('minimum');
  if (isArray(value)) {
    if ('minItems' in schema && value.length < schema.minItems) fail('minItems');
    if (schema.uniqueItems && new Set(value.map(canonical)).size !== value.length) fail('uniqueItems');
    if (schema.items) value.forEach((item, index) => validateNode(root, schema.items, item, `${path}/${index}`, errors));
  }
  if (isObject(value)) {
    (schema.required || []).forEach((name) => {
      if (!Object.prototype.hasOwnProperty.call(value, name)) fail(`required ${name}`);
    });
    const properties = schema.properties || {};
    Object.keys(value).forEach((name) => {
      if (Object.prototype.hasOwnProperty.call(properties, name)) {
        validateNode(root, properties[name], value[name], `${path}/${name}`, errors);
      } else if (schema.additionalProperties === false) {
        fail(`additionalProperties ${name}`);
      }
    });
  }
  if (schema.anyOf) {
    const matches = schema.anyOf.some((sub) => {
      const nested = [];
      validateNode(root, sub, value, path, nested);
      return nested.length === 0;
    });
    if (!matches) fail('anyOf');
  }
}

export function validateAgainstSchema(schema, value) {
  assertSupported(schema);
  const errors = [];
  validateNode(schema, schema, value, '', errors);
  return errors;
}

// Ссылочная целостность, как в KnowledgeBase.validate() пакета knowledge, и
// ограничения раскладки экрана. Вызывается только для данных, прошедших схему.
function integrityErrors(data) {
  const errors = [];
  const sourceIds = new Set();
  data.sources.forEach((source, index) => {
    if (sourceIds.has(source.id)) errors.push(`/sources/${index}: повторный id`);
    sourceIds.add(source.id);
  });
  const checkRefs = (where, ids) => ids.forEach((id) => {
    if (!sourceIds.has(id)) errors.push(`${where}: неизвестный источник`);
  });
  const routeIds = new Set();
  data.routes.forEach((route, routeIndex) => {
    const where = `/routes/${routeIndex}`;
    if (routeIds.has(route.id)) errors.push(`${where}: повторный id`);
    routeIds.add(route.id);
    const nodeIds = new Set();
    const cells = new Set();
    route.nodes.forEach((node, nodeIndex) => {
      if (nodeIds.has(node.id)) errors.push(`${where}/nodes/${nodeIndex}: повторный id`);
      nodeIds.add(node.id);
      const { column, row } = node.layout;
      if (column > LAYOUT_LIMITS.maxColumn || row > LAYOUT_LIMITS.maxRow) {
        errors.push(`${where}/nodes/${nodeIndex}/layout: за пределами сетки экрана`);
      }
      const cell = `${row}:${column}`;
      if (cells.has(cell)) errors.push(`${where}/nodes/${nodeIndex}/layout: клетка уже занята`);
      cells.add(cell);
    });
    if (!nodeIds.has(route.entry_node)) errors.push(`${where}/entry_node: нет такого узла`);
    route.nodes.forEach((node, nodeIndex) => {
      node.next.forEach((edge, edgeIndex) => {
        if (!nodeIds.has(edge.to)) errors.push(`${where}/nodes/${nodeIndex}/next/${edgeIndex}: нет такого узла`);
      });
      checkRefs(`${where}/nodes/${nodeIndex}`, node.sources);
    });
  });
  const noteIds = new Set();
  data.notes.forEach((note, index) => {
    if (noteIds.has(note.id)) errors.push(`/notes/${index}: повторный id`);
    noteIds.add(note.id);
    checkRefs(`/notes/${index}`, note.sources);
  });
  return errors;
}

// Полная проверка набора данных (используется и для ответа сервера).
// reason: 'schema_version' - другая версия схемы, 'schema' - нарушение схемы,
// 'integrity' - битые ссылки или неподдержанная раскладка, 'validator' - сбой
// самой проверки. Сообщения содержат только пути и ключевые слова, без значений.
export function checkDataset(data) {
  if (!isObject(data) || data.schema_version !== SCHEMA_VERSION) {
    return { ok: false, reason: 'schema_version', errors: ['/schema_version: const'], total: 1 };
  }
  let errors;
  let reason = 'schema';
  try {
    errors = validateAgainstSchema(canonicalSchema, data);
    if (errors.length === 0) {
      reason = 'integrity';
      errors = integrityErrors(data);
    }
  } catch (err) {
    return { ok: false, reason: 'validator', errors: [`validator: ${err.name}`], total: 1 };
  }
  if (errors.length === 0) return { ok: true, reason: null, errors: [], total: 0 };
  return { ok: false, reason, errors: errors.slice(0, MAX_REPORTED), total: errors.length };
}

export function validateDataset(data) {
  return checkDataset(data).ok;
}

// Преобразует набор данных knowledge.v1 в структуры экрана.
export function buildGuideModel(data) {
  const SOURCES = {};
  data.sources.forEach((source) => {
    SOURCES[source.id] = {
      title: source.title,
      url: source.url,
      kind: source.kind_label,
      section: source.section,
      officiality: source.officiality,
      checkedAt: source.checked_at,
    };
  });
  const FLOWS = data.routes.map((route) => ({
    id: route.id,
    title: route.title,
    summary: route.summary,
    domain: route.domain,
    coverage: route.coverage,
    entry: route.entry_node,
    nodes: route.nodes.map((node) => ({
      id: node.id,
      title: node.title,
      body: node.body,
      checks: node.checks,
      sources: node.sources,
      next: node.next,
      warning: node.warning || '',
      layout: node.layout,
    })),
  }));
  const PRACTICAL_NOTES = data.notes.map((note) => ({
    id: note.id,
    title: note.title,
    status: note.status,
    text: note.text,
    sources: note.sources,
  }));
  return { FLOWS, SOURCES, PRACTICAL_NOTES, REVIEWED_AT: data.dataset.reviewed_at };
}

const DEFAULT_FLOW_ID = 'epgu-vendor';

// Разбирает адрес вида #guide/<маршрут>/<шаг>. Неизвестный маршрут или шаг
// ведёт на входной шаг маршрута по умолчанию (как в исходном компоненте).
export function findGuideLocation(hash, flows) {
  const match = /^#guide\/([a-z0-9-]+)\/([a-z0-9-]+)$/.exec(hash || '');
  const flow = match && flows.find((item) => item.id === match[1]);
  if (flow && flow.nodes.some((item) => item.id === match[2])) {
    return { flowId: flow.id, nodeId: match[2] };
  }
  const fallback = flows.find((item) => item.id === DEFAULT_FLOW_ID) || flows[0];
  return { flowId: fallback.id, nodeId: fallback.entry };
}
