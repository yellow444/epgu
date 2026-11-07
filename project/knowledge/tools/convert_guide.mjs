// Конвертер guideData.js -> knowledge.v1.json.
// Запуск: node tools/convert_guide.mjs <guideData.js> <out.json>
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve, basename } from 'node:path';
import { pathToFileURL } from 'node:url';

const OFFICIALITY = new Map([
  ['Официальный документ', 'official'],
  ['Официальный документ для старой версии', 'official'],
  ['Официальная историческая публикация', 'official_historical'],
  ['Официальный каталог', 'official_catalog'],
  ['Официальный FAQ', 'official_catalog'],
  ['Документация оператора', 'operator_docs'],
  ['Неофициальная реализация', 'unofficial_implementation'],
  ['Документация неофициальной реализации', 'unofficial_implementation'],
  ['Опыт разработчика, не контракт оператора', 'developer_experience'],
  ['Историческая статья разработчика', 'developer_experience'],
]);

const DOMAIN = new Map([
  ['transition', 'transition'],
  ['epgu-vendor', 'epgu'],
  ['epgu-consumer', 'epgu'],
  ['esia', 'esia'],
  ['smev3', 'smev'],
  ['smev4', 'smev'],
  ['signing', 'signing'],
  ['max', 'max'],
  ['digital-ruble', 'digital_ruble'],
  ['diagnostics', 'diagnostics'],
]);

const EPGU_CAPS = [
  'services.list', 'order.reserve', 'order.push',
  'order.details', 'order.cancel', 'order.download_file',
];
const COVERAGE = new Map([
  ['epgu-vendor', ['official_api_partial', EPGU_CAPS,
    'Ядро исполняет часть операций API ЕПГУ после подключения; сам маршрут подключения выполняется вручную у оператора, ядро не подаёт заявки на подключение.']],
  ['epgu-consumer', ['official_api_partial', EPGU_CAPS,
    'Ядро исполняет часть операций API ЕПГУ при наличии полномочия вендора; получение полномочия выполняется вручную.']],
  ['signing', ['official_api_partial', ['goskey.preview', 'goskey.submit'],
    'Ядро исполняет часть операций подписания через Госключ; остальные шаги справочные.']],
]);
const COVERAGE_DEFAULT = ['informational', [],
  'Справочный маршрут: описание шагов и проверок, ядро его не исполняет.'];

function fail(msg) {
  process.stderr.write(`convert_guide: ${msg}\n`);
  process.exit(1);
}

const [, , srcArg, outArg] = process.argv;
if (!srcArg || !outArg) fail('usage: convert_guide.mjs <guideData.js> <out.json>');

const srcPath = resolve(srcArg);
const sha256 = createHash('sha256').update(readFileSync(srcPath)).digest('hex');
const mod = await import(pathToFileURL(srcPath).href);
const { REVIEWED_AT, SOURCES, FLOWS, PRACTICAL_NOTES } = mod;
if (!REVIEWED_AT || !SOURCES || !FLOWS || !PRACTICAL_NOTES) fail('missing exports in source');

const sources = Object.entries(SOURCES).map(([id, s]) => {
  const officiality = OFFICIALITY.get(s.kind);
  if (!officiality) fail(`unknown source kind for ${id}: ${JSON.stringify(s.kind)}`);
  return {
    id,
    title: s.title,
    url: s.url,
    section: s.section,
    kind_label: s.kind,
    officiality,
    checked_at: REVIEWED_AT,
    version: null,
    sha256: null,
    redistribution: 'link_only',
  };
});

const routes = FLOWS.map((f) => {
  const domain = DOMAIN.get(f.id);
  if (!domain) fail(`no domain mapping for route ${f.id}`);
  const [status, capabilities, note] = COVERAGE.get(f.id) ?? COVERAGE_DEFAULT;
  return {
    id: f.id,
    title: f.title,
    summary: f.summary,
    domain,
    coverage: { status, capabilities: [...capabilities], note },
    entry_node: f.nodes[0].id,
    nodes: f.nodes.map((n) => ({
      id: n.id,
      title: n.title,
      body: n.body,
      checks: [...n.checks],
      sources: [...n.sources],
      next: n.next.map((e) => ({ to: e.to, label: e.label })),
      warning: n.warning === '' || n.warning === undefined ? null : n.warning,
      layout: { column: n.column, row: n.row },
    })),
  };
});

const notes = PRACTICAL_NOTES.map((n, i) => ({
  id: `note-${String(i + 1).padStart(2, '0')}`,
  title: n.title,
  status: n.status,
  text: n.text,
  sources: [...n.sources],
}));

const doc = {
  schema_version: '1.0',
  dataset: {
    id: 'epgu-integration-guide',
    reviewed_at: REVIEWED_AT,
    generated_from: { file: basename(srcPath), sha256, origin: 'repos/public uncommitted' },
    license_note: 'Тексты маршрутов авторские (AGPL проекта). Внешние документы только ссылками.',
  },
  sources,
  routes,
  notes,
};

const outPath = resolve(outArg);
mkdirSync(dirname(outPath), { recursive: true });
writeFileSync(outPath, JSON.stringify(doc, null, 2) + '\n', 'utf8');
