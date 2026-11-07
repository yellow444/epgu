// Синхронизация встроенных копий модели знаний для клиента.
// Create React App не разрешает импорт за пределами src/, поэтому каноническая
// модель и её JSON Schema копируются побайтно в клиент. Копии руками не правят:
// клиент проверяет ответ сервера той же схемой, что и пакет knowledge.
// Так же копируется ручной маршрут: интерфейс показывает тот же набор, что HTTP и MCP.
// Запуск: node tools/sync_ui_copy.mjs          - записать копии
//         node tools/sync_ui_copy.mjs --check  - выйти с кодом 1, если копия отличается
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const components = resolve(here, '../../api-gosuslugi-client/src/components');
const pairs = [
  ['../src/epgu_knowledge/data/knowledge.v1.json', 'IntegrationGuide/knowledge.v1.json'],
  ['../src/epgu_knowledge/schema/knowledge.v1.schema.json', 'IntegrationGuide/knowledge.v1.schema.json'],
  ['../src/epgu_knowledge/data/manual_path.v1.json', 'PublicSetup/manual_path.v1.json'],
  ['../src/epgu_knowledge/data/connection_card.v1.json', 'ConnectionCard/connection_card.v1.json'],
].map(([from, to]) => [resolve(here, from), resolve(components, to)]);

const check = process.argv.includes('--check');
let stale = 0;

for (const [source, target] of pairs) {
  const canonical = readFileSync(source);
  if (check) {
    if (!existsSync(target) || !canonical.equals(readFileSync(target))) {
      process.stderr.write(`sync_ui_copy: копия устарела или отсутствует: ${target}\n`);
      stale += 1;
    }
  } else {
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, canonical);
    process.stdout.write(`sync_ui_copy: записано ${canonical.length} байт в ${target}\n`);
  }
}

if (check) {
  if (stale) {
    process.stderr.write('Выполните: node knowledge/tools/sync_ui_copy.mjs\n');
    process.exit(1);
  }
  process.stdout.write('sync_ui_copy: копии совпадают с канонической моделью\n');
}
