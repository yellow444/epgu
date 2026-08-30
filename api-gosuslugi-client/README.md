# Frontend API Госуслуг

React-интерфейс для backend-шлюза API ЕПГУ/ГУСМЭВ: выбор услуги, получение маркера ЕСИА, подготовка отдельных XML-документов, загрузка вложений, подача заявления, просмотр статусов и работа с Госключом.

Frontend не содержит собственный статический каталог услуг. При запуске он получает профили через `GET /services`, нормализует их в `serviceProfiles.js` и использует описанные backend-ом режимы, имена документов, transforms, варианты и ограничения.

## Фактическая готовность услуг

В реестре 21 профиль:

- три профиля Госключа доступны для отправки: УНЭП `10000000374`, УКЭП для юридического лица/ИП `60025907` и УКЭП с сертификатом Федерального казначейства `60080470`;
- остальные 18 видны в списке с пометкой «справочно», причиной блокировки и ссылкой на спецификацию, но кнопки подготовки/отправки для них отключены;
- у ФССП `60010153` каталогизированы схема и транспорт, но XML является только демонстрационным; включение требует типизированной формы, fail-closed проверки placeholder/полей и приёмки в авторизованном контуре;
- у `10000000374` доступна только capability УНЭП; УКЭП физического лица остаётся справочной из-за отсутствующей опубликованной XSD;
- `60079416` (расшифрование в Госключе) остаётся справочным из-за противоречий официальных материалов.

Наличие профиля в UI не означает готовность интеграции. Backend повторно проверяет `status=verified` и `available=true`, поэтому обход frontend-блокировки не разрешает отправку.

Полная матрица находится в [`../docs/SERVICES.md`](../docs/SERVICES.md).

## Возможности

- выбор услуги из versioned backend-реестра и отображение ведомства, версии/даты спецификации, транспорта и обязательных документов;
- управление сертификатом CryptoPro через backend и получение маркера ЕСИА;
- service-aware подготовка XML: каждый документ имеет собственное конечное имя, transforms и XSD/validation metadata;
- режимы `push`, `chunked` и `adaptive`; реальное разбиение ZIP на части выполняет backend;
- XML-редактор Ace, drag-and-drop вложений и восстановление файлов из IndexedDB; удаление файла/«Очистить все» синхронно очищает кэш, а отдельная кнопка удаляет все локальные документы, ответы и сессию;
- список заявлений, статусы, детали, отмена и скачивание ответных файлов;
- отдельная fail-closed форма Госключа с capability-level проверкой, preview XML и отправкой документов.

## Госключ

`src/components/GoskeyForm/GoskeyForm.js` выбирается только для профиля с генератором `goskey`. Форма проверяет capability и доступность услуги, ОКАТО, срок подписи в часовом поясе Москвы, тип/идентификатор получателя, реквизиты организации, число и расширения документов.

| Backend route | Назначение |
|---|---|
| `GET /goskey/capabilities` | Актуальные состояния возможностей и причины блокировки |
| `POST /goskey/preview` | Типизированная генерация/проверка XML без подписи и отправки |
| `POST /goskey/submit` | Multipart-запрос: JSON в поле `request`, документы в полях `documents`; backend генерирует XML, создаёт detached CAdES и выбирает adaptive-транспорт |

Preview не является криптографической проверкой и ничего не отправляет в ЕПГУ. Для submit требуется backend с отдельно лицензированными CryptoPro CSP/`pycades`, сертификатом и закрытым ключом. Если указан `orderId`, backend использует chunked-путь; без него transport выбирается по размеру итогового подписанного архива.

## Требования и зависимости

- Node.js 24 LTS для разработки и build-stage Docker;
- npm с поддержкой lockfile v3;
- React 18, Ant Design 6, Axios 1.19.0, Ace Editor и IndexedDB (`idb`);
- работающий backend для реальных сценариев.

`react-scripts` относится к devDependencies: он нужен для тестов и сборки, но отсутствует в финальном nginx-образе. Неиспользуемый `cra-template` удалён.

## Локальный запуск

Устанавливайте точное дерево из `package-lock.json`:

```bash
npm ci
npm start
```

Скопируйте безопасный отслеживаемый пример в локальный ignored-файл:

```bash
cp .env.development.example .env.development.local
```

Пример задаёт:

```dotenv
PORT=53000
REACT_APP_BACKEND_URL=http://localhost:55000
```

Dev-сервер доступен на <http://localhost:53000>. Backend должен быть запущен с `ALLOWED_ORIGINS=http://localhost:53000`; переменная `REACT_APP_BACKEND_URL` встраивается в bundle во время сборки.

## Docker и nginx proxy

Из корня репозитория:

```bash
docker compose up -d --build frontend
```

По умолчанию интерфейс доступен на <http://localhost:50080>. Docker build-stage использует `node:24-alpine` и `npm ci`, после чего статический bundle копируется в `nginx:stable-alpine`; Node и build/dev dependencies в runtime-образ не попадают.

Production bundle использует `REACT_APP_BACKEND_URL=/api`. Nginx принимает `/api/...`, удаляет внешний префикс благодаря завершающему `/` в `proxy_pass` и передаёт запрос на `${BACKEND_API}` (по умолчанию `http://api:5000`).

Доступные настройки Compose:

| Переменная | По умолчанию | Когда применяется |
|---|---|---|
| `BACKEND_URL` | `/api` | build arg frontend; становится `REACT_APP_BACKEND_URL` |
| `BACKEND_API` | `http://api:5000` | runtime nginx; внутренний адрес FastAPI |
| `FRONTEND_PORT` | `50080` | host-порт nginx |

## Проверки

```bash
npm ci
npm audit --omit=dev --audit-level=high
CI=true npm test -- --watchAll=false --runInBand
npm run lint
CI=true npm run build
```

Зафиксированный результат после dependency hardening:

- чистый `npm ci`: успешно, 1 435 пакетов;
- production/runtime audit: **0 vulnerabilities**;
- Jest: **3 suites, 20 tests passed** (включая 9 тестов формы Госключа);
- ESLint по `src`: успешно;
- production build и Docker build-stage на Node 24: успешно.

Полный `npm audit` намеренно показывает остаток legacy CRA build/dev-дерева: **57 advisories** - 3 critical, 28 high, 13 moderate и 13 low; единственная прямая уязвимая зависимость - `react-scripts`. Они отсутствуют из `npm audit --omit=dev` и финального nginx-runtime, но остаются риском CI/build-среды. `npm audit fix --force` не применяется: npm предлагает некорректное разрушительное разрешение для `react-scripts`. Долг устраняется отдельной контролируемой миграцией с Create React App, а не принудительным изменением lockfile.

Текущая сборка также предупреждает о неподдерживаемом CRA, старом `caniuse-lite`, одном source map и большом bundle; это не делает текущий build ошибочным, но должно войти в план миграции и оптимизации.

## Структура

```text
src/
  App.js
  serviceProfiles.js
  components/
    FileDropzone/
    GoskeyForm/
    JsonViewer/
    PublicSetup/
```

- `App.js` - вкладки, API-вызовы и orchestration состояния;
- `serviceProfiles.js` - нормализация backend-профилей, режимы отправки, имена документов и XML transforms;
- `GoskeyForm/` - DTO/валидация/маршруты Госключа и тесты;
- `FileDropzone/` - загрузка вложений;
- `PublicSetup/` - публичный ручной сценарий: официальные ссылки,
  редактируемые поля и подготовка обычного письма без чтения вкладок,
  расширения Chrome, автоподстановки и автоматической отправки.

Расширенный TESTEP-сценарий с браузерным мостом, почтовым транспортом,
автоматическим сбором фактических данных и шаблонами хранится в отдельном
приватном репозитории `epgu-private` и не является зависимостью этой сборки.

Дополнительные команды и диагностика приведены в [`HOWTO.md`](./HOWTO.md), backend-контракт - в [`../api-gosuslugi-backend/README.md`](../api-gosuslugi-backend/README.md).

## Лицензия

См. корневой файл [`../LICENSE`](../LICENSE) (AGPL-3.0-or-later).
