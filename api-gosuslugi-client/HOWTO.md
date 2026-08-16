# HOWTO — frontend (React + Ant Design)

## 1. Подготовка среды

Используйте Node.js 24 LTS. Точное дерево зависимостей устанавливается из `package-lock.json`:

```bash
node --version
npm ci
```

Не заменяйте `npm ci` на `npm install` в CI или Docker: `ci` проверяет соответствие manifest/lockfile, очищает `node_modules` и воспроизводит зафиксированные версии. Текущая runtime-версия Axios — 1.19.0; `react-scripts` находится только в devDependencies, `cra-template` отсутствует.

## 2. Локальный dev-сервер

```bash
npm start
```

Скопируйте `.env.development.example` в ignored-файл `.env.development.local`. Он задаёт порт `53000` и прямой backend `http://localhost:55000`; backend запустите с `ALLOWED_ORIGINS=http://localhost:53000`. Для другого адреса измените локальную копию:

```dotenv
PORT=53000
REACT_APP_BACKEND_URL=http://localhost:55000
```

Откройте <http://localhost:53000>. При прямом обращении к backend его `ALLOWED_ORIGINS` должен разрешать origin dev-сервера.

## 3. Запуск через Docker Compose

Из корня репозитория:

```bash
docker compose up -d --build frontend
```

Проверка:

```bash
docker compose ps
docker compose logs frontend
```

По умолчанию:

- браузер открывает <http://localhost:50080>;
- frontend bundle обращается к `/api`;
- nginx подставляет `BACKEND_API=http://api:5000` в `default.conf.template` при старте;
- запрос `/api/services` передаётся FastAPI как `/services` — завершающий `/` в `proxy_pass ${BACKEND_API}/` снимает внешний префикс;
- SPA fallback обслуживает клиентские пути через `index.html`.

Для переопределения:

```bash
BACKEND_URL=/api BACKEND_API=http://api:5000 FRONTEND_PORT=50080 \
  docker compose up -d --build frontend
```

`BACKEND_URL` — build-time значение и требует пересборки. `BACKEND_API` подставляется nginx при запуске контейнера.

## 4. Выбор услуги

При старте UI вызывает `GET /services`. Ответ должен содержать status/available, source specification, submission mode, документы и transforms. Текущий реестр содержит 21 профиль:

| Состояние | Количество | Поведение UI |
|---|---:|---|
| `verified`, доступна | 3 | Можно подготовить/отправить поддержанный сценарий |
| `reference`, заблокирована | 18 | Видна с пометкой «справочно» и причиной; действия отправки отключены |

Исполняемые профили Госключа: `10000000374` (только УНЭП), `60025907` и `60080470`. У ФССП `60010153` схема и транспорт каталогизированы, но XML является только демонстрационным; профиль требует типизированной формы, fail-closed проверки placeholder/полей и приёмки в авторизованном контуре. Frontend не должен включать услугу локальной правкой или только env-override. Сначала backend-профиль должен получить проверенные XML/XSD или типизированный генератор, golden-тесты и `available=true`; UI подхватит его автоматически.

При смене услуги UI:

1. нормализует профиль в `serviceProfiles.js`;
2. выбирает допустимый `push`/`chunked` из `submission`;
3. получает XML через `GET /xml?service=<code>` только для доступного обычного профиля;
4. применяет объявленные transforms и конечные имена документов;
5. не пытается использовать XML предыдущей услуги.

Backend сам создаёт ZIP и делит его на части; frontend не рассчитывает `.z001` и не отправляет заранее нарезанные chunks.

## 5. Госключ

Для четырёх профилей с `generator=goskey` отображается отдельная форма. Она объединяет capability из профиля с live-ответом `GET /goskey/capabilities` и оставляет непроверенные варианты видимыми, но disabled.

Порядок работы:

1. Выберите доступную услугу/вариант.
2. Укажите runtime ОКАТО, срок подписи (Москва, не более 24 часов), тип и идентификатор получателя.
3. Заполните название/ИНН отправителя, описание и при необходимости backlink.
4. Добавьте документы; frontend проверит непустое содержимое, уникальные имена, расширения и `maxDocuments` capability.
5. Нажмите «Предпросмотр XML» — вызывается `POST /goskey/preview`, отправки/подписи нет.
6. Нажмите «Подписать и отправить» — вызывается multipart `POST /goskey/submit`; backend создаёт `req.xml`, отделённую CAdES-подпись для каждого файла и выбирает `push` либо chunked.

Маршруты централизованы в `GOSKEY_ROUTES`:

```text
GET  /goskey/capabilities
POST /goskey/preview
POST /goskey/submit
```

Для submit backend должен иметь лицензированные CryptoPro CSP/`pycades` и доступный сертификат. Ответ `503` в чистом публичном контейнере ожидаем: frontend не подписывает документы сам и не хранит закрытый ключ.

## 6. Заявления, XML и локальное состояние

- Токен ЕСИА хранится в `sessionStorage` и передаётся Axios как Bearer token.
- Загруженные документы кешируются в IndexedDB (`files-db`), а XML/ответы — в browser storage для восстановления после перезагрузки. Удаление/«Очистить все» синхронизировано с IndexedDB; по окончании работы нажмите «Удалить все локальные данные и сессию». На общей рабочей станции persistence всё равно не считается безопасным.
- Ace Editor редактирует XML выбранного профиля; перед отправкой сохраняйте XML с именем, заданным профилем.
- Вкладка «Запросы» получает списки/статусы, детали, отменяет заявления и скачивает ответные файлы через backend.

Если UI показывает «Только справка», смотрите `unavailableReason` и capability reason. Не пытайтесь снять блокировку через DevTools: backend применяет ту же fail-closed проверку.

## 7. Проверки перед изменением или релизом

```bash
npm ci
npm audit --omit=dev --audit-level=high
CI=true npm test -- --watchAll=false --runInBand
npm run lint
CI=true npm run build
docker build --target build -f Dockerfile .
```

Ожидаемый проверенный результат текущего lockfile:

| Gate | Результат |
|---|---|
| `npm ci` | успешно, 1 435 пакетов |
| production audit | 0 vulnerabilities |
| Jest | 3 suites / 20 tests passed; 9 тестов относятся к Госключу |
| ESLint | exit 0 |
| CI build | exit 0, compiled with известными предупреждениями |
| Docker build-stage | exit 0 на `node:24-alpine` и `npm ci` |

Полный `npm audit` возвращает non-zero: 57 advisories в legacy CRA build/dev-дереве (3 critical, 28 high, 13 moderate, 13 low). Единственная прямая уязвимая зависимость — dev-only `react-scripts`; production-аудит и финальный nginx-runtime чисты. Не запускайте `npm audit fix --force`: безопасное устранение требует отдельной миграции с Create React App. До неё CI/build-среду следует считать отдельной зоной риска и не передавать ей production-секреты.

Известные non-blocking warnings:

- Create React App/babel preset больше не сопровождаются;
- устаревшая база `caniuse-lite`;
- один неразбираемый source map;
- основной bundle больше рекомендуемого;
- тесты выводят deprecation/`act(...)` предупреждения Ant Design/React, хотя все assertions проходят.

## 8. Диагностика

### Браузер получает 404 на `/api/...`

Проверьте, что запущен backend, `BACKEND_API` доступен из сети Compose и сгенерированный nginx-конфиг содержит `location /api/` и `proxy_pass` с завершающим slash.

### CORS при локальном запуске

Dev bundle обращается напрямую к `REACT_APP_BACKEND_URL`. Добавьте `http://localhost:53000` в backend `ALLOWED_ORIGINS` либо используйте Docker/nginx same-origin proxy.

### Профиль виден, но отправка отключена

Это штатно для 18 `reference`-профилей или справочной capability Госключа. Причина приходит из backend-реестра; изменение frontend не делает контракт проверенным.

### Госключ submit возвращает 503

Backend запущен без CryptoPro CSP/`pycades`, сертификата или закрытого ключа. Preview при этом может работать, поскольку он не подписывает и не отправляет документы.

### Build завершён с warnings

Проверьте, что строка `The build folder is ready to be deployed` присутствует и exit code равен нулю. CRA/source-map/bundle warnings зафиксированы как migration debt; новые ошибки нельзя скрывать отключением CI.

См. также [`README.md`](./README.md), [`../docs/SERVICES.md`](../docs/SERVICES.md) и [`../api-gosuslugi-backend/README.md`](../api-gosuslugi-backend/README.md).
