# HOWTO - frontend (React + Ant Design)

## 1. Подготовка

Используйте Node.js 24 LTS. Точное дерево зависимостей устанавливается из
`package-lock.json`:

```bash
node --version
npm ci
```

`npm ci` проверяет соответствие manifest/lockfile и воспроизводит
зафиксированные версии. `react-scripts` находится только в devDependencies.

## 2. Dev-сервер

Скопируйте `.env.development.example` в ignored-файл
`.env.development.local`. По умолчанию он задаёт:

```dotenv
PORT=53000
REACT_APP_BACKEND_URL=http://localhost:55000
```

Backend запустите с
`ALLOWED_ORIGINS=http://localhost:53000,http://127.0.0.1:53000`, затем:

```bash
npm start
```

Откройте <http://localhost:53000>.

## 3. Production-сборка

```bash
REACT_APP_BACKEND_URL=https://api.example.test npm run build
```

Каталог `build/` обслуживается обычным статическим веб-сервером. Для клиентских
маршрутов настройте SPA fallback на `index.html`. Адрес backend встраивается в
bundle при сборке, поэтому его изменение требует новой сборки.

## 4. Услуги и Госключ

При старте UI вызывает `GET /services`. Три проверенных профиля Госключа
доступны, остальные справочные профили показываются с причиной блокировки.
Frontend не должен включать услугу локальной правкой: backend повторно проверяет
`status=verified` и `available=true`.

Для профиля с `generator=goskey` порядок такой:

1. заполнить форму и документы;
2. вызвать `POST /goskey/preview` без подписи и отправки;
3. вызвать multipart `POST /goskey/submit` только на backend с
   лицензированными CSP/`pycades`, сертификатом и закрытым ключом.

Ответ `503` на submit в публичной core-установке ожидаем. Frontend не подписывает
документы и не хранит закрытый ключ.

## 5. Локальное состояние

- Токен ЕСИА хранится в `sessionStorage`.
- Файлы кешируются в IndexedDB, XML и ответы - в browser storage.
- После работы используйте «Удалить все локальные данные и сессию».
- Обход frontend-блокировки через DevTools не снимает backend-проверки.

## 6. Проверки

```bash
npm ci
npm audit --omit=dev --audit-level=high
CI=true npm test -- --watchAll=false --runInBand
npm run lint
CI=true npm run build
```

Не запускайте `npm audit fix --force`: legacy CRA build/dev-дерево требует
отдельной миграции, а не неконтролируемой замены lockfile.

## 7. Диагностика

| Симптом | Что проверить |
|---|---|
| 404 при запросе API | `REACT_APP_BACKEND_URL` в текущем bundle |
| CORS | точный адрес frontend в `ALLOWED_ORIGINS` backend |
| Профиль disabled | `unavailableReason` из backend-реестра |
| Госключ submit возвращает `503` | CSP, `pycades`, сертификат и закрытый ключ на backend |
| Build завершён с warnings | exit code и строку готовности каталога `build/` |

См. [`README.md`](./README.md), [`../docs/SERVICES.md`](../docs/SERVICES.md) и
[`../api-gosuslugi-backend/README.md`](../api-gosuslugi-backend/README.md).
