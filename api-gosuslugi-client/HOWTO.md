# HOWTO — frontend (React + Ant Design)

## Локальный запуск

```bash
npm install
# dev-сервер webpack
npm start
```

По умолчанию фронт ожидает backend на `/api`. Для локального dev можно задать:

```env
# .env.development.local
REACT_APP_BACKEND_URL=http://localhost:5000
```

## Запуск в Docker

Из корня репозитория:

```bash
docker-compose up -d --build frontend
```

Nginx слушает `:5080` и проксирует `/api` на backend. Конфиг — `default.conf.template`, подстановка переменных — в `entrypoint.sh`.

## Сборка production-бандла

```bash
npm run build
```

Артефакты — в `build/`. Webpack-конфиг — `webpack.config.js`.

## Структура

```
src/
├── App.js                  # корневой компонент, все табы
├── App.css / index.css     # стили
├── index.js                # bootstrap
├── components/
│   └── FileDropzone/       # drag&drop загрузка
└── logo.gosuslugi.svg
```

## Ключевые UX-сценарии

| Вкладка | Действия |
|---|---|
| Главная | Выбор сертификата, получение токена ЕСИА, сборка и подача заявления |
| XML-редактор | Открытие / редактирование / форматирование `piev_epgu.xml` |
| Запросы | Список заявлений, статусы, скачивание ответов |

Взаимодействие с backend — axios с baseURL из `REACT_APP_BACKEND_URL`. Загруженные файлы кешируются в IndexedDB (`files-db`).

## Частые задачи

### Добавить новую услугу в выпадающий список

Backend отдаёт справочник услуг по `GET /services` (из env `SERVICES`). Достаточно расширить переменную окружения — UI подхватит.

### Изменить тему / брендинг

Ant Design theme конфигурируется через `<ConfigProvider theme={...}>` в `App.js`. Логотип — `logo.gosuslugi.svg`.

### Отладка сетевых вызовов

DevTools → Network. Для локального dev без docker-compose — не забыть `REACT_APP_BACKEND_URL`, иначе CORS.

См. также [../docs/api.md](../docs/api.md), [../docs/sequence-diagrams.md](../docs/sequence-diagrams.md).
