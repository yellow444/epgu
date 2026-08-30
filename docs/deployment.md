# Развёртывание на хосте

Публичный репозиторий содержит исходники, но не готовую контейнеризацию.
Операционные процессы запускаются непосредственно в Python 3.12, frontend
собирается Node.js 24 и публикуется статическим веб-сервером.

## Backend

```powershell
cd api-gosuslugi-backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m uvicorn app:app --host 127.0.0.1 --port 55000
```

Readiness проверяется через `GET /version`. `/hc` и `/status` относятся к
CryptoPro и без лицензированных CSP/`pycades` ожидаемо возвращают `503`.

Основной backend оставляйте на loopback. Он хранит токен и выбранный сертификат
в process-global состоянии и рассчитан на одного доверенного оператора.

## Frontend

```powershell
cd api-gosuslugi-client
npm ci
$env:REACT_APP_BACKEND_URL='https://api.example.test'
npm run build
```

Публикуйте `build/` обычным статическим веб-сервером. Требования:

- SPA fallback на `index.html`;
- TLS;
- security headers и запрет directory listing;
- точный origin frontend в `ALLOWED_ORIGINS` backend;
- недоступность основного backend из Интернета без отдельной аутентификации.

## Входящая точка ИС

Для URL системы и push-сообщений запускайте отдельный процесс с минимальными
правами и отдельным каталогом журнала:

```powershell
cd api-gosuslugi-backend
$env:IS_MNEMONIC='TESTEP'
$env:INBOUND_PUBLIC_URL='https://example.test/is'
$env:INBOUND_MAX_BODY='1048576'
python -m uvicorn inbound:app --host 127.0.0.1 --port 58080 `
  --no-server-header --timeout-keep-alive 15 --limit-concurrency 64
```

Наружу публикуется только этот процесс через TLS reverse proxy. Основной API,
сертификаты и маркер доступа ему не передаются.

## Исходящая выдача сохранённых уведомлений

```powershell
cd api-gosuslugi-backend
$env:OUTBOUND_TOKEN='REPLACE_WITH_RANDOM_SECRET'
$env:OUTBOUND_ALLOW_NETS='10.0.0.0/24'
$env:GEPS_STORE_DIR='D:\epgu-data\geps'
python -m uvicorn outbound:app --host 127.0.0.1 --port 58081 `
  --no-server-header --timeout-keep-alive 15 --limit-concurrency 64
```

Процессу нужен только read-only доступ к уже сохранённым уведомлениям. Он не
должен получать сертификаты, API-Key и возможность обращаться к ЕПГУ.

## Службы ОС

В production оформите каждый процесс как отдельную службу операционной системы
(например, systemd на Linux или Windows Service через выбранный администратором
service wrapper). Для каждой службы задайте:

- отдельного непривилегированного пользователя;
- рабочий каталог и venv;
- явный набор переменных окружения/secret provider;
- автоматический restart с ограничением частоты;
- ротацию журналов и права на каталоги данных;
- health monitoring по `/version` или `/health` соответствующего процесса.

## Обновление

1. Сделайте резервную копию `.env`, лицензий и каталогов данных вне Git.
2. Получите проверенную ревизию исходников.
3. Обновите зависимости в venv через `pip install -r requirements.txt`.
4. Выполните backend tests и `npm ci && npm run build`.
5. Атомарно замените статический `build/` и перезапустите службы.
6. Проверьте `/version`, `/health`, CORS и один безопасный preview.

## Checklist

- [ ] Секреты, сертификаты и ключевые контейнеры находятся вне Git.
- [ ] Основной backend слушает только loopback/закрытую сеть.
- [ ] Публичен только отдельный inbound через TLS proxy.
- [ ] У процессов разные права и каталоги данных.
- [ ] `ALLOWED_ORIGINS` содержит точный origin frontend.
- [ ] CSP/`pycades` установлены из законного источника.
- [ ] Перед обновлением пройдены tests и smoke-check endpoint-ов.
