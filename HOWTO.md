# HOWTO - запуск на обычной системе

Публичная версия намеренно не содержит готовую контейнеризацию. Backend
запускается в Python 3.12, frontend - в Node.js 24. Для подписи отдельно
устанавливаются лицензированные КриптоПро CSP и совместимый `pycades`.

## 1. Требования

- Python 3.12;
- Node.js 24 LTS и npm;
- для реальной подписи - законно полученные CSP, `pycades`, сертификат и
  закрытый ключ;
- для тестового контура - выданные организации API-Key и полномочия ЕПГУ.

## 2. Конфигурация

Скопируйте `.env.example` в локальный файл, который не коммитится:

```powershell
Copy-Item .env.example .env.local
```

Реальные `apikey`, `KeyPin`, сертификаты и ключевые контейнеры храните вне Git.
Backend читает переменные процесса. В PowerShell безопаснее загрузить только
нужные значения в текущий терминал, например:

```powershell
$env:esia_host='https://esia-portal1.test.gosuslugi.ru'
$env:svcdev_host='https://svcdev-gostapi.test.gosuslugi.ru'
$env:ALLOWED_ORIGINS='http://localhost:3000,http://127.0.0.1:3000'
```

## 3. Backend

```powershell
cd api-gosuslugi-backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m uvicorn app:app --host 127.0.0.1 --port 55000
```

Проверка: <http://127.0.0.1:55000/version> и
<http://127.0.0.1:55000/docs>. `/hc` и `/status` без CSP/`pycades` ожидаемо
возвращают `503`, но `/version` должен отвечать `200`.

## 4. Frontend

Во втором терминале:

```powershell
cd api-gosuslugi-client
npm ci
$env:REACT_APP_BACKEND_URL='http://127.0.0.1:55000'
npm start
```

Откройте <http://localhost:3000>. Для production-сборки выполните
`npm run build` и обслуживайте каталог `build/` любым статическим веб-сервером.
Маршрутизацию SPA настройте на возврат `index.html`; адрес backend встраивается
в bundle при сборке через `REACT_APP_BACKEND_URL`.

## 5. Отдельные входящий и исходящий процессы

Если нужны зарегистрированные URL `/is` и `/push`, запустите отдельный процесс
из каталога backend:

```powershell
$env:IS_MNEMONIC='TESTEP'
$env:INBOUND_PUBLIC_URL='https://example.test/is'
python -m uvicorn inbound:app --host 127.0.0.1 --port 58080
```

Отдача уже полученных уведомлений внешней системе запускается отдельно:

```powershell
$env:OUTBOUND_TOKEN='REPLACE_WITH_RANDOM_SECRET'
$env:OUTBOUND_ALLOW_NETS='127.0.0.1/32'
python -m uvicorn outbound:app --host 127.0.0.1 --port 58081
```

Публичный TLS и reverse proxy настраиваются администратором системы. Не
выставляйте основной backend наружу: его токен и выбранный сертификат являются
process-global состоянием одного оператора.

## 6. Проверки

```powershell
cd api-gosuslugi-backend
python -m pip install -r requirements-test.txt
python -m pytest -c pytest.ini

cd ..\api-gosuslugi-client
npm ci
npm audit --omit=dev --audit-level=high
$env:CI='true'
npm test -- --watchAll=false --runInBand
npm run lint
npm run build
```

## 7. Диагностика

| Симптом | Что проверить |
|---|---|
| `/version` недоступен | Терминал backend, активное venv и порт 55000 |
| CORS в браузере | `ALLOWED_ORIGINS` должен содержать точный адрес frontend |
| `/hc` или `/status` возвращает `503` | Для подписи не установлен CSP/`pycades` |
| 401 от ЕСИА | Контур, срок API-Key, сертификат и полномочия; секреты не выводить в лог |
| Услуга видна, но disabled | Это справочный профиль; причина приходит из backend |
| `Invalid XML` | XML не соответствует XSD конкретной услуги |

Подробности: [backend](./api-gosuslugi-backend/HOWTO.md),
[frontend](./api-gosuslugi-client/HOWTO.md),
[развёртывание](./docs/deployment.md) и [безопасность](./docs/security.md).
