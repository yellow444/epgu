# 03 - Конфигурация и известные грабли

## Справочник `.env` (корень репозитория)

| Переменная | Значение по умолчанию | Назначение |
| --- | --- | --- |
| `key_folder` | `./api-gosuslugi-backend/xxx.000` | Папка контейнера ключа КриптоПро (монтируется в `/var/opt/cprocsp/keys/root/xxx.000`) |
| `BACKEND_URL` | `http://192.168.50.100:5080/api` | Абсолютный URL API для React (**вшивается при сборке**) |
| `BACKEND_API` | `http://192.168.50.100:5000/api/` | Куда nginx проксирует `/api/` (runtime) |
| `apikey` | `GUID` | API-Key организации-потребителя |
| `TSAAddress` | `http://testca2012.cryptopro.ru/tsp/tsp.srf` | Сервис штампов времени |
| `esia_host` | `https://esia-portal1.test.gosuslugi.ru` | ЕСИА (test) |
| `svcdev_host` | `https://svcdev-beta.test.gosuslugi.ru` | ЕПГУ (test) |
| `KeyPin` | `1234567890` | PIN контейнера ключа |
| `production` | (пусто) | Флаг прод-режима |
| `SERVICES` | JSON | Карта услуг (см. ниже) |

Также есть `api-gosuslugi-backend/.env` (apikey/TSA/esia/svcdev/KeyPin) - он монтируется в `/app/.env`.

### `SERVICES`
JSON-словарь услуг. Рабочая - `10001449665`:
```
"region":"45000000000", "targetCode":"10001505301",
"eServiceCode":"60010153", "serviceTargetCode":"-60010153",
"req_file":"req.xml", "piev_epgu_file":"piev_epgu.xml"
```
`service2`/`service3` - заглушки (`xxx`).

---

## Известные грабли (и как чинить)

### 1. Папка ключей `xxx.000` не существует
`key_folder` по умолчанию указывает на `./api-gosuslugi-backend/xxx.000`, которой **нет**.
Реальные ключи лежат в **`./keys.000`** (header.key, masks.key, name.key, primary.key, ...).
**Фикс для локали:** в `.env` -> `key_folder=./keys.000`.
Без этого `csptest -enum_cont` не найдёт контейнер, установка КЭП и подпись работать не будут (но сам API стартует).

### 2. Захардкоженный IP `192.168.50.100`
В `.env` и дефолтах compose используется `192.168.50.100`, но IP этой машины другой
(на момент настройки - `192.168.50.215`). Из браузера хоста `192.168.50.100:5080` не откроется.
**Фикс для локали:**
- `BACKEND_URL=http://localhost:5080/api` (браузер -> nginx фронтенда, тот же origin)
- `BACKEND_API=http://api:5000/api/` (nginx -> бэкенд по DNS сервиса compose, надёжнее IP)

После смены `BACKEND_URL` - **пересобрать фронтенд** (`docker compose up -d --build frontend`).

### 3. `BACKEND_URL` должен быть АБСОЛЮТНЫМ
В `App.js` axios создаётся с `baseURL = BACKEND_URL`, но запросы пишутся как
`api.get(\`${BACKEND_URL}/path\`)`. При относительном `BACKEND_URL` (напр. `/api`) путь
задвоится (`/api/api/path`). Поэтому значение всегда абсолютное (`http://.../api`).

### 4. Сборка бэкенда тяжёлая
python:3.8 -> apt (build-essential, libboost-all-dev, gcc) -> КриптоПро CSP -> компиляция pycades.
Первая сборка идёт долго; держите кэш слоёв.

### 5. Клиентские файлы требуют CRLF
Новые файлы в `api-gosuslugi-client/` должны быть в **CRLF**, иначе сборка CRA падает. Dev-сервер - порт 3001.

### 6. `version:` в compose устарел
`docker-compose.yml` начинается с `version: "3.9"` -> warning. Можно удалить строку.

---

## Минимальный профиль для локального запуска

В корневом `.env`:
```
key_folder=./keys.000
BACKEND_URL=http://localhost:5080/api
BACKEND_API=http://api:5000/api/
```
Затем: `docker compose up -d --build`.
UI: http://localhost:5080 · API: http://localhost:5000 (`/status`, `/hc`).

> Это правки под **локальную** проверку. Исходные значения с `192.168.50.100` - для LAN-развёртывания; при коммите учитывайте, нужно ли их сохранять.
