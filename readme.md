# API Госуслуг (ЕПГУ) - интеграционное решение

[![GitHub Stars](https://img.shields.io/github/stars/yellow444/epgu?style=flat&logo=github&label=Stars)](https://github.com/yellow444/epgu)
[![GitHub Forks](https://img.shields.io/github/forks/yellow444/epgu?style=flat&logo=github&label=Forks)](https://github.com/yellow444/epgu/forks)
[![Лицензия](https://img.shields.io/github/license/yellow444/epgu?style=flat)](./LICENSE)
[![Просмотры репозитория за 14 дней, датированный снимок GitHub Traffic](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fyellow444%2Fepgu%2Fmain%2Fproject%2Fdocs%2Fmetrics%2Fviews.json)](./project/docs/metrics/README.md)
[![Клонирования за 14 дней, датированный снимок GitHub Traffic](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fyellow444%2Fepgu%2Fmain%2Fproject%2Fdocs%2Fmetrics%2Fclones.json)](./project/docs/metrics/README.md)

Монорепозиторий для интеграции с API ЕПГУ/ГУСМЭВ: FastAPI-шлюз, React-интерфейс и отдельная Python-библиотека `epgu-api`.

**Бесплатная публичная часть:** гайд с кликабельными схемами по ЕПГУ, ЕСИА, СМЭВ,
подписи, MAX и цифровому рублю; ручная подготовка подключения и карточка TEST.
Они работают без входа и без сервера установки. Карточка разбирает ваши отметки,
не проверяя кабинет и не выдавая их за разрешение оператора. Те же знания и
расчёт доступны через HTTP API и MCP (Model Context Protocol).
[Как запустить и что действительно проверено](./project/epgu/PUBLIC_RELEASE_2026-11-07.md).

**Проект оказался полезен? Поставьте ⭐ [yellow444/epgu](https://github.com/yellow444/epgu)** — так вы поддержите развитие открытого инструментария для интеграции с Госуслугами. Нашли ошибку или недостающий сценарий? [Создайте issue](https://github.com/yellow444/epgu/issues), не прикладывая персональные данные, API-ключи, PIN-коды и закрытые ключи.

[Быстрый старт](#быстрый-старт) · [Инструкция запуска](./project/docs/HOWTO.md) · [Документация](./project/docs/README.md) · [Python SDK](./project/python-epgu/README.md) · [Postman](./project/docs/postman) · [О статистике](./project/docs/metrics/README.md)

> Контракты сверены 12 августа 2026 года с [официальным каталогом API Госуслуг](https://partners.gosuslugi.ru/catalog/api_for_gu). Базовый протокол реализуется по [спецификации API ЕПГУ v1.14 от 29.01.2026](https://gu-st.ru/content/partners/api_for_gu/Specifikaciya_API_EPGU_v1_14.docx). Наличие услуги в каталоге не означает, что её уже можно безопасно отправлять из этого проекта.

Исходники, документация и инструменты собраны в [`project/`](./project/). Для работы в редакторе и выполнения команд ниже открывайте этот каталог.

## Что входит

| Каталог | Назначение |
|---|---|
| [`api-gosuslugi-backend/`](./project/api-gosuslugi-backend) | FastAPI-шлюз: ЕСИА, методы ГУСМЭВ, сборка ZIP, валидация XML/XSD, автоматическая отправка частей |
| [`api-gosuslugi-client/`](./project/api-gosuslugi-client) | React-интерфейс; воспроизводимая локальная сборка использует Node.js 24 и `npm ci` |
| [`python-epgu/`](./project/python-epgu) | Публикуемая Python-библиотека `epgu-api`; CryptoPro подключается через отдельный адаптер |
| [`knowledge/`](./project/knowledge) | Общие данные, схемы, поиск, ручной маршрут и правила карточки подключения |
| [`mcp-server/`](./project/mcp-server) | MCP-сервер stdio; штатный профиль `knowledge` только читает знания и рассчитывает карточку |
| [`docs/api_for_gu/`](./project/docs/api_for_gu) | Manifest 28 официальных документов; локальная загрузка и извлечение XML/XSD по URL + SHA-256 |
| [`scripts/`](./project/scripts) | Синхронизация документов, извлечение контрактов, генерация реестра и структурный аудит |

## Фактический статус услуг

Backend использует версионируемый реестр [`service_profiles.json`](./project/api-gosuslugi-backend/service_profiles.json): 21 профиль описывает источник спецификации, режим отправки, имена документов, подпись, варианты и извлечённые официальные материалы.

- Пять профилей имеют статус `verified` и `available=true`: три сценария Госключа (УНЭП `10000000374`, УКЭП для юридических лиц/ИП `60025907`, УКЭП с сертификатом Федерального казначейства `60080470`) и два заявления ФССП (`60010153`, `10000000352`). Это статус локальной реализации и проверок, а не свидетельство приёмки в TEST/PROD.
- Остальные 16 профилей имеют статус `reference`: они видны в UI вместе с причиной блокировки, но backend запрещает получать их рабочий шаблон и отправлять заявление.
- Для ФССП есть типизированные формы, построитель XML, проверки полей/контрольных цифр, XSD и запрет демонстрационных значений. Приёмка этих двух сценариев в авторизованном контуре пока не подтверждена.
- Внутри `10000000374` проверена только возможность УНЭП; вариант УКЭП физического лица остаётся `reference`, потому что для опубликованного namespace отсутствует XSD. Расшифрование `60079416` также заблокировано из-за противоречий официальных источников.
- Каждый профиль задаёт собственные XML-имена, XSD/валидацию, режим `chunked` или `adaptive` и требования к отделённой CAdES-подписи. XML одной услуги не переиспользуется как шаблон другой.

Полная матрица приведена в [`docs/SERVICES.md`](./project/docs/SERVICES.md). Для перевода справочного профиля в `verified` нужны рабочий шаблон без тестовых персональных данных, XSD/golden-тесты и проверка в соответствующем контуре ЕПГУ.

## Контракт отправки

- `region` передаётся при каждом запросе как фактический код ОКАТО пользователя; это не статическая характеристика услуги.
- Для `chunked` backend сам собирает ZIP, делит его на части по 5 000 000 байт, нумерует поля `chunk` с нуля и файлы с `.z001`, затем последовательно отправляет все части.
- `adaptive` выбирает прямой `/push` для допустимого небольшого архива либо `/order` + `/push/chunked`; этот режим используют три верифицированных сценария Госключа и один заблокированный сценарий расшифрования.
- Служебный `submissionContext` используется только локально для согласованной подстановки `{orderId}`/`{guid}` и не пересылается в ЕПГУ.

## Быстрый старт

Не помещайте реальные API-ключи, PIN-коды, сертификаты или контейнеры закрытых ключей в Git.

```powershell
cd project
Copy-Item .env.example .env.local
cd api-gosuslugi-backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m uvicorn app:app --host 127.0.0.1 --port 55000
```

Во втором терминале, из корня репозитория:

```powershell
cd project/api-gosuslugi-client
npm ci
$env:HOST='127.0.0.1'
$env:REACT_APP_BACKEND_URL='http://127.0.0.1:55000'
npm start
```

- Frontend: <http://localhost:3000>
- Backend/OpenAPI: <http://localhost:55000/docs>

Оба процесса слушают loopback. Выбранный сертификат и токен ЕСИА хранятся в
глобальном состоянии backend, поэтому текущая конфигурация рассчитана на одного
доверенного оператора и не должна публиковаться в сеть как многопользовательский
сервис.

Публичная установка не содержит проприетарные дистрибутивы КриптоПро CSP и
`pycades`. Без них реестр и неподписывающие функции доступны, а операции подписи
и health-check CryptoPro возвращают `503`. Для реальной подписи нужен отдельно
лицензированный host-runtime с CSP, `pycades`, сертификатом и закрытым ключом.

## Проверка

```bash
python scripts/sync_api_for_gu_docs.py --check
python scripts/extract_api_for_gu_assets.py --check
python scripts/audit_repository.py --check

cd api-gosuslugi-backend
python -m pip install -r requirements-test.txt
python -m pytest -q

cd ../api-gosuslugi-client
npm ci
npm audit --omit=dev --audit-level=high
CI=true npm test -- --watchAll=false --runInBand
npm run lint
CI=true npm run build

cd ../python-epgu
python -m pip install -e ".[dev]"
python -m pytest
python -m ruff check .
python -m build
python -m twine check dist/*
```

Исторический срез от 12.08.2026: Python-пакет - 163 теста пройдено, backend -
35 пройдено и 5 CryptoPro-зависимых пропущено, frontend - 20 пройдено. Эти числа
и старый аудит зависимостей не описывают текущую версию. Состав новой публичной
части и границы проверки описаны в [заметке релиза](./project/epgu/PUBLIC_RELEASE_2026-11-07.md);
исходный структурный аудит сохранён в [`docs/AUDIT_2026-08-12.md`](./project/docs/AUDIT_2026-08-12.md).

## Источники и референсы

Авторитетный источник контрактов - [каталог партнёрского портала](https://partners.gosuslugi.ru/catalog/api_for_gu), локальные SHA-256 - в [`docs/api_for_gu/catalog.json`](./project/docs/api_for_gu/catalog.json). Проект [`ofstudio/go-api-epgu`](https://github.com/ofstudio/go-api-epgu) использован как поведенческий Go-референс, но не заменяет актуальные официальные документы и не подтверждает поддержку всех 21 услуг.

При проверке PyPI/GitHub точного Python-аналога для API ЕПГУ/ГУСМЭВ не найдено; одноимённый пакет [`gosuslugi-api`](https://pypi.org/project/gosuslugi-api/) относится к ГИС ЖКХ. Поэтому Python-реализация развивается в [`python-epgu/`](./project/python-epgu).

## Перед публичной публикацией

В текущем индексе `.env` не отслеживается, а `.env.example` содержит только
плейсхолдеры. Реальные ключи, сертификаты и поставки КриптоПро должны оставаться
вне Git. Перед публикацией любой ветки проверяйте её историю и чистый клон;
подробный список проверок приведён в [`docs/AUDIT_2026-08-12.md`](./project/docs/AUDIT_2026-08-12.md).

## Участие и поддержка

[Как внести вклад](./.github/CONTRIBUTING.md) · [Куда задать вопрос](./.github/SUPPORT.md) ·
[Правила поведения](./.github/CODE_OF_CONDUCT.md) · [Сообщить об уязвимости](./.github/SECURITY.md).
Для ошибок, предложений, документации и вопросов доступны отдельные
[формы issue](https://github.com/yellow444/epgu/issues/new/choose). Не публикуйте
в них секреты и персональные данные.

## Лицензия

Корневой проект распространяется по AGPL-3.0-or-later - см. [`LICENSE`](./LICENSE). У Python-пакета также есть отдельные [коммерческие условия](./project/python-epgu/COMMERCIAL-LICENSE.md).

## Поддержать проект

Дочитали и нашли полезное? Поддержите проект звездой:

[![Поддержать проект: перейти к кнопке Star на GitHub](https://img.shields.io/badge/Support-Star_on_GitHub-ffca28?style=for-the-badge&logo=github&logoColor=black)](https://github.com/yellow444/epgu#start-of-content)

Ссылка возвращает к верхней части репозитория: нажмите **Star** справа вверху. Сам бейдж не ставит звезду автоматически.
