# API Госуслуг (ЕПГУ) - интеграционное решение

Монорепозиторий для интеграции с API ЕПГУ/ГУСМЭВ: FastAPI-шлюз, React-интерфейс и отдельная Python-библиотека `epgu-api`.

> Контракты сверены 12 августа 2026 года с [официальным каталогом API Госуслуг](https://partners.gosuslugi.ru/catalog/api_for_gu). Базовый протокол реализуется по [спецификации API ЕПГУ v1.14 от 29.01.2026](https://gu-st.ru/content/partners/api_for_gu/Specifikaciya_API_EPGU_v1_14.docx). Наличие услуги в каталоге не означает, что её уже можно безопасно отправлять из этого проекта.

## Что входит

| Каталог | Назначение |
|---|---|
| [`api-gosuslugi-backend/`](./api-gosuslugi-backend/) | FastAPI-шлюз: ЕСИА, методы ГУСМЭВ, сборка ZIP, валидация XML/XSD, автоматическая отправка частей |
| [`api-gosuslugi-client/`](./api-gosuslugi-client/) | React-интерфейс; воспроизводимая локальная сборка использует Node.js 24 и `npm ci` |
| [`python-epgu/`](./python-epgu/) | Публикуемая Python-библиотека `epgu-api`; CryptoPro подключается через отдельный адаптер |
| [`docs/api_for_gu/`](./docs/api_for_gu/) | Manifest 28 официальных документов; локальная загрузка и извлечение XML/XSD по URL + SHA-256 |
| [`scripts/`](./scripts/) | Синхронизация документов, извлечение контрактов, генерация реестра и структурный аудит |

## Фактический статус услуг

Backend использует версионируемый реестр [`service_profiles.json`](./api-gosuslugi-backend/service_profiles.json): 21 профиль описывает источник спецификации, режим отправки, имена документов, подпись, варианты и извлечённые официальные материалы.

- Три профиля Госключа имеют статус `verified` и `available=true`: УНЭП `10000000374`, УКЭП для юридических лиц/ИП `60025907` и УКЭП с сертификатом Федерального казначейства `60080470`.
- Остальные 18 профилей имеют статус `reference`: они видны в UI вместе с причиной блокировки, но backend запрещает получать их рабочий шаблон и отправлять заявление.
- Для ФССП `60010153` схема и транспорт каталогизированы, однако имеющийся XML является только демонстрационным. До включения нужны типизированная форма, fail-closed проверка placeholder/полей и приёмка в авторизованном контуре.
- Внутри `10000000374` проверена только возможность УНЭП; вариант УКЭП физического лица остаётся `reference`, потому что для опубликованного namespace отсутствует XSD. Расшифрование `60079416` также заблокировано из-за противоречий официальных источников.
- Каждый профиль задаёт собственные XML-имена, XSD/валидацию, режим `chunked` или `adaptive` и требования к отделённой CAdES-подписи. XML одной услуги не переиспользуется как шаблон другой.

Полная матрица приведена в [`docs/SERVICES.md`](./docs/SERVICES.md). Для перевода справочного профиля в `verified` нужны рабочий шаблон без тестовых персональных данных, XSD/golden-тесты и проверка в соответствующем контуре ЕПГУ.

## Контракт отправки

- `region` передаётся при каждом запросе как фактический код ОКАТО пользователя; это не статическая характеристика услуги.
- Для `chunked` backend сам собирает ZIP, делит его на части по 5 000 000 байт, нумерует поля `chunk` с нуля и файлы с `.z001`, затем последовательно отправляет все части.
- `adaptive` выбирает прямой `/push` для допустимого небольшого архива либо `/order` + `/push/chunked`; этот режим используют три верифицированных сценария Госключа и один заблокированный сценарий расшифрования.
- Служебный `submissionContext` используется только локально для согласованной подстановки `{orderId}`/`{guid}` и не пересылается в ЕПГУ.

## Быстрый старт

Не помещайте реальные API-ключи, PIN-коды, сертификаты или контейнеры закрытых ключей в Git.

```powershell
Copy-Item .env.example .env.local
cd api-gosuslugi-backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m uvicorn app:app --host 127.0.0.1 --port 55000
```

Во втором терминале:

```powershell
cd api-gosuslugi-client
npm ci
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

Зафиксированный срез проверки: Python-пакет - 163 теста пройдено; backend - 35 тестов пройдено и 5 CryptoPro-зависимых пропущено; frontend - 20 тестов пройдено, lint и production build успешны. Production-аудит frontend (`--omit=dev`) не находит уязвимостей; 57 advisories остаются только в legacy CRA build/dev-дереве и требуют отдельной миграции. Итоги и ограничения структурного анализа находятся в [`docs/AUDIT_2026-08-12.md`](./docs/AUDIT_2026-08-12.md).

## Источники и референсы

Авторитетный источник контрактов - [каталог партнёрского портала](https://partners.gosuslugi.ru/catalog/api_for_gu), локальные SHA-256 - в [`docs/api_for_gu/catalog.json`](./docs/api_for_gu/catalog.json). Проект [`ofstudio/go-api-epgu`](https://github.com/ofstudio/go-api-epgu) использован как поведенческий Go-референс, но не заменяет актуальные официальные документы и не подтверждает поддержку всех 21 услуг.

При проверке PyPI/GitHub точного Python-аналога для API ЕПГУ/ГУСМЭВ не найдено; одноимённый пакет [`gosuslugi-api`](https://pypi.org/project/gosuslugi-api/) относится к ГИС ЖКХ. Поэтому Python-реализация развивается в [`python-epgu/`](./python-epgu/).

## Перед публичной публикацией

В текущем индексе `.env` не отслеживается, а `.env.example` содержит только
плейсхолдеры. Реальные ключи, сертификаты и поставки КриптоПро должны оставаться
вне Git. Перед публикацией любой ветки проверяйте её историю и чистый клон;
подробный список проверок приведён в [`docs/AUDIT_2026-08-12.md`](./docs/AUDIT_2026-08-12.md).

## Лицензия

Корневой проект распространяется по AGPL-3.0-or-later - см. [`LICENSE`](./LICENSE). У Python-пакета также есть отдельные [коммерческие условия](./python-epgu/COMMERCIAL-LICENSE.md).
