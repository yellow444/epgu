# Как участвовать в проекте

Спасибо за интерес к открытым инструментам интеграции с API Госуслуг (ЕПГУ).
Исправления кода, документации и руководств принимаются через issue и pull
request в репозитории [yellow444/epgu](https://github.com/yellow444/epgu).

Участвуя в проекте, вы соглашаетесь соблюдать
[правила поведения](./CODE_OF_CONDUCT.md). Об уязвимостях не пишите в публичные
issue: порядок описан в [политике безопасности](./SECURITY.md).

## Что входит в публичный репозиторий

Исходники, документация и инструменты лежат в каталоге [`project/`](../project/).
Команды ниже выполняются из него, если не сказано иное.

| Компонент | Каталог | Что проверять |
|---|---|---|
| FastAPI-шлюз | [`project/api-gosuslugi-backend/`](../project/api-gosuslugi-backend/) | `pytest` |
| React-интерфейс | [`project/api-gosuslugi-client/`](../project/api-gosuslugi-client/) | `npm test`, `npm run lint`, сборка |
| Python SDK `epgu-api` | [`project/python-epgu/`](../project/python-epgu/) | `pytest`, `ruff`, сборка пакета |
| Общая база знаний и карточка TEST | [`project/knowledge/`](../project/knowledge/) | `pytest`, схемы, связность ссылок, `sync_ui_copy --check` |
| MCP-сервер | [`project/mcp-server/`](../project/mcp-server/) | `pytest`, stdio на mocks, снимок возможностей |
| Документы и контракты | [`project/docs/`](../project/docs/), [`project/docs/api_for_gu/`](../project/docs/api_for_gu/) | ссылки, сверка с официальными источниками |
| Служебные скрипты | [`project/scripts/`](../project/scripts/) | режим `--check` |

Публичная версия собирается и работает без закрытых расширений. Закрытые
дополнения, их установка и автоматизация не входят в этот репозиторий, и
запросы по ним здесь не рассматриваются. Граница описана в
[`project/epgu/PUBLIC_PRIVATE_REPOSITORIES.md`](../project/epgu/PUBLIC_PRIVATE_REPOSITORIES.md).

## Подготовка рабочей копии

```bash
git clone https://github.com/yellow444/epgu.git
cd epgu/project
```

Дальше следуйте разделу «Быстрый старт» [корневого README](../readme.md) и
[инструкции запуска](../project/docs/HOWTO.md). Для frontend нужен Node.js 24
и `npm ci`. Проприетарные КриптоПро CSP и `pycades` в публичную установку не
входят: без них операции подписи возвращают `503`, а остальная часть проекта
работает.

## Перед тем как начать

1. Поищите похожий [issue](https://github.com/yellow444/epgu/issues). Если его
   нет, откройте новый через подходящую форму и опишите задачу до большой
   правки.
2. Небольшие исправления опечаток и ссылок можно присылать сразу pull request.
3. Изменения контрактов ЕПГУ сверяйте с
   [официальным каталогом API Госуслуг](https://partners.gosuslugi.ru/catalog/api_for_gu)
   и указывайте в описании документ и его версию. Наличие услуги в каталоге
   ещё не означает, что её можно включить в отправку.

## Данные, которые нельзя добавлять

В коммиты, issue, логи и скриншоты не должны попадать:

- API-ключи, токены ЕСИА, cookie и содержимое `.env`;
- PIN-коды, контейнеры закрытых ключей (`*.000` и подобные), личные сертификаты;
- паспортные данные, СНИЛС, ИНН физических лиц и другие персональные данные;
- реальные заявления, ответы ЕПГУ с данными заявителей и рабочие XML.

Для примеров используйте обезличенные или синтетические значения. Публичные
сертификаты CA хранятся в `api-gosuslugi-backend/certs/public/`, личные файлы
только в игнорируемом `certs/personal/`.

## Проверки

Запускайте проверки того компонента, который меняете. Полный список команд
приведён в разделе «Проверка» [корневого README](../readme.md).

Backend:

```bash
cd api-gosuslugi-backend
python -m pip install -r requirements-test.txt
python -m pytest -q
```

Frontend:

```bash
cd api-gosuslugi-client
npm ci
CI=true npm test -- --watchAll=false --runInBand
npm run lint
```

Python SDK:

```bash
cd python-epgu
python -m pip install -e ".[dev]"
python -m pytest
python -m ruff check .
```

Каталог официальных документов и структурный аудит:

```bash
python scripts/sync_api_for_gu_docs.py --check
python scripts/extract_api_for_gu_assets.py --check
python scripts/audit_repository.py --check
```

На чистом клоне эти команды не самодостаточны. Официальные DOCX/PDF и
извлечённые из них XML/XSD с `extracted/inventory.json` не хранятся в Git, и
без них проверки извлечения и аудита завершаются ошибкой. Сначала подготовьте
локальный снимок: скачайте документы и выполните извлечение без `--check`, как
описано в разделе «Обновление и проверка»
[`project/docs/api_for_gu/README.md`](../project/docs/api_for_gu/README.md#обновление-и-проверка).

Для правки только текста достаточно проверить ссылки и пути, которые вы
изменили. Тесты, требующие КриптоПро, в публичной установке пропускаются; это
ожидаемо. Живые вызовы ЕПГУ и ЕСИА в проверки не входят: проект не
предоставляет доступа к тестовому или промышленному контуру Госуслуг.

База знаний (из `project/`):

```bash
cd knowledge
python -m pip install -e ".[test]"
python -m pytest
node tools/sync_ui_copy.mjs --check
```

Полный набор MCP-проверок, включая HTTP-адаптер на mocks (из `project/`):

```bash
cd mcp-server
python -m pip install -r ../api-gosuslugi-backend/requirements-test.txt -e ".[test,operations]"
python -m pytest
python tools/export_capabilities.py --check
```

Публичные тексты, ссылки и правила карточки меняются в каноническом пакете
`knowledge`; встроенные JSON-копии обновляются через `sync_ui_copy.mjs`.
Отметки человека не объявляются проверкой системы. Изменяя правило, проверьте
сценарии с неизвестными и противоречивыми сведениями. Добавляя новый источник,
укажите его статус и дату сверки; ссылка на документ не подтверждает каждое
предложение в подсказке. Ограничения публичного среза описаны в
[заметке релиза](../project/epgu/PUBLIC_RELEASE_2026-11-07.md).

## Pull request

- Одна логическая правка на pull request.
- В описании укажите проблему, результат и выполненные проверки (шаблон
  подставится автоматически).
- Если меняется контракт, профиль услуги или руководство, отметьте это и
  обновите соответствующий документ в `project/docs/`.
- Не меняйте лицензионные файлы в рамках обычной правки.

## Лицензия вкладов

Проект распространяется по [AGPL-3.0-or-later](../LICENSE). Для Python-пакета
также действуют отдельные
[коммерческие условия](../project/python-epgu/COMMERCIAL-LICENSE.md). Присылая
pull request, вы соглашаетесь, что ваш вклад распространяется на условиях
лицензии проекта. Небольшие исправления в `project/python-epgu/` можно
присылать сразу. Существенные изменения SDK и вопросы совместимости вклада с
двойным лицензированием пакета лучше заранее обсудить с maintainer в issue.

## Вопросы

Куда писать с вопросами, описано в [SUPPORT.md](./SUPPORT.md).
