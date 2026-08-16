# epgu-api

Неофициальный типизированный Python-клиент API ЕПГУ/ЕСИА для создания и
отправки заявлений, чтения статусов, справочников и файлов. Поддерживаются
организационный поток `ext-app` и гражданский OAuth2 Authorization Code.

Реализация сверена со «Спецификацией API ЕПГУ v1.14» от 29.01.2026 и с
[`ofstudio/go-api-epgu`](https://github.com/ofstudio/go-api-epgu). Актуальные
официальные документы публикуются в
[каталоге API для госуслуг](https://partners.gosuslugi.ru/catalog/api_for_gu).

> Для реальной работы нужны зарегистрированная информационная система,
> разрешённая услуга, API-Key и сертификат КЭП. XML, XSD, состав архива и способ
> отправки определяются приложением к спецификации конкретной услуги — пакет не
> подменяет эти документы универсальным шаблоном.

## Возможности

- `EpguClient`: `create_order`, `push`, автоматический `push_chunked`,
  `order_info`, `cancel_order`, `orders_status`, `updated_after`, `dictionary`,
  `download_file`.
- Модели v1.14: вложенный `order.id`, статусная страница `content[].status`,
  `count`/`totalCount`, typed-ответы НСИ и ссылки `terrabyte://`.
- `OrderArchive`: безопасная сборка ZIP с отсоединёнными `.sig`.
- `CryptoProSigner` через устанавливаемый отдельно `pycades` или
  `CallableSigner` для HSM/внешнего сервиса подписи.
- `validate_xml`: локальная XSD-валидация без DTD, внешних сущностей и сетевого
  доступа.
- `epgu.services.goskey`: типизированные профили четырёх услуг Госключа,
  безопасная генерация `req.xml`, обязательные `.sig` для каждого файла и
  адаптивный выбор `push`/`order + push_chunked`.
- Python 3.10–3.14, единственная обязательная зависимость — `httpx`.

## Установка

```console
python -m pip install epgu-api
```

Для XSD-валидации:

```console
python -m pip install "epgu-api[xml]"
```

`pycades` поставляется с КриптоПро CSP и не публикуется в PyPI. Без него
используйте `CallableSigner` или заранее полученный access token.

## Организация / информационная система

Секреты берутся из окружения; не храните API-Key, PIN и контейнер ключа в Git.

```python
import os

from epgu import EpguClient, OrderArchive, OrderMeta, TEST, validate_xml
from epgu.auth import OrgTokenProvider
from epgu.signature import CryptoProSigner

signer = CryptoProSigner(
    thumbprint=os.environ["EPGU_CERT_THUMBPRINT"],
    pin=os.environ.get("EPGU_KEY_PIN"),
)
auth = OrgTokenProvider(os.environ["EPGU_API_KEY"], signer, env=TEST)
meta = OrderMeta(
    region=os.environ["EPGU_REGION"],
    service_code=os.environ["EPGU_SERVICE_CODE"],
    target_code=os.environ["EPGU_TARGET_CODE"],
)

req_xml = open("req.xml", "rb").read()
req_xsd = open("req.xsd", "rb").read()
validate_xml(req_xml, req_xsd)

archive = OrderArchive(signer=signer)
archive.add_file("req.xml", req_xml)
archive.add_signed_file("piev_epgu.xml", open("piev_epgu.xml", "rb").read())

with EpguClient(auth, env=TEST) as client:
    order_id = client.create_order(meta)
    client.push_chunked(meta.to_payload(), archive.to_bytes(), order_id=order_id)
```

`push_chunked` делит архив по 5 000 000 байт. Для нескольких частей форма
содержит номера `chunk=0..n-1`, а файлы называются `piev_epgu.z001`,
`piev_epgu.z002` и так далее. Размер можно задать через `chunk_size`.

Одношаговый `push` самостоятельно создаёт заявление и возвращает JSON с
`orderId`; предварительный вызов `create_order` для него не нужен.

## Госключ

Три контракта проходят опубликованные XSD: `10000000374/УНЭП`, `60025907`
(УКЭП юридического лица/ИП) и `60080470` (сертификат Федерального
казначейства). `10000000374/УКЭП` и `60079416` доступны в реестре capability,
но намеренно завершаются `UnsupportedGoskeyContractError`: в официальных
документах отсутствует нужная XSD либо противоречат имена и кратность полей.

```python
from datetime import datetime, timedelta, timezone

from epgu.services import submit_goskey
from epgu.services.goskey import (
    GoskeyAttribute,
    IndividualRecipient,
    IndividualSignRequest,
    SigningVariant,
)

moscow = timezone(timedelta(hours=3))
deadline = datetime.now(moscow) + timedelta(hours=1)
request = IndividualSignRequest(
    variant=SigningVariant.UNEP,
    recipient=IndividualRecipient(snils="000-729-729 38"),
    sign_expiration=deadline,
    description="Документы на подпись",
    attributes=(
        GoskeyAttribute("orgName", "ООО Ромашка"),
        GoskeyAttribute("orgINN", "6950199530"),
    ),
)

# client — настроенный EpguClient, signer — реализация detached CAdES-подписи.
result = submit_goskey(
    client,
    region="36",
    request=request,
    documents={"document.pdf": pdf_bytes},
    signer=signer,
)
print(result.order_id, result.transport)
```

`submit_goskey` непосредственно перед отправкой проверяет временное окно
(будущее, Москва +03:00, не более 24 часов), переиспользует общий
`OrderArchive`, подписывает `req.xml` вместе с каждым бизнес-документом и сам
выбирает прямой `push` либо `order + push/chunked`. Низкоуровневые функции
`build_signed_archive`, `select_transport` и `validate_submission_window`
также остаются публичными. Структурный `ManifestReport`
проверяет пары файлов, имена, расширения и лимиты, но не выдаёт себя за
криптографическую проверку CAdES/цепочки сертификата.

## Гражданин / OAuth2 ЕСИА

Сохраните выданный `state` в серверной сессии и сравните его с callback. Метод
`exchange_callback` проверяет адрес возврата, единственность параметров,
OAuth-ошибку и одноразовость `state`.

```python
import os

from epgu import TEST
from epgu.auth import AasClient
from epgu.signature import CryptoProSigner

aas = AasClient(
    os.environ["ESIA_CLIENT_ID"],
    CryptoProSigner(
        thumbprint=os.environ["EPGU_CERT_THUMBPRINT"],
        pin=os.environ.get("EPGU_KEY_PIN"),
    ),
    env=TEST,
    redirect_uri="https://app.example/esia/callback",
)

authorization_url, state = aas.authorization_url()
# Сохраните state в серверной сессии, затем перенаправьте пользователя.

# В обработчике callback_url — полный URL текущего запроса, а expected_state
# загружен из серверной сессии, не из query-параметра.
token = aas.exchange_callback(callback_url, expected_state=expected_state)
```

Если callback обрабатывается тем же экземпляром `AasClient`, он умеет сверить
`state` со своим одноразовым in-memory хранилищем и без `expected_state`.
Многопроцессному приложению нужно внешнее серверное хранилище.

## Контракты ответов

```python
order = client.order_info(order_id)
print(order.order_id, order.status_code, order.status_history_id)

page = client.orders_status([order_id], page_num=0, page_size=50)
print(page.count, page.total_count, page[0].search_status)

result = client.dictionary("DICTIONARY_CODE", tree_filtering="ONELEVEL")
print(result.total, result[0].value)

attachment = order.file("result.xml")
if attachment is not None:
    body = client.download_file(
        attachment.link,
        status_history_id=order.status_history_id,
        eservice_code=meta.service_code,
    )
```

HTTP-ошибки доступны как `HttpError`, прикладные JSON-ошибки с `code` — как
`ApiError`. Ошибка НСИ в HTTP 200 также преобразуется в `ApiError`.

## Контуры

| Имя | ЕСИА | ЕПГУ |
| --- | --- | --- |
| `TEST` | `esia-portal1.test.gosuslugi.ru` | `svcdev-gostapi.test.gosuslugi.ru` |
| `PROD` | `esia.gosuslugi.ru` | `www.gosuslugi.ru` |
| `TEST_BETA` | `esia-portal1.test.gosuslugi.ru` | устаревающий `svcdev-beta.test.gosuslugi.ru` |

Свой контур задаётся через `Env(esia="https://...", epgu="https://...")`.

## Разработка и выпуск

```console
cd python-epgu
python -m pip install -e ".[dev]"
python -m ruff check .
python -m ruff format --check .
python -m mypy src/epgu
python -m pytest --cov=epgu
python -m build
python -m twine check dist/*
python -m pip_audit --local --skip-editable
```

CI выполняет lint, тесты на Python 3.10–3.14, coverage gate, сборку wheel/sdist,
`twine check`, проверку установки wheel и аудит зависимостей. Перед выпуском
обновите версию одновременно в `pyproject.toml` и `epgu.__version__`, а также
`CHANGELOG.md`. Публикацию выполняйте через PyPI Trusted Publishing; токен PyPI
в репозиторий не добавляется.

Для автоматической публикации настройте Trusted Publisher проекта `epgu-api` в
PyPI: owner `yellow444`, repository `epgu`, workflow `python-publish.yml`,
environment `pypi`. После прохождения CI создайте GitHub Release с тегом,
совпадающим с версией (например, `v0.2.0`). Release-workflow собирает артефакты
в job без OIDC-доступа, проверяет их и только затем передаёт отдельному
publish-job с `id-token: write`; GitHub Actions закреплены полными commit SHA.

## Лицензия

По умолчанию действует AGPL-3.0-or-later, полный текст — в `LICENSE`.
Альтернативные коммерческие условия описаны в `COMMERCIAL-LICENSE.md`.
Атрибуция вдохновившего Go-проекта приведена в `NOTICE`.
