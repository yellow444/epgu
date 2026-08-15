# epgu-api

Python-клиент API Госуслуг (**ЕПГУ / ЕСИА**) для подачи заявлений, отслеживания
статусов и работы с файлами. Подходит как **организациям** (банки, госорганы,
любые информационные системы), так и сценариям от имени **граждан**.

Библиотека вдохновлена [ofstudio/go-api-epgu](https://github.com/ofstudio/go-api-epgu)
(Go), но переосмыслена под Python и расширена: помимо потока «организация → API-Key»
поддержан гражданский OAuth2-поток ЕСИА, а подпись и аутентификация вынесены за
интерфейсы.

> ⚠️ Неофициальная библиотека. Для работы нужен доступ к API ЕПГУ (зарегистрированная
> информационная система, сертификат КЭП, API-Key). Подробности — в документации
> техпортала ЕСИА/ЕПГУ.

## Возможности

- 🔑 **Два сценария авторизации**
  - `OrgTokenProvider` — маркер `ext-app` по API-Key + ГОСТ-подписи (организации/ИС);
  - `AasClient` — OAuth2 Authorization Code ЕСИА (от имени гражданина).
- ✍️ **Подпись за интерфейсом** — `CryptoProSigner` (КриптоПро CSP + pycades) или
  `CallableSigner` (любой внешний механизм). КриптоПро не является обязательной
  зависимостью пакета.
- 📨 **Полный жизненный цикл заявления** — `create_order`, `push` / `push_chunked`,
  `order_info`, `cancel_order`, `orders_status`, `updated_after`, `dictionary`,
  `download_file`.
- 📦 **Сборка комплекта документов** — `OrderArchive` собирает ZIP и автоматически
  кладёт отсоединённые подписи `*.sig`.
- 🧩 **Сценарий «под ключ»** — `submit_application(...)`.
- 🌐 **Тестовый и боевой контуры** — преднастроенные `TEST` и `PROD`.
- 🧪 Типизировано (dataclasses), покрыто тестами, без обязательных тяжёлых зависимостей
  (только `httpx`).

## Установка

```bash
pip install epgu-api
```

Опциональные возможности:

```bash
pip install "epgu-api[xml]"   # валидация XML по XSD (lxml)
```

`pycades` (КриптоПро) ставится **из дистрибутива КриптоПро**, не из PyPI. Без него
библиотека работает — используйте `CallableSigner` или заранее полученный маркер.

## Быстрый старт — организация

```python
from epgu import EpguClient, OrderArchive, OrderMeta, TEST
from epgu.auth import OrgTokenProvider
from epgu.services import submit_application
from epgu.signature import CryptoProSigner

signer = CryptoProSigner(pin="1234567890")
auth = OrgTokenProvider(api_key="ВАШ_API_KEY", signer=signer, env=TEST)

meta = OrderMeta(region="45000000000",
                 service_code="10001449665",
                 target_code="-10001449665")

archive = OrderArchive(signer=signer)
archive.add_file("req.xml", b"<req>...</req>")
archive.add_signed_file("piev_epgu.xml", b"<piev>...</piev>")

with EpguClient(auth, env=TEST) as epgu:
    result = submit_application(epgu, meta, archive, wait=True)
    print(result.order_id, result.order and result.order.status_code)
```

## Быстрый старт — гражданин (OAuth2 ЕСИА)

```python
from epgu import EpguClient, TEST
from epgu.auth import AasClient
from epgu.signature import CryptoProSigner

aas = AasClient("MNEMONIC_ИС", CryptoProSigner(pin="..."), env=TEST,
                redirect_uri="https://app.example/callback", scope="openid fullname")

url, state = aas.authorization_url()      # отправить гражданина по ссылке
# ... после возврата на redirect_uri получаем ?code=...
token = aas.exchange_code(code, state=state)

with EpguClient(token.access_token, env=TEST) as epgu:
    statuses = epgu.updated_after("2024-01-01T00:00:00.000+0300")
```

> Для гражданского потока всё равно нужна зарегистрированная ИС с КЭП: ЕСИА требует
> подписанные запросы авторизации. «Простой гражданин» работает через приложение/ИС,
> действующую от его имени с его согласия.

## Свой механизм подписи

Если КриптоПро используется через отдельный сервис, контейнер или CLI:

```python
from epgu.signature import CallableSigner

def sign(data: bytes) -> bytes:        # вернуть DER-байты отсоединённой CMS-подписи
    return my_external_signer(data)

signer = CallableSigner(sign)
```

## Архитектура

```
epgu/
├── client.py            # EpguClient — методы gusmev/nsi
├── models.py            # OrderMeta, Order, OrderFile, OrderStatus
├── archive.py           # OrderArchive — ZIP + подписи
├── const.py             # TEST / PROD / TSA, User-Agent
├── errors.py            # иерархия исключений
├── auth/                # OrgTokenProvider, AasClient, Token, TokenProvider
├── signature/           # Signer, CryptoProSigner, CallableSigner
└── services/            # submit_application — сценарий «под ключ»
```

## Контуры

| Контур | ЕСИА | ЕПГУ |
| --- | --- | --- |
| `TEST` | esia-portal1.test.gosuslugi.ru | svcdev-beta.test.gosuslugi.ru |
| `PROD` | esia.gosuslugi.ru | api.gosuslugi.ru |

Можно задать свой: `Env(esia="https://...", epgu="https://...")`.

## Разработка

```bash
pip install -e ".[dev]"
pytest
ruff check .
```

## Публикация в PyPI

```bash
python -m build                 # соберёт dist/*.whl и dist/*.tar.gz
twine check dist/*
twine upload dist/*             # боевой PyPI
# или тестовый:
twine upload --repository testpypi dist/*
```

Перед публикацией поднимите версию в `pyproject.toml` и `src/epgu/__init__.py`
(`__version__`) и обновите `CHANGELOG.md`.

## Лицензия

[MIT](LICENSE) © Maksim Sitnikov
