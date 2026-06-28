# epgu-api

Python-клиент API Госуслуг (ЕПГУ и ЕСИА) для подачи заявлений, отслеживания их
статусов и работы с файлами. Подходит и организациям (банки, госорганы, любые
информационные системы), и сценариям от имени граждан.

Библиотека написана по мотивам go-api-epgu (ofstudio/go-api-epgu, язык Go), но
переработана под Python и расширена: кроме потока "организация по API-Key"
поддержан гражданский OAuth2-поток ЕСИА, а подпись и аутентификация вынесены за
отдельные интерфейсы.

Это неофициальная библиотека. Для работы нужен доступ к API ЕПГУ:
зарегистрированная информационная система, сертификат КЭП, API-Key. Подробности
смотрите в документации техпортала ЕСИА и ЕПГУ.

## Возможности

Два сценария авторизации:

- OrgTokenProvider: маркер ext-app по API-Key и ГОСТ-подписи (организации и ИС).
- AasClient: OAuth2 Authorization Code ЕСИА (от имени гражданина).

Подпись за интерфейсом:

- CryptoProSigner на базе КриптоПро CSP и pycades.
- CallableSigner для любого внешнего механизма подписи.
- КриптоПро не является обязательной зависимостью пакета.

Полный жизненный цикл заявления: create_order, push и push_chunked, order_info,
cancel_order, orders_status, updated_after, dictionary, download_file.

Сборка комплекта документов: OrderArchive собирает ZIP и кладёт рядом
отсоединённые подписи в файлах с расширением .sig.

Сценарий "под ключ": функция submit_application.

Готовые адреса тестового и боевого контуров (TEST и PROD).

Типизированные модели на dataclasses, тесты, минимум обязательных зависимостей
(только httpx).

## Установка

    pip install epgu-api

Дополнительно, если нужна проверка XML по XSD:

    pip install "epgu-api[xml]"

Модуль pycades ставится из дистрибутива КриптоПро, а не из PyPI. Без него
библиотека работает: используйте CallableSigner или заранее полученный маркер.

## Быстрый старт для организации

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

## Быстрый старт для гражданина (OAuth2 ЕСИА)

    from epgu import EpguClient, TEST
    from epgu.auth import AasClient
    from epgu.signature import CryptoProSigner

    aas = AasClient("MNEMONIC_ИС", CryptoProSigner(pin="..."), env=TEST,
                    redirect_uri="https://app.example/callback",
                    scope="openid fullname")

    url, state = aas.authorization_url()      # отправить гражданина по ссылке
    # после возврата на redirect_uri получаем параметр code
    token = aas.exchange_code(code, state=state)

    with EpguClient(token.access_token, env=TEST) as epgu:
        statuses = epgu.updated_after("2024-01-01T00:00:00.000+0300")

Для гражданского потока всё равно нужна зарегистрированная ИС с КЭП: ЕСИА требует
подписанные запросы авторизации. Гражданин работает через приложение или ИС,
которая действует от его имени с его согласия.

## Свой механизм подписи

Если КриптоПро используется через отдельный сервис, контейнер или утилиту
командной строки:

    from epgu.signature import CallableSigner

    def sign(data: bytes) -> bytes:
        # вернуть DER-байты отсоединённой CMS-подписи
        return my_external_signer(data)

    signer = CallableSigner(sign)

## Структура пакета

- client.py: EpguClient, методы gusmev и nsi.
- models.py: OrderMeta, Order, OrderFile, OrderStatus.
- archive.py: OrderArchive, сборка ZIP и подписей.
- const.py: TEST, PROD, TSA, User-Agent.
- errors.py: иерархия исключений.
- auth: OrgTokenProvider, AasClient, Token, TokenProvider.
- signature: Signer, CryptoProSigner, CallableSigner.
- services: submit_application, сценарий "под ключ".

## Контуры

Тестовый контур TEST:

- ЕСИА: esia-portal1.test.gosuslugi.ru
- ЕПГУ: svcdev-beta.test.gosuslugi.ru

Боевой контур PROD:

- ЕСИА: esia.gosuslugi.ru
- ЕПГУ: api.gosuslugi.ru

Можно задать свой контур: Env(esia="https://...", epgu="https://...").

## Разработка

    pip install -e ".[dev]"
    pytest
    ruff check .

## Публикация в PyPI

    python -m build
    twine check dist/*
    twine upload dist/*

Для публикации в тестовый PyPI:

    twine upload --repository testpypi dist/*

Перед публикацией поднимите версию в pyproject.toml и в src/epgu/__init__.py
(переменная __version__) и обновите CHANGELOG.md.

## Лицензия

MIT, файл LICENSE.
