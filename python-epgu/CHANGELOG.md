# Changelog

Все значимые изменения проекта документируются в этом файле.
Формат основан на [Keep a Changelog](https://keepachangelog.com/ru/1.0.0/),
проект следует [семантическому версионированию](https://semver.org/lang/ru/).

## [0.1.0] - 2026-06-28

### Добавлено
- Клиент `EpguClient` для API gusmev/nsi: `create_order`, `order_info`,
  `cancel_order`, `push`, `push_chunked`, `orders_status`, `updated_after`,
  `dictionary`, `download_file`.
- Аутентификация: `OrgTokenProvider` (ext-app по API-Key + ГОСТ-подпись) и
  `AasClient` (OAuth2 ЕСИА для граждан).
- Слой подписи за интерфейсом `Signer`: `CryptoProSigner` (КриптоПро/pycades) и
  `CallableSigner` (внешний механизм).
- `OrderArchive` - сборка ZIP-комплекта документов с отсоединёнными подписями.
- Сценарий «под ключ» `submit_application`.
- Преднастроенные контуры `TEST` / `PROD`, типизированные модели, тесты, примеры.
