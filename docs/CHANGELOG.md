# Журнал актуализации

Только содержательные изменения, связанные с актуализацией под [Портал API Госуслуг](https://partners.gosuslugi.ru/catalog/api_for_gu). Технические правки (форматирование, опечатки, версии lockfile) сюда не попадают - для них смотрите `git log`.

## 2026-05-12 - сверка с порталом партнёров

### Документация
- `docs/SERVICES.md` - новый файл: каталог услуг, версии спецификаций, среды и endpoint-ы, прямые ссылки на актуальные DOCX/PDF на `gu-st.ru`.
- `docs/api.md` - ориентир на v1.13 спец. (правки v1.12.1 по ГОСТ TLS / СМЭВ4); добавлены `/version`, `/environments`, `/services/{code}`; раздел о СМЭВ4 / ПОДД с ссылкой на ЕСКС.
- `docs/security.md` - XXE / billion-laughs: рекомендация перенесена в исполняемый код (`resolve_entities=False, no_network=True`).
- `docs/deployment.md` - production-чеклист расширен: ГОСТ TLS + СМЭВ4, согласия пользователей, технологический портал ЕСИА для теста и прода.
- `docs/README.md`, `readme.md`, `HOWTO.md` - даты актуализации, ссылки на новый `SERVICES.md`, расширенный каталог сред.

### Код
- `api-gosuslugi-backend/config.py` - вынесены `DEFAULT_SERVICES`, `ENVIRONMENTS` (test/prod ЕСИА + ЕПГУ + tech-portal + согласия), `SPEC_VERSION="1.13"`, `SPEC_SOURCE`, хелперы `detect_environment` и `serialize_service`.
- `api-gosuslugi-backend/routers.py` - диагностический роутер: `/version`, `/environments`, `/services/{code}`.
- `api-gosuslugi-backend/app.py` - подключение `config.py` и роутеров; безопасный XML-парсер; `version="1.13"` и пояснение про источник в `description` FastAPI-приложения.
- `api-gosuslugi-backend/test_app.py` - тесты на новые эндпоинты, на отказ `/xml` для неизвестной услуги.

### Среды по умолчанию
| Среда | ESIA | EPGU |
|---|---|---|
| test | `https://esia-portal1.test.gosuslugi.ru` | `https://svcdev-beta.test.gosuslugi.ru` |
| prod | `https://esia.gosuslugi.ru` | `https://lk.gosuslugi.ru` (ГОСТ TLS) |

### Каталог услуг по умолчанию
- `60010153` - Наличие ИП (ФССП) - спец. v8
- `60010154` - Ход ИП (ФССП) - спец. v7
- `10000000367` - Подача заявлений/ходатайств/объяснений - спец. v1.3 от 18.06.2024
- `10000000109` - Доставка пенсии и социальных выплат ПФР/СФР

## 2026-05-12+ - расширения после сверки

- `.env.example` - задокументирован полный набор переменных, включая `ALLOWED_ORIGINS` для боевого CORS.
- `.gitignore` - добавлен; исключены каталоги IDE, личные сертификаты, кэши Python и сборка фронта.
- `docs/CHANGELOG.md` - этот журнал.
- Контекст из ЕСКС (info.gosuslugi.ru): подключение к API ЕПГУ возможно через прямой ГОСТ TLS, через СМЭВ4 (ПОДД) или через СВОКС. См. `docs/deployment.md#production-чеклист`.

## Источники
- [partners.gosuslugi.ru/catalog/api_for_gu](https://partners.gosuslugi.ru/catalog/api_for_gu) - каталог документов
- [gu-st.ru/content/partners/api_for_gu/](https://gu-st.ru/content/partners/api_for_gu/) - файлы спецификаций
- [Регламент подключения v1.4 (09.11.2022)](https://gu-st.ru/content/partners/api_for_gu/Reglament_podklyucheniya_k_API_Gosuslug._Versiya_1.4_ot_09.11.2022_g..pdf)
- [Инструкция по подключению](https://gu-st.ru/content/partners/Instrukciya_po_podklucheniyu_API_EPGU.pdf)
- [ЕСКС - настройки подключения услуги к API ЕПГУ](https://info.gosuslugi.ru/articles/%D0%9D%D0%B0%D1%81%D1%82%D1%80%D0%BE%D0%B9%D0%BA%D0%B8_%D0%BF%D0%BE%D0%B4%D0%BA%D0%BB%D1%8E%D1%87%D0%B5%D0%BD%D0%B8%D1%8F_%D1%83%D1%81%D0%BB%D1%83%D0%B3%D0%B8_%D0%BA_API_%D0%95%D0%9F%D0%93%D0%A3/)
- [ЕСКС - подключение к API ЕПГУ через СВОКС](https://info.gosuslugi.ru/articles/%D0%9F%D0%BE%D0%B4%D0%BA%D0%BB%D1%8E%D1%87%D0%B5%D0%BD%D0%B8%D0%B5_%D0%BA_API_%D0%95%D0%9F%D0%93%D0%A3_%D0%BF%D1%80%D0%B8_%D0%BF%D0%BE%D0%BC%D0%BE%D1%89%D0%B8_%D0%A1%D0%92%D0%9E%D0%9A%D0%A1/)
- [ofstudio/go-api-epgu](https://github.com/ofstudio/go-api-epgu) - референсный Go-клиент с адресами и услугами
