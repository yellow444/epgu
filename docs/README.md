# Документация проекта

Полный набор технической и пользовательской документации.
**Дата последней актуализации против [Портала API Госуслуг](https://partners.gosuslugi.ru/catalog/api_for_gu): 2026-05-12.**

## Markdown-документация

| Файл | Описание |
|---|---|
| [CHANGELOG.md](./CHANGELOG.md) | **Журнал актуализации против портала партнёров** (2026-05-12 → ...) |
| [SERVICES.md](./SERVICES.md) | **Каталог услуг и спецификаций**: актуальные версии, ссылки на портал, среды, endpoint-ы |
| [architecture.md](./architecture.md) | Архитектура, компоненты, контейнеры, взаимодействие |
| [api.md](./api.md) | Справочник REST API бэкенда (все эндпоинты) |
| [schemas.md](./schemas.md) | XML/XSD-схемы, модели Pydantic, структура ответов ЕПГУ |
| [sequence-diagrams.md](./sequence-diagrams.md) | Диаграммы последовательностей (Mermaid) |
| [data-model.md](./data-model.md) | Таблицы сущностей и внутреннего состояния |
| [deployment.md](./deployment.md) | Развёртывание, docker-compose, переменные окружения |
| [security.md](./security.md) | Криптография, сертификаты, JWT, риски |
| [../.env.example](../.env.example) | Шаблон переменных окружения с пояснениями |

## Оригинальные регламенты ЕПГУ (docx/pdf)

Полный перечень с привязкой к актуальным источникам — в [SERVICES.md](./SERVICES.md).
Основные локальные файлы:

- `Reglament_podklyucheniya_k_API_Gosuslug_1_8.docx` — регламент подключения (локальная редакция v1.8; на портале публичная v1.4)
- `Specifikaciya_API_EPGU_v1_13.docx` — общая спецификация API (актуально на 2026-05)
- `Specifikaciya_API_EPGU_Podacha_zayavlenij_hodatajstv_obyasnenij_v1_3_kod_uslugi_10000000367_18_06_2024.docx` — услуга `10000000367`
- `Specifikaciya_API_EPGU_Prilozhenie_10000000367_Podacha_zayavleni_hodatajstv_obyasnenij_v1.3.docx` — приложение к ней
- `Specifikaciya_API_EPGU_Prilozhenie_60010153_Nalichie_IP_v8.docx` — услуга `60010153` (ФССП)
- `Specifikaciya_API_EPGU_Servisy_migracionnogo_i_registracionnogo_uchyotov_dlya_gostinic_v1.3.docx` — гостиницы
- `Specifikaciya_API_EPGU_Uvedomlenie_o_trudovoj_deyatelnosti_1.2.docx` — трудовая деятельность
- `Specifikaciya_API_EPGU_Otpravka_dokumentov_na_podpis_v_Gosklyuch_v1.8.docx` — Госключ
- `Rukovodstvo_polzovatelya_dlya_organizacii-potrebitelya_..._Versiya_3.3_...docx` — получение API-Key (потребитель)
- `Rukovodstvo_polzovatelya_dlya_organizacii-vendora_..._Versiya_3.2_...pdf` — получение API-Key (вендор)
- `metodicheskierekomendatsiipoispolzovaniyuesiav348.docx` — методрекомендации ЕСИА (v3.48)
- `rp-esia-tehportal-1328.pdf` — руководство по технологическому порталу ЕСИА

## Документы, доступные на портале, но не загруженные локально

> Добавляются по мере необходимости в соответствующих сценариях. Ссылки актуальны на 2026-05-12.

- [Specifikaciya_API_EPGU_Predostavlenie_informacii_o_hode_IP_v_7.docx](https://gu-st.ru/content/partners/api_for_gu/Specifikaciya_API_EPGU_Predostavlenie_informacii_o_hode_IP_v_7.docx) — Ход ИП, v7
- [Specifikaciya_API_EPGU_Uvedomlenie_o_rastorzhenii_trudovogo_dogovora.docx](https://gu-st.ru/content/partners/api_for_gu/Specifikaciya_API_EPGU_Uvedomlenie_o_rastorzhenii_trudovogo_dogovora.docx) — расторжение трудового договора
- [Instrukciya_po_podklucheniyu_API_EPGU.pdf](https://gu-st.ru/content/partners/Instrukciya_po_podklucheniyu_API_EPGU.pdf) — общая инструкция подключения

## Пошаговые инструкции с иллюстрациями

См. [../step/](../step) — добавление ИС, установка сертификатов, скриншоты.

## Методические материалы ЕСИА / Цифрового профиля

| Документ | Источник |
|---|---|
| Методрекомендации REST API Цифрового профиля | <https://digital.gov.ru/ru/documents/7166/> |
| Методрекомендации по использованию ЕСИА | <https://digital.gov.ru/ru/documents/6186/> |
| Руководство пользователя ЕСИА | <https://digital.gov.ru/ru/documents/6182/> |
| Руководство пользователя технологического портала ЕСИА | <https://digital.gov.ru/ru/documents/6190/> |
