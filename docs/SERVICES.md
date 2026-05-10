# Каталог услуг и спецификаций API ЕПГУ

> Актуализировано: **2026-05-12**.
> Источник истины: [Портал API Госуслуг — раздел «API»](https://partners.gosuslugi.ru/catalog/api_for_gu).
> Файлы спецификаций физически хранятся на `https://gu-st.ru/content/partners/api_for_gu/`.

## 1. Базовые документы

| Документ | Версия (на портале) | Локальная копия | Ссылка |
|---|---|---|---|
| Спецификация API ЕПГУ (основная) | v1.13 (правки v1.12.1 для разделов GOST TLS / СМЭВ4) | `docs/Specifikaciya_API_EPGU_v1_13.docx` | [Specifikaciya_API_EPGU_v1_13.docx](https://gu-st.ru/content/partners/api_for_gu/Specifikaciya_API_EPGU_v1_13.docx) |
| Регламент подключения к API Госуслуг | v1.4 (09.11.2022) — публичный, v1.8 — локальная редакция | `docs/Reglament_podklyucheniya_k_API_Gosuslug_1_8.docx` | [Reglament_podklyucheniya_k_API_Gosuslug._Versiya_1.4_ot_09.11.2022_g..pdf](https://gu-st.ru/content/partners/api_for_gu/Reglament_podklyucheniya_k_API_Gosuslug._Versiya_1.4_ot_09.11.2022_g..pdf) |
| Инструкция по подключению к API ЕПГУ | актуальная | — | [Instrukciya_po_podklucheniyu_API_EPGU.pdf](https://gu-st.ru/content/partners/Instrukciya_po_podklucheniyu_API_EPGU.pdf) |

## 2. Спецификации отдельных услуг

| Услуга | Код | Версия | Локальная копия | Источник |
|---|---|---|---|---|
| Подача заявлений / ходатайств / объяснений | `10000000367` | v1.3 от 18.06.2024 | `docs/Specifikaciya_API_EPGU_Podacha_zayavlenij_..._10000000367_18_06_2024.docx`, `docs/Specifikaciya_API_EPGU_Prilozhenie_10000000367_..._v1.3.docx` | [Specifikaciya_API_EPGU_Podacha_zayavlenij_hodatajstv_obyasnenij_v1_3_kod_uslugi_10000000367_18_06_2024.docx](https://gu-st.ru/content/partners/api_for_gu/Specifikaciya_API_EPGU_Podacha_zayavlenij_hodatajstv_obyasnenij_v1_3_kod_uslugi_10000000367_18_06_2024.docx) |
| Наличие исполнительного производства (ФССП) | `60010153` | v8 | `docs/Specifikaciya_API_EPGU_Prilozhenie_60010153_Nalichie_IP_v8.docx` | [Specifikaciya_API_EPGU_Prilozhenie_60010153_Nalichie_IP_v8.docx](https://gu-st.ru/content/partners/api_for_gu/Specifikaciya_API_EPGU_Prilozhenie_60010153_Nalichie_IP_v8.docx) |
| Предоставление информации о ходе ИП (ФССП) | `60010154`¹ | v7 | _нет (на портале)_ | [Specifikaciya_API_EPGU_Predostavlenie_informacii_o_hode_IP_v_7.docx](https://gu-st.ru/content/partners/api_for_gu/Specifikaciya_API_EPGU_Predostavlenie_informacii_o_hode_IP_v_7.docx) |
| Миграционный и регистрационный учёт гостиниц | `гостиничные коды` | v1.3 | `docs/Specifikaciya_API_EPGU_Servisy_migracionnogo_..._v1.3.docx` | [Specifikaciya_API_EPGU_Servisy_migracionnogo_i_registracionnogo_uchyotov_dlya_gostinic_v1.3.docx](https://gu-st.ru/content/partners/api_for_gu/Specifikaciya_API_EPGU_Servisy_migracionnogo_i_registracionnogo_uchyotov_dlya_gostinic_v1.3.docx) |
| Уведомление о трудовой деятельности | — | v1.2 | `docs/Specifikaciya_API_EPGU_Uvedomlenie_o_trudovoj_deyatelnosti_1.2.docx` | [Specifikaciya_API_EPGU_Uvedomlenie_o_trudovoj_deyatelnosti_1.2.docx](https://gu-st.ru/content/partners/api_for_gu/Specifikaciya_API_EPGU_Uvedomlenie_o_trudovoj_deyatelnosti_1.2.docx) |
| Уведомление о расторжении трудового договора | — | актуальная | _нет (на портале)_ | [Specifikaciya_API_EPGU_Uvedomlenie_o_rastorzhenii_trudovogo_dogovora.docx](https://gu-st.ru/content/partners/api_for_gu/Specifikaciya_API_EPGU_Uvedomlenie_o_rastorzhenii_trudovogo_dogovora.docx) |
| Отправка документов на подпись в Госключ | — | v1.8 (локально) | `docs/Specifikaciya_API_EPGU_Otpravka_dokumentov_na_podpis_v_Gosklyuch_v1.8.docx` | [Specifikaciya_API_EPGU._Otpravka_dokumentov_na_podpis_v_Gosklyuch.docx](https://gu-st.ru/content/partners/api_for_gu/Specifikaciya_API_EPGU._Otpravka_dokumentov_na_podpis_v_Gosklyuch.docx) |
| Доставка пенсии и социальных выплат ПФР/СФР | `10000000109` | актуальная | _нет (на портале)_ | каталог `services/sfr/10000000109-zdp` ([см. референсный Go-клиент](https://github.com/ofstudio/go-api-epgu/tree/master/services/sfr/10000000109-zdp)) |

¹ — код услуги «Ход ИП» на ЕПГУ публикуется отдельно. Уточнять в личном кабинете партнёра в момент заведения услуги.

## 3. Получение API-ключа

| Категория | Документ | Локально | Источник |
|---|---|---|---|
| Организация-потребитель | Руководство пользователя по формированию API-Key и получению маркера доступа, v3.3 (31.01.2023) | `docs/Rukovodstvo_polzovatelya_dlya_organizacii-potrebitelya_..._Versiya_3.3_...docx` | [Портал API Госуслуг](https://partners.gosuslugi.ru/catalog/api_for_gu) |
| Организация-вендор | Руководство пользователя, v3.2 (26.10.2022) | `docs/Rukovodstvo_polzovatelya_dlya_organizacii-vendora_..._Versiya_3.2_...pdf` | [Портал API Госуслуг](https://partners.gosuslugi.ru/catalog/api_for_gu) |

## 4. ЕСИА — методические материалы

| Документ | Локально | Источник |
|---|---|---|
| Методические рекомендации по использованию ЕСИА (v3.48) | `docs/metodicheskierekomendatsiipoispolzovaniyuesiav348.docx` | [digital.gov.ru/ru/documents/6186](https://digital.gov.ru/ru/documents/6186/) |
| Руководство пользователя ЕСИА | — | [digital.gov.ru/ru/documents/6182](https://digital.gov.ru/ru/documents/6182/) |
| Руководство пользователя технологического портала ЕСИА | `docs/rp-esia-tehportal-1328.pdf` | [digital.gov.ru/ru/documents/6190](https://digital.gov.ru/ru/documents/6190/) |
| Методические рекомендации по REST API Цифрового профиля | — | [digital.gov.ru/ru/documents/7166](https://digital.gov.ru/ru/documents/7166/) |

## 5. Среды и endpoint-ы

### 5.1. Прямое подключение по ГОСТ TLS (раздел 1.2 спецификации v1.12.1)

| Среда | URL |
|---|---|
| Тестовая (SVCDEV) | `https://svcdev-beta.test.gosuslugi.ru` |
| Продуктовая | `https://lk.gosuslugi.ru` |

### 5.2. Подключение через СМЭВ4 / ПОДД (раздел 1.3 спецификации v1.12.1)

| Среда | URL |
|---|---|
| Тестовая (SVCDEV) | `https://lkuv.gosuslugi.ru/paip-portal/#/podd/open-api/specifications/card/e28f1ae0-0fdc-431a-9adb-17173564d1db` |
| Продуктовая | _на момент 2024-05 не опубликовано в промышленной СМЭВ4_ |

### 5.3. ЕСИА

| Среда | URL |
|---|---|
| Тестовая (SVCDEV) | `https://esia-portal1.test.gosuslugi.ru` |
| Продуктовая | `https://esia.gosuslugi.ru` |
| Технологический портал, тест | `https://esia-portal1.test.gosuslugi.ru/console/tech` |
| Технологический портал, прод | `https://esia.gosuslugi.ru/console/tech/` |

### 5.4. Согласия пользователя

| Среда | URL |
|---|---|
| Тестовая | `https://svcdev-betalk.test.gosuslugi.ru/settings/third-party/agreements/acting` |
| Продуктовая | `https://lk.gosuslugi.ru/settings/third-party/agreements/acting` |

## 6. Поддерживаемые услуги в этом проекте

| Код | Описание | Файлы (relative `xml/`) | Статус |
|---|---|---|---|
| `60010153` | Наличие ИП — ФССП | `req.xml`, `piev_epgu.xml`, валидируется по `piev_epgu.xsd` | ✅ полностью |
| `10000000367` | Подача заявлений / ходатайств / объяснений | — | ⚠️ env `SERVICES` (без XSD) |
| `10000000109` | Доставка пенсии ПФР/СФР | — | 🆕 добавляется в `SERVICES` по умолчанию |
| `60010154` | Ход ИП (ФССП) | — | 🆕 добавляется в `SERVICES` по умолчанию |

Добавление новой услуги — см. [HOWTO бэкенда: добавить услугу](../api-gosuslugi-backend/HOWTO.md#добавить-новую-услугу).

## 7. Журнал актуализации

| Дата | Что изменилось | Источник |
|---|---|---|
| 2026-05-12 | Сверка каталога партнёрского портала, обновлены ссылки на актуальные документы, добавлены прод-URL ЕСИА/ЕПГУ, расширен `SERVICES` по умолчанию | [partners.gosuslugi.ru/catalog/api_for_gu](https://partners.gosuslugi.ru/catalog/api_for_gu) |
