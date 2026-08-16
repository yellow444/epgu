# Каталог услуг и контрактов API ЕПГУ

> Снимок официального [каталога API Госуслуг](https://partners.gosuslugi.ru/catalog/api_for_gu) прочитан **12 августа 2026 года**. Авторитетный базовый документ — [API ЕПГУ v1.14 от 29.01.2026](https://gu-st.ru/content/partners/api_for_gu/Specifikaciya_API_EPGU_v1_14.docx).

В локальном снимке 28 документов: 21 спецификация отдельной услуги и 7 общих документов. Их URL, размер и SHA-256 записаны в [`api_for_gu/catalog.json`](./api_for_gu/catalog.json). Backend-источник готовности — [`../api-gosuslugi-backend/service_profiles.json`](../api-gosuslugi-backend/service_profiles.json), а не само наличие строки на портале.

## Статусы готовности

- `verified`, `available=true` — профиль имеет локальный шаблон либо типизированный генератор, необходимые XSD/golden-проверки и разрешён backend для отправки.
- `reference`, `available=false` — транспорт, имена документов и официальные материалы каталогизированы, профиль виден в UI, но `/xml`, `/push` и `/push/chunked` блокируют его.
- На этом срезе доступны три профиля Госключа: УНЭП `10000000374`, УКЭП для юридических лиц/ИП `60025907` и УКЭП с сертификатом Федерального казначейства `60080470`. Остальные 18 являются справочными.
- Для ФССП `60010153` схема и chunked-транспорт каталогизированы, но XML из спецификации содержит демонстрационные данные и не является рабочей формой. Профиль можно включить только после реализации типизированной формы, fail-closed проверки placeholder/полей и приёмки в авторизованном контуре.

Таким образом, 21 строка ниже означает полноту реестра, а не обещание 21 работающей интеграции.

## Базовые документы

| Документ | Дата/версия | Локальная копия | Официальный источник |
|---|---|---|---|
| Спецификация API ЕПГУ | v1.14, 29.01.2026 | после sync: `source/Specifikaciya_API_EPGU_v1_14.docx` | [DOCX](https://gu-st.ru/content/partners/api_for_gu/Specifikaciya_API_EPGU_v1_14.docx) |
| Спецификация API ГЭПС | v1.0, 29.01.2026 | после sync: `source/Specifikaciya_API_GEPS_v1.0.docx` | [DOCX](https://gu-st.ru/content/partners/api_for_gu/Specifikaciya_API_GEPS_v1.0.docx) |
| Регламент подключения к API Госуслуг | v1.8, 06.03.2026 | после sync: `source/Reglament_podklyucheniya_k_API_Gosuslug_1_8.docx` | [DOCX](https://gu-st.ru/content/partners/api_for_gu/Reglament_podklyucheniya_k_API_Gosuslug_1_8.docx) |
| Руководство организации-потребителя по API-Key | v3.3, 31.01.2023 | локально после sync | [DOCX](https://gu-st.ru/content/partners/api_for_gu/Rukovodstvo_polzovatelya_dlya_organizacii-potrebitelya_po_formirovaniyu_API-Key_i_polucheniyu_markera_dostupa._Versiya_3.3_ot_31.01.2023_g.docx) |
| Руководство организации-вендора по API-Key | v3.2, 26.10.2022 | локально после sync | [PDF](https://gu-st.ru/content/partners/api_for_gu/Rukovodstvo_polzovatelya_dlya_organizacii-vendora_po_formirovaniyu_API-Key_i_polucheniyu_markera_dostupa._Versiya_3.2_ot_26.10.2022_g..pdf) |
| Инструкция по Личному кабинету API ЕПГУ | v1 | после sync: `source/Instrukciya_LK_API_v1.docx` | [DOCX](https://gu-st.ru/content/partners/api_for_gu/Instrukciya_LK_API_v1.docx) |
| Договор присоединения кредитных организаций № 144687вн | 23.12.2024 | локально после sync | [PDF](https://gu-st.ru/content/partners/api_for_gu/Dogovor_prisoedineniya_k_usloviyam_integracii_kreditnykh_organizacij_k_epgu.pdf) |

## Режимы отправки

| Режим | Последовательность | Правило в backend |
|---|---|---|
| `chunked` | `/api/gusmev/order` → `/api/gusmev/push/chunked` | Backend создаёт ZIP и автоматически отправляет части; имена нескольких частей начинаются с `.z001`, а поле `chunk` — с `0` |
| `adaptive` | `/api/gusmev/push` либо `/order` → `/push/chunked` | Прямой push допустим для архива не более 50 МБ без внедряемого `orderId`; иначе нужен `orderId` и chunked-путь |

Для chunked-отправки спецификация v1.14 требует `meta` на каждой части, размер каждой непоследней части от 5 до 50 МБ, последней — не более 50 МБ, индексы `0..n-1` и завершение всей серии не позднее пяти минут. Реестр сейчас задаёт `chunkSize=5_000_000`.

Поле `region` — runtime-код ОКАТО пользователя. Оно не может быть одним фиксированным значением для всех заявлений услуги.

Для верифицированных сценариев Госключа архив содержит `req.xml`, пользовательские документы и отделённый PKCS#7/CAdES-файл `<имя>.sig` для каждого из них, включая `req.xml`. Криптографическую подпись создаёт переданный signer/CryptoPro-adapter; структурная проверка архива сама по себе не подтверждает криптографическую валидность подписи.

## Матрица 21 услуги

`assets` — число XML/XSD-блоков, механически извлечённых из соответствующего DOCX. Ноль не означает отсутствие контракта вообще: часть документов ссылается на внешний архив/ЛКУВ или описывает формат иначе. И наоборот, ненулевое число не делает профиль исполняемым.

| Код | Услуга | Режим | Документы в ZIP | Варианты | Спецификация и assets | Готовность |
|---|---|---|---|---|---|---|
| `10000000109` | Приём заявлений о доставке пенсий и иных социальных выплат | `chunked` | `req_{guid}.xml`, `trans_{guid}.xml`; подпись: нет | — | [2024-11-15](https://gu-st.ru/content/partners/api_for_gu/Specifikaciya_API_EPGU_Prilozhenie_10000000109_Priem_zayavlenij_o_dostavke_pensij_i_inykh_socialnykh_vyplat_v1.1.docx); assets: 5 | `reference` / заблокирована |
| `10000000110` | Назначение страховых и накопительных пенсий (600110_1) | `chunked` | `req_{guid}.xml`, `trans_{guid}.xml`; подпись: нет | — | [2025-05-29](https://gu-st.ru/content/partners/api_for_gu/Specifikaciya_API_EPGU_Prilozhenie_10000000110_Naznachenie_pensii_v1.1.docx); assets: 4 | `reference` / заблокирована |
| `10000000352` | Предоставление информации о ходе исполнительного производства онлайн | `chunked` | `req.xml`, `piev_epgu.xml`; подпись: нет | — | [2025-09-24](https://gu-st.ru/content/partners/api_for_gu/Specifikaciya_API_EPGU_Prilozhenie_10000000352_Hod_IP_v9.docx); assets: 9 | `reference` / заблокирована |
| `10000000367` | Подача заявлений, ходатайств, объяснений, отводов и жалоб по исполнительному производству | `chunked` | `req.xml`, `piev_epgu.xml`; подпись: нет | Petition<br>IRequestOther | [2026-03-31](https://gu-st.ru/content/partners/api_for_gu/Specifikaciya_API_EPGU_Prilozhenie_10000000367_Podacha_zayavleni_hodatajstv_obyasnenij_v1.4.docx); assets: 42 | `reference` / заблокирована |
| `10000000374` | Отправка документов на подпись в Госключ | `adaptive` | `req.xml`; подпись: CAdES | УНЭП — `verified`<br>УКЭП — `reference`, нет опубликованной XSD | [2025-08-28](https://gu-st.ru/content/partners/api_for_gu/Specifikaciya_API_EPGU_Prilozhenie_10000000374_v1.9.docx); assets: 3 | `verified` / доступна только УНЭП |
| `10000000396` | Информация об исполнительных производствах для снятия ограничений на выезд | `chunked` | `req.xml`, `piev_epgu.xml`; подпись: нет | — | [2024-07-18](https://gu-st.ru/content/partners/api_for_gu/Specifikaciya_API_EPGU_Prilozhenie_10000000396_servis_snyatiya_ogranichenij_na_vyezd_v1.docx); assets: 3 | `reference` / заблокирована |
| `10000000585` | Уведомления о трудовых договорах с иностранными гражданами | `chunked` | `attach.xml`; подпись: нет | заключение договора<br>расторжение договора<br>выплата ВКС | [2024-08-15](https://gu-st.ru/content/partners/api_for_gu/Specifikaciya_API_EPGU_Uvedomlenie_o_trudovoj_deyatelnosti_1.3.docx); assets: 0 | `reference` / заблокирована |
| `10000000588` | Миграционный и регистрационный учёт для гостиниц | `chunked` | `req.xml`; подпись: CAdES | постановка иностранного гражданина<br>снятие иностранного гражданина<br>регистрационный учёт гражданина РФ | [2026-06-22](https://gu-st.ru/content/partners/api_for_gu/Specifikaciya_API_EPGU_Servisy_migracionnogo_i_registracionnogo_uchyotov_dlya_gostinic_v3.0_600588.docx); assets: 0 | `reference` / заблокирована |
| `10000000804` | Регистрация транспортных средств | `chunked` | `trans_{guid}.xml`, `attach.xml`; подпись: нет | новое ТС<br>бывшее в эксплуатации ТС | [2026-03-17](https://gu-st.ru/content/partners/api_for_gu/Spetsifikatsiya_API_EPGU_Prilozhenie_10000000804_RegistratsiyaTS_v1.docx); assets: 13 | `reference` / заблокирована |
| `60010153` | Предоставление информации о наличии исполнительного производства онлайн | `chunked` | `req.xml`, `piev_epgu.xml`; подпись: нет | демонстрационный XML; требуется типизированная форма и fail-closed проверка placeholder/полей | [2024-07-17](https://gu-st.ru/content/partners/api_for_gu/Specifikaciya_API_EPGU_Prilozhenie_60010153_Nalichie_IP_v8.docx); assets: 9 | `reference` / заблокирована до приёмки в авторизованном контуре |
| `60011906` | Подача обращений в органы прокуратуры | `chunked` | `req.xml`; подпись: нет | — | [2026-03-03](https://gu-st.ru/content/partners/api_for_gu/Specification_API_EPGU_Submission_of_appeals_to_the_prosecutors.docx); assets: 3 | `reference` / заблокирована |
| `60013502` | Приём заявлений о доставке пенсии и иных социальных выплат | `chunked` | `req_{guid}.xml`, `trans_{guid}.xml`; подпись: нет | — | [2025-01-17](https://gu-st.ru/content/partners/api_for_gu/Specifikaciya_API_EPGU_Prilozhenie_60013502_Priem_zayavlenij_o_dostavke_pensij_i_inykh_socialnykh_vyplat_v1.2.docx); assets: 9 | `reference` / заблокирована |
| `60013730` | Корректировка сведений индивидуального лицевого счёта | `chunked` | `req_{guid}.xml`, `trans_{guid}.xml`; подпись: нет | — | [2024-12-20](https://gu-st.ru/content/partners/api_for_gu/Specifikaciya_API_EPGU_Prilozhenie_613730_Priem_ot_zastrakhovannykh_lic_zayavlenij_o_korrektirovke_svedenij_ILS_v1.3.docx); assets: 7 | `reference` / заблокирована |
| `60019724` | Назначение страховых и накопительных пенсий | `chunked` | `req_{guid}.xml`, `trans_{guid}.xml`; подпись: нет | ЗНП<br>СНПАР | [2024-09-19](https://gu-st.ru/content/partners/api_for_gu/Specifikaciya_API_EPGU_Prilozhenie_60019724_Naznachenie_pensii_v1.3.docx); assets: 11 | `reference` / заблокирована |
| `60025907` | Подписание документов УКЭП юридическими лицами | `adaptive` | `req.xml`; подпись: CAdES | юрлицо или ИП — `verified` | [2025-08-28](https://gu-st.ru/content/partners/api_for_gu/Specifikaciya_API_EPGU_Prilozhenie_60025907.docx); assets: 2 | `verified` / доступна |
| `60048912` | Обмен сведениями с реестром организаторов распространения информации | `chunked` | `req.xml`; подпись: CAdES | — | [2025-12-03](https://gu-st.ru/content/partners/api_for_gu/Specifikaciya_TOT_03_12_2025.docx); assets: 0 | `reference` / заблокирована |
| `60057731` | Поиск иностранного гражданина в реестре контролируемых лиц | `chunked` | `req.xml`; подпись: нет | — | [2025-03-06](https://gu-st.ru/content/partners/api_for_gu/Specification_API_EPGU_Search_for_foreigner_in_RKL_V_1.3.docx); assets: 3 | `reference` / заблокирована |
| `60078836` | Уведомления медицинских организаций о регистрации граждан | `chunked` | `attach.xml`; подпись: CAdES | — | [2026-04-20](https://gu-st.ru/content/partners/api_for_gu/Specifikaciya_API_EPGU_Servisy_uvedomleniya_ot_medicinskih_organizatsiy_o_registracii_grazhdan_v1.0.docx); assets: 3 | `reference` / заблокирована |
| `60079416` | Расшифрование документов в Госключе | `adaptive` | `req.xml`; подпись: CAdES | — | [2025-11-01](https://gu-st.ru/content/partners/api_for_gu/Specifikaciya_API_EPGU_Prilozhenie_60079416_.docx); assets: 1 | `reference` / заблокирована |
| `60080315` | Ежегодная семейная выплата | `chunked` | `req_{guid}.xml`, `trans_{guid}.xml`; подпись: нет | — | [2026-06-04](https://gu-st.ru/content/partners/api_for_gu/Specifikaciya_API_EPGU_Prilozhenie_680315_Family_v1.0_%20editing_the_directory_SFR_CO_01.docx); assets: 5 | `reference` / заблокирована |
| `60080470` | Подписание УКЭП с сертификатом Федерального казначейства | `adaptive` | `req.xml`; подпись: CAdES | сертификат ФК — `verified` | [2026-02-25](https://gu-st.ru/content/partners/api_for_gu/Specifikaciya_API_EPGU_Prilozhenie_ukep_roskazna.docx); assets: 2 | `verified` / доступна |

Значение «подпись: нет» означает только отсутствие требования `detached-cades` в текущем справочном профиле. Для `reference` это всё равно должно быть подтверждено golden-тестом и тестовым контуром перед включением.

## Среды

| Среда | ЕСИА | API ЕПГУ | Назначение |
|---|---|---|---|
| `test` | `https://esia-portal1.test.gosuslugi.ru` | `https://svcdev-gostapi.test.gosuslugi.ru` | формальный тестовый ГОСТ-контур v1.14 |
| `prod` | `https://esia.gosuslugi.ru` | `https://www.gosuslugi.ru` | промышленный контур |
| `test-beta` | `https://esia-portal1.test.gosuslugi.ru` | `https://svcdev-beta.test.gosuslugi.ru` | совместимость с примерами старых приложений |

## Воспроизводимость

```bash
python scripts/sync_api_for_gu_docs.py --check
python scripts/extract_api_for_gu_assets.py --check
python scripts/build_service_profiles.py
python scripts/audit_repository.py --check
```

`build_service_profiles.py` перезаписывает детерминированный реестр; после запуска следует проверить ожидаемый diff. Для обновления официальных файлов используйте порядок из [`api_for_gu/README.md`](./api_for_gu/README.md), затем повторно проводите профильную проверку. Не повышайте `reference` до `verified` только потому, что хэш документа совпал.

## Известные расхождения официальных материалов

- Для `10000000588` DOCX v3.0 ссылается на пространства имён 2.5.4/2.0.5, тогда как связанный публичный архив схем содержит 2.5.3/2.0.4. До официального разъяснения профиль остаётся заблокированным.
- Для Госключа `60079416` официальные источники расходятся по наличию `FileName`/`Description` и максимальному числу документов (50 или 20), поэтому расшифрование остаётся `reference`.
- В нескольких примерах СФР встречаются кириллические URI пространства имён, которые строгий `lxml` отвергает, хотя менее строгий XML-парсер разбирает структуру. Оригиналы не исправляются молча.
- Для `10000000585`, `60048912` и `10000000588` автоматическое извлечение не нашло самостоятельных XML/XSD-блоков; внешние вложения и ссылки требуют отдельной ручной верификации.

Дополнительная статистика и публикационные блокеры приведены в [`AUDIT_2026-08-12.md`](./AUDIT_2026-08-12.md).
