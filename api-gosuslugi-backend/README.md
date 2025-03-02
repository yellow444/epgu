# README.md

## Описание проекта

Проект предоставляет набор функций и API для работы с Госуслугами, включая управление сертификатами, создание запросов, загрузку и скачивание файлов, а также проверки XML на соответствие XSD.

## Требования

- Python 3.8+
- FastAPI
- PyCades
- requests
- lxml
- dotenv
- uvicorn

## Установка

1. Клонируйте репозиторий:
   ```bash
   git clone <repository-url>
   ```

2. Установите зависимости:
   ```bash
   pip install -r requirements.txt
   ```

3. Настройте `.env` файл:
   ```plaintext
   production=<production_flag>
   apikey=<your_api_key>
   KeyPin=<key_pin>
   TSAAddress=<tsa_address>
   esia_host=<esia_host_url>
   svcdev_host=<svcdev_host_url>
   ```

4. Запустите сервер:
   ```bash
   uvicorn app:app --host 0.0.0.0 --port 5000
   ```

## Описание API

### Получение сертификатов
**URL:** `/get_certificates`

**Метод:** `POST`

Возвращает список доступных сертификатов.

### Установить текущий сертификат
**URL:** `/set_current_certificate`

**Метод:** `POST`

**Параметры:**
- `cert_id` (str): Идентификатор сертификата.

### Получить текущий сертификат
**URL:** `/get_current_certificate`

**Метод:** `POST`

Возвращает текущий установленный сертификат.

### Проверка статуса API
**URL:** `/status`

**Метод:** `GET`

Возвращает версию модуля PyCades.

### Генерация токена доступа
**URL:** `/accessTkn_esia`

**Метод:** `POST`

**Тело запроса:**
```json
{
  "api_key": "<ваш_api_key>"
}
```

### Создание заказа
**URL:** `/order`

**Метод:** `POST`

**Тело запроса:**
```json
{
  "region": "<регион>",
  "serviceCode": "<код_сервиса>",
  "targetCode": "<цель_сервиса>"
}
```

### Получение деталей заказа
**URL:** `/order/{orderId}`

**Метод:** `POST`

### Отмена заказа
**URL:** `/order/{orderId}/cancel`

**Метод:** `POST`

### Получение обновленных данных
**URL:** `/getUpdatedAfter`

**Метод:** `GET`

**Параметры:**
- `pageNum`: Номер страницы
- `pageSize`: Количество элементов на странице
- `updatedAfter`: Дата и время последнего обновления в формате ISO8601

### Скачивание файла
**URL:** `/download_file/{objectId}/{objectType}`

**Метод:** `POST`

**Параметры:**
- `mnemonic`: Имя файла
- `eserviceCode`: Код сервиса

### Отправка файла
**URL:** `/push`

**Метод:** `POST`

**Параметры:**
- `meta`: JSON строка с мета-данными
- `files_upload`: Список загружаемых файлов

### Отправка файла по частям
**URL:** `/push/chunked`

**Метод:** `POST`

**Параметры:**
- `meta`: JSON строка с мета-данными
- `orderId`: Идентификатор заказа
- `chunks`: Общее количество частей
- `chunk`: Текущая часть
- `files_upload`: Список загружаемых файлов

### Проверка XML

**Методы:**
- `validate_xml_content`: Проверяет содержимое XML.
- `validate_xml`: Проверяет XML файл на соответствие XSD схеме.

## Файлы проекта

- `app.py`: Основной файл приложения.
- `.env`: Настройки окружения.
- `requirements.txt`: Зависимости проекта.

## Пример .env файла

```plaintext
production=True
apikey=YOUR_API_KEY
KeyPin=1234567890
TSAAddress=http://www.cryptopro.ru/tsp/tsp.srf
esia_host=https://esia-portal1.test.gosuslugi.ru
svcdev_host=https://svcdev-beta.test.gosuslugi.ru
```

## Документация

Документы, связанные с проектом:

- `Instrukciya_po_podklucheniyu_API_EPGU.pdf`
- `Instruktsiya_po_sozdaniyu_zaprosov_dlya_vypuska_tls_sertifikata.pdf`
- `metodicheskierekomendatsiipoispolzovaniyuesiav348.docx`
- `Reglament_podklyucheniya_k_API_Gosuslug_1_8.docx`
- `reglamentinformatsionnogovzaimodeistviyauchastnikovsoperatorom.docx`
- `Rukovodstvo_polzovatelya_dlya_organizacii-potrebitelya_po_formirovaniyu_API-Key_i_polucheniyu_markera_dostupa._Versiya_3.3_ot_31.01.2023_g.docx`
- `Specifikaciya_API_EPGU_v1_13.docx`

## Лицензия

Этот проект распространяется под лицензией MIT.
