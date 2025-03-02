import os
import io
import base64
import json
import logging
import zipfile
from typing import List
from fastapi import FastAPI, HTTPException, UploadFile, Request, Form, Path, Query, Depends
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import httpx
from dotenv import load_dotenv, find_dotenv
from lxml import etree
import pycades

# Загрузка переменных окружения
load_dotenv(find_dotenv())
production = os.getenv('production')
if production is None or production.strip() == "":
    import debugpy
    debugpy.listen(('0.0.0.0', 5678))
#    debugpy.wait_for_client()
    log_level = logging.DEBUG
else:
    log_level = logging.INFO
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.DEBUG if production is None else logging.INFO,
)
logger = logging.getLogger(__name__)
logger.info(f"log_level:{log_level}")
logger.info(f"production:{production}")
# Глобальные конфигурационные переменные
API_KEY_DEFAULT = os.getenv('apikey', 'my api key')
KEY_PIN = os.getenv('KeyPin', '1234567890')
TSA_ADDRESS = os.getenv('TSAAddress', 'http://www.cryptopro.ru/tsp/tsp.srf')
ESIA_HOST = os.getenv('esia_host', 'https://esia-portal1.test.gosuslugi.ru')
SVCDEV_HOST = os.getenv('svcdev_host', 'https://svcdev-beta.test.gosuslugi.ru')
USER_AGENT = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.19 (KHTML, like Gecko) Ubuntu/12.04 Chromium/18.0.1025.168 Chrome/18.0.1025.168 Safari/535.19'
XSD_FILE = os.getenv('XSD_FILE', '/xml/piev_epgu.xsd')
schema_root = etree.parse(XSD_FILE)
schema = etree.XMLSchema(schema_root)
# Глобальное состояние
CERTIFICATES = {}
CURRENT_CERT_ID = None
ACCESS_TKN_ESIA = ''
services_json = os.environ.get("SERVICES")
if services_json:
    try:
        services_dict = json.loads(services_json)
    except json.JSONDecodeError:
        raise HTTPException(
            status_code=500, detail="Неверный формат переменной SERVICES")
else:
    # Значения по умолчанию, если переменная не задана
    services_dict = {"service1": {"description": "Услуга 1", "req_file": "req.xml", "piev_epgu_file": "piev_epgu.xml"}, "service2": {"description": "Услуга 2",
                                                                                                                                     "req_file": "req.xml", "piev_epgu_file": "piev_epgu.xml"}, "service3": {"description": "Услуга 3", "req_file": "req.xml", "piev_epgu_file": "piev_epgu.xml"}}

# Инициализация FastAPI

app = FastAPI(root_path="/api")
app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)


@app.on_event("startup")
async def startup_event():
    try:
        load_certificates()
    except Exception as e:
        logger.exception(f"Ошибка при старте приложения: {e}")

# Pydantic-модели


class APIKeyRequest(BaseModel):
    api_key: str


class OrderRequest(BaseModel):
    region: str = Field('45000000000', description='Region code')
    serviceCode: str = Field('60010153', description='Service code')
    targetCode: str = Field('-60010153', description='Target code')

# Хелперы


def load_certificates() -> List[str]:
    global CERTIFICATES, CURRENT_CERT_ID
    try:
        store = pycades.Store()
        store.Open(
            pycades.CADESCOM_CONTAINER_STORE,
            pycades.CAPICOM_MY_STORE,
            pycades.CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED,
        )
        certs = store.Certificates
        if certs.Count == 0:
            logger.exception("Сертификаты не найдены в хранилище.")
            raise Exception("Сертификаты не найдены.")
        CERTIFICATES = {
            cert.Thumbprint: cert
            for cert in [certs.Item(i) for i in range(1, certs.Count + 1)]
        }
        cert_ids = list(CERTIFICATES.keys())
        CURRENT_CERT_ID = cert_ids[0] if cert_ids else None
        return cert_ids
    except Exception as e:
        logger.exception(f"Ошибка загрузки сертификатов: {e}")
        raise


def parse_string_to_json(input_str: str) -> dict:
    result = {}
    key = None
    value = []
    inside_quotes = False
    for part in input_str.split(", "):
        if inside_quotes:
            value.append(part)
            if part.endswith('"'):
                inside_quotes = False
                result[key] = " ".join(value).strip('"')
                key, value = None, []
        else:
            if "=" in part:
                key, val = part.split("=", 1)
                key = key.strip()
                if val.startswith('"') and not val.endswith('"'):
                    inside_quotes = True
                    value = [val]
                else:
                    result[key] = val.strip('"').strip()
            else:
                raise ValueError(f"Некорректный формат части: {part}")
    return result


def get_current_certificate_details() -> dict:
    if CURRENT_CERT_ID is None or CURRENT_CERT_ID not in CERTIFICATES:
        raise Exception("Текущий сертификат не установлен.")
    cert = CERTIFICATES[CURRENT_CERT_ID]
    return parse_string_to_json(cert.SubjectName)


def validate_xml_content(xml_content: bytes) -> bool:
    try:

        xml_doc = etree.fromstring(xml_content)
        schema.assertValid(xml_doc)
        return True
    except Exception as e:
        logger.exception(f"Invalid XML content: {e}")
        raise HTTPException(status_code=400, detail=f"Invalid XML: {e}")


def signkey(api_key: str) -> str:
    global TSA_ADDRESS, CURRENT_CERT_ID, KEY_PIN
    if CURRENT_CERT_ID not in CERTIFICATES:
        raise Exception("Текущий сертификат не найден.")
    cert = CERTIFICATES[CURRENT_CERT_ID]
    signer = pycades.Signer()
    signer.Certificate = cert
    signer.CheckCertificate = True
    signer.TSAAddress = TSA_ADDRESS
    signer.KeyPin = '1234567890'
    signedData = pycades.SignedData()
    signedData.ContentEncoding = pycades.CADESCOM_BASE64_TO_BINARY
    message_bytes = api_key.encode("utf-8")
    base64_message = base64.b64encode(message_bytes)
    signedData.Content = base64_message.decode("utf-8")
    bDetached = int(1)
    signature = signedData.SignCades(
        signer, pycades.CADESCOM_CADES_BES, bDetached)
    signature = signature.replace("\r\n", "")
    signature += "=" * ((4 - len(signature) % 4) % 4)
    message_bytes = base64.b64decode(signature)
    result = base64.urlsafe_b64encode(message_bytes).decode("utf-8")
    return result

# Зависимость для асинхронного HTTP клиента


async def get_async_client() -> httpx.AsyncClient:
    async with httpx.AsyncClient(timeout=30) as client:
        yield client

# Эндпоинты


@app.post("/get_certificates")
async def get_certificates_endpoint():
    certs = {}
    for cert_id, cert in CERTIFICATES.items():
        certs[cert_id] = parse_string_to_json(cert.SubjectName)
    result = [{"id": cid, "subject": certs[cid].get(
        "SN", "Unknown")} for cid in certs]
    return JSONResponse(content=result, headers={"Access-Control-Allow-Origin": "*"})


@app.post("/set_current_certificate")
async def set_current_certificate(cert_id: str):
    global CURRENT_CERT_ID
    if cert_id not in CERTIFICATES:
        logger.exception(f"Сертификат с ID {cert_id} не найден.")
        raise HTTPException(
            status_code=400, detail=f"Сертификат с ID {cert_id} не найден.")
    CURRENT_CERT_ID = cert_id
    return JSONResponse(content=None, status_code=200, headers={"Access-Control-Allow-Origin": "*"})


@app.post("/get_current_certificate")
async def get_current_certificate_endpoint():
    try:
        details = get_current_certificate_details()
        return JSONResponse(content={"certId": CURRENT_CERT_ID, "subject": details}, status_code=200)
    except Exception as e:
        logger.exception(str(e))
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/status")
async def home_route():
    version = pycades.About().Version
    module_version = pycades.ModuleVersion()
    return JSONResponse(content={"Version": version, "ModuleVersion": module_version}, status_code=200)


@app.get("/hc")
async def check_route():
    version = pycades.About()
    if version:
        return JSONResponse(content={"status": "Ok"}, status_code=200)
    else:
        return JSONResponse(content={"status": "Error"}, status_code=404)


@app.post("/accessTkn_esia")
async def access_tkn_esia(request: APIKeyRequest, client: httpx.AsyncClient = Depends(get_async_client)):
    global ACCESS_TKN_ESIA, ESIA_HOST, API_KEY_DEFAULT
    api_key_data = request.api_key if request.api_key and request.api_key != "string" else API_KEY_DEFAULT
    if not api_key_data or api_key_data == "":
        raise HTTPException(status_code=400, detail="Некорректный API ключ.")
    try:
        signature = signkey(api_key_data)
        url = f"{ESIA_HOST}/esia-rs/api/public/v1/orgs/ext-app/{api_key_data}/tkn?signature={signature}"
        response = await client.get(url, headers={"User-Agent": USER_AGENT})
        response.raise_for_status()
        res = response.json()
        if "accessTkn" in res:
            ACCESS_TKN_ESIA = res["accessTkn"]
        return res
    except httpx.HTTPStatusError as err:
        logger.exception(f"HTTPError in accessTkn_esia: {err}")
        raise HTTPException(
            status_code=err.response.status_code, detail=str(err))
    except Exception as err:
        logger.exception(f"Unexpected error in accessTkn_esia: {err}")
        raise HTTPException(status_code=500, detail=str(err))


@app.post("/order")
async def order_endpoint(request_data: OrderRequest, client: httpx.AsyncClient = Depends(get_async_client)):
    global ACCESS_TKN_ESIA, SVCDEV_HOST
    try:
        url = f"{SVCDEV_HOST}/api/gusmev/order"
        response = await client.post(
            url,
            json=request_data.dict(),
            headers={
                "Authorization": f"Bearer {ACCESS_TKN_ESIA}",
                "Content-Type": "application/json",
            },
        )
        response.raise_for_status()
        return response.json()
    except httpx.HTTPStatusError as err:
        logger.exception(f"HTTPError in order: {err}")
        raise HTTPException(
            status_code=err.response.status_code, detail=str(err))
    except Exception as err:
        logger.exception(f"Unexpected error in order: {err}")
        raise HTTPException(status_code=500, detail=str(err))


def safe_parse_order(order_details):
    """
    Принимает словарь order_details и пытается безопасно распарсить значение по ключу "order".
    Возвращает распарсенные данные, если строка корректна, или None в случае отсутствия или ошибки парсинга.
    """
    order_str = order_details.get("order")
    if order_str is None:
        # Поле "order" отсутствует
        return None
    if not isinstance(order_str, str):
        # Значение не является строкой, возвращаем None или можно попытаться преобразовать
        return None
    try:
        return json.loads(order_str)
    except json.JSONDecodeError as err:
        # Возвращаем None, если произошла ошибка декодирования JSON
        raise HTTPException(status_code=404, detail=str(order_details))


@app.post("/order/{orderId}")
async def order_with_id(
    request_data: OrderRequest,
    orderId: str = Path(..., description="Order ID"),
    client: httpx.AsyncClient = Depends(get_async_client),
):
    global ACCESS_TKN_ESIA, SVCDEV_HOST
    try:
        url = f"{SVCDEV_HOST}/api/gusmev/order/{orderId}"
        response = await client.post(
            url,
            json=request_data.dict(),
            headers={
                "Authorization": f"Bearer {ACCESS_TKN_ESIA}",
                "Content-Type": "application/json",
            },
        )
        response.raise_for_status()
        order_details = response.json()
        file_details = []
        order_obj = safe_parse_order(order_details)
        if not order_obj:
            raise HTTPException(status_code=404, detail=str(order_details))
        for file in order_obj.get("orderResponseFiles", []):
            if file.get("fileName") == "piev_epgu.zip":
                link = file["link"].split("/")[-1]
                file_details.append({
                    "objectId": order_obj["currentStatusHistoryId"],
                    "objectType": link,
                    "mnemonic": file["fileName"],
                    "eserviceCode": request_data.serviceCode,
                })
        if file_details:
            return JSONResponse(
                content={
                    "message": "Детали запроса успешно получены.",
                    "fileDetails": file_details,
                    "orderDetails": order_obj,
                },
                status_code=200,
            )
        else:
            return JSONResponse(
                content={
                    "message": "Детали запроса отсутствуют.",
                    "orderDetails": order_obj,
                },
                status_code=200,)
    except httpx.HTTPStatusError as err:
        logger.exception(f"HTTPError while processing order/{orderId}: {err}")
        raise HTTPException(
            status_code=err.response.status_code, detail=str(err))
    except HTTPException as err:
        logger.error(
            f"HTTPException while processing order/{orderId}: {err}")
        raise err
    except Exception as err:
        logger.exception(
            f"Unexpected error while processing order/{orderId}: {err}"
        )
        raise HTTPException(status_code=500, detail=str(err))


@app.post("/order/{orderId}/cancel")
async def cancel_order(
    request_data: OrderRequest,
    orderId: str = Path(..., description="Order ID"),
    client: httpx.AsyncClient = Depends(get_async_client),
):
    global ACCESS_TKN_ESIA, SVCDEV_HOST
    try:
        url = f"{SVCDEV_HOST}/api/gusmev/order/{orderId}/cancel"
        response = await client.post(
            url,
            json=request_data.dict(),
            headers={
                "Authorization": f"Bearer {ACCESS_TKN_ESIA}",
                "Content-Type": "application/json",
            },
        )
        response.raise_for_status()
        order_details = response.json()
        return JSONResponse(
            content={
                "message": "Детали запроса отсутствуют.",
                "orderDetails": order_details,
            },
            status_code=200,
        )
    except httpx.HTTPStatusError as err:
        logger.exception(f"HTTPError while processing order/{orderId}: {err}")
        raise HTTPException(
            status_code=err.response.status_code, detail=str(err))
    except HTTPException as err:
        logger.error(
            f"HTTPException while processing order/{orderId}: {err}")
        raise err
    except Exception as err:
        logger.exception(
            f"Unexpected error while processing order/{orderId}: {err}"
        )
        raise HTTPException(status_code=500, detail=str(err))


@app.get("/getUpdatedAfter")
async def get_updated_after(
    pageNum: int,
    pageSize: int,
    updatedAfter: str,
    client: httpx.AsyncClient = Depends(get_async_client),
):
    global ACCESS_TKN_ESIA, SVCDEV_HOST
    try:
        url = f"{SVCDEV_HOST}/api/gusmev/order/getUpdatedAfter"
        params = {"pageNum": pageNum, "pageSize": pageSize,
                  "updatedAfter": updatedAfter}
        response = await client.get(
            url,
            headers={"Authorization": f"Bearer {ACCESS_TKN_ESIA}"},
            params=params,
        )
        response.raise_for_status()
        return JSONResponse(content=response.json(), status_code=200)
    except httpx.HTTPStatusError as err:
        logger.exception(f"HTTPError in getUpdatedAfter: {err}")
        raise HTTPException(
            status_code=err.response.status_code, detail=str(err))
    except Exception as err:
        logger.exception(f"Unexpected error in getUpdatedAfter: {err}")
        raise HTTPException(status_code=500, detail=str(err))


@app.get("/getOrdersStatus/")
async def get_orders_status(
    pageNum: int,
    pageSize: int,
    orderIds: List[int] = Query([]),
    client: httpx.AsyncClient = Depends(get_async_client),
):
    global ACCESS_TKN_ESIA, SVCDEV_HOST
    try:
        url = f"{SVCDEV_HOST}/api/gusmev/order/getOrdersStatus/"
        params = {"pageNum": pageNum, "pageSize": pageSize,
                  "orderIds": ",".join(map(str, orderIds))}
        response = await client.get(
            url,
            headers={"Authorization": f"Bearer {ACCESS_TKN_ESIA}"},
            params=params,
        )
        response.raise_for_status()
        return JSONResponse(content=response.json(), status_code=200)
    except httpx.HTTPStatusError as err:
        logger.exception(f"HTTPError in getOrdersStatus: {err}")
        raise HTTPException(
            status_code=err.response.status_code, detail=str(err))
    except Exception as err:
        logger.exception(f"Unexpected error in getOrdersStatus: {err}")
        raise HTTPException(status_code=500, detail=str(err))


@app.post("/dictionary/{code}")
async def get_dictionary(code: str, client: httpx.AsyncClient = Depends(get_async_client)):
    global ACCESS_TKN_ESIA, SVCDEV_HOST
    try:
        url = f"{SVCDEV_HOST}/api/nsi/v1/dictionary/{code}"
        response = await client.post(url, headers={"Authorization": f"Bearer {ACCESS_TKN_ESIA}"})
        response.raise_for_status()
        return JSONResponse(content=response.json(), status_code=200)
    except httpx.HTTPStatusError as err:
        logger.exception(f"HTTPError in get_dictionary: {err}")
        raise HTTPException(
            status_code=err.response.status_code, detail=str(err))
    except Exception as err:
        logger.exception(f"Unexpected error in get_dictionary: {err}")
        raise HTTPException(status_code=500, detail=str(err))


@app.post("/download_file/{objectId}/{objectType}")
async def download_file(
    objectId: str,
    objectType: str,
    mnemonic: str,
    eserviceCode: str,
    client: httpx.AsyncClient = Depends(get_async_client),
):
    global ACCESS_TKN_ESIA, SVCDEV_HOST
    try:
        download_url = (
            f"{SVCDEV_HOST}/api/gusmev/files/download/{objectId}/{objectType}"
            f"?mnemonic={mnemonic}&eserviceCode={eserviceCode}"
        )
        response = await client.get(
            download_url,
            headers={
                "Authorization": f"Bearer {ACCESS_TKN_ESIA}",
                "User-Agent": USER_AGENT
            },
            follow_redirects=True  # Добавляем параметр, чтобы следовать за редиректами
        )
        response.raise_for_status()
        return StreamingResponse(
            io.BytesIO(response.content),
            media_type="application/zip",
            headers={"Content-Disposition": f"attachment; filename={mnemonic}"},
        )
    except httpx.HTTPStatusError as err:
        logger.exception(f"HTTPError while downloading file: {err}")
        raise HTTPException(
            status_code=err.response.status_code, detail=str(err)
        )
    except Exception as err:
        logger.exception(f"Unexpected error while downloading file: {err}")
        raise HTTPException(status_code=500, detail=str(err))


@app.get("/services")
async def get_services():
    """
    Возвращает список услуг. Каждый элемент списка – объект с ключами:
    - serviceCode: номер сервиса (например, "1")
    - description: описание услуги
    - req_file: имя XML файла запроса
    - piev_epgu_file: имя XML файла приложения
    """
    services_list = []
    for key, value in services_dict.items():
        services_list.append({
            "serviceCode": key,
            "description": value.get("description", ""),
            "req_file": value.get("req_file", ""),
            "piev_epgu_file": value.get("piev_epgu_file", ""),
            "region": value.get("region", ""),
            "targetCode": value.get("targetCode", ""),
            "eServiceCode": value.get("eServiceCode", ""),
            "serviceTargetCode": value.get("serviceTargetCode", "")
        })
    return JSONResponse(content=services_list)


@app.get("/xsd")
async def get_xsd(simple_type_name):
    """
    Извлекает из XSD-схемы, представленной schema_root, все xs:enumeration
    для xs:simpleType с заданным именем simple_type_name.

    Возвращает список словарей с ключами 'value' и 'documentation'.
    """
    # Пространство имён XSD
    ns = {"xs": "http://www.w3.org/2001/XMLSchema"}

    # Находим xs:simpleType с нужным атрибутом name
    simple_type = schema_root.find(
        f".//xs:simpleType[@name='{simple_type_name}']", ns)
    if simple_type is None:
        print(f"xs:simpleType с именем '{simple_type_name}' не найден.")
        return []

    # Находим все xs:enumeration внутри найденного simpleType
    enumerations = simple_type.findall(".//xs:enumeration", ns)
    result = []
    for enum in enumerations:
        value = enum.get("value")
        # Ищем xs:annotation/xs:documentation внутри xs:enumeration
        annotation_elem = enum.find("xs:annotation/xs:documentation", ns)
        documentation = annotation_elem.text.strip(
        ) if annotation_elem is not None and annotation_elem.text else ""
        result.append({"value": value, "documentation": documentation})

    return result


@app.get("/xml")
async def get_xml(service: str = Query(..., description="Тип услуги: service1, service2, service3")):
    if service not in services_dict:
        raise HTTPException(status_code=400, detail="Неверный тип услуги")

    service_data = services_dict[service]
    req_file_name = service_data.get("req_file")
    piev_epgu_file_name = service_data.get("piev_epgu_file")

    # Формируем пути к файлам, предполагается, что они расположены в /xml
    req_path = os.path.join("/xml", req_file_name)
    piev_epgu_path = os.path.join("/xml", piev_epgu_file_name)

    try:
        with open(req_path, "r", encoding="utf-8") as req_file:
            req_content = req_file.read()
        with open(piev_epgu_path, "r", encoding="utf-8") as piev_epgu_file:
            piev_epgu_content = piev_epgu_file.read()
        return {"req": req_content, "piev_epgu": piev_epgu_content}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/zipsize")
async def zipsize(
    request: Request,
    files_upload: List[UploadFile] = None,
):
    try:
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
            if files_upload:
                for file in files_upload:
                    # Проверяем, не разорвал ли клиент соединение
                    if await request.is_disconnected():
                        logger.info(
                            "Клиент разорвал соединение, прекращаем обработку")
                        raise HTTPException(
                            status_code=499, detail="Client disconnected")

                    file_content = await file.read()
                    zip_file.writestr(file.filename, file_content)
        zip_buffer.seek(0)
        archive_size = len(zip_buffer.getvalue())
        return {"zip_size": archive_size}
    except Exception as e:
        logger.exception(f"Unexpected error in zipsize: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/push")
async def push(
    meta: str = Form(...),
    files_upload: List[UploadFile] = None,
    client: httpx.AsyncClient = Depends(get_async_client),
):
    global ACCESS_TKN_ESIA, SVCDEV_HOST
    try:
        meta_data = json.loads(meta)
    except json.JSONDecodeError as e:
        logger.exception(f"Invalid JSON in meta: {e}")
        raise HTTPException(
            status_code=400, detail=f"Invalid JSON in meta: {e}")
    try:
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
            if files_upload:
                for file in files_upload:
                    file_content = await file.read()
                    zip_file.writestr(file.filename, file_content)
        zip_buffer.seek(0)
        files = {
            "meta": (None, json.dumps(meta_data), "application/json"),
            "file": ("piev_epgu.zip", zip_buffer.getvalue(), "application/zip"),
        }
        response = await client.post(
            f"{SVCDEV_HOST}/api/gusmev/push",
            files=files,
            headers={"Authorization": f"Bearer {ACCESS_TKN_ESIA}"},
        )
        if response.status_code != 200:
            logger.exception(f"Error in push: {response.text}")
            raise HTTPException(
                status_code=response.status_code, detail=response.text)
        return response.json()
    except Exception as e:
        logger.exception(f"Unexpected error in push: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/push/chunked")
async def push_chunked(
    files_upload: List[UploadFile] = None,
    meta: str = Form(...),
    orderId: str = Form(...),
    chunks: int = Form(...),
    chunk: int = Form(...),
    client: httpx.AsyncClient = Depends(get_async_client),
):
    global ACCESS_TKN_ESIA, SVCDEV_HOST
    try:
        meta_data = json.loads(meta)
    except json.JSONDecodeError as e:
        logger.exception(f"Invalid JSON in meta: {e}")
        raise HTTPException(
            status_code=400, detail=f"Invalid JSON in meta: {e}")
    try:
        zip_buffer = io.BytesIO()
        archive_name = "piev_epgu"
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
            if files_upload:
                for file in files_upload:
                    file_content = await file.read()
                    if file.filename == "piev_epgu.xml":
                        validate_xml_content(file_content)
                        file.filename = f"{archive_name}.xml"
                    zip_file.writestr(file.filename, file_content)
        zip_buffer.seek(0)
        files = {
            "meta": (None, json.dumps(meta_data), "application/json"),
            "file": (f"{archive_name}.zip", zip_buffer.getvalue(), "application/zip"),
            "orderId": (None, orderId),
        }
        response = await client.post(
            f"{SVCDEV_HOST}/api/gusmev/push/chunked",
            files=files,
            headers={"Authorization": f"Bearer {ACCESS_TKN_ESIA}"},
        )
        if response.status_code != 200:
            logger.exception(f"Error in push chunked: {response.text}")
            raise HTTPException(
                status_code=response.status_code, detail=response.text)
        return response.json()
    except Exception as e:
        logger.exception(f"Unexpected error in push chunked: {e}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("SERVER_PORT", 5000)))
