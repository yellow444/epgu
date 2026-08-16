"""Репетиция Госпочты: полный круг без обращения к ЕПГУ.

Нужна там, где настоящего доступа ещё нет, а проверить хочется всё: построение
адресов, HTTP, заголовок с маркером, разбор ответов, хранилище, планировщик.
Двойник отвечает примерами из «Спецификации API ГЭПС» версии 1.0, отличие от
ЕПГУ ровно одно - кто на том конце.

Запуск (скрипт работает внутри контейнера, рядом с приложением)::

    docker compose cp scripts/geps_rehearsal.py api:/tmp/geps_rehearsal.py
    docker compose exec -u app api python /tmp/geps_rehearsal.py

Скрипт пишет в то же хранилище, что и стенд, поэтому после репетиции данные
надо убрать: docker compose exec -u app api python -c "import geps_store; geps_store.clear()"

Настоящий прогон этим не заменяется. Для него нужны API-Key организации из
техпортала, сертификат организации с закрытым ключом в хранилище контейнера и
роль руководителя или администратора на ЕПГУ.
"""
import asyncio, json, sys, threading, time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, "/app")

THREAD = "6c7a5efd-2a8c-11f0-8080-808080808080"
MESSAGE = "91160bbb-f997-11ef-8080-808080808080"
ATTACHMENT = "61d94a0a-66ce-11ef-8080-808080808080"
TASK = "428bee90-dfef-11f0-a42e-59882f7a740f"
BEARER = "rehearsal-bearer"

seen = []


class Epgu(BaseHTTPRequestHandler):
    """Двойник ЕПГУ: четыре метода ГЭПС, ответы из примеров спецификации."""

    def log_message(self, *args):
        pass

    def _send(self, code, payload, ctype="application/json", headers=None):
        body = payload if isinstance(payload, bytes) else json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _check(self):
        auth = self.headers.get("Authorization", "")
        seen.append((self.command, self.path.split("?")[0], auth == f"Bearer {BEARER}"))
        if auth != f"Bearer {BEARER}":
            self._send(401, {"code": "unauthorized"})
            return False
        return True

    def do_POST(self):
        if not self._check():
            return
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length) or b"{}")
        assert set(payload) == {"startDateTime", "endDateTime", "statusFilter"}, payload
        self._send(200, {"searchTaskUuid": TASK})

    def do_GET(self):
        if not self._check():
            return
        path = self.path.split("?")[0]
        if path.endswith("/search/" + TASK):
            self._send(200, {
                "searchTaskStatus": "COMPLETED", "offset": 0, "limit": 1000, "total": 2,
                "messageList": [
                    {"threadUuid": THREAD, "messageUuid": MESSAGE, "feedTitle": "ФССП",
                     "feedSubtitle": "Извещение о возбуждении исполнительного производства",
                     "isRead": False, "createDate": "2026-08-16T10:20:00.000+03:00"},
                    {"threadUuid": THREAD, "messageUuid": ATTACHMENT, "feedTitle": "МВД",
                     "feedSubtitle": "Штраф оплачен", "isRead": True,
                     "createDate": "2026-08-16T18:05:00.000+03:00"},
                ]})
        elif "/message/" in path:
            uuid = path.rsplit("/", 1)[-1]
            self._send(200, {
                "threadUuid": THREAD, "messageUuid": uuid, "isRead": False,
                "createDate": "2026-08-16T10:20:00.000+03:00",
                "text": '<div class="mail-body-content"><p>Возбуждено исполнительное '
                        'производство № 12345/26/77001-ИП</p><br>Срок для добровольного '
                        'исполнения <b>5 дней</b></div>',
                "params": {"feed_title": "ФССП", "feed_subtitle": "Извещение о возбуждении",
                           "inner_title": "ФССП России", "uin": "32277001260012345678"},
                "attachmentList": [
                    {"messageUuid": uuid, "attachmentUuid": ATTACHMENT,
                     "fileName": "postanovlenie.pdf", "fileSize": 15, "mimeType": "application/pdf",
                     "signed": True, "statusMnemonic": "READY", "statusDescription": "Файл доступен"}],
                "statusList": [
                    {"mnemonic": "ACCEPT_USER_NOT_AGREEMENT", "description": "Доставлено в ГЭПС",
                     "createDate": "2026-08-16T10:20:00.000+03:00"},
                    {"mnemonic": "READ", "description": "Прочитано", "originatorUserName": "Иванов И.И.",
                     "createDate": "2026-08-16T11:00:00.000+03:00"}]})
        elif "/attachment/" in path:
            kind = path.rsplit("/", 1)[-1]
            body = b"SIGNATURE-BYTES" if kind == "sig" else b"%PDF-1.4 real"
            self._send(200, body, "application/pdf",
                       {"Content-Disposition": 'attachment; filename="../postanovlenie.pdf"'})
        else:
            self._send(404, {"code": "not-found"})


server = ThreadingHTTPServer(("127.0.0.1", 9099), Epgu)
threading.Thread(target=server.serve_forever, daemon=True).start()
time.sleep(0.3)

import app as app_module
import geps_scheduler, geps_store, geps_quota

geps_store.clear()
geps_quota.clear()
app_module.SVCDEV_HOST = "http://127.0.0.1:9099"
app_module.ACCESS_TKN_ESIA = BEARER
app_module.ACCESS_TKN_EXP = int(time.time()) + 3600

MSK = timezone(timedelta(hours=3))
now = datetime.now(MSK)


async def main():
    print("== такт 1: заказ списка ==")
    gateway = await app_module._geps_gateway()
    report = await geps_scheduler.tick(gateway, now)
    print("   заказано:", report["ordered"], "| попыток осталось:",
          report["quota"]["limits"]["search"]["remaining"])
    await gateway.aclose()

    print("== такт 2 через час: список готов ==")
    gateway = await app_module._geps_gateway()
    report = await geps_scheduler.tick(gateway, now + timedelta(hours=2))
    print("   получено списков:", report["ready"], "| новых уведомлений:", report["new_messages"],
          "| карточек:", report["details"])
    await gateway.aclose()

    print("== вложение ==")
    from epgu import geps
    import httpx
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(
            app_module.SVCDEV_HOST + geps.attachment_path(MESSAGE, ATTACHMENT, "file"),
            headers={"Authorization": f"Bearer {BEARER}"})
        name = geps.file_name_from_headers(resp.headers)
        saved = geps_store.save_attachment(MESSAGE, ATTACHMENT, resp.content, name)
    print("   имя из заголовка очищено:", name, "| сохранено:", saved["path"], saved["size"], "байт")

    print("== что в хранилище ==")
    print("  ", json.dumps(geps_store.counts(), ensure_ascii=False))
    card = geps_store.get_message(MESSAGE)
    print("   отправитель:", card["sender"], "| тема:", card["subject"])
    print("   статусов:", len(card["detail"]["statuses"]), "| вложений:", len(card["attachments"]))

    print("== обращения, которые увидел двойник ==")
    for method, path, ok in seen:
        print("   %-4s %-70s маркер принят: %s" % (method, path[-70:], ok))

asyncio.run(main())
server.shutdown()
