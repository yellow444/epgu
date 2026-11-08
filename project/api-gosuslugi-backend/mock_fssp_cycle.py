"""Opt-in synthetic FSSP cycle. No sockets, production addresses or real keys.

Uses the existing request builder, official request XSD, ZIP and SDK transports.
The response document below is OUR MOCK FORMAT, not an official FSSP response.
Nothing imports or registers this module from the normal application startup.
"""
from __future__ import annotations

from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
import hashlib
import io
import json
import zipfile

import httpx
from epgu.client import EpguClient
from epgu.const import Env
from epgu.services import fssp
from lxml import etree
from pydantic import ValidationError

import capabilities
from fssp_api import FsspPayload, build_archive, build_checked
import operations

CAPABILITY = 'mock.fssp.60010153.cycle'
TARGET = 'mock-fssp-60010153'
SERVICE = '60010153'
MOCK_ENV = Env('https://mock-esia.invalid', 'https://mock-epgu.invalid')
MOMENT = datetime(2026, 11, 8, 12, tzinfo=timezone.utc)
MOCK_DOCUMENT = '<mock-fssp-result service="60010153"><proceedingsFound>false</proceedingsFound></mock-fssp-result>'
RESULT_FIELDS = {'mock_only': bool, 'service': str, 'order_id': int, 'service_final': bool,
                 'document_name': str, 'document_sha256': str, 'document': str}


def synthetic_form():
    """The single fixed synthetic identity permitted by this demo."""
    return {'serviceCode': SERVICE, 'region': '45000000000', 'side': '1',
            'representation': 'organization', 'includeClosed': True,
            'applicant': {'fullName': 'Петров Пётр Петрович', 'gender': '1',
                          'birthDate': '1985-03-04', 'snils': '112-233-445 95'},
            'organization': {'name': 'ООО «Ромашка»', 'address': '101000, г. Москва, ул. Примерная, д. 1',
                             'inn': '7700000016', 'ogrn': '1027700000019'}}


def synthetic_payload():
    return json.dumps(synthetic_form(), ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()


class MockUpstream:
    """SDK-visible HTTP fixture; only four exact protocol requests are accepted."""
    def __init__(self, fault=None):
        if fault not in (None, 'reserve', 'push', 'status', 'download', 'pending', 'bad_document', 'bad_order'):
            raise ValueError('unknown mock fault')
        self.fault = fault
        self.calls = []
        self.order_id = 3500290327
        self.submitted_documents = {}

    def __call__(self, request):
        if request.url.host != 'mock-epgu.invalid' or request.url.scheme != 'https':
            raise AssertionError('mock upstream refuses other origins')
        path = request.url.path
        if path == '/api/gusmev/order' and request.method == 'POST':
            stage = 'reserve'
        elif path == '/api/gusmev/push/chunked' and request.method == 'POST':
            stage = 'push'
        elif path == f'/api/gusmev/order/{self.order_id}' and request.method == 'POST':
            stage = 'status'
        elif path == '/api/gusmev/files/download/71/Response' and request.method == 'GET':
            stage = 'download'
        else:
            raise AssertionError('unexpected mock request')
        self.calls.append(stage)
        if self.fault == stage:
            raise httpx.ReadError('synthetic lost response', request=request)
        if stage == 'reserve':
            self.order_id = 3500290326 + self.calls.count('reserve')
            assert json.loads(request.content) == {'region': '45000000000', 'serviceCode': SERVICE, 'targetCode': '-'+SERVICE}
            return httpx.Response(200, json={'orderId': self.order_id})
        if stage == 'push':
            assert self.calls[-2:] == ['reserve', 'push']
            message = BytesParser(policy=policy.default).parsebytes(
                b'Content-Type: '+request.headers['content-type'].encode()+b'\r\n\r\n'+request.content)
            fields = {p.get_param('name', header='content-disposition'): p.get_payload(decode=True)
                      for p in message.iter_parts()}
            assert set(fields) == {'meta', 'file', 'orderId'}
            assert fields['orderId'] == str(self.order_id).encode()
            assert json.loads(fields['meta']) == {'region': '45000000000', 'serviceCode': SERVICE, 'targetCode': '-'+SERVICE}
            with zipfile.ZipFile(io.BytesIO(fields['file'])) as archive:
                assert set(archive.namelist()) == {'req.xml', 'piev_epgu.xml'}
                self.submitted_documents = {name: archive.read(name) for name in archive.namelist()}
            node = etree.fromstring(self.submitted_documents['piev_epgu.xml'])
            assert node.find('.//{*}ExternalKey').text == str(self.order_id)
            return httpx.Response(200, json={'orderId': self.order_id})
        if stage == 'status':
            assert self.submitted_documents
            return httpx.Response(200, json={'order': json.dumps({
                'id': self.order_id+1 if self.fault == 'bad_order' else self.order_id,
                'currentStatusHistoryId': 71,
                'currentStatusHistory': {'statusId': 3, 'title': 'Mock completed',
                                         'finalStatus': self.fault != 'pending'},
                'orderResponseFiles': [{'fileName': 'mock-result.xml',
                                       'link': 'terrabyte://mock/mock-result.xml/Response'}]})})
        assert dict(request.url.params) == {'mnemonic': 'mock-result.xml', 'eserviceCode': SERVICE}
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('mock-result.xml', 'not the expected fixture' if self.fault == 'bad_document' else MOCK_DOCUMENT)
        return httpx.Response(200, content=buffer.getvalue(), headers={'Content-Type': 'application/zip'})


class FsspMockExecutor:
    capability_id = CAPABILITY
    external_calls = (
        operations.ExternalCall('reserve', ('reserves_number',)),
        operations.ExternalCall('push', ('external_write',)),
        operations.ExternalCall('status', ()),
        operations.ExternalCall('download', ()),
    )

    def __init__(self, fault=None):
        self.upstream = MockUpstream(fault)

    def validate_input(self, payload, attachments, target):
        if target != TARGET or attachments or len(payload) > 8192:
            raise operations.InvalidRequest('нужен mock-FSSP target без вложений')
        try:
            def unique(pairs):
                result = dict(pairs)
                if len(result) != len(pairs):
                    raise ValueError('duplicate JSON keys')
                return result
            data = json.loads(payload, object_pairs_hook=unique)
            model = FsspPayload.model_validate_json(payload, strict=True)
            if data != synthetic_form():
                raise ValueError('only the fixed synthetic form is supported')
            build_checked(model, order_id=1, moment=MOMENT, environment=fssp.Environment.SVCDEV)
        except (ValueError, ValidationError, fssp.FsspContractError):
            raise operations.InvalidRequest('нужна корректная фиксированная синтетическая форма 60010153') from None

    async def run(self, ctx, payload, attachments, target):
        try:
            self.validate_input(payload, attachments, target)
        except operations.InvalidRequest:
            raise operations.NotSent('invalid_mock_form') from None
        if ctx.context.contour != 'TEST':
            raise operations.NotSent('mock_requires_test_context')
        form = FsspPayload.model_validate_json(payload)
        meta = {'region': form.region, 'serviceCode': SERVICE, 'targetCode': '-'+SERVICE}
        # Transport and addresses are constructed here, never supplied by caller.
        with httpx.Client(transport=httpx.MockTransport(self.upstream), trust_env=False,
                          follow_redirects=False) as http:
            api = EpguClient('synthetic-mock-token', env=MOCK_ENV, client=http)
            ctx.start_call('reserve')
            order_id = api.create_order(meta)
            ctx.mark_done('reserve', str(order_id))
            documents = build_checked(form, order_id=order_id, moment=MOMENT, environment=fssp.Environment.SVCDEV)
            archive = build_archive(documents)
            if len(archive) >= 5_000_000:
                raise operations.NotSent('mock_requires_one_chunk')
            ctx.start_call('push')
            api.push_chunked(meta, archive, order_id=order_id)
            ctx.mark_done('push', str(order_id))
            ctx.start_call('status')
            order = api.order_info(order_id)
            if order.order_id != order_id:
                raise ValueError('mock order mismatch')
            ctx.mark_done('status', str(order.status_history_id))
            if not order.final_status:
                raise operations.NotSent('mock_result_not_ready')
            if (order.status_history_id != 71 or len(order.response_files) != 1 or
                    order.response_files[0].link != 'terrabyte://mock/mock-result.xml/Response'):
                raise operations.NotSent('unexpected_mock_result_reference')
            ctx.start_call('download')
            result = api.download_file(order.response_files[0].link,
                                       status_history_id=order.status_history_id, eservice_code=SERVICE)
            if len(result) > 65536:
                raise ValueError('oversized mock response')
            with zipfile.ZipFile(io.BytesIO(result)) as zipped:
                if zipped.namelist() != ['mock-result.xml']:
                    raise ValueError('unexpected mock ZIP entries')
                with zipped.open('mock-result.xml') as document:
                    content = document.read(1025)
            if content != MOCK_DOCUMENT.encode():
                raise ValueError('unexpected mock document')
            digest = hashlib.sha256(content).hexdigest()
            ctx.mark_done('download', digest)
            return {'mock_only': True, 'service': SERVICE, 'order_id': order_id,
                    'service_final': True, 'document_name': 'mock-result.xml',
                    'document_sha256': digest, 'document': content.decode()}


def install_mock_executor(*, fault=None):
    """Explicit demo/test opt-in. Never used by app.py or the standard MCP CLI."""
    if capabilities.get(CAPABILITY) is None:
        capabilities.register(capabilities.Capability(
            id=CAPABILITY, title='MOCK ONLY: synthetic FSSP 60010153 complete cycle',
            effect='write_external', edition='mock', machine='target',
            scopes=('external:execute',), side_effects=('reserves_number', 'external_write'),
            notes='Synthetic fixture only. Not TEST/PROD admission or a production executor.'))
    executor = FsspMockExecutor(fault)
    operations.register_executor(executor)
    return executor
