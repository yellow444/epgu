"""Full FSSP request/response pipeline through real API and MCP, fake EPGU."""
import base64
import hashlib
import json

import anyio
from fastapi.testclient import TestClient
from mcp import Client
import pytest

import app as application
import capabilities
import mock_fssp_cycle as scenario
import operations
from epgu_mcp.mock_fssp_cycle import mock_server
from epgu_mcp.operations import OperationsConfig
from test_operations import (ORG, approve, bearer, bind, issue,
                             live, make_admin, signed_in, row_of, count_plans)
from test_integration_client_cycle import Spy

pytestmark = pytest.mark.real_auth
PLANS = '/v1/operations/plans'


@pytest.fixture()
def cycle(tmp_path, monkeypatch):
    from types import SimpleNamespace
    import auth
    import auth_store
    monkeypatch.setenv('AUTH_DB_FILE', str(tmp_path/'auth.sqlite3'))
    auth_store._initialized_for = None
    auth.throttle.reset()
    monkeypatch.setattr(capabilities, '_private', [])
    executor = scenario.install_mock_executor()
    live(monkeypatch)
    bind(is_ref='mock-system')
    make_admin()
    admin = TestClient(application.app)
    signed_in(admin)
    key = issue(context={'organization_ref': ORG, 'contour': 'TEST', 'is_ref':'mock-system'})
    env = SimpleNamespace(admin=admin, client=TestClient(application.app), key=key,
                          ex=executor, headers=bearer(key['secret']))
    yield env
    operations.unregister_executor(scenario.CAPABILITY)


def body(key='fssp-cycle-0001', payload=None):
    return {'capability_id':scenario.CAPABILITY, 'target':scenario.TARGET,
            'payload_b64':base64.b64encode(payload if payload is not None else scenario.synthetic_payload()).decode(),
            'attachments':[], 'idempotency_key':key}


def prepare(env, **kwargs):
    return env.client.post(PLANS, json=body(**kwargs), headers=env.headers)


def execute(env, plan):
    return env.client.post(f'{PLANS}/{plan["plan_id"]}/execute',
        json={'plan_hash':plan['plan_hash']}, headers=env.headers)


def assert_result(result):
    assert result['mock_only'] is True and result['service_final'] is True
    assert result['service'] == '60010153'
    assert result['document'] == scenario.MOCK_DOCUMENT
    assert result['document_sha256'] == hashlib.sha256(result['document'].encode()).hexdigest()


def test_complete_http_cycle_and_replay(cycle):
    preview=cycle.admin.post('/fssp/preview',json=scenario.synthetic_form())
    assert preview.status_code==200
    assert set(preview.json()['documents'])=={'req.xml','piev_epgu.xml'}
    first=prepare(cycle);assert first.status_code==201,first.text
    plan=first.json()
    assert cycle.ex.upstream.calls==[]
    review=cycle.admin.get('/v1/admin/operations/plans/'+plan['plan_id'])
    assert review.status_code==200
    assert review.headers['Cache-Control']=='no-store'
    assert base64.b64decode(review.json()['payload_b64'])==scenario.synthetic_payload()
    assert execute(cycle,plan).status_code==409
    assert cycle.ex.upstream.calls==[]
    # Machine key cannot act as the approving human.
    assert cycle.client.post('/v1/admin/operations/plans/'+plan['plan_id']+'/approve',
        json={'plan_hash':plan['plan_hash']},headers=cycle.headers).status_code==401
    assert approve(cycle,plan).status_code==200
    response=execute(cycle,plan);assert response.status_code==200,response.text
    assert_result(response.json()['result'])
    assert cycle.ex.upstream.calls==['reserve','push','status','download']
    again=execute(cycle,plan);assert again.status_code==200
    assert_result(again.json()['result'])
    assert cycle.ex.upstream.calls==['reserve','push','status','download']
    stored=cycle.client.get(PLANS+'/'+plan['plan_id'],headers=cycle.headers).json()
    assert [(s['name'],s['state']) for s in stored['steps']]==[
        (name,'completed') for name in ('reserve','push','status','download')]
    assert prepare(cycle).status_code==200
    assert count_plans()==1


@pytest.mark.parametrize('payload',[b'not json',b'{}',b'[]',b'{"secret":"CANARY"}'])
def test_invalid_form_rejected_before_plan_and_reservation(cycle,payload):
    response=prepare(cycle,payload=payload)
    assert response.status_code==400,response.text
    assert response.json()['code']=='invalid_parameter'
    assert 'CANARY' not in response.text
    assert count_plans()==0 and cycle.ex.upstream.calls==[]


@pytest.mark.parametrize('fault,completed,uncertain',[
    ('reserve',[],['reserve']),('push',['reserve'],['push']),
    ('status',['reserve','push'],['status']),
    ('download',['reserve','push','status'],['download']),
    ('bad_document',['reserve','push','status'],['download']),
    ('bad_order',['reserve','push'],['status']),
])
def test_unknown_outcome_preserves_progress_and_never_resubmits(cycle,fault,completed,uncertain):
    cycle.ex.upstream.fault=fault
    plan=prepare(cycle).json();assert approve(cycle,plan).status_code==200
    failed=execute(cycle,plan)
    assert failed.status_code==502,failed.text
    assert failed.json()['outcome']['completed_calls']==completed
    assert failed.json()['outcome']['uncertain_calls']==uncertain
    calls=list(cycle.ex.upstream.calls)
    assert execute(cycle,plan).status_code==409
    assert cycle.ex.upstream.calls==calls
    assert row_of(plan['plan_id'])['status']=='unknown'


def test_non_final_status_does_not_claim_received_result(cycle):
    cycle.ex.upstream.fault='pending'
    plan=prepare(cycle).json();approve(cycle,plan)
    response=execute(cycle,plan)
    assert response.status_code==409
    assert cycle.ex.upstream.calls==['reserve','push','status']
    assert row_of(plan['plan_id'])['status']=='failed'
    assert execute(cycle,plan).status_code==409


def test_real_mcp_to_real_http_handlers_and_the_same_document(cycle,tmp_path):
    credential=tmp_path/'integration-key';credential.write_text(cycle.key['secret'])
    credential.chmod(0o600)
    transport=Spy(TestClient(application.app,base_url='http://127.0.0.1')._transport)
    server=mock_server(OperationsConfig(base_url='http://127.0.0.1',credential_file=credential,
                                      allow_loopback_http=True,transport=transport))
    async def run():
        async with Client(server) as client:
            names={tool.name for tool in (await client.list_tools()).tools}
            assert {'plan_prepare','plan_get','plan_execute'} <= names
            assert not {'plan_approve','plan_review'} & names
            prepared=await client.call_tool('plan_prepare',body())
            assert not prepared.is_error,prepared.content
            plan=prepared.structured_content
            blocked=await client.call_tool('plan_execute',{'plan_id':plan['plan_id'],'plan_hash':plan['plan_hash']})
            assert blocked.is_error and cycle.ex.upstream.calls==[]
            assert approve(cycle,plan).status_code==200
            done=await client.call_tool('plan_execute',{'plan_id':plan['plan_id'],'plan_hash':plan['plan_hash']})
            assert not done.is_error,done.content
            fetched=await client.call_tool('plan_get',{'plan_id':plan['plan_id']})
            assert not fetched.is_error,fetched.content
            assert_result(fetched.structured_content['result'])
    anyio.run(run)
    assert cycle.ex.upstream.calls==['reserve','push','status','download']
    assert all('cookie' not in req.headers for req in transport.requests)


def test_mock_module_does_not_open_existing_fssp_service(cycle):
    assert capabilities.get('fssp.submit').machine != 'enforced'
    assert 'fssp.submit' not in operations._executors
    assert all(c.machine=='target' for c in capabilities.items() if c.id==scenario.CAPABILITY)


def test_prod_context_is_refused_by_executor_before_upstream(cycle):
    class Context:
        context=type('State',(),{'contour':'PROD'})()
    with pytest.raises(operations.NotSent):
        anyio.run(cycle.ex.run,Context(),scenario.synthetic_payload(),(),scenario.TARGET)
    assert cycle.ex.upstream.calls==[]


@pytest.mark.parametrize('change', ['wrong_service', 'bool_as_number', 'duplicate_key'])
def test_ambiguous_or_other_service_input_cannot_be_prepared(cycle,change):
    data=scenario.synthetic_form()
    if change=='wrong_service':
        data['serviceCode']='10000000352'
    elif change=='bool_as_number':
        data['includeClosed']=1
    raw=json.dumps(data).encode()
    if change=='duplicate_key':
        raw=b'{"serviceCode":"other",'+raw[1:]
    assert prepare(cycle,payload=raw).status_code==400
    assert count_plans()==0 and cycle.ex.upstream.calls==[]


def test_unexpected_validator_error_is_neutral_and_does_not_record_a_plan(cycle,monkeypatch):
    def broken(*args):
        raise RuntimeError('CANARY-INPUT-SECRET')
    monkeypatch.setattr(cycle.ex,'validate_input',broken)
    response=prepare(cycle)
    assert response.status_code==400 and 'CANARY' not in response.text
    assert count_plans()==0 and cycle.ex.upstream.calls==[]


def test_async_preflight_cannot_be_registered(cycle):
    class Bad(scenario.FsspMockExecutor):
        async def validate_input(self,*args):
            pass
    with pytest.raises(ValueError,match='validate_input'):
        operations.register_executor(Bad())


def test_preflight_return_value_is_not_an_implicit_approval(cycle,monkeypatch):
    monkeypatch.setattr(cycle.ex,'validate_input',lambda *args: True)
    assert prepare(cycle).status_code==400
    assert count_plans()==0 and cycle.ex.upstream.calls==[]


@pytest.mark.parametrize('fault',['push','download'])
def test_mcp_reports_unknown_without_retrying_the_fssp_request(cycle,tmp_path,fault):
    cycle.ex.upstream.fault=fault
    credential=tmp_path/'credential';credential.write_text(cycle.key['secret']);credential.chmod(0o600)
    transport=Spy(TestClient(application.app,base_url='http://127.0.0.1')._transport)
    server=mock_server(OperationsConfig(base_url='http://127.0.0.1',credential_file=credential,
        allow_loopback_http=True,transport=transport))
    async def run():
        async with Client(server) as client:
            prepared=await client.call_tool('plan_prepare',body())
            assert not prepared.is_error
            plan=prepared.structured_content
            approve(cycle,plan)
            failed=await client.call_tool('plan_execute',{'plan_id':plan['plan_id'],'plan_hash':plan['plan_hash']})
            assert failed.is_error
            error=json.loads(failed.content[0].text)['error']
            assert error['code']=='outcome_unknown' and error['uncertain_calls']==[fault]
            calls=list(cycle.ex.upstream.calls)
            assert error['completed_calls']==calls[:-1]
            again=await client.call_tool('plan_execute',{'plan_id':plan['plan_id'],'plan_hash':plan['plan_hash']})
            assert again.is_error and cycle.ex.upstream.calls==calls
            stored=await client.call_tool('plan_get',{'plan_id':plan['plan_id']})
            assert not stored.is_error and stored.structured_content['status']=='unknown'
            assert cycle.key['secret'] not in str(failed.content)
    anyio.run(run)
