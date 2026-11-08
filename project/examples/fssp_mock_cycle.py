"""Run two complete synthetic service cycles: HTTP and stdio MCP.

The only listening socket is our own ephemeral 127.0.0.1 backend. EPGU calls
are intercepted by a fixed MockTransport. No Docker, mail, CSP or real identity.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import sys
import threading
import time


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True,help='fresh directory outside any Git checkout')
    args=parser.parse_args()
    output=args.output.resolve()
    if any((p/'.git').exists() for p in (output,*output.parents)):
        parser.error('output must be outside a Git checkout')
    output.mkdir(parents=True,exist_ok=True)
    if any(output.iterdir()):
        parser.error('output directory must be empty')
    project=Path(__file__).resolve().parents[1]
    paths=[project/'api-gosuslugi-backend',project/'python-epgu/src',
           project/'knowledge/src',project/'mcp-server/src']
    for key in list(os.environ):
        if key.upper().startswith(('EPGU_','ESIA_','TESTEP_','AUTH_','MAIL_','GEPS_','TENANCY_',
                                  'SETTINGS_','CERT_','KEYS_','SECRET_','INBOUND_','ACCESS_','SMTP_','IMAP_')) or key.upper() in ('KEYPIN','APIKEY','DEBUG','PRODUCTION'):
            os.environ.pop(key)
    os.environ.update(PYTHON_DOTENV_DISABLED='1',PYTHONDONTWRITEBYTECODE='1',PYTHONUTF8='1',
        AUTH_DB_FILE=str(output/'auth.sqlite3'),SETTINGS_FILE=str(output/'settings.env'),
        GEPS_STORE_DIR=str(output/'geps'),CERT_INBOX_DIR=str(output/'certs'),KEYS_DIR=str(output/'keys'),
        INBOUND_DIR=str(output/'inbound'),MAIL_INBOX_DIR=str(output/'mail'),
        TENANCY_DIR=str(output/'tenancy'),MAIL_STATE_FILE=str(output/'mail-state.json'),
        MAIL_AUTO_FILE=str(output/'mail-auto.json'),SUPPORT_REQUESTS_FILE=str(output/'support.json'),
        EPGU_ADDON_LICENSE_STORE=str(output/'entered-license.json'),
        XML_ROOT=str(project/'api-gosuslugi-backend/xml'),
        esia_host='https://esia-portal1.test.gosuslugi.ru',
        svcdev_host='https://svcdev-gostapi.test.gosuslugi.ru',MAIL_AUTO_ENABLED='0',DEBUG='0')
    sys.path[:0]=[str(p) for p in paths]
    import anyio
    import httpx
    import uvicorn
    from mcp import Client, StdioServerParameters
    import app
    import auth
    import operator_context
    import mock_fssp_cycle as scenario

    # This process is fresh, with all application state in the empty directory.
    thumbprint='AB'*20
    app.CERTIFICATES={thumbprint:object()}
    app.CURRENT_CERT_ID=thumbprint
    app.ACCESS_TKN_ESIA=''
    executor=scenario.install_mock_executor()
    password=secrets.token_urlsafe(24)
    admin_account=auth.create_account('mock-operator',password,installation_admin=True,source='cli')
    operator_context.set_binding('mock-organization','TEST',thumbprint,is_ref='mock-system',by=admin_account.id)
    listener=socket.socket()
    listener.bind(('127.0.0.1',0))
    port=listener.getsockname()[1]
    assert port not in (6081,6082)
    server=uvicorn.Server(uvicorn.Config(app.app,host='127.0.0.1',port=port,
                                      lifespan='off',log_level='warning',access_log=False))
    thread=threading.Thread(target=lambda:server.run(sockets=[listener]),daemon=True)
    thread.start()
    deadline=time.monotonic()+15
    while not server.started:
        if time.monotonic()>deadline or not thread.is_alive():
            server.should_exit=True
            raise RuntimeError('isolated backend did not start')
        time.sleep(.02)
    origin=f'http://127.0.0.1:{port}'
    credential=output/'integration-credential'
    receipt={'mock_only':True,'service':'60010153','approval_actor':'simulated_human_http_session',
             'backend':origin,'private_addons_installed':bool(getattr(app,'multiorg_extension',None)),
             'upstream':'in-memory HTTP MockTransport; no EPGU sockets','runs':{}}
    def check(response,status=200):
        if response.status_code!=status:
            raise RuntimeError(f'local API returned {response.status_code}; expected {status}')
        return response.json()
    def request_body(key):
        return {'capability_id':scenario.CAPABILITY,'target':scenario.TARGET,
                'payload_b64':base64.b64encode(scenario.synthetic_payload()).decode(),
                'attachments':[],'idempotency_key':key}
    def human_approve(admin,plan):
        review=check(admin.get('/v1/admin/operations/plans/'+plan['plan_id']))
        assert base64.b64decode(review['payload_b64'])==scenario.synthetic_payload()
        assert review['hash_verified'] and review['plan_hash']==plan['plan_hash']
        check(admin.post('/v1/admin/operations/plans/'+plan['plan_id']+'/approve',
                         json={'plan_hash':plan['plan_hash']}))
    def record(name,plan,offset):
        result=plan['result'];document=result['document'].encode()
        assert result['mock_only'] and result['service_final']
        assert result['document_sha256']==hashlib.sha256(document).hexdigest()
        assert document==scenario.MOCK_DOCUMENT.encode()
        folder=output/name;folder.mkdir()
        for filename,content in executor.upstream.submitted_documents.items():
            (folder/filename).write_bytes(content)
        (folder/'mock-result.xml').write_bytes(document)
        calls=executor.upstream.calls[offset:]
        assert calls==['reserve','push','status','download']
        assert all(s['state']=='completed' for s in plan['steps'])
        receipt['runs'][name]={'plan_id':plan['plan_id'],'status':plan['status'],
            'order_id':result['order_id'],'upstream_calls':calls,
            'document_sha256':result['document_sha256'],'document_bytes':len(document),
            'request_files':{k:len(v) for k,v in executor.upstream.submitted_documents.items()},
            'journal':[{'name':s['name'],'state':s['state']} for s in plan['steps']]}
    try:
        with httpx.Client(base_url=origin,trust_env=False,follow_redirects=False,timeout=30) as admin:
            check(admin.post('/auth/login',json={'login':'mock-operator','password':password}))
            key=check(admin.post('/v1/admin/integrations',json={'name':'Synthetic mock cycle',
                'scopes':['external:prepare','external:execute'],
                'context':{'organization_ref':'mock-organization','contour':'TEST','is_ref':'mock-system'}}))
            credential.write_text(key['secret'],encoding='ascii');credential.chmod(0o600)
            headers={'Authorization':'Bearer '+key['secret']}
            check(admin.post('/fssp/preview',json=scenario.synthetic_form()))
            with httpx.Client(base_url=origin,headers=headers,trust_env=False,timeout=30) as machine:
                plan=check(machine.post('/v1/operations/plans',json=request_body('http-fssp-demo-0001')),201)
                assert not executor.upstream.calls
                assert machine.post('/v1/operations/plans/'+plan['plan_id']+'/execute',
                    json={'plan_hash':plan['plan_hash']}).status_code==409
                human_approve(admin,plan)
                check(machine.post('/v1/operations/plans/'+plan['plan_id']+'/execute',json={'plan_hash':plan['plan_hash']}))
                stored=check(machine.get('/v1/operations/plans/'+plan['plan_id']))
                record('http',stored,0)
                check(machine.post('/v1/operations/plans/'+plan['plan_id']+'/execute',json={'plan_hash':plan['plan_hash']}))
                assert len(executor.upstream.calls)==4

            async def mcp_cycle():
                child_env={k:os.environ[k] for k in ('PATH','SYSTEMROOT','WINDIR','COMSPEC','PATHEXT','TEMP','TMP') if k in os.environ}
                child_env.update(PYTHONPATH=os.pathsep.join(str(p) for p in paths),
                    PYTHONUTF8='1',PYTHONDONTWRITEBYTECODE='1',PYTHON_DOTENV_DISABLED='1',
                    EPGU_MOCK_BACKEND_URL=origin,EPGU_MOCK_CREDENTIAL_FILE=str(credential))
                params=StdioServerParameters(command=sys.executable,
                    args=['-m','epgu_mcp.mock_fssp_cycle'],env=child_env)
                async with Client(params,mode='auto',read_timeout_seconds=30) as client:
                    names={tool.name for tool in (await client.list_tools()).tools}
                    assert {'plan_prepare','plan_get','plan_execute'}<=names
                    assert not {'plan_approve','plan_review'}&names
                    async def tool(name,args):
                        response=await client.call_tool(name,args)
                        if response.is_error:
                            raise RuntimeError('MCP demo tool failed: '+name)
                        return response.structured_content
                    plan=await tool('plan_prepare',request_body('mcp-fssp-demo-0001'))
                    assert len(executor.upstream.calls)==4
                    human_approve(admin,plan)
                    await tool('plan_execute',{'plan_id':plan['plan_id'],'plan_hash':plan['plan_hash']})
                    stored=await tool('plan_get',{'plan_id':plan['plan_id']})
                    record('mcp',stored,4)
                    await tool('plan_execute',{'plan_id':plan['plan_id'],'plan_hash':plan['plan_hash']})
                    assert len(executor.upstream.calls)==8
            anyio.run(mcp_cycle)
            assert check(admin.post('/v1/admin/integrations/'+key['id']+'/revoke'))['revoked']
            with httpx.Client(base_url=origin,headers=headers,trust_env=False,timeout=30) as revoked:
                assert revoked.get('/v1/operations/plans/'+plan['plan_id']).status_code==401
            check(admin.post('/auth/logout'))
            receipt['integration_revoked']=True
    finally:
        server.should_exit=True
        thread.join(10)
        listener.close()
        credential.unlink(missing_ok=True)
    assert not thread.is_alive()
    receipt['credential_removed']=not credential.exists()
    receipt['backend_stopped']=True
    assert receipt['runs']['http']['document_sha256']==receipt['runs']['mcp']['document_sha256']
    (output/'receipt.json').write_text(json.dumps(receipt,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(receipt,ensure_ascii=False,indent=2))


if __name__=='__main__':
    main()
