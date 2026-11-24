import json
import time
from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient
from spyderpay_core.release import SCHEMA_VERSION,VERSION
from spyderpay_core.postgres.ops.monitor import validate_report,FIELDS,headers as monitor_headers
from spyderpay_core.postgres.service_v3 import verify_v3,load_credentials
from spyderpay_core.postgres.api_v3 import create_app
from spyderpay_core.postgres.operations import classify_snapshot
from test_security_v3 import oidc,svc,Nonces,Rate,FakeProcessor,headers

def report():return {**classify_snapshot(SCHEMA_VERSION,dict.fromkeys(FIELDS,0)),'financial_traffic_paused':False,'gate_generation':0}

def test_monitor_health():
    assert validate_report(report())['severity']=='ok'
    r=report();r['financial_traffic_paused']=True
    assert validate_report(r)['severity']=='critical'
    r=report();r['counts']['invalid_posting_scope']=1;r['status']='critical'
    assert validate_report(r)['severity']=='critical'

@pytest.mark.parametrize('change',['missing','negative','bool','bad_status','live','wrong_schema','wrong_version','extra'])
def test_monitor_report_fails_closed(change):
    r=report()
    if change=='missing':del r['counts']['invalid_journals']
    elif change=='negative':r['counts']['stale_dispatch']=-1
    elif change=='bool':r['counts']['invalid_journals']=True
    elif change=='bad_status':r['status']='degraded'
    elif change=='live':r['real_money']=True
    elif change=='wrong_schema':r['schema']+=1
    elif change=='wrong_version':r['version']='other'
    else:r['secret']='do not return'
    with pytest.raises(ValueError):validate_report(r)

def test_monitor_signed_scope(oidc,svc):
    cfg,_=oidc;scfg,secret,now=svc;c=json.loads(scfg);c[0]['roles']=['monitor'];scfg=json.dumps(c)
    h=monitor_headers('ops-key',secret,stamp=now)
    assert verify_v3('GET','/v3/ops/health',b'',h,load_credentials(scfg),Nonces(),now).roles==frozenset({'monitor'})
    with patch('spyderpay_core.postgres.api_v3.PostgresNonceStore',Nonces),patch('spyderpay_core.postgres.api_v3.IdentityRateLimit',Rate),patch('spyderpay_core.postgres.operations.operational_snapshot',return_value=report()) as mock:
        with TestClient(create_app(FakeProcessor(),scfg,cfg)) as client:
            assert client.get('/v3/ops/health',headers=h).status_code==200
            assert mock.call_args.args[1].roles==frozenset({'monitor'})
            for route in ('/v3/ops/reconciliation','/v3/accounts','/v3/bank/reconciliation','/v3/clearing/reconciliation'):
                assert client.get(route,headers=headers(secret,now,route,b'',method='GET')).status_code==403
            route='/v3/ops/accounts';body=b'{"owner_id":"abc","kind":"customer"}'
            assert client.post(route,content=body,headers=headers(secret,now,route,body)).status_code==403
