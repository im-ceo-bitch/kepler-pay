import base64
import json
import secrets
import time
from dataclasses import replace
from unittest.mock import patch

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from spyderpay_core.ledger import PaymentError
from spyderpay_core.postgres.identity import OIDCVerifier
from spyderpay_core.postgres.service_v3 import sign_v3, verify_v3, load_credentials
from spyderpay_core.postgres.api_v3 import create_app
from spyderpay_core.postgres.store import Principal

ISSUER='https://id.example.test/realms/spyder'
AUD='spyderpay-api'
CLIENT='spider-wallet'
MFA='urn:spyder:test:mfa'

@pytest.fixture(scope='module')
def oidc():
    private=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    jwk=json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key()))
    jwk.update(kid='test-2026',alg='RS256',use='sig')
    config=json.dumps({'issuer':ISSUER,'audience':AUD,'client_id':CLIENT,'mfa_acr_values':[MFA],'jwks':{'keys':[jwk]}})
    def token(overrides=None,headers=None,algorithm='RS256',key=private):
        now=int(time.time())
        claims={'iss':ISSUER,'aud':AUD,'sub':'user-abc','client_id':CLIENT,'sid':'session-abc','jti':secrets.token_urlsafe(16),'iat':now-1,'exp':now+180,'auth_time':now-2,'acr':MFA}
        claims.update(overrides or {})
        return jwt.encode(claims,key,algorithm=algorithm,headers={'kid':'test-2026','typ':'at+jwt',**(headers or {})})
    return config,token

@pytest.fixture
def svc():
    secret=secrets.token_bytes(32);now=int(time.time())
    config=json.dumps([{'key_id':'ops-key','secret_b64':base64.b64encode(secret).decode(),'tenant_id':'tenant-demo','subject':'ops-actor','roles':['ops'],'not_before':now-100,'not_after':now+600}])
    return config,secret,now

class Nonces:
    def __init__(self,*_):self.used=set()
    def claim(self,k,n):
        if (k,n) in self.used:return False
        self.used.add((k,n));return True

class Rate:
    def __init__(self,*_):pass
    def claim(self,p):pass


def headers(secret,now,path,body=b'{}',idem='request-idem-0001',nonce=None,method='POST'):
    nonce=nonce or secrets.token_urlsafe(24);stamp=str(now)
    return {'x-spyder-key-id':'ops-key','x-spyder-timestamp':stamp,'x-spyder-nonce':nonce,'x-spyder-signature':sign_v3(secret,'ops-key',method,path,body,stamp,nonce,idem),'idempotency-key':idem,'content-type':'application/json'}


def test_valid_access_token(oidc):
    cfg,token=oidc;v=OIDCVerifier(cfg);i=v.verify(token())
    assert i.subject=='user-abc' and i.sid=='session-abc'
    v.require_mfa(i)

@pytest.mark.parametrize('overrides',[
    {'iss':'https://wrong.test'},{'aud':'other-api'},{'client_id':'other-client'},{'exp':1},{'iat':1},{'sid':''},{'jti':123},{'sub':None},{'auth_time':9999999999},{'acr':123},{'exp':True},
])
def test_reject_invalid_claims(oidc,overrides):
    cfg,token=oidc
    with pytest.raises(PaymentError):OIDCVerifier(cfg).verify(token(overrides))

@pytest.mark.parametrize('header',[{'typ':'JWT'},{'kid':'unknown'},{'jku':'https://bad.test/jwks'},{'jwk':{}},{'crit':['unknown']}])
def test_reject_token_header(oidc,header):
    cfg,token=oidc
    with pytest.raises(PaymentError):OIDCVerifier(cfg).verify(token(headers=header))


def test_wrong_signature(oidc):
    cfg,token=oidc; other=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    with pytest.raises(PaymentError):OIDCVerifier(cfg).verify(token(key=other))


def test_algorithm_confusion(oidc):
    cfg,token=oidc
    with pytest.raises(PaymentError):OIDCVerifier(cfg).verify(token(algorithm='HS256',key=secrets.token_bytes(32)))

@pytest.mark.parametrize('claims',[{'auth_time':1},{'acr':'password-only'},{'auth_time':None}])
def test_mfa_freshness(oidc,claims):
    cfg,token=oidc;v=OIDCVerifier(cfg);i=v.verify(token(claims))
    with pytest.raises(PaymentError,match='fresh_mfa_required'):v.require_mfa(i)


def test_config_rejects_http_issuer(oidc):
    cfg,_=oidc;c=json.loads(cfg);c['issuer']='http://id.test'
    with pytest.raises(ValueError):OIDCVerifier(json.dumps(c))


def test_config_rejects_duplicate_kid(oidc):
    cfg,_=oidc;c=json.loads(cfg);c['jwks']['keys']*=2
    with pytest.raises(ValueError):OIDCVerifier(json.dumps(c))


def test_v3_idem_bound(svc):
    cfg,sec,now=svc;p='/v3/ops/accounts';h=headers(sec,now,p);h['idempotency-key']='different-idem-0001'
    with pytest.raises(PaymentError):verify_v3('POST',p,b'{}',h,load_credentials(cfg),Nonces(),now)

@pytest.mark.parametrize('field,new',[('x-spyder-signature','0'*64),('x-spyder-key-id','unknown'),('x-spyder-nonce','z'*24),('x-spyder-timestamp','1234567890')])
def test_v3_tampering(svc,field,new):
    cfg,sec,now=svc;p='/v3/ops/accounts';h=headers(sec,now,p);h[field]=new
    with pytest.raises(PaymentError):verify_v3('POST',p,b'{}',h,load_credentials(cfg),Nonces(),now)


def test_v3_replay(svc):
    cfg,sec,now=svc;p='/v3/ops/accounts';h=headers(sec,now,p);store=Nonces();keys=load_credentials(cfg)
    assert verify_v3('POST',p,b'{}',h,keys,store,now).roles==frozenset({'ops'})
    with pytest.raises(PaymentError,match='replayed_request'):verify_v3('POST',p,b'{}',h,keys,store,now)


def test_v3_reject_expired_key(svc):
    cfg,sec,now=svc;p='/v3/ops/accounts';h=headers(sec,now,p)
    with pytest.raises(PaymentError):verify_v3('POST',p,b'{}',h,load_credentials(cfg),Nonces(),now+601)


def test_v3_service_cannot_be_customer(svc):
    cfg,*_=svc;c=json.loads(cfg);c[0]['roles']=['customer']
    with pytest.raises(ValueError):load_credentials(json.dumps(c))


class FakeProcessor:
    def transfer(self,p,source,target,amount,idem):
        if p.approval_id is None:raise PaymentError('approval_required',403)
        return {'amount':amount,'actor':p.subject}
    def create_account(self,p,owner,kind,idem):return {'owner':owner,'kind':kind}

@pytest.fixture
def client(oidc,svc):
    cfg,tok=oidc;scfg,sec,now=svc
    def resolve(_,identity):return Principal('oidc:abc','tenant-demo','server-mapped-owner',frozenset({'customer'}),identity)
    with patch('spyderpay_core.postgres.api_v3.PostgresNonceStore',Nonces),patch('spyderpay_core.postgres.api_v3.IdentityRateLimit',Rate),patch('spyderpay_core.postgres.api_v3.resolve_principal',resolve):
        with TestClient(create_app(FakeProcessor(),scfg,cfg)) as c:
            yield c,tok,sec,now


def test_old_api_not_exposed(client):
    c,*_=client
    assert c.post('/v2/transfers',json={}).status_code==404


def test_service_cannot_use_user_payment_route(client):
    c,_,sec,now=client;path='/v3/transfers';body=b'{"source":"a","target":"b","amount":1}'
    assert c.post(path,content=body,headers=headers(sec,now,path,body)).status_code==403


def test_customer_claim_cannot_be_ops(client):
    c,tok,*_=client
    r=c.post('/v3/ops/accounts',json={'owner_id':'owner','kind':'customer'},headers={'Authorization':'Bearer '+tok({'roles':['ops']}),'Idempotency-Key':'request-idem-0001'})
    assert r.status_code==403


def test_approval_required(client):
    c,tok,*_=client
    r=c.post('/v3/transfers',json={'source':'a','target':'b','amount':1},headers={'Authorization':'Bearer '+tok(),'Idempotency-Key':'request-idem-0001'})
    assert r.status_code==403


def test_approved_user_maps_server_subject(client):
    c,tok,*_=client
    r=c.post('/v3/transfers',json={'source':'a','target':'b','amount':1},headers={'Authorization':'Bearer '+tok({'sub':'external','tenant_id':'evil','role':'ops'}),'Idempotency-Key':'request-idem-0001','X-Spyder-Approval':'00000000-0000-4000-8000-000000000001'})
    assert r.status_code==200,r.text
    assert r.json()['actor']=='server-mapped-owner'


def test_reject_duplicate_headers(client):
    c,tok,*_=client;h=[('authorization','Bearer '+tok()),('authorization','Bearer '+tok()),('content-type','application/json')]
    r=c.post('/v3/transfers',content=b'{}',headers=h)
    assert r.status_code==400 and r.headers['cache-control']=='no-store'


def test_reject_duplicate_json_keys(client):
    c,tok,*_=client;r=c.post('/v3/transfers',content=b'{"amount":1,"amount":2}',headers={'authorization':'Bearer '+tok(),'content-type':'application/json'})
    assert r.status_code==400


def test_no_echo_validation(client):
    c,tok,*_=client;r=c.post('/v3/transfers',json={'source':'s','target':'t','amount':'SECRET_PII'},headers={'authorization':'Bearer '+tok(),'idempotency-key':'request-idem-0001'})
    assert r.status_code==422 and 'SECRET_PII' not in r.text


def test_query_and_encoded_target_rejected(client):
    c,*_=client
    assert c.get('/v3/accounts?x=1').status_code==400
    assert c.get('/v3/%61ccounts').status_code==400


def test_invalid_token_no_sensitive_echo(client):
    c,*_=client;r=c.get('/v3/accounts',headers={'authorization':'Bearer INVALID_SECRET'})
    assert r.status_code==401 and 'INVALID_SECRET' not in r.text and r.headers['x-request-id']


def test_sandbox_credit_disabled(client):
    c,_,sec,now=client;path='/v3/ops/sandbox/credits';body=b'{"account_id":"abc","amount":5}'
    assert c.post(path,content=body,headers=headers(sec,now,path,body)).status_code==403


def test_signed_service_request(client):
    c,_,sec,now=client;path='/v3/ops/accounts';body=b'{"owner_id":"test-owner","kind":"customer"}'
    r=c.post(path,content=body,headers=headers(sec,now,path,body));assert r.status_code==200,r.text


def test_legacy_factory_disabled_outside_test(svc):
    from spyderpay_core.postgres.api import create_app as legacy
    cfg,*_=svc
    with patch.dict('os.environ',{'SPYDERPAY_ENV':'prelicense'}):
        with pytest.raises(RuntimeError,match='legacy_v2_api_is_test_only'):
            legacy(FakeProcessor(),cfg)


def test_bank_rejects_generic_ops_and_user(client):
    c,tok,sec,now=client
    path='/v3/bank/intents';body=json.dumps({'account':str(__import__('uuid').uuid4()),'direction':'withdrawal','provider':'sandbox-bank','amount':100,'beneficiary_ref':'beneficiary-001','consent_ref':'consent-000001'}).encode()
    assert c.post(path,content=body,headers=headers(sec,now,path,body)).status_code==403
    assert c.post(path,content=body,headers={'authorization':'Bearer '+tok(),'idempotency-key':'request-idem-0001','content-type':'application/json'}).status_code==403


def test_signed_bank_role_routes_only_to_bank(oidc,svc):
    cfg,_=oidc;scfg,sec,now=svc
    key=json.loads(scfg);key[0]['roles']=['bank_ops'];scfg=json.dumps(key)
    target='/v3/bank/intents'
    body=json.dumps({'account':'00000000-0000-4000-8000-000000000001','direction':'withdrawal','provider':'sandbox-bank','amount':100,'beneficiary_ref':'beneficiary-001','consent_ref':'consent-000001'}).encode()
    class NoDB(FakeProcessor):
        pass
    with patch('spyderpay_core.postgres.api_v3.PostgresNonceStore',Nonces),patch('spyderpay_core.postgres.api_v3.IdentityRateLimit',Rate),patch('spyderpay_core.postgres.banking.Banking.create',return_value={'state':'created'}) as call:
        with TestClient(create_app(NoDB(),scfg,cfg)) as c:
            r=c.post(target,content=body,headers=headers(sec,now,target,body));assert r.status_code==200,r.text
            assert call.call_args.args[0].roles==frozenset({'bank_ops'})
            other='/v3/ops/accounts';payload=b'{"owner_id":"abc","kind":"customer"}'
            assert c.post(other,content=payload,headers=headers(sec,now,other,payload)).status_code==403


def test_v9_card_endpoints_reject_service_identity(client):
    c,_,secret,now=client;path='/v3/cards/enroll';body=json.dumps({'public_key':'04'+'a'*128}).encode()
    assert c.post(path,content=body,headers=headers(secret,now,path,body)).status_code==403


def test_v9_card_preview_is_not_payment_authorization(client):
    c,tok,*_=client;cid='00000000-0000-4000-8000-000000000001';iid='00000000-0000-4000-8000-000000000002'
    auth={'Authorization':'Bearer '+tok()}
    with patch('spyderpay_core.postgres.cards.Cards.begin_preview',return_value={'payment_authority':False,'sandbox':True}) as m:
        response=c.post(f'/v3/cards/{cid}/preview',json={'invoice_id':iid},headers=auth)
        assert response.status_code==200 and response.json()['payment_authority'] is False
        assert m.call_args.args[0].subject=='server-mapped-owner'
    assert c.post(f'/v3/cards/{cid}/pay',json={'invoice_id':iid},headers=auth).status_code==404


def test_v9_local_readiness_fails_closed_without_db(client):
    c,*_=client
    assert c.get('/health/live').status_code==200
    response=c.get('/health/ready');assert response.status_code==503 and response.json()=={'error':'not_ready'}
    assert response.headers['cache-control']=='no-store'
