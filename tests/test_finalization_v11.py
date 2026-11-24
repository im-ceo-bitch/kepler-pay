import base64,json,time,uuid
from datetime import datetime,timezone,timedelta
from pathlib import Path
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from spyderpay_core.ledger import PaymentError
from spyderpay_core.postgres.provider_evidence import ProviderEvidence,AUDIENCE
from spyderpay_core.postgres.compliance import evaluate
from spyderpay_core.postgres.ops.restore_drill import target,validate_empty,private_file,copy_verified
from spyderpay_core.postgres.ops.backup import publish
from spyderpay_core.postgres.customer_receipt import customer_receipt
from spyderpay_core.postgres.store import Principal
from test_pos_recovery_v7 import counts

@pytest.fixture
def provider():
    now=int(time.time());key=Ed25519PrivateKey.generate();account=str(uuid.uuid4())
    cfg={'keys':[{'issuer':'partner-test','kid':'key-001','public_b64':base64.b64encode(key.public_key().public_bytes_raw()).decode(),'not_before':now-100,'not_after':now+1000}]}
    claims={'iss':'partner-test','aud':AUDIENCE,'iat':now-1,'exp':now+60,'jti':'event-0001','tenant':'tenant-alpha','account':account,'kyc':'verified','screening':'clear','tier':'standard','evidence_digest':'a'*64}
    args={k:claims[k] for k in ('tenant','account','kyc','screening','tier')}
    def sign(changes=None,header=None,k=key):
        return jwt.encode({**claims,**(changes or {})},k,algorithm='EdDSA',headers={'kid':'key-001','typ':'spyderpay-screening+jwt',**(header or {})})
    return ProviderEvidence(json.dumps(cfg)),sign,args,now,cfg

def test_evidence_valid(provider):
    p,sign,args,now,_=provider;ref=p.verify(sign(),**args,now=now)
    assert ref.startswith('provider:') and len(ref)==73
    assert p.verify(sign({'evidence_digest':'b'*64}),**args,now=now)==ref
    assert p.verify(sign({'jti':'event-0002'}),**args,now=now)!=ref

@pytest.mark.parametrize('changes',[{'iss':'other-issuer'},{'aud':'other-audience'},{'tenant':'tenant-other'},{'account':'00000000-0000-0000-0000-000000000000'},{'kyc':'pending'},{'screening':'hit'},{'tier':'enhanced'},{'jti':'x'},{'evidence_digest':'invalid'},{'extra':'PII'}])
def test_evidence_mismatches(provider,changes):
    p,sign,args,now,_=provider
    with pytest.raises(PaymentError,match='invalid_provider_evidence'):p.verify(sign(changes),**args,now=now)

@pytest.mark.parametrize('change',[{'iat':True},{'exp':False},{'iat':0},{'exp':0}])
def test_evidence_invalid_time(provider,change):
    p,sign,args,now,_=provider
    with pytest.raises(PaymentError):p.verify(sign(change),**args,now=now)

def test_evidence_expiry_future_and_key(provider):
    p,sign,args,now,_=provider
    for changes in ({'exp':now},{'iat':now+1},{'exp':now+901}):
        with pytest.raises(PaymentError):p.verify(sign(changes),**args,now=now)
    for token in (sign(header={'kid':'wrong'}),sign(header={'typ':'JWT'}),sign(header={'jku':'https://example.test'}),sign(k=Ed25519PrivateKey.generate()),'bad',None):
        with pytest.raises(PaymentError):p.verify(token,**args,now=now)

def test_evidence_invalid_config(provider):
    _,_,_,_,cfg=provider
    with pytest.raises(ValueError):ProviderEvidence(json.dumps({'keys':cfg['keys']*2}))
    with pytest.raises(ValueError):ProviderEvidence(json.dumps({'keys':[]}))

@pytest.mark.parametrize('change',[{'decided_at':None},{'created_at':None},{'tier':'invalid'},{'decided_at':datetime(2025,1,1,tzinfo=timezone.utc)},{'decided_at':datetime(2026,1,1)}])
def test_risk_malformed_review_denies(change):
    now=datetime(2026,1,1,tzinfo=timezone.utc);review={'decision':'approved','kyc':'verified','screening':'clear','tier':'standard','created_at':now-timedelta(minutes=2),'decided_at':now-timedelta(minutes=1),**change}
    with pytest.raises(PaymentError):evaluate(review,1,0,0,now)

@pytest.mark.parametrize('service,db',[('production','production'),('x sslmode=disable','sp_restore_test1234'),('local','sp_restore_x'),('local','sp_restore_abc;drop')])
def test_restore_target_rejects(service,db):
    with pytest.raises(ValueError):target(service,db)

def test_restore_target_valid():assert 'sslmode=verify-full' in target('restore-lab','sp_restore_test1234')

@pytest.mark.parametrize('change',[{'superuser':True},{'owner':False},{'relations':1},{'routines':1},{'extra_schemas':1},{'recovery':True},{'name':'production'}])
def test_restore_requires_empty_owned_database(change):
    base={'name':'sp_restore_test1234','superuser':False,'owner':True,'relations':0,'routines':0,'extra_schemas':0,'recovery':False}
    validate_empty(base,base['name'])
    with pytest.raises(ValueError):validate_empty({**base,**change},base['name'])

def test_restore_private_file(tmp_path):
    p=tmp_path/'identity';p.write_text('fixture');p.chmod(0o600);assert private_file(str(p))==str(p)
    p.chmod(0o644)
    with pytest.raises(ValueError):private_file(str(p))
    p.chmod(0o600);link=tmp_path/'link';link.symlink_to(p)
    with pytest.raises(ValueError):private_file(str(link))

def test_restore_ciphertext_copy_and_tamper(tmp_path):
    tmp_path.chmod(0o700);k=Ed25519PrivateKey.generate();pub=base64.b64encode(k.public_key().public_bytes_raw()).decode();m=publish(tmp_path,lambda p:p.write_bytes(b'ciphertext fixture'),k,pub,counts());root=tmp_path/m['backup_id'];sig=(root/'signature.txt').read_text();src=root/'database.dump.age'
    copy_verified(src,tmp_path/'copy',m,sig,pub);assert (tmp_path/'copy').read_bytes()==src.read_bytes()
    src.write_bytes(b'x'*m['size'])
    with pytest.raises(ValueError):copy_verified(src,tmp_path/'tamper',m,sig,pub)
    src.write_bytes(b'x')
    with pytest.raises(ValueError):copy_verified(src,tmp_path/'truncated',m,sig,pub)


def test_receipt_service_cannot_read():
    with pytest.raises(PaymentError,match='user_identity_required'):customer_receipt(None,Principal('key','tenant-alpha','alice',frozenset({'customer'})),str(uuid.uuid4()))


def test_provider_route_requires_signed_evidence_when_configured(provider,monkeypatch):
    from fastapi import FastAPI,Request
    from fastapi.responses import JSONResponse
    from fastapi.testclient import TestClient
    from spyderpay_core.postgres.compliance_api import mount_compliance_routes
    from spyderpay_core.postgres.compliance import Compliance
    p,sign,args,now,cfg=provider;ref=p.verify(sign(),**args,now=now)
    app=FastAPI();principal=Principal('kyc-key','tenant-alpha','compliance-maker',frozenset({'compliance_maker'}))
    @app.middleware('http')
    async def attach(request:Request,call_next):
        request.state.principal=principal
        return await call_next(request)
    @app.exception_handler(PaymentError)
    async def handle(request,err):return JSONResponse({'error':err.code},status_code=err.status)
    called=[]
    def record(self,*values):called.append(values);return {'recorded':True}
    monkeypatch.setattr(Compliance,'record',record)
    mount_compliance_routes(app,object(),json.dumps(cfg))
    client=TestClient(app);url='/v3/compliance/accounts/'+args['account']+'/reviews';headers={'Idempotency-Key':'test-evidence-ref-01'}
    body={'kyc':'verified','screening':'clear','tier':'standard','evidence_ref':ref}
    assert client.post(url,json=body,headers=headers).status_code==403
    assert client.post(url,json={**body,'provider_token':sign(),'evidence_ref':'wrong-ref'},headers=headers).status_code==403
    assert not called
    assert client.post(url,json={**body,'provider_token':sign()},headers=headers).json()=={'recorded':True}
    assert len(called)==1 and called[0][-2]==ref
