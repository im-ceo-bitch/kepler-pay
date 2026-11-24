import base64
from datetime import datetime,timezone,timedelta
import json
import time
import uuid
import pytest
import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from spyderpay_core.ledger import PaymentError
from spyderpay_core.postgres.pos import PosTokens, ISSUER,AUDIENCE
from spyderpay_core.postgres.ops.recovery import manifest_bytes,file_fingerprint,verify_backup,classify_restore
from spyderpay_core.release import SCHEMA_VERSION

def b64(x):return base64.b64encode(x).decode()

def cfg():
    priv=Ed25519PrivateKey.generate();now=int(time.time());return {'active_kid':'key-01','private_b64':b64(priv.private_bytes_raw()),'keys':[{'kid':'key-01','public_b64':b64(priv.public_key().public_bytes_raw()),'not_before':now-60,'not_after':now+3600}]}

def invoice():return {'id':str(uuid.uuid4()),'merchant_account':str(uuid.uuid4()),'amount':25000,'state':'pending','expires_at':datetime.now(timezone.utc)+timedelta(minutes=10)}

def test_pos_roundtrip():
    t=PosTokens(json.dumps(cfg()));i=invoice();d=t.verify(t.issue('tenant-alpha',i),'tenant-alpha')
    assert d['amount']==25000 and d['merchant']==i['merchant_account'] and d['invoice']==i['id'] and d['exp']-d['iat']<=90

@pytest.mark.parametrize('field,value',[('tenant','tenant-beta'),('currency','USD'),('purpose','pay'),('amount',True),('amount',0),('aud','other'),('iss','other'),('iat',1),('exp',1)])
def test_pos_rejects_signed_wrong_claims(field,value):
    t=PosTokens(json.dumps(cfg()));d=t.verify(t.issue('tenant-alpha',invoice()),'tenant-alpha');d[field]=value
    token=jwt.encode(d,t.private,algorithm='EdDSA',headers={'kid':t.active,'typ':'spyderpay-pos+jwt'})
    with pytest.raises(PaymentError):t.verify(token,'tenant-alpha')

def test_pos_wrong_key_and_tenant():
    t=PosTokens(json.dumps(cfg()));token=t.issue('tenant-alpha',invoice());other=PosTokens(json.dumps(cfg()))
    with pytest.raises(PaymentError):other.verify(token,'tenant-alpha')
    with pytest.raises(PaymentError):t.verify(token,'tenant-beta')

def test_pos_wrong_algorithm():
    t=PosTokens(json.dumps(cfg()));d=t.verify(t.issue('tenant-alpha',invoice()),'tenant-alpha')
    token=jwt.encode(d,b'x'*32,algorithm='HS256',headers={'kid':t.active,'typ':'spyderpay-pos+jwt'})
    with pytest.raises(PaymentError):t.verify(token,'tenant-alpha')

@pytest.mark.parametrize('state',['paid','refunded','cancelled'])
def test_pos_only_pending(state):
    t=PosTokens(json.dumps(cfg()));i=invoice();i['state']=state
    with pytest.raises(PaymentError):t.issue('tenant-alpha',i)

def test_pos_expired():
    t=PosTokens(json.dumps(cfg()));i=invoice();i['expires_at']=datetime.now(timezone.utc)-timedelta(seconds=1)
    with pytest.raises(PaymentError):t.issue('tenant-alpha',i)

def test_pos_key_pair_mismatch():
    c=cfg();c['private_b64']=cfg()['private_b64']
    with pytest.raises(ValueError):PosTokens(json.dumps(c))

def signed_backup(tmp_path):
    p=tmp_path/'encrypted-backup';p.write_bytes(b'encrypted fixture data');size,digest=file_fingerprint(p)
    m={'format':1,'backup_id':'backup_000000001','sha256':digest,'size':size,'schema':SCHEMA_VERSION,'environment':'prelicense'}
    k=Ed25519PrivateKey.generate();return p,m,b64(k.sign(manifest_bytes(m))),b64(k.public_key().public_bytes_raw())

def test_backup_manifest_roundtrip(tmp_path):
    assert verify_backup(*signed_backup(tmp_path))['verified']

def test_backup_tamper(tmp_path):
    p,m,s,k=signed_backup(tmp_path);p.write_bytes(b'changed')
    with pytest.raises(ValueError,match='backup_integrity_failure'):verify_backup(p,m,s,k)

def test_backup_metadata_tamper(tmp_path):
    p,m,s,k=signed_backup(tmp_path);m['backup_id']='other_backup_00001'
    with pytest.raises(ValueError,match='invalid_backup_signature'):verify_backup(p,m,s,k)

def test_backup_symlink(tmp_path):
    p,m,s,k=signed_backup(tmp_path);link=tmp_path/'link';link.symlink_to(p)
    with pytest.raises(OSError):verify_backup(link,m,s,k)

def counts():return dict.fromkeys(('invalid_journals','invalid_balances','invalid_posting_scope','invalid_holds','invalid_fees','invalid_chargebacks','accounts','journals','postings','intents','outbox','audit_events'),0)
@pytest.mark.parametrize('fault',['invalid_journals','invalid_balances','invalid_posting_scope','invalid_holds','invalid_fees','invalid_chargebacks'])
def test_restore_integrity_fault(fault):
    c=counts();c[fault]=1
    assert not classify_restore(SCHEMA_VERSION,c)['ok']

def test_restore_schema_and_shape():
    assert classify_restore(SCHEMA_VERSION,counts())['ok']
    assert not classify_restore(SCHEMA_VERSION-1,counts())['ok']
    with pytest.raises(ValueError):classify_restore(SCHEMA_VERSION,{})
