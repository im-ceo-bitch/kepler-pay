import copy
from datetime import datetime,timezone,timedelta
import uuid
import pytest
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
from spyderpay_core.ledger import PaymentError
from spyderpay_core.postgres.cards import public_key,transcript,verify_proof,require_user
from spyderpay_core.postgres.store import Principal


def keyhex(k):return k.public_key().public_bytes(serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint).hex()
def fixture():
    k=ec.generate_private_key(ec.SECP256R1())
    r={'id':uuid.uuid4(),'tenant_id':'tenant-alpha','owner_id':'alice','issuer':'https://id.example.test','external_sub':'external-alice','sid':'session-a','purpose':'invoice_preview','card_id':uuid.uuid4(),'public_key':keyhex(k),'nonce':'a'*64,'invoice_id':uuid.uuid4(),'merchant_account':uuid.uuid4(),'amount':25000,'expires_at':datetime.now(timezone.utc)+timedelta(seconds=90)}
    return k,r

def sign(k,row):return k.sign(transcript(row),ec.ECDSA(hashes.SHA256())).hex()

def test_card_proof_roundtrip():
    k,r=fixture();verify_proof(r,sign(k,r));assert b'http' not in transcript(r) and b'session-a' not in transcript(r)

@pytest.mark.parametrize('field,value',[('tenant_id','tenant-beta'),('owner_id','bob'),('issuer','https://other.example.test'),('external_sub','external-bob'),('sid','session-b'),('purpose','enroll'),('nonce','b'*64),('amount',25001),('invoice_id',uuid.uuid4()),('merchant_account',uuid.uuid4()),('card_id',uuid.uuid4()),('id',uuid.uuid4()),('expires_at',datetime.now(timezone.utc)+timedelta(minutes=20))])
def test_card_signature_binds_all_fields(field,value):
    k,r=fixture();sig=sign(k,r);r[field]=value
    with pytest.raises(PaymentError):verify_proof(r,sig)

@pytest.mark.parametrize('key',['', '04'+'0'*128,'02'+'a'*64,'04'+'Z'*128,None,'04'+'A'*128])
def test_reject_invalid_public_key(key):
    with pytest.raises(PaymentError):public_key(key)

@pytest.mark.parametrize('sig',['','gg'*20,'00'*8,'a'*17,'a'*146,None])
def test_reject_invalid_signature(sig):
    _,r=fixture()
    with pytest.raises(PaymentError):verify_proof(r,sig)

def test_wrong_card_key():
    k,r=fixture();other,_=fixture();sig=sign(other,r)
    with pytest.raises(PaymentError):verify_proof(r,sig)

def test_card_requires_consumer_identity():
    for role in ('ops','customer','merchant'):
        with pytest.raises(PaymentError):require_user(Principal('key','tenant-alpha','alice',frozenset({role})))
    with pytest.raises(PaymentError):require_user(Principal('key','tenant-alpha','alice',frozenset({'merchant'}),identity=object()))
