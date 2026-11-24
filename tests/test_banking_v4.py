import json
import base64
import secrets
import time
import uuid
from dataclasses import replace
import pytest
from spyderpay_core.ledger import PaymentError
from spyderpay_core.postgres.banking import Banking, verify_match, provider, reference, authorize_role
from spyderpay_core.postgres.rail_contract import RailInstruction, sandbox_reference, recovery_action
from spyderpay_core.postgres.service_v3 import load_credentials
from spyderpay_core.postgres.store import Principal

I={'tenant_id':'tenant-alpha','provider':'sandbox-bank','provider_ref':'ext-001','direction':'withdrawal','amount':25_000,'beneficiary_ref':'beneficiary-001'}
C={**I,'channel':'callback','actor':'callback-actor','status':'settled'}
S={**I,'channel':'statement','actor':'statement-actor','status':'settled'}

def test_match():assert verify_match(I,C,S)=='settled'
@pytest.mark.parametrize('field,value',[('tenant_id','tenant-other'),('provider','sandbox-other'),('provider_ref','ext-002'),('direction','deposit'),('amount',25001),('beneficiary_ref','beneficiary-002')])
def test_different_evidence_terms(field,value):
    with pytest.raises(PaymentError,match='bank_evidence_mismatch'):verify_match(I,C,{**S,field:value})
@pytest.mark.parametrize('changes',[{'channel':'callback'},{'actor':'callback-actor'}])
def test_independent_channel(changes):
    with pytest.raises(PaymentError,match='independent_evidence_required'):verify_match(I,C,{**S,**changes})
def test_conflicting_status():
    with pytest.raises(PaymentError,match='bank_evidence_conflict'):verify_match(I,C,{**S,'status':'failed'})
def test_failed_both():assert verify_match(I,{**C,'status':'failed'},{**S,'status':'failed'})=='failed'
@pytest.mark.parametrize('value',['visa','bank-live','sandbox-','sandbox-../../','sandbox-Ä','sandbox-ABC',None])
def test_provider_guard(value):
    with pytest.raises(PaymentError):provider(value)
@pytest.mark.parametrize('value',['a','a b','abc/def','abc\n',None])
def test_reference_guard(value):
    with pytest.raises(PaymentError):reference(value)
@pytest.mark.parametrize('role',['ops','customer','merchant','bank_callback','bank_statement','risk_ops'])
def test_bank_review_role_isolated(role):
    with pytest.raises(PaymentError):authorize_role(Principal('id','tenant','subject',frozenset({role})),'bank_review')
def test_multiple_roles_denied():
    with pytest.raises(PaymentError):authorize_role(Principal('id','tenant','subject',frozenset({'bank_review','bank_ops'})),'bank_review')
def test_user_identity_cannot_use_bank_service():
    with pytest.raises(PaymentError):authorize_role(Principal('id','tenant','subject',frozenset({'bank_review'}),identity=object()),'bank_review')
def credential(role,subject='actor-one'):
    now=int(time.time());return {'key_id':secrets.token_hex(8),'secret_b64':base64.b64encode(secrets.token_bytes(32)).decode(),'tenant_id':'tenant-alpha','subject':subject,'roles':[role],'not_before':now-10,'not_after':now+100}
@pytest.mark.parametrize('role',['bank_ops','bank_review','bank_callback','bank_statement','risk_ops'])
def test_bank_credentials(role):assert len(load_credentials(json.dumps([credential(role)])))==1
def test_no_shared_actor_between_roles():
    with pytest.raises(ValueError,match='service_actor_role_conflict'):load_credentials(json.dumps([credential('bank_ops'),credential('bank_review')]))
def test_multiple_credentials_same_role_rotation():assert len(load_credentials(json.dumps([credential('bank_ops'),credential('bank_ops')])))==2
def test_sandbox_reference_is_stable():
    x=RailInstruction(str(uuid.uuid4()),'sandbox-bank','withdrawal',25000,'customer-001');assert sandbox_reference(x)==sandbox_reference(x)
    assert x.idempotency_reference==replace(x,amount=200).idempotency_reference and x.digest!=replace(x,amount=200).digest
@pytest.mark.parametrize('state,support,expected',[('unknown',True,'query_existing_reference'),('unknown',False,'query_existing_reference'),('accepted',True,'await_evidence'),('not_dispatched',True,'retry_same_reference'),('not_dispatched',False,'manual_review')])
def test_recovery(state,support,expected):assert recovery_action(state,support)==expected
@pytest.mark.parametrize('changes',[{'currency':'USD'},{'amount':True},{'amount':0},{'direction':'invalid'},{'provider':'live-bank'}])
def test_rail_validation(changes):
    args={'intent_id':str(uuid.uuid4()),'provider':'sandbox-bank','direction':'withdrawal','amount':25000,'beneficiary_ref':'customer-001',**changes}
    with pytest.raises(PaymentError):RailInstruction(**args)
def test_bank_api_requires_service_role_before_db():
    b=Banking(object());p=Principal('key','tenant','actor',frozenset({'ops'}))
    with pytest.raises(PaymentError,match='bank_service_role_required'):b.review(p,str(uuid.uuid4()),'key-idempotent-001')
