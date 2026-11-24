import base64
import json
import secrets
import time
import uuid
from dataclasses import asdict
from pathlib import Path
import pytest
from spyderpay_core.ledger import PaymentError
from spyderpay_core.postgres.auth import load_keys
from spyderpay_core.postgres.service_v3 import load_credentials, V3_ROLES
from spyderpay_core.postgres.dispatch import Dispatch, next_action
from spyderpay_core.postgres.dispatch_worker import DispatchWorker, normalize_result
from spyderpay_core.postgres.rail_contract import RailInstruction, DispatchResult
from spyderpay_core.postgres.bank_adapter import ExampleHmacCallbackVerifier
from spyderpay_core.postgres.store import Principal
from spyderpay_core.postgres.runtime_preflight import check_runtime,READ_TABLES,REQUIRED_WRITE
from spyderpay_core.release import SCHEMA_VERSION


def credential(role):
    now=int(time.time())
    return {'key_id':'svc-'+role,'secret_b64':base64.b64encode(secrets.token_bytes(32)).decode(),'tenant_id':'tenant-alpha','subject':'actor-'+role,'roles':[role],'not_before':now-30,'not_after':now+600}

@pytest.mark.parametrize('role',sorted(V3_ROLES))
def test_every_configured_service_role_loads(role):
    c=credential(role); assert load_credentials(json.dumps([c]))[c['key_id']].service.principal.roles==frozenset({role})

@pytest.mark.parametrize('role',['compliance_maker','compliance_review','clearing_review','bank_consent','bank_dispatch'])
def test_legacy_does_not_accept_new_roles(role):
    with pytest.raises(ValueError): load_keys(json.dumps([credential(role)]))

@pytest.mark.parametrize('state,outcome,action',[
    ('submitted',None,'lookup_only'),('unknown','unknown','lookup_only'),('submitted','not_dispatched','lookup_only'),
    ('submitted','accepted','await_evidence_or_lookup'),('settled',None,'terminal'),('failed','unknown','terminal'),('cancelled',None,'terminal')])
def test_dispatch_policy(state,outcome,action): assert next_action(state,outcome)==action

@pytest.mark.parametrize('role',['ops','bank_ops','bank_review','bank_callback','customer','merchant'])
def test_claim_requires_dispatch_identity(role):
    with pytest.raises(PaymentError,match='bank_service_role_required'):
        Dispatch(object()).claim(Principal('id','tenant','actor',frozenset({role})),str(uuid.uuid4()))

class FakeDispatch:
    def __init__(self):
        self.instruction=RailInstruction(str(uuid.uuid4()),'sandbox-test','withdrawal',500,'customer-001')
        self.claimed=False;self.outcome=None;self.fail_report=False
    def claim(self,p,iid):
        if self.claimed:raise PaymentError('dispatch_claim_forbidden',409)
        self.claimed=True
        return {'action':'submit_once','instruction':asdict(self.instruction),'request_ref':self.instruction.idempotency_reference,'instruction_digest':self.instruction.digest}
    def report(self,p,iid,outcome,idem):
        if self.fail_report:raise OSError('database unavailable')
        self.outcome=outcome;return {'outcome':outcome}
    def status(self,p,iid):return {'action':next_action('submitted',self.outcome),'request_ref':self.instruction.idempotency_reference,'provider':self.instruction.provider}

class Rail:
    def __init__(self,mode='accepted'):self.mode=mode;self.submits=0;self.lookups=0
    def submit(self,instruction):
        self.submits+=1
        if self.mode=='timeout':raise TimeoutError()
        return DispatchResult('wrong-ref' if self.mode=='wrong' else instruction.idempotency_reference,self.mode if self.mode!='wrong' else 'accepted')
    def lookup(self,ref):self.lookups+=1;return DispatchResult(ref,'accepted')

@pytest.mark.parametrize('mode,expected',[('accepted','accepted'),('timeout','unknown'),('wrong','unknown'),('unknown','unknown'),('not_dispatched','not_dispatched')])
def test_worker_never_resubmits(mode,expected):
    d=FakeDispatch();r=Rail(mode);w=DispatchWorker(d,None,{'sandbox-test':r});iid=d.instruction.intent_id
    assert w.execute(iid)['outcome']==expected
    with pytest.raises(PaymentError):w.execute(iid)
    assert r.submits==1
    assert w.recover(iid)['observation']=='accepted' and r.lookups==1 and r.submits==1

def test_crash_after_external_submit():
    d=FakeDispatch();d.fail_report=True;r=Rail();w=DispatchWorker(d,None,{'sandbox-test':r});iid=d.instruction.intent_id
    with pytest.raises(OSError):w.execute(iid)
    with pytest.raises(PaymentError):w.execute(iid)
    assert w.recover(iid)['observation']=='accepted' and r.submits==1

def test_no_adapter_fails_closed():
    d=FakeDispatch();w=DispatchWorker(d,None,{})
    assert w.execute(d.instruction.intent_id)['outcome']=='not_dispatched'
    assert w.recover(d.instruction.intent_id)['action']=='manual_review'

def test_bad_instruction_digest_never_calls_adapter():
    d=FakeDispatch();r=Rail();claim=d.claim
    def altered(p,iid):return {**claim(p,iid),'instruction_digest':'0'*64}
    d.claim=altered;w=DispatchWorker(d,None,{'sandbox-test':r})
    with pytest.raises(PaymentError,match='dispatch_instruction_mismatch'):w.execute(d.instruction.intent_id)
    assert r.submits==0

@pytest.mark.parametrize('body',[b'{"external_id":"E-123","amount_uzs":1,"amount_uzs":2,"status":"confirmed","receiver_reference":"acc-123"}',b' '*16385,b'{"external_id":"E-123","amount_uzs":NaN,"status":"confirmed","receiver_reference":"acc-123"}'])
def test_callback_malformed_even_with_valid_signature(body):
    key=secrets.token_bytes(32);v=ExampleHmacCallbackVerifier(key,'sandbox-test');ts=str(int(time.time()));h={'x-example-bank-timestamp':ts,'x-example-bank-signature':v.signature(key,body,ts)}
    with pytest.raises(PaymentError):v.verify_callback(body,h)

def test_callback_duplicate_header():
    key=secrets.token_bytes(32);v=ExampleHmacCallbackVerifier(key,'sandbox-test');ts=str(int(time.time()));body=b'{}';h={'x-example-bank-timestamp':ts,'X-Example-Bank-Timestamp':ts,'x-example-bank-signature':v.signature(key,body,ts)}
    with pytest.raises(PaymentError,match='ambiguous_bank_headers'):v.verify_callback(body,h)

class FakeConnection:
    def __init__(self,fault=None):self.fault=fault
    def execute(self,sql,args=None):
        if 'max(version)' in sql:r={'version':SCHEMA_VERSION-1 if self.fault=='schema' else SCHEMA_VERSION}
        elif 'FROM pg_roles' in sql:r={'rolsuper':self.fault=='owner'}
        elif ' AS ok' in sql:r={'ok':self.fault!=args[0]}
        elif ' AS can_read' in sql:r={'can_read':self.fault!='gate_read','unsafe':self.fault=='gate_write'}
        elif ' AS unsafe' in sql:r={'unsafe':self.fault=='delete'}
        else:raise AssertionError(sql)
        return type('Result',(),{'fetchone':lambda self:r})()

@pytest.mark.parametrize('fault',['schema','owner','sp_bank_intents','delete','gate_read','gate_write'])
def test_runtime_preflight_rejects_invalid_role(fault):
    with pytest.raises(RuntimeError):check_runtime(FakeConnection(fault))

def test_runtime_preflight_accepts_only_expected_permissions():check_runtime(FakeConnection())

def test_runtime_sql_identical():
    root=Path(__file__).parents[1]
    assert (root/'infrastructure/postgres/runtime_roles.sql').read_bytes()==(root/'spyderpay_core/postgres/ops/runtime_roles.sql').read_bytes()
