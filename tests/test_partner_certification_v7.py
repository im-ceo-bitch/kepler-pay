import copy
import secrets
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import pytest
from spyderpay_core.ledger import PaymentError
from spyderpay_core.postgres.rail_contract import RailInstruction
from spyderpay_core.postgres.sandbox_rail import SandboxRail
from spyderpay_core.postgres.partner_reconciliation import reconcile
from spyderpay_core.postgres.clearing import validate_batch

PROVIDER='sandbox-bank'
NOW=1_800_000_000

@pytest.fixture
def rail(tmp_path):
    return SandboxRail(tmp_path/'provider.db',PROVIDER,secrets.token_bytes(32),environment='test')

def instruction(direction='deposit',amount=1000):
    return RailInstruction(str(uuid.uuid4()),PROVIDER,direction,amount,'account-001')

def internal(i,state='settled'):
    return dict(provider_ref=i.idempotency_reference,direction=i.direction,amount=i.amount,beneficiary_ref=i.beneficiary_ref,state=state)

def test_persistent_lost_response(rail):
    i=instruction()
    with pytest.raises(TimeoutError):rail.simulate(i,lose_response=True)
    r=SandboxRail(rail.path,PROVIDER,rail.key,environment='sandbox')
    assert r.lookup(i.idempotency_reference).state=='accepted'
    assert r.submit(i).state=='accepted'
    assert len(r.statement_batch()['rows'])==1
    with pytest.raises(PaymentError,match='sandbox_reference_conflict'):r.submit(replace(i,amount=2000))

@pytest.mark.parametrize('env',['production','prelicense','live',''])
def test_no_live_mode(tmp_path,env):
    with pytest.raises(ValueError,match='sandbox_only'):SandboxRail(tmp_path/'x.db',PROVIDER,secrets.token_bytes(32),environment=env)

def test_provider_isolation(rail):
    with pytest.raises(ValueError):SandboxRail(rail.path,'sandbox-other',rail.key,environment='test')
    with pytest.raises(PaymentError):rail.submit(replace(instruction(),provider='sandbox-other'))

def test_concurrent_identical_submit(rail):
    i=instruction()
    with ThreadPoolExecutor(max_workers=8) as pool:
        results=list(pool.map(lambda _:rail.submit(i),range(24)))
    assert all(x.state=='accepted' for x in results)
    assert len(rail.statement_batch()['rows'])==1

def test_unknown_is_not_failed(rail):
    assert rail.lookup(instruction().idempotency_reference).state=='unknown'
    assert rail.statement_batch() is None

def test_callback_matches_statement(rail):
    i=instruction();rail.submit(i)
    raw,headers=rail.callback(i.idempotency_reference,now=NOW)
    ev=rail.verify_callback(raw,headers,now=NOW)
    row=rail.statement_batch()['rows'][0]
    assert ev['event_ref']!=row['event_ref']
    assert all(ev[k]==row[k] for k in ('provider_ref','direction','amount','beneficiary_ref','status'))
    assert len(ev['payload_digest'])==64

@pytest.mark.parametrize('fault',['tampered','expired','duplicate_header','wrong_key','unicode_signature'])
def test_reject_callback_faults(rail,fault):
    i=instruction();rail.submit(i);raw,headers=rail.callback(i.idempotency_reference,now=NOW);now=NOW
    if fault=='tampered':raw=raw.replace(b'1000',b'1001')
    if fault=='expired':now+=121
    if fault=='duplicate_header':headers['X-Sandbox-Timestamp']=headers['x-sandbox-timestamp']
    if fault=='wrong_key':headers['x-sandbox-signature']='0'*64
    if fault=='unicode_signature':headers['x-sandbox-signature']='é'*64
    with pytest.raises(PaymentError):rail.verify_callback(raw,headers,now=now)

def test_paginated_statement_continuity(rail):
    items=[instruction(amount=1000),instruction('withdrawal',300),instruction('withdrawal',200)]
    rail.submit(items[0]);rail.submit(items[1]);rail.simulate(items[2],fail=True)
    a=rail.statement_batch(limit=2);b=rail.statement_batch(a['cursor'],limit=2)
    assert (a['opening'],a['closing'],a['credits'],a['debits'])==(0,700,1000,300)
    assert (b['opening'],b['closing'],b['credits'],b['debits'])==(700,700,0,0)
    assert rail.fetch_statement(b['cursor'])==([],b['cursor'])
    report=reconcile(PROVIDER,0,[a,b],[internal(items[0]),internal(items[1]),internal(items[2],'failed')])
    assert report['balanced'] and report['read_only'] and report['closing']==700

@pytest.mark.parametrize('cursor',['-1','01','1.0','999','١','9'*16,1,True])
def test_cursor_validation(rail,cursor):
    with pytest.raises(ValueError):rail.statement_batch(cursor)

@pytest.mark.parametrize('fault,code',[('missing','missing_external_entry'),('unmatched','unmatched_external_entry'),('terms','terms_mismatch'),('final','final_state_mismatch'),('unknown','awaiting_internal_resolution')])
def test_reconciliation_exceptions(rail,fault,code):
    i=instruction();rail.submit(i);b=rail.statement_batch();ins=[internal(i)]
    if fault=='missing': batches=[]
    else:batches=[b]
    if fault=='unmatched':ins=[]
    if fault=='terms':ins[0]['amount']+=1
    if fault=='final':ins[0]['state']='failed'
    if fault=='unknown':ins[0]['state']='unknown'
    result=reconcile(PROVIDER,0,batches,ins)
    assert not result['balanced'] and result['exceptions'][0]['code']==code

@pytest.mark.parametrize('fault',['duplicate','digest','totals'])
def test_reconcile_rejects_invalid_batches(rail,fault):
    i=instruction();rail.submit(i);b=rail.statement_batch();bad=copy.deepcopy(b)
    if fault=='duplicate':batches=[b,bad]
    elif fault=='digest':bad['digest']='0'*64;batches=[bad]
    else:bad['closing']+=1;batches=[bad]
    with pytest.raises(PaymentError):reconcile(PROVIDER,0,batches,[internal(i)])

def test_balance_gap_report(rail):
    i=instruction();rail.submit(i);b=rail.statement_batch();b['opening']=123;b['closing']+=123
    b['digest']=validate_batch(PROVIDER,b['batch_ref'],b['opening'],b['closing'],b['credits'],b['debits'],b['rows'])
    report=reconcile(PROVIDER,0,[b],[internal(i)])
    assert report['exceptions']==[{'code':'statement_balance_gap','batch_ref':b['batch_ref']}]

@pytest.mark.parametrize('suffix,expected',[('submit','legacy_bank_submit_disabled_use_dispatch_claim'),('unknown','legacy_bank_unknown_disabled_use_dispatch_result')])
def test_legacy_http_transition_no_dispatch_bypass(suffix,expected):
    from fastapi import FastAPI
    from spyderpay_core.postgres.bank_api import mount_bank_routes
    app=FastAPI();mount_bank_routes(app,object())
    route=next(r for r in app.routes if r.path=='/v3/bank/intents/{iid}/'+suffix)
    with pytest.raises(PaymentError,match=expected):route.endpoint(None,str(uuid.uuid4()),None,'valid-idempotency')
