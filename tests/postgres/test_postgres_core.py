"""Real database assertions. CI runs these against PostgreSQL 16 service.

Local: SPYDERPAY_TEST_PG_DSN=postgresql://... pytest -q tests/postgres
"""
import os
import threading
import uuid
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import pytest

pytestmark = pytest.mark.pg
psycopg = pytest.importorskip('psycopg')
from spyderpay_core.postgres.store import PgProcessor,Principal
from spyderpay_core.ledger import PaymentError

DSN=os.getenv('SPYDERPAY_TEST_PG_DSN')
if not DSN:pytest.skip('SPYDERPAY_TEST_PG_DSN not set',allow_module_level=True)

@pytest.fixture()
def engine():
    migration=Path(__file__).parents[2]/'spyderpay_core'/'postgres'/'migrations'/'001_core.sql'
    with psycopg.connect(DSN,autocommit=True) as conn:
        conn.execute(migration.read_text())
        conn.execute('''TRUNCATE sp_postings,sp_journals,sp_accounts,sp_invoices,
          sp_outbox,sp_audit_events,sp_idempotency,sp_api_replay,sp_rate_windows,sp_bank_inbox RESTART IDENTITY CASCADE''')
    return PgProcessor(DSN)

ops=Principal('ops-1','tenant-alpha','operations',frozenset({'ops'}))
alice=Principal('alice','tenant-alpha','alice',frozenset({'customer'}))
bob=Principal('bob','tenant-alpha','bob',frozenset({'customer'}))
merchant=Principal('m','tenant-alpha','coffee',frozenset({'merchant'}))
eve=Principal('eve','tenant-other','eve',frozenset({'customer'}))


def create(engine):
    a=engine.create_account(ops,'alice','customer','create-account-alice')['id']
    b=engine.create_account(ops,'bob','customer','create-account-bob00')['id']
    shop=engine.create_account(ops,'coffee','merchant','create-account-shop0')['id']
    engine.sandbox_credit(ops,a,100_000,'mock-funding-100k')
    return a,b,shop


def test_atomic_transfer_double_entry(engine):
    a,b,_=create(engine)
    t=engine.transfer(alice,a,b,25_000,'payment-transfer-001')
    assert engine.transfer(alice,a,b,25_000,'payment-transfer-001')==t
    assert engine.account(alice,a)['balance']==75_000
    assert engine.account(bob,b)['balance']==25_000
    assert engine.reconcile(ops)['ok']


def test_no_overdraft_and_rollback(engine):
    a,b,_=create(engine)
    with pytest.raises(PaymentError):engine.transfer(alice,a,b,200_000,'payment-too-large')
    assert engine.reconcile(ops)['ok']
    assert engine.account(alice,a)['balance']==100_000


def test_duplicate_key_conflict(engine):
    a,b,_=create(engine)
    engine.transfer(alice,a,b,10_000,'transfer-unique-key')
    with pytest.raises(PaymentError) as ex:
        engine.transfer(alice,a,b,10_001,'transfer-unique-key')
    assert ex.value.status==409
    assert engine.reconcile(ops)['ok']


def test_tenant_and_owner_isolation(engine):
    a,b,_=create(engine)
    with pytest.raises(PaymentError) as ex:
        engine.account(bob,a)
    assert ex.value.status==403
    with pytest.raises(PaymentError):engine.transfer(bob,a,b,100,'other-owner-transfer')
    with pytest.raises(PaymentError):engine.transfer(eve,a,b,100,'cross-tenant-transfer')


def test_invoice_idempotent_paid_refunded(engine):
    a,b,m=create(engine)
    invoice=engine.create_invoice(merchant,m,40_000,'merchant-invoice-001')
    paid=engine.pay_invoice(alice,invoice['id'],a,'merchant-pay-001')
    assert paid['state']=='paid'
    assert engine.pay_invoice(alice,invoice['id'],a,'merchant-pay-001')==paid
    with pytest.raises(PaymentError):engine.pay_invoice(alice,invoice['id'],a,'merchant-pay-002')
    refund=engine.refund_invoice(merchant,invoice['id'],'merchant-refund-001')
    assert refund['state']=='refunded'
    assert engine.account(alice,a)['balance']==100_000
    assert engine.reconcile(ops)['ok']


def test_freeze_blocks_transfer(engine):
    a,b,_=create(engine)
    engine.freeze(ops,a,'operator-risk-hold', 'freeze-account-001')
    with pytest.raises(PaymentError) as ex:
        engine.transfer(alice,a,b,100,'transfer-frozen-001')
    assert ex.value.code=='frozen_or_closed_account'
    assert engine.reconcile(ops)['ok']


def test_concurrent_spending_only_one_succeeds(engine):
    a,b,_=create(engine)
    # Both debits attempt 75k from a 100k account. Must not overdraft.
    def pay(i):
        try:
            engine.transfer(alice,a,b,75_000,f'parallel-transfer-{i:04d}')
            return 'success'
        except PaymentError as ex:
            return ex.code
    with ThreadPoolExecutor(max_workers=2) as pool:
        results=list(pool.map(pay,[1,2]))
    assert results.count('success')==1
    assert results.count('insufficient_funds')==1
    assert engine.account(alice,a)['balance']==25_000
    assert engine.reconcile(ops)['ok']


def test_db_prevents_mutation_of_postings(engine):
    a,b,_=create(engine)
    t=engine.transfer(alice,a,b,10_000,'mutation-test-001')
    with psycopg.connect(DSN,autocommit=True) as conn:
        with pytest.raises(psycopg.Error):
            conn.execute('UPDATE sp_postings SET signed_amount=10 WHERE journal_id=%s',(t['journal_id'],))
    assert engine.reconcile(ops)['ok']


def test_db_rejects_unbalanced_single_posting(engine):
    a,b,_=create(engine)
    with psycopg.connect(DSN,autocommit=True) as conn:
        with pytest.raises(psycopg.Error):
            with conn.transaction():
                j=conn.execute("INSERT INTO sp_journals(tenant_id,kind,actor,currency) VALUES('tenant-alpha','bad','test','UZS') RETURNING id").fetchone()[0]
                conn.execute("INSERT INTO sp_postings(journal_id,account_id,signed_amount,currency) VALUES(%s,%s,100,'UZS')",(j,a))
    assert engine.reconcile(ops)['ok']


def test_outbox_same_transaction(engine):
    a,b,_=create(engine)
    transfer=engine.transfer(alice,a,b,100,'outbox-atomic-001')
    with psycopg.connect(DSN,autocommit=True) as conn:
        x=conn.execute('SELECT count(*) FROM sp_outbox WHERE aggregate_id=%s',(transfer['journal_id'],)).fetchone()[0]
    assert x==1


def test_no_unsafe_negative_or_boolean_amount(engine):
    a,b,_=create(engine)
    for n in (0,-1,True,1.25,'100'):
        with pytest.raises(PaymentError):engine.transfer(alice,a,b,n,'bad-amount-'+str(n).replace('.','_'))
    assert engine.reconcile(ops)['ok']


def test_outbox_claim_ack_exact_lease(engine):
    from spyderpay_core.postgres.outbox import Outbox
    a,b,_=create(engine)
    t=engine.transfer(alice,a,b,100,'lease-outbox-001')
    worker=Outbox(engine)
    items=worker.claim(ops,limit=10)
    target=next(x for x in items if x['aggregate_id']==t['journal_id'])
    assert not worker.ack(ops,target['id'],str(uuid.uuid4()))
    assert worker.ack(ops,target['id'],target['lease_token'])
    assert not worker.ack(ops,target['id'],target['lease_token'])
    assert all(x['id']!=target['id'] for x in worker.claim(ops,limit=100))


def test_outbox_no_duplicate_concurrent_claim(engine):
    from spyderpay_core.postgres.outbox import Outbox
    a,b,_=create(engine)
    t=engine.transfer(alice,a,b,100,'lease-outbox-002')
    worker=Outbox(engine)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results=list(pool.map(lambda _ : worker.claim(ops,limit=100),[1,2]))
    ids=[r['id'] for batch in results for r in batch]
    assert len(ids)==len(set(ids))
    assert any(x['aggregate_id']==t['journal_id'] for batch in results for x in batch)


def test_outbox_tenant_isolation(engine):
    from spyderpay_core.postgres.outbox import Outbox
    a,b,_=create(engine)
    engine.transfer(alice,a,b,100,'outbox-isolation-001')
    other_ops=Principal('other-ops','tenant-other','operations',frozenset({'ops'}))
    assert Outbox(engine).claim(other_ops,limit=10)==[]


def test_reconcile_tenant_isolation(engine):
    a,b,_=create(engine)
    engine.transfer(alice,a,b,10_000,'tenant-reconcile-001')
    other_ops=Principal('other-ops','tenant-other','operations',frozenset({'ops'}))
    assert engine.reconcile(other_ops)=={'ok':True,'unbalanced':0,'balance_mismatch':0,'negative_external':0}


def test_db_rejects_empty_journal_header(engine):
    create(engine)
    with psycopg.connect(DSN,autocommit=True) as conn:
        with pytest.raises(psycopg.Error):
            with conn.transaction():
                conn.execute("INSERT INTO sp_journals(tenant_id,kind,actor,currency) VALUES('tenant-alpha','bad','test','UZS')")
    assert engine.reconcile(ops)['ok']
