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
    from spyderpay_core.postgres.migrate import migrate
    migrate(DSN)
    with psycopg.connect(DSN,autocommit=True) as conn:
        conn.execute('''TRUNCATE sp_bank_evidence_use,sp_bank_cases,sp_bank_evidence,sp_bank_intents,sp_bank_risk,sp_payment_approvals,sp_revoked_sessions,sp_identity_members,sp_postings,sp_journals,sp_accounts,sp_invoices,
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

# Block 1: database invariants and transactional authorization.

def test_db_rejects_balance_without_posting(engine):
    a,b,_=create(engine)
    with psycopg.connect(DSN,autocommit=True) as conn:
        with pytest.raises(psycopg.Error):conn.execute('UPDATE sp_accounts SET balance=balance+100 WHERE id=%s',(a,))
    assert engine.account(alice,a)['balance']==100_000
    assert engine.reconcile(ops)['ok']


def test_db_rejects_nonzero_opening_balance(engine):
    with psycopg.connect(DSN,autocommit=True) as conn:
        with pytest.raises(psycopg.Error):conn.execute("INSERT INTO sp_accounts(tenant_id,owner_id,kind,currency,balance) VALUES('tenant-alpha','bad','customer','UZS',10)")


def test_db_rejects_sealed_journal_append(engine):
    a,b,m=create(engine);t=engine.transfer(alice,a,b,100,'sealed-append-0001')
    with psycopg.connect(DSN,autocommit=True) as conn:
        with pytest.raises(psycopg.Error):conn.execute("INSERT INTO sp_postings(journal_id,account_id,signed_amount,currency) VALUES(%s,%s,1,'UZS')",(t['journal_id'],m))
        with pytest.raises(psycopg.Error):conn.execute('UPDATE sp_journals SET sealed=false WHERE id=%s',(t['journal_id'],))
    assert engine.reconcile(ops)['ok']


def test_db_rejects_account_identity_mutation(engine):
    a,_,_=create(engine)
    with psycopg.connect(DSN,autocommit=True) as conn:
        with pytest.raises(psycopg.Error):conn.execute("UPDATE sp_accounts SET owner_id='attacker' WHERE id=%s",(a,))
        with pytest.raises(psycopg.Error):conn.execute('DELETE FROM sp_accounts WHERE id=%s',(a,))


def test_db_rejects_invoice_terms_change(engine):
    a,b,m=create(engine);inv=engine.create_invoice(merchant,m,1000,'immutable-invoice-01')
    with psycopg.connect(DSN,autocommit=True) as conn:
        with pytest.raises(psycopg.Error):conn.execute('UPDATE sp_invoices SET amount=2000 WHERE id=%s',(inv['id'],))
        with pytest.raises(psycopg.Error):conn.execute('UPDATE sp_invoices SET merchant_account=%s WHERE id=%s',(b,inv['id']))


def test_db_rejects_invoice_linked_to_unrelated_transfer(engine):
    a,b,m=create(engine);inv=engine.create_invoice(merchant,m,1000,'invoice-fake-link-01');t=engine.transfer(alice,a,b,1000,'invoice-other-tx-01')
    with psycopg.connect(DSN,autocommit=True) as conn:
        with pytest.raises(psycopg.Error):conn.execute("UPDATE sp_invoices SET state='paid',payer_account=%s,payment_journal=%s WHERE id=%s",(a,t['journal_id'],inv['id']))


def identity_for(engine, *, owner='alice', role='customer', sub='external-alice', sid='session-a', provision=True):
    import time
    from spyderpay_core.postgres.identity import Identity,resolve_principal
    if provision:
        with psycopg.connect(DSN,autocommit=True) as conn:
            conn.execute('INSERT INTO sp_identity_members(issuer,external_sub,tenant_id,owner_id,role) VALUES(%s,%s,%s,%s,%s)',('https://id.example.test',sub,'tenant-alpha',owner,role))
    now=int(time.time())
    i=Identity('https://id.example.test',sub,sid,now+240,str(uuid.uuid4()),now-10,'mfa-test')
    return resolve_principal(engine,i)


class VerifierPolicy:
    """DB tests isolate the approval transaction; real RSA tokens tested separately."""
    def require_mfa(self,identity):
        import time
        if identity.acr!='mfa-test' or identity.auth_time is None or int(time.time())-identity.auth_time>120:raise PaymentError('fresh_mfa_required',403)


def challenge(engine,p,a,b,amount,key):
    from spyderpay_core.postgres.identity import issue_approval
    return issue_approval(engine,p,'transfer',{'source':a,'target':b,'amount':amount},key)['approval_id']


def confirm(engine,p,aid):
    import time
    from dataclasses import replace
    from spyderpay_core.postgres.identity import confirm_approval
    # Move the test challenge creation time backwards instead of sleeping; test owner only.
    with psycopg.connect(DSN,autocommit=True) as conn:
        conn.execute("UPDATE sp_payment_approvals SET created_at=now()-interval '5 seconds' WHERE id=%s",(aid,))
    fresh=replace(p,identity=replace(p.identity,jti=str(uuid.uuid4()),auth_time=int(time.time())))
    confirm_approval(engine,VerifierPolicy(),fresh,aid)
    return replace(fresh,approval_id=aid)


def test_approval_requires_post_challenge_mfa(engine):
    from spyderpay_core.postgres.identity import confirm_approval
    a,b,_=create(engine);p=identity_for(engine);aid=challenge(engine,p,a,b,100,'challenge-mfa-0001')
    with pytest.raises(PaymentError,match='challenge_invalid_or_fresh_mfa_required'):confirm_approval(engine,VerifierPolicy(),p,aid)
    q=confirm(engine,p,aid)
    assert engine.transfer(q,a,b,100,'challenge-mfa-0001')['amount']==100


def test_approval_required_and_bound_to_amount_and_idem(engine):
    from dataclasses import replace
    a,b,_=create(engine);p=identity_for(engine);key='approval-bound-0001';aid=challenge(engine,p,a,b,100,key)
    with pytest.raises(PaymentError,match='approval_required'):engine.transfer(p,a,b,100,key)
    with pytest.raises(PaymentError):engine.transfer(replace(p,approval_id=aid),a,b,100,key)
    q=confirm(engine,p,aid)
    with pytest.raises(PaymentError,match='approval_invalid_or_expired'):engine.transfer(q,a,b,101,key)
    with pytest.raises(PaymentError,match='approval_invalid_or_expired'):engine.transfer(q,a,b,100,'approval-wrong-idem')
    t=engine.transfer(q,a,b,100,key)
    # Network retries return the original result, never debit a second time.
    assert engine.transfer(p,a,b,100,key)==t
    assert engine.account(alice,a)['balance']==99_900


def test_approval_not_transferable_between_sessions(engine):
    from dataclasses import replace
    a,b,_=create(engine);p=identity_for(engine);key='approval-session-01';aid=challenge(engine,p,a,b,100,key);q=confirm(engine,p,aid)
    other=replace(q,identity=replace(q.identity,sid='other-session'))
    with pytest.raises(PaymentError,match='approval_invalid_or_expired'):engine.transfer(other,a,b,100,key)
    assert engine.transfer(q,a,b,100,key)['amount']==100


def test_approval_expiry(engine):
    a,b,_=create(engine);p=identity_for(engine);key='approval-expiry-01';q=confirm(engine,p,challenge(engine,p,a,b,100,key))
    with psycopg.connect(DSN,autocommit=True) as conn:
        conn.execute("UPDATE sp_payment_approvals SET created_at=now()-interval '10 seconds',expires_at=now()-interval '1 second' WHERE id=%s",(q.approval_id,))
    with pytest.raises(PaymentError,match='approval_invalid_or_expired'):engine.transfer(q,a,b,100,key)


def test_approval_rollback_on_insufficient_funds(engine):
    a,b,_=create(engine);p=identity_for(engine);key='approval-rollback-01';q=confirm(engine,p,challenge(engine,p,a,b,150_000,key))
    with pytest.raises(PaymentError,match='insufficient_funds'):engine.transfer(q,a,b,150_000,key)
    with psycopg.connect(DSN,autocommit=True) as conn:
        assert conn.execute('SELECT consumed_at FROM sp_payment_approvals WHERE id=%s',(q.approval_id,)).fetchone()[0] is None
    assert engine.account(alice,a)['balance']==100_000
    assert engine.reconcile(ops)['ok']


def test_approval_concurrent_retry_debits_once(engine):
    a,b,_=create(engine);p=identity_for(engine);key='approval-race-0001';q=confirm(engine,p,challenge(engine,p,a,b,100,key))
    with ThreadPoolExecutor(max_workers=2) as pool:out=list(pool.map(lambda _:engine.transfer(q,a,b,100,key),range(2)))
    assert out[0]==out[1] and engine.account(alice,a)['balance']==99_900


def test_revocation_prevents_already_confirmed_operation(engine):
    from spyderpay_core.postgres.identity import revoke_session
    a,b,_=create(engine);p=identity_for(engine);key='approval-revoke-01';q=confirm(engine,p,challenge(engine,p,a,b,100,key))
    with psycopg.connect(DSN) as conn:revoke_session(conn,p.identity.issuer,p.identity.subject,p.identity.sid)
    with pytest.raises(PaymentError,match='session_revoked'):engine.transfer(q,a,b,100,key)
    with pytest.raises(PaymentError,match='session_revoked'):engine.account(p,a)
    assert engine.account(alice,a)['balance']==100_000


def test_disabled_member_cannot_spend(engine):
    a,b,_=create(engine);p=identity_for(engine);key='approval-disabled-01';q=confirm(engine,p,challenge(engine,p,a,b,100,key))
    with psycopg.connect(DSN,autocommit=True) as conn:conn.execute('UPDATE sp_identity_members SET enabled=false WHERE issuer=%s AND external_sub=%s',(p.identity.issuer,p.identity.subject))
    with pytest.raises(PaymentError,match='membership_disabled'):engine.transfer(q,a,b,100,key)


def test_runtime_role_cannot_modify_membership_or_truncate(engine):
    a,b,_=create(engine);p=identity_for(engine)
    with psycopg.connect(DSN,autocommit=True) as conn:
        conn.execute((Path(__file__).parents[2]/'spyderpay_core/postgres/ops/runtime_roles.sql').read_text())
        conn.execute('SET ROLE spyderpay_runtime')
        with pytest.raises(psycopg.Error):conn.execute('UPDATE sp_identity_members SET enabled=true')
        with pytest.raises(psycopg.Error):conn.execute('TRUNCATE sp_accounts CASCADE')
        with pytest.raises(psycopg.Error):conn.execute('ALTER TABLE sp_journals DISABLE TRIGGER ALL')
    class RestrictedProcessor(PgProcessor):
        def _connect(self):
            conn=super()._connect();conn.execute('SET ROLE spyderpay_runtime');return conn
    restricted=RestrictedProcessor(DSN)
    assert restricted.account(p,a)['balance']==100_000
    # Actual ledger execution and identity lookup via restricted role.
    key='role-restricted-01';q=confirm(restricted,p,challenge(restricted,p,a,b,100,key))
    assert restricted.transfer(q,a,b,100,key)['amount']==100
    assert restricted.reconcile(ops)['ok']


def test_upgrade_v2_preserves_existing_balances_and_seals_history(engine):
    """Disposable separate database: do not destroy or recreate existing schema."""
    from psycopg import sql
    from psycopg.conninfo import make_conninfo
    from spyderpay_core.postgres.migrate import migrate
    name='sp_upgrade_'+uuid.uuid4().hex[:16]
    target=make_conninfo(DSN,dbname=name)
    with psycopg.connect(DSN,autocommit=True) as admin:
        admin.execute(sql.SQL('CREATE DATABASE {}').format(sql.Identifier(name)))
    try:
        migration=Path(__file__).parents[2]/'spyderpay_core/postgres/migrations/001_core.sql'
        with psycopg.connect(target,autocommit=True) as conn:
            conn.execute(migration.read_text())
            with conn.transaction():
                src=conn.execute("INSERT INTO sp_accounts(tenant_id,owner_id,kind,currency) VALUES('tenant-alpha','system-old','system','UZS') RETURNING id").fetchone()[0]
                dst=conn.execute("INSERT INTO sp_accounts(tenant_id,owner_id,kind,currency) VALUES('tenant-alpha','alice','customer','UZS') RETURNING id").fetchone()[0]
                jid=conn.execute("INSERT INTO sp_journals(tenant_id,kind,actor,currency) VALUES('tenant-alpha','sandbox_credit','legacy','UZS') RETURNING id").fetchone()[0]
                conn.execute("INSERT INTO sp_postings(journal_id,account_id,signed_amount,currency) VALUES(%s,%s,-100,'UZS'),(%s,%s,100,'UZS')",(jid,src,jid,dst))
                conn.execute('UPDATE sp_accounts SET balance=-100 WHERE id=%s',(src,))
                conn.execute('UPDATE sp_accounts SET balance=100 WHERE id=%s',(dst,))
        assert migrate(target)==4 and migrate(target)==4
        with psycopg.connect(target,autocommit=True) as conn:
            assert conn.execute('SELECT balance FROM sp_accounts WHERE id=%s',(dst,)).fetchone()[0]==100
            assert conn.execute('SELECT sealed FROM sp_journals WHERE id=%s',(jid,)).fetchone()[0]
        assert PgProcessor(target).reconcile(ops)['ok']
    finally:
        with psycopg.connect(DSN,autocommit=True) as admin:
            admin.execute(sql.SQL('DROP DATABASE {}').format(sql.Identifier(name)))

# Block 2: bank workflows against real PostgreSQL; no live rails.
from spyderpay_core.postgres.banking import Banking

def bank_actor(role,subject=None,tenant='tenant-alpha'):
    return Principal('key-'+role,tenant,subject or role+'-actor',frozenset({role}))
bo=bank_actor('bank_ops');br=bank_actor('bank_review');bc=bank_actor('bank_callback');bs=bank_actor('bank_statement');risk=bank_actor('risk_ops')

def bank_setup(engine,direction='withdrawal',amount=20000):
    a,b,_=create(engine);bank=Banking(engine)
    bank.risk(risk,a,'approved','risk-review-001','bank-risk-000001')
    i=bank.create(bo,a,direction,'sandbox-bank',amount,'beneficiary-001','consent-000001','bank-create-0001')
    return bank,a,b,i

def submit_bank(bank,i):
    bank.review(br,i['id'],'bank-review-0001')
    return bank.submit(bo,i['id'],'external-reference-1','bank-submit-0001')

def evidence_pair(bank,i,status='settled',**changes):
    common={'provider_id':i['provider'],'provider_ref':i['provider_ref'],'direction':i['direction'],'amount':i['amount'],'beneficiary_ref':i['beneficiary_ref'],'status':status,'payload_digest':'a'*64}
    c=bank.evidence(bc,'callback',event_ref='callback-event-1',idem='bank-callback-0001',**common)
    s=bank.evidence(bs,'statement',event_ref='statement-event-1',idem='bank-statement-001',**{**common,**changes})
    return c,s

def test_bank_withdrawal_hold_then_settle(engine):
    bank,a,b,i=bank_setup(engine);i=submit_bank(bank,i)
    assert engine.account(alice,a)['balance']==80000
    c,s=evidence_pair(bank,i)
    result=bank.settle(br,i['id'],c['id'],s['id'],'bank-settle-0001')
    assert result['state']=='settled' and result['final_journal']
    assert bank.settle(br,i['id'],c['id'],s['id'],'bank-settle-0001')==result
    assert engine.account(alice,a)['balance']==80000 and engine.reconcile(ops)['ok']
    assert bank.report(br)['hold_mismatches']==0

def test_bank_unknown_retains_hold(engine):
    bank,a,_,i=bank_setup(engine);i=submit_bank(bank,i)
    assert bank.unknown(bo,i['id'],'bank-unknown-001')['state']=='unknown'
    with pytest.raises(PaymentError):bank.cancel(br,i['id'],'bank-cancel-0001')
    assert engine.account(alice,a)['balance']==80000
    c,s=evidence_pair(bank,i,'failed');assert bank.settle(br,i['id'],c['id'],s['id'],'bank-settle-0001')['state']=='failed'
    assert engine.account(alice,a)['balance']==100000

def test_bank_deposit_no_credit_until_two_evidence(engine):
    bank,a,_,i=bank_setup(engine,'deposit');i=submit_bank(bank,i)
    assert engine.account(alice,a)['balance']==100000
    c,s=evidence_pair(bank,i)
    with pytest.raises(PaymentError):bank.settle(br,i['id'],c['id'],c['id'],'bank-settle-0000')
    assert engine.account(alice,a)['balance']==100000
    assert bank.settle(br,i['id'],c['id'],s['id'],'bank-settle-0001')['state']=='settled'
    assert engine.account(alice,a)['balance']==120000

def test_bank_mismatch_cannot_settle(engine):
    bank,a,_,i=bank_setup(engine);i=submit_bank(bank,i);c,s=evidence_pair(bank,i,amount=1000)
    with pytest.raises(PaymentError,match='bank_evidence_mismatch'):bank.settle(br,i['id'],c['id'],s['id'],'bank-settle-0001')
    assert engine.account(alice,a)['balance']==80000 and bank.get(br,i['id'])['state']=='submitted'
    assert bank.report(br)['conflicting_intents']==1

def test_bank_cancel_releases_hold_before_submission(engine):
    bank,a,_,i=bank_setup(engine);bank.review(br,i['id'],'bank-review-0001')
    assert bank.cancel(br,i['id'],'bank-cancel-0001')['state']=='cancelled'
    assert engine.account(alice,a)['balance']==100000

def test_bank_same_actor_review_denied(engine):
    bank,a,_,i=bank_setup(engine)
    with pytest.raises(PaymentError,match='independent_review_required'):bank.review(bank_actor('bank_review',bo.subject),i['id'],'bank-review-0001')
    assert engine.account(alice,a)['balance']==100000

def test_bank_risk_required_and_revocation_blocks_submit(engine):
    bank,a,b,i=bank_setup(engine)
    with pytest.raises(PaymentError,match='bank_risk_review_required'):bank.create(bo,b,'deposit','sandbox-bank',200,'beneficiary-002','consent-000002','bank-create-0002')
    bank.review(br,i['id'],'bank-review-0001')
    bank.risk(risk,a,'blocked','risk-review-002','bank-risk-000002')
    with pytest.raises(PaymentError,match='bank_risk_review_required'):bank.submit(bo,i['id'],'external-reference-1','bank-submit-0001')
    assert bank.cancel(br,i['id'],'bank-cancel-0001')['state']=='cancelled'

def test_bank_tenant_isolation(engine):
    bank,a,_,i=bank_setup(engine)
    with pytest.raises(PaymentError,match='bank_intent_not_found'):bank.get(bank_actor('bank_review',tenant='tenant-other'),i['id'])
    with pytest.raises(PaymentError):bank.review(bank_actor('bank_review',tenant='tenant-other'),i['id'],'bank-review-0001')
    assert bank.report(bank_actor('bank_review',tenant='tenant-other'))['totals']==[]

def test_bank_consent_cannot_reuse(engine):
    bank,a,_,i=bank_setup(engine)
    with pytest.raises(PaymentError,match='bank_consent_already_used'):bank.create(bo,a,'withdrawal','sandbox-bank',200,'beneficiary-001','consent-000001','bank-create-0002')

def test_bank_evidence_idempotence_and_conflicting_event(engine):
    bank,a,_,i=bank_setup(engine);i=submit_bank(bank,i);c,s=evidence_pair(bank,i)
    args=(bc,'callback',i['provider'],'callback-event-1',i['provider_ref'],i['direction'],i['amount'],i['beneficiary_ref'],'settled','a'*64)
    assert bank.evidence(*args,'bank-callback-0002')['id']==c['id']
    with pytest.raises(PaymentError,match='bank_event_conflict'):bank.evidence(*args[:-1],'b'*64,'bank-callback-0003')

def test_bank_conflict_not_cherry_picked(engine):
    bank,a,_,i=bank_setup(engine);i=submit_bank(bank,i);c,s=evidence_pair(bank,i)
    bank.evidence(bc,'callback',i['provider'],'callback-event-2',i['provider_ref'],i['direction'],i['amount'],i['beneficiary_ref'],'failed','b'*64,'bank-callback-0002')
    with pytest.raises(PaymentError,match='bank_evidence_conflict'):bank.settle(br,i['id'],c['id'],s['id'],'bank-settle-0001')
    assert engine.account(alice,a)['balance']==80000

def test_bank_double_settle_race(engine):
    bank,a,_,i=bank_setup(engine,'deposit');i=submit_bank(bank,i);c,s=evidence_pair(bank,i)
    def settle(n):
        try:return bank.settle(br,i['id'],c['id'],s['id'],f'bank-settle-{n:04d}')['state']
        except PaymentError as e:return e.code
    with ThreadPoolExecutor(max_workers=2) as pool:out=list(pool.map(settle,[1,2]))
    assert sorted(out)==['bank_not_settleable','settled'];assert engine.account(alice,a)['balance']==120000

def test_bank_case_workflow(engine):
    bank,a,_,i=bank_setup(engine);i=submit_bank(bank,i)
    case=bank.open_case(bo,i['id'],'timeout','bank-case-000001')
    assert bank.report(br)['open_cases']==1
    with pytest.raises(PaymentError):bank.close_case(bank_actor('bank_review',bo.subject),case['id'],'reviewed-001','bank-close-0001')
    assert bank.close_case(br,case['id'],'reviewed-001','bank-close-0002')['state']=='closed'
    assert bank.report(br)['open_cases']==0 and engine.account(alice,a)['balance']==80000

def test_bank_release_to_frozen_account(engine):
    bank,a,_,i=bank_setup(engine);i=submit_bank(bank,i)
    engine.freeze(ops,a,'risk hold after send','freeze-after-send')
    c,s=evidence_pair(bank,i,'failed')
    bank.settle(br,i['id'],c['id'],s['id'],'bank-settle-0001')
    assert engine.account(alice,a)['balance']==100000 and engine.account(alice,a)['status']=='frozen'

def test_bank_db_immutable_evidence_and_intent(engine):
    bank,a,_,i=bank_setup(engine);i=submit_bank(bank,i);c,s=evidence_pair(bank,i)
    with psycopg.connect(DSN,autocommit=True) as conn:
        with pytest.raises(psycopg.Error):conn.execute('UPDATE sp_bank_evidence SET amount=1 WHERE id=%s',(c['id'],))
        with pytest.raises(psycopg.Error):conn.execute('UPDATE sp_bank_intents SET amount=1 WHERE id=%s',(i['id'],))
        with pytest.raises(psycopg.Error):conn.execute("UPDATE sp_bank_intents SET state='failed' WHERE id=%s",(i['id'],))

def test_bank_runtime_role_workflow(engine):
    bank,a,_,i=bank_setup(engine)
    with psycopg.connect(DSN,autocommit=True) as conn:conn.execute((Path(__file__).parents[2]/'spyderpay_core/postgres/ops/runtime_roles.sql').read_text())
    class Restricted(PgProcessor):
        def _connect(self):
            conn=super()._connect();conn.execute('SET ROLE spyderpay_runtime');return conn
    bank=Banking(Restricted(DSN));i=submit_bank(bank,i);c,s=evidence_pair(bank,i)
    assert bank.settle(br,i['id'],c['id'],s['id'],'bank-settle-0001')['state']=='settled'
