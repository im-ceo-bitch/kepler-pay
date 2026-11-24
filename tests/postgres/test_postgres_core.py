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
        conn.execute('''TRUNCATE sp_card_challenges,sp_cards,sp_bank_consents,sp_statement_approvals,sp_statement_rows,sp_statement_batches,sp_compliance_decisions,sp_compliance_reviews,sp_bank_evidence_use,sp_bank_cases,sp_bank_evidence,sp_bank_intents,sp_bank_risk,sp_payment_approvals,sp_revoked_sessions,sp_identity_members,sp_postings,sp_journals,sp_accounts,sp_invoices,
          sp_outbox,sp_audit_events,sp_idempotency,sp_api_replay,sp_rate_windows,sp_bank_inbox RESTART IDENTITY CASCADE''')
        conn.execute("TRUNCATE sp_gate_resume_requests,sp_gate_events; UPDATE sp_runtime_gate SET paused=false,generation=0")
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
    # The authenticated payment path now requires current, independent compliance decisions.
    if provision:
        with engine._connect() as conn:
            accounts=conn.execute("SELECT id FROM sp_accounts WHERE tenant_id='tenant-alpha' AND kind IN ('customer','merchant')").fetchall()
        comp=Compliance(engine)
        for account in accounts:
            aid=str(account['id']); tag=uuid.uuid4().hex
            row=comp.record(bank_actor('compliance_maker'),aid,'verified','clear','standard','kyc-'+tag,'record-'+tag)
            comp.decide(bank_actor('compliance_review'),row['id'],'approved','decide-'+tag)
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
        from spyderpay_core.release import SCHEMA_VERSION
        assert migrate(target)==SCHEMA_VERSION and migrate(target)==SCHEMA_VERSION
        with psycopg.connect(target,autocommit=True) as conn:
            assert conn.execute('SELECT balance FROM sp_accounts WHERE id=%s',(dst,)).fetchone()[0]==100
            assert conn.execute('SELECT sealed FROM sp_journals WHERE id=%s',(jid,)).fetchone()[0]
        assert PgProcessor(target).reconcile(ops)['ok']
    finally:
        with psycopg.connect(DSN,autocommit=True) as admin:
            admin.execute(sql.SQL('DROP DATABASE {}').format(sql.Identifier(name)))

# Block 2: bank workflows against real PostgreSQL; no live rails.
from spyderpay_core.postgres.banking import Banking
from spyderpay_core.postgres.compliance import Compliance
from spyderpay_core.postgres.clearing import Clearing
from spyderpay_core.postgres.consent import Consent

def bank_actor(role,subject=None,tenant='tenant-alpha'):
    return Principal('key-'+role,tenant,subject or role+'-actor',frozenset({role}))
bo=bank_actor('bank_ops');br=bank_actor('bank_review');bc=bank_actor('bank_callback');bs=bank_actor('bank_statement');risk=bank_actor('risk_ops')

def bank_setup(engine,direction='withdrawal',amount=20000):
    a,b,_=create(engine);bank=Banking(engine)
    bank.risk(risk,a,'approved','risk-review-001','bank-risk-000001')
    compliance=Compliance(engine)
    r=compliance.record(bank_actor('compliance_maker'),a,'verified','clear','standard','kyc-ref-001','kyc-record-0001')
    compliance.decide(bank_actor('compliance_review'),r['id'],'approved','kyc-decide-0001')
    Consent(engine).attest(bank_actor('bank_consent'),a,'sandbox-bank',direction,amount,'beneficiary-001','consent-000001','c'*64,'consent-attest-0001')
    i=bank.create(bo,a,direction,'sandbox-bank',amount,'beneficiary-001','consent-000001','bank-create-0001')
    return bank,a,b,i

def submit_bank(bank,i):
    bank.review(br,i['id'],'bank-review-0001')
    return bank.submit(bo,i['id'],'external-reference-1','bank-submit-0001')

def evidence_pair(bank,i,status='settled',**changes):
    common={'provider_id':i['provider'],'provider_ref':i['provider_ref'],'direction':i['direction'],'amount':i['amount'],'beneficiary_ref':i['beneficiary_ref'],'status':status,'payload_digest':'a'*64}
    c=bank.evidence(bc,'callback',event_ref='callback-event-1',idem='bank-callback-0001',**common)
    terms={**common,**changes};row={k:terms[k] for k in ('provider_ref','direction','amount','beneficiary_ref','status')};row['event_ref']='statement-event-1'
    credit=row['amount'] if row['direction']=='deposit' and row['status']=='settled' else 0
    debit=row['amount'] if row['direction']=='withdrawal' and row['status']=='settled' else 0
    clearing=Clearing(bank.p);result=clearing.ingest(bs,i['provider'],'statement-batch-1',100000,100000+credit-debit,credit,debit,[row],'bank-statement-001')
    clearing.approve(bank_actor('clearing_review'),result['batch']['id'],result['batch']['digest'],'statement-approve-001')
    s=result['evidence'][0]
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
    with pytest.raises(PaymentError,match='bank_consent_already_used'):bank.create(bo,a,'withdrawal','sandbox-bank',20000,'beneficiary-001','consent-000001','bank-create-0002')

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

# v5: enforced consent, compliance and independently approved statement batches.
def test_v5_new_compliance_review_blocks_pending_intent(engine):
    bank,a,_,i=bank_setup(engine)
    Compliance(engine).record(bank_actor('compliance_maker'),a,'verified','hit','standard','kyc-ref-002','kyc-record-0002')
    with pytest.raises(PaymentError,match='compliance_review_required'):bank.review(br,i['id'],'bank-review-0001')
    assert engine.account(alice,a)['balance']==100000

def test_v5_cannot_approve_screening_hit(engine):
    a,_,_=create(engine);c=Compliance(engine)
    r=c.record(bank_actor('compliance_maker'),a,'verified','hit','standard','kyc-ref-003','kyc-record-0003')
    with pytest.raises(PaymentError,match='invalid_compliance_decision'):c.decide(bank_actor('compliance_review'),r['id'],'approved','kyc-decide-0003')

def test_v5_compliance_maker_checker_distinct(engine):
    a,_,_=create(engine);c=Compliance(engine);p=bank_actor('compliance_maker')
    r=c.record(p,a,'verified','clear','standard','kyc-ref-003','kyc-record-0003')
    with pytest.raises(PaymentError):c.decide(bank_actor('compliance_review',p.subject),r['id'],'approved','kyc-decide-0003')

def test_v5_consent_terms_cannot_change(engine):
    bank,a,_,i=bank_setup(engine)
    with pytest.raises(PaymentError,match='matching_bank_consent_required'):bank.create(bo,a,'withdrawal','sandbox-bank',20001,'beneficiary-001','consent-000001','bank-create-0002')

def test_v5_unapproved_statement_cannot_settle(engine):
    bank,a,_,i=bank_setup(engine);i=submit_bank(bank,i)
    c=bank.evidence(bc,'callback',i['provider'],'callback-event-1',i['provider_ref'],i['direction'],i['amount'],i['beneficiary_ref'],'settled','a'*64,'bank-callback-0001')
    row=dict(event_ref='statement-event-1',provider_ref=i['provider_ref'],direction=i['direction'],amount=i['amount'],beneficiary_ref=i['beneficiary_ref'],status='settled')
    cl=Clearing(engine);b=cl.ingest(bs,i['provider'],'batch-001',100000,80000,0,20000,[row],'batch-create-001')
    s=b['evidence'][0]
    with pytest.raises(PaymentError,match='reviewed_statement_required'):bank.settle(br,i['id'],c['id'],s['id'],'bank-settle-0001')
    with pytest.raises(PaymentError,match='statement_review_mismatch'):cl.approve(bank_actor('clearing_review'),'{}'.format(b['batch']['id']),'0'*64,'batch-approve-001')
    cl.approve(bank_actor('clearing_review'),b['batch']['id'],b['batch']['digest'],'batch-approve-001')
    assert bank.settle(br,i['id'],c['id'],s['id'],'bank-settle-0001')['state']=='settled'
    assert cl.reconciliation(bank_actor('clearing_review'))['approved_unconsumed_rows']==0

def test_v5_statement_reference_duplicate_batch(engine):
    bank,a,_,i=bank_setup(engine);i=submit_bank(bank,i);evidence_pair(bank,i)
    row=dict(event_ref='statement-event-2',provider_ref=i['provider_ref'],direction=i['direction'],amount=i['amount'],beneficiary_ref=i['beneficiary_ref'],status='settled')
    with pytest.raises(PaymentError,match='statement_reference_already_imported'):Clearing(engine).ingest(bs,i['provider'],'batch-002',100000,80000,0,20000,[row],'batch-create-002')

def test_v5_operational_snapshot_tenant_scoped(engine):
    from spyderpay_core.postgres.operations import operational_snapshot
    bank,a,_,i=bank_setup(engine)
    snapshot=operational_snapshot(engine,ops)
    assert snapshot['status']=='ok' and snapshot['real_money'] is False
    assert operational_snapshot(engine,Principal('ops-other','tenant-other','ops-other',frozenset({'ops'})))['status']=='ok'

def test_v5_internal_payment_new_screening_hit_rolls_back_approval(engine):
    a,b,_=create(engine);p=identity_for(engine);key='risk-revocation-0001';q=confirm(engine,p,challenge(engine,p,a,b,100,key))
    Compliance(engine).record(bank_actor('compliance_maker'),b,'verified','hit','standard','kyc-new-hit-001','kyc-hit-record-001')
    with pytest.raises(PaymentError,match='compliance_review_required'):engine.transfer(q,a,b,100,key)
    assert engine.account(alice,a)['balance']==100000
    with psycopg.connect(DSN,autocommit=True) as conn:
        assert conn.execute('SELECT consumed_at FROM sp_payment_approvals WHERE id=%s',(q.approval_id,)).fetchone()[0] is None

# v6: database-backed one-shot dispatch and production-role preflight.
from spyderpay_core.postgres.dispatch import Dispatch
from spyderpay_core.postgres.runtime_preflight import check_runtime

def test_v6_dispatch_single_claim_and_unknown_recovery(engine):
    bank,a,_,i=bank_setup(engine);bank.review(br,i['id'],'bank-review-0001')
    d=Dispatch(engine);p=bank_actor('bank_dispatch');claim=d.claim(p,i['id'])
    assert claim['request_ref']=='sp-'+i['id'] and claim['action']=='submit_once'
    with pytest.raises(PaymentError,match='dispatch_claim_forbidden'):d.claim(p,i['id'])
    assert d.status(p,i['id'])['action']=='lookup_only'
    assert d.report(p,i['id'],'unknown','dispatch-result-0001')['state']=='unknown'
    assert engine.account(alice,a)['balance']==80000
    with pytest.raises(PaymentError):bank.cancel(br,i['id'],'bank-cancel-0001')
    i=bank.get(br,i['id']);c,s=evidence_pair(bank,i)
    assert bank.settle(br,i['id'],c['id'],s['id'],'bank-settle-0001')['state']=='settled'
    assert d.status(p,i['id'])['action']=='terminal' and engine.reconcile(ops)['ok']

def test_v6_concurrent_claim_only_one(engine):
    bank,a,_,i=bank_setup(engine);bank.review(br,i['id'],'bank-review-0001');d=Dispatch(engine);p=bank_actor('bank_dispatch')
    def claim(_):
        try:return d.claim(p,i['id'])['action']
        except PaymentError as e:return e.code
    with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(claim,[0,1]))
    assert sorted(results)==['dispatch_claim_forbidden','submit_once']

def test_v6_dispatch_tenant_and_actor_isolated(engine):
    bank,a,_,i=bank_setup(engine);bank.review(br,i['id'],'bank-review-0001');d=Dispatch(engine);p=bank_actor('bank_dispatch')
    with pytest.raises(PaymentError):d.claim(bank_actor('bank_dispatch',tenant='tenant-other'),i['id'])
    with pytest.raises(PaymentError):d.claim(bank_actor('bank_dispatch',subject=bo.subject),i['id'])
    d.claim(p,i['id'])
    with pytest.raises(PaymentError):d.report(bank_actor('bank_dispatch',subject='other-actor'),i['id'],'accepted','dispatch-result-0001')
    with pytest.raises(PaymentError):d.status(bank_actor('bank_dispatch',tenant='tenant-other'),i['id'])

def test_v6_dispatch_immutable_and_runtime_role(engine):
    bank,a,_,i=bank_setup(engine);bank.review(br,i['id'],'bank-review-0001')
    with psycopg.connect(DSN,autocommit=True) as conn:
        conn.execute((Path(__file__).parents[2]/'spyderpay_core/postgres/ops/runtime_roles.sql').read_text())
    class Restricted(PgProcessor):
        def _connect(self):
            conn=super()._connect();conn.execute('SET ROLE spyderpay_runtime');return conn
    r=Restricted(DSN);d=Dispatch(r);p=bank_actor('bank_dispatch')
    with r._connect() as conn:check_runtime(conn)
    d.claim(p,i['id']);result=d.report(p,i['id'],'accepted','dispatch-result-0001')
    assert result['outcome']=='accepted'
    assert d.report(p,i['id'],'accepted','dispatch-result-0001')==result
    with psycopg.connect(DSN,autocommit=True) as conn:
        with pytest.raises(psycopg.Error):conn.execute('UPDATE sp_rail_dispatch SET request_ref=%s WHERE intent_id=%s',('other-ref',i['id']))
    with r._connect() as conn:
        with pytest.raises(psycopg.Error):conn.execute('DELETE FROM sp_rail_dispatch WHERE intent_id=%s',(i['id'],))

def test_v6_late_result_does_not_reopen_settled_intent(engine):
    bank,a,_,i=bank_setup(engine);bank.review(br,i['id'],'bank-review-0001');d=Dispatch(engine);p=bank_actor('bank_dispatch')
    d.claim(p,i['id']);i=bank.get(br,i['id']);c,s=evidence_pair(bank,i)
    bank.settle(br,i['id'],c['id'],s['id'],'bank-settle-0001')
    assert d.report(p,i['id'],'unknown','dispatch-result-0001')['state']=='settled'
    assert engine.reconcile(ops)['ok']

# v0.7: fee quote, reversal and full internal chargeback under actual PostgreSQL.
from spyderpay_core.postgres.financial_controls import FinancialControls
fm=bank_actor('fee_maker');fr=bank_actor('fee_review');dm=bank_actor('dispute_maker');dr=bank_actor('dispute_review');de=bank_actor('dispute_execute')

def fee_invoice(engine):
    a,_,shop=create(engine);f=FinancialControls(engine)
    fee=f.propose_fee(fm,shop,200,'agreement-001','fee-propose-0001')
    f.approve_fee(fr,fee['id'],'fee-approve-0001')
    inv=engine.create_invoice(merchant,shop,10000,'fee-invoice-0001')
    assert inv['merchant_fee']==200
    return a,shop,inv,f

def test_v7_fee_locked_at_quote_and_reversal(engine):
    a,shop,i,f=fee_invoice(engine)
    s=f.propose_fee(fm,shop,500,'agreement-002','fee-propose-0002');f.approve_fee(fr,s['id'],'fee-approve-0002')
    engine.pay_invoice(alice,i['id'],a,'fee-pay-0000001')
    assert engine.account(merchant,shop)['balance']==9800
    engine.refund_invoice(merchant,i['id'],'fee-refund-0001')
    assert engine.account(merchant,shop)['balance']==0 and engine.account(alice,a)['balance']==100000
    assert engine.reconcile(ops)['ok']
    with psycopg.connect(DSN) as conn:assert conn.execute('SELECT count(*) FROM sp_fee_movements WHERE invoice_id=%s',(i['id'],)).fetchone()[0]==2

def test_v7_chargeback_full_and_idempotent(engine):
    a,shop,i,f=fee_invoice(engine);engine.pay_invoice(alice,i['id'],a,'fee-pay-0000001')
    c=f.open(dm,i['id'],'not_delivered','case-evidence-001','dispute-open-001')
    with pytest.raises(PaymentError,match='chargeback_in_progress'):engine.refund_invoice(merchant,i['id'],'refund-during-case')
    with pytest.raises(PaymentError):f.execute(de,c['id'],'dispute-exec-001')
    f.decide(dr,c['id'],'approve','review-evidence-001','dispute-decide-01')
    r=f.execute(de,c['id'],'dispute-exec-001');assert f.execute(de,c['id'],'dispute-exec-001')==r
    with pytest.raises(PaymentError):f.execute(de,c['id'],'dispute-exec-002')
    assert engine.account(alice,a)['balance']==100000 and engine.account(merchant,shop)['balance']==0 and engine.reconcile(ops)['ok']

def test_v7_rejected_dispute_allows_normal_refund(engine):
    a,shop,i,f=fee_invoice(engine);engine.pay_invoice(alice,i['id'],a,'fee-pay-0000001')
    c=f.open(dm,i['id'],'other','case-evidence-001','dispute-open-001');f.decide(dr,c['id'],'reject','review-evidence-001','dispute-decide-01')
    with pytest.raises(PaymentError):f.execute(de,c['id'],'dispute-exec-001')
    engine.refund_invoice(merchant,i['id'],'fee-refund-0001');assert engine.account(alice,a)['balance']==100000

def test_v7_fee_independent_and_tenant_isolation(engine):
    _,_,shop=create(engine);f=FinancialControls(engine);s=f.propose_fee(fm,shop,100,'agreement-001','fee-propose-0001')
    with pytest.raises(PaymentError):f.approve_fee(bank_actor('fee_review',fm.subject),s['id'],'fee-approve-0001')
    with pytest.raises(PaymentError):f.approve_fee(bank_actor('fee_review',tenant='tenant-other'),s['id'],'fee-approve-0001')

def test_v7_no_approved_fee_default_zero(engine):
    _,_,shop=create(engine);f=FinancialControls(engine);f.propose_fee(fm,shop,100,'agreement-001','fee-propose-0001')
    assert engine.create_invoice(merchant,shop,10000,'fee-invoice-0001')['merchant_fee']==0

def test_v7_fee_and_dispute_runtime_permissions(engine):
    with psycopg.connect(DSN,autocommit=True) as conn:conn.execute((Path(__file__).parents[2]/'spyderpay_core/postgres/ops/runtime_roles.sql').read_text())
    class Restricted(PgProcessor):
        def _connect(self):
            c=super()._connect();c.execute('SET ROLE spyderpay_runtime');return c
    r=Restricted(DSN);a,shop,i,f=fee_invoice(r);r.pay_invoice(alice,i['id'],a,'fee-pay-0000001')
    c=f.open(dm,i['id'],'other','case-evidence-001','dispute-open-001');f.decide(dr,c['id'],'approve','review-evidence-001','dispute-decide-01');f.execute(de,c['id'],'dispute-exec-001')
    assert r.reconcile(ops)['ok']
    with r._connect() as conn:
        with pytest.raises(psycopg.Error):conn.execute('DELETE FROM sp_chargebacks')
        with pytest.raises(psycopg.Error):conn.execute('UPDATE sp_invoice_fees SET amount=0')

def test_v7_chargeback_concurrent_execution(engine):
    a,shop,i,f=fee_invoice(engine);engine.pay_invoice(alice,i['id'],a,'fee-pay-0000001')
    c=f.open(dm,i['id'],'other','case-evidence-001','dispute-open-001');f.decide(dr,c['id'],'approve','review-evidence-001','dispute-decide-01')
    def run(n):
        try:f.execute(de,c['id'],f'dispute-exec-{n:04}');return True
        except PaymentError:return False
    with ThreadPoolExecutor(max_workers=2) as pool:assert sum(pool.map(run,(1,2)))==1
    assert engine.account(alice,a)['balance']==100000 and engine.reconcile(ops)['ok']

def test_v7_recovery_read_only_query(engine):
    from spyderpay_core.postgres.ops.recovery import RESTORE_SQL,classify_restore
    from spyderpay_core.release import SCHEMA_VERSION
    a,shop,i,f=fee_invoice(engine);engine.pay_invoice(alice,i['id'],a,'fee-pay-0000001')
    with engine._connect() as conn,conn.transaction():
        conn.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
        result=classify_restore(SCHEMA_VERSION,dict(conn.execute(RESTORE_SQL).fetchone()))
    assert result['ok'] and result['counts']['journals']>=3


def test_v7_pos_preview_bound_to_invoice(engine):
    import base64,time,json
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from spyderpay_core.postgres.pos import PosTokens,issue_for_merchant,preview_for_customer
    a,_,shop=create(engine);i=engine.create_invoice(merchant,shop,10000,'pos-invoice-0001')
    mp=identity_for(engine,owner='coffee',role='merchant',sub='external-coffee',sid='session-m')
    cp=identity_for(engine)
    k=Ed25519PrivateKey.generate();now=int(time.time());b64=lambda b:base64.b64encode(b).decode()
    t=PosTokens(json.dumps({'active_kid':'pos-key','private_b64':b64(k.private_bytes_raw()),'keys':[{'kid':'pos-key','public_b64':b64(k.public_key().public_bytes_raw()),'not_before':now-30,'not_after':now+600}]}))
    token=issue_for_merchant(engine,mp,t,i['id'])['token']
    assert preview_for_customer(engine,cp,t,token)['amount']==10000
    engine.pay_invoice(alice,i['id'],a,'pos-pay-00000001')
    with pytest.raises(PaymentError):preview_for_customer(engine,cp,t,token)

# v7.1: executable partner simulator against the actual protected banking core.
@pytest.mark.parametrize('direction,fail,lose_response,expected_balance',[
    ('withdrawal',False,False,80000),('withdrawal',False,True,80000),
    ('withdrawal',True,True,100000),('deposit',False,False,120000),
    ('deposit',True,False,100000)])
def test_v71_partner_roundtrip(engine,tmp_path,direction,fail,lose_response,expected_balance):
    import secrets
    from spyderpay_core.postgres.sandbox_rail import SandboxRail
    from spyderpay_core.postgres.dispatch_worker import DispatchWorker
    from spyderpay_core.postgres.partner_reconciliation import reconcile
    bank,a,_,i=bank_setup(engine,direction)
    bank.review(br,i['id'],'bank-review-0001')
    class FaultRail(SandboxRail):
        def submit(self,instruction):
            return self.simulate(instruction,fail=fail,lose_response=lose_response)
    rail=FaultRail(tmp_path/'partner.db','sandbox-bank',secrets.token_bytes(32),environment='test')
    worker=DispatchWorker(Dispatch(engine),bank_actor('bank_dispatch'),{'sandbox-bank':rail})
    result=worker.execute(i['id'])
    assert result['outcome']==('unknown' if lose_response else 'accepted')
    with pytest.raises(PaymentError):worker.execute(i['id'])
    assert worker.recover(i['id'])['observation']=='accepted'
    i=bank.get(br,i['id']);raw,headers=rail.callback(i['provider_ref']);ev=rail.verify_callback(raw,headers)
    ev['provider_id']=ev.pop('provider')
    callback=bank.evidence(bc,'callback',idem='bank-callback-0001',**ev)
    b=rail.statement_batch();cl=Clearing(engine)
    data=cl.ingest(bs,b['provider'],b['batch_ref'],b['opening'],b['closing'],b['credits'],b['debits'],b['rows'],'bank-statement-001')
    cl.approve(bank_actor('clearing_review'),data['batch']['id'],data['batch']['digest'],'statement-approve-001')
    result=bank.settle(br,i['id'],callback['id'],data['evidence'][0]['id'],'bank-settle-0001')
    assert result['state']==('failed' if fail else 'settled')
    assert engine.account(alice,a)['balance']==expected_balance and engine.reconcile(ops)['ok']
    report=reconcile('sandbox-bank',0,[b],[{k:result[k] for k in ('provider_ref','direction','amount','beneficiary_ref','state')}])
    assert report['balanced']

# v8: amount refunds with atomic fee rounding and remaining balance.
from spyderpay_core.postgres.refunds import refund_amount

def test_v8_partial_refunds_exact_fee_and_total(engine):
    a,shop,i,f=fee_invoice(engine);engine.pay_invoice(alice,i['id'],a,'fee-pay-0000001')
    first=refund_amount(engine,merchant,i['id'],3333,'amount-refund-001')
    assert first['state']=='partially_refunded' and first['fee_amount']==66 and first['remaining']==6667
    assert refund_amount(engine,merchant,i['id'],3333,'amount-refund-001')==first
    with pytest.raises(PaymentError,match='idempotency_conflict'):refund_amount(engine,merchant,i['id'],3334,'amount-refund-001')
    with pytest.raises(PaymentError,match='refund_exceeds_remaining'):refund_amount(engine,merchant,i['id'],6668,'amount-refund-002')
    with pytest.raises(PaymentError,match='use_amount_refund_for_remaining'):engine.refund_invoice(merchant,i['id'],'legacy-refund-001')
    last=refund_amount(engine,merchant,i['id'],6667,'amount-refund-003')
    assert last['fee_amount']==134 and last['state']=='refunded' and last['remaining']==0
    assert engine.account(alice,a)['balance']==100000 and engine.account(merchant,shop)['balance']==0 and engine.reconcile(ops)['ok']
    with engine._connect() as c:assert c.execute('SELECT valid FROM sp_refund_integrity WHERE id=%s',(i['id'],)).fetchone()['valid']

def test_v8_residual_chargeback(engine):
    a,shop,i,f=fee_invoice(engine);engine.pay_invoice(alice,i['id'],a,'fee-pay-0000001')
    refund_amount(engine,merchant,i['id'],4000,'amount-refund-001')
    c=f.open(dm,i['id'],'other','case-evidence-001','dispute-open-001')
    with pytest.raises(PaymentError,match='chargeback_in_progress'):refund_amount(engine,merchant,i['id'],1000,'amount-refund-002')
    f.decide(dr,c['id'],'approve','review-evidence-001','dispute-decide-01')
    f.execute(de,c['id'],'dispute-exec-001')
    assert engine.account(alice,a)['balance']==100000 and engine.account(merchant,shop)['balance']==0
    with engine._connect() as db:
        r=db.execute('SELECT amount,fee_amount FROM sp_amount_refunds WHERE case_id=%s',(c['id'],)).fetchone()
        assert r['amount']==6000 and r['fee_amount']==120
        assert db.execute('SELECT valid FROM sp_refund_integrity WHERE id=%s',(i['id'],)).fetchone()['valid']

def test_v8_concurrent_partial_no_overrefund(engine):
    a,shop,i,f=fee_invoice(engine);engine.pay_invoice(alice,i['id'],a,'fee-pay-0000001')
    def run(n):
        try:refund_amount(engine,merchant,i['id'],7000,f'parallel-refund-{n:04}');return True
        except PaymentError:return False
    with ThreadPoolExecutor(max_workers=2) as pool:assert sum(pool.map(run,(1,2)))==1
    assert engine.account(alice,a)['balance']==97000 and engine.reconcile(ops)['ok']

def test_v8_reject_other_tenant_and_role(engine):
    a,shop,i,f=fee_invoice(engine);engine.pay_invoice(alice,i['id'],a,'fee-pay-0000001')
    with pytest.raises(PaymentError):refund_amount(engine,alice,i['id'],1000,'amount-refund-001')
    alien=Principal('other','tenant-other','coffee',frozenset({'merchant'}))
    with pytest.raises(PaymentError):refund_amount(engine,alien,i['id'],1000,'amount-refund-001')
    assert engine.account(alice,a)['balance']==90000

def test_v8_refunds_under_restricted_db_role(engine):
    with psycopg.connect(DSN,autocommit=True) as c:c.execute((Path(__file__).parents[2]/'spyderpay_core/postgres/ops/runtime_roles.sql').read_text())
    class Restricted(PgProcessor):
        def _connect(self):
            c=super()._connect();c.execute('SET ROLE spyderpay_runtime');return c
    r=Restricted(DSN);a,shop,i,f=fee_invoice(r);r.pay_invoice(alice,i['id'],a,'fee-pay-0000001')
    refund_amount(r,merchant,i['id'],1000,'amount-refund-001')
    with r._connect() as c:
        assert c.execute('SELECT valid FROM sp_refund_integrity WHERE id=%s',(i['id'],)).fetchone()['valid']
        with pytest.raises(psycopg.Error):c.execute('UPDATE sp_amount_refunds SET amount=1')
        with pytest.raises(psycopg.Error):c.execute('DELETE FROM sp_amount_refunds')

def test_v8_amount_refund_mfa_bound_to_amount(engine):
    from spyderpay_core.postgres.identity import issue_approval
    a,shop,i,f=fee_invoice(engine);engine.pay_invoice(alice,i['id'],a,'fee-pay-0000001')
    p=identity_for(engine,owner='coffee',role='merchant',sub='external-coffee')
    key='refund-bound-0001'
    challenge=issue_approval(engine,p,'refund_amount',{'invoice_id':i['id'],'expected_amount':10000,'expected_merchant':shop,'amount':2000},key)
    with pytest.raises(PaymentError,match='approval_required'):refund_amount(engine,p,i['id'],2000,key)
    q=confirm(engine,p,challenge['approval_id'])
    with pytest.raises(PaymentError,match='approval_invalid_or_expired'):refund_amount(engine,q,i['id'],2001,key)
    result=refund_amount(engine,q,i['id'],2000,key)
    assert result['remaining']==8000 and result['fee_amount']==40
    assert refund_amount(engine,p,i['id'],2000,key)==result

# v9 physical card possession only; neither this proof nor a POS QR authorizes money.
def _card_fixture(engine,p=None):
    from cryptography.hazmat.primitives import hashes,serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from spyderpay_core.postgres.cards import Cards
    p=p or identity_for(engine);svc=Cards(engine,VerifierPolicy());k=ec.generate_private_key(ec.SECP256R1())
    pub=k.public_key().public_bytes(serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint).hex()
    def sign(ch):return k.sign(bytes.fromhex(ch['message_hex']),ec.ECDSA(hashes.SHA256())).hex()
    ch=svc.begin_enrollment(p,pub);card=svc.finish(p,ch['challenge_id'],sign(ch))
    return svc,p,card['card_id'],sign,ch,pub


def test_v9_card_enrollment_and_invoice_preview(engine):
    a,_,m=create(engine);i=engine.create_invoice(merchant,m,10000,'card-invoice-0001');svc,p,cid,sign,ch,pub=_card_fixture(engine)
    assert svc.list(p)['cards'][0]['id']==cid
    with pytest.raises(PaymentError):svc.finish(p,ch['challenge_id'],sign(ch))
    with pytest.raises(PaymentError):svc.begin_enrollment(p,pub)
    preview=svc.begin_preview(p,cid,i['id']);proof=svc.finish(p,preview['challenge_id'],sign(preview))
    assert proof['amount']==10000 and proof['requires_payment_approval'] and not proof['payment_authority']
    assert engine.account(alice,a)['balance']==100000
    with pytest.raises(PaymentError):svc.finish(p,preview['challenge_id'],sign(preview))


def test_v9_card_revocation_and_session_binding(engine):
    from dataclasses import replace
    _,_,m=create(engine);i=engine.create_invoice(merchant,m,10000,'card-invoice-0001');svc,p,cid,sign,_,_=_card_fixture(engine)
    ch=svc.begin_preview(p,cid,i['id']);other=replace(p,identity=replace(p.identity,sid='other-session'))
    with pytest.raises(PaymentError):svc.finish(other,ch['challenge_id'],sign(ch))
    assert svc.revoke(p,cid)['state']=='revoked';assert svc.revoke(p,cid)['state']=='revoked'
    with pytest.raises(PaymentError):svc.finish(p,ch['challenge_id'],sign(ch))
    with pytest.raises(PaymentError):svc.begin_preview(p,cid,i['id'])


def test_v9_card_concurrent_challenge_consumption(engine):
    _,_,m=create(engine);i=engine.create_invoice(merchant,m,10000,'card-invoice-0001');svc,p,cid,sign,_,_=_card_fixture(engine)
    ch=svc.begin_preview(p,cid,i['id']);sig=sign(ch)
    def run(_):
        try:svc.finish(p,ch['challenge_id'],sig);return 1
        except PaymentError:return 0
    with ThreadPoolExecutor(max_workers=2) as pool:assert sum(pool.map(run,range(2)))==1


def test_v9_card_runtime_permissions(engine):
    from spyderpay_core.postgres.runtime_preflight import check_runtime
    create(engine);p=identity_for(engine)
    with psycopg.connect(DSN,autocommit=True) as c:c.execute((Path(__file__).parents[2]/'spyderpay_core/postgres/ops/runtime_roles.sql').read_text())
    class Restricted(PgProcessor):
        def _connect(self):
            c=super()._connect();c.execute('SET ROLE spyderpay_runtime');return c
    r=Restricted(DSN);svc,p,cid,_,_,_=_card_fixture(r,p)
    assert svc.list(p)['cards'][0]['id']==cid
    with r._connect() as c:
        check_runtime(c)
        for query in ('DELETE FROM sp_cards','UPDATE sp_cards SET public_key=public_key','TRUNCATE sp_card_challenges'):
            with pytest.raises(psycopg.Error):c.execute(query)
    assert svc.revoke(p,cid)['state']=='revoked'


def test_v9_emergency_gate_blocks_money_but_preserves_idempotency(engine):
    a,b,_=create(engine);first=engine.transfer(alice,a,b,100,'before-gate-payment')
    with engine._connect() as c:c.execute("SELECT sp_gate_pause('incident-0001')")
    assert engine.transfer(alice,a,b,100,'before-gate-payment')==first
    with pytest.raises(PaymentError,match='financial_traffic_paused'):engine.transfer(alice,a,b,200,'after-gate-payment')
    engine.freeze(ops,b,'incident-hold','freeze-gate-0001')
    assert engine.account(alice,a)['balance']==99900 and engine.reconcile(ops)['ok']


def test_v9_incident_separation_and_resume(engine):
    with psycopg.connect(DSN,autocommit=True) as c:
        c.execute((Path(__file__).parents[2]/'spyderpay_core/postgres/ops/runtime_roles.sql').read_text())
        c.execute('SET SESSION AUTHORIZATION spyderpay_incident_maker')
        assert c.execute("SELECT sp_gate_pause('incident-0002')").fetchone()[0]==1
        rid=c.execute("SELECT sp_gate_propose_resume('incident-0002')").fetchone()[0]
        with pytest.raises(psycopg.Error):c.execute('SELECT sp_gate_confirm_resume(%s,%s)',(rid,'incident-0002'))
        c.execute('RESET SESSION AUTHORIZATION')
        c.execute('SET SESSION AUTHORIZATION spyderpay_incident_reviewer')
        with pytest.raises(psycopg.Error):c.execute('SELECT sp_gate_confirm_resume(%s,%s)',(rid,'other-incident'))
        assert c.execute('SELECT sp_gate_confirm_resume(%s,%s)',(rid,'incident-0002')).fetchone()[0]==2
        with pytest.raises(psycopg.Error):c.execute('SELECT sp_gate_confirm_resume(%s,%s)',(rid,'incident-0002'))
        c.execute('RESET SESSION AUTHORIZATION')
        c.execute('SET ROLE spyderpay_runtime')
        assert c.execute('SELECT sp_gate_open()').fetchone()[0]
        with pytest.raises(psycopg.Error):c.execute("SELECT sp_gate_pause('incident-0003')")
        with pytest.raises(psycopg.Error):c.execute('UPDATE sp_runtime_gate SET paused=true')


def test_v9_pause_waits_for_shared_financial_gate(engine):
    with psycopg.connect(DSN,autocommit=True) as first,psycopg.connect(DSN,autocommit=True) as second:
        with first.transaction():
            assert first.execute('SELECT sp_gate_open()').fetchone()[0]
            second.execute("SET lock_timeout='100ms'")
            with pytest.raises(psycopg.errors.LockNotAvailable):second.execute("SELECT sp_gate_pause('incident-0004')")
        assert second.execute("SELECT sp_gate_pause('incident-0004')").fetchone()[0]==1
        assert not first.execute('SELECT sp_gate_open()').fetchone()[0]


def test_v9_backup_role_is_read_only(engine):
    create(engine)
    with psycopg.connect(DSN,autocommit=True) as c:
        c.execute((Path(__file__).parents[2]/'infrastructure/postgres/backup_role.sql').read_text())
        c.execute('SET ROLE spyderpay_backup')
        assert c.execute('SELECT count(*) FROM sp_accounts').fetchone()[0]>=3
        for sql in ('UPDATE sp_accounts SET balance=0','DELETE FROM sp_cards','TRUNCATE sp_audit_events','SELECT sp_gate_pause(\'incident-0005\')'):
            with pytest.raises(psycopg.Error):c.execute(sql)


def test_v10_exact_snapshot_changes_after_financial_transaction(engine):
    from spyderpay_core.postgres.ops.snapshot_fingerprint import fingerprint,TABLES
    a,b,_=create(engine)
    with engine._connect() as c,c.transaction():
        c.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
        first=fingerprint(c);assert first==fingerprint(c) and set(first)==set(TABLES)
        engine.transfer(alice,a,b,100,'snapshot-transfer-0001')
        assert first==fingerprint(c)  # same exported snapshot despite concurrent write
    with engine._connect() as c,c.transaction():
        c.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
        second=fingerprint(c)
    assert first['sp_accounts']['rows']==second['sp_accounts']['rows']
    assert first['sp_accounts']['sha256']!=second['sp_accounts']['sha256']
    assert first['sp_postings']!=second['sp_postings']


def test_v10_monitor_sees_real_counts_without_operator_privileges(engine):
    from spyderpay_core.postgres.operations import operational_snapshot
    from spyderpay_core.postgres.ops.monitor import validate_report
    create(engine)
    m=Principal('monitor-key','tenant-alpha','monitor-agent',frozenset({'monitor'}))
    result=validate_report(operational_snapshot(engine,m))
    assert result['severity']=='ok' and result['real_money'] is False
    with pytest.raises(PaymentError):engine.create_account(m,'new-owner','merchant','monitor-create-0001')
    with engine._connect() as c:c.execute("SELECT sp_gate_pause('monitor-incident-001')")
    assert validate_report(operational_snapshot(engine,m))['severity']=='critical'


def test_v11_receipt_only_payer_and_no_unpaid_receipt(engine):
    from spyderpay_core.postgres.customer_receipt import customer_receipt
    a,b,m=create(engine)
    pa=identity_for(engine);pb=identity_for(engine,owner='bob',sub='external-bob')
    inv=engine.create_invoice(merchant,m,4000,'v11-invoice-receipt-0001')
    with pytest.raises(PaymentError,match='receipt_not_found'):customer_receipt(engine,pa,inv['id'])
    paid=engine.pay_invoice(alice,inv['id'],a,'v11-pay-receipt-0001')
    receipt=customer_receipt(engine,pa,inv['id'])
    assert receipt['payment_journal']==paid['payment_journal'] and receipt['amount']==4000 and receipt['real_money'] is False
    with pytest.raises(PaymentError,match='receipt_not_found'):customer_receipt(engine,pb,inv['id'])
    engine.refund_invoice(merchant,inv['id'],'v11-refund-receipt-0001')
    assert customer_receipt(engine,pa,inv['id'])['refunded_total']==4000


def test_v11_velocity_across_accounts_for_same_owner(engine):
    a,b,_=create(engine)
    second=engine.create_account(ops,'alice','customer','v11-second-alice-account')['id']
    p=identity_for(engine)
    for i in range(10):engine.transfer(alice,a,b,1,f'v11-owner-velocity-{i:04d}')
    with engine._connect() as conn,conn.transaction():
        with pytest.raises(PaymentError,match='bank_velocity_or_amount_limit'):
            Compliance(engine).enforce(conn,p,second,1)
