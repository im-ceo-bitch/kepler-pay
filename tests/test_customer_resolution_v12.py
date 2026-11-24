from contextlib import nullcontext
from types import SimpleNamespace
import pytest
from spyderpay_core.ledger import PaymentError
from spyderpay_core.postgres.store import Principal
from spyderpay_core.postgres import customer_receipt as module
A='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';I='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';M='cccccccc-cccc-4ccc-8ccc-cccccccccccc';J='dddddddd-dddd-4ddd-8ddd-dddddddddddd'
P=Principal('k','tenant','owner',frozenset({'customer'}),identity=object())
class Conn:
    def __init__(self,account,row,expired=False):self.account=account;self.row=row;self.expired=expired;self.calls=[]
    def transaction(self):return nullcontext()
    def execute(self,sql,args):
        self.calls.append((sql,args))
        if 'FROM sp_accounts' in sql:r=self.account
        elif 'FROM sp_invoices' in sql:r=self.row
        elif ' AS expired' in sql:r={'expired':self.expired}
        elif 'UPDATE sp_invoices' in sql:r={'id':I}
        else:raise AssertionError(sql)
        return SimpleNamespace(fetchone=lambda:r)
class Engine:
    def __init__(self,c):self.c=c;self.audit=[]
    def _connect(self):return nullcontext(self.c)
    def _audit(self,*args):self.audit.append(args)
@pytest.fixture(autouse=True)
def mock_membership(monkeypatch):monkeypatch.setattr(module,'assert_membership',lambda c,p:None);monkeypatch.setattr(module,'totals',lambda c,i:(500,0))
def row(state='pending',payer=None,journal=None):return {'id':I,'state':state,'amount':4000,'merchant_account':M,'payer_account':payer,'payment_journal':journal,'expires_at':'2026-11-24T00:00:00Z'}
def test_unresolved_not_final():
    c=Conn({'id':A},row());r=module.resolve_payment(Engine(c),P,I,A,M,4000)
    assert r['state']=='unresolved' and r['receipt'] is None and 'FOR UPDATE' in c.calls[1][0]
def test_expired_is_sealed_before_no_debit():
    c=Conn({'id':A},row(),expired=True);e=Engine(c);r=module.resolve_payment(e,P,I,A,M,4000)
    assert r['state']=='not_paid_final' and r['receipt'] is None
    assert "state='cancelled'" in c.calls[3][0] and e.audit
def test_committed_before_expiry_resolution():
    c=Conn({'id':A},row('paid',A,J),expired=True);r=module.resolve_payment(Engine(c),P,I,A,M,4000)
    assert r['state']=='committed' and r['receipt']['payment_journal']==J and r['receipt']['refunded_total']==500
    assert len(c.calls)==2
def test_wrong_owner_never_queries_invoice():
    c=Conn(None,row('paid',A,J));e=Engine(c)
    with pytest.raises(PaymentError,match='account_not_found'):module.resolve_payment(e,P,I,A,M,4000)
    assert len(c.calls)==1
