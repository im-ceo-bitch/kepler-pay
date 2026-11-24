from contextlib import nullcontext
from types import SimpleNamespace
import pytest
from spyderpay_core.ledger import PaymentError
from spyderpay_core.postgres.store import Principal,_digest
from spyderpay_core.postgres import customer_transfer as module
A='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';B='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';J='dddddddd-dddd-4ddd-8ddd-dddddddddddd'
K='wallet-transfer-'+J
P=Principal('k','tenant','owner',frozenset({'customer'}),identity=object())
D=_digest({'op':'transfer','source':A,'target':B,'amount':3000,'tenant':'tenant'})
class Conn:
    def __init__(self,account,row,leg=None):self.account=account;self.row=row;self.leg=leg;self.calls=[]
    def transaction(self):return nullcontext()
    def execute(self,sql,args):
        self.calls.append((sql,args))
        if 'FROM sp_accounts' in sql:r=self.account
        elif 'FROM sp_idempotency' in sql:r=self.row
        elif 'FROM sp_journals' in sql:r=self.leg
        else:r=None
        return SimpleNamespace(fetchone=lambda:r)
class Engine:
    def __init__(self,c):self.c=c;self.audit=[]
    def _connect(self):return nullcontext(self.c)
    def _audit(self,*args):self.audit.append(args)
@pytest.fixture(autouse=True)
def mock_membership(monkeypatch):monkeypatch.setattr(module,'assert_membership',lambda c,p:None)

def test_no_result_is_not_no_debit():
    c=Conn({'id':A},None);e=Engine(c)
    assert module.resolve_transfer(e,P,A,B,3000,K)['state']=='unresolved'
    assert not any('INSERT' in q for q,_ in c.calls)

def test_cancel_tombstone_matches_transaction_key():
    c=Conn({'id':A},{'request_digest':D,'result':None});e=Engine(c)
    assert module.resolve_transfer(e,P,A,B,3000,K,cancel=True)['state']=='cancelled'
    assert c.calls[1][1]==('["tenant","owner"]',K,D)
    assert 'FOR UPDATE' in c.calls[2][0] and 'result IS NULL' in c.calls[3][0]
    assert e.audit

def test_committed_cannot_be_cancelled():
    c=Conn({'id':A},{'request_digest':D,'result':{'journal_id':J,'source':A,'target':B,'amount':3000,'currency':'UZS'}},{'id':J})
    assert module.resolve_transfer(Engine(c),P,A,B,3000,K,cancel=True)['state']=='committed'
    assert not any('UPDATE sp_idempotency' in q for q,_ in c.calls)

def test_mismatch_is_not_success():
    c=Conn({'id':A},{'request_digest':'wrong','result':None})
    with pytest.raises(PaymentError,match='idempotency_conflict'):module.resolve_transfer(Engine(c),P,A,B,3000,K,cancel=True)
    c=Conn({'id':A},{'request_digest':D,'result':{'journal_id':J,'source':A,'target':B,'amount':3000,'currency':'UZS'}},None)
    with pytest.raises(PaymentError,match='transfer_resolution_mismatch'):module.resolve_transfer(Engine(c),P,A,B,3000,K)
