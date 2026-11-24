from contextlib import nullcontext
from types import SimpleNamespace
import pytest
from spyderpay_core.ledger import PaymentError
from spyderpay_core.postgres.store import Principal
from spyderpay_core.postgres import customer_activity as module

A='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
P=Principal('k','tenant','owner',frozenset({'customer'}),identity=object())
class Conn:
    def __init__(self,account,rows):self.account=account;self.rows=rows;self.calls=[]
    def transaction(self):return nullcontext()
    def execute(self,sql,args):
        self.calls.append((sql,args))
        return SimpleNamespace(fetchone=lambda:self.account,fetchall=lambda:self.rows)
class Processor:
    def __init__(self,conn):self.conn=conn
    def _connect(self):return nullcontext(self.conn)

def test_activity_bounded_and_owner_scoped(monkeypatch):
    monkeypatch.setattr(module,'assert_membership',lambda conn,p:None)
    c=Conn({'id':A},[{'amount':i+1} for i in range(51)])
    r=module.customer_activity(Processor(c),P,A)
    assert r['has_more'] and len(r['activity'])==50 and r['real_money'] is False
    assert c.calls[0][1]==(A,'tenant','owner') and c.calls[1][1]==(A,'tenant')
    assert 'LIMIT 51' in c.calls[1][0]

def test_activity_other_account_does_not_query_postings(monkeypatch):
    monkeypatch.setattr(module,'assert_membership',lambda conn,p:None)
    c=Conn(None,[])
    with pytest.raises(PaymentError,match='account_not_found'):module.customer_activity(Processor(c),P,A)
    assert len(c.calls)==1

@pytest.mark.parametrize('p',[Principal('k','tenant','owner',frozenset({'customer'})),Principal('k','tenant','owner',frozenset({'merchant'}),identity=object())])
def test_activity_rejects_noncustomer(p):
    with pytest.raises(PaymentError,match='customer_identity_required'):module.customer_activity(None,p,A)
