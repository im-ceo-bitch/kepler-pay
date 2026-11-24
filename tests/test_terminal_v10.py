import json
import uuid
from datetime import datetime, timedelta, timezone
import pytest
from spyderpay_core.postgres.ops.merchant_terminal import (Sales, Terminal, MerchantAPI, access_token, check_invoice)

ORIGIN='https://private.example'

def uid():return str(uuid.uuid4())

class API:
    def __init__(self):self.calls=[];self.invoices={};self.fail=False;self.bad=False;self.refunded=0
    def create(self,row):
        self.calls.append(row['id'])
        i=self.invoices.setdefault(row['id'],{'id':uid(),'merchant_account':row['merchant'],'amount':row['amount'],'state':'pending','expires_at':(datetime.now(timezone.utc)+timedelta(minutes=15)).isoformat()})
        if self.fail:raise RuntimeError('lost_response')
        return {**i,'amount':i['amount']+int(self.bad)}
    def status(self,invoice):return {**next(i for i in self.invoices.values() if i['id']==invoice),'refunded_total':self.refunded}
    def qr(self,invoice):return 'signed.preview.token'

@pytest.fixture
def terminal(tmp_path):
    a=API();s=Sales(tmp_path/'private',ORIGIN);return Terminal(a,s),a,s

def test_lost_response_is_resumable(terminal):
    t,a,s=terminal;sid,m=uid(),uid();a.fail=True
    with pytest.raises(RuntimeError):t.create(sid,m,25000)
    assert s.pending()[0]['id']==sid and t.status(sid)['state']=='unknown'
    a.fail=False
    t2=Terminal(a,Sales(s.path.parent,ORIGIN));r=t2.resume(sid)
    assert r['invoice_id']==a.invoices[sid]['id'] and a.calls==[sid,sid] and not s.pending()
    t2.resume(sid);assert len(a.calls)==2

def test_sale_reference_not_reused_for_other_amount(terminal):
    t,a,s=terminal;sid,m=uid(),uid();t.create(sid,m,100)
    with pytest.raises(ValueError,match='sale_reference_conflict'):t.create(sid,m,101)
    with pytest.raises(ValueError):t.create(sid,uid(),100)
    assert len(a.calls)==1

def test_response_mismatch_is_not_attached(terminal):
    t,a,s=terminal;sid=uid();a.bad=True
    with pytest.raises(RuntimeError,match='invoice_mismatch'):t.create(sid,uid(),100)
    assert s.get(sid)['invoice'] is None

def test_payment_status_from_server_not_qr(terminal):
    t,a,s=terminal;sid=uid();t.create(sid,uid(),500)
    assert t.qr(sid)=='signed.preview.token';assert t.status(sid)['state']=='pending'
    a.invoices[sid]['state']='paid';assert t.status(sid)['state']=='paid'
    with pytest.raises(RuntimeError,match='invoice_not_pending'):t.qr(sid)
    a.refunded=200;assert t.status(sid)['refunded_total']==200

def test_expired_invoice_no_qr(terminal):
    t,a,s=terminal;sid=uid();t.create(sid,uid(),500);a.invoices[sid]['expires_at']='2020-01-01T00:00:00+00:00'
    assert t.status(sid)['state']=='expired'
    with pytest.raises(RuntimeError):t.qr(sid)

@pytest.mark.parametrize('amount',[True,False,0,-1,1.5,100000001])
def test_invalid_amount(terminal,amount):
    t,a,s=terminal
    with pytest.raises(ValueError):t.create(uid(),uid(),amount)
    assert not a.calls

def test_private_state_and_origin_scope(tmp_path):
    d=tmp_path/'private';s=Sales(d,ORIGIN);sid=uid();s.reserve(sid,uid(),10)
    with pytest.raises(ValueError):Sales(d,'https://other.example').get(sid)
    d.chmod(0o755)
    with pytest.raises(ValueError):Sales(d,ORIGIN)

def test_secret_file_permissions_and_link(tmp_path):
    f=tmp_path/'token';f.write_text('abc.def.ghi');f.chmod(0o600);assert access_token(f)=='abc.def.ghi'
    f.chmod(0o644)
    with pytest.raises(ValueError):access_token(f)
    link=tmp_path/'link';link.symlink_to(f)
    with pytest.raises(OSError):access_token(link)

@pytest.mark.parametrize('origin',['http://private.example','https://a:b@private.example','https://private.example/api','https://private.example/?x=1'])
def test_no_insecure_origin(origin,tmp_path):
    with pytest.raises(ValueError):MerchantAPI(origin,tmp_path/'token',None)

class Response:
    def __init__(self,status,data):self.status=status;self.data=data
    def read(self,n):return self.data[:n]

def test_tls_request_no_retry_or_redirect(tmp_path):
    f=tmp_path/'token';f.write_text('abc.def.ghi');f.chmod(0o600);calls=[]
    class Connection:
        def __init__(self,*a,**kw):assert kw['context'].check_hostname and kw['context'].verify_mode==2
        def request(self,*a,**kw):calls.append((a,kw))
        def getresponse(self):return Response(302,b'{}')
        def close(self):pass
    api=MerchantAPI(ORIGIN,f,None,transport=Connection)
    with pytest.raises(RuntimeError,match='302'):api.create({'id':uid(),'merchant':uid(),'amount':100})
    assert len(calls)==1 and calls[0][1]['headers']['Idempotency-Key'].startswith('pos-sale-')


def test_recent_sales_survive_restart(terminal):
    t,a,s=terminal;one,two=uid(),uid();merchant=uid();t.create(one,merchant,500);t.create(two,merchant,600)
    restarted=Sales(s.path.parent,ORIGIN);assert {x['id'] for x in restarted.recent()}=={one,two}
    assert not Sales(s.path.parent,'https://other.example').recent()

@pytest.mark.parametrize('state,refund',[('pending',1),('refunded',499),('paid',500),('cancelled',10)])
def test_terminal_rejects_inconsistent_refund_status(terminal,state,refund):
    t,a,s=terminal;sid=uid();t.create(sid,uid(),500);a.invoices[sid]['state']=state;a.refunded=refund
    with pytest.raises(RuntimeError,match='refund_state_mismatch'):t.status(sid)
