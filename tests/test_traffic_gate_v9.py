from types import SimpleNamespace
import pytest
from spyderpay_core.ledger import PaymentError
from spyderpay_core.postgres.traffic_gate import require_open_for

class Conn:
    def __init__(self,row):self.row=row;self.calls=0
    def execute(self,sql):
        assert sql=='SELECT sp_gate_open() AS allowed';self.calls+=1;return SimpleNamespace(fetchone=lambda:self.row)

@pytest.mark.parametrize('op',['transfer','pay_invoice','refund_invoice','refund_amount','chargeback_execute','sandbox_credit','bank_dispatch','bank_settle','bank_review','unknown_new_operation'])
def test_pause_blocks_new_mutations(op):
    c=Conn({'allowed':False})
    with pytest.raises(PaymentError,match='financial_traffic_paused'):require_open_for(c,op)
    assert c.calls==1

@pytest.mark.parametrize('op',['freeze','bank_evidence','bank_unknown','dispatch_result','statement_ingest','bank_case_open'])
def test_pause_preserves_incident_evidence(op):
    c=Conn({'allowed':False});require_open_for(c,op);assert c.calls==0

@pytest.mark.parametrize('row',[None,{'allowed':None},{'allowed':1}])
def test_gate_fails_closed(row):
    with pytest.raises(PaymentError):require_open_for(Conn(row),'transfer')

def test_gate_open():require_open_for(Conn({'allowed':True}),'transfer')
