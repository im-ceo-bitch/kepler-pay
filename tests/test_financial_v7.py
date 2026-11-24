import uuid
import pytest
from spyderpay_core.ledger import PaymentError
from spyderpay_core.postgres.store import Principal
from spyderpay_core.postgres.financial_controls import calculate_fee,FinancialControls

@pytest.mark.parametrize('amount,bps,expected',[(1,1,0),(1,1000,0),(100,100,1),(10000,175,175),(9999,175,174),(100_000_000,1000,10_000_000),(100,0,0)])
def test_exact_integer_fee(amount,bps,expected):
    assert calculate_fee(amount,bps)==expected

@pytest.mark.parametrize('amount,bps',[(0,1),(-1,10),(1,-1),(1,1001),(100,True),(True,1),(1,0.5),(1,'100'),(100_000_001,10)])
def test_invalid_fee(amount,bps):
    with pytest.raises(PaymentError):calculate_fee(amount,bps)

@pytest.mark.parametrize('method,args',[('propose_fee',(str(uuid.uuid4()),100,'evidence-ref','idem-00000001')),('approve_fee',(str(uuid.uuid4()),'idem-00000001')),('open',(str(uuid.uuid4()),'other','evidence-ref','idem-00000001')),('decide',(str(uuid.uuid4()),'approve','evidence-ref','idem-00000001')),('execute',(str(uuid.uuid4()),'idem-00000001'))])
@pytest.mark.parametrize('role',['ops','merchant','customer','bank_review'])
def test_financial_roles_fail_before_db(method,args,role):
    with pytest.raises(PaymentError,match='bank_service_role_required'):
        getattr(FinancialControls(object()),method)(Principal('key','tenant','actor',frozenset({role})),*args)
