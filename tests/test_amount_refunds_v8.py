import random
import pytest
from spyderpay_core.ledger import PaymentError
from spyderpay_core.postgres.refunds import refund_quote
from spyderpay_core.postgres.api_v3 import AmountRefund,AmountRefundApproval
from pydantic import ValidationError

@pytest.mark.parametrize('gross,fee,already,amount,expected',[(10000,200,0,3000,60),(10000,200,3000,7000,140),(3,1,0,1,0),(3,1,1,1,0),(3,1,2,1,1),(100,0,0,100,0),(100,10,0,100,10)])
def test_fee_delta(gross,fee,already,amount,expected):
    assert refund_quote(gross,fee,already,amount)==expected

@pytest.mark.parametrize('gross,fee,already,amount',[(0,0,0,1),(100,101,0,1),(100,-1,0,1),(100,1,99,2),(100,1,-1,1),(100,1,0,True),(100,True,0,1),(100,1,True,1),(100,1,0,0),(100,1,100,1),(100,1,0,1.0)])
def test_invalid_refund(gross,fee,already,amount):
    with pytest.raises(PaymentError):refund_quote(gross,fee,already,amount)

def test_random_partition_exact_total():
    rng=random.Random(20261124)
    for _ in range(1000):
        gross=rng.randint(1,100000);fee=rng.randint(0,gross//10);refunded=returned=0
        while refunded<gross:
            amount=rng.randint(1,gross-refunded)
            delta=refund_quote(gross,fee,refunded,amount)
            assert 0<=delta<=amount
            refunded+=amount;returned+=delta
            assert returned==fee*refunded//gross
        assert returned==fee

@pytest.mark.parametrize('amount',[True,1.1,'100',0,-1])
def test_api_strict_amount(amount):
    with pytest.raises(ValidationError):AmountRefund(amount=amount)

def test_approval_shape():
    d=AmountRefundApproval(operation='refund_amount',invoice_id='id',expected_amount=1000,expected_merchant='merchant',amount=200)
    assert d.model_dump()['amount']==200
    with pytest.raises(ValidationError):AmountRefund(amount=200,payer='other')
