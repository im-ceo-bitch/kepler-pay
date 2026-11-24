from datetime import datetime,timedelta,timezone
import pytest
from spyderpay_core.ledger import PaymentError
from spyderpay_core.postgres.compliance import evaluate,Compliance
from spyderpay_core.postgres.clearing import validate_batch,Clearing
from spyderpay_core.postgres.consent import check_consent,Consent
from spyderpay_core.postgres.operations import classify_snapshot
from spyderpay_core.release import SCHEMA_VERSION
from spyderpay_core.postgres.store import Principal

NOW=datetime(2026,1,1,tzinfo=timezone.utc)
REVIEW=dict(kyc='verified',screening='clear',tier='standard',decision='approved',created_at=NOW-timedelta(minutes=5),decided_at=NOW-timedelta(minutes=1))
ROW=dict(event_ref='event-001',provider_ref='provider-001',direction='deposit',amount=500,beneficiary_ref='beneficiary-001',status='settled')
OTHER=dict(ROW,event_ref='event-002',provider_ref='provider-002',direction='withdrawal',amount=300)
CONSENT=dict(account_id='account',provider='sandbox-bank',direction='withdrawal',amount=100,beneficiary_ref='beneficiary',actor='consent-actor',created_at=NOW-timedelta(minutes=1),expires_at=NOW+timedelta(minutes=1))

def test_policy_ok():evaluate(REVIEW,1,0,0,NOW)
@pytest.mark.parametrize('changes',[{'kyc':'pending'},{'screening':'hit'},{'decision':None},{'decision':'rejected'},{'created_at':NOW-timedelta(hours=25)},{'created_at':NOW+timedelta(seconds=1)},{'decided_at':NOW+timedelta(seconds=1)}])
def test_policy_denies(changes):
    with pytest.raises(PaymentError):evaluate({**REVIEW,**changes},1,0,0,NOW)
@pytest.mark.parametrize('amount,volume,count',[(10000001,0,0),(1,30000000,0),(1,0,10)])
def test_policy_limits(amount,volume,count):
    with pytest.raises(PaymentError,match='bank_velocity_or_amount_limit'):evaluate(REVIEW,amount,volume,count,NOW)
def test_missing_review():
    with pytest.raises(PaymentError):evaluate(None,1,0,0,NOW)
def test_enhanced():evaluate(dict(REVIEW,tier='enhanced'),50_000_000,50_000_000,29,NOW)
def test_batch_order_independent():
    assert validate_batch('sandbox-bank','batch-001',1000,1200,500,300,[ROW,OTHER])==validate_batch('sandbox-bank','batch-001',1000,1200,500,300,[OTHER,ROW])
@pytest.mark.parametrize('opening,closing,credit,debit,rows',[(1000,1199,500,300,[ROW,OTHER]),(1000,1200,501,301,[ROW,OTHER]),(1000,1200,500,300,[ROW,ROW]),(1000,1200,500,300,[ROW,dict(OTHER,provider_ref=ROW['provider_ref'])]),(True,1200,500,300,[ROW,OTHER]),(1000,1200,500,300,[]),(1000,1200,500,300,[dict(ROW,amount=True),OTHER]),(1000,1200,500,300,[dict(ROW,extra='x'),OTHER])])
def test_batch_invalid(opening,closing,credit,debit,rows):
    with pytest.raises(PaymentError):validate_batch('sandbox-bank','batch-001',opening,closing,credit,debit,rows)
def test_failed_row_has_no_movement():validate_batch('sandbox-bank','batch-001',1000,1000,0,0,[dict(ROW,status='failed')])
def test_consent_ok():check_consent(CONSENT,'account','sandbox-bank','withdrawal',100,'beneficiary','bank-actor',NOW)
@pytest.mark.parametrize('changes',[{'account_id':'other'},{'provider':'sandbox-other'},{'direction':'deposit'},{'amount':101},{'beneficiary_ref':'other'},{'actor':'bank-actor'},{'expires_at':NOW},{'created_at':NOW+timedelta(seconds=1)}])
def test_consent_wrong(changes):
    with pytest.raises(PaymentError,match='matching_bank_consent_required'):check_consent(dict(CONSENT,**changes),'account','sandbox-bank','withdrawal',100,'beneficiary','bank-actor',NOW)
def test_compliance_requires_service_role_before_database():
    p=Principal('id','tenant','actor',frozenset({'ops'}))
    with pytest.raises(PaymentError):Compliance(object()).record(p,'bad','verified','clear','standard','ref','idem')
    with pytest.raises(PaymentError):Clearing(object()).approve(p,'bad','digest','idem')
    with pytest.raises(PaymentError):Consent(object()).attest(p,'bad','sandbox-bank','withdrawal',100,'beneficiary','ref','a'*64,'idem')
@pytest.mark.parametrize('schema,changes,expected',[(SCHEMA_VERSION,{},'ok'),(SCHEMA_VERSION-1,{},'critical'),(SCHEMA_VERSION,{'invalid_holds':1},'critical'),(SCHEMA_VERSION,{'stale_outbox':1},'degraded'),(SCHEMA_VERSION,{'invalid_balances':1,'stale_bank_intents':1},'critical')])
def test_health(schema,changes,expected):
    counts=dict.fromkeys(('invalid_journals','invalid_balances','invalid_holds','stale_bank_intents','stale_outbox','stale_statements'),0);counts.update(changes)
    assert classify_snapshot(schema,counts)['status']==expected
