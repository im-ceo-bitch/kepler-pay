"""Private bank simulator API, protected by v3 service authentication."""
from typing import Literal, Annotated
from fastapi import Header, Request
from pydantic import StrictInt, Field
from .api import _Base
from .banking import Banking
from spyderpay_core.ledger import PaymentError

Idem=Annotated[str,Header(min_length=12,max_length=128)]
Ref=Annotated[str,Field(min_length=3,max_length=96)]
Id=Annotated[str,Field(min_length=36,max_length=36)]
Amount=Annotated[StrictInt,Field(ge=1,le=100_000_000)]

class Risk(_Base):
    state: Literal['approved','review','blocked']
    review_ref: Ref

class Intent(_Base):
    account: Id
    direction: Literal['deposit','withdrawal']
    provider: Ref
    amount: Amount
    beneficiary_ref: Ref
    consent_ref: Ref

class Submit(_Base):
    provider_ref: Ref

class Evidence(_Base):
    provider: Ref
    event_ref: Ref
    provider_ref: Ref
    direction: Literal['deposit','withdrawal']
    amount: Amount
    beneficiary_ref: Ref
    status: Literal['settled','failed']
    payload_digest: Annotated[str,Field(pattern=r'^[0-9a-f]{64}$')]

class Settle(_Base):
    callback_id: Id
    statement_id: Id

class Case(_Base):
    reason: Literal['timeout','evidence_conflict','unmatched_statement','risk_hold','customer_dispute','provider_error']

class Resolve(_Base):
    resolution: Ref


def mount_bank_routes(app,processor):
    bank=Banking(processor)
    def actor(request):return request.state.principal

    @app.post('/v3/bank/risk/{account_id}')
    def risk(request: Request,account_id: str,data: Risk,idempotency_key: Idem):
        return bank.risk(actor(request),account_id,data.state,data.review_ref,idempotency_key)

    @app.post('/v3/bank/intents')
    def create(request: Request,data: Intent,idempotency_key: Idem):
        return bank.create(actor(request),data.account,data.direction,data.provider,data.amount,data.beneficiary_ref,data.consent_ref,idempotency_key)

    @app.get('/v3/bank/intents/{iid}')
    def get(request: Request,iid: str):return bank.get(actor(request),iid)

    @app.post('/v3/bank/intents/{iid}/review')
    def review(request: Request,iid: str,data: _Base,idempotency_key: Idem):return bank.review(actor(request),iid,idempotency_key)

    @app.post('/v3/bank/intents/{iid}/submit')
    def submit(request: Request,iid: str,data: Submit,idempotency_key: Idem):raise PaymentError('legacy_bank_submit_disabled_use_dispatch_claim',409)

    @app.post('/v3/bank/intents/{iid}/unknown')
    def unknown(request: Request,iid: str,data: _Base,idempotency_key: Idem):raise PaymentError('legacy_bank_unknown_disabled_use_dispatch_result',409)

    @app.post('/v3/bank/intents/{iid}/cancel')
    def cancel(request: Request,iid: str,data: _Base,idempotency_key: Idem):return bank.cancel(actor(request),iid,idempotency_key)

    @app.post('/v3/bank/evidence/{channel}')
    def evidence(request: Request,channel: Literal['callback','statement'],data: Evidence,idempotency_key: Idem):
        if channel=='statement':raise PaymentError('statement_batch_required',409)
        return bank.evidence(actor(request),channel,data.provider,data.event_ref,data.provider_ref,data.direction,data.amount,data.beneficiary_ref,data.status,data.payload_digest,idempotency_key)

    @app.post('/v3/bank/intents/{iid}/settle')
    def settle(request: Request,iid: str,data: Settle,idempotency_key: Idem):return bank.settle(actor(request),iid,data.callback_id,data.statement_id,idempotency_key)

    @app.get('/v3/bank/reconciliation')
    def report(request: Request):return bank.report(actor(request))

    @app.post('/v3/bank/intents/{iid}/cases')
    def open_case(request: Request,iid: str,data: Case,idempotency_key: Idem):return bank.open_case(actor(request),iid,data.reason,idempotency_key)

    @app.post('/v3/bank/cases/{cid}/close')
    def close_case(request: Request,cid: str,data: Resolve,idempotency_key: Idem):return bank.close_case(actor(request),cid,data.resolution,idempotency_key)
