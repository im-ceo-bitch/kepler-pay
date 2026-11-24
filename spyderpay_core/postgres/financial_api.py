"""Private sandbox fee and dispute endpoints. Existing v3 signature boundary applies."""
from typing import Annotated, Literal
from fastapi import Header, Request
from pydantic import Field, StrictInt
from .api import _Base
from .financial_controls import FinancialControls
Idem=Annotated[str,Header(min_length=12,max_length=128)]
Ref=Annotated[str,Field(min_length=3,max_length=96)]
class Fee(_Base):
    merchant: str
    bps: Annotated[StrictInt,Field(ge=0,le=1000)]
    evidence: Ref
class Dispute(_Base):
    reason: Literal['unauthorized','duplicate','not_delivered','other']
    evidence: Ref
class Decision(_Base):
    decision: Literal['approve','reject']
    evidence: Ref

def mount_financial_routes(app,processor):
    f=FinancialControls(processor)
    @app.post('/v3/finance/fees')
    def propose(request: Request,data: Fee,idempotency_key: Idem):return f.propose_fee(request.state.principal,data.merchant,data.bps,data.evidence,idempotency_key)
    @app.post('/v3/finance/fees/{sid}/approve')
    def approve(request: Request,sid: str,data: _Base,idempotency_key: Idem):return f.approve_fee(request.state.principal,sid,idempotency_key)
    @app.post('/v3/finance/invoices/{iid}/chargeback')
    def open_case(request: Request,iid: str,data: Dispute,idempotency_key: Idem):return f.open(request.state.principal,iid,data.reason,data.evidence,idempotency_key)
    @app.post('/v3/finance/chargebacks/{cid}/decide')
    def decide(request: Request,cid: str,data: Decision,idempotency_key: Idem):return f.decide(request.state.principal,cid,data.decision,data.evidence,idempotency_key)
    @app.post('/v3/finance/chargebacks/{cid}/execute')
    def execute(request: Request,cid: str,data: _Base,idempotency_key: Idem):return f.execute(request.state.principal,cid,idempotency_key)
