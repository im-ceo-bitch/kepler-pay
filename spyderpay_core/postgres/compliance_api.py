from typing import Literal, Annotated
from fastapi import Request
from pydantic import Field, StrictInt
from .api import _Base
from .bank_api import Idem, Ref, Amount
from .compliance import Compliance
from .clearing import Clearing
from .consent import Consent

class Review(_Base):
    kyc: Literal['verified','rejected','pending']
    screening: Literal['clear','hit','pending']
    tier: Literal['standard','enhanced']
    evidence_ref: Ref
    provider_token: Annotated[str,Field(min_length=1,max_length=4096)] | None = None

class Decision(_Base):
    decision: Literal['approved','rejected']

class StatementRow(_Base):
    event_ref: Ref
    provider_ref: Ref
    direction: Literal['deposit','withdrawal']
    amount: Amount
    beneficiary_ref: Ref
    status: Literal['settled','failed']

class Batch(_Base):
    provider: Ref
    batch_ref: Ref
    opening: StrictInt
    closing: StrictInt
    credits: StrictInt
    debits: StrictInt
    rows: Annotated[list[StatementRow],Field(min_length=1,max_length=25)]

class ConsentBody(_Base):
    account: str
    provider: Ref
    direction: Literal['deposit','withdrawal']
    amount: Amount
    beneficiary_ref: Ref
    consent_ref: Ref
    evidence_digest: Annotated[str,Field(pattern=r'^[0-9a-f]{64}$')]

class Approval(_Base):
    digest: Annotated[str,Field(pattern=r'^[0-9a-f]{64}$')]

def mount_compliance_routes(app,processor,provider_config=None):
    from .provider_evidence import ProviderEvidence
    from .banking import authorize_role
    from spyderpay_core.ledger import PaymentError
    provider=ProviderEvidence(provider_config) if provider_config is not None else None
    compliance=Compliance(processor);clearing=Clearing(processor);consent=Consent(processor)
    @app.post('/v3/bank/consents')
    def attest(request:Request,data:ConsentBody,idempotency_key:Idem):
        return consent.attest(request.state.principal,data.account,data.provider,data.direction,data.amount,data.beneficiary_ref,data.consent_ref,data.evidence_digest,idempotency_key)
    @app.post('/v3/compliance/accounts/{account}/reviews')
    def record(request:Request,account:str,data:Review,idempotency_key:Idem):
        principal=request.state.principal
        authorize_role(principal,'compliance_maker')
        if provider is not None:
            ref=provider.verify(data.provider_token,tenant=principal.tenant_id,account=account,kyc=data.kyc,screening=data.screening,tier=data.tier)
            if ref!=data.evidence_ref:raise PaymentError('provider_reference_mismatch',403)
        elif data.provider_token is not None or data.evidence_ref.startswith('provider:'):
            raise PaymentError('provider_not_configured',503)
        return compliance.record(principal,account,data.kyc,data.screening,data.tier,data.evidence_ref,idempotency_key)
    @app.post('/v3/compliance/reviews/{review}/decide')
    def decide(request:Request,review:str,data:Decision,idempotency_key:Idem):
        return compliance.decide(request.state.principal,review,data.decision,idempotency_key)
    @app.post('/v3/clearing/batches')
    def ingest(request:Request,data:Batch,idempotency_key:Idem):
        return clearing.ingest(request.state.principal,data.provider,data.batch_ref,data.opening,data.closing,data.credits,data.debits,[r.model_dump() for r in data.rows],idempotency_key)
    @app.post('/v3/clearing/batches/{batch}/approve')
    def approve(request:Request,batch:str,data:Approval,idempotency_key:Idem):
        return clearing.approve(request.state.principal,batch,data.digest,idempotency_key)
    @app.get('/v3/clearing/reconciliation')
    def report(request:Request):return clearing.reconciliation(request.state.principal)
