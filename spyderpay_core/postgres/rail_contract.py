"""Partner integration contract, deliberately no live transport or credentials.

Do not implement blind retry after ambiguous network failures. A partner adapter
must document its reference uniqueness, idempotency, and status/statement evidence.
The simulator is deterministic and local; it is not a bank.
"""
from dataclasses import dataclass, asdict
from typing import Protocol, Literal
from hashlib import sha256
import json
from .banking import provider, reference
from .store import _amount, _id
from spyderpay_core.ledger import PaymentError

@dataclass(frozen=True)
class RailInstruction:
    intent_id: str
    provider: str
    direction: Literal['deposit','withdrawal']
    amount: int
    beneficiary_ref: str
    currency: str='UZS'
    def __post_init__(self):
        _id(self.intent_id);provider(self.provider);_amount(self.amount);reference(self.beneficiary_ref)
        if self.currency!='UZS' or self.direction not in ('deposit','withdrawal'):raise PaymentError('invalid_rail_instruction',422)
    @property
    def idempotency_reference(self):return 'sp-'+_id(self.intent_id)
    @property
    def digest(self):return sha256(json.dumps(asdict(self),sort_keys=True,separators=(',',':')).encode()).hexdigest()

@dataclass(frozen=True)
class DispatchResult:
    provider_ref: str
    state: Literal['accepted','unknown','not_dispatched']

class BankRail(Protocol):
    def submit(self,instruction: RailInstruction)->DispatchResult: ...
    def lookup(self,idempotency_reference: str)->DispatchResult: ...
    def verify_callback(self,raw_body: bytes,headers: dict)->dict: ...
    def fetch_statement(self,cursor: str|None)->tuple[list[dict],str|None]: ...


def recovery_action(state: str, provider_supports_idempotency: bool)->str:
    """Decision aid; UNKNOWN is not a definitive failure or permission to retry."""
    if state=='accepted':return 'await_evidence'
    if state=='unknown':return 'query_existing_reference'
    if state=='not_dispatched':return 'retry_same_reference' if provider_supports_idempotency else 'manual_review'
    raise PaymentError('unknown_dispatch_state',422)


def sandbox_reference(instruction: RailInstruction)->str:
    return 'sandbox-'+sha256((instruction.provider+':'+instruction.idempotency_reference).encode()).hexdigest()[:40]
