"""Bank integration boundary contracts. NO LIVE RAILS are implemented.

Each licensed provider must have a separately certified adapter. Bank statements are
only evidence to reconcile, NEVER sufficient for minting fiat liabilities by themselves.
"""
from __future__ import annotations
import hashlib
import hmac
import json
import re
import time
from dataclasses import dataclass
from typing import Protocol

from spyderpay_core.ledger import PaymentError


@dataclass(frozen=True)
class BankEvidence:
    provider: str
    external_id: str
    amount_uzs: int
    status: str
    receiver_reference: str


class BankingPartner(Protocol):
    """Implement only after agreements, certification, reconciliation and legal review."""
    def fetch_statement(self, from_cursor: str | None) -> tuple[list[BankEvidence], str | None]: ...
    def verify_callback(self, raw_body: bytes, headers: dict[str,str]) -> BankEvidence: ...
    def confirm_external_funds(self, evidence: BankEvidence) -> bool: ...


class ExampleHmacCallbackVerifier:
    """An EXAMPLE protocol for automated tests, not a bank provider signature format."""
    MAX_SKEW_SECONDS=120
    def __init__(self,secret:bytes,provider_id:str):
        if not isinstance(secret,bytes) or len(secret)<32:raise ValueError('weak signing secret')
        if not isinstance(provider_id,str) or not (3<=len(provider_id)<=64):raise ValueError('invalid provider')
        self.secret=secret;self.provider_id=provider_id

    @staticmethod
    def signature(secret:bytes,body:bytes,timestamp:str)->str:
        return hmac.new(secret,timestamp.encode()+b'.'+body,hashlib.sha256).hexdigest()

    def verify_callback(self,raw_body:bytes,headers:dict[str,str],now:int | None=None)->BankEvidence:
        norm={k.lower():v for k,v in headers.items()}
        timestamp=norm.get('x-example-bank-timestamp','')
        signature=norm.get('x-example-bank-signature','')
        if not re.fullmatch('[0-9]{10}',timestamp) or not re.fullmatch('[0-9a-f]{64}',signature):
            raise PaymentError('invalid_bank_signature',401)
        if abs((now if now is not None else int(time.time()))-int(timestamp))>self.MAX_SKEW_SECONDS:
            raise PaymentError('expired_bank_callback',401)
        if not hmac.compare_digest(self.signature(self.secret,raw_body,timestamp),signature):
            raise PaymentError('invalid_bank_signature',401)
        try:
            obj=json.loads(raw_body)
            if not isinstance(obj,dict) or set(obj)!={'external_id','amount_uzs','status','receiver_reference'}:
                raise ValueError()
            ext=obj['external_id'];amt=obj['amount_uzs'];status=obj['status'];ref=obj['receiver_reference']
            if not isinstance(ext,str) or len(ext)>128 or not ext.isascii() or not ext:raise ValueError()
            if type(amt) is not int or not 0<amt<=100_000_000:raise ValueError()
            if status not in ('pending','confirmed','reversed'):raise ValueError()
            if not isinstance(ref,str) or not 3<=len(ref)<=128:raise ValueError()
        except (ValueError,TypeError,KeyError):
            raise PaymentError('invalid_bank_event',422) from None
        return BankEvidence(self.provider_id,ext,amt,status,ref)
