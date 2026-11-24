"""Adapter-side execution coordinator. No live network implementation is supplied.

The bank adapter must preserve the reference assigned by SpyderPay and disable
transport retries. Lost responses are handled by lookup, not submit.
"""
from .rail_contract import RailInstruction, DispatchResult
from .store import _id
from .dispatch import Dispatch
from spyderpay_core.ledger import PaymentError


def normalize_result(result, request_ref):
    # Reject mismatched or unexpected provider responses conservatively.
    if not isinstance(result,DispatchResult) or result.provider_ref!=request_ref or result.state not in ('accepted','unknown','not_dispatched'):
        return 'unknown'
    return result.state


class DispatchWorker:
    def __init__(self, dispatch:Dispatch, principal, rails):
        self.dispatch=dispatch
        self.principal=principal
        self.rails=dict(rails)

    def execute(self,iid):
        iid=_id(iid)
        claim=self.dispatch.claim(self.principal,iid)
        if claim['action']!='submit_once':
            raise PaymentError('dispatch_permission_missing',409)
        instruction=RailInstruction(**claim['instruction'])
        ref=instruction.idempotency_reference
        if instruction.intent_id!=iid or claim['request_ref']!=ref or claim['instruction_digest']!=instruction.digest:
            raise PaymentError('dispatch_instruction_mismatch',409)
        adapter=self.rails.get(instruction.provider)
        if adapter is None:
            outcome='not_dispatched'
        else:
            try:
                outcome=normalize_result(adapter.submit(instruction),ref)
            except Exception:
                # Transport/parse errors do not prove that no debit occurred.
                outcome='unknown'
        # If recording fails, the durable claim remains. Calling execute again
        # will fail before transport; recovery must use lookup or evidence.
        return self.dispatch.report(self.principal,iid,outcome,'dispatch-result:'+iid)

    def recover(self,iid):
        iid=_id(iid)
        status=self.dispatch.status(self.principal,iid)
        if status['action']=='terminal':
            return {'action':'terminal','reference':status['request_ref']}
        if status['action'] not in ('lookup_only','await_evidence_or_lookup'):
            raise PaymentError('dispatch_recovery_forbidden',409)
        # Caller gets only a status observation, never a ledger posting or
        # another permission to submit. The independent evidence flow settles.
        adapter=self.rails.get(status['provider'])
        if adapter is None:
            return {'action':'manual_review','reference':status['request_ref']}
        try:
            outcome=normalize_result(adapter.lookup(status['request_ref']),status['request_ref'])
        except Exception:
            outcome='unknown'
        return {'action':'await_independent_evidence','reference':status['request_ref'],'observation':outcome}
