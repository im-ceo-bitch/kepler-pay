"""Offline reconciliation of normalized provider batches against internal intents.

Read-only exception report. Never posts, releases holds, or approves evidence.
The starting balance and complete ordered batch export must come from an
independently verified source; the report is not proof of bank authenticity.
"""
from .banking import provider, reference
from .clearing import validate_batch
from .store import _amount
from spyderpay_core.ledger import PaymentError


def reconcile(provider_id, opening, batches, intents):
    provider(provider_id)
    if type(opening) is not int or not isinstance(batches,list) or not isinstance(intents,list):
        raise PaymentError('invalid_reconciliation_input',422)
    if len(batches)>10000 or len(intents)>100000:
        raise PaymentError('reconciliation_input_limit',422)
    exceptions=[]; balance=opening; seen={}; batch_refs=set(); events=set(); internal={}
    for b in batches:
        if not isinstance(b,dict) or not {'provider','batch_ref','opening','closing','credits','debits','rows','digest'}<=set(b) or b['provider']!=provider_id:
            raise PaymentError('invalid_reconciliation_batch',422)
        digest=validate_batch(provider_id,b['batch_ref'],b['opening'],b['closing'],b['credits'],b['debits'],b['rows'])
        if digest!=b['digest'] or b['batch_ref'] in batch_refs:
            raise PaymentError('invalid_reconciliation_batch_digest_or_duplicate',409)
        batch_refs.add(b['batch_ref'])
        if b['opening']!=balance:
            exceptions.append({'code':'statement_balance_gap','batch_ref':b['batch_ref']})
        balance=b['closing']
        for row in b['rows']:
            if row['provider_ref'] in seen or row['event_ref'] in events:
                raise PaymentError('duplicate_reconciliation_evidence',409)
            seen[row['provider_ref']]=row;events.add(row['event_ref'])
    for i in intents:
        if not isinstance(i,dict) or set(i)!={'provider_ref','direction','amount','beneficiary_ref','state'}:
            raise PaymentError('invalid_reconciliation_intent',422)
        ref=reference(i['provider_ref']);reference(i['beneficiary_ref']);_amount(i['amount'])
        if ref in internal or i['direction'] not in ('deposit','withdrawal') or i['state'] not in ('submitted','unknown','settled','failed'):
            raise PaymentError('invalid_reconciliation_intent',422)
        internal[ref]=i
    for ref,row in sorted(seen.items()):
        i=internal.get(ref)
        if i is None:
            code='unmatched_external_entry'
        elif any(row[k]!=i[k] for k in ('direction','amount','beneficiary_ref')):
            code='terms_mismatch'
        elif i['state'] in ('submitted','unknown'):
            code='awaiting_internal_resolution'
        elif i['state']!=row['status']:
            code='final_state_mismatch'
        else:
            continue
        exceptions.append({'code':code,'provider_ref':ref})
    for ref,i in sorted(internal.items()):
        if ref not in seen:
            exceptions.append({'code':'missing_external_entry' if i['state'] in ('settled','failed') else 'awaiting_external_evidence','provider_ref':ref})
    return {'provider':provider_id,'opening':opening,'closing':balance,'external_rows':len(seen),
            'internal_rows':len(internal),'exceptions':exceptions,'balanced':not exceptions,'read_only':True}
