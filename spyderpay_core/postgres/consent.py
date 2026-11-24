"""Trusted sandbox consent attestation, bound to immutable transaction terms.
Actual end-user consent and partner signature verification belong to the certified adapter.
"""
import re
from datetime import datetime,timezone
from spyderpay_core.ledger import PaymentError
from .banking import authorize_role,provider,reference
from .store import _id,_amount,_jsonable
from .compliance import Compliance

def check_consent(c,account,provider_id,direction,amount,beneficiary,actor,now):
    if not c or c['actor']==actor or c['expires_at']<=now or c['created_at']>now or str(c['account_id'])!=account or (c['provider'],c['direction'],c['amount'],c['beneficiary_ref'])!=(provider_id,direction,amount,beneficiary):
        raise PaymentError('matching_bank_consent_required',403)

class Consent:
    def __init__(self,processor):self.p=processor
    def attest(self,p,account,provider_id,direction,amount,beneficiary,consent_ref,evidence_digest,idem):
        authorize_role(p,'bank_consent');account=_id(account);provider_id=provider(provider_id);amount=_amount(amount);beneficiary=reference(beneficiary);consent_ref=reference(consent_ref)
        if direction not in ('deposit','withdrawal') or not isinstance(evidence_digest,str) or not re.fullmatch('[0-9a-f]{64}',evidence_digest):raise PaymentError('invalid_consent',422)
        data=dict(op='consent_attest',account=account,provider=provider_id,direction=direction,amount=amount,beneficiary=beneficiary,consent_ref=consent_ref,digest=evidence_digest)
        def run(conn):
            Compliance.account(conn,p,account)
            row=conn.execute('''INSERT INTO sp_bank_consents(tenant_id,consent_ref,account_id,provider,direction,amount,beneficiary_ref,evidence_digest,actor,expires_at) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,clock_timestamp()+interval '10 minutes') ON CONFLICT DO NOTHING RETURNING *''',(p.tenant_id,consent_ref,account,provider_id,direction,amount,beneficiary,evidence_digest,p.subject)).fetchone()
            if not row:raise PaymentError('consent_reference_reused',409)
            self.p._audit(conn,p,'bank_consent_attested',consent_ref,data)
            return _jsonable(row)
        return self.p._once(p,idem,data,run)
