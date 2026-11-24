"""Single-issue durable dispatch for private pre-license partner adapters.

A claim commits BEFORE a caller may submit to the sandbox. A lost response or
crash is intentionally fail-closed: lookup only, never another submit permit.
This is not exactly-once delivery to a remote bank.
"""
from datetime import datetime, timezone
from dataclasses import asdict
from spyderpay_core.ledger import PaymentError
from .banking import Banking, authorize_role
from .compliance import Compliance
from .rail_contract import RailInstruction
from .store import _id, _jsonable


def instruction_from_intent(i):
    return RailInstruction(str(i['id']),i['provider'],i['direction'],i['amount'],i['beneficiary_ref'])


def next_action(state, outcome=None):
    if state in ('settled','failed','cancelled'):
        return 'terminal'
    if state not in ('submitted','unknown'):
        raise PaymentError('dispatch_not_started',409)
    if outcome=='accepted':
        return 'await_evidence_or_lookup'
    if outcome not in (None,'unknown','not_dispatched'):
        raise PaymentError('invalid_dispatch_outcome',422)
    return 'lookup_only'


class Dispatch:
    def __init__(self, processor):
        self.p=processor
        self.bank=Banking(processor)

    def claim(self,p,iid):
        authorize_role(p,'bank_dispatch'); iid=_id(iid)
        # Not _once(): repeated request must never replay an authorization to transmit.
        with self.p._connect() as conn,conn.transaction():
            from .traffic_gate import require_open_for
            require_open_for(conn,'bank_dispatch')
            i=self.bank._intent(conn,p,iid)
            if i['state']!='authorized' or p.subject in (i['created_by'],i['reviewed_by']):
                raise PaymentError('dispatch_claim_forbidden',409)
            self.bank._risk(conn,p,str(i['account_id']))
            Compliance(self.p).enforce(conn,p,str(i['account_id']),i['amount'],iid)
            self.bank._require_consent(conn,p,i)
            instruction=instruction_from_intent(i)
            ref=instruction.idempotency_reference
            conn.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s,0))',(p.tenant_id+':'+i['provider']+':'+ref,))
            if conn.execute('SELECT 1 FROM sp_bank_intents WHERE tenant_id=%s AND provider=%s AND provider_ref=%s',(p.tenant_id,i['provider'],ref)).fetchone():
                raise PaymentError('bank_provider_reference_reused',409)
            self.bank._transition(conn,p,i,'submitted',external=ref)
            conn.execute('INSERT INTO sp_rail_dispatch(intent_id,tenant_id,request_ref,instruction_digest,actor) VALUES(%s,%s,%s,%s,%s)',(iid,p.tenant_id,ref,instruction.digest,p.subject))
            self.p._audit(conn,p,'dispatch_claimed',iid,{'digest':instruction.digest,'ref':ref})
            return {'instruction':asdict(instruction),'request_ref':ref,'instruction_digest':instruction.digest,'action':'submit_once','sandbox':True}

    def status(self,p,iid):
        authorize_role(p,'bank_dispatch'); iid=_id(iid)
        with self.p._connect() as conn,conn.transaction():
            row=conn.execute('''SELECT d.*,i.state,i.provider,r.outcome FROM sp_rail_dispatch d JOIN sp_bank_intents i ON i.id=d.intent_id LEFT JOIN sp_rail_dispatch_result r ON r.intent_id=d.intent_id WHERE d.tenant_id=%s AND d.intent_id=%s''',(p.tenant_id,iid)).fetchone()
            if not row: raise PaymentError('dispatch_not_found',404)
            return {**_jsonable(row),'action':next_action(row['state'],row['outcome']),'sandbox':True}

    def report(self,p,iid,outcome,idem):
        authorize_role(p,'bank_dispatch'); iid=_id(iid)
        if outcome not in ('accepted','unknown','not_dispatched'):
            raise PaymentError('invalid_dispatch_outcome',422)
        def run(conn):
            i=self.bank._intent(conn,p,iid)
            d=conn.execute('SELECT * FROM sp_rail_dispatch WHERE tenant_id=%s AND intent_id=%s',(p.tenant_id,iid)).fetchone()
            if not d or d['actor']!=p.subject: raise PaymentError('dispatch_actor_mismatch',403)
            row=conn.execute('INSERT INTO sp_rail_dispatch_result(intent_id,actor,outcome) VALUES(%s,%s,%s) ON CONFLICT DO NOTHING RETURNING *',(iid,p.subject,outcome)).fetchone()
            if not row: raise PaymentError('dispatch_result_already_recorded',409)
            state=i['state']
            if state=='submitted' and outcome!='accepted':
                self.bank._transition(conn,p,i,'unknown'); state='unknown'
            self.p._audit(conn,p,'dispatch_result',iid,{'outcome':outcome})
            return {**_jsonable(row),'action':next_action(state,outcome),'state':state,'sandbox':True}
        return self.p._once(p,idem,{'op':'dispatch_result','intent_id':iid,'outcome':outcome},run)
