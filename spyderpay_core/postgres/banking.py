"""Durable, pre-license bank workflow. Never calls live rails.

Amounts are whole simulated UZS. External references are opaque; no PAN or bank
credentials. Each transition, evidence consumption and posting is atomic.
"""
from __future__ import annotations
from datetime import datetime, timezone, timedelta
import re
import uuid
from spyderpay_core.ledger import PaymentError
from .store import PgProcessor, Principal, _id, _amount, _identity, _digest, _jsonable

REF=re.compile(r'^[A-Za-z0-9_.:-]{3,96}$')
PROVIDER=re.compile(r'^sandbox-[a-z0-9-]{2,40}$')
BANK_ROLES={'bank_ops','bank_review','bank_callback','bank_statement','risk_ops'}
TERMINAL={'settled','failed','cancelled'}


def reference(value):
    if not isinstance(value,str) or not REF.fullmatch(value):raise PaymentError('invalid_reference',422)
    return value


def provider(value):
    if not isinstance(value,str) or not PROVIDER.fullmatch(value):raise PaymentError('sandbox_provider_required',422)
    return value


def authorize_role(p,role):
    if p.identity is not None or p.roles!=frozenset({role}):raise PaymentError('bank_service_role_required',403)


def verify_match(intent, callback, statement):
    """Pure matching policy; two independent channels, same immutable terms."""
    if callback['channel']!='callback' or statement['channel']!='statement' or callback['actor']==statement['actor']:
        raise PaymentError('independent_evidence_required',409)
    for ev in (callback,statement):
        if any(str(ev[k])!=str(intent[k]) for k in ('tenant_id','provider','provider_ref','direction','amount','beneficiary_ref')):
            raise PaymentError('bank_evidence_mismatch',409)
    if callback['status']!=statement['status'] or callback['status'] not in ('settled','failed'):
        raise PaymentError('bank_evidence_conflict',409)
    return callback['status']


class Banking:
    def __init__(self,processor: PgProcessor):self.p=processor

    def _intent(self,conn,p,iid):
        row=conn.execute('SELECT * FROM sp_bank_intents WHERE id=%s AND tenant_id=%s FOR UPDATE',(_id(iid),p.tenant_id)).fetchone()
        if not row:raise PaymentError('bank_intent_not_found',404)
        return row

    def _account(self,conn,p,aid,*,active=True):
        row=conn.execute('SELECT * FROM sp_accounts WHERE id=%s AND tenant_id=%s FOR UPDATE',(_id(aid),p.tenant_id)).fetchone()
        if not row or row['kind'] not in ('customer','merchant'):raise PaymentError('account_not_found',404)
        if active and row['status']!='active':raise PaymentError('frozen_or_closed_account',409)
        return row

    def _risk(self,conn,p,aid):
        self._account(conn,p,aid)
        row=conn.execute('SELECT * FROM sp_bank_risk WHERE tenant_id=%s AND account_id=%s FOR SHARE',(p.tenant_id,aid)).fetchone()
        if not row or row['state']!='approved' or row['reviewed_at']<datetime.now(timezone.utc)-timedelta(hours=24):
            raise PaymentError('bank_risk_review_required',403)

    def risk(self,p,account,state,review_ref,idem):
        authorize_role(p,'risk_ops');account=_id(account);review_ref=reference(review_ref)
        if state not in ('approved','review','blocked'):raise PaymentError('invalid_risk_state',422)
        data={'op':'bank_risk','account':account,'state':state,'review_ref':review_ref}
        def run(conn):
            self._account(conn,p,account,active=False)
            row=conn.execute('''INSERT INTO sp_bank_risk(tenant_id,account_id,state,review_ref,reviewed_by)
                VALUES(%s,%s,%s,%s,%s) ON CONFLICT(tenant_id,account_id) DO UPDATE SET state=excluded.state,
                review_ref=excluded.review_ref,reviewed_by=excluded.reviewed_by,reviewed_at=now() RETURNING *''',
                (p.tenant_id,account,state,review_ref,p.subject)).fetchone()
            self.p._audit(conn,p,'bank_risk_review',account,data)
            return _jsonable(row)
        return self.p._once(p,idem,data,run)

    def create(self,p,account,direction,provider_id,amount,beneficiary_ref,consent_ref,idem):
        authorize_role(p,'bank_ops');account=_id(account);provider_id=provider(provider_id);amount=_amount(amount)
        beneficiary_ref=reference(beneficiary_ref);consent_ref=reference(consent_ref)
        if direction not in ('deposit','withdrawal'):raise PaymentError('invalid_direction',422)
        data={'op':'bank_create','account':account,'direction':direction,'provider':provider_id,'amount':amount,'beneficiary_ref':beneficiary_ref,'consent_ref':consent_ref}
        def run(conn):
            self._risk(conn,p,account)
            row=conn.execute('''INSERT INTO sp_bank_intents(tenant_id,account_id,direction,provider,amount,beneficiary_ref,consent_ref,created_by)
              VALUES(%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING RETURNING *''',(p.tenant_id,account,direction,provider_id,amount,beneficiary_ref,consent_ref,p.subject)).fetchone()
            if not row:raise PaymentError('bank_consent_already_used',409)
            self.p._audit(conn,p,'bank_intent_created',str(row['id']),data)
            return _jsonable(row)
        return self.p._once(p,idem,data,run)

    def _system(self,conn,p,tag):
        aid=str(uuid.uuid5(uuid.NAMESPACE_URL,'spyderpay:bank:v4:'+p.tenant_id+':'+tag))
        conn.execute('''INSERT INTO sp_accounts(id,tenant_id,owner_id,kind,currency)
         VALUES(%s,%s,%s,'system','UZS') ON CONFLICT DO NOTHING''',(aid,p.tenant_id,'bank-sandbox'))
        row=self.p._account(conn,aid)
        if row['tenant_id']!=p.tenant_id or row['kind']!='system' or row['owner_id']!='bank-sandbox':raise PaymentError('bank_system_account_invalid',409)
        return aid

    def _transition(self,conn,p,intent,new_state,*,reviewed=None,external=None,hold=None,reserve=None,final=None):
        iid=str(intent['id'])
        row=conn.execute('''UPDATE sp_bank_intents SET state=%s,reviewed_by=coalesce(%s,reviewed_by),
           provider_ref=coalesce(%s,provider_ref),hold_account=coalesce(%s,hold_account),reserve_journal=coalesce(%s,reserve_journal),
           final_journal=coalesce(%s,final_journal),updated_at=now() WHERE id=%s RETURNING *''',
           (new_state,reviewed,external,hold,reserve,final,iid)).fetchone()
        result=_jsonable(row)
        self.p._audit(conn,p,'bank_'+new_state,iid,{'before':intent['state'],'after':new_state,'journal':final or reserve})
        self.p._outbox(conn,p,'bank.intent.'+new_state,iid,{'intent_id':iid,'state':new_state,'direction':intent['direction']})
        return result

    def review(self,p,iid,idem):
        authorize_role(p,'bank_review');iid=_id(iid)
        def run(conn):
            i=self._intent(conn,p,iid)
            if i['state']!='created' or i['created_by']==p.subject:raise PaymentError('independent_review_required',409)
            self._risk(conn,p,str(i['account_id']))
            hold=journal=None
            if i['direction']=='withdrawal':
                hold=self._system(conn,p,'hold:'+iid)
                src,dst=self.p._lock_accounts(conn,str(i['account_id']),hold)
                if dst['balance']!=0:raise PaymentError('bank_hold_not_empty',409)
                journal=self.p._post(conn,p,'bank_reserve',src,dst,i['amount'],iid)
            return self._transition(conn,p,i,'authorized',reviewed=p.subject,hold=hold,reserve=journal)
        return self.p._once(p,idem,{'op':'bank_review','id':iid},run)

    def submit(self,p,iid,external,idem):
        """Record sandbox adapter acceptance; does not make an external request."""
        authorize_role(p,'bank_ops');iid=_id(iid);external=reference(external)
        def run(conn):
            i=self._intent(conn,p,iid)
            if i['state']!='authorized':raise PaymentError('bank_not_authorized',409)
            self._risk(conn,p,str(i['account_id']))
            # Serialize provider reference allocation and detect reuse before unique constraint.
            conn.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s,0))',(p.tenant_id+':'+i['provider']+':'+external,))
            if conn.execute('SELECT 1 FROM sp_bank_intents WHERE tenant_id=%s AND provider=%s AND provider_ref=%s',(p.tenant_id,i['provider'],external)).fetchone():raise PaymentError('bank_provider_reference_reused',409)
            return self._transition(conn,p,i,'submitted',external=external)
        return self.p._once(p,idem,{'op':'bank_submit','id':iid,'external':external},run)

    def unknown(self,p,iid,idem):
        authorize_role(p,'bank_ops');iid=_id(iid)
        def run(conn):
            i=self._intent(conn,p,iid)
            if i['state']!='submitted':raise PaymentError('bank_not_submitted',409)
            return self._transition(conn,p,i,'unknown')
        return self.p._once(p,idem,{'op':'bank_unknown','id':iid},run)

    def _release(self,conn,p,i):
        if i['hold_account'] is None:return None
        src,dst=self.p._lock_accounts(conn,str(i['hold_account']),str(i['account_id']))
        if src['balance']!=i['amount']:raise PaymentError('bank_hold_mismatch',409)
        return self.p._post(conn,p,'bank_release',src,dst,i['amount'],str(i['id']),allow_frozen_credit=True)

    def cancel(self,p,iid,idem):
        authorize_role(p,'bank_review');iid=_id(iid)
        def run(conn):
            i=self._intent(conn,p,iid)
            if i['state'] not in ('created','authorized') or i['created_by']==p.subject:raise PaymentError('bank_cancel_forbidden',409)
            return self._transition(conn,p,i,'cancelled',final=self._release(conn,p,i))
        return self.p._once(p,idem,{'op':'bank_cancel','id':iid},run)

    def evidence(self,p,channel,provider_id,event_ref,provider_ref,direction,amount,beneficiary_ref,status,payload_digest,idem):
        if channel not in ('callback','statement'):raise PaymentError('invalid_channel',422)
        authorize_role(p,'bank_'+channel)
        provider_id=provider(provider_id);event_ref=reference(event_ref);provider_ref=reference(provider_ref);beneficiary_ref=reference(beneficiary_ref);amount=_amount(amount)
        if direction not in ('deposit','withdrawal') or status not in ('settled','failed') or not isinstance(payload_digest,str) or not re.fullmatch(r'[0-9a-f]{64}',payload_digest):raise PaymentError('invalid_bank_evidence',422)
        data={'op':'bank_evidence','channel':channel,'provider':provider_id,'event_ref':event_ref,'provider_ref':provider_ref,'direction':direction,'amount':amount,'beneficiary_ref':beneficiary_ref,'status':status,'payload_digest':payload_digest}
        def run(conn):
            conn.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s,0))',(p.tenant_id+':'+provider_id+':'+provider_ref,))
            row=conn.execute('''INSERT INTO sp_bank_evidence(tenant_id,provider,channel,event_ref,provider_ref,status,direction,amount,beneficiary_ref,actor,payload_digest)
             VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING RETURNING *''',
             (p.tenant_id,provider_id,channel,event_ref,provider_ref,status,direction,amount,beneficiary_ref,p.subject,payload_digest)).fetchone()
            if not row:
                row=conn.execute('SELECT * FROM sp_bank_evidence WHERE tenant_id=%s AND provider=%s AND channel=%s AND event_ref=%s',(p.tenant_id,provider_id,channel,event_ref)).fetchone()
                if any(row[k]!=v for k,v in data.items() if k!='op') or row['actor']!=p.subject:raise PaymentError('bank_event_conflict',409)
            self.p._audit(conn,p,'bank_evidence_received',str(row['id']),data)
            return _jsonable(row)
        return self.p._once(p,idem,data,run)

    def settle(self,p,iid,callback_id,statement_id,idem):
        authorize_role(p,'bank_review');iid=_id(iid);callback_id=_id(callback_id);statement_id=_id(statement_id)
        if callback_id==statement_id:raise PaymentError('independent_evidence_required',409)
        def run(conn):
            i=self._intent(conn,p,iid)
            if i['state'] not in ('submitted','unknown') or i['created_by']==p.subject:raise PaymentError('bank_not_settleable',409)
            conn.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s,0))',(p.tenant_id+':'+i['provider']+':'+i['provider_ref'],))
            rows=conn.execute('SELECT * FROM sp_bank_evidence WHERE id IN (%s,%s) AND tenant_id=%s ORDER BY id',(callback_id,statement_id,p.tenant_id)).fetchall()
            d={str(r['id']):r for r in rows}
            if callback_id not in d or statement_id not in d:raise PaymentError('bank_evidence_missing',404)
            status=verify_match(i,d[callback_id],d[statement_id])
            if p.subject in {d[callback_id]['actor'],d[statement_id]['actor']}:raise PaymentError('independent_reviewer_required',409)
            # All known terminal evidence for the same reference must agree. No cherry picking.
            conflict=conn.execute('''SELECT 1 FROM sp_bank_evidence WHERE tenant_id=%s AND provider=%s AND provider_ref=%s AND
             (status<>%s OR direction<>%s OR amount<>%s OR beneficiary_ref<>%s) LIMIT 1''',(p.tenant_id,i['provider'],i['provider_ref'],status,i['direction'],i['amount'],i['beneficiary_ref'])).fetchone()
            if conflict:raise PaymentError('bank_evidence_conflict',409)
            for eid,channel in ((callback_id,'callback'),(statement_id,'statement')):
                used=conn.execute('INSERT INTO sp_bank_evidence_use(evidence_id,intent_id,channel) VALUES(%s,%s,%s) ON CONFLICT DO NOTHING RETURNING evidence_id',(eid,iid,channel)).fetchone()
                if not used:raise PaymentError('bank_evidence_already_used',409)
            journal=None
            if status=='failed':journal=self._release(conn,p,i)
            elif i['direction']=='deposit':
                # Credits require matched evidence AND still-approved risk. Frozen account goes to exception workflow.
                self._risk(conn,p,str(i['account_id']))
                clearing=self._system(conn,p,'clearing:'+i['provider'])
                src,dst=self.p._lock_accounts(conn,clearing,str(i['account_id']))
                journal=self.p._post(conn,p,'bank_deposit',src,dst,i['amount'],iid)
            else:
                clearing=self._system(conn,p,'clearing:'+i['provider'])
                src,dst=self.p._lock_accounts(conn,str(i['hold_account']),clearing)
                if src['balance']!=i['amount']:raise PaymentError('bank_hold_mismatch',409)
                journal=self.p._post(conn,p,'bank_withdrawal',src,dst,i['amount'],iid)
            return self._transition(conn,p,i,status,final=journal)
        return self.p._once(p,idem,{'op':'bank_settle','id':iid,'callback':callback_id,'statement':statement_id},run)

    def get(self,p,iid):
        if p.identity is not None or not p.roles.intersection({'bank_ops','bank_review','risk_ops'}):raise PaymentError('forbidden',403)
        with self.p._connect() as conn,conn.transaction():return _jsonable(self._intent(conn,p,iid))

    def report(self,p):
        authorize_role(p,'bank_review')
        with self.p._connect() as conn,conn.transaction():
            conn.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
            rows=conn.execute('SELECT state,direction,count(*) AS count,coalesce(sum(amount),0) AS total FROM sp_bank_intents WHERE tenant_id=%s GROUP BY state,direction ORDER BY state,direction',(p.tenant_id,)).fetchall()
            unmatched=conn.execute('''SELECT count(*) AS n FROM sp_bank_evidence e LEFT JOIN sp_bank_intents i ON i.tenant_id=e.tenant_id AND i.provider=e.provider AND i.provider_ref=e.provider_ref WHERE e.tenant_id=%s AND i.id IS NULL''',(p.tenant_id,)).fetchone()['n']
            conflicts=conn.execute('''SELECT count(DISTINCT i.id) AS n FROM sp_bank_intents i JOIN sp_bank_evidence e ON i.tenant_id=e.tenant_id AND i.provider=e.provider AND i.provider_ref=e.provider_ref WHERE i.tenant_id=%s AND (e.amount<>i.amount OR e.direction<>i.direction OR e.beneficiary_ref<>i.beneficiary_ref OR (i.state IN ('settled','failed') AND e.status<>i.state) OR EXISTS(SELECT 1 FROM sp_bank_evidence e2 WHERE e2.tenant_id=e.tenant_id AND e2.provider=e.provider AND e2.provider_ref=e.provider_ref AND e2.status<>e.status))''',(p.tenant_id,)).fetchone()['n']
            holds=conn.execute('''SELECT count(*) AS n FROM sp_bank_intents i JOIN sp_accounts a ON a.id=i.hold_account WHERE i.tenant_id=%s AND a.balance<>CASE WHEN i.state IN ('authorized','submitted','unknown') THEN i.amount ELSE 0 END''',(p.tenant_id,)).fetchone()['n']
            stale=conn.execute("SELECT count(*) AS n FROM sp_bank_intents WHERE tenant_id=%s AND state IN ('submitted','unknown') AND updated_at<now()-interval '30 minutes'",(p.tenant_id,)).fetchone()['n']
            cases=conn.execute("SELECT count(*) AS n FROM sp_bank_cases WHERE tenant_id=%s AND state='open'",(p.tenant_id,)).fetchone()['n']
            return {'totals':[{'state':r['state'],'direction':r['direction'],'count':r['count'],'total':int(r['total'])} for r in rows],'unmatched_evidence':unmatched,'conflicting_intents':conflicts,'hold_mismatches':holds,'stale_intents':stale,'open_cases':cases,'sandbox':True}

    def open_case(self,p,iid,reason,idem):
        authorize_role(p,'bank_ops');iid=_id(iid)
        if reason not in ('timeout','evidence_conflict','unmatched_statement','risk_hold','customer_dispute','provider_error'):raise PaymentError('invalid_case_reason',422)
        def run(conn):
            self._intent(conn,p,iid)
            row=conn.execute('INSERT INTO sp_bank_cases(tenant_id,intent_id,reason,opened_by) VALUES(%s,%s,%s,%s) ON CONFLICT DO NOTHING RETURNING *',(p.tenant_id,iid,reason,p.subject)).fetchone()
            if not row:raise PaymentError('bank_case_already_open',409)
            self.p._audit(conn,p,'bank_case_opened',str(row['id']),{'intent':iid,'reason':reason})
            return _jsonable(row)
        return self.p._once(p,idem,{'op':'bank_case_open','id':iid,'reason':reason},run)

    def close_case(self,p,case_id,resolution,idem):
        authorize_role(p,'bank_review');case_id=_id(case_id);resolution=reference(resolution)
        def run(conn):
            row=conn.execute("UPDATE sp_bank_cases SET state='closed',resolution=%s,closed_by=%s,closed_at=now() WHERE id=%s AND tenant_id=%s AND state='open' AND opened_by<>%s RETURNING *",(resolution,p.subject,case_id,p.tenant_id,p.subject)).fetchone()
            if not row:raise PaymentError('bank_case_not_closeable',409)
            self.p._audit(conn,p,'bank_case_closed',case_id,{'resolution':resolution})
            return _jsonable(row)
        return self.p._once(p,idem,{'op':'bank_case_close','id':case_id,'resolution':resolution},run)
