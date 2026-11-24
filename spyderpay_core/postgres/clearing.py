"""Controlled import of bank statement batches. No network or live rails."""
from spyderpay_core.ledger import PaymentError
from .banking import authorize_role, provider, reference
from .store import _amount, _digest, _id, _jsonable

MAX_BALANCE=10**15

def validate_batch(provider_id,batch_ref,opening,closing,credits,debits,rows):
    provider(provider_id); reference(batch_ref)
    if any(type(x) is not int or abs(x)>MAX_BALANCE for x in (opening,closing,credits,debits)) or min(credits,debits)<0 or not isinstance(rows,list) or not 1<=len(rows)<=25:
        raise PaymentError('invalid_statement_batch',422)
    seen=set(); refs=set(); actual_credits=actual_debits=0
    for row in rows:
        if not isinstance(row,dict) or set(row)!={'event_ref','provider_ref','direction','amount','beneficiary_ref','status'}:raise PaymentError('invalid_statement_row',422)
        for key in ('event_ref','provider_ref','beneficiary_ref'):reference(row[key])
        _amount(row['amount'])
        if row['direction'] not in ('deposit','withdrawal') or row['status'] not in ('settled','failed'):raise PaymentError('invalid_statement_row',422)
        if row['event_ref'] in seen or row['provider_ref'] in refs:raise PaymentError('duplicate_statement_row',409)
        seen.add(row['event_ref']);refs.add(row['provider_ref'])
        if row['status']=='settled':
            if row['direction']=='deposit':actual_credits+=row['amount']
            else:actual_debits+=row['amount']
    if (credits,debits)!=(actual_credits,actual_debits) or closing!=opening+credits-debits:raise PaymentError('statement_control_totals_mismatch',409)
    return _digest(dict(provider=provider_id,batch_ref=batch_ref,opening=opening,closing=closing,credits=credits,debits=debits,rows=sorted(rows,key=lambda r:r['event_ref'])))

class Clearing:
    def __init__(self,processor):self.p=processor

    def ingest(self,p,provider_id,batch_ref,opening,closing,credits,debits,rows,idem):
        authorize_role(p,'bank_statement')
        digest=validate_batch(provider_id,batch_ref,opening,closing,credits,debits,rows)
        def run(conn):
            # Same locks as bank settlement, ordered to avoid batch lock inversion.
            for ref in sorted(r['provider_ref'] for r in rows):
                conn.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s,0))',(p.tenant_id+':'+provider_id+':'+ref,))
            for ref in sorted(r['provider_ref'] for r in rows):
                if conn.execute('''SELECT 1 FROM sp_statement_rows r JOIN sp_bank_evidence e ON e.id=r.evidence_id WHERE e.tenant_id=%s AND e.provider=%s AND e.provider_ref=%s''',(p.tenant_id,provider_id,ref)).fetchone():raise PaymentError('statement_reference_already_imported',409)
            b=conn.execute('''INSERT INTO sp_statement_batches(tenant_id,provider,batch_ref,digest,opening,closing,credit_total,debit_total,row_count,maker) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING RETURNING *''',(p.tenant_id,provider_id,batch_ref,digest,opening,closing,credits,debits,len(rows),p.subject)).fetchone()
            if not b:raise PaymentError('statement_batch_already_imported',409)
            evidence=[]
            for row in rows:
                # Canonical per-row digest. Raw provider files stay in external evidence vault.
                rd=_digest(row)
                ev=conn.execute('''INSERT INTO sp_bank_evidence(tenant_id,provider,channel,event_ref,provider_ref,status,direction,amount,beneficiary_ref,actor,payload_digest) VALUES(%s,%s,'statement',%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING RETURNING *''',(p.tenant_id,provider_id,row['event_ref'],row['provider_ref'],row['status'],row['direction'],row['amount'],row['beneficiary_ref'],p.subject,rd)).fetchone()
                if not ev:raise PaymentError('statement_event_already_imported',409)
                conn.execute('INSERT INTO sp_statement_rows(batch_id,evidence_id) VALUES(%s,%s)',(b['id'],ev['id']))
                evidence.append(_jsonable(ev))
            self.p._audit(conn,p,'statement_ingested',str(b['id']),{'digest':digest,'count':len(rows)})
            return {'batch':_jsonable(b),'evidence':evidence,'review_required':True}
        return self.p._once(p,idem,{'op':'statement_ingest','digest':digest},run)

    def approve(self,p,batch_id,expected_digest,idem):
        authorize_role(p,'clearing_review');batch_id=_id(batch_id)
        def run(conn):
            # Batch immutable; approval unique and independently recorded.
            b=conn.execute('SELECT * FROM sp_statement_batches WHERE tenant_id=%s AND id=%s',(p.tenant_id,batch_id)).fetchone()
            if not b:raise PaymentError('statement_batch_not_found',404)
            if b['maker']==p.subject or b['digest']!=expected_digest:raise PaymentError('statement_review_mismatch',409)
            r=conn.execute('INSERT INTO sp_statement_approvals(batch_id,reviewer) VALUES(%s,%s) ON CONFLICT DO NOTHING RETURNING *',(batch_id,p.subject)).fetchone()
            if not r:raise PaymentError('statement_already_approved',409)
            self.p._audit(conn,p,'statement_approved',batch_id,{'digest':expected_digest})
            return _jsonable(r)
        return self.p._once(p,idem,{'op':'statement_approve','batch_id':batch_id,'digest':expected_digest},run)

    def reconciliation(self,p):
        authorize_role(p,'clearing_review')
        with self.p._connect() as conn,conn.transaction():
            conn.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
            rows=conn.execute('''SELECT b.provider,count(*) AS batches, count(a.batch_id) AS approved, coalesce(sum(b.credit_total) FILTER (WHERE a.batch_id IS NOT NULL),0) AS credits, coalesce(sum(b.debit_total) FILTER (WHERE a.batch_id IS NOT NULL),0) AS debits FROM sp_statement_batches b LEFT JOIN sp_statement_approvals a ON a.batch_id=b.id WHERE b.tenant_id=%s GROUP BY b.provider ORDER BY b.provider''',(p.tenant_id,)).fetchall()
            pending=conn.execute('''SELECT count(*) AS n FROM sp_statement_rows r JOIN sp_statement_batches b ON b.id=r.batch_id JOIN sp_statement_approvals a ON a.batch_id=b.id LEFT JOIN sp_bank_evidence_use u ON u.evidence_id=r.evidence_id WHERE b.tenant_id=%s AND u.evidence_id IS NULL''',(p.tenant_id,)).fetchone()['n']
            return {'providers':[{**_jsonable(r),'credits':int(r['credits']),'debits':int(r['debits'])} for r in rows],'approved_unconsumed_rows':pending,'sandbox':True}
