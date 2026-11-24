"""Sandbox merchant fees and independently reviewed full chargebacks.

All financial movements use the existing ledger in the same DB transaction.
No external scheme chargeback, no negative merchant balance or synthetic credit.
"""
import uuid
from spyderpay_core.ledger import PaymentError
from .store import _id, _amount, _jsonable
from .banking import authorize_role, reference


def calculate_fee(amount,bps):
    _amount(amount)
    if type(bps) is not int or not 0<=bps<=1000:raise PaymentError('invalid_fee_rate',422)
    return amount*bps//10000


def quote_fee(conn, p, invoice):
    # Serialize selection with schedule approval; merchant row is already locked by caller.
    s=conn.execute('''SELECT s.id,s.bps FROM sp_fee_schedules s JOIN sp_fee_approvals a ON a.schedule_id=s.id WHERE s.tenant_id=%s AND s.merchant_account=%s ORDER BY s.created_at DESC,s.id DESC LIMIT 1''',(p.tenant_id,invoice['merchant_account'])).fetchone()
    if s is None:return 0
    amount=calculate_fee(invoice['amount'],s['bps'])
    conn.execute('INSERT INTO sp_invoice_fees(invoice_id,schedule_id,amount) VALUES(%s,%s,%s)',(invoice['id'],s['id'],amount))
    return amount


def fee_movement(processor,conn,p,inv,direction):
    fee=conn.execute('SELECT amount FROM sp_invoice_fees WHERE invoice_id=%s',(inv['id'],)).fetchone()
    if not fee or not fee['amount']:return None
    if direction not in ('collect','reverse'):raise PaymentError('invalid_fee_direction',422)
    aid=str(uuid.uuid5(uuid.NAMESPACE_URL,'spyderpay:merchant-fee:v7:'+p.tenant_id))
    conn.execute("INSERT INTO sp_accounts(id,tenant_id,owner_id,kind,currency) VALUES(%s,%s,'fee-revenue-v7','system','UZS') ON CONFLICT DO NOTHING",(aid,p.tenant_id))
    merchant=str(inv['merchant_account'])
    src,dst=processor._lock_accounts(conn,merchant if direction=='collect' else aid,aid if direction=='collect' else merchant)
    revenue=dst if direction=='collect' else src
    if revenue['tenant_id']!=p.tenant_id or revenue['kind']!='system' or revenue['owner_id']!='fee-revenue-v7':raise PaymentError('invalid_fee_account',409)
    if direction=='reverse' and revenue['balance']<fee['amount']:raise PaymentError('fee_reserve_shortfall',409)
    jid=processor._post(conn,p,'merchant_fee' if direction=='collect' else 'merchant_fee_reverse',src,dst,fee['amount'],str(inv['id']))
    conn.execute('INSERT INTO sp_fee_movements(invoice_id,direction,journal_id) VALUES(%s,%s,%s)',(inv['id'],direction,jid))
    return jid


def refund_guard(conn,iid):
    if conn.execute("SELECT 1 FROM sp_chargebacks c LEFT JOIN sp_chargeback_decisions d ON d.case_id=c.id WHERE c.invoice_id=%s AND d.decision IS DISTINCT FROM 'reject'",(iid,)).fetchone():raise PaymentError('chargeback_in_progress',409)


class FinancialControls:
    def __init__(self,processor):self.p=processor
    def propose_fee(self,p,merchant,bps,evidence,idem):
        authorize_role(p,'fee_maker');merchant=_id(merchant);calculate_fee(1,bps);evidence=reference(evidence)
        data={'op':'fee_propose','merchant':merchant,'bps':bps,'evidence':evidence}
        def run(conn):
            m=conn.execute('SELECT * FROM sp_accounts WHERE id=%s AND tenant_id=%s FOR UPDATE',(merchant,p.tenant_id)).fetchone()
            if not m or m['kind']!='merchant':raise PaymentError('merchant_not_found',404)
            r=conn.execute('INSERT INTO sp_fee_schedules(tenant_id,merchant_account,bps,maker,evidence_ref) VALUES(%s,%s,%s,%s,%s) RETURNING *',(p.tenant_id,merchant,bps,p.subject,evidence)).fetchone()
            self.p._audit(conn,p,'fee_proposed',str(r['id']),data);return _jsonable(r)
        return self.p._once(p,idem,data,run)
    def approve_fee(self,p,sid,idem):
        authorize_role(p,'fee_review');sid=_id(sid)
        def run(conn):
            s=conn.execute('SELECT * FROM sp_fee_schedules WHERE id=%s AND tenant_id=%s',(sid,p.tenant_id)).fetchone()
            if not s or s['maker']==p.subject:raise PaymentError('independent_fee_review_required',403)
            conn.execute('SELECT id FROM sp_accounts WHERE id=%s FOR UPDATE',(s['merchant_account'],))
            r=conn.execute('INSERT INTO sp_fee_approvals(schedule_id,reviewer) VALUES(%s,%s) ON CONFLICT DO NOTHING RETURNING *',(sid,p.subject)).fetchone()
            if not r:raise PaymentError('fee_already_approved',409)
            self.p._audit(conn,p,'fee_approved',sid,{'schedule':sid});return _jsonable(r)
        return self.p._once(p,idem,{'op':'fee_approve','id':sid},run)
    def _invoice(self,conn,p,iid):
        i=conn.execute('SELECT * FROM sp_invoices WHERE id=%s AND tenant_id=%s FOR UPDATE',(_id(iid),p.tenant_id)).fetchone()
        if not i:raise PaymentError('invoice_not_found',404)
        if i['state']!='paid':raise PaymentError('invoice_not_paid',409)
        return i
    def open(self,p,iid,reason,evidence,idem):
        authorize_role(p,'dispute_maker');iid=_id(iid);evidence=reference(evidence)
        if reason not in ('unauthorized','duplicate','not_delivered','other'):raise PaymentError('invalid_dispute_reason',422)
        def run(conn):
            self._invoice(conn,p,iid)
            r=conn.execute('INSERT INTO sp_chargebacks(invoice_id,tenant_id,maker,reason,evidence_ref) VALUES(%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING RETURNING *',(iid,p.tenant_id,p.subject,reason,evidence)).fetchone()
            if not r:raise PaymentError('chargeback_already_exists',409)
            self.p._audit(conn,p,'chargeback_opened',str(r['id']),{'invoice':iid,'reason':reason,'evidence':evidence});return _jsonable(r)
        return self.p._once(p,idem,{'op':'chargeback_open','invoice':iid,'reason':reason,'evidence':evidence},run)
    def _case(self,conn,p,cid):
        c=conn.execute('SELECT * FROM sp_chargebacks WHERE id=%s AND tenant_id=%s',(_id(cid),p.tenant_id)).fetchone()
        if not c:raise PaymentError('chargeback_not_found',404)
        return c
    def decide(self,p,cid,decision,evidence,idem):
        authorize_role(p,'dispute_review');cid=_id(cid);evidence=reference(evidence)
        if decision not in ('approve','reject'):raise PaymentError('invalid_dispute_decision',422)
        def run(conn):
            c=self._case(conn,p,cid);self._invoice(conn,p,c['invoice_id'])
            if c['maker']==p.subject:raise PaymentError('independent_dispute_review_required',403)
            r=conn.execute('INSERT INTO sp_chargeback_decisions(case_id,reviewer,decision,evidence_ref) VALUES(%s,%s,%s,%s) ON CONFLICT DO NOTHING RETURNING *',(cid,p.subject,decision,evidence)).fetchone()
            if not r:raise PaymentError('chargeback_already_decided',409)
            self.p._audit(conn,p,'chargeback_decided',cid,{'decision':decision,'evidence':evidence});return _jsonable(r)
        return self.p._once(p,idem,{'op':'chargeback_decide','id':cid,'decision':decision,'evidence':evidence},run)
    def execute(self,p,cid,idem):
        authorize_role(p,'dispute_execute');cid=_id(cid)
        def run(conn):
            c=self._case(conn,p,cid);inv=self._invoice(conn,p,c['invoice_id'])
            d=conn.execute('SELECT * FROM sp_chargeback_decisions WHERE case_id=%s',(cid,)).fetchone()
            if not d or d['decision']!='approve' or p.subject in (c['maker'],d['reviewer']):raise PaymentError('chargeback_not_independently_approved',403)
            from .refunds import totals,execute_amount
            already,_=totals(conn,str(inv['id']))
            if already:
                result=execute_amount(self.p,conn,p,inv,inv['amount']-already,case_id=cid)
                jid=str(result['journal_id'])
                r=conn.execute('INSERT INTO sp_chargeback_executions(case_id,executor,journal_id) VALUES(%s,%s,%s) RETURNING *',(cid,p.subject,jid)).fetchone()
                self.p._audit(conn,p,'chargeback_executed',cid,{'journal':jid});self.p._outbox(conn,p,'invoice.chargeback',str(inv['id']),{'case_id':cid,'journal_id':jid})
                return _jsonable(r)
            src,dst=self.p._lock_accounts(conn,str(inv['merchant_account']),str(inv['payer_account']))
            fee_movement(self.p,conn,p,inv,'reverse')
            src=self.p._account(conn,str(src['id']))
            jid=self.p._post(conn,p,'merchant_refund',src,dst,inv['amount'],str(inv['id']))
            conn.execute("UPDATE sp_invoices SET state='refunded',refund_journal=%s WHERE id=%s",(jid,inv['id']))
            r=conn.execute('INSERT INTO sp_chargeback_executions(case_id,executor,journal_id) VALUES(%s,%s,%s) RETURNING *',(cid,p.subject,jid)).fetchone()
            self.p._audit(conn,p,'chargeback_executed',cid,{'journal':jid});self.p._outbox(conn,p,'invoice.chargeback',str(inv['id']),{'case_id':cid,'journal_id':jid})
            return _jsonable(r)
        return self.p._once(p,idem,{'op':'chargeback_execute','id':cid},run)
