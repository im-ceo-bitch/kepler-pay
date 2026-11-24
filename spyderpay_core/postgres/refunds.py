"""Amount-bound partial refunds. All postings and refund record commit together."""
from uuid import uuid5,NAMESPACE_URL
from spyderpay_core.ledger import PaymentError
from .store import _id,_amount,_jsonable


def refund_quote(gross,fee,already,amount):
    _amount(gross);_amount(amount)
    if type(fee) is not int or not 0<=fee<=gross or type(already) is not int or not 0<=already<=gross:
        raise PaymentError('invalid_refund_totals',409)
    if amount>gross-already:raise PaymentError('refund_exceeds_remaining',409)
    # Cumulative rounding: the last refund returns every remaining fee unit.
    return fee*(already+amount)//gross-fee*already//gross


def totals(conn,iid):
    r=conn.execute('SELECT coalesce(sum(amount),0) AS amount,coalesce(sum(fee_amount),0) AS fee FROM sp_amount_refunds WHERE invoice_id=%s',(iid,)).fetchone()
    return int(r['amount']),int(r['fee'])


def execute_amount(processor,conn,p,inv,amount,*,case_id=None):
    from .financial_controls import refund_guard
    iid=str(inv['id'])
    if case_id is None:refund_guard(conn,iid)
    already,returned=totals(conn,iid)
    quote=conn.execute('SELECT amount FROM sp_invoice_fees WHERE invoice_id=%s',(iid,)).fetchone()
    fee=int(quote['amount']) if quote else 0
    delta=refund_quote(inv['amount'],fee,already,amount)
    if returned!=fee*already//inv['amount']:raise PaymentError('refund_fee_integrity_error',409)
    merchant,payer=str(inv['merchant_account']),str(inv['payer_account'])
    # Lock all accounts in a single deterministic order before moving money.
    revenue=str(uuid5(NAMESPACE_URL,'spyderpay:merchant-fee:v7:'+p.tenant_id))
    ids=sorted({merchant,payer,*([revenue] if delta else [])})
    rows=conn.execute('SELECT * FROM sp_accounts WHERE id=ANY(%s::uuid[]) ORDER BY id FOR UPDATE',(ids,)).fetchall()
    accounts={str(r['id']):r for r in rows}
    if set(accounts)!=set(ids) or any(r['tenant_id']!=p.tenant_id for r in rows):raise PaymentError('refund_account_invalid',409)
    if accounts[merchant]['kind']!='merchant' or accounts[payer]['kind']!='customer':raise PaymentError('refund_account_invalid',409)
    if p.identity is not None:
        processor._scope(p,accounts[merchant],'merchant')
    # The existing _post checks funds, active status and user compliance.
    fj=None
    if delta:
        rev=accounts[revenue]
        if rev['kind']!='system' or rev['owner_id']!='fee-revenue-v7' or rev['balance']<delta:raise PaymentError('fee_reserve_shortfall',409)
        fj=processor._post(conn,p,'merchant_fee_reverse',rev,accounts[merchant],delta,iid)
    jid=processor._post(conn,p,'merchant_refund',processor._account(conn,merchant),accounts[payer],amount,iid)
    r=conn.execute('''INSERT INTO sp_amount_refunds(invoice_id,amount,fee_amount,journal_id,fee_journal_id,case_id)
        VALUES(%s,%s,%s,%s,%s,%s) RETURNING *''',(iid,amount,delta,jid,fj,case_id)).fetchone()
    remaining=inv['amount']-already-amount
    if remaining==0:
        conn.execute("UPDATE sp_invoices SET state='refunded',refund_journal=%s WHERE id=%s",(jid,iid))
    result={**_jsonable(r),'refunded_total':already+amount,'remaining':remaining,'state':'partially_refunded' if remaining else 'refunded','currency':'UZS'}
    processor._audit(conn,p,'amount_refunded',iid,result)
    processor._outbox(conn,p,'invoice.refund_amount',iid,result)
    return result


def refund_amount(processor,p,iid,amount,idem):
    p.require('merchant');iid=_id(iid);amount=_amount(amount)
    def run(conn):
        inv=conn.execute('SELECT * FROM sp_invoices WHERE id=%s AND tenant_id=%s FOR UPDATE',(iid,p.tenant_id)).fetchone()
        if not inv:raise PaymentError('invoice_not_found',404)
        if inv['state']!='paid':raise PaymentError('invoice_not_paid',409)
        processor._scope(p,processor._account(conn,str(inv['merchant_account'])),'merchant')
        return execute_amount(processor,conn,p,inv,amount)
    return processor._once(p,idem,{'op':'refund_amount','invoice_id':iid,'amount':amount},run)
