"""Payer-only recovery of a committed invoice, independent of client state."""
from spyderpay_core.ledger import PaymentError
from .identity import assert_membership
from .store import _id, _jsonable
from .refunds import totals


def customer_receipt(processor,p,invoice_id):
    if p.identity is None:raise PaymentError('user_identity_required',403)
    p.require('customer')
    with processor._connect() as conn,conn.transaction():
        assert_membership(conn,p)
        row=conn.execute('''SELECT i.id,i.state,i.amount,i.merchant_account,i.payer_account,i.payment_journal
        FROM sp_invoices i JOIN sp_accounts a ON a.id=i.payer_account
        WHERE i.id=%s AND i.tenant_id=%s AND a.tenant_id=i.tenant_id AND a.owner_id=%s AND a.kind='customer'
        AND i.state IN ('paid','refunded') AND i.payment_journal IS NOT NULL''',(_id(invoice_id),p.tenant_id,p.subject)).fetchone()
        if not row:raise PaymentError('receipt_not_found',404)
        result=_jsonable(row)
        result['refunded_total']=row['amount'] if row['state']=='refunded' else totals(conn,str(row['id']))[0]
        return {**result,'currency':'UZS','real_money':False}


def resolve_payment(processor,p,invoice_id,payer_account,expected_merchant,expected_amount):
    """A lost response is not permission to reissue a payment. Lock invoice before
    classifying. Final no-debit requires immutable terms and terminal/expired state.
    No counterparty data or receipt of another payer is returned.
    """
    from .store import _amount
    if p.identity is None or p.roles != frozenset({'customer'}):
        raise PaymentError('customer_identity_required',403)
    iid,payer,merchant,amount=_id(invoice_id),_id(payer_account),_id(expected_merchant),_amount(expected_amount)
    with processor._connect() as conn,conn.transaction():
        assert_membership(conn,p)
        account=conn.execute("SELECT id FROM sp_accounts WHERE id=%s AND tenant_id=%s AND owner_id=%s AND kind='customer'",(payer,p.tenant_id,p.subject)).fetchone()
        if not account:raise PaymentError('account_not_found',404)
        row=conn.execute('''SELECT id,state,amount,merchant_account,payer_account,payment_journal,expires_at
            FROM sp_invoices WHERE id=%s AND tenant_id=%s AND merchant_account=%s AND amount=%s FOR UPDATE''',(iid,p.tenant_id,merchant,amount)).fetchone()
        if not row:raise PaymentError('receipt_not_found',404)
        base={'invoice_id':iid,'payer_account':payer,'merchant_account':merchant,'amount':amount,'currency':'UZS','real_money':False}
        if row['state'] in ('paid','refunded') and str(row['payer_account'])==payer and row['payment_journal']:
            receipt=_jsonable({k:row[k] for k in ('id','state','amount','merchant_account','payer_account','payment_journal')})
            receipt['refunded_total']=amount if row['state']=='refunded' else totals(conn,iid)[0]
            return {**base,'state':'committed','receipt':{**receipt,'currency':'UZS','real_money':False}}
        expired=conn.execute('SELECT %s::timestamptz<=clock_timestamp() AS expired',(row['expires_at'],)).fetchone()['expired']
        # Seal an expired pending invoice into its immutable terminal state before
        # asserting no debit. This also handles clock skew/backward clock adjustments:
        # a delayed POST cannot reopen a cancelled invoice. No ledger write is made.
        if row['state']=='pending' and expired:
            changed=conn.execute("UPDATE sp_invoices SET state='cancelled' WHERE id=%s AND state='pending' RETURNING id",(iid,)).fetchone()
            if not changed:raise PaymentError('resolution_conflict',409)
            processor._audit(conn,p,'expired_invoice_resolution',iid,{'invoice_id':iid})
            return {**base,'state':'not_paid_final','receipt':None}
        if row['state']=='cancelled' or (expired and row['state'] in ('paid','refunded') and str(row['payer_account'])!=payer):
            return {**base,'state':'not_paid_final','receipt':None}
        return {**base,'state':'unresolved','receipt':None}
