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
