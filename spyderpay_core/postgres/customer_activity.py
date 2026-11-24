"""Read-only recent ledger activity scoped to an authenticated account owner."""
from spyderpay_core.ledger import PaymentError
from .identity import assert_membership
from .store import _id, _jsonable


def customer_activity(processor, p, account_id):
    if p.identity is None or p.roles != frozenset({'customer'}):
        raise PaymentError('customer_identity_required', 403)
    aid = _id(account_id)
    with processor._connect() as conn, conn.transaction():
        assert_membership(conn, p)
        account = conn.execute('''SELECT id FROM sp_accounts
            WHERE id=%s AND tenant_id=%s AND owner_id=%s AND kind='customer' ''',
            (aid, p.tenant_id, p.subject)).fetchone()
        if not account:
            raise PaymentError('account_not_found', 404)
        rows = conn.execute('''SELECT j.id AS journal_id,j.kind,j.created_at,
            x.signed_amount AS amount, x.currency, i.id AS invoice_id
            FROM sp_postings x JOIN sp_journals j ON j.id=x.journal_id
            LEFT JOIN sp_invoices i ON i.payment_journal=j.id
                AND i.tenant_id=j.tenant_id AND i.payer_account=x.account_id
            WHERE x.account_id=%s AND j.tenant_id=%s AND x.currency='UZS'
            ORDER BY x.created_at DESC,x.id DESC LIMIT 51''',
            (aid, p.tenant_id)).fetchall()
        return {'account_id':aid, 'currency':'UZS', 'real_money':False,
                'has_more':len(rows)>50, 'activity':[_jsonable(r) for r in rows[:50]]}
