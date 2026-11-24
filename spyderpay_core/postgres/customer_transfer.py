"""Resolve/cancel a wallet-created transfer intent without creating a second debit.
Cancellation reserves the original idempotency key atomically, before a delayed
payment can acquire it. It cannot undo a committed transfer.
"""
import json
import re
from spyderpay_core.ledger import PaymentError
from .identity import assert_membership
from .store import _id, _amount, _digest

WALLET_KEY=re.compile(r'wallet-transfer-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')


def resolve_transfer(processor,p,source,target,amount,idem,*,cancel=False):
    if p.identity is None or p.roles!=frozenset({'customer'}):
        raise PaymentError('customer_identity_required',403)
    src,dst,amount=_id(source),_id(target),_amount(amount)
    if src==dst or not isinstance(idem,str) or not WALLET_KEY.fullmatch(idem) or type(cancel) is not bool:
        raise PaymentError('invalid_transfer_intent',422)
    actor=json.dumps([p.tenant_id,p.subject],separators=(',',':'))
    digest=_digest({'op':'transfer','source':src,'target':dst,'amount':amount,'tenant':p.tenant_id})
    base={'source':src,'target':dst,'amount':amount,'currency':'UZS','real_money':False}
    with processor._connect() as conn,conn.transaction():
        assert_membership(conn,p)
        account=conn.execute("SELECT id FROM sp_accounts WHERE id=%s AND tenant_id=%s AND owner_id=%s AND kind='customer'",(src,p.tenant_id,p.subject)).fetchone()
        if not account:raise PaymentError('account_not_found',404)
        if cancel:
            # Identical key/actor and lock order as PgProcessor._once. An uncommitted
            # transfer either wins or rolls back before cancellation can proceed.
            conn.execute('INSERT INTO sp_idempotency(actor,idem_key,request_digest) VALUES(%s,%s,%s) ON CONFLICT DO NOTHING',(actor,idem,digest))
        row=conn.execute('SELECT request_digest,result FROM sp_idempotency WHERE actor=%s AND idem_key=%s FOR UPDATE',(actor,idem)).fetchone()
        if not row:return {**base,'state':'unresolved','journal_id':None}
        if row['request_digest']!=digest:raise PaymentError('idempotency_conflict',409)
        result=row['result']
        if result is None:
            if not cancel:return {**base,'state':'unresolved','journal_id':None}
            marker={'cancelled':True,'source':src,'target':dst,'amount':amount,'currency':'UZS'}
            conn.execute('UPDATE sp_idempotency SET result=%s::jsonb WHERE actor=%s AND idem_key=%s AND result IS NULL',(json.dumps(marker),actor,idem))
            processor._audit(conn,p,'wallet_transfer_cancelled',idem,{'request_digest':digest})
            return {**base,'state':'cancelled','journal_id':None}
        if not isinstance(result,dict) or any(result.get(k)!=v for k,v in (('source',src),('target',dst),('amount',amount),('currency','UZS'))):
            raise PaymentError('transfer_resolution_mismatch',409)
        if result.get('cancelled') is True:
            return {**base,'state':'cancelled','journal_id':None}
        jid=_id(result.get('journal_id'))
        leg=conn.execute('''SELECT j.id FROM sp_journals j JOIN sp_postings a ON a.journal_id=j.id
            JOIN sp_postings b ON b.journal_id=j.id
            WHERE j.id=%s AND j.tenant_id=%s AND j.kind='transfer' AND j.currency='UZS'
            AND a.account_id=%s AND b.account_id=%s AND a.signed_amount=%s AND b.signed_amount=%s''',(jid,p.tenant_id,src,dst,-amount,amount)).fetchone()
        if not leg:raise PaymentError('transfer_resolution_mismatch',409)
        return {**base,'state':'committed','journal_id':jid}
