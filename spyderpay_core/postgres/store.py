"""PostgreSQL transaction processor reference implementation.

All endpoints are partner/operator-to-operator. No public consumer auth, no real money
issuance, no bank integration. Run in a private test environment only.

Installation: pip install 'psycopg[binary]>=3.2,<4'. This module imports psycopg lazily.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from spyderpay_core.ledger import PaymentError

MAX_AMOUNT = 100_000_000  # policy EXAMPLE, whole UZS. Not approved limit.
MAX_DAILY_OUTGOING = 500_000_000  # policy EXAMPLE, whole UZS.
KEY_RE = re.compile(r'^[A-Za-z0-9._:-]{12,128}$')
IDENTITY_RE = re.compile(r'^[A-Za-z0-9_.:@-]{3,96}$')


def _digest(data: dict) -> str:
    return hashlib.sha256(json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()


def _amount(value: Any) -> int:
    if type(value) is not int or value < 1 or value > MAX_AMOUNT:
        raise PaymentError('invalid_amount_or_limit', 422)
    return value


def _identity(value: str) -> str:
    if not isinstance(value, str) or not IDENTITY_RE.fullmatch(value):
        raise PaymentError('invalid_identity', 422)
    return value


def _id(value: str) -> str:
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, TypeError):
        raise PaymentError('invalid_id', 422) from None


def _jsonable(record: dict[str, Any]) -> dict[str, Any]:
    return {k: (str(v) if isinstance(v, uuid.UUID) else v.isoformat() if isinstance(v, datetime) else v) for k,v in record.items()}


@dataclass(frozen=True)
class Principal:
    key_id: str
    tenant_id: str
    subject: str
    roles: frozenset[str]

    def require(self, role: str):
        if role not in self.roles:
            raise PaymentError('forbidden', 403)


class PgProcessor:
    def __init__(self, dsn: str):
        if not dsn or not isinstance(dsn, str):
            raise ValueError('PostgreSQL DSN required')
        self.dsn = dsn

    def _connect(self):
        try:
            import psycopg
            from psycopg.rows import dict_row
        except ImportError:
            raise RuntimeError('Install psycopg[binary] to run PostgreSQL processor') from None
        return psycopg.connect(self.dsn, autocommit=True, row_factory=dict_row, connect_timeout=5,
                               options='-c statement_timeout=5000 -c lock_timeout=2000')

    def _once(self, principal: Principal, key: str, payload: dict, func: Callable):
        if not isinstance(key, str) or not KEY_RE.fullmatch(key):
            raise PaymentError('idempotency_key_required', 422)
        actor = json.dumps([principal.tenant_id,principal.subject],separators=(',',':'))
        fingerprint = _digest(payload)
        # One transaction contains the idempotency slot, business changes, and outbox.
        with self._connect() as conn:
            with conn.transaction():
                conn.execute('''INSERT INTO sp_idempotency(actor,idem_key,request_digest)
                    VALUES (%s,%s,%s) ON CONFLICT DO NOTHING''',(actor,key,fingerprint))
                row = conn.execute('''SELECT request_digest,result FROM sp_idempotency
                    WHERE actor=%s AND idem_key=%s FOR UPDATE''',(actor,key)).fetchone()
                if row['request_digest'] != fingerprint:
                    raise PaymentError('idempotency_conflict', 409)
                if row['result'] is not None:
                    return row['result']
                result = func(conn)
                conn.execute('''UPDATE sp_idempotency SET result=%s::jsonb
                    WHERE actor=%s AND idem_key=%s''',(json.dumps(result),actor,key))
                return result

    @staticmethod
    def _scope(p: Principal, account: dict, role: str):
        if account['tenant_id'] != p.tenant_id or account['owner_id'] != p.subject or account['kind'] != role:
            raise PaymentError('forbidden', 403)

    @staticmethod
    def _account(conn, aid: str) -> dict:
        row = conn.execute('SELECT * FROM sp_accounts WHERE id=%s',(_id(aid),)).fetchone()
        if not row:
            raise PaymentError('account_not_found', 404)
        return row

    @staticmethod
    def _lock_accounts(conn, source: str, target: str) -> tuple[dict,dict]:
        src_id, dst_id = _id(source), _id(target)
        if src_id == dst_id:
            raise PaymentError('same_account', 422)
        # Deterministic lock ordering prevents reciprocal-transfer deadlocks.
        rows = conn.execute('''SELECT * FROM sp_accounts WHERE id IN (%s,%s)
                              ORDER BY id FOR UPDATE''',(src_id,dst_id)).fetchall()
        by_id = {str(x['id']):x for x in rows}
        if src_id not in by_id or dst_id not in by_id:
            raise PaymentError('account_not_found', 404)
        return by_id[src_id],by_id[dst_id]

    @staticmethod
    def _audit(conn, p: Principal, action: str, target: str, payload: dict):
        conn.execute('''INSERT INTO sp_audit_events(tenant_id,actor,action,target,payload_hash)
            VALUES(%s,%s,%s,%s,%s)''',(p.tenant_id,p.subject,action,target,_digest(payload)))

    @staticmethod
    def _outbox(conn, p: Principal, kind: str, reference: str, payload: dict):
        conn.execute('''INSERT INTO sp_outbox(tenant_id,event_type,aggregate_id,payload)
            VALUES(%s,%s,%s,%s::jsonb)''',(p.tenant_id,kind,reference,json.dumps(payload)))

    def create_account(self, p: Principal, owner: str, kind: str, idem: str) -> dict:
        p.require('ops')
        owner = _identity(owner)
        if kind not in ('customer','merchant'):
            raise PaymentError('invalid_account_kind', 422)
        data = {'op':'create_account','tenant':p.tenant_id,'owner':owner,'kind':kind}
        def run(conn):
            r=conn.execute('''INSERT INTO sp_accounts(tenant_id,owner_id,kind,currency)
                    VALUES(%s,%s,%s,'UZS') RETURNING id,tenant_id,owner_id,kind,currency,status,balance''',
                           (p.tenant_id,owner,kind)).fetchone()
            result=_jsonable(r)
            self._audit(conn,p,'account_created',result['id'],data)
            return result
        return self._once(p,idem,data,run)

    def account(self, p: Principal, account_id: str) -> dict:
        with self._connect() as conn:
            row=self._account(conn,account_id)
            if 'ops' not in p.roles:
                self._scope(p,row,row['kind'])
            elif row['tenant_id'] != p.tenant_id:
                raise PaymentError('forbidden',403)
            return _jsonable(row)

    def _post(self, conn, p: Principal, kind: str, src: dict, dst: dict, amount: int, reference: str | None = None) -> str:
        if src['tenant_id']!=p.tenant_id or dst['tenant_id']!=p.tenant_id:
            raise PaymentError('forbidden',403)
        if src['currency'] != dst['currency'] or src['currency']!='UZS':
            raise PaymentError('currency_mismatch',422)
        if src['status']!='active' or dst['status']!='active':
            raise PaymentError('frozen_or_closed_account',409)
        if src['kind']!='system' and src['balance']<amount:
            raise PaymentError('insufficient_funds',409)
        if src['kind']!='system':
            cutoff=datetime.now(timezone.utc)-timedelta(hours=24)
            row=conn.execute('''SELECT COALESCE(-SUM(p.signed_amount),0) AS total
                FROM sp_postings p JOIN sp_journals j ON j.id=p.journal_id
                WHERE p.account_id=%s AND p.signed_amount<0 AND j.created_at >= %s
                AND j.kind IN ('transfer','merchant_payment')''',(src['id'],cutoff)).fetchone()
            if int(row['total'])+amount>MAX_DAILY_OUTGOING:
                raise PaymentError('daily_limit_exceeded',409)
        journal=conn.execute('''INSERT INTO sp_journals(tenant_id,kind,reference,actor,currency)
                VALUES(%s,%s,%s,%s,'UZS') RETURNING id''',(p.tenant_id,kind,reference,p.subject)).fetchone()
        jid=str(journal['id'])
        conn.execute('''INSERT INTO sp_postings(journal_id,account_id,signed_amount,currency)
                VALUES(%s,%s,%s,'UZS'),(%s,%s,%s,'UZS')''',
                (jid,src['id'],-amount,jid,dst['id'],amount))
        # Conditional updates provide defense in depth for both overdraft and overflow.
        deb=conn.execute('''UPDATE sp_accounts SET balance=balance-%s
            WHERE id=%s AND (%s OR balance >= %s) RETURNING balance''',
            (amount,src['id'],src['kind']=='system',amount)).fetchone()
        if not deb:
            raise PaymentError('insufficient_funds',409)
        cre=conn.execute('''UPDATE sp_accounts SET balance=balance+%s
            WHERE id=%s RETURNING balance''',(amount,dst['id'])).fetchone()
        if not cre:
            raise PaymentError('account_not_found',404)
        self._audit(conn,p,kind,jid,{'src':str(src['id']),'dst':str(dst['id']),'amount':amount})
        self._outbox(conn,p,'ledger.journal.created',jid,{'journal_id':jid,'type':kind,'currency':'UZS'})
        return jid

    def transfer(self, p: Principal, source: str, target: str, amount: int, idem: str) -> dict:
        p.require('customer')
        amount=_amount(amount); source=_id(source);target=_id(target)
        data={'op':'transfer','source':source,'target':target,'amount':amount,'tenant':p.tenant_id}
        def run(conn):
            src,dst=self._lock_accounts(conn,source,target)
            self._scope(p,src,'customer')
            if dst['kind']!='customer' or dst['tenant_id']!=p.tenant_id:
                raise PaymentError('forbidden',403)
            jid=self._post(conn,p,'transfer',src,dst,amount)
            return {'journal_id':jid,'source':source,'target':target,'amount':amount,'currency':'UZS'}
        return self._once(p,idem,data,run)

    def create_invoice(self,p: Principal,merchant_account: str,amount: int,idem: str,ttl_minutes: int = 15) -> dict:
        p.require('merchant'); amount=_amount(amount);merchant_account=_id(merchant_account)
        if type(ttl_minutes) is not int or not 1<=ttl_minutes<=60:
            raise PaymentError('invalid_expiry',422)
        data={'op':'create_invoice','merchant_account':merchant_account,'amount':amount,'ttl_minutes':ttl_minutes}
        def run(conn):
            merchant=self._account(conn,merchant_account)
            self._scope(p,merchant,'merchant')
            if merchant['status']!='active': raise PaymentError('frozen_or_closed_account',409)
            expires=datetime.now(timezone.utc)+timedelta(minutes=ttl_minutes)
            r=conn.execute('''INSERT INTO sp_invoices(tenant_id,merchant_account,amount,expires_at)
                VALUES(%s,%s,%s,%s) RETURNING id,state,amount,expires_at,merchant_account''',
                (p.tenant_id,merchant_account,amount,expires)).fetchone()
            result=_jsonable(r)
            self._audit(conn,p,'invoice_created',result['id'],data)
            self._outbox(conn,p,'invoice.created',result['id'],result)
            return result
        return self._once(p,idem,data,run)

    def invoice(self,p: Principal,invoice_id: str) -> dict:
        iid=_id(invoice_id)
        with self._connect() as conn:
            inv=conn.execute('SELECT * FROM sp_invoices WHERE id=%s',(iid,)).fetchone()
            if not inv or inv['tenant_id'] != p.tenant_id: raise PaymentError('invoice_not_found',404)
            # Customer may obtain invoice details only with invoice capability (future public signed token).
            if 'ops' not in p.roles and 'merchant' in p.roles:
                merchant=self._account(conn,str(inv['merchant_account']))
                self._scope(p,merchant,'merchant')
            elif 'ops' not in p.roles:
                raise PaymentError('forbidden',403)
            return _jsonable(inv)

    def pay_invoice(self,p: Principal,invoice_id: str,payer: str,idem: str) -> dict:
        p.require('customer');iid=_id(invoice_id);payer=_id(payer)
        data={'op':'pay_invoice','invoice_id':iid,'payer':payer}
        def run(conn):
            inv=conn.execute('SELECT * FROM sp_invoices WHERE id=%s FOR UPDATE',(iid,)).fetchone()
            if not inv or inv['tenant_id']!=p.tenant_id: raise PaymentError('invoice_not_found',404)
            if inv['state']!='pending': raise PaymentError('invoice_not_pending',409)
            if inv['expires_at']<=datetime.now(timezone.utc): raise PaymentError('invoice_expired',409)
            src,dst=self._lock_accounts(conn,payer,str(inv['merchant_account']))
            self._scope(p,src,'customer')
            if dst['kind']!='merchant' or dst['tenant_id']!=p.tenant_id:
                raise PaymentError('forbidden',403)
            jid=self._post(conn,p,'merchant_payment',src,dst,inv['amount'],iid)
            r=conn.execute('''UPDATE sp_invoices SET state='paid',payer_account=%s,payment_journal=%s
                WHERE id=%s RETURNING id,state,amount,merchant_account,payer_account,payment_journal''',
                (payer,jid,iid)).fetchone()
            result=_jsonable(r)
            self._outbox(conn,p,'invoice.paid',iid,result)
            return result
        return self._once(p,idem,data,run)

    def refund_invoice(self,p: Principal,invoice_id: str,idem: str) -> dict:
        p.require('merchant');iid=_id(invoice_id)
        data={'op':'refund_invoice','invoice_id':iid}
        def run(conn):
            inv=conn.execute('SELECT * FROM sp_invoices WHERE id=%s FOR UPDATE',(iid,)).fetchone()
            if not inv or inv['tenant_id']!=p.tenant_id: raise PaymentError('invoice_not_found',404)
            if inv['state']!='paid': raise PaymentError('invoice_not_paid',409)
            src,dst=self._lock_accounts(conn,str(inv['merchant_account']),str(inv['payer_account']))
            self._scope(p,src,'merchant')
            jid=self._post(conn,p,'merchant_refund',src,dst,inv['amount'],iid)
            r=conn.execute('''UPDATE sp_invoices SET state='refunded',refund_journal=%s WHERE id=%s
                RETURNING id,state,amount,refund_journal''',(jid,iid)).fetchone()
            result=_jsonable(r)
            self._outbox(conn,p,'invoice.refunded',iid,result)
            return result
        return self._once(p,idem,data,run)

    def freeze(self,p: Principal,account_id: str,reason: str,idem: str) -> dict:
        p.require('ops');account_id=_id(account_id)
        if not isinstance(reason,str) or not (8<=len(reason)<=150):
            raise PaymentError('reason_required',422)
        data={'op':'freeze','account_id':account_id,'reason':reason}
        def run(conn):
            row=conn.execute('SELECT * FROM sp_accounts WHERE id=%s FOR UPDATE',(account_id,)).fetchone()
            if not row or row['tenant_id']!=p.tenant_id: raise PaymentError('account_not_found',404)
            if row['kind']=='system': raise PaymentError('forbidden',403)
            conn.execute("UPDATE sp_accounts SET status='frozen' WHERE id=%s",(account_id,))
            self._audit(conn,p,'account_frozen',account_id,data)
            self._outbox(conn,p,'account.frozen',account_id,{'account_id':account_id})
            return {'account_id':account_id,'status':'frozen'}
        return self._once(p,idem,data,run)

    def reconcile(self,p: Principal) -> dict:
        p.require('ops')
        with self._connect() as conn:
            conn.execute('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY')
            unbalanced=conn.execute('''SELECT j.id FROM sp_journals j LEFT JOIN sp_postings x ON x.journal_id=j.id
                WHERE j.tenant_id=%s GROUP BY j.id HAVING count(x.id)<2 OR COALESCE(sum(x.signed_amount),0)<>0''',(p.tenant_id,)).fetchall()
            balances=conn.execute('''SELECT a.id FROM sp_accounts a LEFT JOIN
                (SELECT account_id,sum(signed_amount) total FROM sp_postings GROUP BY account_id) x ON x.account_id=a.id
                WHERE a.tenant_id=%s AND a.balance<>COALESCE(x.total,0)''',(p.tenant_id,)).fetchall()
            negatives=conn.execute("SELECT id FROM sp_accounts WHERE tenant_id=%s AND kind <> 'system' AND balance<0",(p.tenant_id,)).fetchall()
            result={'ok':not (unbalanced or balances or negatives),'unbalanced':len(unbalanced),
                    'balance_mismatch':len(balances),'negative_external':len(negatives)}
            conn.execute('COMMIT')
            return result

    def sandbox_credit(self,p: Principal,account_id: str,amount: int,idem: str) -> dict:
        """Test-only funding. MUST NOT be routed from a production request."""
        p.require('ops');account_id=_id(account_id);amount=_amount(amount)
        data={'op':'sandbox_credit','account_id':account_id,'amount':amount}
        clearing_id=str(uuid.uuid5(uuid.NAMESPACE_URL,'spyderpay-sandbox-clearing:'+p.tenant_id))
        def run(conn):
            conn.execute('''INSERT INTO sp_accounts(id,tenant_id,owner_id,kind,currency)
                VALUES(%s,%s,'sandbox-only','system','UZS') ON CONFLICT DO NOTHING''',(clearing_id,p.tenant_id))
            src,dst=self._lock_accounts(conn,clearing_id,account_id)
            if dst['tenant_id']!=p.tenant_id or dst['kind']!='customer':raise PaymentError('forbidden',403)
            jid=self._post(conn,p,'sandbox_credit',src,dst,amount)
            return {'journal_id':jid,'account_id':account_id,'amount':amount,'currency':'UZS','sandbox':True}
        return self._once(p,idem,data,run)
