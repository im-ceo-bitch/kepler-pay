"""Sandbox-only double-entry ledger. Never connect this module to real client funds.

All amounts are integer UZS minor-units of this demo (integer whole UZS by convention).
There is deliberately no SPYDER Coin or exchange-rate accounting here.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path


class PaymentError(Exception):
    def __init__(self, code: str, status: int = 400):
        super().__init__(code)
        self.code = code
        self.status = status


def _uuid() -> str:
    return str(uuid.uuid4())


def _hash(payload: dict) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


def _amount(value: object) -> int:
    # bool is a subclass of int, and should not be valid money.
    if type(value) is not int or value <= 0 or value > 10**12:
        raise PaymentError('invalid_positive_integer_amount')
    return value


class Ledger:
    """Intended for local tests and pilot demonstrations; NO bank integration."""

    def __init__(self, filename: str | Path = ':memory:') -> None:
        self.db = sqlite3.connect(str(filename), isolation_level=None, timeout=15, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA foreign_keys = ON')
        self.db.execute('PRAGMA busy_timeout = 15000')
        self.db.execute('PRAGMA journal_mode = WAL')
        self.db.executescript('''
        CREATE TABLE IF NOT EXISTS accounts (
            id TEXT PRIMARY KEY, label TEXT NOT NULL,
            currency TEXT NOT NULL CHECK(currency = 'UZS'),
            category TEXT NOT NULL CHECK(category IN ('customer','merchant','system')),
            balance INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS postings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            journal_id TEXT NOT NULL, account_id TEXT NOT NULL REFERENCES accounts(id),
            amount INTEGER NOT NULL CHECK(amount != 0),
            created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS postings_account_idx ON postings(account_id);
        CREATE INDEX IF NOT EXISTS postings_journal_idx ON postings(journal_id);
        CREATE TABLE IF NOT EXISTS journals (
            id TEXT PRIMARY KEY, kind TEXT NOT NULL,
            created_at INTEGER NOT NULL, reference TEXT
        );
        CREATE TABLE IF NOT EXISTS idempotency (
            key TEXT PRIMARY KEY, request_hash TEXT NOT NULL,
            result_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS invoices (
            id TEXT PRIMARY KEY, merchant_account TEXT NOT NULL REFERENCES accounts(id),
            amount INTEGER NOT NULL CHECK(amount > 0),
            state TEXT NOT NULL CHECK(state IN ('pending','paid','refunded')),
            payer_account TEXT REFERENCES accounts(id),
            payment_journal TEXT REFERENCES journals(id),
            refund_journal TEXT REFERENCES journals(id),
            created_at INTEGER NOT NULL
        );
        ''')
        self.db.execute("INSERT OR IGNORE INTO accounts(id,label,currency,category,balance,created_at) VALUES('sandbox:clearing','SANDBOX CLEARING','UZS','system',0,?)", (int(time.time()),))

    @contextmanager
    def _tx(self):
        self.db.execute('BEGIN IMMEDIATE')
        try:
            yield
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise

    def _once(self, key: str, payload: dict, func):
        if not isinstance(key, str) or not (8 <= len(key) <= 128) or not key.isascii():
            raise PaymentError('idempotency_key_required')
        fingerprint = _hash(payload)
        with self._tx():
            existing = self.db.execute('SELECT request_hash,result_json FROM idempotency WHERE key=?', (key,)).fetchone()
            if existing:
                if existing['request_hash'] != fingerprint:
                    raise PaymentError('idempotency_conflict', 409)
                return json.loads(existing['result_json'])
            result = func()
            self.db.execute('INSERT INTO idempotency(key,request_hash,result_json) VALUES(?,?,?)',
                            (key, fingerprint, json.dumps(result, sort_keys=True)))
            return result

    def _acct(self, account_id: str, expected_category: str | None = None):
        row = self.db.execute('SELECT * FROM accounts WHERE id=?', (account_id,)).fetchone()
        if row is None:
            raise PaymentError('account_not_found', 404)
        if expected_category and row['category'] != expected_category:
            raise PaymentError('incorrect_account_category')
        return row

    def account(self, account_id: str) -> dict:
        row = self._acct(account_id)
        return dict(row)

    def create_account(self, label: str, category: str, idem: str) -> dict:
        if category not in ('customer', 'merchant') or not isinstance(label, str) or not (1 <= len(label.strip()) <= 80):
            raise PaymentError('invalid_account')
        label = label.strip()
        def apply():
            aid = 'acc_' + _uuid()
            self.db.execute('INSERT INTO accounts(id,label,currency,category,balance,created_at) VALUES(?,?,?,?,0,?)',
                            (aid,label,'UZS',category,int(time.time())))
            return self.account(aid)
        return self._once(idem, {'op':'create_account','label':label,'category':category}, apply)

    def _journal(self, kind: str, debit: str, credit: str, amount: int, reference: str | None = None) -> str:
        """Must run inside an IMMEDIATE transaction; debit and credit are separate accounts."""
        amount = _amount(amount)
        if debit == credit:
            raise PaymentError('same_account')
        dr, cr = self._acct(debit), self._acct(credit)
        if dr['currency'] != cr['currency']:
            raise PaymentError('currency_mismatch')
        if dr['category'] != 'system' and dr['balance'] < amount:
            raise PaymentError('insufficient_funds', 409)
        now = int(time.time())
        jid = 'jnl_' + _uuid()
        self.db.execute('INSERT INTO journals(id,kind,created_at,reference) VALUES(?,?,?,?)', (jid,kind,now,reference))
        self.db.executemany('INSERT INTO postings(journal_id,account_id,amount,created_at) VALUES(?,?,?,?)',
                            [(jid,debit,-amount,now),(jid,credit,amount,now)])
        self.db.execute('UPDATE accounts SET balance=balance-? WHERE id=?', (amount,debit))
        self.db.execute('UPDATE accounts SET balance=balance+? WHERE id=?', (amount,credit))
        return jid

    def sandbox_credit(self, account_id: str, amount: int, idem: str) -> dict:
        amount = _amount(amount)
        def apply():
            self._acct(account_id, 'customer')
            jid = self._journal('sandbox_credit','sandbox:clearing',account_id,amount)
            return {'journal_id':jid,'account_id':account_id,'amount':amount,'currency':'UZS','status':'sandbox_only'}
        return self._once(idem, {'op':'sandbox_credit','account_id':account_id,'amount':amount}, apply)

    def transfer(self, source: str, target: str, amount: int, idem: str) -> dict:
        amount = _amount(amount)
        def apply():
            self._acct(source, 'customer')
            self._acct(target, 'customer')
            jid = self._journal('transfer',source,target,amount)
            return {'journal_id':jid,'source':source,'target':target,'amount':amount,'currency':'UZS','status':'sandbox_only'}
        return self._once(idem, {'op':'transfer','source':source,'target':target,'amount':amount}, apply)

    def create_invoice(self, merchant: str, amount: int, idem: str) -> dict:
        amount = _amount(amount)
        def apply():
            self._acct(merchant,'merchant')
            iid = 'inv_' + _uuid()
            self.db.execute('INSERT INTO invoices(id,merchant_account,amount,state,created_at) VALUES(?,?,?,?,?)',
                            (iid,merchant,amount,'pending',int(time.time())))
            return self.invoice(iid)
        return self._once(idem, {'op':'create_invoice','merchant':merchant,'amount':amount}, apply)

    def invoice(self, invoice_id: str) -> dict:
        row = self.db.execute('SELECT * FROM invoices WHERE id=?',(invoice_id,)).fetchone()
        if not row:
            raise PaymentError('invoice_not_found',404)
        return dict(row)

    def pay_invoice(self, invoice_id: str, payer: str, idem: str) -> dict:
        def apply():
            invoice = self.invoice(invoice_id)
            self._acct(payer,'customer')
            if invoice['state'] != 'pending':
                raise PaymentError('invoice_not_pending',409)
            jid = self._journal('merchant_payment',payer,invoice['merchant_account'],invoice['amount'],invoice_id)
            self.db.execute("UPDATE invoices SET state='paid',payer_account=?,payment_journal=? WHERE id=?",
                            (payer,jid,invoice_id))
            return self.invoice(invoice_id)
        return self._once(idem, {'op':'pay_invoice','invoice_id':invoice_id,'payer':payer}, apply)

    def refund_invoice(self, invoice_id: str, idem: str) -> dict:
        def apply():
            invoice = self.invoice(invoice_id)
            if invoice['state'] != 'paid':
                raise PaymentError('invoice_not_paid',409)
            jid = self._journal('merchant_refund',invoice['merchant_account'],invoice['payer_account'],invoice['amount'],invoice_id)
            self.db.execute("UPDATE invoices SET state='refunded',refund_journal=? WHERE id=?",(jid,invoice_id))
            return self.invoice(invoice_id)
        return self._once(idem, {'op':'refund_invoice','invoice_id':invoice_id}, apply)

    def audit_invariants(self) -> dict:
        """Checks zero-sum journals, balance caches, no non-system negative accounts."""
        unbalanced = self.db.execute('''SELECT j.id FROM journals j LEFT JOIN postings p ON p.journal_id=j.id
                             GROUP BY j.id HAVING COALESCE(SUM(p.amount),0)!=0 OR COUNT(p.id)!=2''').fetchall()
        balances = self.db.execute('''SELECT a.id FROM accounts a LEFT JOIN
                         (SELECT account_id,SUM(amount) total FROM postings GROUP BY account_id) p
                         ON p.account_id=a.id WHERE a.balance!=COALESCE(p.total,0)''').fetchall()
        negatives = self.db.execute("SELECT id FROM accounts WHERE category!='system' AND balance<0").fetchall()
        return {'ok':not (unbalanced or balances or negatives),'unbalanced_journals':[x[0] for x in unbalanced],
                'incorrect_balances':[x[0] for x in balances], 'negative_customer_balances':[x[0] for x in negatives]}
