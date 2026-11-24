"""Private pre-license merchant terminal, not a card reader or payment authority.
Requires a trusted external IdP agent to provide a short-lived access token.
A durable sale identifier is written before requesting an invoice. Retry only
with the same sale and idempotency key; never infer payment from a QR scan.
"""
import argparse
from contextlib import contextmanager
import http.client
import json
import os
from pathlib import Path
import re
import sqlite3
import ssl
import stat
import uuid
from urllib.parse import urlsplit
from datetime import datetime, timezone
from spyderpay_core.postgres.store import MAX_AMOUNT

JWT = re.compile(r'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')


def identifier(value):
    if not isinstance(value, str) or str(uuid.UUID(value)) != value:
        raise ValueError('invalid_identifier')
    return value


def amount_value(value):
    if type(value) is not int or not 1 <= value <= MAX_AMOUNT:
        raise ValueError('invalid_amount')
    return value


def access_token(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as f:
        info = os.fstat(f.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.getuid():
            raise ValueError('unsafe_access_token_file')
        token = f.read(8193).decode('ascii').strip()
    if len(token) > 8192 or not JWT.fullmatch(token):
        raise ValueError('invalid_access_token')
    return token


class MerchantAPI:
    def __init__(self, origin, token_path, ca_file, *, transport=http.client.HTTPSConnection):
        u = urlsplit(origin)
        if u.scheme != 'https' or not u.hostname or u.username or u.password or u.path not in ('', '/') or u.query or u.fragment:
            raise ValueError('invalid_https_origin')
        self.host, self.port = u.hostname, u.port or 443
        self.origin = f'https://{u.netloc}'
        self.token_path = token_path
        self.context = ssl.create_default_context(cafile=ca_file)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.transport = transport

    def request(self, method, path, body=None, idem=None):
        # Only fixed paths constructed by methods below, no redirects/proxies/retries.
        headers = {'Authorization': 'Bearer ' + access_token(self.token_path), 'Accept': 'application/json'}
        data = None
        if body is not None:
            headers['Content-Type'] = 'application/json'
            data = json.dumps(body, separators=(',', ':')).encode('ascii')
        if idem is not None:
            headers['Idempotency-Key'] = idem
        c = self.transport(self.host, self.port, timeout=8, context=self.context)
        try:
            c.request(method, path, body=data, headers=headers)
            r = c.getresponse()
            if r.status != 200:
                raise RuntimeError(f'merchant_http_{r.status}')
            data = r.read(131073)
            if len(data) > 131072:
                raise RuntimeError('merchant_response_too_large')
            result = json.loads(data)
            if not isinstance(result, dict):
                raise RuntimeError('invalid_merchant_response')
            return result
        except (OSError, http.client.HTTPException, ValueError):
            raise RuntimeError('merchant_transport_or_response_failed') from None
        finally:
            c.close()

    def accounts(self):
        rows = self.request('GET', '/v3/accounts').get('accounts')
        if not isinstance(rows, list):
            raise RuntimeError('invalid_accounts_response')
        return [identifier(r['id']) for r in rows if r.get('kind') == 'merchant' and r.get('currency') == 'UZS' and r.get('status') == 'active']

    def create(self, sale):
        return self.request('POST', '/v3/invoices', {'merchant_account': sale['merchant'], 'amount': sale['amount'], 'ttl_minutes': 15}, 'pos-sale-' + identifier(sale['id']))

    def status(self, invoice):
        return self.request('GET', '/v3/invoices/' + identifier(invoice))

    def qr(self, invoice):
        result = self.request('POST', '/v3/pos/invoices/' + identifier(invoice) + '/token', {})
        token = result.get('token')
        if result.get('sandbox') is not True or result.get('format') != 'spyderpay-pos+jwt' or not isinstance(token, str) or len(token) > 2048 or not JWT.fullmatch(token):
            raise RuntimeError('invalid_pos_payload')
        return token


class Sales:
    """Local non-secret journal; the server ledger is the only money authority."""
    def __init__(self, directory, origin):
        root = Path(directory)
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = root.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.getuid():
            raise ValueError('private_terminal_directory_required')
        path = root / 'sales.sqlite3'
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.getuid():
                raise ValueError('unsafe_terminal_database')
        finally:
            os.close(fd)
        self.path, self.origin = path, origin
        with self.connect() as c:
            c.execute('''CREATE TABLE IF NOT EXISTS sale(id TEXT PRIMARY KEY, origin TEXT NOT NULL,
                merchant TEXT NOT NULL, amount INTEGER NOT NULL, invoice TEXT, created TEXT NOT NULL)''')

    @contextmanager
    def connect(self):
        c = sqlite3.connect(self.path, timeout=5)
        c.row_factory = sqlite3.Row
        try:
            c.execute('PRAGMA synchronous=FULL')
            with c:
                yield c
        finally:
            c.close()

    def reserve(self, sale, merchant, amount):
        identifier(sale); identifier(merchant); amount_value(amount)
        with self.connect() as c:
            c.execute('INSERT OR IGNORE INTO sale VALUES(?,?,?,?,NULL,?)', (sale,self.origin,merchant,amount,datetime.now(timezone.utc).isoformat()))
            row = self._row(c, sale)
            if row['merchant'] != merchant or row['amount'] != amount:
                raise ValueError('sale_reference_conflict')
        return row

    def _row(self, c, sale):
        row = c.execute('SELECT * FROM sale WHERE id=? AND origin=?', (identifier(sale), self.origin)).fetchone()
        if row is None:
            raise ValueError('sale_not_found')
        return dict(row)

    def get(self, sale):
        with self.connect() as c:
            return self._row(c, sale)

    def attach(self, sale, invoice):
        with self.connect() as c:
            c.execute('UPDATE sale SET invoice=? WHERE id=? AND origin=? AND (invoice IS NULL OR invoice=?)', (identifier(invoice), identifier(sale), self.origin, invoice))
            if self._row(c,sale)['invoice'] != invoice:
                raise RuntimeError('invoice_reference_conflict')

    def recent(self):
        with self.connect() as c:
            return [dict(r) for r in c.execute('SELECT * FROM sale WHERE origin=? ORDER BY created DESC LIMIT 100',(self.origin,))]

    def pending(self):
        with self.connect() as c:
            return [dict(r) for r in c.execute('SELECT * FROM sale WHERE origin=? AND invoice IS NULL ORDER BY created LIMIT 100', (self.origin,))]


def check_invoice(sale, invoice):
    if (identifier(invoice['merchant_account']) != sale['merchant'] or type(invoice['amount']) is not int or invoice['amount'] != sale['amount'] or
            (sale['invoice'] is not None and sale['invoice'] != identifier(invoice['id']))):
        raise RuntimeError('invoice_mismatch')
    identifier(invoice['id'])
    if invoice['state'] not in ('pending','paid','refunded','cancelled','expired'):
        raise RuntimeError('unknown_invoice_state')
    expiry = datetime.fromisoformat(invoice['expires_at'])
    if expiry.tzinfo is None:
        raise RuntimeError('invalid_invoice_expiry')
    refunded = invoice.get('refunded_total',0)
    if type(refunded) is not int or not 0 <= refunded <= sale['amount']:
        raise RuntimeError('invalid_refunded_amount')
    state = invoice['state']
    if (state == 'refunded' and refunded != sale['amount']) or (state in ('pending','cancelled','expired') and refunded != 0) or (state == 'paid' and refunded == sale['amount']):
        raise RuntimeError('refund_state_mismatch')
    if state == 'pending' and expiry <= datetime.now(timezone.utc):
        state = 'expired'
    return {'sale_id':sale['id'],'invoice_id':invoice['id'],'amount':sale['amount'],'currency':'UZS','state':state,'refunded_total':refunded,'prelicense':True}


class Terminal:
    def __init__(self, api, sales):
        self.api, self.sales = api, sales

    def create(self, sale, merchant, amount):
        # Commit local idempotency reference before external request.
        self.sales.reserve(sale,merchant,amount)
        return self.resume(sale)

    def resume(self, sale):
        row = self.sales.get(sale)
        if row['invoice'] is None:
            invoice = self.api.create(row)
            check_invoice(row,invoice)
            self.sales.attach(sale,invoice['id'])
        return self.status(sale)

    def status(self, sale):
        row = self.sales.get(sale)
        if row['invoice'] is None:
            return {'sale_id':sale,'state':'unknown','prelicense':True}
        return check_invoice(row,self.api.status(row['invoice']))

    def qr(self, sale):
        status = self.status(sale)
        if status['state'] != 'pending':
            raise RuntimeError('invoice_not_pending')
        return self.api.qr(status['invoice_id'])


def main():
    if os.getenv('SPYDERPAY_ENV') != 'prelicense':
        raise SystemExit('Prelicense only')
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='cmd',required=True)
    sub.add_parser('accounts'); sub.add_parser('pending'); sub.add_parser('recent'); sub.add_parser('new-reference')
    c = sub.add_parser('create'); c.add_argument('sale'); c.add_argument('merchant'); c.add_argument('amount',type=int)
    for name in ('resume','status','qr'):
        sub.add_parser(name).add_argument('sale')
    a = p.parse_args()
    if a.cmd == 'new-reference':
        print(uuid.uuid4()); return
    api = MerchantAPI(os.environ['SPYDERPAY_TERMINAL_ORIGIN'],os.environ['SPYDERPAY_TERMINAL_TOKEN_FILE'],os.environ['SPYDERPAY_TERMINAL_CA_FILE'])
    sales = Sales(os.environ['SPYDERPAY_TERMINAL_STATE_DIR'],api.origin); terminal = Terminal(api,sales)
    if a.cmd == 'accounts': result = api.accounts()
    elif a.cmd == 'pending': result = sales.pending()
    elif a.cmd == 'recent': result = sales.recent()
    elif a.cmd == 'create': result = terminal.create(a.sale,a.merchant,a.amount)
    elif a.cmd == 'resume': result = terminal.resume(a.sale)
    elif a.cmd == 'status': result = terminal.status(a.sale)
    else:
        import qrcode
        code = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, border=4)
        code.add_data(terminal.qr(a.sale)); code.make(fit=True); code.print_ascii(invert=True)
        return
    print(json.dumps(result,sort_keys=True))

if __name__ == '__main__':
    main()
