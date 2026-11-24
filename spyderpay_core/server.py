"""Minimal local-only HTTP adapter for the SpyderPay sandbox ledger.

Not production software. No user authentication, banking rail, payment acceptance,
real assets, KYC, or PCI compliance. Never expose on public interfaces.
"""
from __future__ import annotations

import argparse
import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit

from .ledger import Ledger, PaymentError


def make_handler(ledger: Ledger, token: str):
    class Handler(BaseHTTPRequestHandler):
        server_version = 'SpyderPaySandbox/0.1'
        def _response(self, status, value):
            data = json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
            self.send_response(status)
            self.send_header('Content-Type','application/json; charset=utf-8')
            self.send_header('Content-Length',str(len(data)))
            self.send_header('Cache-Control','no-store')
            self.send_header('X-Content-Type-Options','nosniff')
            self.end_headers()
            self.wfile.write(data)

        def _dispatch(self):
            path = urlsplit(self.path).path
            if path == '/health' and self.command == 'GET':
                return self._response(200,{'status':'ok','environment':'sandbox','real_money':False})
            supplied = self.headers.get('X-Demo-Token','')
            if not hmac.compare_digest(supplied, token):
                return self._response(401,{'error':'sandbox_token_required'})
            if self.command == 'GET':
                if path.startswith('/v1/accounts/'):
                    return self._response(200,ledger.account(path.removeprefix('/v1/accounts/')))
                if path.startswith('/v1/invoices/'):
                    return self._response(200,ledger.invoice(path.removeprefix('/v1/invoices/')))
                if path == '/sandbox/audit':
                    return self._response(200,ledger.audit_invariants())
                return self._response(404,{'error':'not_found'})
            if self.command != 'POST':
                return self._response(405,{'error':'method_not_allowed'})
            size = self.headers.get('Content-Length','')
            if not size.isdigit() or int(size)>16384:
                return self._response(413,{'error':'invalid_body_length'})
            try:
                data = json.loads(self.rfile.read(int(size)))
                if not isinstance(data, dict):
                    raise ValueError()
            except (ValueError, UnicodeDecodeError):
                return self._response(400,{'error':'invalid_json'})
            key = self.headers.get('Idempotency-Key','')
            if path == '/sandbox/accounts':
                result = ledger.create_account(data.get('label'),data.get('category'),key)
            elif path == '/sandbox/credits':
                result = ledger.sandbox_credit(data.get('account_id'),data.get('amount'),key)
            elif path == '/v1/transfers':
                result = ledger.transfer(data.get('source'),data.get('target'),data.get('amount'),key)
            elif path == '/v1/invoices':
                result = ledger.create_invoice(data.get('merchant_account'),data.get('amount'),key)
            elif path.startswith('/v1/invoices/') and path.endswith('/pay'):
                invoice_id=path[len('/v1/invoices/'):-len('/pay')]
                result = ledger.pay_invoice(invoice_id,data.get('payer_account'),key)
            elif path.startswith('/v1/invoices/') and path.endswith('/refund'):
                invoice_id=path[len('/v1/invoices/'):-len('/refund')]
                result = ledger.refund_invoice(invoice_id,key)
            else:
                return self._response(404,{'error':'not_found'})
            return self._response(200,result)

        def do_GET(self):
            self._handle()
        def do_POST(self):
            self._handle()
        def _handle(self):
            try:
                self._dispatch()
            except PaymentError as exc:
                self._response(exc.status,{'error':exc.code})
            except (sqlite3.Error, OSError):
                self._response(503,{'error':'storage_unavailable'})
        def log_message(self, format, *args):
            # Log only status/route; never log bearer token or request body.
            pass
    import sqlite3
    return Handler


def main():
    ap=argparse.ArgumentParser(description='LOCAL SANDBOX ONLY — no real funds')
    ap.add_argument('--db',default='spyderpay-sandbox.sqlite3')
    ap.add_argument('--port',type=int,default=8765)
    args=ap.parse_args()
    if os.environ.get('SPYDERPAY_ENV','sandbox') != 'sandbox':
        raise SystemExit('Refusing to run: this package only supports SPYDERPAY_ENV=sandbox')
    token=os.environ.get('SPYDERPAY_DEMO_TOKEN')
    if not token or len(token)<24:
        raise SystemExit('Set SPYDERPAY_DEMO_TOKEN to a local random value of >=24 characters')
    ledger=Ledger(args.db)
    server=HTTPServer(('127.0.0.1',args.port),make_handler(ledger,token))
    print(f'SpyderPay SANDBOX API on http://127.0.0.1:{args.port} (local only)')
    try:
        server.serve_forever()
    finally:
        server.server_close()
        ledger.db.close()


if __name__ == '__main__':
    main()
