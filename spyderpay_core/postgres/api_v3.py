"""Pre-license HTTP boundary. No production mode, bank calls or real money issuance."""
from __future__ import annotations
import asyncio
import os
import re
import uuid
from dataclasses import replace
from typing import Annotated, Literal, Union

from fastapi import FastAPI, Header, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import Field, StrictInt
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException as StarletteHTTPException

from spyderpay_core.ledger import PaymentError
from .api import _Base, AccountCreate, Transfer, InvoiceCreate, Pay, Freeze, Credit
from .auth import PostgresNonceStore
from .identity import OIDCVerifier, resolve_principal, assert_membership, issue_approval, confirm_approval
from .service_v3 import load_credentials, verify_v3
from .store import PgProcessor, KEY_RE, _id, _jsonable

MAX_BODY=16384
TARGET=re.compile(rb'/[A-Za-z0-9/_-]{1,220}')
CRITICAL={b'authorization',b'idempotency-key',b'x-spyder-key-id',b'x-spyder-timestamp',b'x-spyder-nonce',b'x-spyder-signature',b'x-spyder-approval',b'content-type',b'content-length',b'host',b'transfer-encoding'}
MONEY_ROUTES={'transfer','pay_invoice','refund_invoice'}


class TransferApproval(_Base):
    operation: Literal['transfer']
    source: str
    target: str
    amount: StrictInt = Field(gt=0)


class InvoiceApproval(_Base):
    operation: Literal['pay_invoice']
    invoice_id: str
    payer: str
    expected_amount: StrictInt = Field(gt=0)
    expected_merchant: str


class RefundApproval(_Base):
    operation: Literal['refund_invoice']
    invoice_id: str
    expected_amount: StrictInt = Field(gt=0)
    expected_merchant: str


Approval=Annotated[Union[TransferApproval,InvoiceApproval,RefundApproval],Field(discriminator='operation')]
Idem=Annotated[str,Header(min_length=12,max_length=128)]


def _response(error: str,status: int):
    return JSONResponse({'error':error},status_code=status)


def _headers(response, request_id):
    response.headers['Cache-Control']='no-store'
    response.headers['X-Content-Type-Options']='nosniff'
    response.headers['Referrer-Policy']='no-referrer'
    response.headers['Content-Security-Policy']="default-src 'none'; frame-ancestors 'none'"
    response.headers['X-Frame-Options']='DENY'
    response.headers['X-Request-Id']=request_id
    return response


def _check_request(request: Request):
    raw=request.scope.get('raw_path',b'')
    if not TARGET.fullmatch(raw) or raw.decode('ascii')!=request.url.path or request.scope.get('query_string',b'') or b'//' in raw or raw.endswith(b'/'):
        raise PaymentError('invalid_request_target',400)
    seen=set()
    for name,val in request.scope['headers']:
        n=name.lower()
        if n in CRITICAL:
            if n in seen or len(val)>8192 or b'\r' in val or b'\n' in val:
                raise PaymentError('ambiguous_request_headers',400)
            seen.add(n)
    if b'content-length' in seen and b'transfer-encoding' in seen:
        raise PaymentError('ambiguous_request_headers',400)
    length=request.headers.get('content-length')
    if length is not None and (not re.fullmatch(r'[0-9]{1,9}',length) or int(length)>MAX_BODY):
        raise PaymentError('invalid_or_excessive_content_length',413)
    if request.method not in ('GET','POST'):
        raise PaymentError('method_not_allowed',405)
    if request.method=='POST' and request.headers.get('content-type','').split(';',1)[0].strip().lower()!='application/json':
        raise PaymentError('unsupported_content_type',415)
    return raw.decode('ascii')


class IdentityRateLimit:
    """Per-subject persistent quota. Network-edge rate limiting remains required."""
    def __init__(self,processor):self.processor=processor
    def claim(self,principal):
        import time
        with self.processor._connect() as conn, conn.transaction():
            row=conn.execute('''INSERT INTO sp_rate_windows(key_id,minute_bucket,hits) VALUES(%s,%s,1)
             ON CONFLICT(key_id,minute_bucket) DO UPDATE SET hits=sp_rate_windows.hits+1 RETURNING hits''',
             (principal.key_id,int(time.time())//60)).fetchone()
            if row['hits']>90:raise PaymentError('rate_limited',429)


def create_app(processor: PgProcessor, service_config: str, oidc_config: str, *, allow_sandbox_credit=False):
    credentials=load_credentials(service_config)
    verifier=OIDCVerifier(oidc_config)
    nonces=PostgresNonceStore(processor)
    rate=IdentityRateLimit(processor)
    app=FastAPI(title='SpyderPay pre-license API',version='0.4.0',docs_url=None,redoc_url=None,openapi_url=None,redirect_slashes=False)
    slots=asyncio.Semaphore(24)

    @app.exception_handler(PaymentError)
    async def payment_error(_request,exc):return _response(exc.code,exc.status)

    @app.exception_handler(RequestValidationError)
    async def validation_error(_request,_exc):return _response('invalid_request',422)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(_request,exc):return _response('not_found' if exc.status_code==404 else 'request_rejected',exc.status_code)

    def authenticate(request,target,body):
        h=request.headers
        auth=h.get('authorization','')
        service=any(h.get(n) is not None for n in ('x-spyder-key-id','x-spyder-timestamp','x-spyder-nonce','x-spyder-signature'))
        if auth and service:raise PaymentError('ambiguous_authentication',400)
        if auth:
            if not auth.startswith('Bearer ') or len(auth.split(' '))!=2:raise PaymentError('invalid_access_token',401)
            identity=verifier.verify(auth[7:])
            principal=resolve_principal(processor,identity)
            rate.claim(principal)
            aid=h.get('x-spyder-approval')
            return replace(principal,approval_id=_id(aid)) if aid is not None else principal
        if h.get('x-spyder-approval') is not None:raise PaymentError('invalid_authentication',401)
        return verify_v3(request.method,target,body,dict(h),credentials,nonces)

    @app.middleware('http')
    async def boundary(request: Request,call_next):
        rid=str(uuid.uuid4())
        acquired=False
        try:
            target=_check_request(request)
            if target=='/health/live' and request.method=='GET':return _headers(await call_next(request),rid)
            if not target.startswith('/v3/'):
                return _headers(_response('not_found',404),rid)
            try:
                await asyncio.wait_for(slots.acquire(),timeout=0.2)
                acquired=True
            except TimeoutError:
                return _headers(_response('overloaded',503),rid)
            data=bytearray()
            async with asyncio.timeout(5):
                async for chunk in request.stream():
                    if len(data)+len(chunk)>MAX_BODY:raise PaymentError('body_too_large',413)
                    data.extend(chunk)
            body=bytes(data)
            if request.method=='GET' and body:raise PaymentError('unexpected_body',400)
            length=request.headers.get('content-length')
            if length is not None and int(length)!=len(body):raise PaymentError('invalid_content_length',400)
            if request.method=='POST':
                # Reject duplicate JSON object keys, NaN, Infinity and malformed UTF-8.
                import json
                def pairs(entries):
                    out={}
                    for k,v in entries:
                        if k in out:raise ValueError('duplicate_json_key')
                        out[k]=v
                    return out
                def constant(_):raise ValueError('nonfinite_json')
                try:
                    parsed=json.loads(body.decode('utf-8'),object_pairs_hook=pairs,parse_constant=constant)
                    if not isinstance(parsed,dict):raise ValueError('object_required')
                except (ValueError,UnicodeError,RecursionError):raise PaymentError('invalid_json',400) from None
            request._body=body
            request.state.principal=await run_in_threadpool(authenticate,request,target,body)
            result=await call_next(request)
        except PaymentError as ex:
            result=_response(ex.code,ex.status)
        except TimeoutError:
            result=_response('request_timeout',408)
        except Exception as ex:
            # No raw payload, token, SQL, or traceback in response/log. Alert on opaque ID.
            import logging
            logging.getLogger('spyderpay.security').error('request_failed request_id=%s error_type=%s',rid,type(ex).__name__)
            result=_response('temporarily_unavailable',503)
        finally:
            if acquired:slots.release()
        return _headers(result,rid)

    def actor(request):return request.state.principal
    def user(request, role):
        p=actor(request)
        if p.identity is None:raise PaymentError('user_identity_required',403)
        p.require(role)
        return p
    def operator(request):
        p=actor(request)
        if p.identity is not None:raise PaymentError('service_identity_required',403)
        p.require('ops')
        return p

    @app.get('/health/live')
    def live():return {'alive':True,'real_money':False,'api_version':3}

    @app.get('/v3/ops/ready')
    def ready(request: Request):
        operator(request)
        with processor._connect() as conn:
            row=conn.execute('SELECT max(version) AS version FROM sp_schema_version').fetchone()
        if row['version']!=4:raise PaymentError('schema_not_ready',503)
        return {'ready':True,'schema':4,'real_money':False}

    @app.get('/v3/accounts')
    def accounts(request: Request):
        p=actor(request)
        if p.identity is None:raise PaymentError('user_identity_required',403)
        with processor._connect() as conn, conn.transaction():
            assert_membership(conn,p)
            rows=conn.execute('''SELECT id,kind,currency,status,balance FROM sp_accounts WHERE tenant_id=%s AND owner_id=%s AND kind=%s ORDER BY created_at,id LIMIT 100''',(p.tenant_id,p.subject,next(iter(p.roles)))).fetchall()
            return {'accounts':[_jsonable(x) for x in rows]}

    @app.get('/v3/accounts/{account_id}')
    def account(request: Request,account_id: str):return processor.account(actor(request),account_id)

    @app.post('/v3/ops/accounts')
    def create_account(request: Request,data: AccountCreate,idempotency_key: Idem):
        return processor.create_account(operator(request),data.owner_id,data.kind,idempotency_key)

    @app.post('/v3/ops/accounts/{account_id}/freeze')
    def freeze(request: Request,account_id: str,data: Freeze,idempotency_key: Idem):
        return processor.freeze(operator(request),account_id,data.reason,idempotency_key)

    @app.get('/v3/ops/reconciliation')
    def reconciliation(request: Request):return processor.reconcile(operator(request))

    @app.post('/v3/ops/sandbox/credits')
    def sandbox_credit(request: Request,data: Credit,idempotency_key: Idem):
        p=operator(request)
        if not allow_sandbox_credit:raise PaymentError('sandbox_credit_disabled',403)
        return processor.sandbox_credit(p,data.account_id,data.amount,idempotency_key)

    @app.post('/v3/approvals')
    def approvals(request: Request,data: Approval,idempotency_key: Idem):
        p=actor(request)
        if p.identity is None:raise PaymentError('user_identity_required',403)
        values=data.model_dump(); op=values.pop('operation')
        return issue_approval(processor,p,op,values,idempotency_key)

    @app.post('/v3/approvals/{approval_id}/confirm')
    def approval_confirm(request: Request,approval_id: str,data: _Base):
        return confirm_approval(processor,verifier,actor(request),approval_id)

    @app.post('/v3/transfers')
    def transfer(request: Request,data: Transfer,idempotency_key: Idem):
        return processor.transfer(user(request,'customer'),data.source,data.target,data.amount,idempotency_key)

    @app.post('/v3/invoices')
    def create_invoice(request: Request,data: InvoiceCreate,idempotency_key: Idem):
        return processor.create_invoice(user(request,'merchant'),data.merchant_account,data.amount,idempotency_key,data.ttl_minutes)

    @app.get('/v3/invoices/{invoice_id}')
    def invoice(request: Request,invoice_id: str):return processor.invoice(actor(request),invoice_id)

    @app.get('/v3/invoices/{invoice_id}/preview')
    def preview(request: Request,invoice_id: str):
        p=user(request,'customer')
        with processor._connect() as conn, conn.transaction():
            assert_membership(conn,p)
            row=conn.execute('''SELECT id,merchant_account,amount,expires_at FROM sp_invoices WHERE id=%s AND tenant_id=%s AND state='pending' AND expires_at>now()''',(_id(invoice_id),p.tenant_id)).fetchone()
            if not row:raise PaymentError('invoice_not_found',404)
            return _jsonable(row)

    @app.post('/v3/invoices/{invoice_id}/pay')
    def pay(request: Request,invoice_id: str,data: Pay,idempotency_key: Idem):
        return processor.pay_invoice(user(request,'customer'),invoice_id,data.payer_account,idempotency_key)

    @app.post('/v3/invoices/{invoice_id}/refund')
    def refund(request: Request,invoice_id: str,data: _Base,idempotency_key: Idem):
        return processor.refund_invoice(user(request,'merchant'),invoice_id,idempotency_key)

    from .bank_api import mount_bank_routes
    mount_bank_routes(app,processor)
    return app


def main():
    if os.getenv('SPYDERPAY_ENV')!='prelicense':raise SystemExit('Refusing non-prelicense environment')
    dsn=os.environ['SPYDERPAY_PG_DSN']
    processor=PgProcessor(dsn)
    with processor._connect() as conn:
        version=conn.execute('SELECT max(version) AS version FROM sp_schema_version').fetchone()['version']
        if version!=4:raise SystemExit('Migrate with a separate database owner before starting API')
        # Application must never run as a superuser or schema owner.
        row=conn.execute('''SELECT r.rolsuper,r.rolcreaterole,r.rolcreatedb,r.rolbypassrls,r.rolreplication,
           pg_has_role(current_user,c.relowner,'MEMBER') AS owns_ledger
           FROM pg_roles r JOIN pg_class c ON c.oid='sp_journals'::regclass WHERE r.rolname=current_user''').fetchone()
        if any(row.values()):raise SystemExit('Unsafe database runtime role')
    app=create_app(processor,os.environ['SPYDERPAY_SERVICE_KEYS_JSON'],os.environ['SPYDERPAY_OIDC_JSON'],allow_sandbox_credit=os.getenv('SPYDERPAY_ALLOW_SANDBOX_CREDIT')=='yes')
    import uvicorn
    uvicorn.run(app,host='127.0.0.1',port=int(os.getenv('PORT','8766')),access_log=False,proxy_headers=False,server_header=False,timeout_keep_alive=3,limit_concurrency=32)

if __name__=='__main__':main()
