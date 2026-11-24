"""Private S2S payment core API. Sandbox/prelicense environment ONLY.

Needs PostgreSQL and operator-authenticated reverse proxy. Binds loopback by default.
No public mobile app may hold these HMAC signing keys; customer OIDC gateway is TBD.
"""
from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, StrictInt

from spyderpay_core.ledger import PaymentError
from .auth import PostgresNonceStore, load_keys, verify
from .store import PgProcessor


class _Base(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)


class AccountCreate(_Base):
    owner_id: str = Field(min_length=3,max_length=96)
    kind: str


class Transfer(_Base):
    source: str
    target: str
    amount: StrictInt = Field(gt=0)


class InvoiceCreate(_Base):
    merchant_account: str
    amount: StrictInt = Field(gt=0)
    ttl_minutes: StrictInt = Field(default=15,ge=1,le=60)


class Pay(_Base):
    payer_account: str


class Freeze(_Base):
    reason: str=Field(min_length=8,max_length=150)


class Credit(_Base):
    account_id: str
    amount: StrictInt = Field(gt=0)


def create_app(processor: PgProcessor, key_config: str):
    keys=load_keys(key_config)
    nonce_store=PostgresNonceStore(processor)
    app=FastAPI(title='SpyderPay Private Payment Core',version='0.2.0',
                docs_url=None,redoc_url=None,openapi_url=None)

    @app.exception_handler(PaymentError)
    async def payment_error(_request:Request,exc:PaymentError):
        return JSONResponse({'error':exc.code},status_code=exc.status,headers={'Cache-Control':'no-store'})

    @app.middleware('http')
    async def security_headers(request:Request,call_next):
        if request.url.path=='/health/live':
            resp=await call_next(request)
        else:
            # Enforce body limit while streaming, BEFORE buffering untrusted bytes.
            length=request.headers.get('content-length','')
            if length.isdigit() and int(length)>16_384:
                return JSONResponse({'error':'body_too_large'},status_code=413)
            chunks=bytearray()
            async for chunk in request.stream():
                if len(chunks)+len(chunk)>16_384:
                    return JSONResponse({'error':'body_too_large'},status_code=413)
                chunks.extend(chunk)
            body=bytes(chunks)
            request._body=body  # Starlette caches body for downstream FastAPI parser.
            try:
                path=request.url.path
                if request.url.query:
                    path+='?'+request.url.query
                request.state.principal=verify(request.method,path,body,dict(request.headers),keys,nonce_store)
            except PaymentError as ex:
                return JSONResponse({'error':ex.code},status_code=ex.status)
            resp=await call_next(request)
        resp.headers['Cache-Control']='no-store'
        resp.headers['X-Content-Type-Options']='nosniff'
        resp.headers['Referrer-Policy']='no-referrer'
        resp.headers['Content-Security-Policy']="default-src 'none'; frame-ancestors 'none'"
        resp.headers['X-Frame-Options']='DENY'
        return resp

    def actor(request:Request):return request.state.principal

    @app.get('/health/live')
    def live():return {'alive':True,'real_money':False}

    @app.get('/v2/accounts/{account_id}')
    def get_account(request:Request,account_id:str):
        return processor.account(actor(request),account_id)

    @app.post('/v2/accounts')
    def create_account(request:Request,data:AccountCreate,idempotency_key:Annotated[str,Header(min_length=12,max_length=128)]):
        return processor.create_account(actor(request),data.owner_id,data.kind,idempotency_key)

    @app.post('/v2/transfers')
    def transfer(request:Request,data:Transfer,idempotency_key:Annotated[str,Header(min_length=12,max_length=128)]):
        return processor.transfer(actor(request),data.source,data.target,data.amount,idempotency_key)

    @app.post('/v2/invoices')
    def invoice(request:Request,data:InvoiceCreate,idempotency_key:Annotated[str,Header(min_length=12,max_length=128)]):
        return processor.create_invoice(actor(request),data.merchant_account,data.amount,idempotency_key,data.ttl_minutes)

    @app.get('/v2/invoices/{invoice_id}')
    def invoice_get(request:Request,invoice_id:str):
        return processor.invoice(actor(request),invoice_id)

    @app.post('/v2/invoices/{invoice_id}/pay')
    def invoice_pay(request:Request,invoice_id:str,data:Pay,idempotency_key:Annotated[str,Header(min_length=12,max_length=128)]):
        return processor.pay_invoice(actor(request),invoice_id,data.payer_account,idempotency_key)

    @app.post('/v2/invoices/{invoice_id}/refund')
    def invoice_refund(request:Request,invoice_id:str,idempotency_key:Annotated[str,Header(min_length=12,max_length=128)]):
        return processor.refund_invoice(actor(request),invoice_id,idempotency_key)

    @app.post('/v2/accounts/{account_id}/freeze')
    def freeze(request:Request,account_id:str,data:Freeze,idempotency_key:Annotated[str,Header(min_length=12,max_length=128)]):
        return processor.freeze(actor(request),account_id,data.reason,idempotency_key)

    @app.get('/v2/ops/reconciliation')
    def reconciliation(request:Request):
        return processor.reconcile(actor(request))

    @app.post('/v2/sandbox/credits')
    def mock_credit(request:Request,data:Credit,idempotency_key:Annotated[str,Header(min_length=12,max_length=128)]):
        # Explicit env gate even for operators. Never activate in a regulated deployment.
        if os.getenv('SPYDERPAY_ALLOW_SANDBOX_CREDIT')!='yes':
            raise PaymentError('sandbox_credit_disabled',403)
        return processor.sandbox_credit(actor(request),data.account_id,data.amount,idempotency_key)

    return app


def main():
    if os.environ.get('SPYDERPAY_ENV')!='prelicense':
        raise SystemExit('Refusing to start outside SPYDERPAY_ENV=prelicense')
    dsn=os.environ.get('SPYDERPAY_PG_DSN')
    keys=os.environ.get('SPYDERPAY_SERVICE_KEYS_JSON')
    if not dsn or not keys:
        raise SystemExit('SPYDERPAY_PG_DSN and SERVICE_KEYS_JSON are required')
    app=create_app(PgProcessor(dsn),keys)
    import uvicorn
    uvicorn.run(app,host='127.0.0.1',port=int(os.getenv('PORT','8766')),log_config=None,access_log=False)


if __name__=='__main__':main()
