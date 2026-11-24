"""S2S message authentication — NOT a replacement for consumer OAuth/OIDC.

This protects private partner/operator APIs against tampering and replay. Clients such
as iOS apps MUST NEVER embed an API signing secret. Use a separate user identity gateway.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
from dataclasses import dataclass
from typing import Any

from spyderpay_core.ledger import PaymentError
from .store import Principal

HEX64 = re.compile(r'^[0-9a-f]{64}$')
NONCE = re.compile(r'^[A-Za-z0-9_-]{20,128}$')
KEY_ID = re.compile(r'^[A-Za-z0-9_.:-]{3,64}$')
MAX_SKEW = 120


@dataclass(frozen=True)
class ServiceKey:
    secret: bytes
    principal: Principal


def load_keys(raw: str) -> dict[str,ServiceKey]:
    """JSON loaded from a secret manager, never version-controlled."""
    keys=json.loads(raw)
    if not isinstance(keys,list) or not keys or len(keys)>100:
        raise ValueError('expected nonempty array of service principals')
    out={}
    for item in keys:
        kid=item['key_id']; encoded=item['secret_b64']
        if not KEY_ID.fullmatch(kid) or kid in out:raise ValueError('invalid or duplicate key id')
        secret=base64.b64decode(encoded,validate=True)
        if len(secret)<32 or len(secret)>128:raise ValueError('service key length must be 32..128 bytes')
        roles=item['roles']; tenant=item['tenant_id']; subject=item['subject']
        if not isinstance(roles,list) or not roles or not set(roles)<={'ops','customer','merchant','bank_ops','bank_review','bank_callback','bank_statement','risk_ops'}:
            raise ValueError('invalid service roles')
        from .store import _identity
        out[kid]=ServiceKey(secret,Principal(kid,_identity(tenant),_identity(subject),frozenset(roles)))
    return out


def canonical(method: str,path: str,body: bytes,timestamp: str,nonce: str) -> bytes:
    # Signed URI includes query string; proxies must preserve it exactly.
    digest=hashlib.sha256(body).hexdigest()
    return f'{timestamp}\n{nonce}\n{method.upper()}\n{path}\n{digest}'.encode('utf-8')


def sign(secret: bytes,method: str,path: str,body: bytes,timestamp: str,nonce: str) -> str:
    return hmac.new(secret,canonical(method,path,body,timestamp,nonce),hashlib.sha256).hexdigest()


def verify(method: str,path: str,body: bytes,headers: dict[str,str],keys: dict[str,ServiceKey],
           nonce_store: Any,now: int | None=None) -> Principal:
    norm={k.lower():v for k,v in headers.items()}
    kid=norm.get('x-spyder-key-id','')
    stamp=norm.get('x-spyder-timestamp','')
    nonce=norm.get('x-spyder-nonce','')
    signature=norm.get('x-spyder-signature','')
    if not KEY_ID.fullmatch(kid) or kid not in keys:
        raise PaymentError('unauthorized',401)
    if not re.fullmatch(r'^[0-9]{10}$',stamp) or not NONCE.fullmatch(nonce) or not HEX64.fullmatch(signature):
        raise PaymentError('unauthorized',401)
    now=now if now is not None else int(time.time())
    if abs(now-int(stamp))>MAX_SKEW:
        raise PaymentError('expired_request',401)
    service=keys[kid]
    expected=sign(service.secret,method,path,body,stamp,nonce)
    if not hmac.compare_digest(signature,expected):
        raise PaymentError('unauthorized',401)
    # Durable replay records, with a unique (key_id, nonce) DB constraint.
    if not nonce_store.claim(kid,nonce):
        raise PaymentError('replayed_request',409)
    return service.principal


class PostgresNonceStore:
    MAX_RPM = 90  # Additional DB guard, not a WAF replacement.
    def __init__(self,processor):
        self.processor=processor

    def claim(self,key_id:str,nonce:str)->bool:
        with self.processor._connect() as conn:
            with conn.transaction():
                bucket=int(time.time()) // 60
                hits=conn.execute('''INSERT INTO sp_rate_windows(key_id,minute_bucket,hits)
                    VALUES(%s,%s,1) ON CONFLICT(key_id,minute_bucket)
                    DO UPDATE SET hits=sp_rate_windows.hits+1 RETURNING hits''',
                    (key_id,bucket)).fetchone()['hits']
                if hits>self.MAX_RPM:
                    raise PaymentError('rate_limited',429)
                row=conn.execute('''INSERT INTO sp_api_replay(key_id,nonce)
                    VALUES(%s,%s) ON CONFLICT DO NOTHING RETURNING key_id''',(key_id,nonce)).fetchone()
                return row is not None

    def purge_expired(self):
        # Only after >= 2x max skew; keep a margin against clock drift.
        with self.processor._connect() as conn:
            conn.execute("DELETE FROM sp_api_replay WHERE observed_at < now() - interval '1 hour'")
            conn.execute('DELETE FROM sp_rate_windows WHERE minute_bucket < %s',(int(time.time())//60-120,))
