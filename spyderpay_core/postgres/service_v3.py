"""Version 3 service signatures: bind credential ID, idempotency header and exact target."""
import hashlib
import hmac
import json
import re
import time
from dataclasses import dataclass
from .auth import load_keys, NONCE, HEX64, KEY_ID, MAX_SKEW
from .store import KEY_RE
from spyderpay_core.ledger import PaymentError


@dataclass(frozen=True)
class Credential:
    service: object
    not_before: int
    not_after: int


V3_ROLES={'ops','monitor','bank_ops','bank_review','bank_callback','bank_statement','risk_ops','compliance_maker','compliance_review','clearing_review','bank_consent','bank_dispatch','fee_maker','fee_review','dispute_maker','dispute_review','dispute_execute'}

def load_credentials(raw: str) -> dict:
    items=json.loads(raw)
    keys=load_keys(raw,allowed_roles=V3_ROLES)
    out={}
    secrets_seen=set()
    actor_roles={}
    for item in items:
        kid=item['key_id']; k=keys[kid]
        start,end=item['not_before'],item['not_after']
        if len(k.principal.roles)!=1 or not k.principal.roles <= V3_ROLES or type(start) is not int or type(end) is not int or not 0<end-start<=90*86400 or k.secret in secrets_seen:
            raise ValueError('invalid_service_credential_scope_or_lifetime')
        actor=(k.principal.tenant_id,k.principal.subject)
        if actor in actor_roles and actor_roles[actor]!=k.principal.roles:raise ValueError("service_actor_role_conflict")
        actor_roles[actor]=k.principal.roles
        secrets_seen.add(k.secret)
        out[kid]=Credential(k,start,end)
    return out


def sign_v3(secret: bytes,kid: str,method: str,target: str,body: bytes,stamp: str,nonce: str,idem: str='')->str:
    # Domain-separated canonical JSON array; no ambiguity between fields.
    msg=json.dumps(['spyderpay-s2s-v3',kid,method.upper(),target,hashlib.sha256(body).hexdigest(),stamp,nonce,idem],separators=(',',':'),ensure_ascii=True).encode()
    return hmac.new(secret,msg,hashlib.sha256).hexdigest()


def verify_v3(method,target,body,headers,credentials,nonce_store,now=None):
    h={k.lower():v for k,v in headers.items()}
    kid=h.get('x-spyder-key-id',''); stamp=h.get('x-spyder-timestamp',''); nonce=h.get('x-spyder-nonce',''); sig=h.get('x-spyder-signature',''); idem=h.get('idempotency-key','')
    if not KEY_ID.fullmatch(kid) or kid not in credentials or not re.fullmatch(r'[0-9]{10}',stamp) or not NONCE.fullmatch(nonce) or not HEX64.fullmatch(sig) or (idem and not KEY_RE.fullmatch(idem)):
        raise PaymentError('unauthorized',401)
    now=int(time.time()) if now is None else now
    c=credentials[kid]
    if not c.not_before<=now<c.not_after or not c.not_before<=int(stamp)<c.not_after or abs(now-int(stamp))>MAX_SKEW:
        raise PaymentError('expired_request',401)
    expected=sign_v3(c.service.secret,kid,method,target,body,stamp,nonce,idem)
    if not hmac.compare_digest(expected,sig):raise PaymentError('unauthorized',401)
    if not nonce_store.claim('v3:'+kid,nonce):raise PaymentError('replayed_request',409)
    return c.service.principal
