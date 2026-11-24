"""OIDC access-token verification and durable, operation-bound approvals.

The configured identity provider must issue RFC 9068 access tokens with sid and
trusted MFA claims. Public keys are provisioned out of band; no token-supplied URL
is ever fetched. User/tenant/role mapping is server-controlled in PostgreSQL.
"""
from __future__ import annotations
import hashlib
import json
import re
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import jwt
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from spyderpay_core.ledger import PaymentError
from .store import Principal, KEY_RE, _digest, _id, _amount

MAX_TOKEN_SECONDS = 600
MAX_MFA_AGE = 120
APPROVAL_TTL = 90
CHALLENGE_TTL = 300
ID = re.compile(r'^[\x21-\x7e]{1,200}$')


@dataclass(frozen=True)
class Identity:
    issuer: str
    subject: str
    sid: str
    expires: int
    jti: str
    auth_time: int | None
    acr: str | None


class OIDCVerifier:
    def __init__(self, config: str):
        c = json.loads(config)
        self.issuer, self.audience, self.client_id = (c[k] for k in ('issuer','audience','client_id'))
        parsed = urlsplit(self.issuer)
        if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment or parsed.query:
            raise ValueError('issuer_must_be_https')
        if not all(isinstance(x,str) and ID.fullmatch(x) for x in (self.audience,self.client_id)):
            raise ValueError('invalid_oidc_audience_or_client')
        acrs = c['mfa_acr_values']
        if not isinstance(acrs,list) or not acrs or not all(isinstance(x,str) and ID.fullmatch(x) for x in acrs):
            raise ValueError('explicit_mfa_acr_required')
        self.mfa_acrs = frozenset(acrs)
        self.keys: dict[str,RSAPublicKey] = {}
        keys = c['jwks']['keys']
        if not isinstance(keys,list) or not 1 <= len(keys) <= 32:
            raise ValueError('invalid_jwks')
        for item in keys:
            kid = item['kid']
            if not isinstance(kid,str) or not ID.fullmatch(kid) or kid in self.keys or item.get('kty')!='RSA' or item.get('alg','RS256')!='RS256' or item.get('use','sig')!='sig' or 'd' in item:
                raise ValueError('invalid_jwk')
            key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(item))
            if not isinstance(key,RSAPublicKey) or not 2048<=key.key_size<=4096:
                raise ValueError('invalid_rsa_key')
            self.keys[kid] = key

    def verify(self, token: str) -> Identity:
        try:
            if not isinstance(token,str) or len(token)>8192 or token.count('.')!=2:
                raise ValueError('invalid_token')
            header = jwt.get_unverified_header(token)
            if header.get('alg')!='RS256' or header.get('typ','').lower() not in ('at+jwt','application/at+jwt') or any(k in header for k in ('jku','x5u','jwk','crit')):
                raise ValueError('invalid_token_header')
            key = self.keys[header['kid']]
            c = jwt.decode(token,key,algorithms=['RS256'],audience=self.audience,issuer=self.issuer,
                           options={'require':['iss','aud','sub','exp','iat','jti','sid','client_id']})
            if c['client_id']!=self.client_id or not all(isinstance(c[k],str) and ID.fullmatch(c[k]) for k in ('sub','sid','jti')):
                raise ValueError('invalid_claims')
            now=int(time.time())
            if type(c['exp']) is not int or type(c['iat']) is not int or not 0 < c['exp']-c['iat']<=MAX_TOKEN_SECONDS or c['iat']>now or c['exp']<=now:
                raise ValueError('invalid_token_lifetime')
            at=c.get('auth_time'); acr=c.get('acr')
            if at is not None and (type(at) is not int or at>c['iat'] or at<=0):
                raise ValueError('invalid_auth_time')
            if acr is not None and not isinstance(acr,str):
                raise ValueError('invalid_acr')
            return Identity(self.issuer,c['sub'],c['sid'],c['exp'],c['jti'],at,acr)
        except (jwt.PyJWTError,ValueError,KeyError,TypeError,AttributeError):
            raise PaymentError('invalid_access_token',401) from None

    def require_mfa(self, identity: Identity):
        now=int(time.time())
        if identity.acr not in self.mfa_acrs or identity.auth_time is None or not 0<=now-identity.auth_time<=MAX_MFA_AGE or identity.expires<=now:
            raise PaymentError('fresh_mfa_required',403)


def _member(conn, identity: Identity) -> dict:
    if identity.expires<=int(time.time()):
        raise PaymentError('invalid_access_token',401)
    row=conn.execute('''SELECT tenant_id,owner_id,role,enabled FROM sp_lock_member(%s,%s)''',(identity.issuer,identity.subject)).fetchone()
    if not row or not row['enabled']:
        raise PaymentError('membership_disabled',403)
    revoked=conn.execute('''SELECT 1 FROM sp_revoked_sessions WHERE issuer=%s AND external_sub=%s AND sid=%s''',
                         (identity.issuer,identity.subject,identity.sid)).fetchone()
    if revoked:
        raise PaymentError('session_revoked',401)
    return row


def resolve_principal(processor, identity: Identity) -> Principal:
    with processor._connect() as conn, conn.transaction():
        row=_member(conn,identity)
    ident=hashlib.sha256(json.dumps([identity.issuer,identity.subject],separators=(',',':')).encode()).hexdigest()
    return Principal('oidc:'+ident,row['tenant_id'],row['owner_id'],frozenset({row['role']}),identity)


def assert_membership(conn, principal: Principal):
    row=_member(conn,principal.identity)
    if (row['tenant_id'],row['owner_id'],frozenset({row['role']})) != (principal.tenant_id,principal.subject,principal.roles):
        raise PaymentError('membership_changed',403)


def revoke_session(conn, issuer: str, subject: str, sid: str):
    """Operator-only DB action. Same member lock serializes with financial writes."""
    conn.execute('SELECT 1 FROM sp_identity_members WHERE issuer=%s AND external_sub=%s FOR UPDATE',(issuer,subject)).fetchone()
    conn.execute('INSERT INTO sp_revoked_sessions(issuer,external_sub,sid) VALUES(%s,%s,%s) ON CONFLICT DO NOTHING',(issuer,subject,sid))


def _approval_payload(conn, processor, p: Principal, operation: str, values: dict) -> tuple[dict,dict]:
    """Canonical values must match PgProcessor's idempotency payload exactly."""
    if operation=='transfer':
        p.require('customer')
        src,dst,amount=_id(values['source']),_id(values['target']),_amount(values['amount'])
        if src==dst:raise PaymentError('same_account',422)
        a,b=processor._account(conn,src),processor._account(conn,dst)
        processor._scope(p,a,'customer')
        if b['tenant_id']!=p.tenant_id or b['kind']!='customer':raise PaymentError('forbidden',403)
        return {'op':operation,'source':src,'target':dst,'amount':amount,'tenant':p.tenant_id},{'source':src,'target':dst,'amount':amount,'currency':'UZS'}
    iid=_id(values['invoice_id'])
    inv=conn.execute('SELECT * FROM sp_invoices WHERE id=%s AND tenant_id=%s',(iid,p.tenant_id)).fetchone()
    if not inv:raise PaymentError('invoice_not_found',404)
    if _amount(values['expected_amount'])!=inv['amount'] or _id(values['expected_merchant'])!=str(inv['merchant_account']):
        raise PaymentError('invoice_terms_mismatch',409)
    if operation=='pay_invoice':
        p.require('customer')
        payer=_id(values['payer'])
        processor._scope(p,processor._account(conn,payer),'customer')
        if inv['state']!='pending':raise PaymentError('invoice_not_pending',409)
        payload={'op':operation,'invoice_id':iid,'payer':payer}
    elif operation in ('refund_invoice','refund_amount'):
        p.require('merchant')
        processor._scope(p,processor._account(conn,str(inv['merchant_account'])),'merchant')
        if inv['state']!='paid':raise PaymentError('invoice_not_paid',409)
        from .refunds import totals,refund_quote
        previous,_=totals(conn,iid)
        if operation=='refund_amount':
            amount=_amount(values['amount'])
            refund_quote(inv['amount'],0,previous,amount)
            return {'op':operation,'invoice_id':iid,'amount':amount},{'invoice_id':iid,'merchant_account':str(inv['merchant_account']),'payer_account':str(inv['payer_account']),'amount':amount,'currency':'UZS'}
        if previous:raise PaymentError('use_amount_refund_for_remaining',409)
        payload={'op':operation,'invoice_id':iid}
    else:raise PaymentError('invalid_operation',422)
    return payload,{'invoice_id':iid,'merchant_account':str(inv['merchant_account']),'amount':inv['amount'],'currency':'UZS'}


def issue_approval(processor, p: Principal, operation: str, values: dict, idem: str) -> dict:
    if p.identity is None or not isinstance(idem,str) or not KEY_RE.fullmatch(idem):
        raise PaymentError('invalid_approval_request',422)
    with processor._connect() as conn, conn.transaction():
        assert_membership(conn,p)
        payload,details=_approval_payload(conn,processor,p,operation,values)
        i=p.identity
        # A transaction-bound approval is short lived, single use, and atomically
        # consumed together with the ledger. Limit outstanding approvals per session.
        conn.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s,0))',(json.dumps([i.issuer,i.subject,i.sid]),))
        n=conn.execute('''SELECT count(*) AS n FROM sp_payment_approvals WHERE issuer=%s AND external_sub=%s AND sid=%s AND consumed_at IS NULL AND expires_at>clock_timestamp()''',(i.issuer,i.subject,i.sid)).fetchone()['n']
        if n>=10:raise PaymentError('approval_limit',429)
        row=conn.execute('''INSERT INTO sp_payment_approvals(issuer,external_sub,sid,tenant_id,owner_id,role,request_digest,idem_key,initiating_jti_hash,expires_at)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,now()+%s*interval '1 second') RETURNING id,expires_at''',
                (i.issuer,i.subject,i.sid,p.tenant_id,p.subject,next(iter(p.roles)),_digest(payload),idem,hashlib.sha256(i.jti.encode()).hexdigest(),CHALLENGE_TTL)).fetchone()
        processor._audit(conn,p,'approval_challenge_created',str(row['id']),payload)
        return {'approval_id':str(row['id']),'expires_at':row['expires_at'].isoformat(),'operation':operation,'details':details,'state':'mfa_required','real_money':False}


def confirm_approval(processor, verifier: OIDCVerifier, p: Principal, approval_id: str) -> dict:
    if p.identity is None:raise PaymentError('user_identity_required',403)
    i=p.identity
    verifier.require_mfa(i)
    with processor._connect() as conn, conn.transaction():
        assert_membership(conn,p)
        # An existing MFA bearer alone cannot approve a newly created challenge:
        # the IdP must issue a different token following an authentication event
        # strictly after the challenge was created (second-resolution claim).
        ttl=min(APPROVAL_TTL,i.expires-int(time.time()),MAX_MFA_AGE-(int(time.time())-i.auth_time))
        if ttl<=0:raise PaymentError('fresh_mfa_required',403)
        row=conn.execute('''UPDATE sp_payment_approvals SET confirmed_at=now(),expires_at=least(expires_at,now()+%s*interval '1 second')
                WHERE id=%s AND issuer=%s AND external_sub=%s AND sid=%s AND tenant_id=%s AND owner_id=%s AND role=%s
                AND confirmed_at IS NULL AND consumed_at IS NULL AND expires_at>clock_timestamp()
                AND initiating_jti_hash<>%s AND floor(extract(epoch FROM created_at))<%s RETURNING id,expires_at''',
                (ttl,_id(approval_id),i.issuer,i.subject,i.sid,p.tenant_id,p.subject,next(iter(p.roles)),hashlib.sha256(i.jti.encode()).hexdigest(),i.auth_time)).fetchone()
        if not row:raise PaymentError('challenge_invalid_or_fresh_mfa_required',403)
        processor._audit(conn,p,'approval_confirmed',str(row['id']),{'approval_id':str(row['id'])})
        return {'approval_id':str(row['id']),'expires_at':row['expires_at'].isoformat(),'state':'confirmed','real_money':False}


def consume_approval(conn,p: Principal,idem: str,fingerprint: str):
    if p.approval_id is None:raise PaymentError('approval_required',403)
    i=p.identity
    row=conn.execute('''UPDATE sp_payment_approvals SET consumed_at=now()
        WHERE id=%s AND issuer=%s AND external_sub=%s AND sid=%s AND tenant_id=%s AND owner_id=%s AND role=%s
        AND idem_key=%s AND request_digest=%s AND confirmed_at IS NOT NULL AND consumed_at IS NULL AND expires_at>clock_timestamp() RETURNING id''',
        (_id(p.approval_id),i.issuer,i.subject,i.sid,p.tenant_id,p.subject,next(iter(p.roles)),idem,fingerprint)).fetchone()
    if not row:raise PaymentError('approval_invalid_or_expired',403)
