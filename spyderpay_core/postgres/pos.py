"""Signed, short-lived POS invoice capability. Not an NFC/card authorization.

The payload can be encoded as a QR by a merchant app. Verification is read-only;
actual payment still requires the existing OIDC step-up and ledger transaction.
Local signing is sandbox-only. An external Vault Transit signer is optional.
"""
from dataclasses import dataclass
import base64
import json
import time
import re
import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey,Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from spyderpay_core.ledger import PaymentError
from .store import _id,_amount,_identity,_jsonable
from .identity import assert_membership

ISSUER='spyderpay-pos-sandbox'; AUDIENCE='spyderpay-wallet-sandbox'; MAX_TTL=90
KID=re.compile(r'^[A-Za-z0-9_-]{3,64}$')


def raw_key(value):
    if not isinstance(value,str):raise ValueError('invalid_pos_key')
    try: key=base64.b64decode(value,validate=True)
    except (ValueError,TypeError):raise ValueError('invalid_pos_key') from None
    if len(key)!=32:raise ValueError('invalid_pos_key')
    return key


@dataclass(frozen=True)
class VerificationKey:
    public: Ed25519PublicKey
    not_before: int
    not_after: int


class PosTokens:
    def __init__(self,config):
        c=json.loads(config)
        if set(c) not in ({'active_kid','private_b64','keys'},{'active_kid','remote_signer','keys'}) or not isinstance(c['keys'],list) or not 1<=len(c['keys'])<=8:raise ValueError('invalid_pos_config')
        self.active=c['active_kid'];self.keys={}
        for k in c['keys']:
            if set(k)!={'kid','public_b64','not_before','not_after'} or not isinstance(k['kid'],str) or not KID.fullmatch(k['kid']) or k['kid'] in self.keys or type(k['not_before']) is not int or type(k['not_after']) is not int or not 0<k['not_after']-k['not_before']<=90*86400:raise ValueError('invalid_pos_key_policy')
            self.keys[k['kid']]=VerificationKey(Ed25519PublicKey.from_public_bytes(raw_key(k['public_b64'])),k['not_before'],k['not_after'])
        if self.active not in self.keys:raise ValueError('invalid_pos_active_key')
        self.private=None
        if 'remote_signer' in c:
            from .remote_signer import VaultTransitSigner
            self.signer=VaultTransitSigner(c['remote_signer'],self.keys[self.active].public)
        else:
            self.private=Ed25519PrivateKey.from_private_bytes(raw_key(c['private_b64']))
            pub=lambda x:x.public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
            if pub(self.private.public_key())!=pub(self.keys[self.active].public):raise ValueError('pos_key_pair_mismatch')
            self.signer=self.private
    def issue(self,tenant,invoice):
        now=int(time.time());key=self.keys[self.active]
        exp=min(now+MAX_TTL,int(invoice['expires_at'].timestamp()),key.not_after)
        if not key.not_before<=now<exp or invoice['state']!='pending':raise PaymentError('pos_invoice_or_key_expired',409)
        body={'iss':ISSUER,'aud':AUDIENCE,'iat':now,'exp':exp,'tenant':_identity(tenant),'invoice':_id(invoice['id']),'merchant':_id(invoice['merchant_account']),'amount':_amount(invoice['amount']),'currency':'UZS','purpose':'invoice_preview'}
        # Build a standard compact JWS so local and remote keys use identical bytes.
        def part(value):return base64.urlsafe_b64encode(json.dumps(value,separators=(',',':'),ensure_ascii=True).encode('ascii')).rstrip(b'=')
        data=part({'alg':'EdDSA','kid':self.active,'typ':'spyderpay-pos+jwt'})+b'.'+part(body)
        try:
            signature=self.signer.sign(data)
            self.keys[self.active].public.verify(signature,data)
        except Exception:raise PaymentError('pos_signer_unavailable',503) from None
        return (data+b'.'+base64.urlsafe_b64encode(signature).rstrip(b'=')).decode('ascii')
    def verify(self,token,tenant):
        if not isinstance(token,str) or len(token)>2048:raise PaymentError('invalid_pos_token',422)
        try:
            header=jwt.get_unverified_header(token)
            if set(header)!={'alg','kid','typ'} or header['alg']!='EdDSA' or header['typ']!='spyderpay-pos+jwt':raise ValueError()
            key=self.keys[header['kid']];now=int(time.time())
            if not key.not_before<=now<key.not_after:raise ValueError()
            required=['iss','aud','iat','exp','tenant','invoice','merchant','amount','currency','purpose']
            d=jwt.decode(token,key.public,algorithms=['EdDSA'],issuer=ISSUER,audience=AUDIENCE,options={'require':required,'strict_aud':True})
            if set(d)!=set(required) or d['tenant']!=tenant or d['currency']!='UZS' or d['purpose']!='invoice_preview' or type(d['iat']) is not int or type(d['exp']) is not int or not key.not_before<=d['iat']<=now<d['exp']<=key.not_after or d['exp']-d['iat']>MAX_TTL:raise ValueError()
            _id(d['invoice']);_id(d['merchant']);_amount(d['amount'])
            return d
        except (jwt.PyJWTError,KeyError,ValueError,TypeError,PaymentError):raise PaymentError('invalid_pos_token',422) from None


def issue_for_merchant(processor,p,tokens,iid):
    if p.identity is None:raise PaymentError('user_identity_required',403)
    p.require('merchant')
    with processor._connect() as conn,conn.transaction():
        assert_membership(conn,p)
        inv=conn.execute("SELECT * FROM sp_invoices WHERE id=%s AND tenant_id=%s AND state='pending' AND expires_at>now()",(_id(iid),p.tenant_id)).fetchone()
        if not inv:raise PaymentError('invoice_not_found',404)
        merchant=processor._account(conn,str(inv['merchant_account']));processor._scope(p,merchant,'merchant')
        if merchant['status']!='active':raise PaymentError('merchant_not_active',409)
    # No network call while holding the DB transaction. Preview rechecks live state.
    return {'token':tokens.issue(p.tenant_id,inv),'format':'spyderpay-pos+jwt','sandbox':True}


def preview_for_customer(processor,p,tokens,token):
    if p.identity is None:raise PaymentError('user_identity_required',403)
    p.require('customer');d=tokens.verify(token,p.tenant_id)
    with processor._connect() as conn,conn.transaction():
        assert_membership(conn,p)
        row=conn.execute("SELECT i.id,i.merchant_account,i.amount,i.expires_at FROM sp_invoices i JOIN sp_accounts a ON a.id=i.merchant_account WHERE i.id=%s AND i.tenant_id=%s AND i.state='pending' AND i.expires_at>now() AND a.status='active'",(d['invoice'],p.tenant_id)).fetchone()
        if not row or str(row['merchant_account'])!=d['merchant'] or row['amount']!=d['amount']:raise PaymentError('pos_invoice_unavailable',409)
        return {**_jsonable(row),'currency':'UZS','sandbox':True,'requires_payment_approval':True}
