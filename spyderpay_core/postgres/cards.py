"""Card possession protocol for pre-license staging. No hardware attestation or payment authority.

P-256 public keys are separate from blockchain private keys. The server builds the
exact signed transcript, scoped to a session, invoice and challenge. A card proof
is not an approval, bearer token, settlement instruction or substitute for MFA.
"""
import hashlib
import json
import re
import secrets
import uuid
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from spyderpay_core.ledger import PaymentError
from .identity import assert_membership
from .store import _id, _amount, _jsonable

TTL=90
KEY=re.compile(r'04[0-9a-f]{128}')
SIG=re.compile(r'[0-9a-f]{16,144}')
DOMAIN='spyderpay-card-proof-v1-prelicense'


def public_key(value):
    if not isinstance(value,str) or not KEY.fullmatch(value):
        raise PaymentError('invalid_card_public_key',422)
    try:return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(),bytes.fromhex(value))
    except ValueError:raise PaymentError('invalid_card_public_key',422) from None


def transcript(row):
    # Canonical JSON array; no user-supplied text is signed verbatim. Session digest
    # avoids sending external identity provider identifiers to an NFC device.
    session=hashlib.sha256(json.dumps([row['issuer'],row['external_sub'],row['sid']],separators=(',',':'),ensure_ascii=True).encode()).hexdigest()
    return json.dumps([DOMAIN,str(row['id']),row['tenant_id'],row['owner_id'],session,
        row['purpose'],str(row['card_id']),row['public_key'],row['nonce'],
        str(row['invoice_id']) if row['invoice_id'] else None,
        str(row['merchant_account']) if row['merchant_account'] else None,
        _amount(row['amount']) if row['amount'] is not None else None,'UZS',
        int(row['expires_at'].timestamp())],separators=(',',':'),ensure_ascii=True).encode('ascii')


def verify_proof(row,signature):
    if not isinstance(signature,str) or not SIG.fullmatch(signature) or len(signature)%2:
        raise PaymentError('invalid_card_signature',422)
    try:public_key(row['public_key']).verify(bytes.fromhex(signature),transcript(row),ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature,ValueError):raise PaymentError('invalid_card_signature',422) from None


def require_user(p):
    if p.identity is None or p.roles!=frozenset({'customer'}):raise PaymentError('customer_identity_required',403)


class Cards:
    def __init__(self,processor,verifier):self.processor=processor;self.verifier=verifier

    def _lock_owner(self,conn,p):
        assert_membership(conn,p)
        # Shared membership lock alone permits concurrency. Serialize card
        # limits and challenge issuance by a separate transaction lock.
        scope=json.dumps(['spyderpay-card-owner-v1',p.tenant_id,p.subject],separators=(',',':'))
        conn.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s,0))',(scope,))

    def _card(self,conn,p,cid):
        card=conn.execute('SELECT * FROM sp_cards WHERE id=%s AND tenant_id=%s AND owner_id=%s FOR UPDATE',(_id(cid),p.tenant_id,p.subject)).fetchone()
        if not card or card['revoked_at'] is not None:raise PaymentError('card_not_available',404)
        return card

    def _invoice(self,conn,p,iid):
        row=conn.execute("""SELECT i.id,i.amount,i.merchant_account FROM sp_invoices i JOIN sp_accounts a ON a.id=i.merchant_account
            WHERE i.id=%s AND i.tenant_id=%s AND i.state='pending' AND i.expires_at>clock_timestamp() AND a.tenant_id=i.tenant_id AND a.status='active' AND a.kind='merchant'""",(_id(iid),p.tenant_id)).fetchone()
        if not row:raise PaymentError('pos_invoice_unavailable',409)
        return row

    def _challenge(self,conn,p,purpose,cid,key,inv=None):
        # Owner transaction lock serializes issuance, including parallel sessions.
        count=conn.execute("SELECT count(*) AS n FROM sp_card_challenges WHERE tenant_id=%s AND owner_id=%s AND created_at>now()-interval '1 minute'",(p.tenant_id,p.subject)).fetchone()['n']
        if count>=10:raise PaymentError('card_challenge_rate_limit',429)
        i=p.identity
        row=conn.execute('''INSERT INTO sp_card_challenges(id,tenant_id,owner_id,issuer,external_sub,sid,card_id,purpose,public_key,nonce,invoice_id,merchant_account,amount,expires_at)
         VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,now()+%s*interval '1 second') RETURNING *''',
         (str(uuid.uuid4()),p.tenant_id,p.subject,i.issuer,i.subject,i.sid,cid,purpose,key,secrets.token_hex(32),inv['id'] if inv else None,inv['merchant_account'] if inv else None,inv['amount'] if inv else None,TTL)).fetchone()
        return {'challenge_id':str(row['id']),'card_id':str(row['card_id']),'message_hex':transcript(row).hex(),'expires_at':row['expires_at'].isoformat(),'algorithm':'ECDSA-P256-SHA256-DER','sandbox':True,'payment_authority':False}

    def begin_enrollment(self,p,key):
        require_user(p);self.verifier.require_mfa(p.identity);public_key(key)
        with self.processor._connect() as conn,conn.transaction():
            self._lock_owner(conn,p)
            if conn.execute('SELECT 1 FROM sp_cards WHERE public_key=%s',(key,)).fetchone():raise PaymentError('card_key_unavailable',409)
            n=conn.execute('SELECT count(*) AS n FROM sp_cards WHERE tenant_id=%s AND owner_id=%s AND revoked_at IS NULL',(p.tenant_id,p.subject)).fetchone()['n']
            if n>=5:raise PaymentError('card_limit',409)
            return self._challenge(conn,p,'enroll',str(uuid.uuid4()),key)

    def begin_preview(self,p,cid,iid):
        require_user(p)
        with self.processor._connect() as conn,conn.transaction():
            self._lock_owner(conn,p);card=self._card(conn,p,cid);inv=self._invoice(conn,p,iid)
            return self._challenge(conn,p,'invoice_preview',str(card['id']),card['public_key'],inv)

    def finish(self,p,challenge,signature):
        require_user(p)
        with self.processor._connect() as conn,conn.transaction():
            self._lock_owner(conn,p);i=p.identity
            row=conn.execute('''SELECT * FROM sp_card_challenges WHERE id=%s AND tenant_id=%s AND owner_id=%s AND issuer=%s AND external_sub=%s AND sid=%s
              AND consumed_at IS NULL AND expires_at>clock_timestamp() FOR UPDATE''',(_id(challenge),p.tenant_id,p.subject,i.issuer,i.subject,i.sid)).fetchone()
            if not row:raise PaymentError('card_challenge_unavailable',409)
            verify_proof(row,signature)
            if row['purpose']=='enroll':
                self.verifier.require_mfa(i)
                n=conn.execute('SELECT count(*) AS n FROM sp_cards WHERE tenant_id=%s AND owner_id=%s AND revoked_at IS NULL',(p.tenant_id,p.subject)).fetchone()['n']
                if n>=5:raise PaymentError('card_limit',409)
                inserted=conn.execute('INSERT INTO sp_cards(id,tenant_id,owner_id,public_key) VALUES(%s,%s,%s,%s) ON CONFLICT DO NOTHING RETURNING id',(row['card_id'],p.tenant_id,p.subject,row['public_key'])).fetchone()
                if not inserted:raise PaymentError('card_key_unavailable',409)
                result={'card_id':str(row['card_id']),'state':'enrolled','hardware_attested':False}
            else:
                card=self._card(conn,p,row['card_id']);inv=self._invoice(conn,p,row['invoice_id'])
                if card['public_key']!=row['public_key'] or inv['merchant_account']!=row['merchant_account'] or inv['amount']!=row['amount']:raise PaymentError('card_invoice_mismatch',409)
                result={'card_id':str(card['id']),'state':'possession_verified','invoice_id':str(inv['id']),'merchant_account':str(inv['merchant_account']),'amount':inv['amount'],'currency':'UZS','requires_payment_approval':True}
            consumed=conn.execute('UPDATE sp_card_challenges SET consumed_at=clock_timestamp() WHERE id=%s AND consumed_at IS NULL AND expires_at>clock_timestamp() RETURNING id',(row['id'],)).fetchone()
            if not consumed:raise PaymentError('card_challenge_unavailable',409)
            self.processor._audit(conn,p,'card_'+row['purpose'],str(row['card_id']),{'challenge':str(row['id'])})
            return {**result,'sandbox':True,'payment_authority':False}

    def revoke(self,p,cid):
        require_user(p);self.verifier.require_mfa(p.identity)
        with self.processor._connect() as conn,conn.transaction():
            self._lock_owner(conn,p)
            row=conn.execute('SELECT id,revoked_at FROM sp_cards WHERE id=%s AND tenant_id=%s AND owner_id=%s FOR UPDATE',(_id(cid),p.tenant_id,p.subject)).fetchone()
            if not row:raise PaymentError('card_not_available',404)
            if row['revoked_at'] is None:
                conn.execute('UPDATE sp_cards SET revoked_at=clock_timestamp() WHERE id=%s',(row['id'],))
                self.processor._audit(conn,p,'card_revoked',str(row['id']),{})
            return {'card_id':str(row['id']),'state':'revoked','sandbox':True}

    def list(self,p):
        require_user(p)
        with self.processor._connect() as conn,conn.transaction():
            self._lock_owner(conn,p)
            rows=conn.execute('SELECT id,created_at,revoked_at FROM sp_cards WHERE tenant_id=%s AND owner_id=%s ORDER BY created_at DESC,id LIMIT 100',(p.tenant_id,p.subject)).fetchall()
            return {'cards':[_jsonable(r) for r in rows],'sandbox':True,'hardware_attested':False}
