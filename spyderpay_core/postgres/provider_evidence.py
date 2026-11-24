"""Provider-attested screening results; no automatic KYC approval or PII storage.

The partner gateway signs this narrow contract after authenticating the actual
provider. Verification keys are configured out of band, never fetched from JWT.
Manual review remains a separate maker/checker decision.
"""
import base64
import hashlib
import json
import re
import time
import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from spyderpay_core.ledger import PaymentError
from .store import _id, _identity

IDENT = re.compile(r'[A-Za-z0-9_.:-]{3,96}')
AUDIENCE = 'spyderpay-compliance-prelicense'
MAX_AGE = 900
FIELDS = {'iss','aud','iat','exp','jti','tenant','account','kyc','screening','tier','evidence_digest'}

class ProviderEvidence:
    def __init__(self, config):
        obj = json.loads(config)
        if not isinstance(obj, dict) or set(obj) != {'keys'} or not isinstance(obj['keys'], list) or not 1 <= len(obj['keys']) <= 32:
            raise ValueError('invalid_compliance_provider_config')
        self.keys = {}
        for item in obj['keys']:
            if not isinstance(item, dict) or set(item) != {'issuer','kid','public_b64','not_before','not_after'}:
                raise ValueError('invalid_compliance_provider_key')
            issuer, kid = item['issuer'], item['kid']
            if not all(isinstance(x,str) and IDENT.fullmatch(x) for x in (issuer,kid)) or kid in self.keys or type(item['not_before']) is not int or type(item['not_after']) is not int or not 0 < item['not_after']-item['not_before'] <= 366*86400:
                raise ValueError('invalid_compliance_provider_key_policy')
            key = Ed25519PublicKey.from_public_bytes(base64.b64decode(item['public_b64'],validate=True))
            self.keys[kid] = (issuer,key,item['not_before'],item['not_after'])

    def verify(self, token, *, tenant, account, kyc, screening, tier, now=None):
        try:
            if not isinstance(token,str) or len(token)>4096 or not re.fullmatch(r'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',token):
                raise ValueError()
            h = jwt.get_unverified_header(token)
            if set(h) != {'typ','alg','kid'} or h['alg'] != 'EdDSA' or h['typ'] != 'spyderpay-screening+jwt':
                raise ValueError()
            issuer,key,start,end = self.keys[h['kid']]
            # Time checked explicitly, with no clock leeway and an injectable test clock.
            c = jwt.decode(token,key,algorithms=['EdDSA'],issuer=issuer,audience=AUDIENCE,options={'require':sorted(FIELDS),'strict_aud':True,'verify_exp':False,'verify_iat':False})
            now = int(time.time()) if now is None else now
            if set(c)!=FIELDS or type(c['iat']) is not int or type(c['exp']) is not int or not start<=c['iat']<=now<c['exp']<=end or not 0<c['exp']-c['iat']<=MAX_AGE:
                raise ValueError()
            if not isinstance(c['jti'],str) or not IDENT.fullmatch(c['jti']) or not isinstance(c['evidence_digest'],str) or not re.fullmatch(r'[0-9a-f]{64}',c['evidence_digest']):
                raise ValueError()
            if (c['tenant'],c['account'],c['kyc'],c['screening'],c['tier'])!=(_identity(tenant),_id(account),kyc,screening,tier) or kyc not in ('verified','rejected','pending') or screening not in ('clear','hit','pending') or tier not in ('standard','enhanced'):
                raise ValueError()
            # A provider event cannot be reused by rotating keys or modifying claims.
            return 'provider:'+hashlib.sha256(json.dumps([issuer,c['jti']],separators=(',',':')).encode()).hexdigest()
        except (jwt.PyJWTError, ValueError, TypeError, KeyError, PaymentError):
            raise PaymentError('invalid_provider_evidence',403) from None
