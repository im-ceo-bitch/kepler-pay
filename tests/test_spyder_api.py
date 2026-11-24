"""API boundary tests without real PostgreSQL. Real PostgreSQL tests live in tests/postgres/."""
import base64
import json
import secrets
import time
import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient
from spyderpay_core.postgres.auth import sign
from spyderpay_core.postgres.api import create_app
from spyderpay_core.ledger import PaymentError

class FakeProcessor:
    def __init__(self):self.claimed=set()
    def _connect(self):return None
    def transfer(self,p,source,target,amount,idem):
        p.require('customer')
        if amount<=0:raise PaymentError('invalid_amount')
        return {'amount':amount,'currency':'UZS','journal_id':'mock-only'}

class FakeNonceStore:
    def __init__(self,p):self.p=p
    def claim(self,k,n):
        if (k,n) in self.p.claimed:return False
        self.p.claimed.add((k,n));return True

class APITests(unittest.TestCase):
    def setUp(self):
        self.secret=secrets.token_bytes(32)
        cfg=json.dumps([{'key_id':'svc-test','secret_b64':base64.b64encode(self.secret).decode(),
            'tenant_id':'tenant-demo','subject':'user-alice','roles':['customer']}])
        self.p=FakeProcessor()
        self.patch=patch('spyderpay_core.postgres.api.PostgresNonceStore',FakeNonceStore)
        self.patch.start()
        self.env_patch=patch.dict('os.environ',{'SPYDERPAY_ENV':'test'})
        self.env_patch.start()
        self.client=TestClient(create_app(self.p,cfg))

    def tearDown(self):
        self.patch.stop()
        self.env_patch.stop()

    def request(self,path='/v2/transfers',body=None,method='POST',tamper=False,idem='a-test-idempotency-key'):
        if body is None:body={'source':'account-1','target':'account-2','amount':10}
        raw=json.dumps(body,separators=(',',':')).encode()
        ts=str(int(time.time()));nonce=secrets.token_urlsafe(24)
        h={'X-Spyder-Key-Id':'svc-test','X-Spyder-Timestamp':ts,'X-Spyder-Nonce':nonce,
           'X-Spyder-Signature':sign(self.secret,method,path,raw,ts,nonce),'Idempotency-Key':idem,
           'Content-Type':'application/json'}
        if tamper:raw=raw+b' '
        return self.client.request(method,path,content=raw,headers=h)

    def test_unauthed_no_access(self):
        r=self.client.post('/v2/transfers',json={'amount':20})
        self.assertEqual(r.status_code,401)

    def test_health_not_sensitive(self):
        r=self.client.get('/health/live')
        self.assertEqual(r.status_code,200)
        self.assertFalse(r.json()['real_money'])

    def test_valid_signed_transfer(self):
        r=self.request()
        self.assertEqual(r.status_code,200,r.text)
        self.assertEqual(r.json()['amount'],10)
        self.assertEqual(r.headers['cache-control'],'no-store')

    def test_body_tampering(self):
        r=self.request(tamper=True)
        self.assertEqual(r.status_code,401)

    def test_schema_rejects_float_amount(self):
        r=self.request(body={'source':'a','target':'b','amount':1.5})
        self.assertEqual(r.status_code,422)

    def test_schema_rejects_extra_fields(self):
        r=self.request(body={'source':'a','target':'b','amount':15,'admin':True})
        self.assertEqual(r.status_code,422)

    def test_missing_idempotency_key(self):
        r=self.request(idem='')
        self.assertEqual(r.status_code,422)

    def test_disabled_issuance(self):
        with patch.dict('os.environ',{'SPYDERPAY_ALLOW_SANDBOX_CREDIT':'no'}):
            r=self.request('/v2/sandbox/credits',{'account_id':'a','amount':100})
        self.assertEqual(r.status_code,403)

    def test_excessive_body(self):
        r=self.request(body={'a':'x'*17000})
        self.assertEqual(r.status_code,413)

if __name__=='__main__':unittest.main()
