import base64
import json
import os
import secrets
import time
import unittest
from spyderpay_core.ledger import PaymentError
from spyderpay_core.postgres.auth import load_keys,sign,verify,canonical

class Nonces:
    def __init__(self):self.used=set()
    def claim(self,k,n):
        key=(k,n)
        if key in self.used:return False
        self.used.add(key);return True

class AuthTests(unittest.TestCase):
    def setUp(self):
        self.secret=secrets.token_bytes(32)
        self.cfg=json.dumps([{'key_id':'svc-test','secret_b64':base64.b64encode(self.secret).decode(),
                              'tenant_id':'tenant-demo','subject':'user-alice', 'roles':['customer']}])
        self.keys=load_keys(self.cfg)
        self.now=int(time.time())
        self.nonces=Nonces()
        self.body=b'{"amount":123}'
        self.path='/v2/transfers'

    def hdr(self,body=None,path=None,timestamp=None,nonce=None):
        nonce=nonce or secrets.token_urlsafe(24)
        timestamp=str(timestamp or self.now)
        body=self.body if body is None else body
        path=self.path if path is None else path
        return {'X-Spyder-Key-Id':'svc-test','X-Spyder-Timestamp':timestamp,
                'X-Spyder-Nonce':nonce,'X-Spyder-Signature':sign(self.secret,'POST',path,body,timestamp,nonce)}

    def test_valid_signature(self):
        p=verify('POST',self.path,self.body,self.hdr(),self.keys,self.nonces,self.now)
        self.assertEqual(p.subject,'user-alice')
        self.assertIn('customer',p.roles)

    def test_replay_same_nonce(self):
        h=self.hdr()
        verify('POST',self.path,self.body,h,self.keys,self.nonces,self.now)
        with self.assertRaises(PaymentError) as e:
            verify('POST',self.path,self.body,h,self.keys,self.nonces,self.now)
        self.assertEqual(e.exception.code,'replayed_request')

    def test_tampered_payload(self):
        with self.assertRaises(PaymentError):
            verify('POST',self.path,b'{"amount":999}',self.hdr(),self.keys,self.nonces,self.now)

    def test_tampered_path(self):
        with self.assertRaises(PaymentError):
            verify('POST','/v2/invoices',self.body,self.hdr(),self.keys,self.nonces,self.now)

    def test_tampered_method(self):
        with self.assertRaises(PaymentError):
            verify('GET',self.path,self.body,self.hdr(),self.keys,self.nonces,self.now)

    def test_expired_and_future_signature(self):
        for shift in (-121,121):
            with self.subTest(shift=shift),self.assertRaises(PaymentError):
                verify('POST',self.path,self.body,self.hdr(timestamp=self.now+shift),self.keys,self.nonces,self.now)

    def test_reject_weak_secrets(self):
        c=json.loads(self.cfg)
        c[0]['secret_b64']=base64.b64encode(b'short').decode()
        with self.assertRaises(ValueError):load_keys(json.dumps(c))

    def test_reject_incorrect_key(self):
        h=self.hdr();h['X-Spyder-Key-Id']='unknown-key'
        with self.assertRaises(PaymentError):verify('POST',self.path,self.body,h,self.keys,self.nonces,self.now)

    def test_reject_malformed_nonce(self):
        h=self.hdr();h['X-Spyder-Nonce']='x'
        with self.assertRaises(PaymentError):verify('POST',self.path,self.body,h,self.keys,self.nonces,self.now)

    def test_reject_duplicate_key_id(self):
        c=json.loads(self.cfg)
        with self.assertRaises(ValueError):load_keys(json.dumps(c+c))

    def test_reject_incorrect_scope(self):
        p=verify('POST',self.path,self.body,self.hdr(),self.keys,self.nonces,self.now)
        with self.assertRaises(PaymentError) as e:p.require('merchant')
        self.assertEqual(e.exception.status,403)

    def test_signature_deterministic(self):
        ts=str(self.now);nonce='A'*24
        sig=sign(self.secret,'POST',self.path,self.body,ts,nonce)
        self.assertEqual(sig,sign(self.secret,'POST',self.path,self.body,ts,nonce))
        self.assertEqual(len(sig),64)

    def test_query_is_signed(self):
        h=self.hdr(path=self.path+'?a=1')
        with self.assertRaises(PaymentError):
            verify('POST',self.path+'?a=2',self.body,h,self.keys,self.nonces,self.now)

if __name__=='__main__':unittest.main()
