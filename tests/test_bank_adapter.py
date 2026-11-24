import json
import secrets
import time
import unittest
from spyderpay_core.postgres.bank_adapter import ExampleHmacCallbackVerifier
from spyderpay_core.ledger import PaymentError

class BankBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.secret=secrets.token_bytes(32)
        self.verifier=ExampleHmacCallbackVerifier(self.secret,'bank-simulator')
        self.body=json.dumps({'external_id':'E-123','amount_uzs':1000,'status':'confirmed','receiver_reference':'acc-123'}).encode()
        self.timestamp=str(int(time.time()))
        self.headers={'X-Example-Bank-Timestamp':self.timestamp,'X-Example-Bank-Signature':self.verifier.signature(self.secret,self.body,self.timestamp)}

    def test_good_evidence_only(self):
        e=self.verifier.verify_callback(self.body,self.headers)
        self.assertEqual(e.amount_uzs,1000)
        self.assertEqual(e.provider,'bank-simulator')

    def test_tamper_amount(self):
        with self.assertRaises(PaymentError):
            self.verifier.verify_callback(self.body.replace(b'1000',b'9000'),self.headers)

    def test_reject_old_timestamp(self):
        with self.assertRaises(PaymentError):
            self.verifier.verify_callback(self.body,self.headers,now=int(self.timestamp)+121)

    def test_reject_boolean_amount(self):
        bad=self.body.replace(b'1000',b'true')
        h={**self.headers,'X-Example-Bank-Signature':self.verifier.signature(self.secret,bad,self.timestamp)}
        with self.assertRaises(PaymentError) as e:self.verifier.verify_callback(bad,h)
        self.assertEqual(e.exception.status,422)

    def test_reject_unexpected_fields(self):
        body=self.body[:-1]+b',"credit_me":true}'
        h={**self.headers,'X-Example-Bank-Signature':self.verifier.signature(self.secret,body,self.timestamp)}
        with self.assertRaises(PaymentError):self.verifier.verify_callback(body,h)

    def test_reject_invalid_status(self):
        body=self.body.replace(b'confirmed',b'auto_credit')
        h={**self.headers,'X-Example-Bank-Signature':self.verifier.signature(self.secret,body,self.timestamp)}
        with self.assertRaises(PaymentError):self.verifier.verify_callback(body,h)

    def test_reject_weak_signing_key(self):
        with self.assertRaises(ValueError):ExampleHmacCallbackVerifier(b'short','bank-simulator')

if __name__=='__main__':unittest.main()
