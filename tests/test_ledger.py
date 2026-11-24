import tempfile
import unittest
from pathlib import Path
from spyderpay_core import Ledger, PaymentError


class TestLedger(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.l=Ledger(Path(self.tmp.name)/'ledger.db')
        self.a=self.l.create_account('Alice','customer','create-alice')['id']
        self.b=self.l.create_account('Bob','customer','create-bob00')['id']
        self.shop=self.l.create_account('Coffee Point','merchant','create-shop00')['id']

    def tearDown(self):
        self.l.db.close()
        self.tmp.cleanup()

    def seed(self,amount=100_000):
        self.l.sandbox_credit(self.a,amount,'seed-alice-0001')

    def test_credit_zero_sum(self):
        self.seed()
        self.assertEqual(self.l.account(self.a)['balance'],100_000)
        self.assertEqual(self.l.account('sandbox:clearing')['balance'],-100_000)
        self.assertTrue(self.l.audit_invariants()['ok'])

    def test_exactly_once_credit(self):
        self.seed()
        self.l.sandbox_credit(self.a,100_000,'seed-alice-0001')
        self.assertEqual(self.l.account(self.a)['balance'],100_000)

    def test_idempotency_conflict(self):
        self.seed()
        with self.assertRaises(PaymentError) as cm:
            self.l.sandbox_credit(self.a,100_001,'seed-alice-0001')
        self.assertEqual(cm.exception.status,409)

    def test_transfer(self):
        self.seed()
        t=self.l.transfer(self.a,self.b,30_000,'transfer-00001')
        self.assertEqual(self.l.transfer(self.a,self.b,30_000,'transfer-00001'),t)
        self.assertEqual(self.l.account(self.a)['balance'],70_000)
        self.assertEqual(self.l.account(self.b)['balance'],30_000)
        self.assertTrue(self.l.audit_invariants()['ok'])

    def test_insufficient_funds_rollback(self):
        with self.assertRaises(PaymentError):
            self.l.transfer(self.a,self.b,1,'transfer-failed')
        self.assertEqual(self.l.account(self.a)['balance'],0)
        self.assertEqual(self.l.account(self.b)['balance'],0)
        self.assertTrue(self.l.audit_invariants()['ok'])

    def test_no_negative_or_fractional_amounts(self):
        for amount in (0,-1,2.5,'15',True,None):
            with self.assertRaises(PaymentError):
                self.l.sandbox_credit(self.a,amount,'bad-amount-0001')

    def test_same_account(self):
        self.seed()
        with self.assertRaises(PaymentError):
            self.l.transfer(self.a,self.a,1,'bad-same-00001')
        self.assertTrue(self.l.audit_invariants()['ok'])

    def test_invoice_payment_refund(self):
        self.seed()
        invoice=self.l.create_invoice(self.shop,45_000,'create-inv-001')
        paid=self.l.pay_invoice(invoice['id'],self.a,'pay-invoice-001')
        self.assertEqual(paid['state'],'paid')
        self.assertEqual(self.l.account(self.a)['balance'],55_000)
        self.assertEqual(self.l.account(self.shop)['balance'],45_000)
        refunded=self.l.refund_invoice(invoice['id'],'refund-invoice-001')
        self.assertEqual(refunded['state'],'refunded')
        self.assertEqual(self.l.account(self.a)['balance'],100_000)
        self.assertEqual(self.l.account(self.shop)['balance'],0)
        self.assertTrue(self.l.audit_invariants()['ok'])

    def test_cannot_double_pay_or_refund(self):
        self.seed()
        iid=self.l.create_invoice(self.shop,500,'create-inv-002')['id']
        self.l.pay_invoice(iid,self.a,'pay-invoice-002')
        with self.assertRaises(PaymentError):
            self.l.pay_invoice(iid,self.a,'pay-invoice-003')
        self.l.refund_invoice(iid,'refund-invoice-002')
        with self.assertRaises(PaymentError):
            self.l.refund_invoice(iid,'refund-invoice-003')
        self.assertTrue(self.l.audit_invariants()['ok'])

    def test_refund_requires_merchant_balance(self):
        self.seed()
        iid=self.l.create_invoice(self.shop,400,'create-inv-004')['id']
        self.l.pay_invoice(iid,self.a,'pay-invoice-004')
        # Production would need receivable/account freeze/chargeback support.
        with self.l._tx():
            self.l._journal('test_spend',self.shop,self.b,400)
        with self.assertRaises(PaymentError):
            self.l.refund_invoice(iid,'refund-invoice-004')
        self.assertEqual(self.l.invoice(iid)['state'],'paid')
        self.assertTrue(self.l.audit_invariants()['ok'])

    def test_persistence(self):
        self.seed()
        path=self.l.db.execute('PRAGMA database_list').fetchone()['file']
        new=Ledger(path)
        try:
            self.assertEqual(new.account(self.a)['balance'],100_000)
            self.assertTrue(new.audit_invariants()['ok'])
        finally:
            new.db.close()

    def test_money_not_mixed_with_spy(self):
        with self.assertRaises(PaymentError):
            self.l.create_account('Crypto','SPY','crypto-acc-001')

if __name__=='__main__':
    unittest.main()
