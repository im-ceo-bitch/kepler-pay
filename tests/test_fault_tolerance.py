"""Deterministic fault and invariant stress tests for SQLite baseline simulator.
PostgreSQL transactional equivalent is tested in tests/postgres/.
"""
import random
import tempfile
import unittest
from pathlib import Path
from spyderpay_core.ledger import Ledger,PaymentError

class FaultToleranceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.l=Ledger(Path(self.temp.name)/'faults.sqlite3')
        self.accounts=[self.l.create_account('Customer-'+str(i),'customer',f'create-customer-{i:03d}')['id'] for i in range(4)]
        for i,aid in enumerate(self.accounts):
            self.l.sandbox_credit(aid,100_000,f'seed-{i:04d}-sandbox')

    def tearDown(self):
        self.l.db.close();self.temp.cleanup()

    def test_fault_rolls_back_postings_and_balance(self):
        old=self.l._journal
        def fault(*args,**kwargs):
            old(*args,**kwargs)
            raise RuntimeError('injected_crash_after_postings')
        self.l._journal=fault
        with self.assertRaises(RuntimeError):
            self.l.transfer(self.accounts[0],self.accounts[1],10_000,'injected-rollback-key')
        self.l._journal=old
        self.assertEqual(self.l.account(self.accounts[0])['balance'],100_000)
        self.assertEqual(self.l.account(self.accounts[1])['balance'],100_000)
        self.assertTrue(self.l.audit_invariants()['ok'])
        self.assertEqual(self.l.db.execute('SELECT count(*) FROM journals WHERE kind=\'transfer\'').fetchone()[0],0)

    def test_randomized_double_entry_invariants_500(self):
        rng=random.Random(73391)
        for i in range(500):
            src,dst=rng.sample(self.accounts,2)
            amount=rng.randint(1,9000)
            try:self.l.transfer(src,dst,amount,f'property-transfer-{i:05d}')
            except PaymentError as ex:self.assertEqual(ex.code,'insufficient_funds')
            if i%25==0:self.assertTrue(self.l.audit_invariants()['ok'])
        totals=sum(self.l.account(x)['balance'] for x in self.accounts)
        self.assertEqual(totals,400_000)
        self.assertTrue(self.l.audit_invariants()['ok'])

    def test_persistent_idempotency_after_restart(self):
        src,dst=self.accounts[:2]
        key='idempotent-across-restart'
        result=self.l.transfer(src,dst,1000,key)
        path=self.l.db.execute('PRAGMA database_list').fetchone()['file']
        second=Ledger(path)
        try:
            self.assertEqual(result,second.transfer(src,dst,1000,key))
            self.assertEqual(second.account(src)['balance'],99000)
            self.assertTrue(second.audit_invariants()['ok'])
        finally:second.db.close()

if __name__=='__main__':unittest.main()
