"""Protected release-policy tests: source ZIPs are forbidden from editing scripts/."""
import base64
import importlib.util
import json
import secrets
import time
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]

class SecurityContract(unittest.TestCase):
    def test_migration_has_ledger_guards(self):
        sql=(ROOT/'spyderpay_core/postgres/migrations/001_core.sql').read_text()
        for x in ('sp_balanced_journal','sp_no_posting_changes','sp_no_audit_changes',
                  'sp_posting_currency','sp_balanced_header','sp_idempotency','sp_api_replay','sp_rate_windows'):
            self.assertIn(x,sql)

    def test_service_signature_is_not_body_only(self):
        from spyderpay_core.postgres.auth import sign
        secret=secrets.token_bytes(32)
        sig=sign(secret,'POST','/v2/transfers',b'{}','1111111111','A'*24)
        self.assertNotEqual(sig,sign(secret,'GET','/v2/transfers',b'{}','1111111111','A'*24))
        self.assertNotEqual(sig,sign(secret,'POST','/v2/invoices',b'{}','1111111111','A'*24))
        self.assertNotEqual(sig,sign(secret,'POST','/v2/transfers',b'{ }','1111111111','A'*24))

    def test_prelicense_gate_is_present(self):
        content=(ROOT/'spyderpay_core/postgres/api.py').read_text()
        self.assertIn("SPYDERPAY_ENV",content)
        self.assertIn("prelicense",content)
        self.assertIn("SPYDERPAY_ALLOW_SANDBOX_CREDIT",content)

    def test_installer_denies_actions(self):
        loc=ROOT/'scripts/secure_unpack.py'
        spec=importlib.util.spec_from_file_location('protected_unpack',loc)
        mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
        for path in ('../escape','spyderpay_core/../.github/foo','.github/workflows/foo.yml','spyderpay_core/.env'):
            with self.assertRaises(ValueError):mod._safe_path(path,('spyderpay_core',))

if __name__=='__main__':unittest.main()
