-- Block 1: ledger finality, identity/session revocation, one-time approvals.
BEGIN;
SELECT pg_advisory_xact_lock(8421778102);
-- Maintenance window: block concurrent legacy financial writers during validation.
LOCK TABLE sp_accounts,sp_journals,sp_postings,sp_invoices IN ACCESS EXCLUSIVE MODE;
-- Fail migration if old data is inconsistent. Never silently repair financial records.
DO $$ BEGIN
 IF EXISTS (SELECT 1 FROM sp_accounts a LEFT JOIN (SELECT account_id,sum(signed_amount) s FROM sp_postings GROUP BY account_id) p ON a.id=p.account_id WHERE a.balance<>coalesce(p.s,0)) OR EXISTS (SELECT 1 FROM sp_journals j LEFT JOIN sp_postings p ON p.journal_id=j.id GROUP BY j.id HAVING count(p.id)<2 OR coalesce(sum(p.signed_amount),0)<>0) THEN
 RAISE EXCEPTION 'legacy_ledger_requires_reconciliation'; END IF;
END $$;
ALTER TABLE sp_journals ADD COLUMN IF NOT EXISTS sealed boolean NOT NULL DEFAULT true;
ALTER TABLE sp_journals ALTER COLUMN sealed SET DEFAULT false;
CREATE OR REPLACE FUNCTION sp_guard_journal() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'immutable_journal' USING ERRCODE='23000'; END IF;
 IF OLD.sealed OR NOT NEW.sealed OR (to_jsonb(NEW)-'sealed') IS DISTINCT FROM (to_jsonb(OLD)-'sealed') THEN RAISE EXCEPTION 'immutable_journal' USING ERRCODE='23000'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS sp_no_journal_changes ON sp_journals;
CREATE TRIGGER sp_no_journal_changes BEFORE UPDATE OR DELETE ON sp_journals FOR EACH ROW EXECUTE FUNCTION sp_guard_journal();
CREATE OR REPLACE FUNCTION sp_reject_sealed_posting() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE is_sealed boolean;
BEGIN
 SELECT sealed INTO is_sealed FROM sp_journals WHERE id=NEW.journal_id FOR UPDATE;
 IF is_sealed IS DISTINCT FROM false THEN RAISE EXCEPTION 'sealed_journal' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS sp_posting_seal ON sp_postings;
CREATE TRIGGER sp_posting_seal BEFORE INSERT ON sp_postings FOR EACH ROW EXECUTE FUNCTION sp_reject_sealed_posting();
CREATE OR REPLACE FUNCTION sp_require_sealed() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM sp_journals WHERE id=NEW.id AND sealed) THEN RAISE EXCEPTION 'unsealed_journal' USING ERRCODE='23514'; END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS sp_sealed_at_commit ON sp_journals;
CREATE CONSTRAINT TRIGGER sp_sealed_at_commit AFTER INSERT ON sp_journals DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION sp_require_sealed();
CREATE OR REPLACE FUNCTION sp_guard_account() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'immutable_account_identity' USING ERRCODE='23000'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.balance<>0 THEN RAISE EXCEPTION 'nonzero_opening_balance' USING ERRCODE='23514'; END IF;
 ELSE
  IF (to_jsonb(NEW)-'balance'-'status') IS DISTINCT FROM (to_jsonb(OLD)-'balance'-'status') THEN RAISE EXCEPTION 'immutable_account_identity' USING ERRCODE='23000'; END IF;
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS sp_account_identity ON sp_accounts;
CREATE TRIGGER sp_account_identity BEFORE INSERT OR UPDATE OR DELETE ON sp_accounts FOR EACH ROW EXECUTE FUNCTION sp_guard_account();
-- Deferred verification uses existing account row locks. This is correctness-first;
-- benchmark historical scan cost before large-scale deployment.
CREATE OR REPLACE FUNCTION sp_check_account_balance() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE aid uuid; cached bigint; actual numeric;
BEGIN
 IF TG_TABLE_NAME='sp_accounts' THEN aid:=NEW.id; ELSE aid:=NEW.account_id; END IF;
 SELECT balance INTO cached FROM sp_accounts WHERE id=aid FOR UPDATE;
 SELECT coalesce(sum(signed_amount),0) INTO actual FROM sp_postings WHERE account_id=aid;
 IF cached IS DISTINCT FROM actual THEN RAISE EXCEPTION 'balance_without_postings' USING ERRCODE='23514'; END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS sp_balance_account ON sp_accounts;
CREATE CONSTRAINT TRIGGER sp_balance_account AFTER INSERT OR UPDATE ON sp_accounts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION sp_check_account_balance();
DROP TRIGGER IF EXISTS sp_balance_posting ON sp_postings;
CREATE CONSTRAINT TRIGGER sp_balance_posting AFTER INSERT ON sp_postings DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION sp_check_account_balance();
CREATE OR REPLACE FUNCTION sp_guard_invoice() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'immutable_invoice' USING ERRCODE='23000'; END IF;
 IF (to_jsonb(NEW)-'state'-'payer_account'-'payment_journal'-'refund_journal') IS DISTINCT FROM (to_jsonb(OLD)-'state'-'payer_account'-'payment_journal'-'refund_journal') THEN RAISE EXCEPTION 'immutable_invoice_terms' USING ERRCODE='23514'; END IF;
 IF NOT ((OLD.state='pending' AND NEW.state='paid' AND NEW.payer_account IS NOT NULL AND NEW.payment_journal IS NOT NULL AND NEW.refund_journal IS NULL) OR (OLD.state='paid' AND NEW.state='refunded' AND NEW.payer_account=OLD.payer_account AND NEW.payment_journal=OLD.payment_journal AND NEW.refund_journal IS NOT NULL) OR (OLD.state='pending' AND NEW.state='cancelled' AND NEW.payer_account IS NULL AND NEW.payment_journal IS NULL AND NEW.refund_journal IS NULL)) THEN RAISE EXCEPTION 'invalid_invoice_transition' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS sp_invoice_guard ON sp_invoices;
CREATE TRIGGER sp_invoice_guard BEFORE UPDATE OR DELETE ON sp_invoices FOR EACH ROW EXECUTE FUNCTION sp_guard_invoice();
CREATE TABLE IF NOT EXISTS sp_identity_members (
 issuer text NOT NULL, external_sub text NOT NULL, tenant_id text NOT NULL, owner_id text NOT NULL,
 role text NOT NULL CHECK(role IN ('customer','merchant')), enabled boolean NOT NULL DEFAULT true,
 PRIMARY KEY(issuer,external_sub), UNIQUE(tenant_id,owner_id,role)
);
CREATE TABLE IF NOT EXISTS sp_revoked_sessions (
 issuer text NOT NULL, external_sub text NOT NULL, sid text NOT NULL, revoked_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(issuer,external_sub,sid)
);
CREATE TABLE IF NOT EXISTS sp_payment_approvals (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), issuer text NOT NULL, external_sub text NOT NULL, sid text NOT NULL,
 tenant_id text NOT NULL, owner_id text NOT NULL, role text NOT NULL CHECK(role IN ('customer','merchant')),
 request_digest text NOT NULL CHECK(length(request_digest)=64), idem_key text NOT NULL CHECK(length(idem_key) BETWEEN 12 AND 128),
 initiating_jti_hash text NOT NULL CHECK(length(initiating_jti_hash)=64),
 created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL, confirmed_at timestamptz, consumed_at timestamptz,
 CHECK(consumed_at IS NULL OR confirmed_at IS NOT NULL),
 CHECK(expires_at>created_at), FOREIGN KEY(issuer,external_sub) REFERENCES sp_identity_members(issuer,external_sub)
);
CREATE INDEX IF NOT EXISTS sp_approvals_expiry ON sp_payment_approvals(expires_at);
CREATE INDEX IF NOT EXISTS sp_approvals_owner ON sp_payment_approvals(issuer,external_sub,sid,expires_at);
-- Lock membership without granting runtime permission to alter identity records.
CREATE OR REPLACE FUNCTION sp_lock_member(p_issuer text,p_sub text)
RETURNS TABLE(tenant_id text,owner_id text,role text,enabled boolean)
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT m.tenant_id,m.owner_id,m.role,m.enabled FROM public.sp_identity_members m
 WHERE m.issuer=p_issuer AND m.external_sub=p_sub FOR SHARE OF m
$$;
REVOKE ALL ON FUNCTION sp_lock_member(text,text) FROM PUBLIC;
-- Check invoice journal links against the actual sealed, two-leg movement.
CREATE OR REPLACE FUNCTION sp_invoice_link_check() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE j uuid; expected_kind text; src uuid; dst uuid; n bigint;
BEGIN
 IF NOT EXISTS(SELECT 1 FROM sp_accounts WHERE id=NEW.merchant_account AND tenant_id=NEW.tenant_id AND kind='merchant') THEN RAISE EXCEPTION 'invalid_invoice_merchant' USING ERRCODE='23514'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.state<>'pending' OR NEW.payer_account IS NOT NULL OR NEW.payment_journal IS NOT NULL OR NEW.refund_journal IS NOT NULL THEN RAISE EXCEPTION 'invalid_invoice_initial_state' USING ERRCODE='23514'; END IF;
  RETURN NEW;
 END IF;
 IF NEW.state='paid' THEN j:=NEW.payment_journal; expected_kind:='merchant_payment'; src:=NEW.payer_account; dst:=NEW.merchant_account;
 ELSIF NEW.state='refunded' THEN j:=NEW.refund_journal; expected_kind:='merchant_refund'; src:=NEW.merchant_account; dst:=NEW.payer_account;
 ELSE RETURN NEW; END IF;
 IF NOT EXISTS(SELECT 1 FROM sp_accounts WHERE id=NEW.payer_account AND tenant_id=NEW.tenant_id AND kind='customer') THEN RAISE EXCEPTION 'invalid_invoice_payer' USING ERRCODE='23514'; END IF;
 IF NOT EXISTS(SELECT 1 FROM sp_journals WHERE id=j AND tenant_id=NEW.tenant_id AND kind=expected_kind AND reference=NEW.id::text AND sealed) THEN RAISE EXCEPTION 'invalid_invoice_journal' USING ERRCODE='23514'; END IF;
 SELECT count(*) INTO n FROM sp_postings WHERE journal_id=j;
 IF n<>2 OR NOT EXISTS(SELECT 1 FROM sp_postings WHERE journal_id=j AND account_id=src AND signed_amount=-NEW.amount) OR NOT EXISTS(SELECT 1 FROM sp_postings WHERE journal_id=j AND account_id=dst AND signed_amount=NEW.amount) THEN RAISE EXCEPTION 'invalid_invoice_postings' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS sp_invoice_link ON sp_invoices;
CREATE TRIGGER sp_invoice_link BEFORE INSERT OR UPDATE ON sp_invoices FOR EACH ROW EXECUTE FUNCTION sp_invoice_link_check();
CREATE UNIQUE INDEX IF NOT EXISTS sp_invoice_payment_once ON sp_invoices(payment_journal) WHERE payment_journal IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS sp_invoice_refund_once ON sp_invoices(refund_journal) WHERE refund_journal IS NOT NULL;
INSERT INTO sp_schema_version(version) VALUES(3) ON CONFLICT DO NOTHING;
COMMIT;
