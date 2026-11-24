-- SpyderPay Core v0.2.0 reference PostgreSQL schema.
-- Separate financial ledger from Spider Blockchain. All amounts are integer UZS.
-- Requires PostgreSQL 16+. No card PAN, seed, private keys, or cryptocurrency accounts.
BEGIN;
SELECT pg_advisory_xact_lock(8421778102);
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE IF NOT EXISTS sp_schema_version (version integer PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS sp_accounts (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id text NOT NULL,
 owner_id text NOT NULL, kind text NOT NULL CHECK(kind IN ('customer','merchant','system')),
 currency text NOT NULL CHECK(currency='UZS'),
 status text NOT NULL DEFAULT 'active' CHECK(status IN ('active','frozen','closed')),
 balance bigint NOT NULL DEFAULT 0,
 created_at timestamptz NOT NULL DEFAULT now(),
 CONSTRAINT nonnegative_external CHECK(kind='system' OR balance >= 0),
 CONSTRAINT reasonable_balance CHECK(balance BETWEEN -900000000000000000 AND 900000000000000000)
);
CREATE INDEX IF NOT EXISTS sp_accounts_owner_idx ON sp_accounts (tenant_id,owner_id);
CREATE TABLE IF NOT EXISTS sp_journals (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id text NOT NULL, kind text NOT NULL,
 reference text, created_at timestamptz NOT NULL DEFAULT now(),
 actor text NOT NULL, currency text NOT NULL CHECK(currency='UZS')
);
CREATE TABLE IF NOT EXISTS sp_postings (
 id bigserial PRIMARY KEY, journal_id uuid NOT NULL REFERENCES sp_journals(id),
 account_id uuid NOT NULL REFERENCES sp_accounts(id),
 signed_amount bigint NOT NULL CHECK (signed_amount<>0),
 currency text NOT NULL CHECK(currency='UZS'), created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(journal_id,account_id)
);
CREATE INDEX IF NOT EXISTS sp_postings_account_idx ON sp_postings(account_id,created_at DESC);
CREATE TABLE IF NOT EXISTS sp_idempotency (
 actor text NOT NULL, idem_key text NOT NULL, request_digest text NOT NULL,
 result jsonb, created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(actor,idem_key), CHECK(length(idem_key) BETWEEN 12 AND 128)
);
CREATE TABLE IF NOT EXISTS sp_invoices (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id text NOT NULL,
 merchant_account uuid NOT NULL REFERENCES sp_accounts(id), amount bigint NOT NULL CHECK(amount>0),
 payer_account uuid REFERENCES sp_accounts(id), state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','paid','refunded','cancelled')),
 payment_journal uuid REFERENCES sp_journals(id), refund_journal uuid REFERENCES sp_journals(id),
 expires_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 CHECK((state='paid' AND payer_account IS NOT NULL AND payment_journal IS NOT NULL) OR state<>'paid')
);
CREATE TABLE IF NOT EXISTS sp_outbox (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id text NOT NULL, event_type text NOT NULL,
 aggregate_id text NOT NULL, payload jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), delivered_at timestamptz,
 attempts integer NOT NULL DEFAULT 0,
 lease_token uuid, leased_until timestamptz,
 next_attempt_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS sp_outbox_pending_idx ON sp_outbox(created_at) WHERE delivered_at IS NULL;
CREATE TABLE IF NOT EXISTS sp_audit_events (
 id bigserial PRIMARY KEY, tenant_id text NOT NULL, actor text NOT NULL, action text NOT NULL,
 target text NOT NULL, payload_hash text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS sp_api_replay (
 key_id text NOT NULL, nonce text NOT NULL, observed_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(key_id,nonce)
);
CREATE INDEX IF NOT EXISTS sp_api_replay_gc_idx ON sp_api_replay(observed_at);
CREATE TABLE IF NOT EXISTS sp_rate_windows (
 key_id text NOT NULL, minute_bucket bigint NOT NULL, hits integer NOT NULL DEFAULT 0,
 PRIMARY KEY (key_id,minute_bucket)
);
CREATE TABLE IF NOT EXISTS sp_bank_inbox (
 source text NOT NULL, external_event_id text NOT NULL,
 payload_digest text NOT NULL, status text NOT NULL DEFAULT 'received',
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(source,external_event_id)
);
CREATE OR REPLACE FUNCTION sp_reject_immutable_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'immutable_ledger_table' USING ERRCODE='23000'; END; $$;
DROP TRIGGER IF EXISTS sp_no_posting_changes ON sp_postings;
CREATE TRIGGER sp_no_posting_changes BEFORE UPDATE OR DELETE ON sp_postings
 FOR EACH ROW EXECUTE FUNCTION sp_reject_immutable_change();
DROP TRIGGER IF EXISTS sp_no_journal_changes ON sp_journals;
CREATE TRIGGER sp_no_journal_changes BEFORE UPDATE OR DELETE ON sp_journals
 FOR EACH ROW EXECUTE FUNCTION sp_reject_immutable_change();
DROP TRIGGER IF EXISTS sp_no_audit_changes ON sp_audit_events;
CREATE TRIGGER sp_no_audit_changes BEFORE UPDATE OR DELETE ON sp_audit_events
 FOR EACH ROW EXECUTE FUNCTION sp_reject_immutable_change();
-- Deferred invariant: a journal must have at least two balanced legs, even across a transaction.
CREATE OR REPLACE FUNCTION sp_assert_balanced_journal() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE cnt integer; total numeric; currencies integer;
BEGIN
 SELECT count(*),COALESCE(sum(signed_amount),0),count(DISTINCT currency)
 INTO cnt,total,currencies FROM sp_postings WHERE journal_id=NEW.journal_id;
 IF cnt<2 OR total<>0 OR currencies<>1 THEN
  RAISE EXCEPTION 'unbalanced_journal %',NEW.journal_id USING ERRCODE='23514';
 END IF;
 RETURN NULL;
END; $$;
DROP TRIGGER IF EXISTS sp_balanced_journal ON sp_postings;
CREATE CONSTRAINT TRIGGER sp_balanced_journal AFTER INSERT ON sp_postings
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION sp_assert_balanced_journal();
-- Also reject empty journal headers (a postings-only trigger would miss them).
CREATE OR REPLACE FUNCTION sp_verify_journal_header() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE cnt integer; total numeric;
BEGIN
 SELECT count(*),COALESCE(sum(signed_amount),0) INTO cnt,total
 FROM sp_postings WHERE journal_id=NEW.id;
 IF cnt<2 OR total<>0 THEN
  RAISE EXCEPTION 'invalid_journal_header %',NEW.id USING ERRCODE='23514';
 END IF;
 RETURN NULL;
END; $$;
DROP TRIGGER IF EXISTS sp_balanced_header ON sp_journals;
CREATE CONSTRAINT TRIGGER sp_balanced_header AFTER INSERT ON sp_journals
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION sp_verify_journal_header();
CREATE OR REPLACE FUNCTION sp_validate_posting_currency() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE ac_currency text; journal_currency text; ac_tenant text; journal_tenant text;
BEGIN
 SELECT currency,tenant_id INTO ac_currency,ac_tenant FROM sp_accounts WHERE id=NEW.account_id;
 SELECT currency,tenant_id INTO journal_currency,journal_tenant FROM sp_journals WHERE id=NEW.journal_id;
 IF NEW.currency<>ac_currency OR NEW.currency<>journal_currency OR ac_tenant<>journal_tenant THEN
  RAISE EXCEPTION 'currency_mismatch' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END; $$;
DROP TRIGGER IF EXISTS sp_posting_currency ON sp_postings;
CREATE TRIGGER sp_posting_currency BEFORE INSERT ON sp_postings
 FOR EACH ROW EXECUTE FUNCTION sp_validate_posting_currency();
INSERT INTO sp_schema_version(version) VALUES(2) ON CONFLICT DO NOTHING;
COMMIT;
