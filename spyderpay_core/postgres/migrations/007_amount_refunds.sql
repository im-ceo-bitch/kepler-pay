BEGIN;
SELECT pg_advisory_xact_lock(8421778102);
CREATE TABLE sp_amount_refunds (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), invoice_id uuid NOT NULL REFERENCES sp_invoices(id),
 amount bigint NOT NULL CHECK(amount>0), fee_amount bigint NOT NULL CHECK(fee_amount>=0 AND fee_amount<=amount),
 journal_id uuid NOT NULL UNIQUE REFERENCES sp_journals(id), fee_journal_id uuid UNIQUE REFERENCES sp_journals(id),
 case_id uuid UNIQUE REFERENCES sp_chargebacks(id), created_at timestamptz NOT NULL DEFAULT now(),
 CHECK((fee_amount=0)=(fee_journal_id IS NULL))
);
CREATE INDEX sp_amount_refunds_invoice ON sp_amount_refunds(invoice_id);
CREATE TRIGGER immutable_record BEFORE UPDATE OR DELETE ON sp_amount_refunds FOR EACH ROW EXECUTE FUNCTION sp_reject_immutable_change();
CREATE FUNCTION sp_amount_refund_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE inv sp_invoices%ROWTYPE; prior bigint; f bigint; prevfee bigint; rev uuid;
BEGIN
 SELECT * INTO inv FROM sp_invoices WHERE id=NEW.invoice_id FOR UPDATE;
 IF inv.state IS DISTINCT FROM 'paid' THEN RAISE EXCEPTION 'invoice_not_paid' USING ERRCODE='23514'; END IF;
 SELECT coalesce(sum(amount),0),coalesce(sum(fee_amount),0) INTO prior,prevfee FROM sp_amount_refunds WHERE invoice_id=inv.id;
 SELECT coalesce((SELECT amount FROM sp_invoice_fees WHERE invoice_id=inv.id),0) INTO f;
 IF NEW.amount>inv.amount-prior OR NEW.fee_amount<>f*(prior+NEW.amount)/inv.amount-prevfee THEN RAISE EXCEPTION 'invalid_refund_total' USING ERRCODE='23514'; END IF;
 IF EXISTS(SELECT 1 FROM sp_fee_movements WHERE invoice_id=inv.id AND direction='reverse') THEN RAISE EXCEPTION 'legacy_fee_already_reversed' USING ERRCODE='23514'; END IF;
 IF NEW.case_id IS NULL THEN
  IF EXISTS(SELECT 1 FROM sp_chargebacks c LEFT JOIN sp_chargeback_decisions d ON d.case_id=c.id WHERE c.invoice_id=inv.id AND d.decision IS DISTINCT FROM 'reject') THEN RAISE EXCEPTION 'chargeback_in_progress' USING ERRCODE='23514'; END IF;
 ELSE
  IF NEW.amount<>inv.amount-prior OR NOT EXISTS(SELECT 1 FROM sp_chargebacks c JOIN sp_chargeback_decisions d ON d.case_id=c.id WHERE c.id=NEW.case_id AND c.invoice_id=inv.id AND d.decision='approve') THEN RAISE EXCEPTION 'invalid_refund_case' USING ERRCODE='23514'; END IF;
 END IF;
 IF NOT EXISTS(SELECT 1 FROM sp_journals WHERE id=NEW.journal_id AND tenant_id=inv.tenant_id AND kind='merchant_refund' AND reference=inv.id::text AND sealed) OR (SELECT count(*) FROM sp_postings WHERE journal_id=NEW.journal_id)<>2 OR NOT EXISTS(SELECT 1 FROM sp_postings WHERE journal_id=NEW.journal_id AND account_id=inv.merchant_account AND signed_amount=-NEW.amount) OR NOT EXISTS(SELECT 1 FROM sp_postings WHERE journal_id=NEW.journal_id AND account_id=inv.payer_account AND signed_amount=NEW.amount) THEN RAISE EXCEPTION 'invalid_amount_refund_journal' USING ERRCODE='23514'; END IF;
 IF NEW.fee_amount>0 THEN
  SELECT p.account_id INTO rev FROM sp_postings p JOIN sp_accounts a ON a.id=p.account_id WHERE p.journal_id=NEW.fee_journal_id AND a.kind='system' AND a.owner_id='fee-revenue-v7' AND a.tenant_id=inv.tenant_id;
  IF rev IS NULL OR NOT EXISTS(SELECT 1 FROM sp_journals WHERE id=NEW.fee_journal_id AND tenant_id=inv.tenant_id AND kind='merchant_fee_reverse' AND reference=inv.id::text AND sealed) OR (SELECT count(*) FROM sp_postings WHERE journal_id=NEW.fee_journal_id)<>2 OR NOT EXISTS(SELECT 1 FROM sp_postings WHERE journal_id=NEW.fee_journal_id AND account_id=rev AND signed_amount=-NEW.fee_amount) OR NOT EXISTS(SELECT 1 FROM sp_postings WHERE journal_id=NEW.fee_journal_id AND account_id=inv.merchant_account AND signed_amount=NEW.fee_amount) THEN RAISE EXCEPTION 'invalid_amount_fee_journal' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER amount_refund_guard BEFORE INSERT ON sp_amount_refunds FOR EACH ROW EXECUTE FUNCTION sp_amount_refund_guard();
-- Existing full-refund journal path remains valid for all old invoices.
CREATE OR REPLACE FUNCTION sp_invoice_link_check() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE j uuid; expected_kind text; src uuid; dst uuid; n bigint; movement bigint; prior bigint;
BEGIN
 IF NOT EXISTS(SELECT 1 FROM sp_accounts WHERE id=NEW.merchant_account AND tenant_id=NEW.tenant_id AND kind='merchant') THEN RAISE EXCEPTION 'invalid_invoice_merchant' USING ERRCODE='23514'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.state<>'pending' OR NEW.payer_account IS NOT NULL OR NEW.payment_journal IS NOT NULL OR NEW.refund_journal IS NOT NULL THEN RAISE EXCEPTION 'invalid_invoice_initial_state' USING ERRCODE='23514'; END IF;
  RETURN NEW;
 END IF;
 movement:=NEW.amount;
 IF NEW.state='paid' THEN j:=NEW.payment_journal; expected_kind:='merchant_payment'; src:=NEW.payer_account; dst:=NEW.merchant_account;
 ELSIF NEW.state='refunded' THEN
  j:=NEW.refund_journal; expected_kind:='merchant_refund'; src:=NEW.merchant_account; dst:=NEW.payer_account;
  SELECT coalesce(sum(amount),0) INTO prior FROM sp_amount_refunds WHERE invoice_id=NEW.id;
  IF prior>0 THEN
   SELECT amount INTO movement FROM sp_amount_refunds WHERE invoice_id=NEW.id AND journal_id=j;
   IF prior<>NEW.amount OR movement IS NULL THEN RAISE EXCEPTION 'invalid_refund_final_total' USING ERRCODE='23514'; END IF;
  END IF;
 ELSE RETURN NEW; END IF;
 IF NOT EXISTS(SELECT 1 FROM sp_accounts WHERE id=NEW.payer_account AND tenant_id=NEW.tenant_id AND kind='customer') THEN RAISE EXCEPTION 'invalid_invoice_payer' USING ERRCODE='23514'; END IF;
 IF NOT EXISTS(SELECT 1 FROM sp_journals WHERE id=j AND tenant_id=NEW.tenant_id AND kind=expected_kind AND reference=NEW.id::text AND sealed) THEN RAISE EXCEPTION 'invalid_invoice_journal' USING ERRCODE='23514'; END IF;
 SELECT count(*) INTO n FROM sp_postings WHERE journal_id=j;
 IF n<>2 OR NOT EXISTS(SELECT 1 FROM sp_postings WHERE journal_id=j AND account_id=src AND signed_amount=-movement) OR NOT EXISTS(SELECT 1 FROM sp_postings WHERE journal_id=j AND account_id=dst AND signed_amount=movement) THEN RAISE EXCEPTION 'invalid_invoice_postings' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION sp_check_invoice_fee_finality() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE iid uuid; st text; gross bigint; f bigint; collected boolean; reversed boolean; total bigint; returned bigint;
BEGIN
 IF TG_TABLE_NAME='sp_invoices' THEN iid:=NEW.id; ELSE iid:=NEW.invoice_id; END IF;
 SELECT state,amount INTO st,gross FROM sp_invoices WHERE id=iid;
 SELECT coalesce((SELECT amount FROM sp_invoice_fees WHERE invoice_id=iid),0) INTO f;
 SELECT EXISTS(SELECT 1 FROM sp_fee_movements WHERE invoice_id=iid AND direction='collect'),EXISTS(SELECT 1 FROM sp_fee_movements WHERE invoice_id=iid AND direction='reverse') INTO collected,reversed;
 SELECT coalesce(sum(amount),0),coalesce(sum(fee_amount),0) INTO total,returned FROM sp_amount_refunds WHERE invoice_id=iid;
 IF total>0 THEN
  IF total>gross OR st NOT IN ('paid','refunded') OR (total=gross) IS DISTINCT FROM (st='refunded') OR reversed OR returned<>f*total/gross THEN RAISE EXCEPTION 'amount_refund_state_mismatch' USING ERRCODE='23514'; END IF;
  IF EXISTS(SELECT 1 FROM sp_amount_refunds r LEFT JOIN sp_chargeback_executions e ON e.case_id=r.case_id AND e.journal_id=r.journal_id WHERE r.invoice_id=iid AND r.case_id IS NOT NULL AND e.case_id IS NULL) THEN RAISE EXCEPTION 'amount_refund_case_execution_missing' USING ERRCODE='23514'; END IF;
 ELSIF reversed IS DISTINCT FROM (f>0 AND st='refunded') THEN RAISE EXCEPTION 'fee_invoice_state_mismatch' USING ERRCODE='23514'; END IF;
 IF collected IS DISTINCT FROM (f>0 AND st IN ('paid','refunded')) THEN RAISE EXCEPTION 'fee_invoice_state_mismatch' USING ERRCODE='23514'; END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER amount_refund_final AFTER INSERT ON sp_amount_refunds DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION sp_check_invoice_fee_finality();
-- Read-only integrity view for health checks and restore verification.
CREATE VIEW sp_refund_integrity AS
SELECT i.id,i.tenant_id,
 CASE WHEN t.amount>0 THEN t.amount<=i.amount AND i.state IN ('paid','refunded') AND (t.amount=i.amount)=(i.state='refunded') AND NOT coalesce(m.reversed,false) AND t.fee=trunc(coalesce(f.amount,0)*t.amount/i.amount) AND (i.state<>'refunded' OR EXISTS(SELECT 1 FROM sp_amount_refunds r WHERE r.invoice_id=i.id AND r.journal_id=i.refund_journal))
 ELSE coalesce(m.reversed,false)=(coalesce(f.amount,0)>0 AND i.state='refunded') END
 AND coalesce(m.collected,false)=(coalesce(f.amount,0)>0 AND i.state IN ('paid','refunded')) AS valid
FROM sp_invoices i LEFT JOIN sp_invoice_fees f ON f.invoice_id=i.id
LEFT JOIN LATERAL (SELECT coalesce(sum(amount),0) amount,coalesce(sum(fee_amount),0) fee FROM sp_amount_refunds WHERE invoice_id=i.id) t ON true
LEFT JOIN LATERAL (SELECT bool_or(direction='collect') collected,bool_or(direction='reverse') reversed FROM sp_fee_movements WHERE invoice_id=i.id) m ON true;
DO $$ BEGIN IF EXISTS(SELECT 1 FROM sp_refund_integrity WHERE NOT valid) THEN RAISE EXCEPTION 'preexisting_fee_integrity_failure'; END IF; END $$;
INSERT INTO sp_schema_version(version) VALUES(8);
COMMIT;
