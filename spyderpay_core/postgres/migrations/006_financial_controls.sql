BEGIN;
SELECT pg_advisory_xact_lock(8421778102);
CREATE TABLE sp_fee_schedules (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id text NOT NULL,
 merchant_account uuid NOT NULL REFERENCES sp_accounts(id), bps integer NOT NULL CHECK(bps BETWEEN 0 AND 1000),
 maker text NOT NULL, evidence_ref text NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE sp_fee_approvals (
 schedule_id uuid PRIMARY KEY REFERENCES sp_fee_schedules(id), reviewer text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX sp_fee_schedule_merchant ON sp_fee_schedules(tenant_id,merchant_account,created_at DESC);
CREATE TABLE sp_invoice_fees (
 invoice_id uuid PRIMARY KEY REFERENCES sp_invoices(id), schedule_id uuid NOT NULL REFERENCES sp_fee_schedules(id),
 amount bigint NOT NULL CHECK(amount>=0), created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE sp_fee_movements (
 invoice_id uuid NOT NULL REFERENCES sp_invoice_fees(invoice_id), direction text NOT NULL CHECK(direction IN ('collect','reverse')),
 journal_id uuid NOT NULL UNIQUE REFERENCES sp_journals(id), created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(invoice_id,direction)
);
CREATE TABLE sp_chargebacks (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), invoice_id uuid NOT NULL UNIQUE REFERENCES sp_invoices(id), tenant_id text NOT NULL,
 maker text NOT NULL, reason text NOT NULL CHECK(reason IN ('unauthorized','duplicate','not_delivered','other')),
 evidence_ref text NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE sp_chargeback_decisions (
 case_id uuid PRIMARY KEY REFERENCES sp_chargebacks(id), reviewer text NOT NULL,
 decision text NOT NULL CHECK(decision IN ('approve','reject')), evidence_ref text NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE sp_chargeback_executions (
 case_id uuid PRIMARY KEY REFERENCES sp_chargebacks(id), executor text NOT NULL,
 journal_id uuid NOT NULL UNIQUE REFERENCES sp_journals(id), created_at timestamptz NOT NULL DEFAULT now()
);
CREATE OR REPLACE FUNCTION sp_fee_schedule_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM sp_accounts WHERE id=NEW.merchant_account AND tenant_id=NEW.tenant_id AND kind='merchant') THEN RAISE EXCEPTION 'invalid_fee_merchant' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER sp_fee_merchant BEFORE INSERT ON sp_fee_schedules FOR EACH ROW EXECUTE FUNCTION sp_fee_schedule_guard();
CREATE OR REPLACE FUNCTION sp_fee_approval_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM sp_fee_schedules WHERE id=NEW.schedule_id AND maker<>NEW.reviewer) THEN RAISE EXCEPTION 'fee_independent_review_required' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER sp_fee_independent BEFORE INSERT ON sp_fee_approvals FOR EACH ROW EXECUTE FUNCTION sp_fee_approval_guard();
CREATE OR REPLACE FUNCTION sp_fee_quote_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM sp_invoices i JOIN sp_fee_schedules s ON s.id=NEW.schedule_id JOIN sp_fee_approvals a ON a.schedule_id=s.id WHERE i.id=NEW.invoice_id AND i.state='pending' AND s.tenant_id=i.tenant_id AND s.merchant_account=i.merchant_account AND NEW.amount=(i.amount*s.bps)/10000) THEN RAISE EXCEPTION 'invalid_fee_quote' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER sp_fee_quote BEFORE INSERT ON sp_invoice_fees FOR EACH ROW EXECUTE FUNCTION sp_fee_quote_guard();
CREATE OR REPLACE FUNCTION sp_fee_movement_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE inv sp_invoices%ROWTYPE; fee bigint; src uuid; dst uuid; rev uuid; expected_kind text;
BEGIN
 SELECT * INTO inv FROM sp_invoices WHERE id=NEW.invoice_id;
 SELECT amount INTO fee FROM sp_invoice_fees WHERE invoice_id=NEW.invoice_id;
 SELECT p.account_id INTO rev FROM sp_postings p JOIN sp_accounts a ON a.id=p.account_id WHERE p.journal_id=NEW.journal_id AND a.kind='system' AND a.owner_id='fee-revenue-v7' AND a.tenant_id=inv.tenant_id;
 IF fee IS NULL OR fee<=0 OR rev IS NULL THEN RAISE EXCEPTION 'invalid_fee_movement' USING ERRCODE='23514'; END IF;
 IF NEW.direction='collect' THEN src:=inv.merchant_account; dst:=rev; expected_kind:='merchant_fee';
 ELSE src:=rev; dst:=inv.merchant_account; expected_kind:='merchant_fee_reverse';
  IF NOT EXISTS(SELECT 1 FROM sp_fee_movements WHERE invoice_id=NEW.invoice_id AND direction='collect') THEN RAISE EXCEPTION 'fee_not_collected' USING ERRCODE='23514'; END IF;
 END IF;
 IF NOT EXISTS(SELECT 1 FROM sp_journals WHERE id=NEW.journal_id AND tenant_id=inv.tenant_id AND kind=expected_kind AND reference=inv.id::text AND sealed) OR (SELECT count(*) FROM sp_postings WHERE journal_id=NEW.journal_id)<>2 OR NOT EXISTS(SELECT 1 FROM sp_postings WHERE journal_id=NEW.journal_id AND account_id=src AND signed_amount=-fee) OR NOT EXISTS(SELECT 1 FROM sp_postings WHERE journal_id=NEW.journal_id AND account_id=dst AND signed_amount=fee) THEN RAISE EXCEPTION 'invalid_fee_journal' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER sp_fee_movement BEFORE INSERT ON sp_fee_movements FOR EACH ROW EXECUTE FUNCTION sp_fee_movement_guard();
CREATE OR REPLACE FUNCTION sp_check_invoice_fee_finality() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE iid uuid; st text; fee bigint; collected boolean; reversed boolean;
BEGIN
 IF TG_TABLE_NAME='sp_invoices' THEN iid:=NEW.id; ELSE iid:=NEW.invoice_id; END IF;
 SELECT state INTO st FROM sp_invoices WHERE id=iid;
 SELECT amount INTO fee FROM sp_invoice_fees WHERE invoice_id=iid;
 IF coalesce(fee,0)=0 THEN RETURN NULL; END IF;
 SELECT EXISTS(SELECT 1 FROM sp_fee_movements WHERE invoice_id=iid AND direction='collect'),EXISTS(SELECT 1 FROM sp_fee_movements WHERE invoice_id=iid AND direction='reverse') INTO collected,reversed;
 IF collected IS DISTINCT FROM (st IN ('paid','refunded')) OR reversed IS DISTINCT FROM (st='refunded') THEN RAISE EXCEPTION 'fee_invoice_state_mismatch' USING ERRCODE='23514'; END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER sp_fee_final_invoice AFTER INSERT OR UPDATE ON sp_invoices DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION sp_check_invoice_fee_finality();
CREATE CONSTRAINT TRIGGER sp_fee_final_quote AFTER INSERT ON sp_invoice_fees DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION sp_check_invoice_fee_finality();
CREATE CONSTRAINT TRIGGER sp_fee_final_movement AFTER INSERT ON sp_fee_movements DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION sp_check_invoice_fee_finality();
CREATE OR REPLACE FUNCTION sp_chargeback_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_TABLE_NAME='sp_chargebacks' THEN
  IF NOT EXISTS(SELECT 1 FROM sp_invoices WHERE id=NEW.invoice_id AND tenant_id=NEW.tenant_id AND state='paid') THEN RAISE EXCEPTION 'chargeback_invoice_not_paid' USING ERRCODE='23514'; END IF;
 ELSIF TG_TABLE_NAME='sp_chargeback_decisions' THEN
  IF NOT EXISTS(SELECT 1 FROM sp_chargebacks c JOIN sp_invoices i ON i.id=c.invoice_id WHERE c.id=NEW.case_id AND c.maker<>NEW.reviewer AND i.state='paid') THEN RAISE EXCEPTION 'chargeback_independent_review_required' USING ERRCODE='23514'; END IF;
 ELSE
  IF NOT EXISTS(SELECT 1 FROM sp_chargebacks c JOIN sp_chargeback_decisions d ON d.case_id=c.id JOIN sp_invoices i ON i.id=c.invoice_id WHERE c.id=NEW.case_id AND d.decision='approve' AND NEW.executor NOT IN (c.maker,d.reviewer) AND i.state='refunded' AND i.refund_journal=NEW.journal_id) THEN RAISE EXCEPTION 'invalid_chargeback_execution' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER sp_chargeback_open_guard BEFORE INSERT ON sp_chargebacks FOR EACH ROW EXECUTE FUNCTION sp_chargeback_guard();
CREATE TRIGGER sp_chargeback_decision_guard BEFORE INSERT ON sp_chargeback_decisions FOR EACH ROW EXECUTE FUNCTION sp_chargeback_guard();
CREATE TRIGGER sp_chargeback_execution_guard BEFORE INSERT ON sp_chargeback_executions FOR EACH ROW EXECUTE FUNCTION sp_chargeback_guard();
CREATE OR REPLACE FUNCTION sp_chargeback_refund_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.state='refunded' AND EXISTS(SELECT 1 FROM sp_chargebacks c LEFT JOIN sp_chargeback_decisions d ON d.case_id=c.id LEFT JOIN sp_chargeback_executions e ON e.case_id=c.id WHERE c.invoice_id=NEW.id AND d.decision IS DISTINCT FROM 'reject' AND e.case_id IS NULL) THEN RAISE EXCEPTION 'chargeback_requires_execution' USING ERRCODE='23514'; END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER sp_chargeback_refund_final AFTER UPDATE ON sp_invoices DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION sp_chargeback_refund_guard();
DO $$ DECLARE t text; BEGIN FOREACH t IN ARRAY ARRAY['sp_fee_schedules','sp_fee_approvals','sp_invoice_fees','sp_fee_movements','sp_chargebacks','sp_chargeback_decisions','sp_chargeback_executions'] LOOP EXECUTE format('CREATE TRIGGER immutable_record BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION sp_reject_immutable_change()',t); END LOOP; END $$;
INSERT INTO sp_schema_version(version) VALUES(7);
COMMIT;
