BEGIN;
SELECT pg_advisory_xact_lock(8421778102);
-- Opaque references only; source documents remain with the contracted identity provider.
CREATE TABLE sp_compliance_reviews (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id text NOT NULL,
 account_id uuid NOT NULL REFERENCES sp_accounts(id),
 kyc text NOT NULL CHECK(kyc IN ('verified','rejected','pending')),
 screening text NOT NULL CHECK(screening IN ('clear','hit','pending')),
 tier text NOT NULL CHECK(tier IN ('standard','enhanced')),
 evidence_ref text NOT NULL, maker text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(tenant_id,evidence_ref)
);
CREATE INDEX sp_compliance_account ON sp_compliance_reviews(tenant_id,account_id,created_at DESC,id);
CREATE TABLE sp_compliance_decisions (
 review_id uuid PRIMARY KEY REFERENCES sp_compliance_reviews(id), reviewer text NOT NULL,
 decision text NOT NULL CHECK(decision IN ('approved','rejected')), decided_at timestamptz NOT NULL DEFAULT now()
);
CREATE FUNCTION sp_compliance_decision_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM sp_compliance_reviews r WHERE r.id=NEW.review_id AND r.maker<>NEW.reviewer AND (NEW.decision='rejected' OR (r.kyc='verified' AND r.screening='clear'))) THEN RAISE EXCEPTION 'invalid_compliance_decision'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER sp_compliance_decision_guard BEFORE INSERT ON sp_compliance_decisions FOR EACH ROW EXECUTE FUNCTION sp_compliance_decision_guard();
CREATE TRIGGER sp_compliance_review_immutable BEFORE UPDATE OR DELETE ON sp_compliance_reviews FOR EACH ROW EXECUTE FUNCTION sp_reject_immutable_change();
CREATE TRIGGER sp_compliance_decision_immutable BEFORE UPDATE OR DELETE ON sp_compliance_decisions FOR EACH ROW EXECUTE FUNCTION sp_reject_immutable_change();
CREATE TABLE sp_statement_batches (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id text NOT NULL,
 provider text NOT NULL, batch_ref text NOT NULL, digest text NOT NULL CHECK(digest ~ '^[0-9a-f]{64}$'),
 opening bigint NOT NULL, closing bigint NOT NULL, credit_total bigint NOT NULL CHECK(credit_total>=0),
 debit_total bigint NOT NULL CHECK(debit_total>=0), row_count integer NOT NULL CHECK(row_count BETWEEN 1 AND 25),
 maker text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,provider,batch_ref), CHECK(closing=opening+credit_total-debit_total)
);
CREATE TABLE sp_statement_rows (
 batch_id uuid NOT NULL REFERENCES sp_statement_batches(id),
 evidence_id uuid NOT NULL UNIQUE REFERENCES sp_bank_evidence(id), PRIMARY KEY(batch_id,evidence_id)
);
CREATE TABLE sp_statement_approvals (
 batch_id uuid PRIMARY KEY REFERENCES sp_statement_batches(id), reviewer text NOT NULL,
 approved_at timestamptz NOT NULL DEFAULT now()
);
CREATE FUNCTION sp_statement_row_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('statement-batch:'||NEW.batch_id::text,0));
 IF EXISTS(SELECT 1 FROM sp_statement_approvals WHERE batch_id=NEW.batch_id) OR NOT EXISTS(SELECT 1 FROM sp_statement_batches b JOIN sp_bank_evidence e ON e.id=NEW.evidence_id WHERE b.id=NEW.batch_id AND b.tenant_id=e.tenant_id AND b.provider=e.provider AND e.channel='statement' AND e.actor=b.maker) THEN RAISE EXCEPTION 'invalid_statement_row'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER sp_statement_row_guard BEFORE INSERT ON sp_statement_rows FOR EACH ROW EXECUTE FUNCTION sp_statement_row_guard();
CREATE FUNCTION sp_statement_approval_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('statement-batch:'||NEW.batch_id::text,0));
 IF NOT EXISTS(SELECT 1 FROM sp_statement_batches b JOIN (SELECT count(*) n,coalesce(sum(e.amount) FILTER(WHERE e.direction='deposit' AND e.status='settled'),0) credits,coalesce(sum(e.amount) FILTER(WHERE e.direction='withdrawal' AND e.status='settled'),0) debits FROM sp_statement_rows r JOIN sp_bank_evidence e ON e.id=r.evidence_id WHERE r.batch_id=NEW.batch_id) t ON t.n=b.row_count AND t.credits=b.credit_total AND t.debits=b.debit_total WHERE b.id=NEW.batch_id AND b.maker<>NEW.reviewer) THEN RAISE EXCEPTION 'invalid_statement_approval'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER sp_statement_approval_guard BEFORE INSERT ON sp_statement_approvals FOR EACH ROW EXECUTE FUNCTION sp_statement_approval_guard();
CREATE TRIGGER sp_statement_batch_immutable BEFORE UPDATE OR DELETE ON sp_statement_batches FOR EACH ROW EXECUTE FUNCTION sp_reject_immutable_change();
CREATE TRIGGER sp_statement_row_immutable BEFORE UPDATE OR DELETE ON sp_statement_rows FOR EACH ROW EXECUTE FUNCTION sp_reject_immutable_change();
CREATE TRIGGER sp_statement_approval_immutable BEFORE UPDATE OR DELETE ON sp_statement_approvals FOR EACH ROW EXECUTE FUNCTION sp_reject_immutable_change();
-- Future finalizations must use reviewed statement evidence. Existing settled journals stay unchanged.
CREATE FUNCTION sp_require_reviewed_statement() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.state IN ('settled','failed') AND OLD.state IS DISTINCT FROM NEW.state AND NOT EXISTS(SELECT 1 FROM sp_bank_evidence_use u JOIN sp_statement_rows r ON r.evidence_id=u.evidence_id JOIN sp_statement_approvals a ON a.batch_id=r.batch_id WHERE u.intent_id=NEW.id AND u.channel='statement') THEN RAISE EXCEPTION 'reviewed_statement_required'; END IF;
 RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER sp_require_reviewed_statement AFTER UPDATE ON sp_bank_intents DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION sp_require_reviewed_statement();
CREATE TABLE sp_bank_consents (
 tenant_id text NOT NULL, consent_ref text NOT NULL, account_id uuid NOT NULL REFERENCES sp_accounts(id),
 provider text NOT NULL, direction text NOT NULL CHECK(direction IN ('deposit','withdrawal')),
 amount bigint NOT NULL CHECK(amount BETWEEN 1 AND 100000000), beneficiary_ref text NOT NULL,
 evidence_digest text NOT NULL CHECK(evidence_digest ~ '^[0-9a-f]{64}$'), actor text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), expires_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,consent_ref), CHECK(expires_at>created_at AND expires_at<=created_at+interval '15 minutes')
);
CREATE TRIGGER sp_bank_consent_immutable BEFORE UPDATE OR DELETE ON sp_bank_consents FOR EACH ROW EXECUTE FUNCTION sp_reject_immutable_change();
CREATE FUNCTION sp_bank_require_consent() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM sp_bank_consents c WHERE c.tenant_id=NEW.tenant_id AND c.consent_ref=NEW.consent_ref AND c.account_id=NEW.account_id AND c.provider=NEW.provider AND c.direction=NEW.direction AND c.amount=NEW.amount AND c.beneficiary_ref=NEW.beneficiary_ref AND c.actor<>NEW.created_by AND c.expires_at>clock_timestamp()) THEN RAISE EXCEPTION 'matching_bank_consent_required'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER sp_bank_require_consent BEFORE INSERT ON sp_bank_intents FOR EACH ROW EXECUTE FUNCTION sp_bank_require_consent();
INSERT INTO sp_schema_version(version) VALUES(5);
COMMIT;
