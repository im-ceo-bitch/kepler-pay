-- Pre-license bank simulator workflow. No live money or network connectors.
BEGIN;
SELECT pg_advisory_xact_lock(8421778102);
CREATE TABLE sp_bank_risk (
 tenant_id text NOT NULL, account_id uuid NOT NULL REFERENCES sp_accounts(id),
 state text NOT NULL CHECK(state IN ('approved','review','blocked')),
 review_ref text NOT NULL, reviewed_by text NOT NULL, reviewed_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(tenant_id,account_id)
);
CREATE TABLE sp_bank_intents (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id text NOT NULL,
 account_id uuid NOT NULL REFERENCES sp_accounts(id), direction text NOT NULL CHECK(direction IN ('deposit','withdrawal')),
 provider text NOT NULL CHECK(provider ~ '^sandbox-[a-z0-9-]{2,40}$'), amount bigint NOT NULL CHECK(amount BETWEEN 1 AND 100000000),
 beneficiary_ref text NOT NULL, consent_ref text NOT NULL, created_by text NOT NULL,
 reviewed_by text, provider_ref text, state text NOT NULL DEFAULT 'created'
 CHECK(state IN ('created','authorized','submitted','unknown','settled','failed','cancelled')),
 hold_account uuid UNIQUE REFERENCES sp_accounts(id), reserve_journal uuid UNIQUE REFERENCES sp_journals(id),
 final_journal uuid UNIQUE REFERENCES sp_journals(id), created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,provider,provider_ref), UNIQUE(tenant_id,consent_ref),
 CHECK(reviewed_by IS NULL OR reviewed_by<>created_by),
 CHECK(direction='withdrawal' OR (hold_account IS NULL AND reserve_journal IS NULL)),
 CHECK((hold_account IS NULL)=(reserve_journal IS NULL)),
 CHECK(state NOT IN ('authorized','submitted','unknown','settled','failed') OR reviewed_by IS NOT NULL),
 CHECK(state NOT IN ('submitted','unknown','settled','failed') OR provider_ref IS NOT NULL),
 CHECK(state NOT IN ('created','authorized','submitted','unknown') OR final_journal IS NULL),
 CHECK(state<>'settled' OR final_journal IS NOT NULL)
);
CREATE INDEX sp_bank_intents_pending ON sp_bank_intents(tenant_id,state,updated_at);
CREATE TABLE sp_bank_evidence (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id text NOT NULL, provider text NOT NULL CHECK(provider ~ '^sandbox-[a-z0-9-]{2,40}$'),
 channel text NOT NULL CHECK(channel IN ('callback','statement')), event_ref text NOT NULL, provider_ref text NOT NULL,
 status text NOT NULL CHECK(status IN ('settled','failed')), direction text NOT NULL CHECK(direction IN ('deposit','withdrawal')),
 amount bigint NOT NULL CHECK(amount BETWEEN 1 AND 100000000), beneficiary_ref text NOT NULL,
 actor text NOT NULL, payload_digest text NOT NULL CHECK(length(payload_digest)=64), created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,provider,channel,event_ref)
);
CREATE INDEX sp_bank_evidence_match ON sp_bank_evidence(tenant_id,provider,provider_ref,channel);
CREATE TABLE sp_bank_evidence_use (
 evidence_id uuid PRIMARY KEY REFERENCES sp_bank_evidence(id), intent_id uuid NOT NULL REFERENCES sp_bank_intents(id),
 channel text NOT NULL CHECK(channel IN ('callback','statement')), UNIQUE(intent_id,channel)
);
CREATE TABLE sp_bank_cases (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id text NOT NULL, intent_id uuid NOT NULL REFERENCES sp_bank_intents(id),
 reason text NOT NULL, opened_by text NOT NULL, opened_at timestamptz NOT NULL DEFAULT now(),
 state text NOT NULL DEFAULT 'open' CHECK(state IN ('open','closed')), resolution text, closed_by text, closed_at timestamptz,
 CHECK((state='open' AND resolution IS NULL AND closed_by IS NULL AND closed_at IS NULL) OR (state='closed' AND resolution IS NOT NULL AND closed_by IS NOT NULL AND closed_at IS NOT NULL AND closed_by<>opened_by))
);
CREATE UNIQUE INDEX sp_bank_open_case ON sp_bank_cases(intent_id,reason) WHERE state='open';
CREATE TRIGGER sp_bank_evidence_immutable BEFORE UPDATE OR DELETE ON sp_bank_evidence FOR EACH ROW EXECUTE FUNCTION sp_reject_immutable_change();
CREATE TRIGGER sp_bank_evidence_use_immutable BEFORE UPDATE OR DELETE ON sp_bank_evidence_use FOR EACH ROW EXECUTE FUNCTION sp_reject_immutable_change();
CREATE FUNCTION sp_bank_intent_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'immutable_bank_intent' USING ERRCODE='23000'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.state<>'created' OR NEW.reviewed_by IS NOT NULL OR NEW.provider_ref IS NOT NULL OR NEW.hold_account IS NOT NULL OR NEW.final_journal IS NOT NULL THEN RAISE EXCEPTION 'invalid_initial_bank_intent'; END IF;
  IF NOT EXISTS(SELECT 1 FROM sp_accounts WHERE id=NEW.account_id AND tenant_id=NEW.tenant_id AND kind IN ('customer','merchant')) THEN RAISE EXCEPTION 'invalid_bank_account'; END IF;
  RETURN NEW;
 END IF;
 IF (to_jsonb(NEW)-'state'-'reviewed_by'-'provider_ref'-'hold_account'-'reserve_journal'-'final_journal'-'updated_at') IS DISTINCT FROM (to_jsonb(OLD)-'state'-'reviewed_by'-'provider_ref'-'hold_account'-'reserve_journal'-'final_journal'-'updated_at') OR (OLD.reviewed_by IS NOT NULL AND NEW.reviewed_by IS DISTINCT FROM OLD.reviewed_by) OR (OLD.provider_ref IS NOT NULL AND NEW.provider_ref IS DISTINCT FROM OLD.provider_ref) OR (OLD.reserve_journal IS NOT NULL AND (NEW.reserve_journal IS DISTINCT FROM OLD.reserve_journal OR NEW.hold_account IS DISTINCT FROM OLD.hold_account)) THEN RAISE EXCEPTION 'immutable_bank_terms'; END IF;
 IF NOT ((OLD.state='created' AND NEW.state IN ('authorized','cancelled')) OR (OLD.state='authorized' AND NEW.state IN ('submitted','cancelled')) OR (OLD.state='submitted' AND NEW.state IN ('unknown','settled','failed')) OR (OLD.state='unknown' AND NEW.state IN ('settled','failed'))) THEN RAISE EXCEPTION 'invalid_bank_transition'; END IF;
 IF NEW.direction='withdrawal' AND NEW.state IN ('authorized','submitted','unknown','settled','failed') AND NEW.reserve_journal IS NULL THEN RAISE EXCEPTION 'missing_reservation'; END IF;
 IF NEW.direction='withdrawal' AND NEW.state IN ('failed','settled','cancelled') AND NEW.reserve_journal IS NOT NULL AND NEW.final_journal IS NULL THEN RAISE EXCEPTION 'missing_release_or_settlement'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER sp_bank_intent_guard_trigger BEFORE INSERT OR UPDATE OR DELETE ON sp_bank_intents FOR EACH ROW EXECUTE FUNCTION sp_bank_intent_guard();
CREATE FUNCTION sp_bank_check_links() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE j uuid; k text; src uuid; dst uuid; n bigint;
BEGIN
 IF NEW.hold_account IS NOT NULL THEN
  IF NOT EXISTS(SELECT 1 FROM sp_accounts WHERE id=NEW.hold_account AND tenant_id=NEW.tenant_id AND kind='system' AND owner_id='bank-sandbox') THEN RAISE EXCEPTION 'invalid_bank_hold_account'; END IF;
  IF NOT EXISTS(SELECT 1 FROM sp_journals WHERE id=NEW.reserve_journal AND tenant_id=NEW.tenant_id AND kind='bank_reserve' AND reference=NEW.id::text AND sealed) OR (SELECT count(*) FROM sp_postings WHERE journal_id=NEW.reserve_journal)<>2 OR NOT EXISTS(SELECT 1 FROM sp_postings WHERE journal_id=NEW.reserve_journal AND account_id=NEW.account_id AND signed_amount=-NEW.amount) OR NOT EXISTS(SELECT 1 FROM sp_postings WHERE journal_id=NEW.reserve_journal AND account_id=NEW.hold_account AND signed_amount=NEW.amount) THEN RAISE EXCEPTION 'invalid_bank_reservation'; END IF;
 END IF;
 IF NEW.state IN ('settled','failed') THEN
  IF (SELECT count(*) FROM sp_bank_evidence_use u JOIN sp_bank_evidence e ON e.id=u.evidence_id WHERE u.intent_id=NEW.id AND u.channel=e.channel AND e.tenant_id=NEW.tenant_id AND e.provider=NEW.provider AND e.provider_ref=NEW.provider_ref AND e.direction=NEW.direction AND e.amount=NEW.amount AND e.beneficiary_ref=NEW.beneficiary_ref AND e.status=NEW.state)<>2 OR (SELECT count(DISTINCT e.actor) FROM sp_bank_evidence_use u JOIN sp_bank_evidence e ON e.id=u.evidence_id WHERE u.intent_id=NEW.id)<>2 THEN RAISE EXCEPTION 'invalid_bank_evidence_links'; END IF;
 END IF;
 IF NEW.final_journal IS NOT NULL THEN
  j:=NEW.final_journal;
  IF NEW.state='settled' AND NEW.direction='deposit' THEN k:='bank_deposit';dst:=NEW.account_id;
  ELSIF NEW.state='settled' AND NEW.direction='withdrawal' THEN k:='bank_withdrawal';src:=NEW.hold_account;
  ELSIF NEW.state IN ('failed','cancelled') AND NEW.direction='withdrawal' THEN k:='bank_release';src:=NEW.hold_account;dst:=NEW.account_id;
  ELSE RAISE EXCEPTION 'unexpected_bank_final_journal'; END IF;
  IF NOT EXISTS(SELECT 1 FROM sp_journals WHERE id=j AND tenant_id=NEW.tenant_id AND kind=k AND reference=NEW.id::text AND sealed) OR (SELECT count(*) FROM sp_postings WHERE journal_id=j)<>2 THEN RAISE EXCEPTION 'invalid_bank_final_journal'; END IF;
  IF src IS NOT NULL AND NOT EXISTS(SELECT 1 FROM sp_postings WHERE journal_id=j AND account_id=src AND signed_amount=-NEW.amount) THEN RAISE EXCEPTION 'invalid_bank_source'; END IF;
  IF dst IS NOT NULL AND NOT EXISTS(SELECT 1 FROM sp_postings WHERE journal_id=j AND account_id=dst AND signed_amount=NEW.amount) THEN RAISE EXCEPTION 'invalid_bank_destination'; END IF;
  IF src IS NULL AND NOT EXISTS(SELECT 1 FROM sp_postings p JOIN sp_accounts a ON a.id=p.account_id WHERE p.journal_id=j AND p.signed_amount=-NEW.amount AND a.kind='system' AND a.owner_id='bank-sandbox') THEN RAISE EXCEPTION 'invalid_bank_clearing'; END IF;
  IF dst IS NULL AND NOT EXISTS(SELECT 1 FROM sp_postings p JOIN sp_accounts a ON a.id=p.account_id WHERE p.journal_id=j AND p.signed_amount=NEW.amount AND a.kind='system' AND a.owner_id='bank-sandbox') THEN RAISE EXCEPTION 'invalid_bank_clearing'; END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER sp_bank_links BEFORE UPDATE ON sp_bank_intents FOR EACH ROW EXECUTE FUNCTION sp_bank_check_links();
CREATE FUNCTION sp_bank_case_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'immutable_bank_case'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.state<>'open' OR NOT EXISTS(SELECT 1 FROM sp_bank_intents WHERE id=NEW.intent_id AND tenant_id=NEW.tenant_id) THEN RAISE EXCEPTION 'invalid_bank_case'; END IF;
 ELSIF OLD.state<>'open' OR NEW.state<>'closed' OR (to_jsonb(NEW)-'state'-'resolution'-'closed_by'-'closed_at') IS DISTINCT FROM (to_jsonb(OLD)-'state'-'resolution'-'closed_by'-'closed_at') THEN RAISE EXCEPTION 'immutable_bank_case'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER sp_bank_case_guard_trigger BEFORE INSERT OR UPDATE OR DELETE ON sp_bank_cases FOR EACH ROW EXECUTE FUNCTION sp_bank_case_guard();
INSERT INTO sp_schema_version(version) VALUES(4);
COMMIT;
