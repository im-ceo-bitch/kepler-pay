BEGIN;
SELECT pg_advisory_xact_lock(8421778102);
DO $$ BEGIN IF (SELECT max(version) FROM sp_schema_version)<>8 THEN RAISE EXCEPTION 'schema_8_required'; END IF; END $$;
CREATE TABLE sp_cards (
 id uuid PRIMARY KEY, tenant_id text NOT NULL, owner_id text NOT NULL,
 public_key text NOT NULL UNIQUE CHECK(public_key ~ '^04[0-9a-f]{128}$'),
 created_at timestamptz NOT NULL DEFAULT now(), revoked_at timestamptz,
 CHECK(revoked_at IS NULL OR revoked_at>=created_at)
);
CREATE INDEX sp_cards_owner ON sp_cards(tenant_id,owner_id,created_at);
CREATE TABLE sp_card_challenges (
 id uuid PRIMARY KEY, tenant_id text NOT NULL, owner_id text NOT NULL,
 issuer text NOT NULL, external_sub text NOT NULL, sid text NOT NULL,
 card_id uuid NOT NULL, purpose text NOT NULL CHECK(purpose IN ('enroll','invoice_preview')),
 public_key text NOT NULL CHECK(public_key ~ '^04[0-9a-f]{128}$'),
 nonce text NOT NULL UNIQUE CHECK(nonce ~ '^[0-9a-f]{64}$'),
 invoice_id uuid REFERENCES sp_invoices(id), merchant_account uuid REFERENCES sp_accounts(id),
 amount bigint, created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL,
 consumed_at timestamptz,
 CHECK(expires_at>created_at AND expires_at<=created_at+interval '120 seconds'),
 CHECK(consumed_at IS NULL OR (consumed_at>=created_at AND consumed_at<expires_at)),
 CHECK((purpose='enroll' AND invoice_id IS NULL AND merchant_account IS NULL AND amount IS NULL) OR
 (purpose='invoice_preview' AND invoice_id IS NOT NULL AND merchant_account IS NOT NULL AND amount IS NOT NULL AND amount BETWEEN 1 AND 100000000))
);
CREATE INDEX sp_card_challenges_owner ON sp_card_challenges(tenant_id,owner_id,created_at);
CREATE FUNCTION sp_card_revoke_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'immutable_card'; END IF;
 IF OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NULL OR
 (to_jsonb(NEW)-'revoked_at') IS DISTINCT FROM (to_jsonb(OLD)-'revoked_at') THEN RAISE EXCEPTION 'invalid_card_mutation'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER sp_card_revoke_guard BEFORE UPDATE OR DELETE ON sp_cards FOR EACH ROW EXECUTE FUNCTION sp_card_revoke_only();
CREATE FUNCTION sp_card_consume_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'immutable_card_challenge'; END IF;
 IF OLD.consumed_at IS NOT NULL OR NEW.consumed_at IS NULL OR NEW.consumed_at>=OLD.expires_at OR
 (to_jsonb(NEW)-'consumed_at') IS DISTINCT FROM (to_jsonb(OLD)-'consumed_at') THEN RAISE EXCEPTION 'invalid_card_challenge_mutation'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER sp_card_consume_guard BEFORE UPDATE OR DELETE ON sp_card_challenges FOR EACH ROW EXECUTE FUNCTION sp_card_consume_only();
-- Global write gate: shared row lock is held by every new money mutation;
-- pause waits for existing transactions and blocks future ones across replicas.
CREATE TABLE sp_runtime_gate(singleton boolean PRIMARY KEY CHECK(singleton),paused boolean NOT NULL,generation bigint NOT NULL CHECK(generation>=0),changed_at timestamptz NOT NULL DEFAULT now());
INSERT INTO sp_runtime_gate(singleton,paused,generation) VALUES(true,false,0);
CREATE TABLE sp_gate_events(generation bigint PRIMARY KEY CHECK(generation>0),paused boolean NOT NULL,actor text NOT NULL,incident_ref text NOT NULL CHECK(incident_ref ~ '^[A-Za-z0-9_.:-]{6,96}$'),created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE sp_gate_resume_requests(id uuid PRIMARY KEY DEFAULT gen_random_uuid(),generation bigint NOT NULL REFERENCES sp_gate_events(generation),maker text NOT NULL,incident_ref text NOT NULL CHECK(incident_ref ~ '^[A-Za-z0-9_.:-]{6,96}$'),created_at timestamptz NOT NULL DEFAULT now());
CREATE TRIGGER sp_gate_events_immutable BEFORE UPDATE OR DELETE ON sp_gate_events FOR EACH ROW EXECUTE FUNCTION sp_reject_immutable_change();
CREATE TRIGGER sp_gate_requests_immutable BEFORE UPDATE OR DELETE ON sp_gate_resume_requests FOR EACH ROW EXECUTE FUNCTION sp_reject_immutable_change();
CREATE FUNCTION sp_gate_open() RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT NOT g.paused FROM public.sp_runtime_gate g WHERE singleton FOR SHARE OF g
$$;
CREATE FUNCTION sp_gate_pause(ref text) RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE g public.sp_runtime_gate%ROWTYPE;
BEGIN
 IF ref IS NULL OR ref !~ '^[A-Za-z0-9_.:-]{6,96}$' THEN RAISE EXCEPTION 'invalid_incident_ref'; END IF;
 SELECT * INTO STRICT g FROM public.sp_runtime_gate WHERE singleton FOR UPDATE;
 IF g.paused THEN RETURN g.generation; END IF;
 UPDATE public.sp_runtime_gate SET paused=true,generation=g.generation+1,changed_at=clock_timestamp() WHERE singleton;
 INSERT INTO public.sp_gate_events(generation,paused,actor,incident_ref) VALUES(g.generation+1,true,session_user,ref);
 RETURN g.generation+1;
END $$;
CREATE FUNCTION sp_gate_propose_resume(ref text) RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE g public.sp_runtime_gate%ROWTYPE; rid uuid;
BEGIN
 IF ref IS NULL OR ref !~ '^[A-Za-z0-9_.:-]{6,96}$' THEN RAISE EXCEPTION 'invalid_incident_ref'; END IF;
 SELECT * INTO STRICT g FROM public.sp_runtime_gate WHERE singleton FOR SHARE;
 IF NOT g.paused THEN RAISE EXCEPTION 'gate_not_paused'; END IF;
 INSERT INTO public.sp_gate_resume_requests(generation,maker,incident_ref) VALUES(g.generation,session_user,ref) RETURNING id INTO rid;
 RETURN rid;
END $$;
CREATE FUNCTION sp_gate_confirm_resume(rid uuid,ref text) RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE g public.sp_runtime_gate%ROWTYPE; r public.sp_gate_resume_requests%ROWTYPE;
BEGIN
 SELECT * INTO STRICT g FROM public.sp_runtime_gate WHERE singleton FOR UPDATE;
 SELECT * INTO STRICT r FROM public.sp_gate_resume_requests WHERE id=rid;
 IF NOT g.paused OR r.generation<>g.generation OR r.maker=session_user OR ref IS DISTINCT FROM r.incident_ref OR r.created_at<clock_timestamp()-interval '15 minutes' THEN RAISE EXCEPTION 'resume_review_forbidden'; END IF;
 UPDATE public.sp_runtime_gate SET paused=false,generation=g.generation+1,changed_at=clock_timestamp() WHERE singleton;
 INSERT INTO public.sp_gate_events(generation,paused,actor,incident_ref) VALUES(g.generation+1,false,session_user,ref);
 RETURN g.generation+1;
END $$;
REVOKE ALL ON FUNCTION sp_gate_open(),sp_gate_pause(text),sp_gate_propose_resume(text),sp_gate_confirm_resume(uuid,text) FROM PUBLIC;
INSERT INTO sp_schema_version(version) VALUES(9);
COMMIT;
