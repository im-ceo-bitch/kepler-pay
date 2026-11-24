-- Durable, single-issue sandbox dispatch permission. External transmission is never atomic with SQL.
BEGIN;
SELECT pg_advisory_xact_lock(8421778102);
CREATE TABLE sp_rail_dispatch (
 intent_id uuid PRIMARY KEY REFERENCES sp_bank_intents(id),
 tenant_id text NOT NULL,
 request_ref text NOT NULL,
 instruction_digest text NOT NULL CHECK(instruction_digest ~ '^[0-9a-f]{64}$'),
 actor text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,request_ref)
);
CREATE TABLE sp_rail_dispatch_result (
 intent_id uuid PRIMARY KEY REFERENCES sp_rail_dispatch(intent_id),
 actor text NOT NULL,
 outcome text NOT NULL CHECK(outcome IN ('accepted','unknown','not_dispatched')),
 observed_at timestamptz NOT NULL DEFAULT now()
);
CREATE FUNCTION sp_dispatch_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM sp_bank_intents i WHERE i.id=NEW.intent_id AND i.tenant_id=NEW.tenant_id AND i.state='submitted' AND i.provider_ref=NEW.request_ref AND NEW.request_ref='sp-'||i.id::text AND NEW.actor<>i.reviewed_by AND NEW.actor<>i.created_by) THEN
  RAISE EXCEPTION 'invalid_dispatch_permission';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER sp_dispatch_guard BEFORE INSERT ON sp_rail_dispatch FOR EACH ROW EXECUTE FUNCTION sp_dispatch_guard();
CREATE FUNCTION sp_dispatch_result_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM sp_rail_dispatch d WHERE d.intent_id=NEW.intent_id AND d.actor=NEW.actor) THEN
  RAISE EXCEPTION 'invalid_dispatch_actor';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER sp_dispatch_result_guard BEFORE INSERT ON sp_rail_dispatch_result FOR EACH ROW EXECUTE FUNCTION sp_dispatch_result_guard();
CREATE TRIGGER sp_dispatch_immutable BEFORE UPDATE OR DELETE ON sp_rail_dispatch FOR EACH ROW EXECUTE FUNCTION sp_reject_immutable_change();
CREATE TRIGGER sp_dispatch_result_immutable BEFORE UPDATE OR DELETE ON sp_rail_dispatch_result FOR EACH ROW EXECUTE FUNCTION sp_reject_immutable_change();
-- No result record is not proof of a failed transfer. Never clear a reservation on this basis.
CREATE INDEX sp_dispatch_tenant_created ON sp_rail_dispatch(tenant_id,created_at);
INSERT INTO sp_schema_version(version) VALUES(6);
COMMIT;
