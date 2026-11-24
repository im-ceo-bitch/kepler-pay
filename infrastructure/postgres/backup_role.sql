-- Dedicated pre-license DB only. Apply after every migration as owner.
-- Grant membership to a separately provisioned named backup login; not API.
BEGIN;
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='spyderpay_backup') THEN CREATE ROLE spyderpay_backup NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; END IF;
END $$;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO spyderpay_backup;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO spyderpay_backup;
GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO spyderpay_backup;
COMMIT;
