-- Apply manually as database administrator AFTER migrating, in a dedicated database.
-- Create login roles separately via the secret manager, then grant them these NOLOGIN groups.
-- Do not grant runtime login membership in the schema owner's role.
BEGIN;
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='spyderpay_runtime') THEN CREATE ROLE spyderpay_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='spyderpay_identity_admin') THEN CREATE ROLE spyderpay_identity_admin NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; END IF;
END $$;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO spyderpay_runtime,spyderpay_identity_admin;
GRANT SELECT ON sp_schema_version,sp_accounts,sp_journals,sp_postings,sp_invoices,sp_idempotency,sp_outbox,sp_audit_events,sp_api_replay,sp_rate_windows,sp_payment_approvals,sp_revoked_sessions TO spyderpay_runtime;
GRANT INSERT(id,tenant_id,owner_id,kind,currency),UPDATE(balance,status) ON sp_accounts TO spyderpay_runtime;
GRANT INSERT(tenant_id,kind,reference,actor,currency),UPDATE(sealed) ON sp_journals TO spyderpay_runtime;
GRANT INSERT(journal_id,account_id,signed_amount,currency) ON sp_postings TO spyderpay_runtime;
GRANT INSERT(tenant_id,merchant_account,amount,expires_at),UPDATE(state,payer_account,payment_journal,refund_journal) ON sp_invoices TO spyderpay_runtime;
GRANT INSERT(actor,idem_key,request_digest),UPDATE(result) ON sp_idempotency TO spyderpay_runtime;
GRANT INSERT(tenant_id,event_type,aggregate_id,payload),UPDATE(delivered_at,attempts,lease_token,leased_until,next_attempt_at) ON sp_outbox TO spyderpay_runtime;
GRANT INSERT(tenant_id,actor,action,target,payload_hash) ON sp_audit_events TO spyderpay_runtime;
GRANT INSERT(key_id,nonce),DELETE ON sp_api_replay TO spyderpay_runtime;
GRANT INSERT(key_id,minute_bucket,hits),UPDATE(hits),DELETE ON sp_rate_windows TO spyderpay_runtime;
GRANT INSERT(issuer,external_sub,sid,tenant_id,owner_id,role,request_digest,idem_key,initiating_jti_hash,expires_at),UPDATE(confirmed_at,expires_at,consumed_at) ON sp_payment_approvals TO spyderpay_runtime;
GRANT USAGE ON SEQUENCE sp_postings_id_seq,sp_audit_events_id_seq TO spyderpay_runtime;
GRANT EXECUTE ON FUNCTION sp_lock_member(text,text) TO spyderpay_runtime;
GRANT SELECT,INSERT,UPDATE(enabled) ON sp_identity_members TO spyderpay_identity_admin;
GRANT SELECT,INSERT ON sp_revoked_sessions TO spyderpay_identity_admin;
GRANT SELECT ON sp_bank_risk,sp_bank_intents,sp_bank_evidence,sp_bank_evidence_use,sp_bank_cases TO spyderpay_runtime;
GRANT INSERT(tenant_id,account_id,state,review_ref,reviewed_by),UPDATE(state,review_ref,reviewed_by,reviewed_at) ON sp_bank_risk TO spyderpay_runtime;
GRANT INSERT(tenant_id,account_id,direction,provider,amount,beneficiary_ref,consent_ref,created_by),UPDATE(state,reviewed_by,provider_ref,hold_account,reserve_journal,final_journal,updated_at) ON sp_bank_intents TO spyderpay_runtime;
GRANT INSERT(tenant_id,provider,channel,event_ref,provider_ref,status,direction,amount,beneficiary_ref,actor,payload_digest) ON sp_bank_evidence TO spyderpay_runtime;
GRANT INSERT(evidence_id,intent_id,channel) ON sp_bank_evidence_use TO spyderpay_runtime;
GRANT INSERT(tenant_id,intent_id,reason,opened_by),UPDATE(state,resolution,closed_by,closed_at) ON sp_bank_cases TO spyderpay_runtime;
-- Intentionally no TRUNCATE, DELETE on financial records, or DDL rights for runtime.
COMMIT;
