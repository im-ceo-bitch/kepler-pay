# Pre-license staging operations (block 3 start)

Never store or process real customer funds here. Network ingress must be private;
no public access to the API, database, administrative routes or simulator.

## Deploy
- Use a dedicated private database, secret manager, separately authenticated IdP,
  and distinct login principals for owner/migration, runtime and identity admin.
- Take and verify a database backup before migrating; run migration once under
  owner using `python -m spyderpay_core.postgres.ops.migrate`, then apply
  `spyderpay_core/postgres/ops/runtime_roles.sql` as DB administrator.
- Use the nonroot container reference in `infrastructure/container/Dockerfile`;
  build from repository root. Place reverse proxy in same network namespace as
  API (binds loopback). Enforce read-only root FS, dropped capabilities,
  no-new-privileges, resource limits and private egress/ingress ACLs. Inject DSN
  and identity/service config from secret manager; never place in git or images.
- Base image digest, dependency lockfile and image SBOM/signing still need
  externally verified release pipeline. Dockerfile has not been built here.
- Verify live `/health/live` and signed `/v3/ops/ready` and `/v3/ops/health` per
  tenant before traffic. `/v3/ops/health` reports counts only, not an assertion
  of availability for all external dependencies. Refuse any real-money mode.

## Alert and recover
- Critical: ledger or hold mismatch or wrong schema. Stop financial traffic at
  ingress; preserve evidence; do not edit balances or reopen sealed journals.
  Escalate to two authorized incident responders. Compare journals and statements.
- Degraded: stale bank intents, approved evidence backlog or event queue lag.
  Investigate existing reference; never retry an ambiguous bank debit as new.
- Notify ops via external monitoring; metrics endpoint must not be publicly exposed.
  Alert thresholds are staging examples, not contractual SLOs.
- Backup and restore rehearsal must use a dedicated isolated test environment,
  with encrypted backups, independent checksum and access control. Restore into
  an empty separate database, run migrations, compare counts, journal balances,
  bank holds and event delivery state. Verify all tenants, record restore time
  and recovery point; no restore over a live database.
- After suspected compromise, freeze affected financial traffic, revoke service
  credentials and sessions through trusted controls; rotate keys out of band.
  Preserve audit evidence, review transactions, reopen only with dual approval.

## v0.6 dispatch incident
- No response to claim: check signed GET; never issue a second transfer based on absence of an HTTP response.
- No response to bank submit: lookup the same request reference, reconcile independent callback/statement evidence, and escalate. Keep holds until definitive settlement/failure evidence.
- On `stale_dispatch`, `exhausted_outbox`, `conflicting_bank_evidence`, or `unmatched_bank_evidence`, route to the incident owner. Do not delete evidence or manually change account balances.
- API startup now performs DB runtime privilege preflight. Apply the current canonical SQL grant script after migration. Investigate permission failures; never fix them by running as database owner.

## Still open for block 3
Load/chaos/failover tests, externally monitored SLO, backup/restore drill,
managed KMS/HSM and credential rotation, hardware NFC card and POS integration,
merchant interface, regional availability and independent penetration test.

## v0.7 restore verification and POS
- Keep backup encryption and signing keys separate from runtime credentials. Sign the canonical bytes from `spyderpay_core.postgres.ops.recovery.manifest_bytes` with a trusted independent Ed25519 signing service. Manifest schema: `{format:1,backup_id,sha256,size,schema,environment:"prelicense"}`. The hash covers encrypted backup bytes. The detached signature is base64 of 64 raw bytes. Do not trust a public key shipped alongside the backup; configure the independently pinned key.
- `SPYDERPAY_ENV=prelicense python -m spyderpay_core.postgres.ops.recovery verify /secure/encrypted-backup /secure/manifest.json /secure/signature.txt`. On failure quarantine; do not extract or restore. Keep verified bytes in immutable storage between verification and restore; decrypt in isolated trusted environment using the approved tool. Use approved pg_restore process in a NEW empty private database only, with separate credentials, never overwrite a running DB. Record original snapshot counts and time; compare to restored results; verify WAL/PITR separately.
- Restore check: set `SPYDERPAY_RESTORE_PG_DSN` to a dedicated read-only connection to a DB named `sp_restore_<unique_suffix>`; then `SPYDERPAY_ENV=prelicense python -m spyderpay_core.postgres.ops.recovery inspect`. It detects several invariants, not proof of full source completeness. Test failure scenarios before promoting. Do not use the staging role as DB owner.
- POS is disabled without `SPYDERPAY_POS_KEYS_JSON`. Sandbox config `{active_kid,private_b64,keys:[{kid,public_b64,not_before,not_after}]}`. Times are epoch seconds; raw Ed25519 private/public bytes base64-encoded; generate outside code, store in secret manager, never include in a ZIP. Key lifetime max 90 days; token lifetime max 90 seconds. For rotation preload public verification keys, switch active signer via trusted deployment, keep old keys until tokens expire, then remove. Compromised key must be removed immediately. Never put the signing key into a merchant/mobile client. Local key import is not HSM-backed.
- Critical alerts: `invalid_fees`, `invalid_chargebacks`; degraded: `stale_chargebacks`. No manual edits to ledgers or dispute tables. Keep financial traffic closed until independently reconciled.
