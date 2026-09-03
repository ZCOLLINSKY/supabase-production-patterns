# Supabase backup and restore runbook

LightDeck uses two complementary recovery layers. Both must be proven before a
production schema/data migration or restore:

1. **Supabase managed backups and PITR** are the authoritative database-level
   recovery layer. They are transaction-consistent and cover recovery cases a
   REST export cannot. Confirm a recent restore point and the purchased
   retention window in the Supabase dashboard before every migration.
2. **The private-Blob logical export** is a defense-in-depth, row-readable copy
   of every table exposed to the service role through PostgREST. It is useful
   for recovering selected rows after the managed-backup window has passed.

The logical export is ordered and count-checked per table, but it is **not a
transaction-consistent snapshot, even within one table**: every PostgREST page
and verification check is a separate database request, so writes can occur
between pages as well as between tables. The exporter fails closed on detectable
count, schema, duplicate-key, and after-cursor drift. It still cannot prove a
single MVCC point in time; for example, same-primary-key value changes or churn
entirely behind an already-exported cursor can produce a time-mixed logical copy
without violating those structural checks. It does not include unexposed
schemas such as Supabase Auth internals. Managed backups/PITR remain the
authoritative recovery and pre-migration layer.

For the one-time bootstrap of this backup endpoint, first confirm the managed
Supabase recovery point, deploy only the additive backup endpoint/configuration,
then immediately trigger and verify the first logical recovery point. Do not
couple that bootstrap deployment to a schema migration.

PITR is not enabled on this project yet, and no restore has been rehearsed. Until both are done, the verified logical export is the only recovery point I can prove, and the managed layer above is written as the target state, not the current one.

## Scheduled private-Blob export

Vercel invokes `GET /api/backup-supabase` daily at 05:17 UTC. The function has a
300-second platform limit and stops internally before that deadline so it can
emit a failure signal. It never writes to Vercel's ephemeral filesystem.

Required production environment variables:

- `CRON_SECRET`: a random value of at least 16 bytes. Vercel sends it as the
  exact `Authorization: Bearer ...` header. Missing or incorrect auth performs
  no backup or monitoring write.
- `SUPABASE_URL`
- `SUPABASE_SERVICE_ROLE_KEY`
- `SUPABASE_BACKUP_BLOB_READ_WRITE_TOKEN`: the token for a **dedicated private
  Vercel Blob store**. Never reuse `BLOB_READ_WRITE_TOKEN` or
  `LIGHTDECK_EDITABLE_BLOB_READ_WRITE_TOKEN`; those tokens belong to the public
  proposal-image store and private editable-photo store respectively, and Blob
  access mode is store-level.

Required for production monitoring:

- `HEALTHCHECK_BACKUP_URL`: a Healthchecks.io ping URL configured for a daily
  period plus a suitable grace window. The cron sends `/start`, the base URL on
  success, and `/fail` on an authenticated run failure.

`npm run verify:prod-config -- <downloaded-env-file>` exits nonzero when any of
the three backup-specific names above is absent or blank. Its diagnostics print
variable names only, never credential values.

Optional bounded settings:

- `SUPABASE_BACKUP_RETENTION_DAYS`: default `90`, allowed `7..3650`.
- `SUPABASE_BACKUP_PAGE_SIZE`: default `250`, allowed `25..1000`.
- `SUPABASE_BACKUP_MAX_BYTES`: default 512 MiB, allowed 1 MiB..10 GiB.

Missing/malformed configuration, or reuse of either image-store token, fails
closed with HTTP 503. A dedicated token whose store does not actually permit
private writes fails the authenticated backup with HTTP 500 and no recovery-
point marker. There is no fallback table list: if authenticated OpenAPI
discovery fails, the run fails rather than silently omitting a newly added table.

## Recovery-point format and failure behavior

Each run has an immutable prefix:

```text
lightdeck-backups/supabase/<run-id>/
  tables/<table>/page-000001.json.gz
  tables/<table>/page-000002.json.gz
  manifest.json
  verified.json
  retention.json
```

Tables use primary-key keyset pagination rather than a shifting offset. The
first page captures an exact row count. After exporting that many rows, one
additional request asks for at most one row after the final primary-key cursor;
any result proves the starting count displaced a legitimate tail row and fails
the run. A final `HEAD` request checks that the count did not change, and a
second OpenAPI discovery checks that the table/column/primary-key schema did not
change during the run. Oversized responses are cancelled and retried with a
smaller page size, down to one row; every response and the whole run remain
byte-bounded. Exact canonical primary-key identities are tracked across the
whole table, not reset at page boundaries, so a repeated earlier page cannot
satisfy the starting row count and become a recovery point. Identity count,
individual size, and aggregate retained identity bytes have hard safety limits;
exceeding one fails the run instead of allowing unbounded memory growth. These
checks detect important live-write hybrids but do not turn independent
PostgREST requests into an MVCC snapshot; use managed backups/PITR whenever a
transaction-consistent recovery point is required.

Every stored page has compressed and raw SHA-256 values, byte counts, and a row
count in `manifest.json`. The manifest also records table primary keys, columns,
table totals, whole-run totals, and the discovered-schema hash.

- A failed discovery/table/page/count/schema check attempts to write
  `manifest.failed.json`. Partial pages can remain for diagnosis or salvage,
  but no `manifest.json` exists and the run is not a recovery point.
- A complete `manifest.json` is necessary but is not by itself a recovery
  point. The function privately reads the manifest and every referenced page
  back from Blob, rechecks compressed and raw hashes and byte/row totals,
  decompresses with a hard bound, validates primary-key values, and reconciles
  the exact Blob page inventory.
- Only after that full read-back succeeds does the function publish the
  immutable `verified.json` recovery-point marker. A read-back failure writes
  `verification.failed.json` when possible and never starts retention.
- Retention validates each candidate marker and its manifest hash, keeps at
  least the seven newest verified recovery points regardless of age (failed,
  manifest-only, and corrupt-marker runs do not consume a protection slot), and
  writes `retention.json` separately.
- A retention failure attempts to write `retention.failed.json`, returns HTTP
  500, and emits `/fail`; the already-read-back-verified recovery point remains
  valid.
- No API response or log contains Supabase or Blob credentials.

## Verify a backup before relying on it

Verification is read-only and must happen regularly, not for the first time
during an incident. With the private-store token in the environment:

```bash
node scripts/verify-supabase-backup.mjs
```

That selects the newest run advertising an immutable `verified.json` marker and
then independently re-verifies its manifest and all data pages. To verify a
specific run:

```bash
node scripts/verify-supabase-backup.mjs --run=<run-id>
```

The verifier privately downloads every referenced page, checks compressed
SHA-256, decompresses with a hard size bound, checks raw SHA-256, parses each
JSON array, validates primary-key values, and reconciles page, table, manifest,
and Blob-inventory totals. Any missing, extra, corrupted, oversized, duplicate-
key, or mismatched page exits nonzero.

Record the verified run ID and verification output before applying a migration.
Merely seeing blobs in the dashboard is not proof that they are readable.

## Legacy local exporter

`scripts/backup-supabase.mjs` is read-only, but it uses offset pagination and can
fall back to a hard-coded table list. It therefore cannot prove a complete,
stable production snapshot while writes are active and **must not be used as
pre-migration recovery evidence**. The managed backup plus a newly verified
private-Blob run are the release requirement.

The legacy script remains available only for an explicitly scoped,
operator-held salvage copy (prefer a quiesced source and an explicit `--tables`
list):

```bash
SUPABASE_URL=https://<project>.supabase.co \
SUPABASE_SERVICE_ROLE_KEY=<service-role-key> \
node scripts/backup-supabase.mjs --out=/path/on/encrypted-durable-storage
```

Its output contains client PII and payment metadata. Store it only on encrypted
durable storage, never in the repository. A laptop-local export is supplementary
and is neither the scheduled production backup nor a valid migration gate.

## Manual restore procedure

There is intentionally no automatic production restore command.

1. Confirm the exact production project identity and preserve the current state.
2. Prefer Supabase managed restore/PITR for whole-database or relationally
   consistent recovery.
3. For selected-row recovery, run the verifier above against the chosen logical
   run before extracting any data.
4. Download only the required private page objects with authenticated Vercel
   Blob tooling. Verify their compressed and raw hashes against `manifest.json`
   again, then inspect the decompressed JSON offline.
5. Restore first into an isolated Supabase branch or temporary database. Diff
   primary keys, foreign keys, tenant ownership, and money fields.
6. Prepare a reviewed, narrowly scoped SQL/REST change for the missing rows.
   Never bulk-replace a production table from logical pages.
7. Take a fresh managed backup and require a successful logical-backup response
   with `verified: true`, record its run ID and verification totals, re-run the
   verifier against that exact run, obtain explicit approval, apply the scoped
   repair, and run the affected API/invariant checks.

The scheduled export protects recovery options; it never authorizes a restore.
