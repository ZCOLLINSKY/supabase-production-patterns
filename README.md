# Supabase production patterns

Real migrations from a production Supabase Postgres database that runs [LightDeck](https://www.lightdeck.tech), a vertical SaaS for lighting contractors. The application is a set of Vercel serverless functions that talk to Postgres through the service role. The browser never touches application data directly.

These are the real migration files from the private repository, byte for byte, with the project reference and customer data stripped. What I can prove about application is narrower than "it all ran," and the repository says so: one of these carries a dated production receipt, most were applied by hand in the SQL editor with no receipt recorded, and two still carry an `(UNAPPLIED)` header because that is their honest state. Each file's header explains why it exists and what it refuses to assume.

**Start here:** [`sql/2026-07-16-durable-rate-limit-ledger.sql`](sql/2026-07-16-durable-rate-limit-ledger.sql) (156 lines, one table, one RPC, shape validation before replacing the function) or [`sql/2026-07-16-stripe-event-claims.sql`](sql/2026-07-16-stripe-event-claims.sql) (webhook claims with a bounded lease).

Published 2026-09-03, extracted from the private repository so the work is inspectable ahead of Supabase Select. The commit dates here are the extraction date, not when the code was written; the SQL headers carry their own authoring dates.

## The constraint that shapes everything

Serverless functions have no shared memory and no guaranteed single instance. Any state that must be agreed on across requests, retries, and concurrent webhooks has to live in Postgres, and it has to be written so a re-run, a partial prior apply, or a crash mid-effect converges instead of corrupting.

## Supabase features in use, and not in use

Used: Postgres (the whole data plane), Row Level Security enabled and forced on every application table, PostgREST through the service role from Vercel functions, SQL functions as RPCs (`SECURITY DEFINER` with pinned `search_path`), row triggers for immutability and append-only enforcement, an event trigger for future-object lockdown, partial and unique indexes, identity columns, `jsonb` with `CHECK`-enforced shape, `lock_timeout` on most migrations, managed backups as the recovery layer the runbook designates authoritative (turning on PITR is still on my go-live list), and the Supabase CLI migration folder for the newest migrations.

Not used, on purpose: Supabase Auth (sign-in is Google ID-token verification plus LightDeck-minted magic links and sessions in Postgres), Edge Functions (the API is Vercel serverless), Storage (files live in Vercel Blob), and Realtime. Saying so here so nobody reads more into the stack than is there.

## Patterns

### 1. Durable rate limiting in Postgres
[`sql/2026-07-16-durable-rate-limit-ledger.sql`](sql/2026-07-16-durable-rate-limit-ledger.sql)

One row per account per day. A `charge_ai_usage` RPC does the insert-or-update and the limit check in one statement, returning `ok, units, remaining`. The application fails closed in production when the ledger is unreachable, so this migration ships in the release bundle rather than being assumed from history. The file validates the existing table shape before replacing the function and rebuilds the unique index instead of trusting a same-named legacy one.

### 2. Idempotent, retry-safe render attempts
[`sql/2026-08-16-render-attempt-idempotency.sql`](sql/2026-08-16-render-attempt-idempotency.sql) and [`sql/2026-08-17-fix-claim-render-attempt-ambiguity.sql`](sql/2026-08-17-fix-claim-render-attempt-ambiguity.sql)

Image generation is slow and expensive, and clients retry. Every attempt is keyed by a SHA-256 of its fingerprint. The store is a compare-and-swap on `state in ('in-progress','succeeded','terminal-failed')`; a retry with the same attempt id gets the exact recorded artifact back. Seven-day retention with a `SECURITY DEFINER` purge function.

The second file is the honest part. The first applied version raised SQLSTATE 42702 (ambiguous column) on every call, so the API fail-closed at 503 for all renders until `#variable_conflict use_column` was added. Both the bug and the fix are kept so the history is reviewable.

### 3. Stripe webhook ownership with a bounded lease
[`sql/2026-07-16-stripe-event-claims.sql`](sql/2026-07-16-stripe-event-claims.sql)

An invocation atomically claims an event, holds a lease while applying it, and marks completion only afterward. Two concurrent deliveries of the same event cannot both apply it. Rows written by the older insert-after-effects implementation keep their dedupe meaning through the upgrade.

### 4. Row-embedded outbox for paid-invoice effects
[`sql/2026-07-15-invoice-effect-outbox.sql`](sql/2026-07-15-invoice-effect-outbox.sql) and [`sql/2026-07-17-invoice-effect-lease.sql`](sql/2026-07-17-invoice-effect-lease.sql)

The same conditional `PATCH` that commits `status='paid'` also writes `paid_effects_status='pending'`. A crash after that commit leaves durable work for the lifecycle sweep (receipt, review request, checkout-session invalidation) instead of losing it. The lease file adds row-level claims so two workers cannot both send, and per-channel completion so a retry never re-sends a channel that already succeeded.

### 5. Append-only provenance receipts
[`sql/2026-08-01-render-receipts.sql`](sql/2026-08-01-render-receipts.sql)

Every render and presentation is bound to hashes: design, source photo, output bytes. Rows are append-only via a mutation-rejecting trigger. The table stores no image bytes, no client identity, no share tokens, no provider credentials. It is the durable authority for "what facts and design produced this image."

### 6. One-way state transitions enforced in the database
[`sql/2026-08-30-onboarding-state-machine.sql`](sql/2026-08-30-onboarding-state-machine.sql) and [`sql/2026-08-21-proposal-client-as-built-atomic.sql`](sql/2026-08-21-proposal-client-as-built-atomic.sql)

Onboarding is `NEW → FIRST_JOB → FIRST_PROPOSAL → ACTIVATED`, constrained by `CHECK`, backfilled from durable history, and advanced only by server-owned events. A proposal's `source_job_id` is immutable once bound, enforced by a `BEFORE UPDATE` trigger, so a stale callback or a second job in the same account cannot rewrite the wrong client document. Legacy rows that cannot be upgraded truthfully go to a service-readable quarantine table rather than being fabricated into "truth."

### 7. Idempotent creation under lost responses
[`sql/2026-07-16-proposal-create-idempotency.sql`](sql/2026-07-16-proposal-create-idempotency.sql)

A serverless response can be lost after the commit. Retrying the same confirmed browser action must return the existing token, not create a second live revision. A normalized unique guard makes that a database invariant.

### 8. Deny by default, and keep it that way
[`sql/2026-06-19-rls-lockdown.sql`](sql/2026-06-19-rls-lockdown.sql) and [`sql/2026-07-16-public-schema-lockdown.sql`](sql/2026-07-16-public-schema-lockdown.sql)

RLS enabled and forced on every application table with no permissive policy for browser roles, so the default is deny. Privileges are also revoked at the grant layer, so a future policy added by mistake finds nothing behind it. The second file adds an event trigger that applies the same lockdown to any future public relation or routine, scoped so it cannot touch auth, storage, or extension schemas, and ends by creating a probe routine to prove the guard fires.

### 9. A single outbound gate ledger
[`sql/2026-09-02-outbound-gate.sql`](sql/2026-09-02-outbound-gate.sql)

Halt rows, send records with dedupe keys and salted recipient hashes, and non-message actions that must stay attributable share one table. Partial indexes keep the dedupe and halt lookups narrow. The global kill switch is an environment flag rather than a row so it still works when the database is down.

### 10. Gap-free per-account sequences
[`sql/2026-06-17-invoice-seq.sql`](sql/2026-06-17-invoice-seq.sql)

Invoice numbers must be gap-free per account, not merely monotonic. An account-scoped atomic counter replaces a time-derived number.

### 11. Small lockdown template
[`sql/2026-08-26-support-tickets.sql`](sql/2026-08-26-support-tickets.sql)

The minimal pattern every new table follows: RLS enabled and forced, browser roles revoked, service role granted.

## Runbook

`docs/backup-and-restore.md` describes the two recovery layers: managed backups and PITR as the authoritative layer, plus a daily logical export to a private object store that is ordered and count-checked per table and fails closed on drift. It is explicit about what the logical export cannot prove (a single MVCC point in time) so nobody treats it as a snapshot.

## Conventions you will see in every file

- Most files open with `BEGIN; SET LOCAL lock_timeout = '5s';` so a migration never queues behind a long transaction in production.
- `IF NOT EXISTS` everywhere, with explicit notes on what that does not backfill (a `CHECK` or primary key on a pre-existing table).
- Shape validation before `CREATE OR REPLACE FUNCTION`, raising a clear exception on drift.
- `SECURITY DEFINER` functions pin `search_path = pg_catalog, public` and have `EXECUTE` revoked from `PUBLIC`, `anon`, and `authenticated`.
- Headers say what the file does not backfill and, where it matters, whether it has been applied.

## Author

Zach Collins, founder-operator of a lighting installation business and the solo builder of LightDeck. Profile: [github.com/ZCOLLINSKY](https://github.com/ZCOLLINSKY).
