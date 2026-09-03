-- Durable render-attempt idempotency (UNAPPLIED).
--
-- 2026-08-17 CORRECTION. The version of this file that was applied to
-- production created a claim_render_attempt that raised SQLSTATE 42702
-- ("column reference \"attempt_id\" is ambiguous") on EVERY call, so
-- public.render_attempts never gained a row and api/render.js fail-closed at
-- 503 attempt_store_unavailable for 100% of night renders. The function body
-- below now opens with `#variable_conflict use_column`, which fixes it. A
-- database that already ran the broken version must additionally apply
-- scripts/migrations/2026-08-17-fix-claim-render-attempt-ambiguity.sql — the
-- CREATE TABLE IF NOT EXISTS guards here make a re-run of this whole file safe
-- too, but the hotfix file is the smaller, reviewable change.
--
-- Transport retries reuse one opaque attempt id. This table is the
-- cross-instance CAS store for in-progress / succeeded / terminal-failed
-- attempt state, including a recoverable exact response artifact.
--
-- Do NOT use public.render_receipts for attempt state. That table is
-- append-only, forbids image bytes, and CHECK(record_type) only allows
-- origin / presentation / presentation_pack.
--
-- artifact jsonb may contain image bytes. Retain 7 days via created_at
-- + expires_at (created_at + interval '7 days'). purge_expired_render_attempts
-- DELETEs expired rows. service_role only. Not a public CDN.
--
-- No UPDATE-forbid trigger: state must compare-and-swap.
-- DELETE is only via purge_expired_render_attempts (SECURITY DEFINER).
-- Do not apply this file from the freeze; Vercel attempt-id traffic
-- fail-closes until it is applied.
--
-- Partial existing tables: ADD COLUMN IF NOT EXISTS and
-- CREATE UNIQUE INDEX IF NOT EXISTS are best-effort. Full CHECK /
-- PRIMARY KEY / UNIQUE table constraints are fresh-table-only
-- (CREATE TABLE IF NOT EXISTS). ADD COLUMN does not add missing
-- CHECK or PRIMARY KEY. Unique-index create FAILS if duplicate
-- old attempt_id values exist. Do not claim CHECK/PK are backfilled.
-- CREATE OR REPLACE function is safe either way. Do not apply.

BEGIN;
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS public.render_attempts (
  attempt_key         text        PRIMARY KEY,
  tenant_id           text        NOT NULL,
  attempt_id          text        NOT NULL,
  fingerprint_sha256  text        NOT NULL,
  fingerprint         jsonb       NOT NULL,
  state               text        NOT NULL,
  status_code         int,
  verified            boolean     NOT NULL DEFAULT false,
  withheld            boolean     NOT NULL DEFAULT false,
  artifact            jsonb,
  artifact_ref        text,
  created_at          timestamptz NOT NULL DEFAULT now(),
  expires_at          timestamptz NOT NULL DEFAULT (now() + interval '7 days'),
  CONSTRAINT render_attempts_key_sha256 CHECK (attempt_key ~ '^[a-f0-9]{64}$'),
  CONSTRAINT render_attempts_fingerprint_sha256 CHECK (fingerprint_sha256 ~ '^[a-f0-9]{64}$'),
  CONSTRAINT render_attempts_artifact_ref_sha256 CHECK (
    artifact_ref IS NULL OR artifact_ref ~ '^[a-f0-9]{64}$'
  ),
  CONSTRAINT render_attempts_state_check CHECK (
    state IN ('in-progress', 'succeeded', 'terminal-failed')
  ),
  CONSTRAINT render_attempts_fingerprint_object CHECK (jsonb_typeof(fingerprint) = 'object'),
  CONSTRAINT render_attempts_attempt_id_charset CHECK (
    char_length(attempt_id) BETWEEN 16 AND 128
    AND attempt_id ~ '^[A-Za-z0-9._~-]+$'
  ),
  CONSTRAINT render_attempts_tenant_attempt_uniq UNIQUE (tenant_id, attempt_id),
  CONSTRAINT render_attempts_attempt_id_uniq UNIQUE (attempt_id)
);

-- Partial-existing table: add retention columns if a prior apply created the
-- table without them. Defaults backfill existing rows. This path does NOT
-- add missing CHECK or PRIMARY KEY — those remain fresh-table-only.
ALTER TABLE public.render_attempts
  ADD COLUMN IF NOT EXISTS created_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE public.render_attempts
  ADD COLUMN IF NOT EXISTS expires_at timestamptz NOT NULL DEFAULT (now() + interval '7 days');

-- Best-effort unique indexes. CREATE UNIQUE INDEX IF NOT EXISTS fails if
-- existing rows already have duplicate attempt_id values. That failure is
-- intentional: clean the duplicates before applying. Not a CHECK/PK backfill.
CREATE UNIQUE INDEX IF NOT EXISTS render_attempts_attempt_id_uniq
  ON public.render_attempts (attempt_id);
CREATE UNIQUE INDEX IF NOT EXISTS render_attempts_tenant_attempt_uniq
  ON public.render_attempts (tenant_id, attempt_id);

-- purge_expired_render_attempts filters solely on expires_at. Keep that
-- retention lookup bounded as the attempt table grows.
CREATE INDEX IF NOT EXISTS render_attempts_expires_at_idx
  ON public.render_attempts (expires_at);

-- Add missing CHECKs only when they are absent AND existing rows already
-- satisfy them. Dirty data fails loudly. Does not backfill PRIMARY KEY.
DO $$
BEGIN
  IF to_regclass('public.render_attempts') IS NULL THEN
    RETURN;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'render_attempts_attempt_id_charset'
       AND conrelid = 'public.render_attempts'::regclass
  ) THEN
    IF EXISTS (
      SELECT 1 FROM public.render_attempts
       WHERE attempt_id IS NULL
          OR char_length(attempt_id) NOT BETWEEN 16 AND 128
          OR attempt_id !~ '^[A-Za-z0-9._~-]+$'
    ) THEN
      RAISE EXCEPTION 'render_attempts: cannot add attempt_id charset CHECK; existing rows are dirty';
    END IF;
    ALTER TABLE public.render_attempts
      ADD CONSTRAINT render_attempts_attempt_id_charset CHECK (
        char_length(attempt_id) BETWEEN 16 AND 128
        AND attempt_id ~ '^[A-Za-z0-9._~-]+$'
      );
  END IF;
END;
$$;

ALTER TABLE public.render_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.render_attempts FORCE ROW LEVEL SECURITY;

REVOKE ALL PRIVILEGES ON TABLE public.render_attempts FROM PUBLIC;

DO $$
DECLARE
  browser_role text;
BEGIN
  IF pg_catalog.to_regrole('service_role') IS NULL THEN
    RAISE EXCEPTION 'LightDeck render attempts require the Supabase service_role role';
  END IF;
  FOREACH browser_role IN ARRAY ARRAY['anon', 'authenticated']
  LOOP
    IF pg_catalog.to_regrole(browser_role) IS NOT NULL THEN
      EXECUTE format('REVOKE ALL PRIVILEGES ON TABLE public.render_attempts FROM %I', browser_role);
    END IF;
  END LOOP;
  -- CAS complete needs UPDATE. DELETE only via purge_expired_render_attempts.
  GRANT SELECT, INSERT, UPDATE ON TABLE public.render_attempts TO service_role;
END;
$$;

-- Atomic claim: INSERT ... ON CONFLICT (attempt_id) DO NOTHING RETURNING *;
-- if no row, SELECT the existing bound row. One function. Returns the bound
-- row either way (inserted=true on first writer).
-- Return type may have grown (created_at / expires_at); drop the old
-- signature so CREATE OR REPLACE can replace a partial-existing function.
DROP FUNCTION IF EXISTS public.claim_render_attempt(text, text, jsonb, text, text);

CREATE OR REPLACE FUNCTION public.claim_render_attempt(
  p_tenant_id text,
  p_attempt_id text,
  p_fingerprint jsonb,
  p_fingerprint_sha256 text,
  p_attempt_key text
)
RETURNS TABLE(
  attempt_key text,
  tenant_id text,
  attempt_id text,
  fingerprint_sha256 text,
  fingerprint jsonb,
  state text,
  status_code int,
  verified boolean,
  withheld boolean,
  artifact jsonb,
  artifact_ref text,
  created_at timestamptz,
  expires_at timestamptz,
  inserted boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
#variable_conflict use_column
-- The directive above is MANDATORY and must stay the first line of the body.
-- RETURNS TABLE turns every result column name into a PL/pgSQL OUT variable
-- that is in scope for the whole body, so the bare `ON CONFLICT (attempt_id)`
-- inference list below is ambiguous between that OUT variable and the real
-- column:
--   ERROR 42702: column reference "attempt_id" is ambiguous
--   DETAIL: It could refer to either a PL/pgSQL variable or a table column.
-- The error is raised on EVERY call, so an applied-but-unfixed function claims
-- nothing, inserts nothing, and fail-closes api/render.js at 503
-- attempt_store_unavailable for every render in production (2026-08-17).
-- Renaming the OUT columns is not an option: lib/render-attempt-store.js
-- rowToRecord() reads them by name off the PostgREST JSON. Naming the unique
-- CONSTRAINT is not an option either: the partial-existing-table path above
-- creates a unique INDEX of that name, not a constraint. use_column resolves
-- ambiguity to the column; nothing in this body ever wants the OUT variable
-- (every read is p_* or v_row.*), so the rule is total.
DECLARE
  v_row public.render_attempts%ROWTYPE;
  v_inserted boolean := false;
BEGIN
  IF p_attempt_id IS NULL
     OR char_length(p_attempt_id) < 16
     OR char_length(p_attempt_id) > 128
     OR p_attempt_id !~ '^[A-Za-z0-9._~-]+$' THEN
    RAISE EXCEPTION 'invalid_attempt_id';
  END IF;
  IF p_tenant_id IS NULL OR btrim(p_tenant_id) = '' THEN
    RAISE EXCEPTION 'tenant_required';
  END IF;
  IF p_attempt_key IS NULL OR p_attempt_key !~ '^[a-f0-9]{64}$' THEN
    RAISE EXCEPTION 'invalid_attempt_key';
  END IF;
  IF p_fingerprint_sha256 IS NULL OR p_fingerprint_sha256 !~ '^[a-f0-9]{64}$' THEN
    RAISE EXCEPTION 'invalid_fingerprint_sha256';
  END IF;
  IF p_fingerprint IS NULL OR jsonb_typeof(p_fingerprint) <> 'object' THEN
    RAISE EXCEPTION 'invalid_fingerprint';
  END IF;

  INSERT INTO public.render_attempts (
    attempt_key, tenant_id, attempt_id, fingerprint_sha256, fingerprint,
    state, status_code, verified, withheld, artifact, artifact_ref,
    created_at, expires_at
  ) VALUES (
    p_attempt_key, p_tenant_id, p_attempt_id, p_fingerprint_sha256, p_fingerprint,
    'in-progress', NULL, false, false, NULL, NULL,
    now(), now() + interval '7 days'
  )
  ON CONFLICT (attempt_id) DO NOTHING
  RETURNING * INTO v_row;

  IF FOUND THEN
    v_inserted := true;
  ELSE
    SELECT ra.* INTO STRICT v_row
      FROM public.render_attempts ra
     WHERE ra.attempt_id = p_attempt_id;
  END IF;

  RETURN QUERY SELECT
    v_row.attempt_key,
    v_row.tenant_id,
    v_row.attempt_id,
    v_row.fingerprint_sha256,
    v_row.fingerprint,
    v_row.state,
    v_row.status_code,
    v_row.verified,
    v_row.withheld,
    v_row.artifact,
    v_row.artifact_ref,
    v_row.created_at,
    v_row.expires_at,
    v_inserted;
END;
$$;

REVOKE ALL ON FUNCTION public.claim_render_attempt(text, text, jsonb, text, text) FROM PUBLIC;
DO $$
DECLARE
  browser_role text;
BEGIN
  FOREACH browser_role IN ARRAY ARRAY['anon', 'authenticated']
  LOOP
    IF pg_catalog.to_regrole(browser_role) IS NOT NULL THEN
      EXECUTE format('REVOKE ALL ON FUNCTION public.claim_render_attempt(text, text, jsonb, text, text) FROM %I', browser_role);
    END IF;
  END LOOP;
  GRANT EXECUTE ON FUNCTION public.claim_render_attempt(text, text, jsonb, text, text) TO service_role;
END;
$$;

-- Bounded retention: DELETE rows whose expires_at has passed. Returns deleted count.
CREATE OR REPLACE FUNCTION public.purge_expired_render_attempts(
  p_now timestamptz DEFAULT now()
)
RETURNS TABLE(deleted integer)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_deleted integer := 0;
BEGIN
  DELETE FROM public.render_attempts
   WHERE expires_at <= COALESCE(p_now, now());
  GET DIAGNOSTICS v_deleted = ROW_COUNT;
  RETURN QUERY SELECT v_deleted;
END;
$$;

REVOKE ALL ON FUNCTION public.purge_expired_render_attempts(timestamptz) FROM PUBLIC;
DO $$
DECLARE
  browser_role text;
BEGIN
  FOREACH browser_role IN ARRAY ARRAY['anon', 'authenticated']
  LOOP
    IF pg_catalog.to_regrole(browser_role) IS NOT NULL THEN
      EXECUTE format('REVOKE ALL ON FUNCTION public.purge_expired_render_attempts(timestamptz) FROM %I', browser_role);
    END IF;
  END LOOP;
  GRANT EXECUTE ON FUNCTION public.purge_expired_render_attempts(timestamptz) TO service_role;
END;
$$;

COMMIT;
