-- PRODUCTION HOTFIX (UNAPPLIED): repair public.claim_render_attempt.
--
-- WHAT IS BROKEN. 2026-08-16-render-attempt-idempotency.sql applied cleanly and
-- created public.render_attempts, but the claim function it created raises on
-- EVERY call:
--
--   ERROR:  column reference "attempt_id" is ambiguous
--   LINE 10:   ON CONFLICT (attempt_id) DO NOTHING
--   DETAIL:  It could refer to either a PL/pgSQL variable or a table column.
--   CONTEXT: PL/pgSQL function claim_render_attempt(text,text,jsonb,text,text)
--
-- RETURNS TABLE(... attempt_id text ...) declares an OUT variable named
-- attempt_id that is in scope for the whole body, and the ON CONFLICT inference
-- list is resolved as an identifier reference, so it matches both the variable
-- and the column. SQLSTATE 42702, raised before the INSERT executes.
--
-- WHAT IT COSTS. lib/api-shared.js supabaseRpc turns the PostgREST error into a
-- throw; lib/render-attempt-store.js claimAttempt catches it and returns
-- attempt_store_unavailable; api/render.js fail-closes at 503 BEFORE any unit is
-- charged and before the provider is called. Since PR #132 the builder mints an
-- attemptId on every render, so this is 100% of production night renders: the
-- per-IP rate rows are written, public.render_attempts stays at zero rows, no
-- account units move, and the browser silently degrades to its on-device
-- deterministic overlay. Observed live 2026-08-17 16:35/16:36/16:52/16:54 UTC.
--
-- WHY THIS FILE IS SAFE TO RUN. CREATE OR REPLACE FUNCTION with the identical
-- signature and return type. No table is touched, no row is read or written, no
-- grant is widened, no data is destroyed. Re-running it is a no-op. Applying it
-- to a database that never got the 08-16 migration will fail on the missing
-- table type; apply 2026-08-16-render-attempt-idempotency.sql first in that case
-- (it now carries the same fix).
--
-- VERIFY AFTER APPLYING (expects inserted=t then inserted=f, one row):
--   select attempt_id, state, inserted from public.claim_render_attempt(
--     'migration-selfcheck', 'nr1_00000000000000000000000000000000',
--     '{"selfcheck":true}'::jsonb, repeat('a',64), repeat('b',64));
--   -- run it twice, then clean up:
--   delete from public.render_attempts where tenant_id = 'migration-selfcheck';

BEGIN;
SET LOCAL lock_timeout = '5s';

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
-- THE FIX, and it must stay the first line of the body. Ambiguous identifiers
-- resolve to the table column. Nothing in this body ever wants the OUT variable
-- (every read is p_* or v_row.*), so the rule is total and behaviour is
-- otherwise byte-identical to the 08-16 function.
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

-- Replacing a body does not change the signature, so PostgREST's cache is
-- already correct. The notify is harmless and covers a stack whose DDL watch
-- is not installed.
NOTIFY pgrst, 'reload schema';

COMMIT;
