-- Store the post-completion homeowner as-built outside proposals.proposal_data.
-- The proposal owns one immutable browser job id, and every publish/revoke is an
-- ordered, idempotent state transition. This prevents stale callbacks, retries,
-- or another job in the same account from changing the wrong client document.

BEGIN;
SET LOCAL lock_timeout = '5s';

ALTER TABLE public.proposals
  ADD COLUMN IF NOT EXISTS source_job_id text;
ALTER TABLE public.proposals
  DROP CONSTRAINT IF EXISTS proposals_source_job_id_check;
ALTER TABLE public.proposals
  ADD CONSTRAINT proposals_source_job_id_check
  CHECK (
    source_job_id IS NULL
    OR (
      source_job_id = btrim(source_job_id)
      AND char_length(source_job_id) BETWEEN 8 AND 200
      AND source_job_id ~ '^[A-Za-z0-9_-]+$'
    )
  );

-- A legacy proposal may acquire its browser job binding once. After that it is
-- identity, not editable payload. Enforce the one-way transition in Postgres so
-- two stale replace requests cannot bind the same client token to different
-- jobs, including while one request is publishing a sidecar.
CREATE OR REPLACE FUNCTION public.enforce_proposal_source_job_id_immutable()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF OLD.source_job_id IS NOT NULL
     AND NEW.source_job_id IS DISTINCT FROM OLD.source_job_id THEN
    RAISE EXCEPTION 'proposal source job id is immutable'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION public.enforce_proposal_source_job_id_immutable()
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.enforce_proposal_source_job_id_immutable()
  TO service_role;
DROP TRIGGER IF EXISTS proposals_source_job_id_immutable ON public.proposals;
CREATE TRIGGER proposals_source_job_id_immutable
  BEFORE UPDATE OF source_job_id ON public.proposals
  FOR EACH ROW
  EXECUTE FUNCTION public.enforce_proposal_source_job_id_immutable();

CREATE TABLE IF NOT EXISTS public.proposal_client_as_builts (
  proposal_token text PRIMARY KEY
    REFERENCES public.proposals(token) ON DELETE CASCADE,
  account_id text NOT NULL,
  source_job_id text NOT NULL,
  owner_record jsonb,
  owner_record_sha256 text,
  record jsonb,
  record_sha256 text,
  published boolean NOT NULL DEFAULT false,
  state_version bigint NOT NULL DEFAULT 1,
  published_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

-- Upgrade an earlier Preview draft in place. Production had no sidecar at the
-- time this migration was prepared, but rerunning the exact SQL must still
-- converge rather than leave an old function overload or nullable boundary.
ALTER TABLE public.proposal_client_as_builts
  ADD COLUMN IF NOT EXISTS source_job_id text;
ALTER TABLE public.proposal_client_as_builts
  ADD COLUMN IF NOT EXISTS owner_record jsonb;
ALTER TABLE public.proposal_client_as_builts
  ADD COLUMN IF NOT EXISTS owner_record_sha256 text;
ALTER TABLE public.proposal_client_as_builts
  ADD COLUMN IF NOT EXISTS state_version bigint NOT NULL DEFAULT 1;

-- The first Preview draft stored only the homeowner projection. It has no
-- source job id or exact owner record, so fabricating either during upgrade
-- would turn redacted client data into false contractor truth. Recover the job
-- binding where an exact newer record/editable bundle proves it; preserve every
-- incompatible legacy row in a service-readable, browser-denied quarantine and
-- remove it from the live sidecar before enforcing the stronger constraints.
CREATE TABLE IF NOT EXISTS public.proposal_client_as_built_legacy_quarantine (
  proposal_token text PRIMARY KEY,
  account_id text,
  legacy_row jsonb NOT NULL,
  quarantine_reason text NOT NULL,
  quarantined_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE public.proposal_client_as_built_legacy_quarantine ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.proposal_client_as_built_legacy_quarantine
  FROM PUBLIC, anon, authenticated, service_role;
GRANT SELECT ON TABLE public.proposal_client_as_built_legacy_quarantine TO service_role;

UPDATE public.proposal_client_as_builts
   SET source_job_id = owner_record->>'jobId'
 WHERE source_job_id IS NULL
   AND jsonb_typeof(owner_record) = 'object'
   AND owner_record->>'jobId' = btrim(owner_record->>'jobId')
   AND char_length(owner_record->>'jobId') BETWEEN 8 AND 200
   AND owner_record->>'jobId' ~ '^[A-Za-z0-9_-]+$';
UPDATE public.proposals
   SET source_job_id = editable_state #>> '{design,jobId}'
 WHERE source_job_id IS NULL
   AND jsonb_typeof(editable_state) = 'object'
   AND editable_state #>> '{design,jobId}' = btrim(editable_state #>> '{design,jobId}')
   AND char_length(editable_state #>> '{design,jobId}') BETWEEN 8 AND 200
   AND editable_state #>> '{design,jobId}' ~ '^[A-Za-z0-9_-]+$';
UPDATE public.proposals proposal
   SET source_job_id = sidecar.source_job_id
  FROM public.proposal_client_as_builts sidecar
 WHERE proposal.token = sidecar.proposal_token
   AND proposal.source_job_id IS NULL
   AND sidecar.source_job_id IS NOT NULL
   AND sidecar.source_job_id = btrim(sidecar.source_job_id)
   AND char_length(sidecar.source_job_id) BETWEEN 8 AND 200
   AND sidecar.source_job_id ~ '^[A-Za-z0-9_-]+$';
UPDATE public.proposal_client_as_builts sidecar
   SET source_job_id = proposal.source_job_id
  FROM public.proposals proposal
 WHERE proposal.token = sidecar.proposal_token
   AND sidecar.source_job_id IS NULL
   AND proposal.source_job_id IS NOT NULL;

CREATE TEMP TABLE ld_invalid_client_as_built_upgrade
ON COMMIT DROP
AS
SELECT sidecar.proposal_token
  FROM public.proposal_client_as_builts sidecar
  JOIN public.proposals proposal ON proposal.token = sidecar.proposal_token
 WHERE sidecar.account_id IS DISTINCT FROM proposal.account_id
    OR sidecar.source_job_id IS NULL
    OR sidecar.source_job_id IS DISTINCT FROM proposal.source_job_id
    OR sidecar.source_job_id IS DISTINCT FROM btrim(sidecar.source_job_id)
    OR char_length(sidecar.source_job_id) NOT BETWEEN 8 AND 200
    OR sidecar.source_job_id !~ '^[A-Za-z0-9_-]+$'
    OR sidecar.state_version IS NULL
    OR sidecar.state_version < 1
    OR (
      (sidecar.owner_record IS NULL) IS DISTINCT FROM (sidecar.owner_record_sha256 IS NULL)
    )
    OR (
      sidecar.owner_record IS NOT NULL
      AND (
        jsonb_typeof(sidecar.owner_record) IS DISTINCT FROM 'object'
        OR sidecar.owner_record_sha256 !~ '^[a-f0-9]{64}$'
        OR coalesce(sidecar.owner_record->>'version' = '1', false) IS DISTINCT FROM true
        OR coalesce(sidecar.owner_record->>'status' = 'field-verified', false) IS DISTINCT FROM true
        OR coalesce(sidecar.owner_record->>'fieldVerified' = 'true', false) IS DISTINCT FROM true
        OR coalesce(sidecar.owner_record->>'jobId' = sidecar.source_job_id, false) IS DISTINCT FROM true
      )
    )
    OR (
      sidecar.published = true
      AND (
        sidecar.owner_record IS NULL
        OR sidecar.owner_record_sha256 IS NULL
        OR sidecar.record IS NULL
        OR jsonb_typeof(sidecar.record) IS DISTINCT FROM 'object'
        OR sidecar.record_sha256 IS NULL
        OR sidecar.record_sha256 !~ '^[a-f0-9]{64}$'
        OR sidecar.published_at IS NULL
        OR sidecar.revoked_at IS NOT NULL
      )
    )
    OR (
      sidecar.published = false
      AND (
        sidecar.record IS NOT NULL
        OR sidecar.record_sha256 IS NOT NULL
        OR sidecar.published_at IS NOT NULL
        OR sidecar.revoked_at IS NULL
      )
    );

INSERT INTO public.proposal_client_as_built_legacy_quarantine (
  proposal_token, account_id, legacy_row, quarantine_reason, quarantined_at
)
SELECT sidecar.proposal_token, sidecar.account_id, to_jsonb(sidecar),
       'incompatible_pre_atomic_sidecar', clock_timestamp()
  FROM public.proposal_client_as_builts sidecar
  JOIN ld_invalid_client_as_built_upgrade invalid
    ON invalid.proposal_token = sidecar.proposal_token
ON CONFLICT (proposal_token) DO UPDATE SET
  account_id = EXCLUDED.account_id,
  legacy_row = EXCLUDED.legacy_row,
  quarantine_reason = EXCLUDED.quarantine_reason,
  quarantined_at = EXCLUDED.quarantined_at;

DELETE FROM public.proposal_client_as_builts sidecar
 USING ld_invalid_client_as_built_upgrade invalid
 WHERE invalid.proposal_token = sidecar.proposal_token;

ALTER TABLE public.proposal_client_as_builts
  ALTER COLUMN source_job_id SET NOT NULL;
ALTER TABLE public.proposal_client_as_builts
  ALTER COLUMN state_version SET DEFAULT 1;
ALTER TABLE public.proposal_client_as_builts
  ALTER COLUMN state_version SET NOT NULL;

ALTER TABLE public.proposal_client_as_builts
  DROP CONSTRAINT IF EXISTS proposal_client_as_builts_token_canonical_check;
ALTER TABLE public.proposal_client_as_builts
  ADD CONSTRAINT proposal_client_as_builts_token_canonical_check
  CHECK (
    proposal_token <> ''
    AND proposal_token = btrim(proposal_token)
    AND char_length(proposal_token) BETWEEN 8 AND 200
    AND proposal_token ~ '^[A-Za-z0-9_-]+$'
  );
ALTER TABLE public.proposal_client_as_builts
  DROP CONSTRAINT IF EXISTS proposal_client_as_builts_account_check;
ALTER TABLE public.proposal_client_as_builts
  ADD CONSTRAINT proposal_client_as_builts_account_check
  CHECK (account_id <> '' AND account_id = btrim(account_id));
ALTER TABLE public.proposal_client_as_builts
  DROP CONSTRAINT IF EXISTS proposal_client_as_builts_source_job_check;
ALTER TABLE public.proposal_client_as_builts
  ADD CONSTRAINT proposal_client_as_builts_source_job_check
  CHECK (
    source_job_id = btrim(source_job_id)
    AND char_length(source_job_id) BETWEEN 8 AND 200
    AND source_job_id ~ '^[A-Za-z0-9_-]+$'
  );
ALTER TABLE public.proposal_client_as_builts
  DROP CONSTRAINT IF EXISTS proposal_client_as_builts_state_check;
ALTER TABLE public.proposal_client_as_builts
  ADD CONSTRAINT proposal_client_as_builts_state_check
  CHECK (
    state_version >= 1
    AND (
      (owner_record IS NULL AND owner_record_sha256 IS NULL)
      OR (
        jsonb_typeof(owner_record) = 'object'
        AND owner_record_sha256 IS NOT NULL
        AND owner_record_sha256 ~ '^[a-f0-9]{64}$'
        AND coalesce(owner_record->>'version' = '1', false)
        AND coalesce(owner_record->>'status' = 'field-verified', false)
        AND coalesce(owner_record->>'fieldVerified' = 'true', false)
        AND coalesce(owner_record->>'jobId' = source_job_id, false)
      )
    )
    AND (
      (
        published = true
        AND owner_record IS NOT NULL
        AND owner_record_sha256 IS NOT NULL
        AND record IS NOT NULL
        AND jsonb_typeof(record) = 'object'
        AND record_sha256 IS NOT NULL
        AND record_sha256 ~ '^[a-f0-9]{64}$'
        AND published_at IS NOT NULL
        AND revoked_at IS NULL
      )
      OR
      (
        published = false
        AND record IS NULL
        AND record_sha256 IS NULL
        AND published_at IS NULL
        AND revoked_at IS NOT NULL
      )
    )
  );

DROP INDEX IF EXISTS public.proposal_client_as_builts_account_idx;
CREATE INDEX IF NOT EXISTS proposal_client_as_builts_published_cursor_idx
  ON public.proposal_client_as_builts
  (account_id, published_at DESC, proposal_token DESC)
  WHERE published = true;

CREATE TABLE IF NOT EXISTS public.proposal_client_as_built_operations (
  proposal_token text NOT NULL
    REFERENCES public.proposals(token) ON DELETE CASCADE,
  operation_id text NOT NULL,
  account_id text NOT NULL,
  source_job_id text NOT NULL,
  action text NOT NULL,
  request_sha256 text,
  expected_version bigint NOT NULL,
  resulting_version bigint NOT NULL,
  result jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (proposal_token, operation_id)
);
ALTER TABLE public.proposal_client_as_built_operations
  ADD COLUMN IF NOT EXISTS request_sha256 text;
ALTER TABLE public.proposal_client_as_built_operations
  DROP CONSTRAINT IF EXISTS proposal_client_as_built_operations_identity_check;
ALTER TABLE public.proposal_client_as_built_operations
  ADD CONSTRAINT proposal_client_as_built_operations_identity_check
  CHECK (
    proposal_token = btrim(proposal_token)
    AND char_length(proposal_token) BETWEEN 8 AND 200
    AND proposal_token ~ '^[A-Za-z0-9_-]+$'
    AND operation_id = btrim(operation_id)
    AND char_length(operation_id) BETWEEN 16 AND 200
    AND operation_id ~ '^[A-Za-z0-9_-]+$'
    AND account_id <> ''
    AND account_id = btrim(account_id)
    AND source_job_id = btrim(source_job_id)
    AND char_length(source_job_id) BETWEEN 8 AND 200
    AND source_job_id ~ '^[A-Za-z0-9_-]+$'
    AND action IN ('publish', 'revoke')
    AND (
      (action = 'publish' AND request_sha256 IS NOT NULL AND request_sha256 ~ '^[a-f0-9]{64}$')
      OR (action = 'revoke' AND request_sha256 IS NULL)
    )
    AND expected_version >= 0
    AND resulting_version >= expected_version
    AND jsonb_typeof(result) = 'object'
  );
CREATE INDEX IF NOT EXISTS proposal_client_as_built_operations_account_idx
  ON public.proposal_client_as_built_operations
  (account_id, created_at DESC, proposal_token, operation_id);

ALTER TABLE public.proposal_client_as_builts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.proposal_client_as_built_operations ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.proposal_client_as_builts FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.proposal_client_as_built_operations FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.proposal_client_as_builts FROM service_role;
REVOKE ALL ON TABLE public.proposal_client_as_built_operations FROM service_role;
GRANT SELECT, INSERT, UPDATE ON TABLE public.proposal_client_as_builts TO service_role;
GRANT SELECT, INSERT ON TABLE public.proposal_client_as_built_operations TO service_role;

DROP FUNCTION IF EXISTS public.set_proposal_client_as_built(text,text,text,jsonb,text);
DROP FUNCTION IF EXISTS public.set_proposal_client_as_built(text,text,text,text,jsonb,text,text,bigint);
DROP FUNCTION IF EXISTS public.set_proposal_client_as_built(text,text,text,text,jsonb,text,jsonb,text,text,bigint);

CREATE FUNCTION public.set_proposal_client_as_built(
  p_account_id text,
  p_token text,
  p_source_job_id text,
  p_action text,
  p_owner_record jsonb,
  p_owner_record_sha256 text,
  p_record jsonb,
  p_record_sha256 text,
  p_operation_id text,
  p_expected_version bigint
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
DECLARE
  proposal_status text;
  proposal_accepted_at timestamptz;
  proposal_source_job_id text;
  existing_row public.proposal_client_as_builts%ROWTYPE;
  prior_operation public.proposal_client_as_built_operations%ROWTYPE;
  action_name text := lower(coalesce(p_action, ''));
  current_version bigint := 0;
  next_version bigint;
  event_stamp timestamptz;
  event_iso text;
  stored_record jsonb;
  operation_result jsonb;
BEGIN
  IF nullif(btrim(p_account_id), '') IS NULL OR p_account_id <> btrim(p_account_id) THEN
    RAISE EXCEPTION 'canonical account id is required';
  END IF;
  IF nullif(btrim(p_token), '') IS NULL
     OR p_token <> btrim(p_token)
     OR char_length(p_token) NOT BETWEEN 8 AND 200
     OR p_token !~ '^[A-Za-z0-9_-]+$' THEN
    RAISE EXCEPTION 'canonical proposal token is required';
  END IF;
  IF nullif(btrim(p_source_job_id), '') IS NULL
     OR p_source_job_id <> btrim(p_source_job_id)
     OR char_length(p_source_job_id) NOT BETWEEN 8 AND 200
     OR p_source_job_id !~ '^[A-Za-z0-9_-]+$' THEN
    RAISE EXCEPTION 'canonical proposal source job id is required';
  END IF;
  IF nullif(btrim(p_operation_id), '') IS NULL
     OR p_operation_id <> btrim(p_operation_id)
     OR char_length(p_operation_id) NOT BETWEEN 16 AND 200
     OR p_operation_id !~ '^[A-Za-z0-9_-]+$' THEN
    RAISE EXCEPTION 'canonical as-built operation id is required';
  END IF;
  IF p_expected_version IS NULL OR p_expected_version < 0 THEN
    RAISE EXCEPTION 'nonnegative expected as-built version is required';
  END IF;
  IF action_name NOT IN ('publish', 'revoke') THEN
    RAISE EXCEPTION 'as-built action must be publish or revoke';
  END IF;
  IF action_name = 'publish'
     AND (
       jsonb_typeof(p_owner_record) IS DISTINCT FROM 'object'
       OR octet_length(p_owner_record::text) > 262144
       OR p_owner_record->>'version' IS DISTINCT FROM '1'
       OR p_owner_record->>'status' IS DISTINCT FROM 'field-verified'
       OR p_owner_record->>'fieldVerified' IS DISTINCT FROM 'true'
       OR p_owner_record->>'jobId' IS DISTINCT FROM p_source_job_id
       OR p_owner_record_sha256 IS NULL
       OR p_owner_record_sha256 !~ '^[a-f0-9]{64}$'
     ) THEN
    RAISE EXCEPTION 'invalid owner as-built record';
  END IF;
  IF action_name = 'revoke'
     AND (p_owner_record IS NOT NULL OR p_owner_record_sha256 IS NOT NULL) THEN
    RAISE EXCEPTION 'revoke must not replace the owner as-built record';
  END IF;

  -- This proposal lock is the serialization point for both the first sidecar
  -- insert and every later transition. The immutable job binding is rechecked
  -- under the same lock; an API precheck alone is not authoritative.
  SELECT upper(coalesce(status, '')), accepted_at, source_job_id
    INTO proposal_status, proposal_accepted_at, proposal_source_job_id
    FROM public.proposals
   WHERE token = p_token
     AND account_id = p_account_id
   FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'proposal ownership mismatch';
  END IF;
  IF proposal_source_job_id IS NULL
     OR proposal_source_job_id IS DISTINCT FROM p_source_job_id THEN
    RAISE EXCEPTION 'proposal source job mismatch';
  END IF;
  -- accepted_at is intentionally retained when a signed proposal is revoked.
  -- Status therefore has to win: a delayed publisher waiting on this row lock
  -- must observe REVOKED and fail instead of resurrecting client-visible data.
  IF action_name = 'publish' AND proposal_status = 'REVOKED' THEN
    RAISE EXCEPTION 'revoked proposal cannot publish an as-built';
  END IF;
  IF action_name = 'publish'
     AND proposal_status <> 'ACCEPTED'
     AND proposal_accepted_at IS NULL THEN
    RAISE EXCEPTION 'proposal must be accepted before as-built publication';
  END IF;

  SELECT * INTO existing_row
    FROM public.proposal_client_as_builts
   WHERE proposal_token = p_token
   FOR UPDATE;
  IF FOUND THEN current_version := existing_row.state_version; END IF;

  SELECT * INTO prior_operation
    FROM public.proposal_client_as_built_operations
   WHERE proposal_token = p_token
     AND operation_id = p_operation_id;
  IF FOUND THEN
    IF prior_operation.account_id IS DISTINCT FROM p_account_id
       OR prior_operation.source_job_id IS DISTINCT FROM p_source_job_id
       OR prior_operation.action IS DISTINCT FROM action_name
       OR prior_operation.request_sha256 IS DISTINCT FROM p_owner_record_sha256
       OR prior_operation.expected_version IS DISTINCT FROM p_expected_version THEN
      RAISE EXCEPTION 'as-built operation identity mismatch';
    END IF;
    IF prior_operation.resulting_version = current_version THEN
      RETURN prior_operation.result || jsonb_build_object(
        'operation_replay', true,
        'idempotent', true
      );
    END IF;
    RETURN jsonb_build_object(
      'conflict', true,
      'reason', 'as_built_operation_superseded',
      'operation_replay', true,
      'operation_result', prior_operation.result,
      'state_version', current_version,
      'published', CASE WHEN existing_row.proposal_token IS NULL THEN false ELSE existing_row.published END,
      'published_at', existing_row.published_at,
      'record_sha256', existing_row.record_sha256,
      'revoked_at', existing_row.revoked_at,
      'owner_record', existing_row.owner_record,
      'owner_record_sha256', existing_row.owner_record_sha256
    );
  END IF;

  IF p_expected_version <> current_version THEN
    RETURN jsonb_build_object(
      'conflict', true,
      'reason', 'as_built_version_conflict',
      'operation_replay', false,
      'state_version', current_version,
      'published', CASE WHEN existing_row.proposal_token IS NULL THEN false ELSE existing_row.published END,
      'published_at', existing_row.published_at,
      'record_sha256', existing_row.record_sha256,
      'revoked_at', existing_row.revoked_at,
      'owner_record', existing_row.owner_record,
      'owner_record_sha256', existing_row.owner_record_sha256
    );
  END IF;

  IF action_name = 'publish' THEN
    IF jsonb_typeof(p_record) IS DISTINCT FROM 'object'
       OR octet_length(p_record::text) > 262144
       OR p_record->>'authority' IS DISTINCT FROM 'lightdeck_field_verified_as_built_v1'
       OR p_record->>'version' IS DISTINCT FROM '1'
       OR p_record->>'published' IS DISTINCT FROM 'true'
       OR p_record->>'status' IS DISTINCT FROM 'field-verified'
       OR jsonb_typeof(p_record->'runs') IS DISTINCT FROM 'array'
       OR jsonb_array_length(p_record->'runs') NOT BETWEEN 1 AND 100
       OR p_record_sha256 IS NULL
       OR p_record_sha256 !~ '^[a-f0-9]{64}$' THEN
      RAISE EXCEPTION 'invalid field-verified as-built projection';
    END IF;

    IF existing_row.proposal_token IS NOT NULL
       AND existing_row.published = true
       AND existing_row.account_id = p_account_id
       AND existing_row.source_job_id = p_source_job_id
       AND existing_row.owner_record_sha256 = p_owner_record_sha256
       AND existing_row.owner_record = p_owner_record
       AND existing_row.record_sha256 = p_record_sha256
       AND jsonb_typeof(existing_row.record) = 'object'
       AND (existing_row.record - 'published_at' - 'record_sha256')
           = (p_record - 'published_at' - 'record_sha256')
       AND existing_row.record->>'record_sha256' = p_record_sha256
       AND existing_row.published_at IS NOT NULL
       AND existing_row.record->>'published_at'
           = to_char(existing_row.published_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
       AND existing_row.revoked_at IS NULL THEN
      operation_result := jsonb_build_object(
        'published', true,
        'published_at', existing_row.record->>'published_at',
        'record_sha256', existing_row.record_sha256,
        'state_version', current_version,
        'operation_id', p_operation_id,
        'idempotent', true,
        'operation_replay', false
      );
      INSERT INTO public.proposal_client_as_built_operations (
        proposal_token, operation_id, account_id, source_job_id, action, request_sha256,
        expected_version, resulting_version, result
      ) VALUES (
        p_token, p_operation_id, p_account_id, p_source_job_id, action_name, p_owner_record_sha256,
        p_expected_version, current_version, operation_result
      );
      RETURN operation_result;
    END IF;

    event_stamp := clock_timestamp();
    event_iso := to_char(event_stamp AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
    next_version := current_version + 1;
    stored_record := jsonb_set(
      jsonb_set(p_record - 'published_at' - 'record_sha256', '{published_at}', to_jsonb(event_iso), true),
      '{record_sha256}', to_jsonb(p_record_sha256), true
    );

    INSERT INTO public.proposal_client_as_builts (
      proposal_token, account_id, source_job_id, owner_record, owner_record_sha256,
      record, record_sha256,
      published, state_version, published_at, revoked_at, created_at, updated_at
    ) VALUES (
      p_token, p_account_id, p_source_job_id, p_owner_record, p_owner_record_sha256,
      stored_record, p_record_sha256,
      true, next_version, event_stamp, NULL, event_stamp, event_stamp
    )
    ON CONFLICT (proposal_token) DO UPDATE SET
      account_id = EXCLUDED.account_id,
      source_job_id = EXCLUDED.source_job_id,
      owner_record = EXCLUDED.owner_record,
      owner_record_sha256 = EXCLUDED.owner_record_sha256,
      record = EXCLUDED.record,
      record_sha256 = EXCLUDED.record_sha256,
      published = true,
      state_version = EXCLUDED.state_version,
      published_at = EXCLUDED.published_at,
      revoked_at = NULL,
      updated_at = EXCLUDED.updated_at;

    operation_result := jsonb_build_object(
      'published', true,
      'published_at', event_iso,
      'record_sha256', p_record_sha256,
      'state_version', next_version,
      'operation_id', p_operation_id,
      'idempotent', false,
      'operation_replay', false
    );
  ELSE
    IF existing_row.proposal_token IS NOT NULL
       AND existing_row.published = false
       AND existing_row.account_id = p_account_id
       AND existing_row.source_job_id = p_source_job_id
       AND existing_row.revoked_at IS NOT NULL THEN
      operation_result := jsonb_build_object(
        'published', false,
        'revoked_at', to_char(existing_row.revoked_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
        'state_version', current_version,
        'operation_id', p_operation_id,
        'idempotent', true,
        'operation_replay', false
      );
      INSERT INTO public.proposal_client_as_built_operations (
        proposal_token, operation_id, account_id, source_job_id, action, request_sha256,
        expected_version, resulting_version, result
      ) VALUES (
        p_token, p_operation_id, p_account_id, p_source_job_id, action_name, NULL,
        p_expected_version, current_version, operation_result
      );
      RETURN operation_result;
    END IF;

    event_stamp := clock_timestamp();
    event_iso := to_char(event_stamp AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
    next_version := current_version + 1;
    INSERT INTO public.proposal_client_as_builts (
      proposal_token, account_id, source_job_id, owner_record, owner_record_sha256,
      record, record_sha256,
      published, state_version, published_at, revoked_at, created_at, updated_at
    ) VALUES (
      p_token, p_account_id, p_source_job_id, NULL, NULL,
      NULL, NULL,
      false, next_version, NULL, event_stamp, event_stamp, event_stamp
    )
    ON CONFLICT (proposal_token) DO UPDATE SET
      account_id = EXCLUDED.account_id,
      source_job_id = EXCLUDED.source_job_id,
      record = NULL,
      record_sha256 = NULL,
      published = false,
      state_version = EXCLUDED.state_version,
      published_at = NULL,
      revoked_at = EXCLUDED.revoked_at,
      updated_at = EXCLUDED.updated_at;

    operation_result := jsonb_build_object(
      'published', false,
      'revoked_at', event_iso,
      'state_version', next_version,
      'operation_id', p_operation_id,
      'idempotent', false,
      'operation_replay', false
    );
  END IF;

  INSERT INTO public.proposal_client_as_built_operations (
    proposal_token, operation_id, account_id, source_job_id, action, request_sha256,
    expected_version, resulting_version, result
  ) VALUES (
    p_token, p_operation_id, p_account_id, p_source_job_id, action_name, p_owner_record_sha256,
    p_expected_version, next_version, operation_result
  );
  RETURN operation_result;
END;
$$;

REVOKE ALL ON FUNCTION public.set_proposal_client_as_built(text,text,text,text,jsonb,text,jsonb,text,text,bigint)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.set_proposal_client_as_built(text,text,text,text,jsonb,text,jsonb,text,text,bigint)
  TO service_role;

-- Fail the migration if its browser-denied, invoker-rights contract drifted.
DO $$
DECLARE
  sidecar_oid oid := 'public.proposal_client_as_builts'::regclass;
  operation_oid oid := 'public.proposal_client_as_built_operations'::regclass;
  quarantine_oid oid := 'public.proposal_client_as_built_legacy_quarantine'::regclass;
  routine_oid oid := pg_catalog.to_regprocedure('public.set_proposal_client_as_built(text,text,text,text,jsonb,text,jsonb,text,text,bigint)');
  binding_routine_oid oid := pg_catalog.to_regprocedure('public.enforce_proposal_source_job_id_immutable()');
  old_routine_oid oid := pg_catalog.to_regprocedure('public.set_proposal_client_as_built(text,text,text,jsonb,text)');
  interim_routine_oid oid := pg_catalog.to_regprocedure('public.set_proposal_client_as_built(text,text,text,text,jsonb,text,text,bigint)');
  routine_security_definer boolean;
  routine_config text[];
  sidecar_rls boolean;
  operation_rls boolean;
  quarantine_rls boolean;
  binding_routine_security_definer boolean;
  binding_routine_config text[];
  binding_trigger_count integer;
BEGIN
  SELECT c.relrowsecurity INTO STRICT sidecar_rls
    FROM pg_catalog.pg_class c WHERE c.oid = sidecar_oid;
  SELECT c.relrowsecurity INTO STRICT operation_rls
    FROM pg_catalog.pg_class c WHERE c.oid = operation_oid;
  SELECT c.relrowsecurity INTO STRICT quarantine_rls
    FROM pg_catalog.pg_class c WHERE c.oid = quarantine_oid;
  IF sidecar_rls IS DISTINCT FROM true
     OR operation_rls IS DISTINCT FROM true
     OR quarantine_rls IS DISTINCT FROM true
     OR pg_catalog.has_table_privilege('anon', sidecar_oid, 'SELECT')
     OR pg_catalog.has_table_privilege('authenticated', sidecar_oid, 'SELECT')
     OR pg_catalog.has_table_privilege('anon', operation_oid, 'SELECT')
     OR pg_catalog.has_table_privilege('authenticated', operation_oid, 'SELECT')
     OR NOT pg_catalog.has_table_privilege('service_role', sidecar_oid, 'SELECT')
     OR NOT pg_catalog.has_table_privilege('service_role', sidecar_oid, 'INSERT')
     OR NOT pg_catalog.has_table_privilege('service_role', sidecar_oid, 'UPDATE')
     OR pg_catalog.has_table_privilege('service_role', sidecar_oid, 'DELETE')
     OR NOT pg_catalog.has_table_privilege('service_role', operation_oid, 'SELECT')
     OR NOT pg_catalog.has_table_privilege('service_role', operation_oid, 'INSERT')
     OR pg_catalog.has_table_privilege('service_role', operation_oid, 'UPDATE')
     OR pg_catalog.has_table_privilege('service_role', operation_oid, 'DELETE')
     OR pg_catalog.has_table_privilege('anon', quarantine_oid, 'SELECT')
     OR pg_catalog.has_table_privilege('authenticated', quarantine_oid, 'SELECT')
     OR NOT pg_catalog.has_table_privilege('service_role', quarantine_oid, 'SELECT')
     OR pg_catalog.has_table_privilege('service_role', quarantine_oid, 'INSERT')
     OR pg_catalog.has_table_privilege('service_role', quarantine_oid, 'UPDATE')
     OR pg_catalog.has_table_privilege('service_role', quarantine_oid, 'DELETE') THEN
    RAISE EXCEPTION 'client as-built tables do not have the exact service-only contract';
  END IF;

  IF old_routine_oid IS NOT NULL OR interim_routine_oid IS NOT NULL OR routine_oid IS NULL THEN
    RAISE EXCEPTION 'set_proposal_client_as_built has a stale or missing signature';
  END IF;
  SELECT p.prosecdef, p.proconfig
    INTO STRICT routine_security_definer, routine_config
    FROM pg_catalog.pg_proc p
   WHERE p.oid = routine_oid;
  IF routine_security_definer IS DISTINCT FROM false
     OR routine_config IS DISTINCT FROM ARRAY['search_path=pg_catalog, public']::text[]
     OR pg_catalog.has_function_privilege('anon', routine_oid, 'EXECUTE')
     OR pg_catalog.has_function_privilege('authenticated', routine_oid, 'EXECUTE')
     OR NOT pg_catalog.has_function_privilege('service_role', routine_oid, 'EXECUTE') THEN
    RAISE EXCEPTION 'set_proposal_client_as_built does not have the exact service-only invoker contract';
  END IF;

  SELECT count(*) INTO STRICT binding_trigger_count
    FROM pg_catalog.pg_trigger trigger_row
   WHERE trigger_row.tgrelid = 'public.proposals'::regclass
     AND trigger_row.tgname = 'proposals_source_job_id_immutable'
     AND NOT trigger_row.tgisinternal
     AND trigger_row.tgenabled = 'O';
  IF binding_routine_oid IS NULL OR binding_trigger_count <> 1 THEN
    RAISE EXCEPTION 'proposal source job immutability trigger is missing';
  END IF;
  SELECT p.prosecdef, p.proconfig
    INTO STRICT binding_routine_security_definer, binding_routine_config
    FROM pg_catalog.pg_proc p
   WHERE p.oid = binding_routine_oid;
  IF binding_routine_security_definer IS DISTINCT FROM false
     OR binding_routine_config IS DISTINCT FROM ARRAY['search_path=pg_catalog, public']::text[]
     OR pg_catalog.has_function_privilege('anon', binding_routine_oid, 'EXECUTE')
     OR pg_catalog.has_function_privilege('authenticated', binding_routine_oid, 'EXECUTE')
     OR NOT pg_catalog.has_function_privilege('service_role', binding_routine_oid, 'EXECUTE') THEN
    RAISE EXCEPTION 'proposal source job immutability trigger has the wrong contract';
  END IF;
END;
$$;

NOTIFY pgrst, 'reload schema';
COMMIT;
