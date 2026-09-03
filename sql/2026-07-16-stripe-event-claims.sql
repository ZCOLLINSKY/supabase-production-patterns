-- Durable Stripe webhook ownership. One invocation atomically claims an event,
-- holds a bounded lease while applying it, and marks it complete only afterward.

BEGIN;
SET LOCAL lock_timeout = '5s';

ALTER TABLE public.stripe_events
  ADD COLUMN IF NOT EXISTS processing_status text,
  ADD COLUMN IF NOT EXISTS claim_owner text,
  ADD COLUMN IF NOT EXISTS lease_until timestamptz,
  ADD COLUMN IF NOT EXISTS attempts integer,
  ADD COLUMN IF NOT EXISTS completed_at timestamptz,
  ADD COLUMN IF NOT EXISTS last_error text,
  ADD COLUMN IF NOT EXISTS webhook_source text,
  ADD COLUMN IF NOT EXISTS livemode boolean,
  ADD COLUMN IF NOT EXISTS payload_sha256 text,
  ADD COLUMN IF NOT EXISTS updated_at timestamptz;

-- Rows written by the old insert-after-effects implementation represent events
-- that were already handled. Preserve their dedupe meaning during the upgrade.
UPDATE public.stripe_events
   SET processing_status = coalesce(processing_status, 'completed'),
       attempts = coalesce(attempts, 1),
       completed_at = coalesce(completed_at, created_at, now()),
       updated_at = coalesce(updated_at, completed_at, created_at, now())
 WHERE processing_status IS NULL
    OR attempts IS NULL
    OR updated_at IS NULL;

ALTER TABLE public.stripe_events
  ALTER COLUMN processing_status SET DEFAULT 'pending',
  ALTER COLUMN processing_status SET NOT NULL,
  ALTER COLUMN attempts SET DEFAULT 0,
  ALTER COLUMN attempts SET NOT NULL,
  ALTER COLUMN updated_at SET DEFAULT now(),
  ALTER COLUMN updated_at SET NOT NULL;

ALTER TABLE public.stripe_events
  DROP CONSTRAINT IF EXISTS stripe_events_processing_status_check,
  DROP CONSTRAINT IF EXISTS stripe_events_webhook_source_check,
  DROP CONSTRAINT IF EXISTS stripe_events_payload_sha256_check,
  DROP CONSTRAINT IF EXISTS stripe_events_attempts_check;
ALTER TABLE public.stripe_events
  ADD CONSTRAINT stripe_events_processing_status_check
    CHECK (processing_status IN ('pending', 'processing', 'failed', 'completed')),
  ADD CONSTRAINT stripe_events_webhook_source_check
    CHECK (webhook_source IS NULL OR webhook_source IN ('platform', 'connect')),
  ADD CONSTRAINT stripe_events_payload_sha256_check
    CHECK (payload_sha256 IS NULL OR payload_sha256 ~ '^[0-9a-f]{64}$'),
  ADD CONSTRAINT stripe_events_attempts_check
    CHECK (attempts >= 0);

CREATE OR REPLACE FUNCTION public.claim_stripe_event(
  p_event_id text,
  p_event_type text,
  p_livemode boolean,
  p_source text,
  p_payload_sha256 text,
  p_owner_id text,
  p_lease_seconds integer DEFAULT 300
)
RETURNS TABLE(claim_result text, attempts integer, lease_until timestamptz)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_event_id text := nullif(btrim(p_event_id), '');
  v_event_type text := nullif(btrim(p_event_type), '');
  v_source text := lower(nullif(btrim(p_source), ''));
  v_digest text := lower(nullif(btrim(p_payload_sha256), ''));
  v_owner text := nullif(btrim(p_owner_id), '');
  v_lease integer := greatest(30, least(coalesce(p_lease_seconds, 300), 900));
  v_row public.stripe_events%ROWTYPE;
BEGIN
  IF v_event_id IS NULL OR length(v_event_id) > 255 OR v_event_id <> p_event_id THEN
    RAISE EXCEPTION 'valid canonical Stripe event id required';
  END IF;
  IF v_event_type IS NULL OR length(v_event_type) > 120 OR v_event_type <> p_event_type THEN
    RAISE EXCEPTION 'valid canonical Stripe event type required';
  END IF;
  IF v_source NOT IN ('platform', 'connect') THEN
    RAISE EXCEPTION 'valid Stripe webhook source required';
  END IF;
  IF p_livemode IS NULL THEN RAISE EXCEPTION 'Stripe livemode required'; END IF;
  IF v_digest IS NULL OR v_digest !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'valid Stripe payload digest required';
  END IF;
  IF v_owner IS NULL OR length(v_owner) > 120 THEN
    RAISE EXCEPTION 'valid Stripe event owner required';
  END IF;

  INSERT INTO public.stripe_events (
    event_id, event_type, processing_status, claim_owner, lease_until,
    attempts, webhook_source, livemode, payload_sha256, created_at, updated_at
  ) VALUES (
    v_event_id, v_event_type, 'pending', NULL, NULL,
    0, v_source, p_livemode, v_digest, now(), now()
  )
  ON CONFLICT (event_id) DO NOTHING;

  SELECT se.* INTO STRICT v_row
    FROM public.stripe_events se
   WHERE se.event_id = v_event_id
   FOR UPDATE;

  -- Event ids are not sufficient dedupe authority by themselves. Validate the
  -- immutable signed identity/digest even for completed rows; otherwise a replay
  -- reusing an old evt_ id with different contents is silently accepted forever.
  IF v_row.event_type IS DISTINCT FROM v_event_type
     OR v_row.webhook_source IS DISTINCT FROM v_source
     OR v_row.livemode IS DISTINCT FROM p_livemode
     OR v_row.payload_sha256 IS DISTINCT FROM v_digest THEN
    RAISE EXCEPTION 'Stripe event id replayed with different signed contents';
  END IF;
  IF v_row.processing_status = 'completed' THEN
    RETURN QUERY SELECT 'completed'::text, v_row.attempts, v_row.lease_until;
    RETURN;
  END IF;
  IF v_row.processing_status = 'processing'
     AND v_row.claim_owner IS DISTINCT FROM v_owner
     AND v_row.lease_until IS NOT NULL
     AND v_row.lease_until > clock_timestamp() THEN
    RETURN QUERY SELECT 'busy'::text, v_row.attempts, v_row.lease_until;
    RETURN;
  END IF;

  UPDATE public.stripe_events se
     SET processing_status = 'processing',
         claim_owner = v_owner,
         lease_until = clock_timestamp() + make_interval(secs => v_lease),
         attempts = se.attempts + 1,
         last_error = NULL,
         updated_at = clock_timestamp()
   WHERE se.event_id = v_event_id
   RETURNING se.* INTO STRICT v_row;

  RETURN QUERY SELECT 'claimed'::text, v_row.attempts, v_row.lease_until;
END;
$$;

CREATE OR REPLACE FUNCTION public.complete_stripe_event(
  p_event_id text,
  p_owner_id text
)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_result text;
BEGIN
  UPDATE public.stripe_events se
     SET processing_status = 'completed',
         completed_at = clock_timestamp(),
         claim_owner = NULL,
         lease_until = NULL,
         last_error = NULL,
         updated_at = clock_timestamp()
   WHERE se.event_id = nullif(btrim(p_event_id), '')
     AND se.processing_status = 'processing'
     AND se.claim_owner = nullif(btrim(p_owner_id), '')
   RETURNING 'completed' INTO v_result;
  RETURN coalesce(v_result, 'lost');
END;
$$;

CREATE OR REPLACE FUNCTION public.fail_stripe_event(
  p_event_id text,
  p_owner_id text,
  p_error text
)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_result text;
BEGIN
  UPDATE public.stripe_events se
     SET processing_status = 'failed',
         claim_owner = NULL,
         lease_until = NULL,
         last_error = left(coalesce(p_error, 'handler failed'), 1000),
         updated_at = clock_timestamp()
   WHERE se.event_id = nullif(btrim(p_event_id), '')
     AND se.processing_status = 'processing'
     AND se.claim_owner = nullif(btrim(p_owner_id), '')
   RETURNING 'failed' INTO v_result;
  RETURN coalesce(v_result, 'lost');
END;
$$;

REVOKE ALL ON FUNCTION public.claim_stripe_event(text,text,boolean,text,text,text,integer)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.complete_stripe_event(text,text)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.fail_stripe_event(text,text,text)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.claim_stripe_event(text,text,boolean,text,text,text,integer)
  TO service_role;
GRANT EXECUTE ON FUNCTION public.complete_stripe_event(text,text)
  TO service_role;
GRANT EXECUTE ON FUNCTION public.fail_stripe_event(text,text,text)
  TO service_role;

COMMIT;
