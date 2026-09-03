-- Durable cross-instance usage and rate-limit ledger.
--
-- Public authentication, lead intake, sharing, maps, chat, and support use the
-- atomic charge_ai_usage RPC as a serverless-safe governor. Production fails
-- closed when this dependency is unavailable, so the table and RPC belong in
-- the release bundle rather than in an assumed historical migration.

BEGIN;
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS public.ai_usage (
  id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  account_id  text        NOT NULL,
  usage_date  date        NOT NULL,
  units       integer     NOT NULL DEFAULT 0,
  created_at  timestamptz NOT NULL DEFAULT pg_catalog.now(),
  updated_at  timestamptz NOT NULL DEFAULT pg_catalog.now()
);

-- Fail before replacing the RPC if a legacy table has drifted into a shape the
-- governor cannot update atomically.
DO $$
DECLARE
  invalid_columns integer;
BEGIN
  SELECT count(*)
    INTO invalid_columns
    FROM (VALUES
      ('account_id', 'text', true),
      ('usage_date', 'date', true),
      ('units', 'integer', true),
      ('updated_at', 'timestamp with time zone', true)
    ) AS expected(column_name, data_type, required_not_null)
    LEFT JOIN information_schema.columns actual
      ON actual.table_schema = 'public'
     AND actual.table_name = 'ai_usage'
     AND actual.column_name = expected.column_name
   WHERE actual.column_name IS NULL
      OR actual.data_type <> expected.data_type
      OR (expected.required_not_null AND actual.is_nullable <> 'NO');

  IF invalid_columns > 0 THEN
    RAISE EXCEPTION 'public.ai_usage has an incompatible production shape';
  END IF;

  IF EXISTS (
    SELECT 1
      FROM public.ai_usage
     WHERE units < 0
        OR nullif(btrim(account_id), '') IS NULL
        OR account_id <> btrim(account_id)
        OR length(account_id) > 256
  ) THEN
    RAISE EXCEPTION 'public.ai_usage contains invalid account keys or units';
  END IF;
END;
$$;

-- Rebuild rather than trust a same-named legacy index whose key, predicate, or
-- uniqueness may have drifted. Duplicate data makes CREATE fail transactionally.
DROP INDEX IF EXISTS public.ai_usage_account_day_uniq;
CREATE UNIQUE INDEX ai_usage_account_day_uniq
  ON public.ai_usage (account_id, usage_date);

ALTER TABLE public.ai_usage ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ai_usage FORCE ROW LEVEL SECURITY;

CREATE OR REPLACE FUNCTION public.charge_ai_usage(
  p_account_id text,
  p_usage_date date,
  p_cost integer,
  p_limit integer
)
RETURNS TABLE(ok boolean, units integer, remaining integer)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_units integer;
BEGIN
  IF p_account_id IS NULL
     OR length(btrim(p_account_id)) = 0
     OR p_account_id <> btrim(p_account_id)
     OR length(p_account_id) > 256 THEN
    RAISE EXCEPTION 'p_account_id must be canonical and nonblank';
  END IF;
  IF p_usage_date IS NULL THEN
    RAISE EXCEPTION 'p_usage_date is required';
  END IF;
  IF p_cost IS NULL OR p_cost < 0 THEN
    RAISE EXCEPTION 'p_cost must be nonnegative';
  END IF;
  IF p_limit IS NULL OR p_limit < 0 THEN
    RAISE EXCEPTION 'p_limit must be nonnegative';
  END IF;

  INSERT INTO public.ai_usage (account_id, usage_date, units, updated_at)
  VALUES (p_account_id, p_usage_date, 0, pg_catalog.now())
  ON CONFLICT (account_id, usage_date) DO NOTHING;

  UPDATE public.ai_usage
     SET units = public.ai_usage.units + p_cost,
         updated_at = pg_catalog.now()
   WHERE account_id = p_account_id
     AND usage_date = p_usage_date
     AND public.ai_usage.units <= p_limit - p_cost
  RETURNING public.ai_usage.units INTO v_units;

  IF FOUND THEN
    RETURN QUERY SELECT true, v_units, greatest(0, p_limit - v_units);
    RETURN;
  END IF;

  SELECT public.ai_usage.units
    INTO v_units
    FROM public.ai_usage
   WHERE account_id = p_account_id
     AND usage_date = p_usage_date;

  RETURN QUERY
  SELECT false, coalesce(v_units, 0), greatest(0, p_limit - coalesce(v_units, 0));
END;
$$;

REVOKE ALL PRIVILEGES ON TABLE public.ai_usage FROM PUBLIC;
REVOKE ALL PRIVILEGES ON SEQUENCE public.ai_usage_id_seq FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.charge_ai_usage(text,date,integer,integer) FROM PUBLIC;

DO $$
DECLARE
  browser_role text;
BEGIN
  IF pg_catalog.to_regrole('service_role') IS NULL THEN
    RAISE EXCEPTION 'LightDeck usage ledger requires the Supabase service_role role';
  END IF;

  FOREACH browser_role IN ARRAY ARRAY['anon', 'authenticated']
  LOOP
    IF pg_catalog.to_regrole(browser_role) IS NOT NULL THEN
      EXECUTE format('REVOKE ALL PRIVILEGES ON TABLE public.ai_usage FROM %I', browser_role);
      EXECUTE format('REVOKE ALL PRIVILEGES ON SEQUENCE public.ai_usage_id_seq FROM %I', browser_role);
      EXECUTE format(
        'REVOKE ALL PRIVILEGES ON FUNCTION public.charge_ai_usage(text,date,integer,integer) FROM %I',
        browser_role
      );
    END IF;
  END LOOP;

  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.ai_usage TO service_role;
  GRANT USAGE, SELECT, UPDATE ON SEQUENCE public.ai_usage_id_seq TO service_role;
  GRANT EXECUTE ON FUNCTION public.charge_ai_usage(text,date,integer,integer) TO service_role;
END;
$$;

COMMIT;
