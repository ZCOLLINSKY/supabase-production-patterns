-- Private append-only render/provenance receipt ledger.
--
-- This table is the durable server-side authority for raw render receipts,
-- proposal presentation receipts, and presentation-pack manifests. It stores
-- no image bytes, client identity, share token, or provider credential.

BEGIN;
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS public.render_receipts (
  receipt_id                  text        PRIMARY KEY,
  store_version               text        NOT NULL,
  record_type                 text        NOT NULL,
  account_ref                 text        NOT NULL,
  proposal_ref                text,
  request_id                  text        NOT NULL DEFAULT '',
  request_hash                text,
  design_hash                 text        NOT NULL,
  source_photo_hash           text        NOT NULL,
  origin_output_sha256        text        NOT NULL,
  presentation_output_sha256  text,
  model                       text        NOT NULL DEFAULT '',
  verified                    boolean     NOT NULL DEFAULT false,
  verified_at                 timestamptz,
  render_receipt              jsonb,
  presentation_receipt        jsonb,
  pack_receipt                jsonb,
  context                     jsonb       NOT NULL DEFAULT '{}'::jsonb,
  recorded_at                 timestamptz NOT NULL DEFAULT pg_catalog.now(),
  CONSTRAINT render_receipts_id_sha256 CHECK (receipt_id ~ '^[a-f0-9]{64}$'),
  CONSTRAINT render_receipts_account_sha256 CHECK (account_ref ~ '^[a-f0-9]{64}$'),
  CONSTRAINT render_receipts_proposal_sha256 CHECK (proposal_ref IS NULL OR proposal_ref ~ '^[a-f0-9]{64}$'),
  CONSTRAINT render_receipts_request_sha256 CHECK (request_hash IS NULL OR request_hash ~ '^[a-f0-9]{64}$'),
  CONSTRAINT render_receipts_design_sha256 CHECK (design_hash ~ '^[a-f0-9]{64}$'),
  CONSTRAINT render_receipts_source_sha256 CHECK (source_photo_hash ~ '^[a-f0-9]{64}$'),
  CONSTRAINT render_receipts_origin_sha256 CHECK (origin_output_sha256 ~ '^[a-f0-9]{64}$'),
  CONSTRAINT render_receipts_presentation_sha256 CHECK (
    presentation_output_sha256 IS NULL OR presentation_output_sha256 ~ '^[a-f0-9]{64}$'
  ),
  CONSTRAINT render_receipts_type CHECK (record_type IN ('origin', 'presentation', 'presentation_pack')),
  CONSTRAINT render_receipts_payload CHECK (
    render_receipt IS NOT NULL OR presentation_receipt IS NOT NULL OR pack_receipt IS NOT NULL
  ),
  CONSTRAINT render_receipts_context_object CHECK (jsonb_typeof(context) = 'object')
);

CREATE INDEX IF NOT EXISTS render_receipts_request_idx ON public.render_receipts (request_id) WHERE request_id <> '';
CREATE INDEX IF NOT EXISTS render_receipts_design_idx ON public.render_receipts (design_hash, recorded_at DESC);
CREATE INDEX IF NOT EXISTS render_receipts_origin_output_idx ON public.render_receipts (origin_output_sha256);
CREATE INDEX IF NOT EXISTS render_receipts_presentation_output_idx ON public.render_receipts (presentation_output_sha256)
  WHERE presentation_output_sha256 IS NOT NULL;
CREATE INDEX IF NOT EXISTS render_receipts_proposal_idx ON public.render_receipts (proposal_ref, recorded_at)
  WHERE proposal_ref IS NOT NULL;

CREATE TABLE IF NOT EXISTS public.render_receipt_consumptions (
  nonce             text        PRIMARY KEY,
  origin_signature  text        NOT NULL UNIQUE,
  receipt_id        text        NOT NULL,
  account_ref       text        NOT NULL,
  proposal_ref      text        NOT NULL,
  consumed_at       timestamptz NOT NULL DEFAULT pg_catalog.now(),
  CONSTRAINT render_receipt_consumptions_nonce_sha256 CHECK (nonce ~ '^[a-f0-9]{64}$'),
  CONSTRAINT render_receipt_consumptions_signature_sha256 CHECK (origin_signature ~ '^[a-f0-9]{64}$'),
  CONSTRAINT render_receipt_consumptions_receipt_sha256 CHECK (receipt_id ~ '^[a-f0-9]{64}$'),
  CONSTRAINT render_receipt_consumptions_account_sha256 CHECK (account_ref ~ '^[a-f0-9]{64}$'),
  CONSTRAINT render_receipt_consumptions_proposal_sha256 CHECK (proposal_ref ~ '^[a-f0-9]{64}$')
);

CREATE INDEX IF NOT EXISTS render_receipt_consumptions_proposal_idx
  ON public.render_receipt_consumptions (proposal_ref, consumed_at);

ALTER TABLE public.render_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.render_receipts FORCE ROW LEVEL SECURITY;
ALTER TABLE public.render_receipt_consumptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.render_receipt_consumptions FORCE ROW LEVEL SECURITY;

CREATE OR REPLACE FUNCTION public.lightdeck_reject_render_receipt_mutation()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  RAISE EXCEPTION 'render_receipts is append-only';
END;
$$;

DROP TRIGGER IF EXISTS render_receipts_append_only ON public.render_receipts;
CREATE TRIGGER render_receipts_append_only
BEFORE UPDATE OR DELETE ON public.render_receipts
FOR EACH ROW EXECUTE FUNCTION public.lightdeck_reject_render_receipt_mutation();

DROP TRIGGER IF EXISTS render_receipt_consumptions_append_only ON public.render_receipt_consumptions;
CREATE TRIGGER render_receipt_consumptions_append_only
BEFORE UPDATE OR DELETE ON public.render_receipt_consumptions
FOR EACH ROW EXECUTE FUNCTION public.lightdeck_reject_render_receipt_mutation();

-- Atomically consume every signed origin nonce and append every presentation
-- ledger row. A unique collision rolls the whole consumption subtransaction
-- back and returns a stable replay result; no partial package can consume only
-- some tier receipts.
CREATE OR REPLACE FUNCTION public.publish_render_receipts(
  p_account_ref text,
  p_proposal_ref text,
  p_records jsonb,
  p_consumptions jsonb
)
RETURNS TABLE(ok boolean, stored integer, consumed integer, reason text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_stored integer := 0;
  v_consumed integer := 0;
BEGIN
  IF p_account_ref !~ '^[a-f0-9]{64}$' OR p_proposal_ref !~ '^[a-f0-9]{64}$' OR
     jsonb_typeof(p_records) <> 'array' OR jsonb_typeof(p_consumptions) <> 'array' OR
     jsonb_array_length(p_records) < 1 OR jsonb_array_length(p_records) > 64 OR
     jsonb_array_length(p_consumptions) < 1 OR jsonb_array_length(p_consumptions) > 64 THEN
    RETURN QUERY SELECT false, 0, 0, 'render_receipt_scope_invalid'::text;
    RETURN;
  END IF;
  IF EXISTS (
    SELECT 1
      FROM jsonb_to_recordset(p_consumptions) AS item(
        nonce text, origin_signature text, receipt_id text, account_ref text
      )
     WHERE item.account_ref IS DISTINCT FROM p_account_ref
        OR item.nonce !~ '^[a-f0-9]{64}$'
        OR item.origin_signature !~ '^[a-f0-9]{64}$'
        OR item.receipt_id !~ '^[a-f0-9]{64}$'
  ) THEN
    RETURN QUERY SELECT false, 0, 0, 'render_receipt_scope_invalid'::text;
    RETURN;
  END IF;
  IF EXISTS (
    SELECT 1
      FROM jsonb_array_elements(p_records) AS rec(item)
     WHERE rec.item->>'account_ref' IS DISTINCT FROM p_account_ref
        OR rec.item->>'proposal_ref' IS DISTINCT FROM p_proposal_ref
        OR COALESCE(rec.item->>'receipt_id', '') !~ '^[a-f0-9]{64}$'
  ) OR EXISTS (
    SELECT 1
      FROM jsonb_array_elements(p_consumptions) AS con(item)
     WHERE NOT EXISTS (
       SELECT 1
         FROM jsonb_array_elements(p_records) AS rec(item)
        WHERE rec.item->>'receipt_id' = con.item->>'receipt_id'
          AND rec.item->'render_receipt'->>'nonce' = con.item->>'nonce'
          AND rec.item->'render_receipt'->>'signature' = con.item->>'origin_signature'
     )
  ) OR EXISTS (
    SELECT 1
      FROM jsonb_array_elements(p_records) AS rec(item)
     WHERE jsonb_typeof(rec.item->'render_receipt') = 'object'
       AND NOT EXISTS (
         SELECT 1
           FROM jsonb_array_elements(p_consumptions) AS con(item)
          WHERE con.item->>'receipt_id' = rec.item->>'receipt_id'
            AND con.item->>'nonce' = rec.item->'render_receipt'->>'nonce'
            AND con.item->>'origin_signature' = rec.item->'render_receipt'->>'signature'
       )
  ) THEN
    RETURN QUERY SELECT false, 0, 0, 'render_receipt_scope_invalid'::text;
    RETURN;
  END IF;

  BEGIN
    INSERT INTO public.render_receipt_consumptions (
      nonce, origin_signature, receipt_id, account_ref, proposal_ref
    )
    SELECT item.nonce, item.origin_signature, item.receipt_id, item.account_ref, p_proposal_ref
      FROM jsonb_to_recordset(p_consumptions) AS item(
        nonce text, origin_signature text, receipt_id text, account_ref text
      );
    GET DIAGNOSTICS v_consumed = ROW_COUNT;
  EXCEPTION WHEN unique_violation THEN
    RETURN QUERY SELECT false, 0, 0, 'render_receipt_reused'::text;
    RETURN;
  END;

  INSERT INTO public.render_receipts (
    receipt_id, store_version, record_type, account_ref, proposal_ref,
    request_id, request_hash, design_hash, source_photo_hash,
    origin_output_sha256, presentation_output_sha256, model, verified,
    verified_at, render_receipt, presentation_receipt, pack_receipt,
    context, recorded_at
  )
  SELECT
    item.receipt_id, item.store_version, item.record_type, item.account_ref, item.proposal_ref,
    item.request_id, item.request_hash, item.design_hash, item.source_photo_hash,
    item.origin_output_sha256, item.presentation_output_sha256, item.model, item.verified,
    item.verified_at, item.render_receipt, item.presentation_receipt, item.pack_receipt,
    item.context, item.recorded_at
  FROM jsonb_to_recordset(p_records) AS item(
    receipt_id text, store_version text, record_type text, account_ref text, proposal_ref text,
    request_id text, request_hash text, design_hash text, source_photo_hash text,
    origin_output_sha256 text, presentation_output_sha256 text, model text, verified boolean,
    verified_at timestamptz, render_receipt jsonb, presentation_receipt jsonb, pack_receipt jsonb,
    context jsonb, recorded_at timestamptz
  )
  WHERE item.account_ref = p_account_ref AND item.proposal_ref = p_proposal_ref
  ON CONFLICT (receipt_id) DO NOTHING;
  GET DIAGNOSTICS v_stored = ROW_COUNT;

  IF v_consumed <> jsonb_array_length(p_consumptions) OR
     v_stored <> jsonb_array_length(p_records) THEN
    RAISE EXCEPTION 'render receipt consumption count mismatch';
  END IF;
  RETURN QUERY SELECT true, v_stored, v_consumed, ''::text;
END;
$$;

REVOKE ALL PRIVILEGES ON TABLE public.render_receipts FROM PUBLIC;
REVOKE ALL PRIVILEGES ON TABLE public.render_receipt_consumptions FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.lightdeck_reject_render_receipt_mutation() FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.publish_render_receipts(text,text,jsonb,jsonb) FROM PUBLIC;

DO $$
DECLARE
  browser_role text;
BEGIN
  IF pg_catalog.to_regrole('service_role') IS NULL THEN
    RAISE EXCEPTION 'LightDeck render receipts require the Supabase service_role role';
  END IF;
  FOREACH browser_role IN ARRAY ARRAY['anon', 'authenticated']
  LOOP
    IF pg_catalog.to_regrole(browser_role) IS NOT NULL THEN
      EXECUTE format('REVOKE ALL PRIVILEGES ON TABLE public.render_receipts FROM %I', browser_role);
      EXECUTE format('REVOKE ALL PRIVILEGES ON TABLE public.render_receipt_consumptions FROM %I', browser_role);
      EXECUTE format(
        'REVOKE ALL PRIVILEGES ON FUNCTION public.lightdeck_reject_render_receipt_mutation() FROM %I',
        browser_role
      );
      EXECUTE format(
        'REVOKE ALL PRIVILEGES ON FUNCTION public.publish_render_receipts(text,text,jsonb,jsonb) FROM %I',
        browser_role
      );
    END IF;
  END LOOP;
  GRANT SELECT, INSERT ON TABLE public.render_receipts TO service_role;
  GRANT SELECT, INSERT ON TABLE public.render_receipt_consumptions TO service_role;
  GRANT EXECUTE ON FUNCTION public.publish_render_receipts(text,text,jsonb,jsonb) TO service_role;
END;
$$;

COMMIT;
