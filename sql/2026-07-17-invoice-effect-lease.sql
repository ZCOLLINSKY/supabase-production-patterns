-- Atomic ownership + per-channel durability for paid invoice effects.
--
-- A row-level claim prevents concurrent webhook/lifecycle workers from both
-- sending. Receipt and review states are committed independently so a retry after
-- a partial failure never re-sends a channel already durably satisfied.

BEGIN;
SET LOCAL lock_timeout = '5s';

ALTER TABLE public.invoices
  ADD COLUMN IF NOT EXISTS paid_effects_claim_owner text,
  ADD COLUMN IF NOT EXISTS paid_effects_lease_until timestamptz,
  ADD COLUMN IF NOT EXISTS paid_receipt_status text,
  ADD COLUMN IF NOT EXISTS paid_review_status text;

-- Reconcile a partial/manual prior definition instead of trusting IF NOT EXISTS.
ALTER TABLE public.invoices
  ALTER COLUMN paid_effects_claim_owner TYPE text USING paid_effects_claim_owner::text,
  ALTER COLUMN paid_effects_claim_owner DROP DEFAULT,
  ALTER COLUMN paid_effects_claim_owner DROP NOT NULL,
  ALTER COLUMN paid_effects_lease_until TYPE timestamptz USING paid_effects_lease_until::timestamptz,
  ALTER COLUMN paid_effects_lease_until DROP DEFAULT,
  ALTER COLUMN paid_effects_lease_until DROP NOT NULL,
  ALTER COLUMN paid_receipt_status TYPE text USING paid_receipt_status::text,
  ALTER COLUMN paid_receipt_status DROP DEFAULT,
  ALTER COLUMN paid_receipt_status DROP NOT NULL,
  ALTER COLUMN paid_review_status TYPE text USING paid_review_status::text,
  ALTER COLUMN paid_review_status DROP DEFAULT,
  ALTER COLUMN paid_review_status DROP NOT NULL;

ALTER TABLE public.invoices
  DROP CONSTRAINT IF EXISTS invoices_paid_receipt_status_check,
  DROP CONSTRAINT IF EXISTS invoices_paid_review_status_check,
  DROP CONSTRAINT IF EXISTS invoices_paid_effect_claim_pair_check;

ALTER TABLE public.invoices
  ADD CONSTRAINT invoices_paid_receipt_status_check
  CHECK (
    paid_receipt_status IS NULL
    OR paid_receipt_status IN ('pending', 'sent', 'skipped', 'failed')
  ) NOT VALID,
  ADD CONSTRAINT invoices_paid_review_status_check
  CHECK (
    paid_review_status IS NULL
    OR paid_review_status IN ('pending', 'sent', 'skipped', 'failed')
  ) NOT VALID,
  ADD CONSTRAINT invoices_paid_effect_claim_pair_check
  CHECK (
    (
      paid_effects_status IS DISTINCT FROM 'processing'
      AND paid_effects_claim_owner IS NULL
      AND paid_effects_lease_until IS NULL
    )
    OR (
      paid_effects_status = 'processing'
      AND paid_effects_claim_owner IS NOT NULL
      AND btrim(paid_effects_claim_owner) = paid_effects_claim_owner
      AND paid_effects_claim_owner <> ''
      AND paid_effects_lease_until IS NOT NULL
    )
  ) NOT VALID;

ALTER TABLE public.invoices
  VALIDATE CONSTRAINT invoices_paid_receipt_status_check;
ALTER TABLE public.invoices
  VALIDATE CONSTRAINT invoices_paid_review_status_check;
ALTER TABLE public.invoices
  VALIDATE CONSTRAINT invoices_paid_effect_claim_pair_check;

DROP INDEX IF EXISTS public.idx_invoices_paid_effects_claim_recovery;
CREATE INDEX idx_invoices_paid_effects_claim_recovery
  ON public.invoices (paid_effects_status, paid_effects_lease_until, paid_effects_updated_at)
  WHERE paid_effects_status IN ('pending', 'failed', 'processing');

DO $verify$
DECLARE
  column_spec record;
  column_row record;
  constraint_name text;
  constraint_row record;
  index_row record;
BEGIN
  FOR column_spec IN
    SELECT * FROM (VALUES
      ('paid_effects_claim_owner', 'text'),
      ('paid_effects_lease_until', 'timestamp with time zone'),
      ('paid_receipt_status', 'text'),
      ('paid_review_status', 'text')
    ) AS expected(name, type_name)
  LOOP
    SELECT a.attnotnull,
           pg_catalog.format_type(a.atttypid, a.atttypmod) AS type_name,
           d.adbin IS NOT NULL AS has_default
      INTO column_row
      FROM pg_catalog.pg_attribute a
      LEFT JOIN pg_catalog.pg_attrdef d
        ON d.adrelid = a.attrelid AND d.adnum = a.attnum
     WHERE a.attrelid = 'public.invoices'::regclass
       AND a.attname = column_spec.name
       AND a.attnum > 0
       AND NOT a.attisdropped;
    IF NOT FOUND
       OR column_row.attnotnull
       OR column_row.has_default
       OR column_row.type_name <> column_spec.type_name THEN
      RAISE EXCEPTION 'invoice paid-effect column % is not canonical', column_spec.name;
    END IF;
  END LOOP;

  FOREACH constraint_name IN ARRAY ARRAY[
    'invoices_paid_receipt_status_check',
    'invoices_paid_review_status_check',
    'invoices_paid_effect_claim_pair_check'
  ]
  LOOP
    SELECT convalidated, contype
      INTO constraint_row
      FROM pg_catalog.pg_constraint
     WHERE conrelid = 'public.invoices'::regclass
       AND conname = constraint_name;
    IF NOT FOUND OR NOT constraint_row.convalidated OR constraint_row.contype <> 'c' THEN
      RAISE EXCEPTION 'invoice paid-effect constraint % is not canonical', constraint_name;
    END IF;
  END LOOP;

  SELECT i.indisvalid,
         i.indisready,
         i.indisunique,
         i.indnkeyatts,
         i.indpred IS NOT NULL AS is_partial,
         pg_catalog.pg_get_expr(i.indpred, i.indrelid) AS predicate,
         ARRAY(
           SELECT a.attname
             FROM unnest(i.indkey::smallint[]) WITH ORDINALITY AS key(attnum, ord)
             JOIN pg_catalog.pg_attribute a
               ON a.attrelid = i.indrelid AND a.attnum = key.attnum
            WHERE key.ord <= i.indnkeyatts
            ORDER BY key.ord
         ) AS key_columns
    INTO index_row
    FROM pg_catalog.pg_index i
    JOIN pg_catalog.pg_class c ON c.oid = i.indexrelid
   WHERE i.indrelid = 'public.invoices'::regclass
     AND c.relname = 'idx_invoices_paid_effects_claim_recovery';
  IF NOT FOUND
     OR NOT index_row.indisvalid
     OR NOT index_row.indisready
     OR index_row.indisunique
     OR index_row.indnkeyatts <> 3
     OR NOT index_row.is_partial
     OR index_row.key_columns <> ARRAY[
       'paid_effects_status', 'paid_effects_lease_until', 'paid_effects_updated_at'
     ]::name[]
     OR index_row.predicate NOT LIKE '%pending%'
     OR index_row.predicate NOT LIKE '%failed%'
     OR index_row.predicate NOT LIKE '%processing%' THEN
    RAISE EXCEPTION 'invoice paid-effect recovery index is not canonical';
  END IF;
END
$verify$;

COMMIT;
