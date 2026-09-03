-- ============================================================================
-- 2026-06-17 · Gap-free per-account invoice numbering
--             (IDEMPOTENT · ADDITIVE · safe to re-run)
-- ----------------------------------------------------------------------------
-- WHY:
--   api/invoices.js mints the auto invoice number. The old logic derived the
--   number from the current time (EG-<seconds-since-anchor>), which is monotonic
--   but NOT gap-free (EG-1002, EG-1047, EG-1991, ...). The owner's hand-numbered
--   series is EG-1001, EG-1002, EG-1003 ... and a real billing series should
--   continue gap-free.
--
--   This migration adds an account-scoped, ATOMIC counter so two invoices
--   created at the same instant can never mint the same number:
--     1. accounts.last_invoice_seq  int  default 1001   (seeds AFTER EG-1001)
--     2. next_invoice_seq(p_account_id) RPC: increments and RETURNS the new value
--        in a SINGLE UPDATE statement (no read-then-write race).
--   The first call for an account returns 1002, then 1003, 1004, ... → the API
--   mints EG-1002, EG-1003, EG-1004 with NO gaps.
--
-- GRACEFUL FALLBACK (no code change needed if you DON'T run this):
--   When the RPC / column is absent or Supabase is unreachable, api/invoices.js
--   falls back to the monotonic time-derived number. Running this migration is
--   what switches live numbering onto the gap-free path.
--
-- RUN THIS IN: the Supabase SQL editor for the PRODUCTION project, once.
-- ============================================================================

-- 1) Atomic counter column on accounts. Seed at 1001 so the FIRST increment
--    returns 1002 (just after the owner's hand-made EG-1001). Existing rows are
--    backfilled to 1001 by the DEFAULT + the UPDATE below.
ALTER TABLE public.accounts
  ADD COLUMN IF NOT EXISTS last_invoice_seq integer NOT NULL DEFAULT 1001;

-- Backfill any pre-existing accounts whose column was just added as NULL-safe.
-- (ADD COLUMN ... DEFAULT already backfills, but this is belt-and-suspenders for
--  a re-run after a manual column tweak.)
UPDATE public.accounts
  SET last_invoice_seq = 1001
  WHERE last_invoice_seq IS NULL OR last_invoice_seq < 1001;

-- 2) Atomic increment-and-return. SECURITY DEFINER so the service-role API key
--    can call it. The single UPDATE ... RETURNING is race-free: each concurrent
--    caller gets its own distinct, strictly-increasing seq.
CREATE OR REPLACE FUNCTION public.next_invoice_seq(p_account_id text)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_seq integer;
BEGIN
  IF p_account_id IS NULL OR length(trim(p_account_id)) = 0 THEN
    RETURN NULL;
  END IF;

  UPDATE public.accounts
    SET last_invoice_seq = last_invoice_seq + 1
    WHERE id::text = p_account_id
    RETURNING last_invoice_seq INTO v_seq;

  -- No such account row → let the API fall back to the time-derived number.
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;

  RETURN v_seq;
END;
$$;

-- NOTE: id::text lets the RPC match whether accounts.id is uuid or text. If your
-- accounts PK column is named differently, change `id` above to that column.


-- ============================================================================
-- 3) CENTS-ACCURATE money + CREDIT columns on the invoices table.
-- ----------------------------------------------------------------------------
-- WHY: the launch schema declared subtotal/tax_amount/total/deposit_paid/
-- balance_due as INTEGER, so a real bill like 62.7 ft @ $32 = $2,006.40 would
-- truncate to 2006 on persist. api/invoices.js now rounds money to CENTS; for
-- the persisted row to hold cents (and the new credit) these columns must be
-- numeric(12,2) and the credit columns must exist. The in-memory email render
-- already shows cents; this makes the STORED row match.
--
-- ALTER TYPE integer -> numeric is a safe widening (no data loss; existing
-- whole-dollar integers become x.00). ADD COLUMN IF NOT EXISTS is additive.
-- Safe to re-run.
-- ============================================================================
ALTER TABLE public.invoices
  ALTER COLUMN subtotal     TYPE numeric(12,2),
  ALTER COLUMN tax_amount   TYPE numeric(12,2),
  ALTER COLUMN total        TYPE numeric(12,2),
  ALTER COLUMN deposit_paid TYPE numeric(12,2),
  ALTER COLUMN balance_due  TYPE numeric(12,2);

-- amount_paid is nullable integer in the launch schema; widen it too.
ALTER TABLE public.invoices
  ALTER COLUMN amount_paid  TYPE numeric(12,2);

-- CREDIT: a non-payment reduction (raffle/auction credit, goodwill discount)
-- folded into the total by the handler (total = subtotal + tax - credit). Stored
-- so the emailed/printable breakdown can render the negative credit line with
-- its own label.
ALTER TABLE public.invoices
  ADD COLUMN IF NOT EXISTS credit       numeric(12,2) NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS credit_label text;

-- Columns the F6 deposit-collection + dated-deposit template already writes but
-- the launch schema never declared (so the row could not persist them). Additive.
ALTER TABLE public.invoices
  ADD COLUMN IF NOT EXISTS deposit_collected boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS deposit_paid_at   text;

