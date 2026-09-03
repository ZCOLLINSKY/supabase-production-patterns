-- Row-embedded payment-effect outbox.
--
-- paid_effects_status='pending' is written by the SAME conditional invoice PATCH
-- that commits status='paid'. A crash after that commit therefore leaves durable
-- work for the lifecycle retry sweep (Checkout-session invalidation, receipt, review,
-- and link cleanup) instead of permanently losing those effects.

BEGIN;
SET LOCAL lock_timeout = '5s';

ALTER TABLE public.invoices
  ADD COLUMN IF NOT EXISTS paid_effects_key text,
  ADD COLUMN IF NOT EXISTS paid_effects_status text,
  ADD COLUMN IF NOT EXISTS paid_effects_attempts integer NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS paid_effects_last_error text,
  ADD COLUMN IF NOT EXISTS paid_effects_updated_at timestamptz,
  ADD COLUMN IF NOT EXISTS paid_effects_completed_at timestamptz;

CREATE INDEX IF NOT EXISTS idx_invoices_paid_effects_retry
  ON public.invoices (paid_effects_status, paid_effects_updated_at)
  WHERE paid_effects_status IN ('pending', 'failed');

COMMIT;
